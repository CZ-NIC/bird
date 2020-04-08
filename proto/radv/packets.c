/*
 *	BIRD -- RAdv Packet Processing
 *
 *	(c) 2011--2019 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2011--2019 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */


#include <stdlib.h>
#include "radv.h"

struct radv_ra_packet
{
  u8 type;
  u8 code;
  u16 checksum;
  u8 current_hop_limit;
  u8 flags;
  u16 router_lifetime;
  u32 reachable_time;
  u32 retrans_timer;
};

#define OPT_RA_MANAGED 0x80
#define OPT_RA_OTHER_CFG 0x40

#define OPT_PREFIX	3
#define OPT_MTU		5
#define OPT_ROUTE	24
#define OPT_RDNSS	25
#define OPT_DNSSL	31

struct radv_opt_prefix
{
  u8 type;
  u8 length;
  u8 pxlen;
  u8 flags;
  u32 valid_lifetime;
  u32 preferred_lifetime;
  u32 reserved;
  ip6_addr prefix;
};

#define OPT_PX_ONLINK 0x80
#define OPT_PX_AUTONOMOUS 0x40

struct radv_opt_mtu
{
  u8 type;
  u8 length;
  u16 reserved;
  u32 mtu;
};

struct radv_opt_route {
  u8 type;
  u8 length;
  u8 pxlen;
  u8 flags;
  u32 lifetime;
  u8 prefix[];
};

struct radv_opt_rdnss
{
  u8 type;
  u8 length;
  u16 reserved;
  u32 lifetime;
  ip6_addr servers[];
};

struct radv_opt_dnssl
{
  u8 type;
  u8 length;
  u16 reserved;
  u32 lifetime;
  char domain[];
};

static int
radv_prepare_route(struct radv_iface *ifa, struct radv_route *rt,
		   char **buf, char *bufend)
{
  struct radv_proto *p = ifa->ra;
  u8 px_blocks = (net6_pxlen(rt->n.addr) + 63) / 64;
  u8 opt_len = 8 * (1 + px_blocks);

  if (*buf + opt_len > bufend)
  {
    log(L_WARN, "%s: Too many RA options on interface %s",
	p->p.name, ifa->iface->name);
    return -1;
  }

  uint preference = rt->preference_set ? rt->preference : ifa->cf->route_preference;
  uint lifetime = rt->lifetime_set ? rt->lifetime : ifa->cf->route_lifetime;
  uint valid = rt->valid && p->valid && (p->active || !ifa->cf->route_lifetime_sensitive);

  struct radv_opt_route *opt = (void *) *buf;
  *buf += opt_len;
  opt->type = OPT_ROUTE;
  opt->length = 1 + px_blocks;
  opt->pxlen = net6_pxlen(rt->n.addr);
  opt->flags = preference;
  opt->lifetime = valid ? htonl(lifetime) : 0;

  /* Copy the relevant part of the prefix */
  ip6_addr px_addr = ip6_hton(net6_prefix(rt->n.addr));
  memcpy(opt->prefix, &px_addr, 8 * px_blocks);

  /* Keeping track of first linger timeout */
  if (!rt->valid)
    ifa->valid_time = MIN(ifa->valid_time, rt->changed + ifa->cf->route_linger_time S);

  return 0;
}

static int
radv_prepare_rdnss(struct radv_iface *ifa, list *rdnss_list, char **buf, char *bufend)
{
  struct radv_rdnss_config *rcf = HEAD(*rdnss_list);

  while(NODE_VALID(rcf))
  {
    struct radv_rdnss_config *rcf_base = rcf;
    struct radv_opt_rdnss *op = (void *) *buf;
    int max_i = (bufend - *buf - sizeof(struct radv_opt_rdnss)) / sizeof(ip6_addr);
    int i = 0;

    if (max_i < 1)
      goto too_much;

    op->type = OPT_RDNSS;
    op->reserved = 0;

    if (rcf->lifetime_mult)
      op->lifetime = htonl(rcf->lifetime_mult * ifa->cf->max_ra_int);
    else
      op->lifetime = htonl(rcf->lifetime);

    while(NODE_VALID(rcf) &&
	  (rcf->lifetime == rcf_base->lifetime) &&
	  (rcf->lifetime_mult == rcf_base->lifetime_mult))
      {
	if (i >= max_i)
	  goto too_much;

	op->servers[i] = ip6_hton(rcf->server);
	i++;

	rcf = NODE_NEXT(rcf);
      }

    op->length = 1+2*i;
    *buf += 8 * op->length;
  }

  return 0;

 too_much:
  log(L_WARN "%s: Too many RA options on interface %s",
      ifa->ra->p.name, ifa->iface->name);
  return -1;
}

int
radv_process_domain(struct radv_dnssl_config *cf)
{
  /* Format of domain in search list is <size> <label> <size> <label> ... 0 */

  const char *dom = cf->domain;
  const char *dom_end = dom; /* Just to  */
  u8 *dlen_save = &cf->dlen_first;
  uint len;

  while (dom_end)
  {
    dom_end = strchr(dom, '.');
    len = dom_end ? (uint)(dom_end - dom) : strlen(dom);

    if (len < 1 || len > 63)
      return -1;

    *dlen_save = len;
    dlen_save = (u8 *) dom_end;

    dom += len + 1;
  }

  len = dom - cf->domain;
  if (len > 254)
    return -1;

  cf->dlen_all = len;

  return 0;
}

static int
radv_prepare_dnssl(struct radv_iface *ifa, list *dnssl_list, char **buf, char *bufend)
{
  struct radv_dnssl_config *dcf = HEAD(*dnssl_list);

  while(NODE_VALID(dcf))
  {
    struct radv_dnssl_config *dcf_base = dcf;
    struct radv_opt_dnssl *op = (void *) *buf;
    int bsize = bufend - *buf - sizeof(struct radv_opt_dnssl);
    int bpos = 0;

    if (bsize < 0)
      goto too_much;

    bsize = bsize & ~7; /* Round down to multiples of 8 */

    op->type = OPT_DNSSL;
    op->reserved = 0;

    if (dcf->lifetime_mult)
      op->lifetime = htonl(dcf->lifetime_mult * ifa->cf->max_ra_int);
    else
      op->lifetime = htonl(dcf->lifetime);

    while(NODE_VALID(dcf) &&
	  (dcf->lifetime == dcf_base->lifetime) &&
	  (dcf->lifetime_mult == dcf_base->lifetime_mult))
      {
	if (bpos + dcf->dlen_all + 1 > bsize)
	  goto too_much;

	op->domain[bpos++] = dcf->dlen_first;
	memcpy(op->domain + bpos, dcf->domain, dcf->dlen_all);
	bpos += dcf->dlen_all;

	dcf = NODE_NEXT(dcf);
      }

    int blen = (bpos + 7) / 8;
    bzero(op->domain + bpos, 8 * blen - bpos);
    op->length = 1 + blen;
    *buf += 8 * op->length;
  }

  return 0;

 too_much:
  log(L_WARN "%s: Too many RA options on interface %s",
      ifa->ra->p.name, ifa->iface->name);
  return -1;
}

static int
radv_prepare_prefix(struct radv_iface *ifa, struct radv_prefix *px,
		    char **buf, char *bufend)
{
  struct radv_prefix_config *pc = px->cf;

  if (*buf + sizeof(struct radv_opt_prefix) > bufend)
  {
    log(L_WARN "%s: Too many prefixes on interface %s",
	ifa->ra->p.name, ifa->iface->name);
    return -1;
  }

  struct radv_opt_prefix *op = (void *) *buf;
  op->type = OPT_PREFIX;
  op->length = 4;
  op->pxlen = px->prefix.pxlen;
  op->flags = (pc->onlink ? OPT_PX_ONLINK : 0) |
    (pc->autonomous ? OPT_PX_AUTONOMOUS : 0);
  op->valid_lifetime = (ifa->ra->active || !pc->valid_lifetime_sensitive) ?
    htonl(pc->valid_lifetime) : 0;
  op->preferred_lifetime = (ifa->ra->active || !pc->preferred_lifetime_sensitive) ?
    htonl(pc->preferred_lifetime) : 0;
  op->reserved = 0;
  op->prefix = ip6_hton(px->prefix.prefix);
  *buf += sizeof(*op);

  /* Keeping track of first linger timeout */
  if (!px->valid)
    ifa->valid_time = MIN(ifa->valid_time, px->changed + ifa->cf->prefix_linger_time S);

  return 0;
}

static void
radv_prepare_ra(struct radv_iface *ifa)
{
  struct radv_proto *p = ifa->ra;
  struct radv_config *cf = (struct radv_config *) (p->p.cf);
  struct radv_iface_config *ic = ifa->cf;
  btime now = current_time();

  char *buf = ifa->sk->tbuf;
  char *bufstart = buf;
  char *bufend = buf + ifa->sk->tbsize;

  struct radv_ra_packet *pkt = (void *) buf;
  pkt->type = ICMPV6_RA;
  pkt->code = 0;
  pkt->checksum = 0;
  pkt->current_hop_limit = ic->current_hop_limit;
  pkt->router_lifetime = (p->valid && (p->active || !ic->default_lifetime_sensitive)) ?
    htons(ic->default_lifetime) : 0;
  pkt->flags = (ic->managed ? OPT_RA_MANAGED : 0) |
    (ic->other_config ? OPT_RA_OTHER_CFG : 0) |
    (pkt->router_lifetime ? ic->default_preference : 0);
  pkt->reachable_time = htonl(ic->reachable_time);
  pkt->retrans_timer = htonl(ic->retrans_timer);
  buf += sizeof(*pkt);

  if (ic->link_mtu)
  {
    struct radv_opt_mtu *om = (void *) buf;
    om->type = OPT_MTU;
    om->length = 1;
    om->reserved = 0;
    om->mtu = htonl(ic->link_mtu);
    buf += sizeof (*om);
  }

  /* Keeping track of first linger timeout */
  ifa->valid_time = TIME_INFINITY;

  struct radv_prefix *px;
  WALK_LIST(px, ifa->prefixes)
  {
    /* Skip invalid prefixes that are past linger timeout but still not pruned */
    if (!px->valid && ((px->changed + ic->prefix_linger_time S) <= now))
	continue;

    if (radv_prepare_prefix(ifa, px, &buf, bufend) < 0)
      goto done;
  }

  if (! ic->rdnss_local)
    if (radv_prepare_rdnss(ifa, &cf->rdnss_list, &buf, bufend) < 0)
      goto done;

  if (radv_prepare_rdnss(ifa, &ic->rdnss_list, &buf, bufend) < 0)
    goto done;

  if (! ic->dnssl_local)
    if (radv_prepare_dnssl(ifa, &cf->dnssl_list, &buf, bufend) < 0)
      goto done;

  if (radv_prepare_dnssl(ifa, &ic->dnssl_list, &buf, bufend) < 0)
    goto done;

  if (p->fib_up)
  {
    FIB_WALK(&p->routes, struct radv_route, rt)
    {
      /* Skip invalid routes that are past linger timeout but still not pruned */
      if (!rt->valid && ((rt->changed + ic->route_linger_time S) <= now))
	continue;

      if (radv_prepare_route(ifa, rt, &buf, bufend) < 0)
	goto done;
    }
    FIB_WALK_END;
  }

 done:
  ifa->plen = buf - bufstart;
}


void
radv_send_ra(struct radv_iface *ifa, ip_addr to)
{
  struct radv_proto *p = ifa->ra;

  /* TX queue is already full */
  if (!sk_tx_buffer_empty(ifa->sk))
    return;

  if (ifa->valid_time <= current_time())
    radv_invalidate(ifa);

  /* We store prepared RA in tbuf */
  if (!ifa->plen)
    radv_prepare_ra(ifa);

  if (ipa_zero(to))
  {
    to = IP6_ALL_NODES;
    RADV_TRACE(D_PACKETS, "Sending RA via %s", ifa->iface->name);
  }
  else
  {
    RADV_TRACE(D_PACKETS, "Sending RA to %I via %s", to, ifa->iface->name);
  }

  int done = sk_send_to(ifa->sk, ifa->plen, to, 0);
  if (!done)
    log(L_WARN "%s: TX queue full on %s", p->p.name, ifa->iface->name);
}


static void
radv_receive_rs(struct radv_proto *p, struct radv_iface *ifa, ip_addr from)
{
  RADV_TRACE(D_PACKETS, "Received RS from %I via %s",
	     from, ifa->iface->name);

  if (ifa->cf->solicited_ra_unicast && ipa_nonzero(from))
    radv_send_ra(ifa, from);
  else
    radv_iface_notify(ifa, RA_EV_RS);
}

static int
radv_rx_hook(sock *sk, uint size)
{
  struct radv_iface *ifa = sk->data;
  struct radv_proto *p = ifa->ra;

  /* We want just packets from sk->iface */
  if (sk->lifindex != sk->iface->index)
    return 1;

  if (ipa_equal(sk->faddr, sk->saddr))
    return 1;

  if (size < 8)
    return 1;

  byte *buf = sk->rbuf;

  if (buf[1] != 0)
    return 1;

  /* Validation is a bit sloppy - Hop Limit is not checked and
     length of options is ignored for RS and left to later for RA */

  switch (buf[0])
  {
  case ICMPV6_RS:
    radv_receive_rs(p, ifa, sk->faddr);
    return 1;

  case ICMPV6_RA:
    RADV_TRACE(D_PACKETS, "Received RA from %I via %s",
	       sk->faddr, ifa->iface->name);
    /* FIXME - there should be some checking of received RAs, but we just ignore them */
    return 1;

  default:
    return 1;
  }
}

static void
radv_tx_hook(sock *sk)
{
  struct radv_iface *ifa = sk->data;
  log(L_INFO "%s: TX queue ready on %s", ifa->ra->p.name, ifa->iface->name);

  /* Some RAs may be missed due to full TX queue */
  radv_iface_notify(ifa, RA_EV_RS);
}

static void
radv_err_hook(sock *sk, int err)
{
  struct radv_iface *ifa = sk->data;
  log(L_ERR "%s: Socket error on %s: %M", ifa->ra->p.name, ifa->iface->name, err);
}

int
radv_sk_open(struct radv_iface *ifa)
{
  sock *sk = sk_new(ifa->pool);
  sk->type = SK_IP;
  sk->subtype = SK_IPV6;
  sk->dport = ICMPV6_PROTO;
  sk->saddr = ifa->addr->ip;
  sk->vrf = ifa->ra->p.vrf;

  sk->ttl = 255; /* Mandatory for Neighbor Discovery packets */
  sk->rx_hook = radv_rx_hook;
  sk->tx_hook = radv_tx_hook;
  sk->err_hook = radv_err_hook;
  sk->iface = ifa->iface;
  sk->rbsize = 1024; // bufsize(ifa);
  sk->tbsize = 1024; // bufsize(ifa);
  sk->data = ifa;
  sk->flags = SKF_LADDR_RX;

  if (sk_open(sk) < 0)
    goto err;

  /* We want listen just to ICMPv6 messages of type RS and RA */
  if (sk_set_icmp6_filter(sk, ICMPV6_RS, ICMPV6_RA) < 0)
    goto err;

  if (sk_setup_multicast(sk) < 0)
    goto err;

  if (sk_join_group(sk, IP6_ALL_ROUTERS) < 0)
    goto err;

  ifa->sk = sk;
  return 1;

 err:
  sk_log_error(sk, ifa->ra->p.name);
  rfree(sk);
  return 0;
}

