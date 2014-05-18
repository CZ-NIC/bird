/*
 *	BIRD -- Linux Netlink Interface
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/alloca.h"
#include "lib/timer.h"
#include "lib/unix.h"
#include "lib/krt.h"
#include "lib/socket.h"
#include "lib/string.h"
#include "conf/conf.h"

#include <asm/types.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#ifndef MSG_TRUNC			/* Hack: Several versions of glibc miss this one :( */
#define MSG_TRUNC 0x20
#endif

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif

/*
 *	Synchronous Netlink interface
 */

struct nl_sock
{
  int fd;
  u32 seq;
  byte *rx_buffer;			/* Receive buffer */
  struct nlmsghdr *last_hdr;		/* Recently received packet */
  unsigned int last_size;
};

#define NL_RX_SIZE 8192

static struct nl_sock nl_scan = {.fd = -1};	/* Netlink socket for synchronous scan */
static struct nl_sock nl_req  = {.fd = -1};	/* Netlink socket for requests */

static void
nl_open_sock(struct nl_sock *nl)
{
  if (nl->fd < 0)
    {
      nl->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
      if (nl->fd < 0)
	die("Unable to open rtnetlink socket: %m");
      nl->seq = now;
      nl->rx_buffer = xmalloc(NL_RX_SIZE);
      nl->last_hdr = NULL;
      nl->last_size = 0;
    }
}

static void
nl_open(void)
{
  nl_open_sock(&nl_scan);
  nl_open_sock(&nl_req);
}

static void
nl_send(struct nl_sock *nl, struct nlmsghdr *nh)
{
  struct sockaddr_nl sa;

  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  nh->nlmsg_pid = 0;
  nh->nlmsg_seq = ++(nl->seq);
  if (sendto(nl->fd, nh, nh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    die("rtnetlink sendto: %m");
  nl->last_hdr = NULL;
}

static void
nl_request_dump(int pf, int cmd)
{
  struct {
    struct nlmsghdr nh;
    struct rtgenmsg g;
  } req;
  req.nh.nlmsg_type = cmd;
  req.nh.nlmsg_len = sizeof(req);
  req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.g.rtgen_family = pf;
  nl_send(&nl_scan, &req.nh);
}

static struct nlmsghdr *
nl_get_reply(struct nl_sock *nl)
{
  for(;;)
    {
      if (!nl->last_hdr)
	{
	  struct iovec iov = { nl->rx_buffer, NL_RX_SIZE };
	  struct sockaddr_nl sa;
	  struct msghdr m = { (struct sockaddr *) &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
	  int x = recvmsg(nl->fd, &m, 0);
	  if (x < 0)
	    die("nl_get_reply: %m");
	  if (sa.nl_pid)		/* It isn't from the kernel */
	    {
	      DBG("Non-kernel packet\n");
	      continue;
	    }
	  nl->last_size = x;
	  nl->last_hdr = (void *) nl->rx_buffer;
	  if (m.msg_flags & MSG_TRUNC)
	    bug("nl_get_reply: got truncated reply which should be impossible");
	}
      if (NLMSG_OK(nl->last_hdr, nl->last_size))
	{
	  struct nlmsghdr *h = nl->last_hdr;
	  nl->last_hdr = NLMSG_NEXT(h, nl->last_size);
	  if (h->nlmsg_seq != nl->seq)
	    {
	      log(L_WARN "nl_get_reply: Ignoring out of sequence netlink packet (%x != %x)",
		  h->nlmsg_seq, nl->seq);
	      continue;
	    }
	  return h;
	}
      if (nl->last_size)
	log(L_WARN "nl_get_reply: Found packet remnant of size %d", nl->last_size);
      nl->last_hdr = NULL;
    }
}

static struct rate_limit rl_netlink_err;

static int
nl_error(struct nlmsghdr *h)
{
  struct nlmsgerr *e;
  int ec;

  if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
    {
      log(L_WARN "Netlink: Truncated error message received");
      return ENOBUFS;
    }
  e = (struct nlmsgerr *) NLMSG_DATA(h);
  ec = -e->error;
  if (ec)
    log_rl(&rl_netlink_err, L_WARN "Netlink: %s", strerror(ec));
  return ec;
}

static struct nlmsghdr *
nl_get_scan(void)
{
  struct nlmsghdr *h = nl_get_reply(&nl_scan);

  if (h->nlmsg_type == NLMSG_DONE)
    return NULL;
  if (h->nlmsg_type == NLMSG_ERROR)
    {
      nl_error(h);
      return NULL;
    }
  return h;
}

static int
nl_exchange(struct nlmsghdr *pkt)
{
  struct nlmsghdr *h;

  nl_send(&nl_req, pkt);
  for(;;)
    {
      h = nl_get_reply(&nl_req);
      if (h->nlmsg_type == NLMSG_ERROR)
	break;
      log(L_WARN "nl_exchange: Unexpected reply received");
    }
  return nl_error(h) ? -1 : 0;
}

/*
 *	Netlink attributes
 */

static int nl_attr_len;

static void *
nl_checkin(struct nlmsghdr *h, int lsize)
{
  nl_attr_len = h->nlmsg_len - NLMSG_LENGTH(lsize);
  if (nl_attr_len < 0)
    {
      log(L_ERR "nl_checkin: underrun by %d bytes", -nl_attr_len);
      return NULL;
    }
  return NLMSG_DATA(h);
}

static int
nl_parse_attrs(struct rtattr *a, struct rtattr **k, int ksize)
{
  int max = ksize / sizeof(struct rtattr *);
  bzero(k, ksize);
  while (RTA_OK(a, nl_attr_len))
    {
      if (a->rta_type < max)
	k[a->rta_type] = a;
      a = RTA_NEXT(a, nl_attr_len);
    }
  if (nl_attr_len)
    {
      log(L_ERR "nl_parse_attrs: remnant of size %d", nl_attr_len);
      return 0;
    }
  else
    return 1;
}

#define IPSIZE(ipv4) ((ipv4) ? sizeof(ip4_addr) : sizeof(ip6_addr))

static inline ip4_addr rta4_get_ip4(struct rtattr *a)
{ return ip4_get(RTA_DATA(a)); }

static inline ip6_addr rta6_get_ip6(struct rtattr *a)
{ return ip6_get(RTA_DATA(a)); }

static inline ip_addr rta4_get_ipa(struct rtattr *a)
{ return ipa_from_ip4(ip4_get(RTA_DATA(a))); }

static inline ip_addr rta6_get_ipa(struct rtattr *a)
{ return ipa_from_ip6(ip6_get(RTA_DATA(a))); }

static inline ip_addr rtax_get_ipa(struct rtattr *a, const int ipv4)
{ return ipv4 ? rta4_get_ipa(a) : rta6_get_ipa(a); }

static inline void ipax_put(void *buf, ip_addr a, const int ipv4)
{ if (ipv4) ip4_put(buf, ipa_to_ip4(a)); else ip6_put(buf, ipa_to_ip6(a)); }


void *
nl_add_attr(struct nlmsghdr *h, unsigned bufsize, unsigned code, unsigned dlen)
{
  unsigned len = RTA_LENGTH(dlen);
  unsigned pos = NLMSG_ALIGN(h->nlmsg_len);
  struct rtattr *a;

  if (pos + len > bufsize)
    bug("nl_add_attr: packet buffer overflow");
  a = (struct rtattr *)((char *)h + pos);
  a->rta_type = code;
  a->rta_len = len;
  h->nlmsg_len = pos + len;
  return RTA_DATA(a);
}

static inline void
nl_add_attr_u32(struct nlmsghdr *h, unsigned bufsize, int code, u32 data)
{
  void *buf = nl_add_attr(h, bufsize, code, 4);
  memcpy(buf, &data, 4);
}

static inline void
nl_add_attr_ipa(struct nlmsghdr *h, unsigned bufsize, int code, ip_addr ipa, const int ipv4)
{
  void *buf = nl_add_attr(h, bufsize, code, IPSIZE(ipv4));
  ipax_put(buf, ipa, ipv4);
}

#define RTNH_SIZE(ipv4) (sizeof(struct rtnexthop) + sizeof(struct rtattr) + IPSIZE(ipv4))

static inline void
add_mpnexthop(char *buf, ip_addr ipa, const int ipv4, unsigned iface, unsigned char weight)
{
  struct rtnexthop *nh = (void *) buf;
  struct rtattr *rt = (void *) (buf + sizeof(*nh));
  nh->rtnh_len = RTNH_SIZE(ipv4);
  nh->rtnh_flags = 0;
  nh->rtnh_hops = weight;
  nh->rtnh_ifindex = iface;
  rt->rta_len = sizeof(*rt) + IPSIZE(ipv4);
  rt->rta_type = RTA_GATEWAY;
  ipax_put(buf + sizeof(*nh) + sizeof(*rt), ipa, ipv4);
}


static void
nl_add_multipath(struct nlmsghdr *h, unsigned bufsize, struct mpnh *nh, const int ipv4)
{
  unsigned len = sizeof(struct rtattr);
  unsigned pos = NLMSG_ALIGN(h->nlmsg_len);
  char *buf = (char *)h + pos;
  struct rtattr *rt = (void *) buf;
  buf += len;
  
  for (; nh; nh = nh->next)
    {
      len += RTNH_SIZE(ipv4);
      if (pos + len > bufsize)
	bug("nl_add_multipath: packet buffer overflow");

      add_mpnexthop(buf, nh->gw, ipv4, nh->iface->index, nh->weight);
      buf += RTNH_SIZE(ipv4);
    }

  rt->rta_type = RTA_MULTIPATH;
  rt->rta_len = len;
  h->nlmsg_len = pos + len;
}


static struct mpnh *
nl_parse_multipath(struct krt_proto *p, struct rtattr *ra, const int ipv4)
{
  /* Temporary buffer for multicast nexthops */
  static struct mpnh *nh_buffer;
  static int nh_buf_size;	/* in number of structures */
  static int nh_buf_used;

  struct rtattr *a[RTA_CACHEINFO+1];
  struct rtnexthop *nh = RTA_DATA(ra);
  struct mpnh *rv, *first, **last;
  int len = RTA_PAYLOAD(ra);

  first = NULL;
  last = &first;
  nh_buf_used = 0;

  while (len)
    {
      /* Use RTNH_OK(nh,len) ?? */
      if ((len < sizeof(*nh)) || (len < nh->rtnh_len))
	return NULL;

      if (nh_buf_used == nh_buf_size)
      {
	nh_buf_size = nh_buf_size ? (nh_buf_size * 2) : 4;
	nh_buffer = xrealloc(nh_buffer, nh_buf_size * sizeof(struct mpnh));
      }
      *last = rv = nh_buffer + nh_buf_used++;
      rv->next = NULL;
      last = &(rv->next);

      rv->weight = nh->rtnh_hops;
      rv->iface = if_find_by_index(nh->rtnh_ifindex);
      if (!rv->iface)
	return NULL;

      /* Nonexistent RTNH_PAYLOAD ?? */
      nl_attr_len = nh->rtnh_len - RTNH_LENGTH(0);
      nl_parse_attrs(RTNH_DATA(nh), a, sizeof(a));
      if (a[RTA_GATEWAY])
	{
	  if (RTA_PAYLOAD(a[RTA_GATEWAY]) != IPSIZE(ipv4))
	    return NULL;

	  rv->gw = rtax_get_ipa(a[RTA_GATEWAY], ipv4);
	  neighbor *ng = neigh_find2(&p->p, &rv->gw, rv->iface,
				     (nh->rtnh_flags & RTNH_F_ONLINK) ? NEF_ONLINK : 0);
	  if (!ng || (ng->scope == SCOPE_HOST))
	    return NULL;
	}
      else
	return NULL;

      len -= NLMSG_ALIGN(nh->rtnh_len);
      nh = RTNH_NEXT(nh);
    }

  return first;
}


/*
 *	Scanning of interfaces
 */

static void
nl_parse_link(struct nlmsghdr *h, int scan)
{
  struct ifinfomsg *i;
  struct rtattr *a[IFLA_WIRELESS+1];
  int new = h->nlmsg_type == RTM_NEWLINK;
  struct iface f = {};
  struct iface *ifi;
  char *name;
  u32 mtu;
  unsigned int fl;

  if (!(i = nl_checkin(h, sizeof(*i))) || !nl_parse_attrs(IFLA_RTA(i), a, sizeof(a)))
    return;
  if (!a[IFLA_IFNAME] || RTA_PAYLOAD(a[IFLA_IFNAME]) < 2 ||
      !a[IFLA_MTU] || RTA_PAYLOAD(a[IFLA_MTU]) != 4)
    {
      if (scan || !a[IFLA_WIRELESS])
        log(L_ERR "nl_parse_link: Malformed message received");
      return;
    }
  name = RTA_DATA(a[IFLA_IFNAME]);
  memcpy(&mtu, RTA_DATA(a[IFLA_MTU]), sizeof(u32));

  ifi = if_find_by_index(i->ifi_index);
  if (!new)
    {
      DBG("KIF: IF%d(%s) goes down\n", i->ifi_index, name);
      if (!ifi)
	return;

      if_delete(ifi);
    }
  else
    {
      DBG("KIF: IF%d(%s) goes up (mtu=%d,flg=%x)\n", i->ifi_index, name, mtu, i->ifi_flags);
      if (ifi && strncmp(ifi->name, name, sizeof(ifi->name)-1))
	if_delete(ifi);

      strncpy(f.name, name, sizeof(f.name)-1);
      f.index = i->ifi_index;
      f.mtu = mtu;

      fl = i->ifi_flags;
      if (fl & IFF_UP)
	f.flags |= IF_ADMIN_UP;
      if (fl & IFF_LOWER_UP)
	f.flags |= IF_LINK_UP;
      if (fl & IFF_LOOPBACK)		/* Loopback */
	f.flags |= IF_MULTIACCESS | IF_LOOPBACK | IF_IGNORE;
      else if (fl & IFF_POINTOPOINT)	/* PtP */
	f.flags |= IF_MULTICAST;
      else if (fl & IFF_BROADCAST)	/* Broadcast */
	f.flags |= IF_MULTIACCESS | IF_BROADCAST | IF_MULTICAST;
      else
	f.flags |= IF_MULTIACCESS;	/* NBMA */

      ifi = if_update(&f);

      if (!scan)
	if_end_partial_update(ifi);
    }
}

static void
nl_parse_addr(struct nlmsghdr *h, int scan)
{
  struct ifaddrmsg *i;
  struct rtattr *a[IFA_ANYCAST+1];
  int new = (h->nlmsg_type == RTM_NEWADDR);
  struct ifa ifa;
  ip_addr addr;
  int ipv4 = 0;

  if (!(i = nl_checkin(h, sizeof(*i))) || !nl_parse_attrs(IFA_RTA(i), a, sizeof(a)))
    return;

  bzero(&ifa, sizeof(ifa));

  if (i->ifa_family == AF_INET)
    {
      if (!a[IFA_ADDRESS] || (RTA_PAYLOAD(a[IFA_ADDRESS]) != sizeof(ip4_addr)) ||
	  !a[IFA_LOCAL]   || (RTA_PAYLOAD(a[IFA_LOCAL]) != sizeof(ip4_addr)))
	goto malformed;

      addr = rta4_get_ipa(a[IFA_ADDRESS]);
      ifa.ip = rta4_get_ipa(a[IFA_LOCAL]);
      ipv4 = 1;
    }
  else if (i->ifa_family == AF_INET6)
    {
      if (!a[IFA_ADDRESS] || (RTA_PAYLOAD(a[IFA_ADDRESS]) != sizeof(ip6_addr)) ||
	  (a[IFA_LOCAL]   && (RTA_PAYLOAD(a[IFA_LOCAL]) != sizeof(ip6_addr))))
	goto malformed;

      addr = rta6_get_ipa(a[IFA_ADDRESS]);
      /* IFA_LOCAL can be unset for IPv6 interfaces */
      ifa.ip = a[IFA_LOCAL] ? rta6_get_ipa(a[IFA_LOCAL]) : addr;
    }
  else
    return;	/* Ignore unknown address families */

  ifa.iface = if_find_by_index(i->ifa_index);
  if (!ifa.iface)
    {
      log(L_ERR "KIF: Received address message for unknown interface %d", i->ifa_index);
      return;
    }

  if (i->ifa_flags & IFA_F_SECONDARY)
    ifa.flags |= IA_SECONDARY;

  ifa.pxlen = i->ifa_prefixlen + (ipv4 ? 96 : 0); // XXXX: Hack
  if (ifa.pxlen > BITS_PER_IP_ADDRESS)
    {
      log(L_ERR "KIF: Received invalid pxlen %d on %s",  i->ifa_prefixlen, ifa.iface->name);
      return;
    }

  if (i->ifa_prefixlen == BITS_PER_IP_ADDRESS)
    {
      ifa.prefix = ifa.brd = addr;

      /* It is either a host address or a peer address */
      if (ipa_equal(ifa.ip, addr))
	ifa.flags |= IA_HOST;
      else
	{
	  ifa.flags |= IA_PEER;
	  ifa.opposite = addr;
	}
    }
  else
    {
      ip_addr netmask = ipa_mkmask(ifa.pxlen);
      ifa.prefix = ipa_and(addr, netmask);
      ifa.brd = ipa_or(addr, ipa_not(netmask));

      if (i->ifa_prefixlen == BITS_PER_IP_ADDRESS - 1)
	ifa.opposite = ipa_opposite_m1(ifa.ip);

      if ((i->ifa_prefixlen == BITS_PER_IP_ADDRESS - 2) && ipv4)
	ifa.opposite = ipa_opposite_m2(ifa.ip);
    }

  int scope = ipa_classify(ifa.ip);
  if ((scope == IADDR_INVALID) || !(scope & IADDR_HOST))
    {
      log(L_ERR "KIF: Received invalid address %I on %s", ifa.ip, ifa.iface->name);
      return;
    }
  ifa.scope = scope & IADDR_SCOPE_MASK;

  DBG("KIF: IF%d(%s): %s IPA %I, flg %x, net %I/%d, brd %I, opp %I\n",
      ifa.iface->index, ifa.iface->name, new ? "added" : "removed",
      ifa.ip, ifa.flags, ifa.prefix, ifa.pxlen, ifa.brd, ifa.opposite);

  if (new)
    ifa_update(&ifa);
  else
    ifa_delete(&ifa);

  if (!scan)
    if_end_partial_update(ifa.iface);

  return;

 malformed:
  log(L_ERR "KIF: Received malformed address message");
  return;
}

void
kif_do_scan(struct kif_proto *p UNUSED)
{
  struct nlmsghdr *h;

  if_start_update();

  /* Is it important which AF_* is used for link-level interface scan?
     It seems that some information is available only when AF_INET is used. */

  nl_request_dump(AF_INET, RTM_GETLINK);
  while (h = nl_get_scan())
    if (h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK)
      nl_parse_link(h, 1);
    else
      log(L_DEBUG "nl_scan_ifaces: Unknown packet received (type=%d)", h->nlmsg_type);

  nl_request_dump(AF_INET, RTM_GETADDR);
  while (h = nl_get_scan())
    if (h->nlmsg_type == RTM_NEWADDR || h->nlmsg_type == RTM_DELADDR)
      nl_parse_addr(h, 1);
    else
      log(L_DEBUG "nl_scan_ifaces: Unknown packet received (type=%d)", h->nlmsg_type);

  nl_request_dump(AF_INET6, RTM_GETADDR);
  while (h = nl_get_scan())
    if (h->nlmsg_type == RTM_NEWADDR || h->nlmsg_type == RTM_DELADDR)
      nl_parse_addr(h, 1);
    else
      log(L_DEBUG "nl_scan_ifaces: Unknown packet received (type=%d)", h->nlmsg_type);

  if_end_update();
}

/*
 *	Routes
 */

static struct krt_proto *nl_table4_map[NL_NUM_TABLES];
static struct krt_proto *nl_table6_map[NL_NUM_TABLES];
#define nl_tablex_map(x) (x ? nl_table4_map : nl_table6_map)

int
krt_capable(rte *e)
{
  rta *a = e->attrs;

  if (a->cast != RTC_UNICAST)
    return 0;

  switch (a->dest)
    {
    case RTD_ROUTER:
    case RTD_DEVICE:
      if (a->iface == NULL)
	return 0;
    case RTD_BLACKHOLE:
    case RTD_UNREACHABLE:
    case RTD_PROHIBIT:
    case RTD_MULTIPATH:
      break;
    default:
      return 0;
    }
  return 1;
}

static inline int
nh_bufsize(struct mpnh *nh, const int ipv4)
{
  int rv = 0;
  for (; nh != NULL; nh = nh->next)
    rv += RTNH_SIZE(ipv4);
  return rv;
}

static int
nl_send_route(struct krt_proto *p, rte *e, struct ea_list *eattrs, int new)
{
  int ipv4 = (p->addr_type == RT_IPV4);
  eattr *ea;
  net *net = e->net;
  rta *a = e->attrs;
  struct {
    struct nlmsghdr h;
    struct rtmsg r;
    char buf[128 + nh_bufsize(a->nexthops, ipv4)];
  } r;

  DBG("nl_send_route(%F,new=%d)\n", &net->n, new);

  bzero(&r.h, sizeof(r.h));
  bzero(&r.r, sizeof(r.r));
  r.h.nlmsg_type = new ? RTM_NEWROUTE : RTM_DELROUTE;
  r.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  r.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (new ? NLM_F_CREATE|NLM_F_EXCL : 0);

  r.r.rtm_family = ipv4 ? AF_INET : AF_INET6;
  r.r.rtm_dst_len = net->n.pxlen - (ipv4 ? 96 : 0); // XXXX: Hack;
  r.r.rtm_tos = 0;
  r.r.rtm_table = KRT_CF->sys.table_id;
  r.r.rtm_protocol = RTPROT_BIRD;
  r.r.rtm_scope = RT_SCOPE_UNIVERSE;
  nl_add_attr_ipa(&r.h, sizeof(r), RTA_DST, *FPREFIX_IP(&net->n), ipv4);

  u32 metric = 0;
  if (new && e->attrs->source == RTS_INHERIT)
    metric = e->u.krt.metric;
  if (ea = ea_find(eattrs, EA_KRT_METRIC))
    metric = ea->u.data;
  if (metric != 0)
    nl_add_attr_u32(&r.h, sizeof(r), RTA_PRIORITY, metric);

  if (ea = ea_find(eattrs, EA_KRT_PREFSRC))
    nl_add_attr_ipa(&r.h, sizeof(r), RTA_PREFSRC, *(ip_addr *)ea->u.ptr->data, ipv4);

  if (ea = ea_find(eattrs, EA_KRT_REALM))
    nl_add_attr_u32(&r.h, sizeof(r), RTA_FLOW, ea->u.data);

  /* a->iface != NULL checked in krt_capable() for router and device routes */

  switch (a->dest)
    {
    case RTD_ROUTER:
      r.r.rtm_type = RTN_UNICAST;
      nl_add_attr_u32(&r.h, sizeof(r), RTA_OIF, a->iface->index);
      nl_add_attr_ipa(&r.h, sizeof(r), RTA_GATEWAY, a->gw, ipv4);
      break;
    case RTD_DEVICE:
      r.r.rtm_type = RTN_UNICAST;
      nl_add_attr_u32(&r.h, sizeof(r), RTA_OIF, a->iface->index);
      break;
    case RTD_BLACKHOLE:
      r.r.rtm_type = RTN_BLACKHOLE;
      break;
    case RTD_UNREACHABLE:
      r.r.rtm_type = RTN_UNREACHABLE;
      break;
    case RTD_PROHIBIT:
      r.r.rtm_type = RTN_PROHIBIT;
      break;
    case RTD_MULTIPATH:
      r.r.rtm_type = RTN_UNICAST;
      nl_add_multipath(&r.h, sizeof(r), a->nexthops, ipv4);
      break;
    default:
      bug("krt_capable inconsistent with nl_send_route");
    }

  return nl_exchange(&r.h);
}

void
krt_replace_rte(struct krt_proto *p, net *n, rte *new, rte *old, struct ea_list *eattrs)
{
  int err = 0;

  /*
   * NULL for eattr of the old route is a little hack, but we don't
   * get proper eattrs for old in rt_notify() anyway. NULL means no
   * extended route attributes and therefore matches if the kernel
   * route has any of them.
   */

  if (old)
    {
      // log(L_WARN "KRT: %p OLD %I/%d GW %I", p, n->n.prefix, n->n.pxlen, old->attrs->gw);
    nl_send_route(p, old, NULL, 0);
    }

  if (new)
    {
      // log(L_WARN "KRT: %p NEW %I/%d %I/%d GW %I", p, n->n.prefix, n->n.pxlen, new->attrs->gw);
    err = nl_send_route(p, new, eattrs, 1);
    }

  if (err < 0)
    n->n.flags |= KRF_SYNC_ERROR;
  else
    n->n.flags &= ~KRF_SYNC_ERROR;
}


#define SKIP(ARG...) do { DBG("KRT: Ignoring route - " ARG); return; } while(0)

static void
nl_parse_route(struct nlmsghdr *h, int scan)
{
  struct krt_proto *p;
  struct rtmsg *i;
  struct rtattr *a[RTA_CACHEINFO+1];
  int new = h->nlmsg_type == RTM_NEWROUTE;
  ip_addr dst = IPA_NONE;
  u32 oif = ~0;
  int src, ipv4, ipsize;

  if (!(i = nl_checkin(h, sizeof(*i))) || !nl_parse_attrs(RTM_RTA(i), a, sizeof(a)))
    return;

  if (i->rtm_family == AF_INET)
    ipv4 = 1;
  else if (i->rtm_family == AF_INET6)
    ipv4 = 0;
  else
    return;	/* Ignore unknown address families */

  ipsize = IPSIZE(ipv4);
  if ((a[RTA_DST] && RTA_PAYLOAD(a[RTA_DST]) != ipsize) ||
      (a[RTA_IIF] && RTA_PAYLOAD(a[RTA_IIF]) != 4) ||
      (a[RTA_OIF] && RTA_PAYLOAD(a[RTA_OIF]) != 4) ||
      (a[RTA_GATEWAY] && RTA_PAYLOAD(a[RTA_GATEWAY]) != ipsize) ||
      (a[RTA_PRIORITY] && RTA_PAYLOAD(a[RTA_PRIORITY]) != 4) ||
      (a[RTA_PREFSRC] && RTA_PAYLOAD(a[RTA_PREFSRC]) != ipsize) ||
      (a[RTA_FLOW] && RTA_PAYLOAD(a[RTA_FLOW]) != 4))
    {
      log(L_ERR "KRT: Malformed message received");
      return;
    }

  if (a[RTA_DST])
    dst = rtax_get_ipa(a[RTA_DST], ipv4);
  else if (ipv4) // XXXX hack
    dst = ipa_build4(0,0,0,0);

  if (a[RTA_OIF])
    memcpy(&oif, RTA_DATA(a[RTA_OIF]), sizeof(oif));

  DBG("KRT: Got %I/%d, type=%d, oif=%d, table=%d, prid=%d\n", dst, i->rtm_dst_len, i->rtm_type, oif, i->rtm_table, i->rtm_protocol);

  p = nl_tablex_map(ipv4)[i->rtm_table];
  if (!p)				/* We don't know this table */
    SKIP("unknown table %d\n", i->rtm_table);

  if (a[RTA_IIF])			/* We don't support IIF */
    SKIP("IIF set\n");

  if (i->rtm_tos != 0)			/* We don't support TOS */
    SKIP("TOS %02x\n", i->rtm_tos);

  if (scan && !new)
    SKIP("RTM_DELROUTE in scan\n");

  int c = ipa_classify_net(dst);
  if ((c < 0) || !(c & IADDR_HOST) || ((c & IADDR_SCOPE_MASK) <= SCOPE_LINK))
    SKIP("strange class/scope\n");

  // ignore rtm_scope, it is not a real scope
  // if (i->rtm_scope != RT_SCOPE_UNIVERSE)
  //   SKIP("scope %u\n", i->rtm_scope);

  switch (i->rtm_protocol)
    {
    case RTPROT_UNSPEC:
      SKIP("proto unspec\n");

    case RTPROT_REDIRECT:
      src = KRT_SRC_REDIRECT;
      break;

    case RTPROT_KERNEL:
      src = KRT_SRC_KERNEL;
      return;

    case RTPROT_BIRD:
      if (!scan)
	SKIP("echo\n");
      src = KRT_SRC_BIRD;
      break;

    case RTPROT_BOOT:
    default:
      src = KRT_SRC_ALIEN;
    }

  int pxlen = i->rtm_dst_len + (ipv4 ? 96 : 0);  // XXXX: Hack
  net *net = net_get(p->p.table, dst, pxlen);

  rta ra = {
    .src= p->p.main_source,
    .source = RTS_INHERIT,
    .scope = SCOPE_UNIVERSE,
    .cast = RTC_UNICAST
  };

  switch (i->rtm_type)
    {
    case RTN_UNICAST:

      if (a[RTA_MULTIPATH])
	{
	  ra.dest = RTD_MULTIPATH;
	  ra.nexthops = nl_parse_multipath(p, a[RTA_MULTIPATH], ipv4);
	  if (!ra.nexthops)
	    {
	      log(L_ERR "KRT: Received strange multipath route %F", &net->n);
	      return;
	    }
	    
	  break;
	}

      ra.iface = if_find_by_index(oif);
      if (!ra.iface)
	{
	  log(L_ERR "KRT: Received route %F with unknown ifindex %u", &net->n, oif);
	  return;
	}

      if (a[RTA_GATEWAY])
	{
	  neighbor *ng;
	  ra.dest = RTD_ROUTER;
	  ra.gw = rtax_get_ipa(a[RTA_GATEWAY], ipv4);

#ifdef IPV6
	  /* Silently skip strange 6to4 routes */
	  if (ipa_in_net(ra.gw, IPA_NONE, 96))
	    return;
#endif

	  ng = neigh_find2(&p->p, &ra.gw, ra.iface,
			   (i->rtm_flags & RTNH_F_ONLINK) ? NEF_ONLINK : 0);
	  if (!ng || (ng->scope == SCOPE_HOST))
	    {
	      log(L_ERR "KRT: Received route %F with strange next-hop %I",
		  &net->n, ra.gw);
	      return;
	    }
	}
      else
	ra.dest = RTD_DEVICE;

      break;
    case RTN_BLACKHOLE:
      ra.dest = RTD_BLACKHOLE;
      break;
    case RTN_UNREACHABLE:
      ra.dest = RTD_UNREACHABLE;
      break;
    case RTN_PROHIBIT:
      ra.dest = RTD_PROHIBIT;
      break;
    /* FIXME: What about RTN_THROW? */
    default:
      SKIP("type %d\n", i->rtm_type);
      return;
    }

  rte *e = rte_get_temp(&ra);
  e->net = net;
  e->u.krt.src = src;
  e->u.krt.proto = i->rtm_protocol;
  e->u.krt.type = i->rtm_type;

  if (a[RTA_PRIORITY])
    memcpy(&e->u.krt.metric, RTA_DATA(a[RTA_PRIORITY]), sizeof(e->u.krt.metric)); 
  else
    e->u.krt.metric = 0;

  if (a[RTA_PREFSRC])
    {
      ip_addr ps = rtax_get_ipa(a[RTA_PREFSRC], ipv4);

      ea_list *ea = alloca(sizeof(ea_list) + sizeof(eattr));
      ea->next = ra.eattrs;
      ra.eattrs = ea;
      ea->flags = EALF_SORTED;
      ea->count = 1;
      ea->attrs[0].id = EA_KRT_PREFSRC;
      ea->attrs[0].flags = 0;
      ea->attrs[0].type = EAF_TYPE_IP_ADDRESS;
      ea->attrs[0].u.ptr = alloca(sizeof(struct adata) + sizeof(ps));
      ea->attrs[0].u.ptr->length = sizeof(ps);
      memcpy(ea->attrs[0].u.ptr->data, &ps, sizeof(ps));
    }

  if (a[RTA_FLOW])
    {
      ea_list *ea = alloca(sizeof(ea_list) + sizeof(eattr));
      ea->next = ra.eattrs;
      ra.eattrs = ea;
      ea->flags = EALF_SORTED;
      ea->count = 1;
      ea->attrs[0].id = EA_KRT_REALM;
      ea->attrs[0].flags = 0;
      ea->attrs[0].type = EAF_TYPE_INT;
      memcpy(&ea->attrs[0].u.data, RTA_DATA(a[RTA_FLOW]), 4);
    }

  if (scan)
    krt_got_route(p, e);
  else
    krt_got_route_async(p, e, new);
}

void
krt_do_scan(struct krt_proto *p UNUSED)	/* CONFIG_ALL_TABLES_AT_ONCE => p is NULL */
{
  struct nlmsghdr *h;

  nl_request_dump(AF_INET, RTM_GETROUTE);
  while (h = nl_get_scan())
    if (h->nlmsg_type == RTM_NEWROUTE || h->nlmsg_type == RTM_DELROUTE)
      nl_parse_route(h, 1);
    else
      log(L_DEBUG "nl_scan_fire: Unknown packet received (type=%d)", h->nlmsg_type);

  nl_request_dump(AF_INET6, RTM_GETROUTE);
  while (h = nl_get_scan())
    if (h->nlmsg_type == RTM_NEWROUTE || h->nlmsg_type == RTM_DELROUTE)
      nl_parse_route(h, 1);
    else
      log(L_DEBUG "nl_scan_fire: Unknown packet received (type=%d)", h->nlmsg_type);
}

/*
 *	Asynchronous Netlink interface
 */

static sock *nl_async_sk;		/* BIRD socket for asynchronous notifications */
static byte *nl_async_rx_buffer;	/* Receive buffer */

static void
nl_async_msg(struct nlmsghdr *h)
{
  switch (h->nlmsg_type)
    {
    case RTM_NEWROUTE:
    case RTM_DELROUTE:
      DBG("KRT: Received async route notification (%d)\n", h->nlmsg_type);
      nl_parse_route(h, 0);
      break;
    case RTM_NEWLINK:
    case RTM_DELLINK:
      DBG("KRT: Received async link notification (%d)\n", h->nlmsg_type);
      nl_parse_link(h, 0);
      break;
    case RTM_NEWADDR:
    case RTM_DELADDR:
      DBG("KRT: Received async address notification (%d)\n", h->nlmsg_type);
      nl_parse_addr(h, 0);
      break;
    default:
      DBG("KRT: Received unknown async notification (%d)\n", h->nlmsg_type);
    }
}

static int
nl_async_hook(sock *sk, int size UNUSED)
{
  struct iovec iov = { nl_async_rx_buffer, NL_RX_SIZE };
  struct sockaddr_nl sa;
  struct msghdr m = { (struct sockaddr *) &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
  struct nlmsghdr *h;
  int x;
  unsigned int len;

  x = recvmsg(sk->fd, &m, 0);
  if (x < 0)
    {
      if (errno == ENOBUFS)
	{
	  /*
	   *  Netlink reports some packets have been thrown away.
	   *  One day we might react to it by asking for route table
	   *  scan in near future.
	   */
	  return 1;	/* More data are likely to be ready */
	}
      else if (errno != EWOULDBLOCK)
	log(L_ERR "Netlink recvmsg: %m");
      return 0;
    }
  if (sa.nl_pid)		/* It isn't from the kernel */
    {
      DBG("Non-kernel packet\n");
      return 1;
    }
  h = (void *) nl_async_rx_buffer;
  len = x;
  if (m.msg_flags & MSG_TRUNC)
    {
      log(L_WARN "Netlink got truncated asynchronous message");
      return 1;
    }
  while (NLMSG_OK(h, len))
    {
      nl_async_msg(h);
      h = NLMSG_NEXT(h, len);
    }
  if (len)
    log(L_WARN "nl_async_hook: Found packet remnant of size %d", len);
  return 1;
}

static void
nl_open_async(void)
{
  sock *sk;
  struct sockaddr_nl sa;
  int fd;

  if (nl_async_sk)
    return;

  DBG("KRT: Opening async netlink socket\n");

  fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd < 0)
    {
      log(L_ERR "Unable to open asynchronous rtnetlink socket: %m");
      return;
    }

  bzero(&sa, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  sa.nl_groups = RTMGRP_LINK |
    RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE |
    RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE;
  if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
    {
      log(L_ERR "Unable to bind asynchronous rtnetlink socket: %m");
      close(fd);
      return;
    }

  nl_async_rx_buffer = xmalloc(NL_RX_SIZE);

  sk = nl_async_sk = sk_new(krt_pool);
  sk->type = SK_MAGIC;
  sk->rx_hook = nl_async_hook;
  sk->fd = fd;
  if (sk_open(sk) < 0)
    bug("Netlink: sk_open failed");
}

/*
 *	Interface to the UNIX krt module
 */

void
krt_sys_start(struct krt_proto *p)
{
  nl_tablex_map(p->addr_type == RT_IPV4)[KRT_CF->sys.table_id] = p;

  nl_open();
  nl_open_async();
}

void
krt_sys_shutdown(struct krt_proto *p UNUSED)
{
  nl_tablex_map(p->addr_type == RT_IPV4)[KRT_CF->sys.table_id] = NULL;
}

int
krt_sys_reconfigure(struct krt_proto *p UNUSED, struct krt_config *n, struct krt_config *o)
{
  return n->sys.table_id == o->sys.table_id;
}

static u32 nl_table4_cf[(NL_NUM_TABLES+31) / 32];
static u32 nl_table6_cf[(NL_NUM_TABLES+31) / 32];

void
krt_sys_preconfig(struct config *c UNUSED)
{
  bzero(&nl_table4_cf, sizeof(nl_table4_cf));
  bzero(&nl_table6_cf, sizeof(nl_table6_cf));
}

void
krt_sys_postconfig(struct krt_config *x)
{
  u32 *tbl = (x->c.table->addr_type == RT_IPV4) ? nl_table4_cf : nl_table6_cf;
  u32 id = x->sys.table_id;

  if (tbl[id/32] & (1 << (id%32)))
    cf_error("Multiple kernel syncers defined for table #%d", id);

  tbl[id/32] |= (1 << (id%32));
}

void
krt_sys_init_config(struct krt_config *cf)
{
  cf->sys.table_id = RT_TABLE_MAIN;
}

void
krt_sys_copy_config(struct krt_config *d, struct krt_config *s)
{
  d->sys.table_id = s->sys.table_id;
}



void
kif_sys_start(struct kif_proto *p UNUSED)
{
  nl_open();
  nl_open_async();
}

void
kif_sys_shutdown(struct kif_proto *p UNUSED)
{
}
