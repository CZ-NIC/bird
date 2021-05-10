/*
 *	BIRD -- OSPF
 *
 *	(c) 1999--2005 Ondrej Filip <feela@network.cz>
 *	(c) 2009--2014 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2009--2014 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "ospf.h"
#include "nest/password.h"
#include "lib/md5.h"
#include "lib/mac.h"
#include "lib/socket.h"

const char * const ospf_pkt_names[] = {
  [HELLO_P]	= "HELLO",
  [DBDES_P]	= "DBDES",
  [LSREQ_P]	= "LSREQ",
  [LSUPD_P]	= "LSUPD",
  [LSACK_P]	= "LSACK",
};

void
ospf_pkt_fill_hdr(struct ospf_iface *ifa, void *buf, u8 h_type)
{
  struct ospf_proto *p = ifa->oa->po;
  struct ospf_packet *pkt;

  pkt = (struct ospf_packet *) buf;

  pkt->version = ospf_get_version(p);
  pkt->type = h_type;
  pkt->length = htons(ospf_pkt_maxsize(ifa));
  pkt->routerid = htonl(p->router_id);
  pkt->areaid = htonl(ifa->oa->areaid);
  pkt->checksum = 0;
  pkt->instance_id = ifa->instance_id;
  pkt->autype = ospf_is_v2(p) ? ifa->autype : 0;
}

/* We assume OSPFv2 in ospf_pkt_finalize() */
static void
ospf_pkt_finalize2(struct ospf_iface *ifa, struct ospf_packet *pkt, uint *plen)
{
  struct ospf_proto *p = ifa->oa->po;
  struct password_item *pass = NULL;
  union ospf_auth2 *auth = (void *) (pkt + 1);
  memset(auth, 0, sizeof(union ospf_auth2));

  /* Compatibility note: auth may contain anything if autype is
     none, but nonzero values do not work with Mikrotik OSPF */

  pkt->checksum = 0;
  pkt->autype = ifa->autype;

  switch (ifa->autype)
  {
  case OSPF_AUTH_SIMPLE:
    pass = password_find(ifa->passwords, 1);
    if (!pass)
    {
      log(L_ERR "No suitable password found for authentication");
      return;
    }
    strncpy(auth->password, pass->password, sizeof(auth->password));
    /* fallthrough */

  case OSPF_AUTH_NONE:
    {
      void *body = (void *) (auth + 1);
      uint blen = *plen - sizeof(struct ospf_packet) - sizeof(union ospf_auth2);
      pkt->checksum = ipsum_calculate(pkt, sizeof(struct ospf_packet), body, blen, NULL);
    }
    break;

  case OSPF_AUTH_CRYPT:
    pass = password_find(ifa->passwords, 0);
    if (!pass)
    {
      log(L_ERR "%s: No suitable password found for authentication", p->p.name);
      return;
    }

    /* Perhaps use random value to prevent replay attacks after
       reboot when system does not have independent RTC? */
    if (!ifa->csn)
    {
      ifa->csn = (u32) (current_real_time() TO_S);
      ifa->csn_use = current_time();
    }

    /* We must have sufficient delay between sending a packet and increasing
       CSN to prevent reordering of packets (in a network) with different CSNs */
    if ((current_time() - ifa->csn_use) > 1 S)
      ifa->csn++;

    ifa->csn_use = current_time();

    uint auth_len = mac_type_length(pass->alg);
    byte *auth_tail = ((byte *) pkt + *plen);
    *plen += auth_len;

    ASSERT(*plen < ifa->sk->tbsize);

    auth->c32.zero = 0;
    auth->c32.keyid = pass->id;
    auth->c32.len = auth_len;
    auth->c32.csn = htonl(ifa->csn);

    /* Append key for keyed hash, append padding for HMAC (RFC 5709 3.3) */
    if (pass->alg < ALG_HMAC)
      strncpy(auth_tail, pass->password, auth_len);
    else
      memset32(auth_tail, HMAC_MAGIC, auth_len / 4);

    mac_fill(pass->alg, pass->password, pass->length, (byte *) pkt, *plen, auth_tail);
    break;

  default:
    bug("Unknown authentication type");
  }
}

/*
 * Return an extra packet size that should be added to a final packet size
 */
static void
ospf_pkt_finalize3(struct ospf_iface *ifa, struct ospf_packet *pkt, uint *plen, ip_addr src)
{
  struct ospf_proto *p = ifa->oa->po;
  struct ospf_auth3 *auth = (void *) ((byte *) pkt + *plen);

  pkt->checksum = 0;
  pkt->autype = 0;

  if (ifa->autype != OSPF_AUTH_CRYPT)
    return;

  struct password_item *pass = password_find(ifa->passwords, 0);
  if (!pass)
  {
    log(L_ERR "%s: No suitable password found for authentication", p->p.name);
    return;
  }

  /* FIXME: Ensure persistence */
  p->csn64++;

  uint mac_len = mac_type_length(pass->alg);
  uint auth_len = sizeof(struct ospf_auth3) + mac_len;
  *plen += auth_len;

  ASSERT(*plen < ifa->sk->tbsize);

  memset(auth, 0, sizeof(struct ospf_auth3));
  auth->type = htons(OSPF3_AUTH_HMAC);
  auth->length = htons(auth_len);
  auth->reserved = 0;
  auth->sa_id = htons(pass->id);
  put_u64(&auth->csn, p->csn64);

  /* Initialize with src IP address padded with HMAC_MAGIC */
  put_ip6(auth->data, ipa_to_ip6(src));
  memset32(auth->data + 16, HMAC_MAGIC, (mac_len - 16) / 4);

  /* Attach OSPFv3 Cryptographic Protocol ID to the key */
  uint pass_len = pass->length + 2;
  byte *pass_key = alloca(pass_len);
  memcpy(pass_key, pass->password, pass->length);
  put_u16(pass_key + pass->length, OSPF3_CRYPTO_ID);

  mac_fill(pass->alg, pass_key, pass_len, (byte *) pkt, *plen, auth->data);
}


static int
ospf_pkt_checkauth2(struct ospf_neighbor *n, struct ospf_iface *ifa, struct ospf_packet *pkt, uint len)
{
  struct ospf_proto *p = ifa->oa->po;
  union ospf_auth2 *auth = (void *) (pkt + 1);
  struct password_item *pass = NULL;
  const char *err_dsc = NULL;
  uint err_val = 0;

  uint plen = ntohs(pkt->length);
  u8 autype = pkt->autype;

  if (autype != ifa->autype)
    DROP("authentication method mismatch", autype);

  switch (autype)
  {
  case OSPF_AUTH_NONE:
    return 1;

  case OSPF_AUTH_SIMPLE:
    pass = password_find(ifa->passwords, 1);
    if (!pass)
      DROP1("no password found");

    if (!password_verify(pass, auth->password, sizeof(auth->password)))
      DROP("wrong password", pass->id);

    return 1;

  case OSPF_AUTH_CRYPT:
    pass = password_find_by_id(ifa->passwords, auth->c32.keyid);
    if (!pass)
      DROP("no suitable password found", auth->c32.keyid);

    uint auth_len = mac_type_length(pass->alg);

    if (plen + auth->c32.len > len)
      DROP("packet length mismatch", len);

    if (auth->c32.len != auth_len)
      DROP("wrong authentication length", auth->c32.len);

    u32 rcv_csn = ntohl(auth->c32.csn);
    if (n && (rcv_csn < n->csn))
      // DROP("lower sequence number", rcv_csn);
    {
      /* We want to report both new and old CSN */
      LOG_PKT_AUTH("Authentication failed for nbr %R on %s - "
		   "lower sequence number (rcv %u, old %u)",
		   n->rid, ifa->ifname, rcv_csn, n->csn);
      return 0;
    }

    byte *auth_tail = ((byte *) pkt) + plen;
    byte *auth_data = alloca(auth_len);
    memcpy(auth_data, auth_tail, auth_len);

    /* Append key for keyed hash, append padding for HMAC (RFC 5709 3.3) */
    if (pass->alg < ALG_HMAC)
      strncpy(auth_tail, pass->password, auth_len);
    else
      memset32(auth_tail, HMAC_MAGIC, auth_len / 4);

    if (!mac_verify(pass->alg, pass->password, pass->length,
		    (byte *) pkt, plen + auth_len, auth_data))
      DROP("wrong authentication code", pass->id);

    if (n)
      n->csn = rcv_csn;

    return 1;

  default:
    bug("Unknown authentication type");
  }

drop:
  LOG_PKT_AUTH("Authentication failed for nbr %R on %s - %s (%u)",
	       (n ? n->rid : ntohl(pkt->routerid)), ifa->ifname, err_dsc, err_val);

  return 0;
}

static int
ospf_pkt_checkauth3(struct ospf_neighbor *n, struct ospf_iface *ifa, struct ospf_packet *pkt, uint len, ip_addr src)
{
  struct ospf_proto *p = ifa->oa->po;
  const char *err_dsc = NULL;
  uint err_val = 0;

  uint plen = ntohs(pkt->length);
  uint opts, lls_present, auth_present;

  /*
   * When autentication is not enabled, ignore the trailer. This is different
   * from OSPFv2, but it is necessary in order to support migration modes. Note
   * that regular authenticated packets do not have valid checksum and will be
   * dropped by OS on non-authenticated ifaces.
   */
  if (ifa->autype != OSPF_AUTH_CRYPT)
    return 1;

  switch(pkt->type)
  {
  case HELLO_P:
    opts = ospf_hello3_options(pkt);
    lls_present = opts & OPT_L_V3;
    auth_present = opts & OPT_AT;
    break;

  case DBDES_P:
    opts = ospf_dbdes3_options(pkt);
    lls_present = opts & OPT_L_V3;
    auth_present = opts & OPT_AT;
    break;

  default:
    lls_present = 0;
    auth_present = n->options & OPT_AT;
  }

  if (!auth_present)
    DROP1("missing authentication trailer");

  if (lls_present)
  {
    if ((plen + sizeof(struct ospf_lls)) > len)
      DROP("packet length mismatch", len);

    struct ospf_lls *lls = (void *) ((byte *) pkt + plen);
    plen += ntohs(lls->length);
  }

  if ((plen + sizeof(struct ospf_auth3)) > len)
    DROP("packet length mismatch", len);

  struct ospf_auth3 *auth = (void *) ((byte *) pkt + plen);

  uint rcv_auth_type = ntohs(auth->type);
  if (rcv_auth_type != OSPF3_AUTH_HMAC)
    DROP("authentication method mismatch", rcv_auth_type);

  uint rcv_auth_len = ntohs(auth->length);
  if (plen + rcv_auth_len > len)
    DROP("packet length mismatch", len);

  uint rcv_key_id = ntohs(auth->sa_id);
  struct password_item *pass = password_find_by_id(ifa->passwords, rcv_key_id);
  if (!pass)
    DROP("no suitable password found", rcv_key_id);

  uint mac_len = mac_type_length(pass->alg);
  if (rcv_auth_len != (sizeof(struct ospf_auth3) + mac_len))
    DROP("wrong authentication length", rcv_auth_len);

  uint pt = pkt->type - 1;
  u64 rcv_csn = get_u64(&auth->csn);
  if (n && (rcv_csn <= n->csn64[pt]))
  {
    /* We want to report both new and old CSN */
    LOG_PKT_AUTH("Authentication failed for nbr %R on %s - "
		 "lower sequence number (rcv %u, old %u)",
		 n->rid, ifa->ifname, (uint) rcv_csn, (uint) n->csn64[pt]);
    return 0;
  }

  /* Save the received authentication data */
  byte *auth_data = alloca(mac_len);
  memcpy(auth_data, auth->data, mac_len);

  /* Initialize with src IP address padded with HMAC_MAGIC */
  put_ip6(auth->data, ipa_to_ip6(src));
  memset32(auth->data + 16, HMAC_MAGIC, (mac_len - 16) / 4);

  /* Attach OSPFv3 Cryptographic Protocol ID to the key */
  uint pass_len = pass->length + 2;
  byte *pass_key = alloca(pass_len);
  memcpy(pass_key, pass->password, pass->length);
  put_u16(pass_key + pass->length, OSPF3_CRYPTO_ID);

  if (!mac_verify(pass->alg, pass_key, pass_len,
		  (byte *) pkt, plen + rcv_auth_len, auth_data))
    DROP("wrong authentication code", pass->id);

  if (n)
    n->csn64[pt] = rcv_csn;

  return 1;

drop:
  LOG_PKT_AUTH("Authentication failed for nbr %R on %s - %s (%u)",
	       (n ? n->rid : ntohl(pkt->routerid)), ifa->ifname, err_dsc, err_val);

  return 0;
}

/**
 * ospf_rx_hook
 * @sk: socket we received the packet.
 * @len: length of the packet
 *
 * This is the entry point for messages from neighbors. Many checks (like
 * authentication, checksums, size) are done before the packet is passed to
 * non generic functions.
 */
int
ospf_rx_hook(sock *sk, uint len)
{
  /* We want just packets from sk->iface. Unfortunately, on BSD we cannot filter
     out other packets at kernel level and we receive all packets on all sockets */
  if (sk->lifindex != sk->iface->index)
    return 1;

  DBG("OSPF: RX hook called (iface %s, src %I, dst %I)\n",
      sk->iface->name, sk->faddr, sk->laddr);

  /* Initially, the packet is associated with the 'master' iface */
  struct ospf_iface *ifa = sk->data;
  struct ospf_proto *p = ifa->oa->po;
  const char *err_dsc = NULL;
  uint err_val = 0;

  /* Should not happen */
  if (ifa->state <= OSPF_IS_LOOP)
    return 1;

  int src_local, dst_local, dst_mcast;
  src_local = ospf_ipa_local(sk->faddr, ifa->addr);
  dst_local = ipa_equal(sk->laddr, ifa->addr->ip);
  dst_mcast = ipa_equal(sk->laddr, ifa->all_routers) || ipa_equal(sk->laddr, ifa->des_routers);

  if (ospf_is_v2(p))
  {
    /* First, we eliminate packets with strange address combinations.
     * In OSPFv2, they might be for other ospf_ifaces (with different IP
     * prefix) on the same real iface, so we don't log it. We enforce
     * that (src_local || dst_local), therefore we are eliminating all
     * such cases.
     */
    if (dst_mcast && !src_local)
      return 1;
    if (!dst_mcast && !dst_local)
      return 1;

    /* Ignore my own broadcast packets */
    if (ifa->cf->real_bcast && ipa_equal(sk->faddr, ifa->addr->ip))
      return 1;
  }
  else
  {
    /* In OSPFv3, src_local and dst_local mean link-local.
     * RFC 5340 says that local (non-vlink) packets use
     * link-local src address, but does not enforce it. Strange.
     */
    if (dst_mcast && !src_local)
      LOG_PKT_WARN("Multicast packet received from non-link-local %I via %s",
		   sk->faddr, ifa->ifname);
  }

  /* Second, we check packet length, checksum, and the protocol version */
  struct ospf_packet *pkt = (void *) sk_rx_buffer(sk, &len);


  if (pkt == NULL)
    DROP("bad IP header", len);

  if (len < sizeof(struct ospf_packet))
    DROP("too short", len);

  if (pkt->version != ospf_get_version(p))
    DROP("version mismatch", pkt->version);

  uint plen = ntohs(pkt->length);
  uint hlen = sizeof(struct ospf_packet) + (ospf_is_v2(p) ? sizeof(union ospf_auth2) : 0);
  if ((plen < hlen) || ((plen % 4) != 0))
    DROP("invalid length", plen);

  if (sk->flags & SKF_TRUNCATED)
  {
    /* If we have dynamic buffers and received truncated message, we expand RX buffer */

    uint bs = plen + 256;
    bs = BIRD_ALIGN(bs, 1024);

    if (!ifa->cf->rx_buffer && (bs > sk->rbsize))
      sk_set_rbsize(sk, bs);

    DROP("truncated", plen);
  }

  if (plen > len)
    DROP("length mismatch", plen);

  if (ospf_is_v2(p) && (pkt->autype != OSPF_AUTH_CRYPT))
  {
    void *body = ((void *) pkt) + hlen;
    uint blen = plen - hlen;

    if (!ipsum_verify(pkt, sizeof(struct ospf_packet), body, blen, NULL))
      DROP("invalid checksum", ntohs(pkt->checksum));
  }

  /* Third, we resolve associated iface and handle vlinks. */

  u32 areaid = ntohl(pkt->areaid);
  u32 rid = ntohl(pkt->routerid);
  u8 instance_id = pkt->instance_id;

  if (areaid == ifa->oa->areaid)
  {
    /* Matching area ID */

    if (instance_id != ifa->instance_id)
      return 1;

    /* It is real iface, source should be local (in OSPFv2) */
    if (ospf_is_v2(p) && !src_local)
      DROP1("strange source address");

    goto found;
  }
  else if ((areaid == 0) && !dst_mcast)
  {
    /* Backbone area ID and possible vlink packet */

    if ((p->areano == 1) || !oa_is_ext(ifa->oa))
      return 1;

    struct ospf_iface *iff = NULL;
    WALK_LIST(iff, p->iface_list)
    {
      if ((iff->type == OSPF_IT_VLINK) &&
	  (iff->voa == ifa->oa) &&
	  (iff->instance_id == instance_id) &&
	  (iff->vid == rid))
      {
	/* Vlink should be UP */
	if (iff->state != OSPF_IS_PTP)
	  return 1;

	ifa = iff;
	goto found;
      }
    }

    /*
     * Cannot find matching vlink. It is either misconfigured vlink; NBMA or
     * PtMP with misconfigured area ID, or packet for some other instance (that
     * is possible even if instance_id == ifa->instance_id, because it may be
     * also vlink packet in the other instance, which is different namespace).
     */

    return 1;
  }
  else
  {
    /* Non-matching area ID but cannot be vlink packet */

    if (instance_id != ifa->instance_id)
      return 1;

    DROP("area mismatch", areaid);
  }


found:
  if (ifa->stub)	    /* This shouldn't happen */
    return 1;

  if (ipa_equal(sk->laddr, ifa->des_routers) && (ifa->sk_dr == 0))
    return 1;

  /* TTL check must be done after instance dispatch */
  if (ifa->check_ttl && (sk->rcv_ttl < 255))
    DROP("wrong TTL", sk->rcv_ttl);

  if (rid == p->router_id)
    DROP1("my own router ID");

  if (rid == 0)
    DROP1("zero router ID");

  /* Check packet type here, ospf_pkt_checkauth3() expects valid values */
  if (pkt->type < HELLO_P || pkt->type > LSACK_P)
    DROP("invalid packet type", pkt->type);

  /* In OSPFv2, neighbors are identified by either IP or Router ID, based on network type */
  uint t = ifa->type;
  struct ospf_neighbor *n;
  if (ospf_is_v2(p) && ((t == OSPF_IT_BCAST) || (t == OSPF_IT_NBMA) || (t == OSPF_IT_PTMP)))
    n = find_neigh_by_ip(ifa, sk->faddr);
  else
    n = find_neigh(ifa, rid);

  if (!n && (pkt->type != HELLO_P))
  {
    OSPF_TRACE(D_PACKETS, "Non-HELLO packet received from unknown nbr %R on %s, src %I",
	       rid, ifa->ifname, sk->faddr);
    return 1;
  }

  /* We need to ignore out-of-state packets before ospf_pkt_checkauth3() */
  if ((pkt->type > DBDES_P) && (n->state < NEIGHBOR_EXCHANGE))
  {
    OSPF_TRACE(D_PACKETS, "%s packet ignored - lesser state than Exchange",
	       ospf_pkt_names[pkt->type]);
    return 1;
  }

  /* ospf_pkt_checkauthX() has its own error logging */
  if ((ospf_is_v2(p) ?
       !ospf_pkt_checkauth2(n, ifa, pkt, len) :
       !ospf_pkt_checkauth3(n, ifa, pkt, len, sk->faddr)))
    return 1;

  switch (pkt->type)
  {
  case HELLO_P:
    ospf_receive_hello(pkt, ifa, n, sk->faddr);
    break;

  case DBDES_P:
    ospf_receive_dbdes(pkt, ifa, n);
    break;

  case LSREQ_P:
    ospf_receive_lsreq(pkt, ifa, n);
    break;

  case LSUPD_P:
    ospf_receive_lsupd(pkt, ifa, n);
    break;

  case LSACK_P:
    ospf_receive_lsack(pkt, ifa, n);
    break;
  };
  return 1;

drop:
  LOG_PKT("Bad packet from %I via %s - %s (%u)",
	  sk->faddr, ifa->ifname, err_dsc, err_val);

  return 1;
}

/*
void
ospf_tx_hook(sock * sk)
{
  struct ospf_iface *ifa= (struct ospf_iface *) (sk->data);
//  struct proto *p = (struct proto *) (ifa->oa->p);
  log(L_ERR "OSPF: TX hook called on %s", ifa->ifname);
}
*/

void
ospf_err_hook(sock * sk, int err)
{
  struct ospf_iface *ifa = (struct ospf_iface *) (sk->data);
  struct ospf_proto *p = ifa->oa->po;
  log(L_ERR "%s: Socket error on %s: %M", p->p.name, ifa->ifname, err);
}

void
ospf_verr_hook(sock *sk, int err)
{
  struct ospf_proto *p = (struct ospf_proto *) (sk->data);
  log(L_ERR "%s: Vlink socket error: %M", p->p.name, err);
}

void
ospf_send_to(struct ospf_iface *ifa, ip_addr dst)
{
  sock *sk = ifa->sk;
  struct ospf_packet *pkt = (struct ospf_packet *) sk->tbuf;
  uint plen = ntohs(pkt->length);

  if (ospf_is_v2(ifa->oa->po))
    ospf_pkt_finalize2(ifa, pkt, &plen);
  else
    ospf_pkt_finalize3(ifa, pkt, &plen, sk->saddr);

  int done = sk_send_to(sk, plen, dst, 0);
  if (!done)
    log(L_WARN "OSPF: TX queue full on %s", ifa->ifname);
}

static void
ospf_send_to_designated(struct ospf_iface *ifa)
{
  /* In case of real-broadcast mode */
  if (ipa_zero(ifa->des_routers))
  {
    if (ipa_nonzero2(ifa->drip))
      ospf_send_to(ifa, ifa->drip);

    if (ipa_nonzero2(ifa->bdrip))
      ospf_send_to(ifa, ifa->bdrip);

    return;
  }

  ospf_send_to(ifa, ifa->des_routers);
}

static void
ospf_send_to_adjacent(struct ospf_iface *ifa)
{
  struct ospf_neighbor *n;

  WALK_LIST(n, ifa->neigh_list)
    if (n->state >= NEIGHBOR_EXCHANGE)
      ospf_send_to(ifa, n->ip);
}

void
ospf_send_to_iface(struct ospf_iface *ifa)
{
  /*
   * Send packet to (relevant) neighbors on iface
   *
   * On broadcast networks, destination is either AllSPFRouters, or AllDRouters.
   * On PtP networks, destination is always AllSPFRouters. On non-broadcast
   * networks, packets are sent as unicast to every adjacent neighbor.
   */

  if (ifa->type == OSPF_IT_BCAST)
  {
    if ((ifa->state == OSPF_IS_DR) || (ifa->state == OSPF_IS_BACKUP))
      ospf_send_to_all(ifa);
    else
      ospf_send_to_designated(ifa);
  }
  else if (ifa->type == OSPF_IT_PTP)
    ospf_send_to_all(ifa);
  else /* Non-broadcast */
    ospf_send_to_adjacent(ifa);
}
