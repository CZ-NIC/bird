/*
 *	BIRD -- Routing Information Protocol (RIP)
 *
 *	(c) 1998--1999 Pavel Machek <pavel@ucw.cz>
 *	(c) 2004--2013 Ondrej Filip <feela@network.cz>
 *	(c) 2009--2015 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2009--2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

#include "rip.h"
#include "lib/mac.h"


#define RIP_CMD_REQUEST		1	/* want info */
#define RIP_CMD_RESPONSE	2	/* responding to request */

#define RIP_CMD_UPDATE_REQUEST	9
#define RIP_CMD_UPDATE_RESPONSE	10
#define RIP_CMD_UPDATE_ACK	11

#define RIP_BLOCK_LENGTH	20
#define RIP_PASSWD_LENGTH	16

#define RIP_AF_IPV4		2
#define RIP_AF_AUTH		0xffff

#define RIP_UPDATE_VERSION	1


/* RIP packet header */
struct rip_packet
{
  u8 command;
  u8 version;
  u16 unused;
};

/* Triggered RIP update header (RFC 2091) */
struct rip_update_hdr
{
  u8 version;
  u8 flush;
  u16 seqnum;
};

/* RTE block for RIPv2 */
struct rip_block_v2
{
  u16 family;
  u16 tag;
  ip4_addr network;
  ip4_addr netmask;
  ip4_addr next_hop;
  u32 metric;
};

/* RTE block for RIPng */
struct rip_block_ng
{
  ip6_addr prefix;
  u16 tag;
  u8 pxlen;
  u8 metric;
};

/* Authentication block for RIPv2 */
struct rip_block_auth
{
  u16 must_be_ffff;
  u16 auth_type;
  union {
    char password[16];
    struct {
      u16 packet_len;
      u8 key_id;
      u8 auth_len;
      u32 seq_num;
      u32 unused1;
      u32 unused2;
    };
  };
};

/* Authentication tail, RFC 4822 */
struct rip_auth_tail
{
  u16 must_be_ffff;
  u16 must_be_0001;
  byte auth_data[0];
};

/* Internal representation of RTE block data */
struct rip_block
{
  net_addr net;
  u32 metric;
  u16 tag;
  u16 no_af;
  ip_addr next_hop;
};

static int
rip_send_ack(struct rip_proto *p, struct rip_iface *ifa, uint flush, uint seqnum);

#define DROP(DSC,VAL) do { err_dsc = DSC; err_val = VAL; goto drop; } while(0)
#define DROP1(DSC) do { err_dsc = DSC; goto drop; } while(0)
#define SKIP(DSC) do { err_dsc = DSC; goto skip; } while(0)

#define LOG_PKT(msg, args...) \
  log_rl(&p->log_pkt_tbf, L_REMOTE "%s: " msg, p->p.name, args)

#define LOG_PKT_AUTH(msg, args...) \
  log_rl(&p->log_pkt_tbf, L_AUTH "%s: " msg, p->p.name, args)

#define LOG_RTE(msg, args...) \
  log_rl(&p->log_rte_tbf, L_REMOTE "%s: " msg, p->p.name, args)


static inline void * rip_tx_buffer(struct rip_iface *ifa)
{ return ifa->sk->tbuf; }

static inline uint
rip_pkt_hdrlen(struct rip_iface *ifa)
{
  return sizeof(struct rip_packet) +
    (ifa->cf->demand_circuit ? sizeof(struct rip_update_hdr) : 0) +
    (ifa->cf->auth_type ? RIP_BLOCK_LENGTH : 0);
}

static inline struct rip_update_hdr *
rip_get_update_hdr(struct rip_packet *pkt)
{
  return (void *) ((byte *) pkt + sizeof(struct rip_packet));
}

static inline struct rip_block_auth *
rip_get_auth_block(struct rip_iface *ifa, struct rip_packet *pkt)
{
  return (void *) ((byte *) pkt + sizeof(struct rip_packet) +
		   (ifa->cf->demand_circuit ? sizeof(struct rip_update_hdr) : 0));
}


static inline void
rip_put_block(struct rip_proto *p, byte *pos, struct rip_block *rte)
{
  if (rip_is_v2(p))
  {
    struct rip_block_v2 *block = (void *) pos;
    block->family = rte->no_af ? 0 : htons(RIP_AF_IPV4);
    block->tag = htons(rte->tag);
    block->network = ip4_hton(net4_prefix(&rte->net));
    block->netmask = ip4_hton(ip4_mkmask(net4_pxlen(&rte->net)));
    block->next_hop = ip4_hton(ipa_to_ip4(rte->next_hop));
    block->metric = htonl(rte->metric);
  }
  else /* RIPng */
  {
    struct rip_block_ng *block = (void *) pos;
    block->prefix = ip6_hton(net6_prefix(&rte->net));
    block->tag = htons(rte->tag);
    block->pxlen = net6_pxlen(&rte->net);
    block->metric = rte->metric;
  }
}

static inline void
rip_put_next_hop(struct rip_proto *p UNUSED, byte *pos, struct rip_block *rte)
{
  struct rip_block_ng *block = (void *) pos;
  block->prefix = ip6_hton(ipa_to_ip6(rte->next_hop));
  block->tag = 0;
  block->pxlen = 0;
  block->metric = 0xff;
}

static inline int
rip_get_block(struct rip_proto *p, byte *pos, struct rip_block *rte)
{
  if (rip_is_v2(p))
  {
    struct rip_block_v2 *block = (void *) pos;

    /* Skip blocks with strange AF, including authentication blocks */
    if (block->family != (rte->no_af ? 0 : htons(RIP_AF_IPV4)))
      return 0;

    uint pxlen = ip4_masklen(ip4_ntoh(block->netmask));
    net_fill_ip4(&rte->net, ip4_ntoh(block->network), pxlen);
    rte->metric = ntohl(block->metric);
    rte->tag = ntohs(block->tag);
    rte->next_hop = ipa_from_ip4(ip4_ntoh(block->next_hop));

    return 1;
  }
  else /* RIPng */
  {
    struct rip_block_ng *block = (void *) pos;

    /* Handle and skip next hop blocks */
    if (block->metric == 0xff)
    {
      rte->next_hop = ipa_from_ip6(ip6_ntoh(block->prefix));
      if (!ipa_is_link_local(rte->next_hop)) rte->next_hop = IPA_NONE;
      return 0;
    }

    uint pxlen = (block->pxlen <= IP6_MAX_PREFIX_LENGTH) ? block->pxlen : 255;
    net_fill_ip6(&rte->net, ip6_ntoh(block->prefix), pxlen);
    rte->metric = block->metric;
    rte->tag = ntohs(block->tag);
    /* rte->next_hop is deliberately kept unmodified */;

    return 1;
  }
}

static inline void
rip_update_csn(struct rip_proto *p UNUSED, struct rip_iface *ifa)
{
  /*
   * We update crypto sequence numbers at the beginning of update session to
   * avoid issues with packet reordering, so packets inside one update session
   * have the same CSN. We are using real time, but enforcing monotonicity.
   */
  if (ifa->cf->auth_type == RIP_AUTH_CRYPTO)
  {
    u32 now_real = (u32) (current_real_time() TO_S);
    ifa->csn = (ifa->csn < now_real) ? now_real : ifa->csn + 1;
  }
}

static inline void
rip_fill_header(struct rip_iface *ifa, struct rip_packet *pkt, uint cmd)
{
  *pkt = (struct rip_packet) {
    .command = cmd,
    .version = ifa->cf->version
  };
}

static inline void
rip_fill_update_hdr(struct rip_packet *pkt, uint flush, uint seqnum)
{
  struct rip_update_hdr *hdr = rip_get_update_hdr(pkt);

  *hdr = (struct rip_update_hdr) {
    .version = RIP_UPDATE_VERSION,
    .flush = flush,
    .seqnum = htons(seqnum)
  };
}

static void
rip_fill_authentication(struct rip_proto *p, struct rip_iface *ifa, struct rip_packet *pkt, uint *plen)
{
  struct rip_block_auth *auth = rip_get_auth_block(ifa, pkt);
  struct password_item *pass = password_find(ifa->cf->passwords, 0);

  if (!pass)
  {
    /* FIXME: This should not happen */
    log(L_ERR "%s: No suitable password found for authentication", p->p.name);
    memset(auth, 0, sizeof(struct rip_block_auth));
    return;
  }

  switch (ifa->cf->auth_type)
  {
  case RIP_AUTH_PLAIN:
    auth->must_be_ffff = htons(0xffff);
    auth->auth_type = htons(RIP_AUTH_PLAIN);
    strncpy(auth->password, pass->password, RIP_PASSWD_LENGTH);
    return;

  case RIP_AUTH_CRYPTO:
    auth->must_be_ffff = htons(0xffff);
    auth->auth_type = htons(RIP_AUTH_CRYPTO);
    auth->packet_len = htons(*plen);
    auth->key_id = pass->id;
    auth->auth_len = mac_type_length(pass->alg);
    auth->seq_num = ifa->csn_ready ? htonl(ifa->csn) : 0;
    auth->unused1 = 0;
    auth->unused2 = 0;
    ifa->csn_ready = 1;

    if (pass->alg < ALG_HMAC)
      auth->auth_len += sizeof(struct rip_auth_tail);

    /*
     * Note that RFC 4822 is unclear whether auth_len should cover whole
     * authentication trailer or just auth_data length.
     *
     * FIXME: We should use just auth_data length by default. Currently we put
     * the whole auth trailer length in keyed hash case to keep old behavior,
     * but we put just auth_data length in the new HMAC case. Note that Quagga
     * has config option for this.
     *
     * Crypto sequence numbers are increased by sender in rip_update_csn().
     * First CSN should be zero, this is handled by csn_ready.
     */

    struct rip_auth_tail *tail = (void *) ((byte *) pkt + *plen);
    tail->must_be_ffff = htons(0xffff);
    tail->must_be_0001 = htons(0x0001);

    uint auth_len = mac_type_length(pass->alg);
    *plen += sizeof(struct rip_auth_tail) + auth_len;

    /* Append key for keyed hash, append padding for HMAC (RFC 4822 2.5) */
    if (pass->alg < ALG_HMAC)
      strncpy(tail->auth_data, pass->password, auth_len);
    else
      memset32(tail->auth_data, HMAC_MAGIC, auth_len / 4);

    mac_fill(pass->alg, pass->password, pass->length,
	     (byte *) pkt, *plen, tail->auth_data);
    return;

  default:
    bug("Unknown authentication type");
  }
}

static int
rip_check_authentication(struct rip_proto *p, struct rip_iface *ifa, struct rip_packet *pkt, uint *plen, uint hdr_len, struct rip_neighbor *n)
{
  struct rip_block_auth *auth = (void *) ((byte *) pkt + hdr_len);
  struct password_item *pass = NULL;
  const char *err_dsc = NULL;
  uint err_val = 0;
  uint auth_type = 0;

  /* Check for authentication entry */
  if ((*plen >= (hdr_len + sizeof(struct rip_block_auth))) &&
      (auth->must_be_ffff == htons(0xffff)))
    auth_type = ntohs(auth->auth_type);

  if (auth_type != ifa->cf->auth_type)
    DROP("authentication method mismatch", auth_type);

  switch (auth_type)
  {
  case RIP_AUTH_NONE:
    return 1;

  case RIP_AUTH_PLAIN:
    pass = password_find_by_value(ifa->cf->passwords, auth->password, RIP_PASSWD_LENGTH);
    if (!pass)
      DROP1("wrong password");

    return 1;

  case RIP_AUTH_CRYPTO:
    pass = password_find_by_id(ifa->cf->passwords, auth->key_id);
    if (!pass)
      DROP("no suitable password found", auth->key_id);

    uint data_len = ntohs(auth->packet_len);
    uint auth_len = mac_type_length(pass->alg);
    uint auth_len2 = sizeof(struct rip_auth_tail) + auth_len;

    /*
     * Ideally, first check should be check for internal consistency:
     *   (data_len + sizeof(struct rip_auth_tail) + auth->auth_len) != *plen
     *
     * Second one should check expected code length:
     *   auth->auth_len != auth_len
     *
     * But as auth->auth_len has two interpretations, we simplify this
     */

    if (data_len + auth_len2 != *plen)
      DROP("packet length mismatch", *plen);

    /* Warning: two interpretations of auth_len field */
    if ((auth->auth_len != auth_len) && (auth->auth_len != auth_len2))
      DROP("wrong authentication length", auth->auth_len);

    struct rip_auth_tail *tail = (void *) ((byte *) pkt + data_len);
    if ((tail->must_be_ffff != htons(0xffff)) || (tail->must_be_0001 != htons(0x0001)))
      DROP1("authentication trailer is missing");

    /* Accept higher sequence number, or zero if connectivity is lost */
    /* FIXME: sequence number must be password/SA specific */
    u32 rcv_csn = ntohl(auth->seq_num);
    if ((rcv_csn < n->csn) && (rcv_csn || n->uc))
    {
      /* We want to report both new and old CSN */
      LOG_PKT_AUTH("Authentication failed for %I on %s - "
		   "lower sequence number (rcv %u, old %u)",
		   n->nbr->addr, ifa->iface->name, rcv_csn, n->csn);
      return 0;
    }

    byte *auth_data = alloca(auth_len);
    memcpy(auth_data, tail->auth_data, auth_len);

    /* Append key for keyed hash, append padding for HMAC (RFC 4822 2.5) */
    if (pass->alg < ALG_HMAC)
      strncpy(tail->auth_data, pass->password, auth_len);
    else
      memset32(tail->auth_data, HMAC_MAGIC, auth_len / 4);

    if (!mac_verify(pass->alg, pass->password, pass->length,
		    (byte *) pkt, *plen, auth_data))
      DROP("wrong authentication code", pass->id);

    *plen = data_len;
    n->csn = rcv_csn;

    return 1;
  }

drop:
  LOG_PKT_AUTH("Authentication failed for %I on %s - %s (%u)",
	       n->nbr->addr, ifa->iface->name, err_dsc, err_val);

  return 0;
}

static inline int
rip_send_to(struct rip_proto *p, struct rip_iface *ifa, struct rip_packet *pkt, uint plen, ip_addr dst)
{
  if (ifa->cf->auth_type)
    rip_fill_authentication(p, ifa, pkt, &plen);

  return sk_send_to(ifa->sk, plen, dst, 0);
}

static inline void
rip_kick_rxmt_timer(struct rip_iface *ifa)
{
  if (! tm_active(ifa->rxmt_timer))
    tm_start(ifa->rxmt_timer, ifa->cf->rxmt_time);
}


void
rip_send_request(struct rip_proto *p, struct rip_iface *ifa)
{
  struct rip_packet *pkt = rip_tx_buffer(ifa);
  byte *pos = (byte *) pkt + rip_pkt_hdrlen(ifa);

  rip_fill_header(ifa, pkt, RIP_CMD_REQUEST);

  if (ifa->cf->demand_circuit)
  {
    pkt->command = RIP_CMD_UPDATE_REQUEST;
    rip_fill_update_hdr(pkt, 0, 0);

    /* Must be acknowledged by update response */
    ifa->req_pending = 1;
    rip_kick_rxmt_timer(ifa);
  }

  struct rip_block b = { .no_af = 1, .metric = p->infinity };
  rip_put_block(p, pos, &b);
  pos += RIP_BLOCK_LENGTH;

  rip_update_csn(p, ifa);

  TRACE(D_PACKETS, "Sending request via %s", ifa->iface->name);
  rip_send_to(p, ifa, pkt, pos - (byte *) pkt, ifa->addr);
}

static void
rip_receive_request(struct rip_proto *p, struct rip_iface *ifa, struct rip_packet *pkt, uint plen, struct rip_neighbor *from)
{
  TRACE(D_PACKETS, "Request received from %I on %s", from->nbr->addr, ifa->iface->name);

  byte *pos = (byte *) pkt + rip_pkt_hdrlen(ifa);

  /* We expect one regular block */
  if (plen != (rip_pkt_hdrlen(ifa) + RIP_BLOCK_LENGTH))
    return;

  struct rip_block b = { .no_af = 1 };

  if (!rip_get_block(p, pos, &b))
    return;

  /* Special case - infinity metric, for RIPng also zero prefix */
  if ((b.metric != p->infinity) ||
      (rip_is_ng(p) && !net_zero_ip6((net_addr_ip6 *) &b.net)))
    return;

  /* We do nothing if TX is already active */
  if (ifa->tx_active)
  {
    TRACE(D_EVENTS, "Skipping request from %I on %s, TX is busy", from->nbr->addr, ifa->iface->name);
    return;
  }

  if (!ifa->cf->passive)
    rip_send_table(p, ifa, from->nbr->addr, 0);
}


static int
rip_send_response(struct rip_proto *p, struct rip_iface *ifa)
{
  if (! ifa->tx_active)
    return 0;

  /* In demand circuit mode, we may wait for ACK */
  if (ifa->tx_pending)
    return 0;

  struct rip_packet *pkt = rip_tx_buffer(ifa);
  byte *pos = (byte *) pkt + rip_pkt_hdrlen(ifa);
  byte *max = (byte *) pkt + ifa->tx_plen -
    (rip_is_v2(p) ? RIP_BLOCK_LENGTH : 2*RIP_BLOCK_LENGTH);
  ip_addr last_next_hop = IPA_NONE;
  btime now_ = current_time();
  int send = 0;

  rip_fill_header(ifa, pkt, RIP_CMD_RESPONSE);

  if (ifa->cf->demand_circuit)
  {
    pkt->command = RIP_CMD_UPDATE_RESPONSE;
    rip_fill_update_hdr(pkt, ifa->tx_flush, ifa->tx_seqnum);
  }

  FIB_ITERATE_START(&p->rtable, &ifa->tx_fit, struct rip_entry, en)
  {
    /* Dummy entries */
    if (!en->valid)
      goto next_entry;

    /* Stale entries that should be removed */
    if ((en->valid == RIP_ENTRY_STALE) &&
	((en->changed + ifa->cf->garbage_time) <= now_))
      goto next_entry;

    /* Triggered updates */
    if (en->changed < ifa->tx_changed)
      goto next_entry;

    /* Not enough space for current entry */
    if (pos > max)
    {
      FIB_ITERATE_PUT(&ifa->tx_fit);
      goto send_pkt;
    }

    struct rip_block rte = {
      .metric = en->metric,
      .tag = en->tag
    };

    net_copy(&rte.net, en->n.addr);

    if (en->iface == ifa->iface)
      rte.next_hop = en->next_hop;

    if (rip_is_v2(p) && (ifa->cf->version == RIP_V1))
    {
      /* Skipping subnets (i.e. not hosts, classful networks or default route) */
      if (ip4_masklen(ip4_class_mask(net4_prefix(&rte.net))) != rte.net.pxlen)
	goto next_entry;

      rte.tag = 0;
      rte.net.pxlen = 0;
      rte.next_hop = IPA_NONE;
    }

    /* Split horizon */
    if (en->from == ifa->iface && ifa->cf->split_horizon)
    {
      if (ifa->cf->poison_reverse)
      {
	rte.metric = p->infinity;
	rte.next_hop = IPA_NONE;
      }
      else
	goto next_entry;
    }

    // TRACE(D_PACKETS, "    %N -> %I metric %d", &rte.net, rte.next_hop, rte.metric);

    /* RIPng next hop entry */
    if (rip_is_ng(p) && !ipa_equal(rte.next_hop, last_next_hop))
    {
      last_next_hop = rte.next_hop;
      rip_put_next_hop(p, pos, &rte);
      pos += RIP_BLOCK_LENGTH;
    }

    rip_put_block(p, pos, &rte);
    pos += RIP_BLOCK_LENGTH;
    send = 1;

  next_entry: ;
  }
  FIB_ITERATE_END;

  if (send)
  {
    FIB_ITERATE_PUT_END(&ifa->tx_fit);
    goto send_pkt;
  }

  /* Do not send empty packet */

  ifa->tx_active = 0;

  /* Unlink second iterator */
  FIB_ITERATE_UNLINK(&ifa->tx_done, &p->rtable);

  return 0;

send_pkt:

  /* Waiting for ack or timeout */
  if (ifa->cf->demand_circuit)
  {
    ifa->tx_pending = 1;
    rip_kick_rxmt_timer(ifa);
  }

  TRACE(D_PACKETS, "Sending response via %s", ifa->iface->name);
  return rip_send_to(p, ifa, pkt, pos - (byte *) pkt, ifa->tx_addr);
}

/**
 * rip_send_table - RIP interface timer hook
 * @p: RIP instance
 * @ifa: RIP interface
 * @addr: destination IP address
 * @changed: time limit for triggered updates
 *
 * The function activates an update session and starts sending routing update
 * packets (using rip_send_response()). The session may be finished during the
 * call or may continue in rip_tx_hook() until all appropriate routes are
 * transmitted. Note that there may be at most one active update session per
 * interface, the function will terminate the old active session before
 * activating the new one.
 */
void
rip_send_table(struct rip_proto *p, struct rip_iface *ifa, ip_addr addr, btime changed)
{
  DBG("RIP: Opening TX session to %I on %s\n", addr, ifa->iface->name);

  rip_reset_tx_session(p, ifa);

  ifa->tx_active = 1;
  ifa->tx_addr = addr;
  ifa->tx_changed = changed;
  FIB_ITERATE_INIT(&ifa->tx_fit, &p->rtable);
  FIB_ITERATE_INIT(&ifa->tx_done, &p->rtable);

  if (ifa->cf->demand_circuit)
    ifa->tx_flush = ! changed;

  rip_update_csn(p, ifa);

  while (rip_send_response(p, ifa) > 0)
    ;
}

static void
rip_tx_hook(sock *sk)
{
  struct rip_iface *ifa = sk->data;
  struct rip_proto *p = ifa->rip;

  DBG("RIP: TX hook called (iface %s, src %I, dst %I)\n",
      sk->iface->name, sk->saddr, sk->daddr);

  while (rip_send_response(p, ifa) > 0)
    ;
}

static void
rip_err_hook(sock *sk, int err)
{
  struct rip_iface *ifa = sk->data;
  struct rip_proto *p = ifa->rip;

  log(L_ERR "%s: Socket error on %s: %M", p->p.name, ifa->iface->name, err);

  rip_reset_tx_session(p, ifa);
}

static void
rip_receive_response(struct rip_proto *p, struct rip_iface *ifa, struct rip_packet *pkt, uint plen, struct rip_neighbor *from)
{
  struct rip_block rte = {};
  const char *err_dsc = NULL;

  TRACE(D_PACKETS, "Response received from %I on %s", from->nbr->addr, ifa->iface->name);

  byte *pos = (byte *) pkt + rip_pkt_hdrlen(ifa);
  byte *end = (byte *) pkt + plen;

  btime expires = current_time() + ifa->cf->timeout_time;

  if (pkt->command == RIP_CMD_UPDATE_RESPONSE)
  {
    struct rip_update_hdr *hdr = rip_get_update_hdr(pkt);
    rip_send_ack(p, ifa, hdr->flush, ntohs(hdr->seqnum));
    expires = TIME_INFINITY;

    /* Handle flush bit */
    if (hdr->flush)
    {
      /* Flush old routes */
      rip_flush_table(p, from);

      /* Acknowledge pending request */
      ifa->req_pending = 0;
    }
  }

  for (; pos < end; pos += RIP_BLOCK_LENGTH)
  {
    /* Find next regular RTE */
    if (!rip_get_block(p, pos, &rte))
      continue;

    if (rip_is_v2(p) && (pkt->version == RIP_V1))
    {
      if (ifa->cf->check_zero && (rte.tag || rte.net.pxlen || ipa_nonzero(rte.next_hop)))
	SKIP("RIPv1 reserved field is nonzero");

      rte.tag = 0;
      rte.net.pxlen = ip4_masklen(ip4_class_mask(net4_prefix(&rte.net)));
      rte.next_hop = IPA_NONE;
    }

    if (rte.net.pxlen == 255)
      SKIP("invalid prefix length");

    net_normalize(&rte.net);

    int c = net_classify(&rte.net);
    if ((c < 0) || !(c & IADDR_HOST) || ((c & IADDR_SCOPE_MASK) <= SCOPE_LINK))
      SKIP("invalid prefix");

    if (rte.metric > p->infinity)
      SKIP("invalid metric");

    if (ipa_nonzero(rte.next_hop))
    {
      neighbor *nbr = neigh_find(&p->p, rte.next_hop, ifa->iface, 0);
      if (!nbr || (nbr->scope <= 0))
	rte.next_hop = IPA_NONE;
    }

    // TRACE(D_PACKETS, "    %N -> %I metric %d", &rte.net.n, rte.next_hop, rte.metric);

    rte.metric += ifa->cf->metric;

    if (rte.metric < p->infinity)
    {
      struct rip_rte new = {
	.from = from,
	.next_hop = ipa_nonzero(rte.next_hop) ? rte.next_hop : from->nbr->addr,
	.metric = rte.metric,
	.tag = rte.tag,
	.expires = expires
      };

      rip_update_rte(p, &rte.net, &new);
    }
    else
      rip_withdraw_rte(p, &rte.net, from);

    continue;

  skip:
    LOG_RTE("Ignoring route %N received from %I - %s",
	    &rte.net, from->nbr->addr, err_dsc);
  }
}

int
rip_send_flush(struct rip_proto *p, struct rip_iface *ifa)
{
  /* Caller should handle cleanup of pending response */
  if (ifa->tx_pending)
    return 0;

  struct rip_packet *pkt = rip_tx_buffer(ifa);

  rip_fill_header(ifa, pkt, RIP_CMD_UPDATE_RESPONSE);
  rip_fill_update_hdr(pkt, 1, ifa->tx_seqnum);

  /* We suppose that iface is going down, so we do not expect ACK */
  ifa->tx_seqnum++;

  TRACE(D_PACKETS, "Sending response via %s", ifa->iface->name);
  return rip_send_to(p, ifa, pkt, rip_pkt_hdrlen(ifa), ifa->tx_addr);
}


static int
rip_send_ack(struct rip_proto *p, struct rip_iface *ifa, uint flush, uint seqnum)
{
  struct rip_packet *pkt = rip_tx_buffer(ifa);

  rip_fill_header(ifa, pkt, RIP_CMD_UPDATE_ACK);
  rip_fill_update_hdr(pkt, flush, seqnum);

  TRACE(D_PACKETS, "Sending acknowledge via %s", ifa->iface->name);
  return rip_send_to(p, ifa, pkt, rip_pkt_hdrlen(ifa), ifa->tx_addr);
}

static void
rip_receive_ack(struct rip_proto *p, struct rip_iface *ifa, struct rip_packet *pkt, uint plen UNUSED, struct rip_neighbor *from)
{
  TRACE(D_PACKETS, "Acknowledge received from %I on %s", from->nbr->addr, ifa->iface->name);

  struct rip_update_hdr *hdr = rip_get_update_hdr(pkt);
  uint seqnum = ntohs(hdr->seqnum);

  if (! ifa->tx_active || ! ifa->tx_pending)
  {
    LOG_PKT("Bad acknowledge packet from %I via %s - no pending response",
	    from->nbr->addr, ifa->iface->name);
    return;
  }

  if (seqnum != ifa->tx_seqnum)
  {
    LOG_PKT("Bad acknowledge packet from %I via %s - "
	    "mismatched sequence number (rcv %u, old %u)",
	    from->nbr->addr, ifa->iface->name, seqnum, (uint) ifa->tx_seqnum);
    return;
  }

  /* Move acked position */
  FIB_ITERATE_COPY(&ifa->tx_done, &ifa->tx_fit, &p->rtable);

  /* Packet is no longer pending */
  ifa->tx_pending = 0;
  ifa->tx_seqnum++;

  /* Next one does not have flush bit */
  ifa->tx_flush = 0;

  rip_send_response(p, ifa);
}

/**
 * rip_rxmt_timeout - RIP retransmission timer hook
 * @t: timer
 *
 * In Demand Circuit mode, update packets must be acknowledged to ensure
 * reliability. If they are not acknowledged, we need to retransmit them.
 */
void
rip_rxmt_timeout(timer *t)
{
  struct rip_iface *ifa = t->data;
  struct rip_proto *p = ifa->rip;

  if (ifa->req_pending)
    rip_send_request(p, ifa);

  if (ifa->tx_pending)
  {
    /* Revert to acked position */
    FIB_ITERATE_COPY(&ifa->tx_fit, &ifa->tx_done, &p->rtable);

    /* Packet is no longer pending */
    ifa->tx_pending = 0;
    ifa->tx_seqnum++;

    rip_send_response(p, ifa);
  }
}


static int
rip_rx_hook(sock *sk, uint len)
{
  struct rip_iface *ifa = sk->data;
  struct rip_proto *p = ifa->rip;
  const char *err_dsc = NULL;
  uint err_val = 0;

  if (sk->lifindex != sk->iface->index)
    return 1;

  DBG("RIP: RX hook called (iface %s, src %I, dst %I)\n",
      sk->iface->name, sk->faddr, sk->laddr);

  /* Silently ignore my own packets */
  if (ipa_equal(sk->faddr, sk->saddr))
    return 1;

  if (rip_is_ng(p) && !ipa_is_link_local(sk->faddr))
    DROP1("wrong src address");

  struct rip_neighbor *n = rip_get_neighbor(p, &sk->faddr, ifa);

  if (!n)
    DROP1("not from neighbor");

  if ((ifa->cf->ttl_security == 1) && (sk->rcv_ttl < 255))
    DROP("wrong TTL", sk->rcv_ttl);

  if (sk->fport != sk->dport)
    DROP("wrong src port", sk->fport);

  if (len < sizeof(struct rip_packet))
    DROP("too short", len);

  if (sk->flags & SKF_TRUNCATED)
    DROP("truncated", len);

  struct rip_packet *pkt = (struct rip_packet *) sk->rbuf;
  uint pkt_len = len;
  uint hdr_len = sizeof(struct rip_packet);
  uint update_msg = 0;

  if (!pkt->version || (ifa->cf->version_only && (pkt->version != ifa->cf->version)))
    DROP("wrong version", pkt->version);

  /* Update packets (RFC 2091) have additional header even before auth data */
  if ((pkt->command == RIP_CMD_UPDATE_REQUEST) ||
      (pkt->command == RIP_CMD_UPDATE_RESPONSE) ||
      (pkt->command == RIP_CMD_UPDATE_ACK))
  {
    hdr_len += sizeof(struct rip_update_hdr);

    if (len < hdr_len)
      DROP("too short", len);

    struct rip_update_hdr *hdr = rip_get_update_hdr(pkt);

    if (hdr->version != RIP_UPDATE_VERSION)
      DROP("wrong update header version", hdr->version);

    if (hdr->flush > 1)
      DROP("wrong flush value", hdr->flush);

    update_msg = 1;
  }

  /* rip_check_authentication() has its own error logging */
  if (rip_is_v2(p) && !rip_check_authentication(p, ifa, pkt, &pkt_len, hdr_len, n))
    return 1;

  if ((pkt_len - hdr_len) % RIP_BLOCK_LENGTH)
    DROP("invalid length", pkt_len);

  if (update_msg != ifa->cf->demand_circuit)
    DROP("demand circuit mode mismatch", update_msg);

  n->last_seen = current_time();
  rip_update_bfd(p, n);

  switch (pkt->command)
  {
  case RIP_CMD_REQUEST:
  case RIP_CMD_UPDATE_REQUEST:
    rip_receive_request(p, ifa, pkt, pkt_len, n);
    break;

  case RIP_CMD_RESPONSE:
  case RIP_CMD_UPDATE_RESPONSE:
    rip_receive_response(p, ifa, pkt, pkt_len, n);
    break;

  case RIP_CMD_UPDATE_ACK:
    rip_receive_ack(p, ifa, pkt, pkt_len, n);
    break;

  default:
    DROP("unknown command", pkt->command);
  }
  return 1;

drop:
  LOG_PKT("Bad packet from %I via %s - %s (%u)",
	  sk->faddr, sk->iface->name, err_dsc, err_val);

  return 1;
}

int
rip_open_socket(struct rip_iface *ifa)
{
  struct rip_proto *p = ifa->rip;

  sock *sk = sk_new(p->p.pool);
  sk->type = SK_UDP;
  sk->subtype = rip_is_v2(p) ? SK_IPV4 : SK_IPV6;
  sk->sport = ifa->cf->port;
  sk->dport = ifa->cf->port;
  sk->iface = ifa->iface;
  sk->saddr = rip_is_v2(p) ? ifa->iface->addr4->ip : ifa->iface->llv6->ip;
  sk->vrf = p->p.vrf;

  sk->rx_hook = rip_rx_hook;
  sk->tx_hook = rip_tx_hook;
  sk->err_hook = rip_err_hook;
  sk->data = ifa;

  sk->tos = ifa->cf->tx_tos;
  sk->priority = ifa->cf->tx_priority;
  sk->ttl = ifa->cf->ttl_security ? 255 : 1;
  sk->flags = SKF_LADDR_RX | ((ifa->cf->ttl_security == 1) ? SKF_TTL_RX : 0);

  /* sk->rbsize and sk->tbsize are handled in rip_iface_update_buffers() */

  if (sk_open(sk) < 0)
    goto err;

  if (ifa->cf->mode == RIP_IM_MULTICAST)
  {
    if (sk_setup_multicast(sk) < 0)
      goto err;

    if (sk_join_group(sk, ifa->addr) < 0)
      goto err;
  }
  else /* Broadcast */
  {
    if (sk_setup_broadcast(sk) < 0)
      goto err;

    if (ipa_zero(ifa->addr))
    {
      sk->err = "Missing broadcast address";
      goto err;
    }
  }

  ifa->sk = sk;
  return 1;

err:
  sk_log_error(sk, p->p.name);
  rfree(sk);
  return 0;
}
