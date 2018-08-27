/*
 *	BIRD -- The Babel protocol
 *
 *	Copyright (c) 2015--2016 Toke Hoiland-Jorgensen
 * 	(c) 2016--2017 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2016--2017 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	This file contains the packet and TLV handling code for the protocol.
 */

#include "babel.h"


struct babel_pkt_header {
  u8 magic;
  u8 version;
  u16 length;
} PACKED;

struct babel_tlv {
  u8 type;
  u8 length;
  u8 value[0];
} PACKED;

struct babel_tlv_ack_req {
  u8 type;
  u8 length;
  u16 reserved;
  u16 nonce;
  u16 interval;
} PACKED;

struct babel_tlv_ack {
  u8 type;
  u8 length;
  u16 nonce;
} PACKED;

struct babel_tlv_hello {
  u8 type;
  u8 length;
  u16 flags;
  u16 seqno;
  u16 interval;
} PACKED;

struct babel_tlv_ihu {
  u8 type;
  u8 length;
  u8 ae;
  u8 reserved;
  u16 rxcost;
  u16 interval;
  u8 addr[0];
} PACKED;

struct babel_tlv_router_id {
  u8 type;
  u8 length;
  u16 reserved;
  u64 router_id;
} PACKED;

struct babel_tlv_next_hop {
  u8 type;
  u8 length;
  u8 ae;
  u8 reserved;
  u8 addr[0];
} PACKED;

struct babel_tlv_update {
  u8 type;
  u8 length;
  u8 ae;
  u8 flags;
  u8 plen;
  u8 omitted;
  u16 interval;
  u16 seqno;
  u16 metric;
  u8 addr[0];
} PACKED;

struct babel_tlv_route_request {
  u8 type;
  u8 length;
  u8 ae;
  u8 plen;
  u8 addr[0];
} PACKED;

struct babel_tlv_seqno_request {
  u8 type;
  u8 length;
  u8 ae;
  u8 plen;
  u16 seqno;
  u8 hop_count;
  u8 reserved;
  u64 router_id;
  u8 addr[0];
} PACKED;

struct babel_subtlv_source_prefix {
  u8 type;
  u8 length;
  u8 plen;
  u8 addr[0];
} PACKED;


/* Hello flags */
#define BABEL_HF_UNICAST	0x8000

/* Update flags */
#define BABEL_UF_DEF_PREFIX	0x80
#define BABEL_UF_ROUTER_ID	0x40


struct babel_parse_state {
  struct babel_proto *proto;
  struct babel_iface *ifa;
  ip_addr saddr;
  ip_addr next_hop_ip4;
  ip_addr next_hop_ip6;
  u64 router_id;		/* Router ID used in subsequent updates */
  u8 def_ip6_prefix[16];	/* Implicit IPv6 prefix in network order */
  u8 def_ip4_prefix[4];		/* Implicit IPv4 prefix in network order */
  u8 router_id_seen;		/* router_id field is valid */
  u8 def_ip6_prefix_seen;	/* def_ip6_prefix is valid */
  u8 def_ip4_prefix_seen;	/* def_ip4_prefix is valid */
  u8 current_tlv_endpos;	/* End of self-terminating TLVs (offset from start) */
  u8 sadr_enabled;
};

enum parse_result {
  PARSE_SUCCESS,
  PARSE_ERROR,
  PARSE_IGNORE,
};

struct babel_write_state {
  u64 router_id;
  u8 router_id_seen;
  ip_addr next_hop_ip4;
  ip_addr next_hop_ip6;
  u8 def_ip6_prefix[16];	/* Implicit IPv6 prefix in network order */
  u8 def_ip6_pxlen;
};


#define DROP(DSC,VAL) do { err_dsc = DSC; err_val = VAL; goto drop; } while(0)
#define DROP1(DSC) do { err_dsc = DSC; goto drop; } while(0)
#define LOG_PKT(msg, args...) \
  log_rl(&p->log_pkt_tbf, L_REMOTE "%s: " msg, p->p.name, args)

#define FIRST_TLV(p) ((struct babel_tlv *) (((struct babel_pkt_header *) p) + 1))
#define NEXT_TLV(t) ((struct babel_tlv *) (((byte *) t) + TLV_LENGTH(t)))
#define TLV_LENGTH(t) (t->type == BABEL_TLV_PAD1 ? 1 : t->length + sizeof(struct babel_tlv))
#define TLV_OPT_LENGTH(t) (t->length + sizeof(struct babel_tlv) - sizeof(*t))
#define TLV_HDR(tlv,t,l) ({ tlv->type = t; tlv->length = l - sizeof(struct babel_tlv); })
#define TLV_HDR0(tlv,t) TLV_HDR(tlv, t, tlv_data[t].min_length)

#define NET_SIZE(n) BYTES(net_pxlen(n))

static inline uint
bytes_equal(u8 *b1, u8 *b2, uint maxlen)
{
  uint i;
  for (i = 0; (i < maxlen) && (*b1 == *b2); i++, b1++, b2++)
    ;
  return i;
}

static inline uint
get_time16(const void *p)
{
  uint v = get_u16(p) * BABEL_TIME_UNITS;
  return MAX(BABEL_MIN_INTERVAL, v);
}

static inline void
put_time16(void *p, uint v)
{
  put_u16(p, v / BABEL_TIME_UNITS);
}

static inline void
read_ip4_px(net_addr *n, const void *p, uint plen)
{
  ip4_addr addr = {0};
  memcpy(&addr, p, BYTES(plen));
  net_fill_ip4(n, ip4_ntoh(addr), plen);
}

static inline void
put_ip4_px(void *p, net_addr *n)
{
  ip4_addr addr = ip4_hton(net4_prefix(n));
  memcpy(p, &addr, NET_SIZE(n));
}

static inline void
read_ip6_px(net_addr *n, const void *p, uint plen)
{
  ip6_addr addr = IPA_NONE;
  memcpy(&addr, p, BYTES(plen));
  net_fill_ip6(n, ip6_ntoh(addr), plen);
}

static inline void
put_ip6_px(void *p, net_addr *n)
{
  ip6_addr addr = ip6_hton(net6_prefix(n));
  memcpy(p, &addr, NET_SIZE(n));
}

static inline ip6_addr
get_ip6_ll(const void *p)
{
  return ip6_build(0xfe800000, 0, get_u32(p+0), get_u32(p+4));
}

static inline void
put_ip6_ll(void *p, ip6_addr addr)
{
  put_u32(p+0, _I2(addr));
  put_u32(p+4, _I3(addr));
}


/*
 *	TLV read/write functions
 */

static int babel_read_ack_req(struct babel_tlv *hdr, union babel_msg *msg, struct babel_parse_state *state);
static int babel_read_hello(struct babel_tlv *hdr, union babel_msg *msg, struct babel_parse_state *state);
static int babel_read_ihu(struct babel_tlv *hdr, union babel_msg *msg, struct babel_parse_state *state);
static int babel_read_router_id(struct babel_tlv *hdr, union babel_msg *msg, struct babel_parse_state *state);
static int babel_read_next_hop(struct babel_tlv *hdr, union babel_msg *msg, struct babel_parse_state *state);
static int babel_read_update(struct babel_tlv *hdr, union babel_msg *msg, struct babel_parse_state *state);
static int babel_read_route_request(struct babel_tlv *hdr, union babel_msg *msg, struct babel_parse_state *state);
static int babel_read_seqno_request(struct babel_tlv *hdr, union babel_msg *msg, struct babel_parse_state *state);
static int babel_read_source_prefix(struct babel_tlv *hdr, union babel_msg *msg, struct babel_parse_state *state);

static uint babel_write_ack(struct babel_tlv *hdr, union babel_msg *msg, struct babel_write_state *state, uint max_len);
static uint babel_write_hello(struct babel_tlv *hdr, union babel_msg *msg, struct babel_write_state *state, uint max_len);
static uint babel_write_ihu(struct babel_tlv *hdr, union babel_msg *msg, struct babel_write_state *state, uint max_len);
static uint babel_write_update(struct babel_tlv *hdr, union babel_msg *msg, struct babel_write_state *state, uint max_len);
static uint babel_write_route_request(struct babel_tlv *hdr, union babel_msg *msg, struct babel_write_state *state, uint max_len);
static uint babel_write_seqno_request(struct babel_tlv *hdr, union babel_msg *msg, struct babel_write_state *state, uint max_len);
static int babel_write_source_prefix(struct babel_tlv *hdr, net_addr *net, uint max_len);

struct babel_tlv_data {
  u8 min_length;
  int (*read_tlv)(struct babel_tlv *hdr, union babel_msg *m, struct babel_parse_state *state);
  uint (*write_tlv)(struct babel_tlv *hdr, union babel_msg *m, struct babel_write_state *state, uint max_len);
  void (*handle_tlv)(union babel_msg *m, struct babel_iface *ifa);
};

static const struct babel_tlv_data tlv_data[BABEL_TLV_MAX] = {
  [BABEL_TLV_ACK_REQ] = {
    sizeof(struct babel_tlv_ack_req),
    babel_read_ack_req,
    NULL,
    babel_handle_ack_req
  },
  [BABEL_TLV_ACK] = {
    sizeof(struct babel_tlv_ack),
    NULL,
    babel_write_ack,
    NULL
  },
  [BABEL_TLV_HELLO] = {
    sizeof(struct babel_tlv_hello),
    babel_read_hello,
    babel_write_hello,
    babel_handle_hello
  },
  [BABEL_TLV_IHU] = {
    sizeof(struct babel_tlv_ihu),
    babel_read_ihu,
    babel_write_ihu,
    babel_handle_ihu
  },
  [BABEL_TLV_ROUTER_ID] = {
    sizeof(struct babel_tlv_router_id),
    babel_read_router_id,
    NULL,
    NULL
  },
  [BABEL_TLV_NEXT_HOP] = {
    sizeof(struct babel_tlv_next_hop),
    babel_read_next_hop,
    NULL,
    NULL
  },
  [BABEL_TLV_UPDATE] = {
    sizeof(struct babel_tlv_update),
    babel_read_update,
    babel_write_update,
    babel_handle_update
  },
  [BABEL_TLV_ROUTE_REQUEST] = {
    sizeof(struct babel_tlv_route_request),
    babel_read_route_request,
    babel_write_route_request,
    babel_handle_route_request
  },
  [BABEL_TLV_SEQNO_REQUEST] = {
    sizeof(struct babel_tlv_seqno_request),
    babel_read_seqno_request,
    babel_write_seqno_request,
    babel_handle_seqno_request
  },
};

static int
babel_read_ack_req(struct babel_tlv *hdr, union babel_msg *m,
		   struct babel_parse_state *state)
{
  struct babel_tlv_ack_req *tlv = (void *) hdr;
  struct babel_msg_ack_req *msg = &m->ack_req;

  msg->type = BABEL_TLV_ACK_REQ;
  msg->nonce = get_u16(&tlv->nonce);
  msg->interval = get_time16(&tlv->interval);
  msg->sender = state->saddr;

  if (!msg->interval)
    return PARSE_ERROR;

  return PARSE_SUCCESS;
}

static uint
babel_write_ack(struct babel_tlv *hdr, union babel_msg *m,
                struct babel_write_state *state UNUSED, uint max_len UNUSED)
{
  struct babel_tlv_ack *tlv = (void *) hdr;
  struct babel_msg_ack *msg = &m->ack;

  TLV_HDR0(tlv, BABEL_TLV_ACK);
  put_u16(&tlv->nonce, msg->nonce);

  return sizeof(struct babel_tlv_ack);
}

static int
babel_read_hello(struct babel_tlv *hdr, union babel_msg *m,
                 struct babel_parse_state *state)
{
  struct babel_tlv_hello *tlv = (void *) hdr;
  struct babel_msg_hello *msg = &m->hello;

  /* We currently don't support unicast Hello */
  u16 flags = get_u16(&tlv->flags);
  if (flags & BABEL_HF_UNICAST)
    return PARSE_IGNORE;

  msg->type = BABEL_TLV_HELLO;
  msg->seqno = get_u16(&tlv->seqno);
  msg->interval = get_time16(&tlv->interval);
  msg->sender = state->saddr;

  return PARSE_SUCCESS;
}

static uint
babel_write_hello(struct babel_tlv *hdr, union babel_msg *m,
                  struct babel_write_state *state UNUSED, uint max_len UNUSED)
{
  struct babel_tlv_hello *tlv = (void *) hdr;
  struct babel_msg_hello *msg = &m->hello;

  TLV_HDR0(tlv, BABEL_TLV_HELLO);
  put_u16(&tlv->seqno, msg->seqno);
  put_time16(&tlv->interval, msg->interval);

  return sizeof(struct babel_tlv_hello);
}

static int
babel_read_ihu(struct babel_tlv *hdr, union babel_msg *m,
               struct babel_parse_state *state)
{
  struct babel_tlv_ihu *tlv = (void *) hdr;
  struct babel_msg_ihu *msg = &m->ihu;

  msg->type = BABEL_TLV_IHU;
  msg->ae = tlv->ae;
  msg->rxcost = get_u16(&tlv->rxcost);
  msg->interval = get_time16(&tlv->interval);
  msg->addr = IPA_NONE;
  msg->sender = state->saddr;

  if (msg->ae >= BABEL_AE_MAX)
    return PARSE_IGNORE;

  /*
   * We only actually read link-local IPs. In every other case, the addr field
   * will be 0 but validation will succeed. The handler takes care of these
   * cases. We handle them here anyway because we need the length for parsing
   * subtlvs.
   */
  switch (msg->ae)
  {
  case BABEL_AE_IP4:
    if (TLV_OPT_LENGTH(tlv) < 4)
      return PARSE_ERROR;
    state->current_tlv_endpos += 4;
    break;

  case BABEL_AE_IP6:
    if (TLV_OPT_LENGTH(tlv) < 16)
      return PARSE_ERROR;
    state->current_tlv_endpos += 16;
    break;

  case BABEL_AE_IP6_LL:
    if (TLV_OPT_LENGTH(tlv) < 8)
      return PARSE_ERROR;

    msg->addr = ipa_from_ip6(get_ip6_ll(&tlv->addr));
    state->current_tlv_endpos += 8;
    break;
  }

  return PARSE_SUCCESS;
}

static uint
babel_write_ihu(struct babel_tlv *hdr, union babel_msg *m,
                struct babel_write_state *state UNUSED, uint max_len)
{
  struct babel_tlv_ihu *tlv = (void *) hdr;
  struct babel_msg_ihu *msg = &m->ihu;

  if (ipa_is_link_local(msg->addr) && max_len < sizeof(struct babel_tlv_ihu) + 8)
    return 0;

  TLV_HDR0(tlv, BABEL_TLV_IHU);
  put_u16(&tlv->rxcost, msg->rxcost);
  put_time16(&tlv->interval, msg->interval);

  if (!ipa_is_link_local(msg->addr))
  {
    tlv->ae = BABEL_AE_WILDCARD;
    return sizeof(struct babel_tlv_ihu);
  }
  put_ip6_ll(&tlv->addr, msg->addr);
  tlv->ae = BABEL_AE_IP6_LL;
  hdr->length += 8;
  return sizeof(struct babel_tlv_ihu) + 8;
}

static int
babel_read_router_id(struct babel_tlv *hdr, union babel_msg *m UNUSED,
                     struct babel_parse_state *state)
{
  struct babel_tlv_router_id *tlv = (void *) hdr;

  state->router_id = get_u64(&tlv->router_id);
  state->router_id_seen = 1;

  return PARSE_IGNORE;
}

/* This is called directly from babel_write_update() */
static uint
babel_write_router_id(struct babel_tlv *hdr, u64 router_id,
		      struct babel_write_state *state, uint max_len UNUSED)
{
  struct babel_tlv_router_id *tlv = (void *) hdr;

  /* We still assume that first min_length bytes are available and zeroed */

  TLV_HDR0(tlv, BABEL_TLV_ROUTER_ID);
  put_u64(&tlv->router_id, router_id);

  state->router_id = router_id;
  state->router_id_seen = 1;

  return sizeof(struct babel_tlv_router_id);
}

static int
babel_read_next_hop(struct babel_tlv *hdr, union babel_msg *m UNUSED,
                    struct babel_parse_state *state)
{
  struct babel_tlv_next_hop *tlv = (void *) hdr;

  switch (tlv->ae)
  {
  case BABEL_AE_WILDCARD:
    return PARSE_ERROR;

  case BABEL_AE_IP4:
    if (TLV_OPT_LENGTH(tlv) < sizeof(ip4_addr))
      return PARSE_ERROR;

    state->next_hop_ip4 = ipa_from_ip4(get_ip4(&tlv->addr));
    state->current_tlv_endpos += sizeof(ip4_addr);
    return PARSE_IGNORE;

  case BABEL_AE_IP6:
    if (TLV_OPT_LENGTH(tlv) < sizeof(ip6_addr))
      return PARSE_ERROR;

    state->next_hop_ip6 = ipa_from_ip6(get_ip6(&tlv->addr));
    state->current_tlv_endpos += sizeof(ip6_addr);
    return PARSE_IGNORE;

  case BABEL_AE_IP6_LL:
    if (TLV_OPT_LENGTH(tlv) < 8)
      return PARSE_ERROR;

    state->next_hop_ip6 = ipa_from_ip6(get_ip6_ll(&tlv->addr));
    state->current_tlv_endpos += 8;
    return PARSE_IGNORE;

  default:
    return PARSE_IGNORE;
  }

  return PARSE_IGNORE;
}

/* This is called directly from babel_write_update() and returns -1 if a next
   hop should be written but there is not enough space. */
static int
babel_write_next_hop(struct babel_tlv *hdr, ip_addr addr,
		     struct babel_write_state *state, uint max_len)
{
  struct babel_tlv_next_hop *tlv = (void *) hdr;

  if (ipa_zero(addr))
  {
    /* Should not happen */
    return 0;
  }
  else if (ipa_is_ip4(addr) && !ipa_equal(addr, state->next_hop_ip4))
  {
    uint len = sizeof(struct babel_tlv_next_hop) + sizeof(ip4_addr);
    if (len > max_len)
      return -1;

    TLV_HDR(tlv, BABEL_TLV_NEXT_HOP, len);

    tlv->ae = BABEL_AE_IP4;
    put_ip4(&tlv->addr, ipa_to_ip4(addr));
    state->next_hop_ip4 = addr;

    return len;
  }
  else if (ipa_is_ip6(addr) && !ipa_equal(addr, state->next_hop_ip6))
  {
    uint len = sizeof(struct babel_tlv_next_hop) + sizeof(ip6_addr);
    if (len > max_len)
      return -1;

    TLV_HDR(tlv, BABEL_TLV_NEXT_HOP, len);

    tlv->ae = BABEL_AE_IP6;
    put_ip6(&tlv->addr, ipa_to_ip6(addr));
    state->next_hop_ip6 = addr;

    return len;
  }

  return 0;
}

static int
babel_read_update(struct babel_tlv *hdr, union babel_msg *m,
                  struct babel_parse_state *state)
{
  struct babel_tlv_update *tlv = (void *) hdr;
  struct babel_msg_update *msg = &m->update;

  msg->type = BABEL_TLV_UPDATE;
  msg->interval = get_time16(&tlv->interval);
  msg->seqno = get_u16(&tlv->seqno);
  msg->metric = get_u16(&tlv->metric);

  /* Length of received prefix data without omitted part */
  int len = BYTES(tlv->plen) - (int) tlv->omitted;
  u8 buf[16] = {};

  if ((len < 0) || ((uint) len > TLV_OPT_LENGTH(tlv)))
    return PARSE_ERROR;

  switch (tlv->ae)
  {
  case BABEL_AE_WILDCARD:
    if (tlv->plen > 0)
      return PARSE_ERROR;

    if (msg->metric != 65535)
      return PARSE_ERROR;

    msg->wildcard = 1;
    break;

  case BABEL_AE_IP4:
    if (tlv->plen > IP4_MAX_PREFIX_LENGTH)
      return PARSE_ERROR;

    /* Cannot omit data if there is no saved prefix */
    if (tlv->omitted && !state->def_ip4_prefix_seen)
      return PARSE_ERROR;

    /* Update must have next hop, unless it is retraction */
    if (ipa_zero(state->next_hop_ip4) && (msg->metric != BABEL_INFINITY))
      return PARSE_IGNORE;

    /* Merge saved prefix and received prefix parts */
    memcpy(buf, state->def_ip4_prefix, tlv->omitted);
    memcpy(buf + tlv->omitted, tlv->addr, len);

    ip4_addr prefix4 = get_ip4(buf);
    net_fill_ip4(&msg->net, prefix4, tlv->plen);

    if (tlv->flags & BABEL_UF_DEF_PREFIX)
    {
      put_ip4(state->def_ip4_prefix, prefix4);
      state->def_ip4_prefix_seen = 1;
    }

    msg->next_hop = state->next_hop_ip4;

    break;

  case BABEL_AE_IP6:
    if (tlv->plen > IP6_MAX_PREFIX_LENGTH)
      return PARSE_ERROR;

    /* Cannot omit data if there is no saved prefix */
    if (tlv->omitted && !state->def_ip6_prefix_seen)
      return PARSE_ERROR;

    /* Merge saved prefix and received prefix parts */
    memcpy(buf, state->def_ip6_prefix, tlv->omitted);
    memcpy(buf + tlv->omitted, tlv->addr, len);

    ip6_addr prefix6 = get_ip6(buf);
    net_fill_ip6(&msg->net, prefix6, tlv->plen);

    if (state->sadr_enabled)
      net_make_ip6_sadr(&msg->net);

    if (tlv->flags & BABEL_UF_DEF_PREFIX)
    {
      put_ip6(state->def_ip6_prefix, prefix6);
      state->def_ip6_prefix_seen = 1;
    }

    if (tlv->flags & BABEL_UF_ROUTER_ID)
    {
      state->router_id = ((u64) _I2(prefix6)) << 32 | _I3(prefix6);
      state->router_id_seen = 1;
    }

    msg->next_hop = state->next_hop_ip6;

    break;

  case BABEL_AE_IP6_LL:
    /* ??? */
    return PARSE_IGNORE;

  default:
    return PARSE_IGNORE;
  }

  /* Update must have Router ID, unless it is retraction */
  if (!state->router_id_seen && (msg->metric != BABEL_INFINITY))
  {
    DBG("Babel: No router ID seen before update\n");
    return PARSE_ERROR;
  }

  msg->router_id = state->router_id;
  msg->sender = state->saddr;
  state->current_tlv_endpos += len;

  return PARSE_SUCCESS;
}

static uint
babel_write_update(struct babel_tlv *hdr, union babel_msg *m,
                   struct babel_write_state *state, uint max_len)
{
  struct babel_msg_update *msg = &m->update;
  uint len0 = 0;

  /*
   * When needed, we write Router-ID TLV before Update TLV and return size of
   * both of them. There is enough space for the Router-ID TLV, because
   * sizeof(struct babel_tlv_router_id) == sizeof(struct babel_tlv_update).
   *
   * Router ID is not used for retractions, so do not use it in such case.
   */
  if ((msg->metric < BABEL_INFINITY) &&
      (!state->router_id_seen || (msg->router_id != state->router_id)))
  {
    len0 = babel_write_router_id(hdr, msg->router_id, state, max_len);
    hdr = NEXT_TLV(hdr);
  }

  /*
   * We also may add Next Hop TLV for regular updates. It may fail for not
   * enough space or it may be unnecessary as the next hop is the same as the
   * last one already announced. So we handle all three cases.
   */
  if (msg->metric < BABEL_INFINITY)
  {
    int l = babel_write_next_hop(hdr, msg->next_hop, state, max_len - len0);
    if (l < 0)
      return 0;

    if (l)
    {
      len0 += l;
      hdr = NEXT_TLV(hdr);
    }
  }

  struct babel_tlv_update *tlv = (void *) hdr;
  uint len = sizeof(struct babel_tlv_update) + NET_SIZE(&msg->net);

  if (len0 + len > max_len)
    return 0;

  memset(tlv, 0, sizeof(struct babel_tlv_update));
  TLV_HDR(tlv, BABEL_TLV_UPDATE, len);

  if (msg->wildcard)
  {
    tlv->ae = BABEL_AE_WILDCARD;
    tlv->plen = 0;
  }
  else if (msg->net.type == NET_IP4)
  {
    tlv->ae = BABEL_AE_IP4;
    tlv->plen = net4_pxlen(&msg->net);
    put_ip4_px(tlv->addr, &msg->net);
  }
  else
  {
    tlv->ae = BABEL_AE_IP6;
    tlv->plen = net6_pxlen(&msg->net);

    /* Address compression - omit initial matching bytes */
    u8 buf[16], omit;
    put_ip6(buf, net6_prefix(&msg->net));
    omit = bytes_equal(buf, state->def_ip6_prefix,
		       MIN(tlv->plen, state->def_ip6_pxlen) / 8);

    if (omit > 0)
    {
      memcpy(tlv->addr, buf + omit, NET_SIZE(&msg->net) - omit);

      tlv->omitted = omit;
      tlv->length -= omit;
      len -= omit;
    }
    else
    {
      put_ip6_px(tlv->addr, &msg->net);
      tlv->flags |= BABEL_UF_DEF_PREFIX;

      put_ip6(state->def_ip6_prefix, net6_prefix(&msg->net));
      state->def_ip6_pxlen = tlv->plen;
    }
  }

  put_time16(&tlv->interval, msg->interval);
  put_u16(&tlv->seqno, msg->seqno);
  put_u16(&tlv->metric, msg->metric);

  if (msg->net.type == NET_IP6_SADR)
  {
    int l = babel_write_source_prefix(hdr, &msg->net, max_len - (len0 + len));
    if (l < 0)
      return 0;

    len += l;
  }

  return len0 + len;
}

static int
babel_read_route_request(struct babel_tlv *hdr, union babel_msg *m,
                         struct babel_parse_state *state)
{
  struct babel_tlv_route_request *tlv = (void *) hdr;
  struct babel_msg_route_request *msg = &m->route_request;

  msg->type = BABEL_TLV_ROUTE_REQUEST;

  switch (tlv->ae)
  {
  case BABEL_AE_WILDCARD:
    /* Wildcard requests must have plen 0 */
    if (tlv->plen > 0)
      return PARSE_ERROR;

    msg->full = 1;
    return PARSE_SUCCESS;

  case BABEL_AE_IP4:
    if (tlv->plen > IP4_MAX_PREFIX_LENGTH)
      return PARSE_ERROR;

    if (TLV_OPT_LENGTH(tlv) < BYTES(tlv->plen))
      return PARSE_ERROR;

    read_ip4_px(&msg->net, tlv->addr, tlv->plen);
    state->current_tlv_endpos += BYTES(tlv->plen);
    return PARSE_SUCCESS;

  case BABEL_AE_IP6:
    if (tlv->plen > IP6_MAX_PREFIX_LENGTH)
      return PARSE_ERROR;

    if (TLV_OPT_LENGTH(tlv) < BYTES(tlv->plen))
      return PARSE_ERROR;

    read_ip6_px(&msg->net, tlv->addr, tlv->plen);
    state->current_tlv_endpos += BYTES(tlv->plen);

    if (state->sadr_enabled)
      net_make_ip6_sadr(&msg->net);

    return PARSE_SUCCESS;

  case BABEL_AE_IP6_LL:
    return PARSE_ERROR;

  default:
    return PARSE_IGNORE;
  }

  return PARSE_IGNORE;
}

static uint
babel_write_route_request(struct babel_tlv *hdr, union babel_msg *m,
			  struct babel_write_state *state UNUSED, uint max_len)
{
  struct babel_tlv_route_request *tlv = (void *) hdr;
  struct babel_msg_route_request *msg = &m->route_request;

  uint len = sizeof(struct babel_tlv_route_request) + NET_SIZE(&msg->net);

  if (len > max_len)
    return 0;

  TLV_HDR(tlv, BABEL_TLV_ROUTE_REQUEST, len);

  if (msg->full)
  {
    tlv->ae = BABEL_AE_WILDCARD;
    tlv->plen = 0;
  }
  else if (msg->net.type == NET_IP4)
  {
    tlv->ae = BABEL_AE_IP4;
    tlv->plen = net4_pxlen(&msg->net);
    put_ip4_px(tlv->addr, &msg->net);
  }
  else
  {
    tlv->ae = BABEL_AE_IP6;
    tlv->plen = net6_pxlen(&msg->net);
    put_ip6_px(tlv->addr, &msg->net);
  }

  if (msg->net.type == NET_IP6_SADR)
  {
    int l = babel_write_source_prefix(hdr, &msg->net, max_len - len);
    if (l < 0)
      return 0;

    len += l;
  }

  return len;
}

static int
babel_read_seqno_request(struct babel_tlv *hdr, union babel_msg *m,
                         struct babel_parse_state *state)
{
  struct babel_tlv_seqno_request *tlv = (void *) hdr;
  struct babel_msg_seqno_request *msg = &m->seqno_request;

  msg->type = BABEL_TLV_SEQNO_REQUEST;
  msg->seqno = get_u16(&tlv->seqno);
  msg->hop_count = tlv->hop_count;
  msg->router_id = get_u64(&tlv->router_id);
  msg->sender = state->saddr;

  if (tlv->hop_count == 0)
    return PARSE_ERROR;

  switch (tlv->ae)
  {
  case BABEL_AE_WILDCARD:
    return PARSE_ERROR;

  case BABEL_AE_IP4:
    if (tlv->plen > IP4_MAX_PREFIX_LENGTH)
      return PARSE_ERROR;

    if (TLV_OPT_LENGTH(tlv) < BYTES(tlv->plen))
      return PARSE_ERROR;

    read_ip4_px(&msg->net, tlv->addr, tlv->plen);
    state->current_tlv_endpos += BYTES(tlv->plen);
    return PARSE_SUCCESS;

  case BABEL_AE_IP6:
    if (tlv->plen > IP6_MAX_PREFIX_LENGTH)
      return PARSE_ERROR;

    if (TLV_OPT_LENGTH(tlv) < BYTES(tlv->plen))
      return PARSE_ERROR;

    read_ip6_px(&msg->net, tlv->addr, tlv->plen);
    state->current_tlv_endpos += BYTES(tlv->plen);

    if (state->sadr_enabled)
      net_make_ip6_sadr(&msg->net);

    return PARSE_SUCCESS;

  case BABEL_AE_IP6_LL:
    return PARSE_ERROR;

  default:
    return PARSE_IGNORE;
  }

  return PARSE_IGNORE;
}

static uint
babel_write_seqno_request(struct babel_tlv *hdr, union babel_msg *m,
			  struct babel_write_state *state UNUSED, uint max_len)
{
  struct babel_tlv_seqno_request *tlv = (void *) hdr;
  struct babel_msg_seqno_request *msg = &m->seqno_request;

  uint len = sizeof(struct babel_tlv_seqno_request) + NET_SIZE(&msg->net);

  if (len > max_len)
    return 0;

  TLV_HDR(tlv, BABEL_TLV_SEQNO_REQUEST, len);

  if (msg->net.type == NET_IP4)
  {
    tlv->ae = BABEL_AE_IP4;
    tlv->plen = net4_pxlen(&msg->net);
    put_ip4_px(tlv->addr, &msg->net);
  }
  else
  {
    tlv->ae = BABEL_AE_IP6;
    tlv->plen = net6_pxlen(&msg->net);
    put_ip6_px(tlv->addr, &msg->net);
  }

  put_u16(&tlv->seqno, msg->seqno);
  tlv->hop_count = msg->hop_count;
  put_u64(&tlv->router_id, msg->router_id);

  if (msg->net.type == NET_IP6_SADR)
  {
    int l = babel_write_source_prefix(hdr, &msg->net, max_len - len);
    if (l < 0)
      return 0;

    len += l;
  }

  return len;
}

static int
babel_read_source_prefix(struct babel_tlv *hdr, union babel_msg *msg,
			 struct babel_parse_state *state UNUSED)
{
  struct babel_subtlv_source_prefix *tlv = (void *) hdr;
  net_addr_ip6_sadr *net;

  /*
   * We would like to skip the sub-TLV if SADR is not enabled, but we do not
   * know AF of the enclosing TLV yet. We will do that later.
   */

  /* Check internal consistency */
  if ((tlv->length < 1) ||
      (tlv->plen > IP6_MAX_PREFIX_LENGTH) ||
      (tlv->length < (1 + BYTES(tlv->plen))))
    return PARSE_ERROR;

  /* Plen MUST NOT be 0 */
  if (tlv->plen == 0)
    return PARSE_ERROR;

  switch(msg->type)
  {
  case BABEL_TLV_UPDATE:
    /* Wildcard updates with source prefix MUST be silently ignored */
    if (msg->update.wildcard)
      return PARSE_IGNORE;

    net = (void *) &msg->update.net;
    break;

  case BABEL_TLV_ROUTE_REQUEST:
    /* Wildcard requests with source addresses MUST be silently ignored */
    if (msg->route_request.full)
      return PARSE_IGNORE;

    net = (void *) &msg->route_request.net;
    break;

  case BABEL_TLV_SEQNO_REQUEST:
    net = (void *) &msg->seqno_request.net;
    break;

  default:
    return PARSE_ERROR;
  }

  /* If SADR is active, the net has appropriate type */
  if (net->type != NET_IP6_SADR)
    return PARSE_IGNORE;

  /* Duplicate Source Prefix sub-TLV; SHOULD ignore whole TLV */
  if (net->src_pxlen > 0)
    return PARSE_IGNORE;

  net_addr_ip6 src;
  read_ip6_px((void *) &src, tlv->addr, tlv->plen);
  net->src_prefix = src.prefix;
  net->src_pxlen = src.pxlen;

  return PARSE_SUCCESS;
}

static int
babel_write_source_prefix(struct babel_tlv *hdr, net_addr *n, uint max_len)
{
  struct babel_subtlv_source_prefix *tlv = (void *) NEXT_TLV(hdr);
  net_addr_ip6_sadr *net = (void *) n;

  /* Do not use this sub-TLV for default prefix */
  if (net->src_pxlen == 0)
    return 0;

  uint len = sizeof(*tlv) + BYTES(net->src_pxlen);

  if (len > max_len)
    return -1;

  TLV_HDR(tlv, BABEL_SUBTLV_SOURCE_PREFIX, len);
  hdr->length += len;

  net_addr_ip6 src = NET_ADDR_IP6(net->src_prefix, net->src_pxlen);
  tlv->plen = src.pxlen;
  put_ip6_px(tlv->addr, (void *) &src);

  return len;
}


static inline int
babel_read_subtlvs(struct babel_tlv *hdr,
		   union babel_msg *msg,
		   struct babel_parse_state *state)
{
  struct babel_tlv *tlv;
  byte *pos, *end = (byte *) hdr + TLV_LENGTH(hdr);
  int res;

  for (tlv = (void *) hdr + state->current_tlv_endpos;
       (byte *) tlv < end;
       tlv = NEXT_TLV(tlv))
  {
    /* Ugly special case */
    if (tlv->type == BABEL_TLV_PAD1)
      continue;

    /* The end of the common TLV header */
    pos = (byte *)tlv + sizeof(struct babel_tlv);
    if ((pos > end) || (pos + tlv->length > end))
      return PARSE_ERROR;

    /*
     * The subtlv type space is non-contiguous (due to the mandatory bit), so
     * use a switch for dispatch instead of the mapping array we use for TLVs
     */
    switch (tlv->type)
    {
    case BABEL_SUBTLV_SOURCE_PREFIX:
      res = babel_read_source_prefix(tlv, msg, state);
      if (res != PARSE_SUCCESS)
	return res;
      break;

    case BABEL_SUBTLV_PADN:
    default:
      /* Unknown mandatory subtlv; PARSE_IGNORE ignores the whole TLV */
      if (tlv->type >= 128)
	return PARSE_IGNORE;
      break;
    }
  }

  return PARSE_SUCCESS;
}

static inline int
babel_read_tlv(struct babel_tlv *hdr,
               union babel_msg *msg,
               struct babel_parse_state *state)
{
  if ((hdr->type <= BABEL_TLV_PADN) ||
      (hdr->type >= BABEL_TLV_MAX) ||
      !tlv_data[hdr->type].read_tlv)
    return PARSE_IGNORE;

  if (TLV_LENGTH(hdr) < tlv_data[hdr->type].min_length)
    return PARSE_ERROR;

  state->current_tlv_endpos = tlv_data[hdr->type].min_length;
  memset(msg, 0, sizeof(*msg));

  int res = tlv_data[hdr->type].read_tlv(hdr, msg, state);
  if (res != PARSE_SUCCESS)
    return res;

  return babel_read_subtlvs(hdr, msg, state);
}

static uint
babel_write_tlv(struct babel_tlv *hdr,
		union babel_msg *msg,
		struct babel_write_state *state,
		uint max_len)
{
  if ((msg->type <= BABEL_TLV_PADN) ||
      (msg->type >= BABEL_TLV_MAX) ||
      !tlv_data[msg->type].write_tlv)
    return 0;

  if (tlv_data[msg->type].min_length > max_len)
    return 0;

  memset(hdr, 0, tlv_data[msg->type].min_length);
  return tlv_data[msg->type].write_tlv(hdr, msg, state, max_len);
}


/*
 *	Packet RX/TX functions
 */

static int
babel_send_to(struct babel_iface *ifa, ip_addr dest)
{
  sock *sk = ifa->sk;
  struct babel_pkt_header *hdr = (void *) sk->tbuf;
  int len = get_u16(&hdr->length) + sizeof(struct babel_pkt_header);

  DBG("Babel: Sending %d bytes to %I\n", len, dest);
  return sk_send_to(sk, len, dest, 0);
}

/**
 * babel_write_queue - Write a TLV queue to a transmission buffer
 * @ifa: Interface holding the transmission buffer
 * @queue: TLV queue to write (containing internal-format TLVs)
 *
 * This function writes a packet to the interface transmission buffer with as
 * many TLVs from the &queue as will fit in the buffer. It returns the number of
 * bytes written (NOT counting the packet header). The function is called by
 * babel_send_queue() and babel_send_unicast() to construct packets for
 * transmission, and uses per-TLV helper functions to convert the
 * internal-format TLVs to their wire representations.
 *
 * The TLVs in the queue are freed after they are written to the buffer.
 */
static uint
babel_write_queue(struct babel_iface *ifa, list *queue)
{
  struct babel_proto *p = ifa->proto;
  struct babel_write_state state = { .next_hop_ip6 = ifa->addr };

  if (EMPTY_LIST(*queue))
    return 0;

  byte *pos = ifa->sk->tbuf;
  byte *end = pos + ifa->tx_length;

  struct babel_pkt_header *pkt = (void *) pos;
  pkt->magic = BABEL_MAGIC;
  pkt->version = BABEL_VERSION;
  pkt->length = 0;
  pos += sizeof(struct babel_pkt_header);

  struct babel_msg_node *msg;
  WALK_LIST_FIRST(msg, *queue)
  {
    if (pos >= end)
      break;

    int len = babel_write_tlv((struct babel_tlv *) pos, &msg->msg, &state, end - pos);

    if (!len)
      break;

    pos += len;
    rem_node(NODE msg);
    sl_free(p->msg_slab, msg);
  }

  uint plen = pos - (byte *) pkt;
  put_u16(&pkt->length, plen - sizeof(struct babel_pkt_header));

  return plen;
}

void
babel_send_queue(void *arg)
{
  struct babel_iface *ifa = arg;
  while ((babel_write_queue(ifa, &ifa->msg_queue) > 0) &&
	 (babel_send_to(ifa, IP6_BABEL_ROUTERS) > 0));
}

static inline void
babel_kick_queue(struct babel_iface *ifa)
{
  /*
   * Only schedule send event if there is not already data in the socket buffer.
   * Otherwise we may overwrite the data already in the buffer.
   */

  if ((ifa->sk->tpos == ifa->sk->tbuf) && !ev_active(ifa->send_event))
    ev_schedule(ifa->send_event);
}

/**
 * babel_send_unicast - send a single TLV via unicast to a destination
 * @msg: TLV to send
 * @ifa: Interface to send via
 * @dest: Destination of the TLV
 *
 * This function is used to send a single TLV via unicast to a designated
 * receiver. This is used for replying to certain incoming requests, and for
 * sending unicast requests to refresh routes before they expire.
 */
void
babel_send_unicast(union babel_msg *msg, struct babel_iface *ifa, ip_addr dest)
{
  struct babel_proto *p = ifa->proto;
  struct babel_msg_node *msgn = sl_alloc(p->msg_slab);
  list queue;

  msgn->msg = *msg;
  init_list(&queue);
  add_tail(&queue, NODE msgn);
  babel_write_queue(ifa, &queue);
  babel_send_to(ifa, dest);

  /* We could overwrite waiting packet here, we may have to kick TX queue */
  if (!EMPTY_LIST(ifa->msg_queue))
    babel_kick_queue(ifa);
}

/**
 * babel_enqueue - enqueue a TLV for transmission on an interface
 * @msg: TLV to enqueue (in internal TLV format)
 * @ifa: Interface to enqueue to
 *
 * This function is called to enqueue a TLV for subsequent transmission on an
 * interface. The transmission event is triggered whenever a TLV is enqueued;
 * this ensures that TLVs will be transmitted in a timely manner, but that TLVs
 * which are enqueued in rapid succession can be transmitted together in one
 * packet.
 */
void
babel_enqueue(union babel_msg *msg, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_msg_node *msgn = sl_alloc(p->msg_slab);
  msgn->msg = *msg;
  add_tail(&ifa->msg_queue, NODE msgn);
  babel_kick_queue(ifa);
}

/**
 * babel_process_packet - process incoming data packet
 * @pkt: Pointer to the packet data
 * @len: Length of received packet
 * @saddr: Address of packet sender
 * @ifa: Interface packet was received on.
 *
 * This function is the main processing hook of incoming Babel packets. It
 * checks that the packet header is well-formed, then processes the TLVs
 * contained in the packet. This is done in two passes: First all TLVs are
 * parsed into the internal TLV format. If a TLV parser fails, processing of the
 * rest of the packet is aborted.
 *
 * After the parsing step, the TLV handlers are called for each parsed TLV in
 * order.
 */
static void
babel_process_packet(struct babel_pkt_header *pkt, int len,
                     ip_addr saddr, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_tlv *tlv;
  struct babel_msg_node *msg;
  list msgs;
  int res;

  int plen = sizeof(struct babel_pkt_header) + get_u16(&pkt->length);
  byte *pos;
  byte *end = (byte *)pkt + plen;

  struct babel_parse_state state = {
    .proto	  = p,
    .ifa	  = ifa,
    .saddr	  = saddr,
    .next_hop_ip6 = saddr,
    .sadr_enabled = babel_sadr_enabled(p),
  };

  if ((pkt->magic != BABEL_MAGIC) || (pkt->version != BABEL_VERSION))
  {
    TRACE(D_PACKETS, "Strange packet from %I via %s - magic %d version %d",
	  saddr, ifa->iface->name, pkt->magic, pkt->version);
    return;
  }

  if (plen > len)
  {
    LOG_PKT("Bad packet from %I via %s - %s (%u)",
	    saddr, ifa->iface->name, "length mismatch", plen);
    return;
  }

  TRACE(D_PACKETS, "Packet received from %I via %s",
        saddr, ifa->iface->name);

  init_list(&msgs);

  /* First pass through the packet TLV by TLV, parsing each into internal data
     structures. */
  for (tlv = FIRST_TLV(pkt);
       (byte *)tlv < end;
       tlv = NEXT_TLV(tlv))
  {
    /* Ugly special case */
    if (tlv->type == BABEL_TLV_PAD1)
      continue;

    /* The end of the common TLV header */
    pos = (byte *)tlv + sizeof(struct babel_tlv);
    if ((pos > end) || (pos + tlv->length > end))
    {
      LOG_PKT("Bad TLV from %I via %s type %d pos %d - framing error",
	      saddr, ifa->iface->name, tlv->type, (byte *)tlv - (byte *)pkt);
      break;
    }

    msg = sl_alloc(p->msg_slab);
    res = babel_read_tlv(tlv, &msg->msg, &state);
    if (res == PARSE_SUCCESS)
    {
      add_tail(&msgs, NODE msg);
    }
    else if (res == PARSE_IGNORE)
    {
      DBG("Babel: Ignoring TLV of type %d\n", tlv->type);
      sl_free(p->msg_slab, msg);
    }
    else /* PARSE_ERROR */
    {
      LOG_PKT("Bad TLV from %I via %s type %d pos %d - parse error",
	      saddr, ifa->iface->name, tlv->type, (byte *)tlv - (byte *)pkt);
      sl_free(p->msg_slab, msg);
      break;
    }
  }

  /* Parsing done, handle all parsed TLVs */
  WALK_LIST_FIRST(msg, msgs)
  {
    if (tlv_data[msg->msg.type].handle_tlv)
      tlv_data[msg->msg.type].handle_tlv(&msg->msg, ifa);
    rem_node(NODE msg);
    sl_free(p->msg_slab, msg);
  }
}

static void
babel_err_hook(sock *sk, int err)
{
  struct babel_iface *ifa = sk->data;
  struct babel_proto *p = ifa->proto;

  log(L_ERR "%s: Socket error on %s: %M", p->p.name, ifa->iface->name, err);
  /* FIXME: Drop queued TLVs here? */
}


static void
babel_tx_hook(sock *sk)
{
  struct babel_iface *ifa = sk->data;

  DBG("Babel: TX hook called (iface %s, src %I, dst %I)\n",
      sk->iface->name, sk->saddr, sk->daddr);

  babel_send_queue(ifa);
}


static int
babel_rx_hook(sock *sk, uint len)
{
  struct babel_iface *ifa = sk->data;
  struct babel_proto *p = ifa->proto;
  const char *err_dsc = NULL;
  uint err_val = 0;

  if (sk->lifindex != ifa->iface->index)
    return 1;

  DBG("Babel: RX hook called (iface %s, src %I, dst %I)\n",
      sk->iface->name, sk->faddr, sk->laddr);

  /* Silently ignore my own packets */
  if (ipa_equal(sk->faddr, sk->saddr))
    return 1;

  if (!ipa_is_link_local(sk->faddr))
    DROP1("wrong src address");

  if (sk->fport != ifa->cf->port)
    DROP("wrong src port", sk->fport);

  if (len < sizeof(struct babel_pkt_header))
    DROP("too short", len);

  if (sk->flags & SKF_TRUNCATED)
    DROP("truncated", len);

  babel_process_packet((struct babel_pkt_header *) sk->rbuf, len, sk->faddr, ifa);
  return 1;

drop:
  LOG_PKT("Bad packet from %I via %s - %s (%u)",
	  sk->faddr, sk->iface->name, err_dsc, err_val);
  return 1;
}

int
babel_open_socket(struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;

  sock *sk;
  sk = sk_new(ifa->pool);
  sk->type = SK_UDP;
  sk->sport = ifa->cf->port;
  sk->dport = ifa->cf->port;
  sk->iface = ifa->iface;
  sk->saddr = ifa->addr;
  sk->vrf = p->p.vrf;

  sk->rx_hook = babel_rx_hook;
  sk->tx_hook = babel_tx_hook;
  sk->err_hook = babel_err_hook;
  sk->data = ifa;

  sk->tos = ifa->cf->tx_tos;
  sk->priority = ifa->cf->tx_priority;
  sk->ttl = 1;
  sk->flags = SKF_LADDR_RX;

  if (sk_open(sk) < 0)
    goto err;

  if (sk_setup_multicast(sk) < 0)
    goto err;

  if (sk_join_group(sk, IP6_BABEL_ROUTERS) < 0)
    goto err;

  ifa->sk = sk;
  return 1;

err:
  sk_log_error(sk, p->p.name);
  rfree(sk);
  return 0;
}
