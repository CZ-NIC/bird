/*
 *	BIRD -- Simple Network Management Protocol (SNMP)
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 */

#include "lib/unaligned.h"
#include "subagent.h"
#include "bgp_mib.h"

/* =============================================================
 *  Problems
 *  ------------------------------------------------------------
 *
 *    change of remote ip -> no notification, no update
 *    same ip, different ports
 *    distinct VRF (two interfaces with overlapping private addrs)
 *    posible link-local addresses in LOCAL_IP
 *
 */

static int parse_response(struct snmp_proto *p, byte *buf, uint size);
static inline uint vb_size(struct agentx_varbind *vb);
static int snmp_stop_ack(sock *sk, uint size);
static void do_response(struct snmp_proto *p, byte *buf, uint size);
static uint parse_get_pdu(struct snmp_proto *p, byte *buf, uint size);
static uint parse_gets_pdu(struct snmp_proto *p, byte *buf, uint size);
static byte *prepare_response(struct snmp_proto *p, byte *buf, uint size);
static void response_err_ind(byte *buf, uint err, uint ind);
static struct oid *search_mib(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, struct oid *o_curr, uint contid);
static struct oid *prefixize(struct snmp_proto *p, struct oid *o, int byte_ord);
static inline byte *find_n_fill(struct snmp_proto *p, struct oid *o, byte *buf, uint size, uint contid, int byte_ord);
static byte *no_such_object(byte *buf, struct agentx_varbind *vb);

static const char * const snmp_errs[] = {
  #define SNMP_ERR_SHIFT 256
  [AGENTX_RES_OPEN_FAILED - SNMP_ERR_SHIFT] = "Open failed",
  [AGENTX_RES_NOT_OPEN - SNMP_ERR_SHIFT] = "Not open",
  [AGENTX_RES_INDEX_WRONG_TYPE - SNMP_ERR_SHIFT] = "Index wrong type",
  [AGENTX_RES_INDEX_ALREADY_ALLOC - SNMP_ERR_SHIFT] = "Index already allocated",
  [AGENTX_RES_INDEX_NONE_AVAIL - SNMP_ERR_SHIFT] = "Index none availlable",
  [AGENTX_RES_NOT_ALLOCATED - SNMP_ERR_SHIFT] = "Not allocated",
  [AGENTX_RES_UNSUPPORTED_CONTEXT - SNMP_ERR_SHIFT] = "Unsupported contex",
  [AGENTX_RES_DUPLICATE_REGISTR - SNMP_ERR_SHIFT] = "Duplicate registration",
  [AGENTX_RES_UNKNOWN_REGISTR - SNMP_ERR_SHIFT] = "Unknown registration",
  [AGENTX_RES_UNKNOWN_AGENT_CAPS - SNMP_ERR_SHIFT] = "Unknown agent caps",
  [AGENTX_RES_PARSE_ERROR - SNMP_ERR_SHIFT] = "Parse error",
  [AGENTX_RES_REQUEST_DENIED - SNMP_ERR_SHIFT] = "Request denied",
  [AGENTX_RES_PROCESSING_ERR - SNMP_ERR_SHIFT] = "Processing error",
};

/* payload length in bytes */
static inline size_t
pkt_len(byte *buf, byte *pkt)
{
  return (pkt - buf) - AGENTX_HEADER_SIZE;
}

static inline size_t
str_size(const char *str)
{
  return 4 + BIRD_ALIGN(strlen(str), 4);
}

int
snmp_valid_ip4_index(struct oid *o, uint start)
{
  for (int i = 0; i < 4; i++)
    if (o->ids[start + i] >= 256)
      return 0;	// false
 
  return 1; // true 
}

int
snmp_valid_ip4_index_safe(struct oid *o, uint start)
{
  if (start + 3 < o->n_subid)
    return snmp_valid_ip4_index(o, start);
  else
    return 0; // false
}

static byte *
put_str(byte *buf, const char *str)
{
  uint len = strlen(str);
  uint slen = BIRD_ALIGN(len, 4);

  if (len > MAX_STR)
    return NULL;

  STORE_PTR(buf, len);

  memcpy(buf + 4, str, len);

  for (uint i = 0; i < slen - len; i++)
    buf[len + i] = 0x00;  // PADDING

  return buf + str_size(str);
}

static byte *
put_blank(byte *buf)
{
  STORE_PTR(buf, 0);
  return buf + 4;
}

static byte *
put_oid(byte *buf, struct oid *oid)
{
  log(L_INFO "testing oid");
  for (uint i = 0; i < oid->n_subid; i++)
    log(L_INFO "oid id %d:  %u", i, oid->ids[i]);
  log(L_INFO "put_oid()");
  put_u8(buf, oid->n_subid);
  log(L_INFO "data %p: %02X", buf, *buf);
  put_u8(++buf, oid->prefix);
  log(L_INFO "data %p: %02X", buf, *buf);
  put_u8(++buf, oid->include);
  log(L_INFO "data %p: %02X", buf, *buf);
  put_u8(++buf, 0);  // PADDING
  /* last increment */
  ++buf;
  log(L_INFO "oid head end %p", buf);

  /* copy OID data */
#ifdef SNMP_NATIVE
  for (uint i = 0; i < oid->n_subid; i++)
    *(((u32 *) buf) + i) = oid->ids[i];
#else
  put_u32s(buf, oid->ids, oid->n_subid << 2);
#endif
/*
  for (uint i = 0; i <= (oid->n_subid << 2) +4 ; i += 4)
    log(L_INFO "OID % 3u: %02X %02X %02X %02X", i,
      *(buf - 4 + i),
      *(buf - 4 + i + 1),
      *(buf - 4 + i + 2),
      *(buf - 4  + i + 3)
  );
*/

  return buf + (oid->n_subid << 2);
}

void
snmp_oid_ip4_index(struct oid *o, ip4_addr addr)
{
  u32 temp = ip4_to_u32(addr);
  STORE(o->ids[5], temp >> 24);
  STORE(o->ids[6], (temp & 0x00FF0000) >> 16);
  STORE(o->ids[7], (temp & 0x0000FF00) >> 8);
  STORE(o->ids[8], temp & 0x000000FF);
}

/* paste data at first byte in message
 *   with 3B of padding
 */
static byte *
paste_fbyte(byte *buf, u8 data)
{
  log(L_INFO "paste_fbyte()");
  put_u8(buf, data);
  put_u24(++buf, 0);  // PADDING
  return buf + 3;
}

static void
open_pdu(struct snmp_proto *p, struct oid *oid)
{
  sock *sk = p->sock;
  byte *buf, *pkt;
  buf = pkt = sk->tbuf;
  uint size = sk->tbsize;

  // should be configurable
  const char *str = "bird";

  //uint pkt_size = 0;

  if (size > AGENTX_HEADER_SIZE + snmp_oid_size(oid) + str_size(str))
  {
    log(L_INFO "open_pdu()");

    struct agentx_header *h;
    SNMP_CREATE(pkt, struct agentx_header, h)
    SNMP_B_HEADER(h, AGENTX_OPEN_PDU)

    STORE(h->session_id, 1);
    STORE(h->transaction_id, 1);
    STORE(h->packet_id, 1);

    pkt = paste_fbyte(pkt, p->timeout);
    pkt = put_oid(pkt, oid);
    pkt = put_str(pkt, str);

    SNMP_UPDATE(h, pkt_len(buf, pkt));

    int ret = sk_send(sk, pkt - buf);

    if (ret == 0)
      log(L_INFO "sk_send sleep");
    else if (ret < 0)
      log(L_INFO "sk_send err %d", ret);
    else
      log(L_INFO "sk_send ok !!! ");
  }

  else
    log(L_INFO "open_pdu() insufficient size, %u <= %u ",
	size, AGENTX_HEADER_SIZE + snmp_oid_size(oid) + str_size(str));
}

/* index allocate / deallocate pdu * /
static void
de_allocate_pdu(struct snmp_proto *p, struct oid *oid, u8 type)
{
  sock *sk = p->sock;
  byte *buf, *pkt;
  buf = pkt = sk->tbuf;
  uint size = sk->tbsize;

  if (size > AGENTX_HEADER_SIZE + )
  {
    log(L_INFO "de_allocate_pdu()");

    struct agentx_header *h;
    SNMP_CREATE(pkt, struct agentx_header, h);
    SNMP_B_HEADER(h, type);
    SNMP_SESSION(h,p);

    struct agentx_varbind *vb = (struct agentx_varbind *) pkt;
    STORE_16(vb->type, AGENTX_OBJECT_ID);
    STORE(vb->oid,
  }

  else
    log(L_INFO "de_allocate_pdu(): insufficient size");
}
*/

/* register / unregister pdu */
static void
un_register_pdu(struct snmp_proto *p, struct oid *oid, uint index, uint len, u8 type)
{
  sock *sk = p->sock;
  byte *buf, *pkt;
  buf = pkt = sk->tbuf;
  uint size = sk->tbsize;

  /* conditional +4 for upper-bound */
  if (size > AGENTX_HEADER_SIZE + snmp_oid_size(oid) + ((len > 1) ? 4 : 0))
  {
    log(L_INFO "un_register_pdu()");
    struct agentx_un_register_pdu *ur;
    SNMP_CREATE(pkt, struct agentx_un_register_pdu, ur);
    struct agentx_header *h = &ur->h;

    // FIXME correctly set INSTANCE REGISTRATION bit
    SNMP_HEADER(h, type, AGENTX_FLAG_INSTANCE_REGISTRATION);
    SNMP_SESSION(h, p);

    /* do not override timeout */
    STORE(ur->timeout, 0);
    /* default priority */
    STORE(ur->priority, AGENTX_PRIORITY);
    STORE(ur->range_subid, (len > 1) ? index : 0);

    pkt = put_oid(pkt, oid);
    log(L_INFO "pkt - buf : %lu sizeof %u", pkt -buf, AGENTX_HEADER_SIZE);

    /* place upper-bound if needed */
    if (len > 1)
    {
      STORE_PTR(pkt, len);
      pkt += 4;
    }

    log("size of pkt: %u", pkt_len(buf,pkt));
    SNMP_UPDATE(h, pkt_len(buf, pkt));

    for (uint i = 0; i < pkt - buf; i++)
      log(L_INFO "%p:  %02X", buf+i, *(buf + i));

    log(L_INFO "sending (un)register %d", type);
    int ret = sk_send(sk, pkt - buf);

    if (ret == 0)
      log(L_INFO "sk_send sleep");
    else if (ret < 0)
      log(L_INFO "sk_send err %d", ret);
    else
      log(L_INFO "sk_send ok !!");
  }

  else
    log(L_INFO "un_register_pdu() insufficient size");
}

/* register pdu */
static void
snmp_register(struct snmp_proto *p, struct oid *oid, uint index, uint len)
{
  un_register_pdu(p, oid, index, len, AGENTX_REGISTER_PDU);
}


/* unregister pdu */
static void UNUSED
snmp_unregister(struct snmp_proto *p, struct oid *oid, uint index, uint len)
{
  un_register_pdu(p, oid, index, len, AGENTX_UNREGISTER_PDU);
}

static void
close_pdu(struct snmp_proto *p, u8 reason)
{
  sock *sk = p->sock;
  byte *buf, *pkt;
  buf = pkt = sk->tbuf;
  uint size = sk->tbsize;
  log(L_INFO "close_pdu() size: %u %c %u", size, (size > AGENTX_HEADER_SIZE + 4)
? '>':'<', AGENTX_HEADER_SIZE);

  /* +4B for reason */
  if (size > AGENTX_HEADER_SIZE + 4)
  {
    struct agentx_header *h;
    SNMP_CREATE(pkt, struct agentx_header, h)
    SNMP_B_HEADER(h, AGENTX_CLOSE_PDU)

    SNMP_SESSION(h, p)

    pkt = paste_fbyte(pkt, reason);

    SNMP_UPDATE(h, pkt_len(buf, pkt));

    log(L_INFO "preparing to sk_send()");
    int ret = sk_send(sk, pkt - buf);

    if (ret == 0)
      log(L_INFO "sk_send sleep");
    else if (ret < 0)
      log(L_INFO "sk_send err");
    else
      log(L_INFO, "sk_send ok !!");
  }
}

static inline void
refresh_ids(struct snmp_proto *p, struct agentx_header *h)
{
  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;
  p->transaction_id = LOAD(h->transaction_id, byte_ord);
  p->packet_id = LOAD(h->packet_id, byte_ord);
}

static int
parse_pkt(struct snmp_proto *p, byte *buf, uint size)
{
  if (size < AGENTX_HEADER_SIZE)
    return 0;

  uint len = 0;
  struct agentx_header *h = (void *) buf;
  log(L_INFO "parse_pkt got type %u", h->type);
  switch (h->type)
  {
    case AGENTX_RESPONSE_PDU:
      return parse_response(p, buf, size);

    /*
    case AGENTX_GET_PDU:
      refresh_ids(p, h);
      return parse_get_pdu(p, buf, size);
    */

    case AGENTX_GET_PDU:
    case AGENTX_GET_NEXT_PDU:
    case AGENTX_GET_BULK_PDU:
      refresh_ids(p, h);
      len = parse_gets_pdu(p, buf, size);
      break;

    /* should not happen */
    default:
      die("unknown packet type %u", h->type);
  }

  log(L_INFO "parsed, sending ... to addr %I:%u -> %I:%u",
    p->sock->saddr, p->sock->sport, p->sock->daddr, p->sock->dport);
  if (len && p->state != SNMP_ERR)
  {
    p->to_send = len;
    int ret = sk_send(p->sock, len);
    log(L_INFO "message sent");

    if (ret == 0)
      log(L_INFO "sk_send sleep");
    else if (ret < 0)
      log(L_INFO "sk_send err no: %d '%s'", ret, strerror(ret));
    else
      log("sk_send OK ! !!");
  }

  return len;
}

static int
parse_response(struct snmp_proto *p, byte *buf, uint size)
{
  if (size < sizeof(struct agentx_response))
    return 0;

  struct agentx_response *r = (void *) buf;
  struct agentx_header *h = &r->h;

  log(L_INFO "endianity: %s, session %u, transaction: %u", (h->flags & AGENTX_NETWORK_BYTE_ORDER) ? "big end":
"little end", h->session_id, h->transaction_id);
  log(L_INFO "sid: %3u\ttid: %3u\tpid: %3u\t", p->session_id, p->transaction_id,
p->packet_id);

  log(L_INFO "size %u", h->payload);
  log(L_INFO "uptime: %u s", r->uptime);

  if (r->err == AGENTX_RES_NO_ERROR)
    do_response(p, buf, size);
  else
    log(L_INFO "an error occured '%s'", snmp_errs[get_u16(&r->err) -
SNMP_ERR_SHIFT]);

  return 1;
}

static void
do_response(struct snmp_proto *p, byte *buf, uint size UNUSED)
{
  struct agentx_response *r = (void *) buf;
  struct agentx_header *h = &r->h;

  /* TODO make it asynchronous for better speed */
  switch (p->state)
  {
    case SNMP_INIT:
      if (h->flags & AGENTX_NETWORK_BYTE_ORDER)
      {
	p->session_id = get_u32(&h->session_id);
	p->transaction_id = get_u32(&h->transaction_id);
	p->packet_id = get_u32(&h->packet_id);
      }
      else
      {
	memcpy(&p->session_id, &h->session_id, 12);
      }

      p->transaction_id++;

      log(L_INFO "sending register-pdu");

      // register whole BGP4-MIB
      u32 arr_bgp[] = {1, 15, 1};
      struct oid *o = mb_allocz(p->p.pool, 4 * sizeof(u32));
      put_u8(&o->n_subid, 2);
      put_u8(&o->prefix, 2);

      memcpy(o->ids, arr_bgp, 2 * sizeof(u32));

      snmp_register(p, o, 0, 1);

      put_u8(&o->n_subid, 3);
      STORE(o->ids[2], arr_bgp[2]);
      snmp_register(p, o, 0, 1);


      STORE(o->ids[2], 2);
      snmp_register(p, o, 0, 1);

      mb_free(o);

      u32 arr_with_prefix[] = {1, 15, 3, 1, 1};
      struct oid *o2 = mb_allocz(p->p.pool, 10 * sizeof(u32));

      put_u8(&o2->n_subid, 9);
      memcpy(o2->ids, arr_with_prefix, 5 * sizeof(u32));
      u32 remote_addr[] = {10, 0, 0, 0};
      memcpy(o2->ids + 5, remote_addr, 4 * sizeof(u32));
      STORE(o2->prefix, 2);

      // register first line in BGP4-MIB bgpPeerTable
      // TODO register all bind bgp connections
      snmp_register(p, o2, 9, 24);

      log(L_INFO "before hash walk");
      HASH_WALK(p->bgp_hash, next, peer)
      {
	snmp_oid_ip4_index(o2, ipa_to_ip4(peer->peer_ip));

	log(L_INFO "");
	log(L_INFO "o2 n_subid %u prefix %u include %u", o2->n_subid,
	  o2->prefix, o2->include);
	for (int i = 0; i < o2->n_subid; i++)
	  log(L_INFO "%d: %u", i, o2->ids[i]);
	log(L_INFO "");

	snmp_register(p, o2, 9, 24);
      }
      HASH_WALK_END;
      log(L_INFO "after hash walk");

      mb_free(o2);

      p->state = SNMP_REGISTR;
      //proto_notify_state(&p->p, PS_UP);
      break;

    case SNMP_REGISTR:
      p->state = SNMP_CONN;
      break;

    case SNMP_CONN:
      break;

    default:
      die("unkonwn SNMP state");
  }
}

static uint UNUSED
parse_get_pdu(struct snmp_proto *p, byte *buf, uint size)
{
  log(L_INFO "parse_get_pdu()");

  sock *sk = p->sock;
  byte *res_pkt, *res = sk->tbuf;
  uint rsize = sk->tbsize;

  if (size < AGENTX_HEADER_SIZE)
    return 0;

  log(L_INFO "Get-PDU enough room %p", buf);

  struct agentx_header *h = (void *) buf;
  ADVANCE(buf, size, AGENTX_HEADER_SIZE);
  log(L_INFO "advancing %p cause %u", buf, AGENTX_HEADER_SIZE);

  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

  byte *pkt = buf;
  uint pkt_size = LOAD(h->payload, byte_ord);
  log(L_INFO "RX packet size is %u", pkt_size);

  uint clen;	      /* context len */
  char *context = NULL;
  SNMP_LOAD_CONTEXT(p, h, pkt, context, clen)
  log(L_INFO "after context load %p, pkt == buf %d", pkt, pkt == buf);

  res_pkt = prepare_response(p, res, rsize);
  log(L_INFO "response header created: %p (%u)", res_pkt, res_pkt - res);
  /* parsing one search range */
  uint ind = 1;
  int err = 0;
               /* parsed  */
  while (!err && pkt - buf < pkt_size)
  {
    struct oid *o_start, *o_end;
    o_start = (struct oid *) pkt;
    pkt += snmp_oid_size(o_start);
    o_end = (struct oid *) pkt;  // for Get-PDU always null
    pkt += snmp_oid_size(o_end);

    log(L_INFO "sizes o_start %lu o_end %lu", snmp_oid_size(o_start),
	snmp_oid_size(o_end));

    log(L_INFO "o_subid: %u o_prefix %u o_include %u ---",
	o_start->n_subid, o_start->prefix, o_start->include);


    /* currently unsupported non-default context */
    res_pkt = find_n_fill(p, o_start, res_pkt, rsize, 0, byte_ord);

    /*
    struct agentx_varbind *vb_start;
    vb_start = (void *) res_pkt;

    memcpy(&vb_start->name, o_start, oid_size(o_start));
    STORE_16(vb_start->type, AGENTX_INTEGER);
    STORE_16(vb_start->pad, 0);  // padding zeroing
    res_pkt += vb_size(vb_start);

    log(L_INFO " vb_size() rpkt %p %u", res_pkt, res_pkt - res);

    STORE_PTR(res_pkt, 0x1234ABCD);

    log(L_INFO " STORE_PTR int-value rpkt %p %u", res_pkt, res_pkt - res);
    res_pkt += 4;
    log(L_INFO " shift rpkt %p %u", res_pkt, res_pkt - res);
    */
    ind++;
  }

  struct agentx_header *rh = (void *) res;
  SNMP_UPDATE(rh, pkt_len(res, res_pkt));

  if (err)
    response_err_ind(res, err, ind);

  log(L_INFO "res->payload %u (loaded) %u, trying to send: %u",
    rh->payload, LOAD(rh->payload, rh->flags & AGENTX_NETWORK_BYTE_ORDER),
    res_pkt - res + 4);

  int ret = sk_send(sk, res_pkt - res);
  log(L_INFO "message sent");

  if (ret == 0)
    log(L_INFO "sk_send sleep");
  else if (ret < 0)
    log(L_INFO "sk_send err no: %d", ret);
  else
    log(L_INFO "sk_send OK !!");

  return 1;
}

static u8
get_mib_class(struct oid *oid)
{
  if (oid->prefix != 2 && oid->ids[0] != 1)
    return SNMP_CLASS_INVALID;

  switch (oid->ids[1])
  {
    case SNMP_BGP4_MIB:
      return SNMP_CLASS_BGP;

    default:
      return SNMP_CLASS_END;
  } 
}

/* req is request */
static uint
parse_gets_pdu(struct snmp_proto *p, byte *req, uint size)
{
  log(L_INFO "parse_gets_pdu");

  sock *sk = p->sock;
  byte *res_pkt, *res = sk->tbuf;
  uint rsize = sk->tbsize;

  if (size < AGENTX_HEADER_SIZE)
    return 0;

  struct agentx_header *h = (void *) req;
  ADVANCE(req, size, AGENTX_HEADER_SIZE);
  log(L_INFO "advancing %p cause header", req);

  byte *pkt = req;

  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;
  uint pkt_size = LOAD(h->payload, byte_ord);

  uint clen;
  char *context;
  SNMP_LOAD_CONTEXT(p, h, req, context, clen);

  res_pkt = prepare_response(p, res, rsize);
  uint ind = 1;
  int err = 0;
  while (!err && pkt - req < pkt_size)
  {
    struct oid *o_start_b, *o_end_b;
    o_start_b = (struct oid *) pkt;
    pkt += snmp_oid_size(o_start_b);
    o_end_b = (struct oid *) pkt;
    pkt += snmp_oid_size(o_end_b);

    /* advertised size of oid is greater then size of message */
    if (snmp_oid_size(o_start_b) > size || snmp_oid_size(o_end_b) > size)
    {
      log(L_INFO "too big o_start or o_end");
      err = -1;  /* parse error too big n_subid (greater than message) */
      continue;
    }

    /* object identifier (oid) normalization */
    struct oid *o_start = prefixize(p, o_start_b, byte_ord);
    struct oid *o_end = prefixize(p, o_end_b, byte_ord);

    u8 mib_class = get_mib_class(o_start);
    switch (h->type)
    {
      case AGENTX_GET_PDU:
	log(L_INFO "type Get-PDU");
	res_pkt = snmp_mib_fill(p, o_start, mib_class, res_pkt, rsize, 0, byte_ord);
	//res_pkt = find_n_fill(p, o_start, res_pkt, rsize, 0, byte_ord);
	break;

      case AGENTX_GET_NEXT_PDU:
	log(L_INFO "type GetNext-PDU");

	o_start = search_mib(p, o_start, o_end, NULL, 0);
	if (o_start)
	  res_pkt = snmp_mib_fill(p, o_start, mib_class, res_pkt, rsize, 0, byte_ord);
	  //res_pkt = find_n_fill(p, o_start, res_pkt, rsize, 0, byte_ord);
	else
	{
	  log(L_INFO "null o_start GetNext-PDU err handling next");
	  err = -2;
	  continue;
	}
	break;

      case AGENTX_GET_BULK_PDU:
      {
	log(L_INFO "type GetBulk-PDU");

	struct oid  *o_curr = NULL;
	/* TODO add res packet size limiting logic */
	while ((o_curr = search_mib(p, o_start, o_end, o_curr, 0)) != NULL)
	{
	  res_pkt = snmp_mib_fill(p, o_curr, mib_class, res_pkt, rsize, 0, byte_ord);
	  //res_pkt = find_n_fill(p, o_curr, res_pkt, rsize, 0, byte_ord);
	}

        mb_free(o_curr);

	/* no item found */
	if (res_pkt == res + sizeof(struct agentx_response))
	{
	  log(L_INFO "no item found ");
	  err = -2;
	  continue;
	}
	break;
      }
    }

    mb_free(o_start);
    mb_free(o_end);

    ind++;
  }

  switch (err)
  {
    case 0:
      response_err_ind(req, AGENTX_RES_NO_ERROR, 0);
      err = 1;
      break;
    case -1:
      response_err_ind(req, AGENTX_RES_PARSE_ERROR, ind);
      break;

    /* no item found - could it happen? */
    case -2:
      response_err_ind(req, AGENTX_RES_GEN_ERROR, ind);
      break;
  }

  log(L_INFO " pasting size");
  struct agentx_header *rh = (void *) res;
  SNMP_UPDATE(rh, pkt_len(res, res_pkt));

  log(L_INFO "%p %lu", p->sock->ttx, res_pkt - res);
  log(L_INFO "%p %p", res_pkt, res);

  for (int i = 0; i < res_pkt - res; i++)
    log(L_INFO "%p: %02X", res + i, *(res + i));

  return res_pkt - res;
}

void
snmp_start_subagent(struct snmp_proto *p)
{
  log(L_INFO "snmp_start_subagent() starting subagent");

  /* blank oid means unsupported */
  struct oid *o = mb_allocz(p->p.pool, sizeof(struct oid));
  open_pdu(p, o);
  mb_free(o);
}

void
snmp_stop_subagent(struct snmp_proto *p)
{
  log(L_INFO "snmp_stop_subagent()");
  sock *sk = p->sock;

  if (p->state == SNMP_CONN)
  {
    close_pdu(p, AGENTX_CLOSE_SHUTDOWN);

    sk->rx_hook = snmp_stop_ack;
  }
}

/* return number of bytes used  by @o */
uint
snmp_oid_size(struct oid *o)
{
  /* faster multipication by 4 */
  return 4 + (o->n_subid << 2);
}

static inline int
oid_prefix(struct oid *o, u32 *prefix, uint len)
{
  for (uint i = 0; i < len; i++)
    if (o->ids[i] != prefix[i])
      return 0; // false

  return 1; // true
}

/* return number of bytes used by @vb */
static inline uint
vb_size(struct agentx_varbind *vb)
{
  /* +4B for type and pad */
  return snmp_oid_size(&vb->name) + 4;
}

int
snmp_rx(sock *sk, uint size)
{
  log(L_INFO "snmp_rx()");
  struct snmp_proto *p = sk->data;
  byte *pkt = sk->rbuf;

  // 1 means all done; 0 means to be continued
  return parse_pkt(p, pkt, size);
  /*
  while (end >= pkt + AGENTX_HEADER_SIZE)
  {
    parse_header(p);
    parse_pkt(p, );
  }
  */
}

/* ping pdu */
void
snmp_ping(struct snmp_proto *p)
{
  /* this does not support non-default context */
  sock *sk = p->sock;
  byte *pkt = sk->tbuf;
  uint size = sk->tbsize;

  if (size > AGENTX_HEADER_SIZE)
  {
    log(L_INFO "ping_pdu()");
    struct agentx_header *h;
    log("before dead %p", pkt );
    SNMP_CREATE(pkt, struct agentx_header, h);
    SNMP_B_HEADER(h, AGENTX_PING_PDU);
    SNMP_SESSION(h, p);

    /* sending only header => pkt - buf */
    int ret = sk_send(sk, AGENTX_HEADER_SIZE);

    if (ret == 0)
      log(L_INFO "sk_send sleep");
    else if (ret < 0)
      log(L_INFO "sk_send err %d", ret);
    else
      log("sk_send ok ! !");
  }

  else
    log(L_INFO "ping_pdu() insufficient size");
}


static int
snmp_stop_ack(sock *sk, uint size)
{
  struct snmp_proto *p = sk->data;
  byte *buf = sk->rbuf;

  if (size < AGENTX_HEADER_SIZE)
    return 0;

  if (parse_response(p, buf, size))
  {
    p->p.disabled = 1;
    proto_notify_state(&p->p, PS_DOWN);

    sk->tx_hook = NULL;
    sk->rx_hook = NULL;
  }

  /* all done */
  return 0;
}

/*
void
snmp_agent_reconfigure(void)
{

}

static int
compare(struct oid *left, struct oid *right)
{
  const u32 INTERNET_PREFIX[] = {1, 3, 6, 1};

  if (left->prefix == 0 && right->prefix == 0)
    goto test_ids;

  if (right->prefix == 0)
  {
    struct oid *temp = left;
    left = right;
    right = temp;
  }

  if (left->prefix == 0)
  {
    for (int i = 0; i < 4; i++)
      if (left->ids[i] < INTERNET_PREFIX[i])
	return -1;
      else if (left->ids[i] > INTERNET_PREFIX[i])
	return 1;

    for (int i = 0; i < MIN(left->n_subid - 4, right->n_subid); i++)
      if (left->ids[i + 4] < right->ids[i])
	return -1;
      else if (left->ids[i + 4] > right->ids[i])
	return 1;

    goto all_same;
  }

  if (left->prefix < right->prefix)
    return -1;
  else if (left->prefix > right->prefix)
    return 1;

test_ids:
  for (int i = 0; i < MIN(left->n_subid, right->n_subid); i++)
    if (left->ids[i] < right->ids[i])
      return -1;
    else if (left->ids[i] > right->ids[i])
      return 1;

all_same:
  / * shorter sequence is before longer in lexicografical order * /
  if (left->n_subid < right->n_subid)
    return -1;
  else if (left->n_subid > right->n_subid)
    return 1;
  else
    return 0;
}

*/

static inline int
is_bgp4_mib_prefix(struct oid *o)
{
  if (o->prefix == 2 && o->ids[0] == 15)
    return 1;
  else
    return 0;
}

static inline int
has_inet_prefix(struct oid *o)
{
  return (o->n_subid > 4 && o->ids[0] == 1 &&
	  o->ids[1] == 3 && o->ids[2] == 6 &&
	  o->ids[3] == 1);
}

/* tree is tree with "internet" prefix .1.3.6.1 
   working only with o_start, o_end allocated in heap (not from buffer)*/
static struct oid *
search_mib(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, struct oid *o_curr, uint contid UNUSED)
{
  log(L_INFO "search_mib()");

  if (!o_start)
    return NULL;

  if (!o_curr)
  {
    o_curr = mb_alloc(p->p.pool, snmp_oid_size(o_start));
    memcpy(o_curr, o_start, snmp_oid_size(o_start));
    // XXX is it right time to free o_start right now (here) ?
  }

  if (o_curr->n_subid > 1 &&
      o_curr->ids[0] == 1)
  {
    switch (o_curr->ids[1])
    {
      case SNMP_BGP4_MIB:
	return search_bgp_mib(p, o_curr, o_end, 0);
        
      default:
        return NULL;
    }
  }

  return NULL;
}

static byte *
find_bgp_one(struct bgp_proto *bp, struct oid *o, byte *pkt, uint size UNUSED, uint contid UNUSED)
{
  struct bgp_conn *b_conn = bp->conn;
  struct bgp_conn *b_in = &bp->incoming_conn;
  struct bgp_conn *b_out = &bp->outgoing_conn;

  struct bgp_stats *b_stats = &bp->stats;
  const struct bgp_config *b_conf = bp->cf;

  uint b_state;

  if (b_conn)
    b_state = b_conn->state;
  else if (MAX(b_in->state, b_out->state) == BS_CLOSE &&
    MIN(b_in->state, b_out->state) != BS_CLOSE)
    b_state = MIN(b_in->state, b_out->state);
  /* BS_CLOSE is unsupported by BGP4-MIB */
  else if (MIN(b_in->state, b_out->state) == BS_CLOSE)
    b_state = BS_IDLE;
  else
    b_state = MAX(b_in->state, b_out->state);

  struct agentx_varbind *vb = (void *) pkt;
  pkt += vb_size(vb);

  switch (o->ids[4])
  {
    case SNMP_BGP_IDENTIFIER:
      if (b_state == BS_OPENCONFIRM || b_state == BS_ESTABLISHED)
      {
	STORE_PTR(pkt, ipa_to_u32(bp->remote_ip));
	BGP_DATA(vb, AGENTX_IP_ADDRESS, pkt);
      }
      else
      {
	put_blank(pkt);		/* store 4B of zeroes */
	BGP_DATA(vb, AGENTX_IP_ADDRESS, pkt);
      }
      break;

    case SNMP_BGP_STATE:
      STORE_PTR(pkt, b_state);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case SNMP_BGP_ADMIN_STATUS:
      if (((struct proto *) bp)->disabled)
	STORE_PTR(pkt, AGENTX_ADMIN_STOP);
      else
	STORE_PTR(pkt, AGENTX_ADMIN_START);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case SNMP_BGP_NEGOTIATED_VERSION:
      if (b_state == BS_OPENCONFIRM || b_state == BS_ESTABLISHED)
	STORE_PTR(pkt, 4);
      else
	STORE_PTR(pkt, 0);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case SNMP_BGP_LOCAL_ADDR:
      // TODO XXX bp->link_addr & zero local_ip
      STORE_PTR(pkt, ipa_to_u32(bp->local_ip));
      BGP_DATA(vb, AGENTX_IP_ADDRESS, pkt);
      break;

    case SNMP_BGP_LOCAL_PORT:
      STORE_PTR(pkt, b_conf->local_port);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case SNMP_BGP_REMOTE_ADDR:
      STORE_PTR(pkt, ipa_to_u32(bp->remote_ip));
      BGP_DATA(vb, AGENTX_IP_ADDRESS, pkt);
      break;

    case SNMP_BGP_REMOTE_PORT:
      STORE_PTR(pkt, b_conf->remote_port);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case SNMP_BGP_REMOTE_AS:
      STORE_PTR(pkt, bp->remote_as);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    /* IN UPDATES */
    case SNMP_BGP_RX_UPDATES:
      STORE_PTR(pkt, b_stats->rx_updates);
      BGP_DATA(vb, AGENTX_COUNTER_32, pkt);
      break;

    /* OUT UPDATES */
    case SNMP_BGP_TX_UPDATES:
      STORE_PTR(pkt, b_stats->tx_updates);
      BGP_DATA(vb, AGENTX_COUNTER_32, pkt);
      break;

    /* IN MESSAGES */
    case SNMP_BGP_RX_MESSAGES:
      STORE_PTR(pkt, b_stats->rx_messages);
      BGP_DATA(vb, AGENTX_COUNTER_32, pkt);
      break;

    /* OUT MESSAGES */
    case SNMP_BGP_TX_MESSAGES:
      STORE_PTR(pkt, b_stats->tx_messages);
      BGP_DATA(vb, AGENTX_COUNTER_32, pkt);
      break;

    case SNMP_BGP_LAST_ERROR:
      STORE_PTR(pkt, 2);
      pkt += 4;
      /* force network order */
      put_u32(pkt,
	(bp->last_error_code << 8 | bp->last_error_code << 24) & 0xFFFF0000);
      /* real size is 8 but we already shifted the pkt by 4 */
      BGP_DATA(vb, AGENTX_OCTET_STRING, pkt);
      break;

    case SNMP_BGP_FSM_TRANSITIONS:
      STORE_PTR(pkt, b_stats->fsm_established_transitions);
      BGP_DATA(vb, AGENTX_COUNTER_32, pkt);
      break;

    case SNMP_BGP_RETRY_INTERVAL:
      STORE_PTR(pkt, b_conf->connect_retry_time);
      BGP_DATA(vb, AGENTX_COUNTER_32, pkt);
      break;

    case SNMP_BGP_HOLD_TIME:
      if (b_conn && b_conf->hold_time)
	STORE_PTR(pkt, b_conn->hold_time);
      else
	STORE_PTR(pkt, 0);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case SNMP_BGP_KEEPALIVE:
      if (b_conn && b_conf->keepalive_time)
	STORE_PTR(pkt, b_conn->keepalive_time);
      else
	STORE_PTR(pkt, 0);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case SNMP_BGP_HOLD_TIME_CONFIGURED:
      STORE_PTR(pkt, b_conf->hold_time);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case SNMP_BGP_KEEPALIVE_CONFIGURED:
      STORE_PTR(pkt, b_conf->keepalive_time);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    /* UNSUPPORTED */
    /* TODO XXX forbiden value 0 */
    case SNMP_BGP_ORIGINATION_INTERVAL:
    case SNMP_BGP_MIN_ROUTE_ADVERTISEMENT:
      STORE_PTR(pkt, 0);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case SNMP_BGP_FSM_ESTABLISHED_TIME:
    case SNMP_BGP_IN_UPDATE_ELAPSED_TIME:
      return no_such_object(pkt, vb);

    /* no default */
  }

  return pkt;
}

/* contid - context identification number */
static byte *
snmp_bgp_record(struct snmp_proto *p, struct oid *o, byte *buf, uint size, uint contid)
{
  struct agentx_varbind *vb = (void *) buf;
  byte *pkt = buf + vb_size(vb);

  switch (o->ids[2])
  {
    case SNMP_BGP_VERSION:
      STORE_PTR(pkt, 1);   // string len
      pkt += 4;
      STORE_PTR(pkt, BGP4_VERSIONS);
      /* real size is 8 but we already shifted the pkt by 4 */
      BGP_DATA(vb, AGENTX_OCTET_STRING, pkt);
      break;

    case SNMP_BGP_LOCAL_AS:
      // XXX local as to use
      STORE_PTR(pkt, p->local_as);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case SNMP_BGP_PEER_TABLE:
      /* end part of .1.3.6.1.2.1.15.3.1.x.a.b.c.d */
      if (o->n_subid < 9 || o->ids[3] != SNMP_BGP_PEER_ENTRY
	  || o->ids[4] == 0 || o->ids[4] > 24)
	return no_such_object(pkt, vb);

      // TODO enumerate range requests
      ip_addr addr = ipa_build4(o->ids[5], o->ids[6], o->ids[7], o->ids[8]);
      struct snmp_bgp_peer *pe =
        HASH_FIND(p->bgp_hash, SNMP_HASH, addr);

      struct bgp_proto *bp = NULL;
      if (pe && ((struct proto_config *)pe->config)->proto &&
	  ipa_equal(addr,
	    (((struct bgp_proto *) ((struct proto_config *)pe->config)->proto)->remote_ip)))
      {
	bp = (void *) ((struct proto_config *) pe->config)->proto;
      }

      /* IF WE CONSIDER CHANGES OF REMOTE IP
      else
      {
	struct snmp_bond *b;
	WALK_LIST(b, p->bgp_entries)
	  if (b->proto->proto &&
	      ipa_equal(((struct bgp_proto *) b->proto->proto)->remote_ip, addr))
	    bp = (struct bgp_proto *) b->proto->proto;
      }
      */

      if (!bp)
	/* pkt += 0; no data */
	return no_such_object(pkt, vb);

      return find_bgp_one(bp, o, buf, size, contid);
      break;

    default:
      /* pkt += 0; no data */
      return no_such_object(pkt, vb);
  }

  return pkt;
}

/*
static byte *
find_ospf_record(struct snmp_proto *p, struct oid *o, byte *buf, uint size)
{
  // TODO XXX
  return NULL;
}
*/

static byte *
no_such_object(byte *buf, struct agentx_varbind *vb)
{
  vb->type = AGENTX_NO_SUCH_OBJECT;
  return buf;
}

static UNUSED byte *
no_such_instance(byte *buf, struct agentx_varbind *vb)
{
  vb->type = AGENTX_NO_SUCH_INSTANCE;
  return buf;
}

static inline byte *
find_prefixed(struct snmp_proto *p, struct oid *o, byte *buf, uint size, uint contid)
{
  struct agentx_varbind *vb = (void *) buf;

  memcpy(&vb->name, o, snmp_oid_size(o));

                       /* SNMPv2   mgmt		     mib-2 */
  if (o->n_subid < 2 || (o->prefix != 2 && o->ids[0] != 1))
    no_such_object(buf + vb_size(vb), vb);

  switch (o->ids[1])
  {
    case SNMP_BGP4_MIB:
      log(L_INFO "find_prefixed() BGP4");
      return snmp_bgp_record(p, o, buf, size, contid);

    case SNMP_OSPFv3_MIB:
      return no_such_object(buf, vb);
      //return find_ospf_record(p, o, buf, size);

    default:
      return no_such_object(buf, vb);
  }
}

/** 
 * prefixize - return prefixed oid copy if possible
 * @proto: allocation pool holder
 * @oid: from packet loaded object identifier
 * @byte_ord: byte order of @oid 
 *
 * Returns prefixed (meaning with nonzero prefix field) oid copy of @oid if
 * possible. NULL otherwise. Returned pointer is always allocated from @proto's
 * pool not a pointer to recieve buffer (from which is most likely @oid).
 */
static struct oid *
prefixize(struct snmp_proto *proto, struct oid *oid, int byte_ord)
{
  const u32 prefix[] = {1, 3, 6, 1};

  if (oid->n_subid < 5)
    return NULL;

  for (int i = 0; i < 4; i++)
    if (LOAD(oid->ids[i], byte_ord) != prefix[i])
      return NULL;

  if (oid->ids[4] >= 256)
    return NULL;

  struct oid *new = mb_alloc(proto->p.pool, 
          sizeof(struct oid) + MAX((oid->n_subid - 5) * sizeof(u32), 0));

  memcpy(new, oid, sizeof(struct oid));
  new->n_subid = oid->n_subid - 5;

  /* validity check before allocation => ids[4] < 256 
     and can be copied to one byte new->prefix */
  new->prefix = oid->ids[4];

  memcpy(&new->ids, &oid->ids[5], new->n_subid * sizeof(u32));
  return new;
}

static inline byte *
find_n_fill(struct snmp_proto *p, struct oid *o, byte *buf, uint size, uint contid, int byte_ord)
{
  struct oid *new;
  if (!o->prefix && (new = prefixize(p, o, byte_ord)) != NULL)
    return find_prefixed(p, new, buf, size, contid);
  else if (o->prefix)
    return find_prefixed(p, o, buf, size, contid);

  return NULL;
}

/**
 * snmp_mib_fill - 
 */
static byte *
snmp_mib_fill(struct snmp_proto *p, struct oid *oid, u8 mib_class, byte *buf,
uint size, uint contid, int byte_ord)
{ 
  struct agentx_varbind *vb = (void *) buf;

  memcpy(&vb->name, oid, snmp_oid_size(oid));

                       /* SNMPv2   mgmt		     mib-2 */
  if (oid->n_subid < 2 || (oid->prefix != 2 && oid->ids[0] != 1))
    return no_such_object(buf + vb_size(vb), vb);

  switch (mib_class)
  {
    case SNMP_CLASS_BGP:
      buf = snmp_bgp_fill(p, oid, buf, size, contid, byte_ord);
      break;   
  }
 
  return buf; 
}

static byte *
prepare_response(struct snmp_proto *p, byte *buf, uint size)
{
  log(L_INFO "prepare_response()");

  if (size < sizeof(struct agentx_response))
    return NULL;
  struct agentx_response *r = (void *) buf;
  struct agentx_header *h = &r->h;

  SNMP_B_HEADER(h, AGENTX_RESPONSE_PDU)
  SNMP_SESSION(h, p)

  /* protocol doesn't care about subagent upTime */
  STORE(r->uptime, 0);
  STORE_16(r->err, AGENTX_RES_NO_ERROR);
  STORE_16(r->index, 0);

  buf += sizeof(struct agentx_response);
  return buf;
}

static void
response_err_ind(byte *buf, uint err, uint ind)
{
  log(L_INFO "reponse_err_ind() %u %u", err, ind);
  struct agentx_response *res = (void *) buf;

  res->err = err;
  res->index = ind;
}

#undef SNMP_ERR_SHIFT
