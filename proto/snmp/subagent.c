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
#include "snmp_utils.h"
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

static byte *snmp_mib_fill(struct snmp_proto *p, struct oid *oid, u8 mib_class,
byte *buf, uint size, struct snmp_error *error, uint contid, int byte_ord);

static int parse_response(struct snmp_proto *p, byte *buf, uint size);
// static int snmp_stop_ack(sock *sk, uint size);
static int do_response(struct snmp_proto *p, byte *buf, uint size);
// static uint parse_get_pdu(struct snmp_proto *p, byte *buf, uint size);
static uint parse_gets_pdu(struct snmp_proto *p, byte *buf, uint size);
static byte *prepare_response(struct snmp_proto *p, byte *buf, uint size);
static void response_err_ind(byte *buf, uint err, uint ind);
static struct oid *search_mib(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, struct oid *o_curr, u8 mib_class, uint contid);
// static inline byte *find_n_fill(struct snmp_proto *p, struct oid *o, byte *buf, uint size, uint contid, int byte_ord);


static const char * const snmp_errs[] = {
  #define SNMP_ERR_SHIFT 256
  [AGENTX_RES_OPEN_FAILED	  - SNMP_ERR_SHIFT] = "Open failed",
  [AGENTX_RES_NOT_OPEN		  - SNMP_ERR_SHIFT] = "Not open",
  [AGENTX_RES_INDEX_WRONG_TYPE	  - SNMP_ERR_SHIFT] = "Index wrong type",
  [AGENTX_RES_INDEX_ALREADY_ALLOC - SNMP_ERR_SHIFT] = "Index already allocated",
  [AGENTX_RES_INDEX_NONE_AVAIL	  - SNMP_ERR_SHIFT] = "Index none availlable",
  [AGENTX_RES_NOT_ALLOCATED	  - SNMP_ERR_SHIFT] = "Not allocated",
  [AGENTX_RES_UNSUPPORTED_CONTEXT - SNMP_ERR_SHIFT] = "Unsupported contex",
  [AGENTX_RES_DUPLICATE_REGISTER  - SNMP_ERR_SHIFT] = "Duplicate registration",
  [AGENTX_RES_UNKNOWN_REGISTER	  - SNMP_ERR_SHIFT] = "Unknown registration",
  [AGENTX_RES_UNKNOWN_AGENT_CAPS  - SNMP_ERR_SHIFT] = "Unknown agent caps",
  [AGENTX_RES_PARSE_ERROR	  - SNMP_ERR_SHIFT] = "Parse error",
  [AGENTX_RES_REQUEST_DENIED	  - SNMP_ERR_SHIFT] = "Request denied",
  [AGENTX_RES_PROCESSING_ERR	  - SNMP_ERR_SHIFT] = "Processing error",
};

static const char * const snmp_pkt_type[] = {
  [AGENTX_OPEN_PDU]		  =  "Open-PDU",
  [AGENTX_CLOSE_PDU]		  =  "Close-PDU",
  [AGENTX_REGISTER_PDU]		  =  "Register-PDU",
  [AGENTX_UNREGISTER_PDU]	  =  "Unregister-PDU",
  [AGENTX_GET_PDU]		  =  "Get-PDU",
  [AGENTX_GET_NEXT_PDU]		  =  "GetNext-PDU",
  [AGENTX_GET_BULK_PDU]		  =  "GetBulk-PDU",
  [AGENTX_TEST_SET_PDU]		  =  "TestSet-PDU",
  [AGENTX_COMMIT_SET_PDU]	  =  "CommitSet-PDU",
  [AGENTX_UNDO_SET_PDU]		  =  "UndoSet-PDU",
  [AGENTX_CLEANUP_SET_PDU]	  =  "CleanupSet-PDU",
  [AGENTX_NOTIFY_PDU]		  =  "Notify-PDU",
  [AGENTX_PING_PDU]		  =  "Ping-PDU",
  [AGENTX_INDEX_ALLOCATE_PDU]     =  "IndexAllocate-PDU",
  [AGENTX_INDEX_DEALLOCATE_PDU]   =  "IndexDeallocate-PDU",
  [AGENTX_ADD_AGENT_CAPS_PDU]	  =  "AddAgentCaps-PDU",
  [AGENTX_REMOVE_AGENT_CAPS_PDU]  =  "RemoveAgentCaps-PDU",
  [AGENTX_RESPONSE_PDU]		  =  "Response-PDU",
};

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

  if (size > AGENTX_HEADER_SIZE + snmp_oid_size(oid) + snmp_str_size(str))
  {
    snmp_log("open_pdu()");

    struct agentx_header *h;
    SNMP_CREATE(pkt, struct agentx_header, h)
    SNMP_B_HEADER(h, AGENTX_OPEN_PDU)

    STORE(h->session_id, 1);
    STORE(h->transaction_id, 1);
    STORE(h->packet_id, 1);

    pkt = snmp_put_fbyte(pkt, p->timeout);
    pkt = snmp_put_oid(pkt, oid);
    pkt = snmp_put_str(pkt, str);

    SNMP_UPDATE(h, snmp_pkt_len(buf, pkt));

    int ret = sk_send(sk, pkt - buf);

    if (ret == 0)
      snmp_log("sk_send sleep");
    else if (ret < 0)
      snmp_log("sk_send err %d", ret);
    else
      snmp_log("sk_send ok !!!");
  }

  else
    snmp_log("open_pdu() insufficient size, %u <= %u ",
	size, AGENTX_HEADER_SIZE + snmp_oid_size(oid) + snmp_str_size(str));
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
    snmp_log("de_allocate_pdu()");

    struct agentx_header *h;
    SNMP_CREATE(pkt, struct agentx_header, h);
    SNMP_B_HEADER(h, type);
    SNMP_SESSION(h,p);

    struct agentx_varbind *vb = (struct agentx_varbind *) pkt;
    STORE_16(vb->type, AGENTX_OBJECT_ID);
    STORE(vb->oid,
  }

  else
    snmp_log("de_allocate_pdu(): insufficient size");
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
    snmp_log("un_register_pdu()");
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

    pkt = snmp_put_oid(pkt, oid);
    // snmp_log("pkt - buf : %lu sizeof %u", pkt -buf, AGENTX_HEADER_SIZE);

    /* place upper-bound if needed */
    if (len > 1)
    {
      STORE_PTR(pkt, len);
      pkt += 4;
    }

    // log("size of pkt: %u", snmp_pkt_len(buf,pkt));
    SNMP_UPDATE(h, snmp_pkt_len(buf, pkt));

    /*
    for (uint i = 0; i < pkt - buf; i++)
      snmp_log("%p:  %02X", buf+i, *(buf + i));
    */

    snmp_log("sending (un)register %s", snmp_pkt_type[type]);
    int ret = sk_send(sk, pkt - buf);

    if (ret == 0)
      snmp_log("sk_send sleep");
    else if (ret < 0)
      snmp_log("sk_send err %d", ret);
    else
      snmp_log("sk_send ok !!");
  }

  else
    snmp_log("un_register_pdu() insufficient size");
}

/* register pdu */
void
snmp_register(struct snmp_proto *p, struct oid *oid, uint index, uint len)
{
  un_register_pdu(p, oid, index, len, AGENTX_REGISTER_PDU);
}


/* unregister pdu */
void UNUSED
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
  snmp_log("close_pdu() size: %u %c %u", size, (size > AGENTX_HEADER_SIZE + 4)
? '>':'<', AGENTX_HEADER_SIZE);

  /* +4B for reason */
  if (size > AGENTX_HEADER_SIZE + 4)
  {
    struct agentx_header *h;
    SNMP_CREATE(pkt, struct agentx_header, h)
    SNMP_B_HEADER(h, AGENTX_CLOSE_PDU)

    SNMP_SESSION(h, p)

    pkt = snmp_put_fbyte(pkt, reason);

    SNMP_UPDATE(h, snmp_pkt_len(buf, pkt));

    snmp_log("preparing to sk_send()");
    int ret = sk_send(sk, pkt - buf);

    if (ret == 0)
      snmp_log("sk_send sleep");
    else if (ret < 0)
      snmp_log("sk_send err");
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

  snmp_log("parse_pkt got type %s", snmp_pkt_type[h->type]);

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

  snmp_log("parsed, sending ... to addr %I:%u -> %I:%u",
    p->sock->saddr, p->sock->sport, p->sock->daddr, p->sock->dport);
  if (len && p->state != SNMP_ERR)
  {
    p->to_send = len;
    int ret = sk_send(p->sock, len);
    snmp_log("message sent");

    if (ret == 0)
      snmp_log("sk_send sleep");
    else if (ret < 0)
      snmp_log("sk_send err no: %d '%s'", ret, strerror(ret));
    else
      log("sk_send OK ! !!");
  }

  /* whole buffer was parsed while generating response */
  if (len == size)
    return 1; /* meaning buffer is empty */
  else
    return 0; /* meaning buffer stil contain some data to be parsed, parsing is not finished */
}

static int
parse_response(struct snmp_proto *p, byte *buf, uint size)
{
  snmp_log("parse_response() g%u h%u", size, sizeof(struct agentx_header));

  snmp_dump_packet(buf, size);

  if (size < sizeof(struct agentx_response))
    return 0;

  struct agentx_response *r = (void *) buf;
  struct agentx_header *h = &r->h;

  snmp_log("  endianity: %s, session %u, transaction: %u", (h->flags & AGENTX_NETWORK_BYTE_ORDER) ? "big end":
"little end", h->session_id, h->transaction_id);
  snmp_log("  sid: %3u\ttid: %3u\tpid: %3u", p->session_id, p->transaction_id,
p->packet_id);

  snmp_log("  pkt size %u", h->payload);
  // snmp_log("uptime: %u s", r->uptime);

  if (r->err == AGENTX_RES_NO_ERROR)
    return do_response(p, buf, size);
  else
    // TODO handle corrupted packets properly (and return appropriate retval)
    snmp_log("an error occured '%s'", snmp_errs[get_u16(&r->err) -
SNMP_ERR_SHIFT]);

  return 1;
}

static inline int
snmp_registered_all(struct snmp_proto *p)
{
  snmp_log("snmp_registered_all() %u", list_length(&p->register_queue));
  return p->register_to_ack == 0;
}

static void
snmp_register_mibs(struct snmp_proto *p) {
  snmp_log("snmp_register_mibs()");

  snmp_bgp_register(p);

  snmp_log("registering all done");
}

static int
do_response(struct snmp_proto *p, byte *buf, uint size UNUSED)
{
  snmp_log("do_response()");
  struct agentx_response *r = (void *) buf;
  struct agentx_header *h = &r->h;

  int network_byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

  /* TODO make it asynchronous for better speed */
  switch (p->state)
  {
    case SNMP_INIT:
      /* parse open_pdu response */
      if (network_byte_ord)
      {
	p->session_id = get_u32(&h->session_id);
	p->transaction_id = get_u32(&h->transaction_id);
	p->packet_id = get_u32(&h->packet_id);
      }
      else
      {
	memcpy(&p->session_id, &h->session_id, 12);
      }

      /* the state needs to be changed before sending registering PDUs to
       * use correct do_response action on them
       */
      snmp_log("changing state to REGISTER");
      p->state = SNMP_REGISTER;
      snmp_register_mibs(p);
      snmp_log("do_response state SNMP_INIT register list %u", list_length(&p->register_queue));

      break;

    case SNMP_REGISTER:
      snmp_log("do_response state SNMP_REGISTER register list %u", list_length(&p->register_queue));
      snmp_register_ack(p ,h);

      if (snmp_registered_all(p)) {
	snmp_log("changing proto_snmp state to CONNECTED");
	p->state = SNMP_CONN;
      }
      break;

    case SNMP_CONN:
      // proto_notify_state(&p->p, PS_UP);
      break;

    case SNMP_STOP:
      /* do nothing here */
      break;

    default:
      die("unkonwn SNMP state");
  }

  uint pkt_size = LOAD(h->payload, network_byte_ord) + sizeof(struct agentx_header);
  snmp_log("do_response size %u pkt_size %u", size, pkt_size);
  if (size > pkt_size)
  {
    memmove(buf, buf + pkt_size, size - pkt_size);
    snmp_dump_packet(buf, size - pkt_size);
    return 0;
  }
  else
    /* all parsed */
    return 1;
}

#if 0
static uint UNUSED
parse_get_pdu(struct snmp_proto *p, byte *buf, uint size)
{
  snmp_log("parse_get_pdu()");

  sock *sk = p->sock;
  byte *res_pkt, *res = sk->tbuf;
  uint rsize = sk->tbsize;

  if (size < AGENTX_HEADER_SIZE)
    return 0;

  snmp_log("Get-PDU enough room %p", buf);

  struct agentx_header *h = (void *) buf;
  ADVANCE(buf, size, AGENTX_HEADER_SIZE);
  snmp_log("advancing %p cause %u", buf, AGENTX_HEADER_SIZE);

  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

  byte *pkt = buf;
  uint pkt_size = LOAD(h->payload, byte_ord);
  snmp_log("RX packet size is %u", pkt_size);

  uint clen;	      /* context len */
  char *context = NULL;
  SNMP_LOAD_CONTEXT(p, h, pkt, context, clen)
  snmp_log("after context load %p, pkt == buf %d", pkt, pkt == buf);

  res_pkt = prepare_response(p, res, rsize);
  snmp_log("response header created: %p (%u)", res_pkt, res_pkt - res);
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

    snmp_log("sizes o_start %lu o_end %lu", snmp_oid_size(o_start),
	snmp_oid_size(o_end));

    snmp_log("o_subid: %u o_prefix %u o_include %u ---",
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

    snmp_log(" vb_size() rpkt %p %u", res_pkt, res_pkt - res);

    STORE_PTR(res_pkt, 0x1234ABCD);

    snmp_log(" STORE_PTR int-value rpkt %p %u", res_pkt, res_pkt - res);
    res_pkt += 4;
    snmp_log(" shift rpkt %p %u", res_pkt, res_pkt - res);
    */
    ind++;
  }

  struct agentx_header *rh = (void *) res;
  SNMP_UPDATE(rh, snmp_pkt_len(res, res_pkt));

  if (err)
    response_err_ind(res, err, ind);

  snmp_log("res->payload %u (loaded) %u, trying to send: %u",
    rh->payload, LOAD(rh->payload, rh->flags & AGENTX_NETWORK_BYTE_ORDER),
    res_pkt - res + 4);

  int ret = sk_send(sk, res_pkt - res);
  snmp_log("message sent");

  if (ret == 0)
    snmp_log("sk_send sleep");
  else if (ret < 0)
    snmp_log("sk_send err no: %d", ret);
  else
    snmp_log("sk_send OK !!");

  return 1;
}
#endif

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

static byte *
snmp_get_next(struct snmp_proto *p, struct oid *o_start, struct oid *o_end,
byte *pkt, uint rsize, uint contid, u8 mib_class, int byte_ord)
{
  snmp_log("type GetNext-PDU");
  struct oid *o_copy;
  o_copy = search_mib(p, o_start, o_end, NULL, mib_class, contid);

  snmp_log("search result");
  snmp_oid_dump(o_copy);

  struct snmp_error error = (struct snmp_error) {
    .oid = o_start,
    .type = AGENTX_END_OF_MIB_VIEW,
  };

  /*
  pkt = snmp_mib_fill(
    p, o_copy, mib_class, pkt, rsize, &error, contid, byte_ord
  );
  */

  if (o_copy)
  {
    pkt = snmp_mib_fill(
      p, o_copy, mib_class, pkt, rsize, &error, contid, byte_ord
    );

    mb_free(o_copy);
  }
  else
  {
    struct agentx_varbind *vb = snmp_create_varbind(pkt, o_start);
    pkt += snmp_varbind_size(vb);
    vb->type = AGENTX_NO_SUCH_OBJECT;
  }

  snmp_log("over HERE ");
  return pkt;
}

static byte *
snmp_get_bulk(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, byte *pkt, uint size, struct agentx_bulk_state *state, uint contid, int byte_ord)
{
  snmp_log("type GetBulk-PDU");

  u8 mib_class = get_mib_class(o_start);

  if (state->index <= state->getbulk.non_repeaters)
  {
    return snmp_get_next(p, o_start, o_end, pkt, size, contid, mib_class, byte_ord);
  }

  else
  {
    u8 mib_class = get_mib_class(o_start);
    struct oid *o_curr = NULL;
    struct oid *o_predecessor;

    uint i = 0;
    do
    {
      o_predecessor = o_curr;
      o_curr = search_mib(p, o_start, o_end, o_curr, mib_class, contid);
      mib_class = get_mib_class(o_curr);
      i++;
    } while (o_curr != NULL && i < state->repetition);

    log("bulk search result - repeating");
    snmp_oid_dump(o_curr);

    struct snmp_error error = (struct snmp_error) {
      .oid = (o_predecessor != NULL) ? o_predecessor : o_start,
      .type = AGENTX_END_OF_MIB_VIEW,
    };

    return snmp_mib_fill(p, o_curr, mib_class, pkt, size, &error, contid, byte_ord);

    // REMOVE ME
    #if 0
    last *byte = pkt;
    if (o_curr)
    {
      pkt = snmp_mib_fill(p, o_curr, mib_class, pkt, size, contid, byte_ord);
    }

    else if (!o_curr || pkt == last)
    {
      state->failed++;

      if (!o_predecessor)
	o_predecessor = o_start;

      struct agentx_varbind *vb = snmp_create_varbind(pkt, o_predecessor);
      pkt += snmp_varbind_size(vb);
      vb->type = AGENTX_END_OF_MIB_VIEW;
    }

    return pkt;
    #endif
  }
}

/* req is request */
static uint
parse_gets_pdu(struct snmp_proto *p, byte *req, uint size)
{
  snmp_log("parse_gets_pdu");

  sock *sk = p->sock;
  byte *res_pkt, *res = sk->tbuf;
  uint rsize = sk->tbsize;

  if (size < AGENTX_HEADER_SIZE)
    return 0;

  struct agentx_header *h = (void *) req;
  ADVANCE(req, size, AGENTX_HEADER_SIZE);
  snmp_log("advancing %p cause header", req);

  byte *pkt = req;

  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;
  uint pkt_size = LOAD(h->payload, byte_ord);

  uint clen;
  char *context;
  SNMP_LOAD_CONTEXT(p, h, req, context, clen);

  res_pkt = prepare_response(p, res, rsize);

  /* used only for state AGENTX_GET_BULK_PDU */
  struct agentx_bulk_state bulk_state;

  if (h->type == AGENTX_GET_BULK_PDU)
  {
    struct agentx_getbulk *bulk = (void*) res_pkt;
    res_pkt += sizeof(struct agentx_getbulk);
    bulk_state = (struct agentx_bulk_state) {
      .getbulk.non_repeaters = LOAD(bulk->non_repeaters, byte_ord),
      .getbulk.max_repetitions = LOAD(bulk->max_repetitions, byte_ord),
      .index = 1,
      .repetition = 1,
    };
  }

  uint ind = 1;
  int err = 0;
  while (!err && pkt - req < pkt_size)
  {
    /* oids from message buffer */
    struct oid *o_start_b, *o_end_b;
    o_start_b = (struct oid *) pkt;
    pkt += snmp_oid_size(o_start_b);
    o_end_b = (struct oid *) pkt;
    pkt += snmp_oid_size(o_end_b);

    /* advertised size of oid is greater then size of message */
    if (snmp_oid_size(o_start_b) > size || snmp_oid_size(o_end_b) > size)
    {
      snmp_log("too big o_start or o_end");
      err = -1;  /* parse error too big n_subid (greater than message) */
      continue;
    }

    snmp_oid_dump(o_start_b);
    snmp_oid_dump(o_end_b);
    /* object identifier (oid) normalization */

    struct oid *o_start = snmp_prefixize(p, o_start_b, byte_ord);
    struct oid *o_end = snmp_prefixize(p, o_end_b, byte_ord);

    snmp_oid_dump(o_start);
    snmp_oid_dump(o_end);

    u8 mib_class = get_mib_class(o_start);

    snmp_log("get mib_class () %d -> next pdu parsing ... ", mib_class);

    switch (h->type)
    {
      case AGENTX_GET_PDU:
	snmp_log("type Get-PDU");

	struct snmp_error error = (struct snmp_error) {
	  .oid = o_start,
	  .type = AGENTX_NO_SUCH_OBJECT,
	};

	res_pkt = snmp_mib_fill(p, o_start, mib_class, res_pkt, rsize, &error, 0, byte_ord);

	//res_pkt = find_n_fill(p, o_start, res_pkt, rsize, 0, byte_ord);
	break;

      case AGENTX_GET_NEXT_PDU:
	res_pkt = snmp_get_next(p, o_start, o_end, res_pkt, rsize, 0, mib_class, byte_ord);

	break;

      case AGENTX_GET_BULK_PDU:
	res_pkt = snmp_get_bulk(p, o_start, o_end, res_pkt, rsize, &bulk_state, 0, byte_ord);
	break;

      // REMOVE ME
      #if 0
      {
	snmp_log("type GetBulk-PDU");

	struct oid  *o_curr = NULL;
	/* TODO add res packet size limiting logic */
	while ((o_curr = search_mib(p, o_start, o_end, o_curr, mib_class, 0)) != NULL)
	{
	  res_pkt = snmp_mib_fill(p, o_curr, mib_class, res_pkt, rsize, 0, byte_ord);
	  //res_pkt = find_n_fill(p, o_curr, res_pkt, rsize, 0, byte_ord);
	}

        mb_free(o_curr);

	/* no item found */
	if (res_pkt == res + sizeof(struct agentx_response))
	{
	  snmp_log("no item found ");
	  err = -2;
	  continue;
	}
	break;
      }
      #endif
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

  snmp_log(" pasting size");
  struct agentx_header *rh = (void *) res;
  SNMP_UPDATE(rh, snmp_pkt_len(res, res_pkt));

  snmp_log("%p %lu", p->sock->ttx, res_pkt - res);
  snmp_log("%p %p", res_pkt, res);

  for (int i = 0; i < res_pkt - res; i++)
    snmp_log("%p: %02X", res + i, *(res + i));

  return res_pkt - res;
}

void
snmp_start_subagent(struct snmp_proto *p)
{
  snmp_log("snmp_start_subagent() starting subagent");

  /* blank oid means unsupported */
  struct oid *blank = snmp_oid_blank(p);
  open_pdu(p, blank);
  mb_free(blank);
}

void
snmp_stop_subagent(struct snmp_proto *p)
{
  snmp_log("snmp_stop_subagent() state %s", p->state);
  // sock *sk = p->sock;

  if (p->state == SNMP_STOP)
    close_pdu(p, AGENTX_CLOSE_SHUTDOWN);
}

static inline int
oid_prefix(struct oid *o, u32 *prefix, uint len)
{
  for (uint i = 0; i < len; i++)
    if (o->ids[i] != prefix[i])
      return 0; // false

  return 1; // true
}

int
snmp_rx(sock *sk, uint size)
{
  snmp_log("snmp_rx()");
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
    snmp_log("ping_pdu()");
    struct agentx_header *h;
    SNMP_CREATE(pkt, struct agentx_header, h);
    SNMP_B_HEADER(h, AGENTX_PING_PDU);
    SNMP_SESSION(h, p);

    /* sending only header => pkt - buf */
    int ret = sk_send(sk, AGENTX_HEADER_SIZE);

    if (ret == 0)
      snmp_log("sk_send sleep");
    else if (ret < 0)
      snmp_log("sk_send err %d", ret);
    else
      snmp_log("sk_send ok ! !");
  }

  else
    snmp_log("ping_pdu() insufficient size");
}

#if 0
static int
snmp_stop_ack(sock *sk, uint size)
{
  struct snmp_proto *p = sk->data;
  byte *buf = sk->rbuf;

  if (size < AGENTX_HEADER_SIZE)
    return 0;

  // TODO FIXME parse_response could return 0 even if waiting packet was parsed
  if (parse_response(p, buf, size))
  {
    // p->p.disabled = 1;
    proto_notify_state(&p->p, PS_DOWN);

    //sk->tx_hook = NULL;
    //sk->rx_hook = NULL;
  }

  /* all done */
  return 0;
}
#endif

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

/**
 * upper_bound_check - check if oid is before SearchRange end
 *
 * @found: best oid found in MIB tree
 * @bound: upper bound specified in SearchRange
 *
 * check if found oid meet the SearchRange upper bound condition in
 * lexicographical order, returns boolean value
 */
static int
upper_bound_check(struct oid *found, struct oid *bound)
{
  if (snmp_is_oid_empty(bound))
    return 1;

  if (snmp_oid_compare(found, bound) < 0)
    return 0;

  return 0;
}

static inline struct oid *
search_mib_unchecked(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, struct oid *o_curr, u8 mib_class UNUSED, uint contid UNUSED)
{
  snmp_log("search_mib_unchecked()");

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
	o_curr = search_bgp_mib(p, o_curr, o_end, 0);

	if (o_curr != NULL)
	  return o_curr;


	/* fall through */

	/*
	case SNMP_OSPF_MIB:
	  o_curr = search_bgp_mib(p, o_curr, o_end, 0);

	  if (o_curr != NULL)
	    return o_curr;
	  // fall through
	 */

      default:
        return NULL;
    }
  }

  return NULL;
}

/* tree is tree with "internet" prefix .1.3.6.1
   working only with o_start, o_end allocated in heap (not from buffer)*/
static struct oid *
search_mib(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, struct oid *o_curr, u8 mib_class, uint contid UNUSED)
{
  struct oid *found = search_mib_unchecked(p, o_start, o_end, o_curr, mib_class, contid);

  if (upper_bound_check(found, o_end))
    return found;
  else {
    mb_free(found);
    return NULL;
  }
}

// XXX moved to bgp_mib.c
#if 0
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

  struct agentx_varbind *vb = snmp_create_varbind(pkt, o);
  pkt += snmp_varbind_size(vb);

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
	snmp_put_blank(pkt);		/* store 4B of zeroes */
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
      vb->type = AGENTX_NO_SUCH_OBJECT;      

    /* no default */
  }

  return pkt;
}
#endif

#if 0
/* contid - context identification number */
static byte *
snmp_bgp_record(struct snmp_proto *p, struct oid *o, byte *buf, uint size, uint contid)
{
  struct agentx_varbind *vb = snmp_create_varbind(buf, o);
  byte *pkt = buf + snmp_varbind_size(vb);

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
	vb->type = AGENTX_NO_SUCH_OBJECT;

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
      { /* pkt += 0; no data inserted into the packet */
	vb->type = AGENTX_NO_SUCH_OBJECT;
	return pkt;
      }

      return find_bgp_one(bp, o, buf, size, contid);
      break;

    default:
      /* pkt += 0; no data */
      vb->type = AGENTX_NO_SUCH_OBJECT;
  }

  return pkt;
}
#endif

/*
static byte *
find_ospf_record(struct snmp_proto *p, struct oid *o, byte *buf, uint size)
{
  // TODO XXX
  return NULL;
}
*/

#if 0
static inline byte *
find_prefixed(struct snmp_proto *p, struct oid *o, byte *buf, uint size, uint contid)
{
  snmp_log("find_prefixed() - shouldn't be called");
  struct agentx_varbind *vb = snmp_create_varbind(buf, o);
  buf += snmp_varbind_size(vb);

                       /* SNMPv2   mgmt		     mib-2 */
  if (o->n_subid < 2 || (o->prefix != 2 && o->ids[0] != 1))
  {
    vb->type = AGENTX_NO_SUCH_OBJECT;
    return buf;
  }

  switch (o->ids[1])
  {
    case SNMP_BGP4_MIB:
      snmp_log("find_prefixed() BGP4");
      //return snmp_bgp_record(p, o, buf, size, contid);
      return buf;

    case SNMP_OSPFv3_MIB:
      //return snmp_no_such_object(buf, vb);
	  //return find_ospf_record(p, o, buf, size);
     return buf; 

    default:
      vb->type = AGENTX_NO_SUCH_OBJECT;
      return buf; 
      //return snmp_no_such_object(buf, vb);
  }
}
#endif

/** 
 * snmp_prefixize - return prefixed oid copy if possible
 * @proto: allocation pool holder
 * @oid: from packet loaded object identifier
 * @byte_ord: byte order of @oid 
 *
 * Returns prefixed (meaning with nonzero prefix field) oid copy of @oid if
 * possible, NULL otherwise. Returned pointer is always allocated from @proto's
 * pool not a pointer to recieve buffer (from which is most likely @oid).
 */
struct oid *
snmp_prefixize(struct snmp_proto *proto, struct oid *oid, int byte_ord)
{
  const u32 prefix[] = {1, 3, 6, 1};

  if (oid == NULL)
    return NULL;

  if (snmp_is_oid_empty(oid))
  {
    /* allocate new zeroed oid */
    return snmp_oid_blank(proto);
  }
  else if (LOAD(oid->n_subid, byte_ord) != 0)
  {
    struct oid *new = mb_allocz(proto->p.pool, snmp_oid_size(oid));
    memcpy(new, oid, snmp_oid_size(oid));
    return new;
  }

  if (oid->n_subid < 5)
    return NULL;

  for (int i = 0; i < 4; i++)
    if (LOAD(oid->ids[i], byte_ord) != prefix[i])
      return NULL;

  /* validity chech here */
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

#if 0
static inline byte *
find_n_fill(struct snmp_proto *p, struct oid *o, byte *buf, uint size, uint contid, int byte_ord)
{
  struct oid *new;
  if (!o->prefix && (new = snmp_prefixize(p, o, byte_ord)) != NULL)
    return find_prefixed(p, new, buf, size, contid);
  else if (o->prefix)
    return find_prefixed(p, o, buf, size, contid);

  return NULL;
}
#endif

/**
 * snmp_mib_fill - 
 */
static byte *snmp_mib_fill(struct snmp_proto *p, struct oid *oid, u8 mib_class,
byte *buf, uint size, struct snmp_error *error, uint contid, int byte_ord)
{
  snmp_log("snmp_mib_fill()");

  if (oid == NULL)
    return buf;

  struct agentx_varbind *vb = snmp_create_varbind(buf, oid);
  buf += snmp_varbind_size(vb);

                       /* SNMPv2      mgmt		  mib-2 */
  if (oid->n_subid < 2 || (oid->prefix != 2 && oid->ids[0] != 1))
  {
    vb->type = AGENTX_NO_SUCH_OBJECT; 
    return buf;
  }

  byte *last = buf;
  switch (mib_class)
  {
    case SNMP_CLASS_BGP:
      buf = snmp_bgp_fill(p, vb, buf, size, contid, byte_ord);
      break;
  }
 
  if (last == buf)
  {
    buf = snmp_fix_varbind(vb, error->oid);
    vb->type = error->type;
  }

  return buf;
}

static byte *
prepare_response(struct snmp_proto *p, byte *buf, uint size)
{
  snmp_log("prepare_response()");

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
  snmp_log("reponse_err_ind() %u %u", err, ind);
  struct agentx_response *res = (void *) buf;

  res->err = err;
  res->index = ind;
}

#undef SNMP_ERR_SHIFT
