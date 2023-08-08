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
 *    context is allocated as copied, is it approach really needed? wouldn't it
 *	sufficient just use the context in rx-buffer?
 *
 */

//static byte *snmp_mib_fill(struct snmp_proto *p, struct oid *oid, u8 mib_class, struct snmp_pdu_context *c);

static void snmp_mib_fill2(struct snmp_proto *p, struct oid *oid, struct snmp_pdu_context *c);
static uint parse_response(struct snmp_proto *p, byte *buf, uint size);
//static uint parse_response(struct snmp_proto *p, byte *buf, uint size);
// static int snmp_stop_ack(sock *sk, uint size);
static void do_response(struct snmp_proto *p, byte *buf, uint size);
//static uint parse_gets_pdu(struct snmp_proto *p, byte *buf, uint size, uint *skip);
static uint parse_gets2_pdu(struct snmp_proto *p, byte *buf, uint size, uint *skip);
//static uint parse_gets_pdu(struct snmp_proto *p, struct snmp_pdu_context *c);
// static uint parse_close_pdu(struct snmp_proto *p, struct snmp_pdu_context *c);
static uint parse_close_pdu(struct snmp_proto *p, byte *buf, uint size);
static struct agentx_response *prepare_response(struct snmp_proto *p, struct snmp_pdu_context *c);
//static byte *prepare_response(struct snmp_proto *p, struct snmp_pdu_context *c);
//static struct agentx_response *prepare_response(struct snmp_proto *p, byte *buf, uint size);
static void response_err_ind(struct agentx_response *res, uint err, uint ind);
static uint update_packet_size(struct snmp_proto *p, byte *start, byte *end);
//static void response_err_ind(byte *buf, uint err, uint ind);
//static struct oid *search_mib(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, struct oid *o_curr, u8 mib_class, struct snmp_pdu_context *c);
static struct oid *search_mib(struct snmp_proto *p, const struct oid *o_start, const struct oid *o_end, struct oid *o_curr, struct snmp_pdu_context *c, enum snmp_search_res *result);
//static struct oid *search_mib(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, struct oid *o_curr, u8 mib_class, uint contid);
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
  struct snmp_pdu_context c = {
    .buffer = sk->tpos,
    .size = sk->tbuf + sk->tbsize - sk->tpos,
  };
  byte *buf = c.buffer;

  // TODO should be configurable; with check on string length
  const char *str = "bird";

  /* +4 for timeout (1B with 4B alignment) */
  if (c.size < AGENTX_HEADER_SIZE + snmp_oid_size(oid) + snmp_str_size(str) + 4)
  {
    snmp_manage_tbuf(p, &c);
    buf = c.buffer;
  }

  struct agentx_header *h = (struct agentx_header *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);
  SNMP_BLANK_HEADER(h, AGENTX_OPEN_PDU);

  STORE_U32(h->session_id, 1);
  STORE_U32(h->transaction_id, 1);
  STORE_U32(h->packet_id, 1);

  c.size -= (4 + snmp_oid_size(oid) + snmp_str_size(str));
  c.buffer = snmp_put_fbyte(c.buffer, p->timeout);
  c.buffer = snmp_put_oid(c.buffer, oid);
  c.buffer = snmp_put_str(c.buffer, str);

  snmp_log("send PDU data (open) ...");
  uint s = update_packet_size(p, buf, c.buffer);
  int ret = sk_send(sk, s);
  if (ret > 0)
    snmp_log("sk_send OK!");
  else if (ret == 0)
    snmp_log("sk_send sleep");
  else
    snmp_log("sk_send error");
}

#if 0
static int
de_allocate_pdu(struct snmp_proto *p, struct oid *oids[], uint len,
		struct agentx_alloc_context *ac, u8 type)
{
  sock *sk = p->sock;
  //byte *buf = sk->tbuf;
  //uint size = sk->tbsize;
  byte *buf = sk->tpos;
  uint size = sk->tbuf + sk->tbsize - sk->tpos;

  uint total_len = 0;
  struct oid *o_curr = NULL;
  for (uint i = 0; i < len; i++)
  {
    o_curr = oids[i];
    uint sz = snmp_oid_size(o_curr);
    total_len += sz;
  }

  if (total_len == 0)
    return 0;

  if (size < AGENTX_HEADER_SIZE + total_len)
  {
    // need bigger tx buffer (more mem)
    return 0;
  }

  int blank = AGENTX_FLAG_BLANK;
  struct agentx_header *h;
  SNMP_CREATE(buf, struct agentx_header, h);
  SNMP_HEADER(h, type,
      (ac->is_instance ? AGENTX_FLAG_INSTANCE_REGISTRATION : blank)
    | (ac->new_index ? AGENTX_FLAG_NEW_INDEX : blank)
    | (ac->any_index ? AGENTX_FLAG_ANY_INDEX : blank));
  ADVANCE(buf, size, AGENTX_HEADER_SIZE);
  STORE(h->payload, total_len);

  for (uint i = 0; i < len; i++)
  {
    o_curr = oids[i];
    // TODO fix copy to buffer
    memcpy(buf, o_curr, snmp_oid_size(o_curr));
    ADVANCE(buf, size, snmp_oid_size(o_curr));
  }

  // increment p->packet_id
  // queue the allocation request

  int ret = sk_send(sk, total_len);
  if (ret == 0)
  {
    snmp_log("sk_send sleep");
    return 1;
  }
  else if (ret < 0)
  {
    snmp_log("sk_send err %d", ret);
    return 1;
  }
  else
  {
    snmp_log("sk_send ok !!");
    return 0;
  }
}

static int UNUSED
index_allocate_pdu(struct snmp_proto *p, struct oid *oids[], uint len, struct
agentx_alloc_context *ac)
{
  return de_allocate_pdu(p, oids, len, ac, AGENTX_INDEX_ALLOCATE_PDU);
}

static int UNUSED
index_deallocate_pdu(struct snmp_proto *p, struct oid *oids[], uint len, struct
agentx_alloc_context *ac)
{
  return de_allocate_pdu(p, oids, len, ac, AGENTX_INDEX_DEALLOCATE_PDU);
}
#endif

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
    SNMP_BLANK_HEADER(h, type);
    SNMP_SESSION(h,p);

    struct agentx_varbind *vb = (struct agentx_varbind *) pkt;
    STORE_16(vb->type, AGENTX_OBJECT_ID);
    STORE(vb->oid,
  }

  else
    snmp_log("de_allocate_pdu(): insufficient size");
}
*/

/* Register-PDU / Unregister-PDU */
static inline void
un_register_pdu(struct snmp_proto *p, struct oid *oid, uint index, uint len, u8 type, u8 is_instance)
{
  sock *sk = p->sock;
  //buf = pkt = sk->tbuf;
  //uint size = sk->tbsize;
  struct snmp_pdu_context c = {
    .buffer = sk->tpos,
    .size =  sk->tbuf + sk->tbsize - sk->tpos,
  };
  byte *buf = c.buffer;

  /* conditional +4 for upper-bound */
  if (c.size < AGENTX_HEADER_SIZE + snmp_oid_size(oid) + ((len > 1) ? 4 : 0))
  {
    snmp_log("un_register_pdu() insufficient size");
    snmp_manage_tbuf(p, &c);
    buf = c.buffer;
  }

  snmp_log("un_register_pdu()");
  struct agentx_un_register_pdu *ur = (struct agentx_un_register_pdu *)c.buffer;
  ADVANCE(c.buffer, c.size, sizeof(struct agentx_un_register_pdu));
  struct agentx_header *h = &ur->h;

  // FIXME correctly set INSTANCE REGISTRATION bit
  SNMP_HEADER(h, type, is_instance ? AGENTX_FLAG_INSTANCE_REGISTRATION : 0);
  /* use new transactionID, reset packetID */
  p->packet_id++;
  SNMP_SESSION(h, p);

  /* do not override timeout */
  STORE_U32(ur->timeout, 15);
  /* default priority */
  STORE_U32(ur->priority, AGENTX_PRIORITY);
  STORE_U32(ur->range_subid, (len > 1) ? index : 0);

  snmp_put_oid(c.buffer, oid);
  ADVANCE(c.buffer, c.size, snmp_oid_size(oid));
  // snmp_log("pkt - buf : %lu sizeof %u", pkt -buf, AGENTX_HEADER_SIZE);

  /* place upper-bound if needed */
  if (len > 1)
  {
    STORE_PTR(c.buffer, len);
    ADVANCE(c.buffer, c.size, 4);
  }

  uint s = update_packet_size(p, buf, c.buffer);

  snmp_log("sending (un)register %s", snmp_pkt_type[type]);
  int ret = sk_send(sk, s);
  if (ret > 0)
    snmp_log("sk_send OK!");
  else if (ret == 0)
    snmp_log("sk_send sleep");
  else
    snmp_log("sk_send error");
}

/* register pdu */
void
snmp_register(struct snmp_proto *p, struct oid *oid, uint index, uint len, u8 is_instance)
{
  un_register_pdu(p, oid, index, len, AGENTX_REGISTER_PDU, is_instance);
}


/* unregister pdu */
void UNUSED
snmp_unregister(struct snmp_proto *p, struct oid *oid, uint index, uint len)
{
  un_register_pdu(p, oid, index, len, AGENTX_UNREGISTER_PDU, 0);
}

static void
close_pdu(struct snmp_proto *p, u8 reason)
{
  sock *sk = p->sock;
  struct snmp_pdu_context c = {
    .buffer = sk->tpos,
    .size = sk->tbuf + sk->tbsize - sk->tpos,
  };
  byte *buf = c.buffer;

  snmp_log("close_pdu() size: %u %c %u", c.size, (c.size > AGENTX_HEADER_SIZE + 4)
? '>':'<', AGENTX_HEADER_SIZE);

  /* +4B for reason */
  if (c.size < AGENTX_HEADER_SIZE + 4)
  {
    snmp_manage_tbuf(p, &c);
    buf = c.buffer;
  }

  struct agentx_header *h = (struct agentx_header *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);
  SNMP_BLANK_HEADER(h, AGENTX_CLOSE_PDU);
  p->packet_id++;
  SNMP_SESSION(h, p);

  snmp_put_fbyte(c.buffer, reason);
  ADVANCE(c.buffer, c.size, 4);

  uint s = update_packet_size(p, buf, c.buffer);

  snmp_log("preparing to sk_send() (close)");
  int ret = sk_send(sk, s);
  if (ret > 0)
    snmp_log("sk_send OK!");
  else if (ret == 0)
    snmp_log("sk_send sleep");
  else
    snmp_log("sk_send error");
}

#if 0
static void UNUSED
parse_testset_pdu(struct snmp_proto *p)
{
  sock *sk = p->sock;
  sk_send(sk, 0);
}

static void UNUSED
parse_commitset_pdu(struct snmp_proto *p)
{
  sock *sk = p->sock;
  sk_send(sk, 0);
}

static void UNUSED
parse_undoset_pdu(struct snmp_proto *p)
{
  sock *sk = p->sock;
  sk_send(sk, 0);
}

static void UNUSED
parse_cleanupset_pdu(struct snmp_proto *p)
{
  sock *sk = p->sock;
  sk_send(sk, 0);
}

static void UNUSED
addagentcaps_pdu(struct snmp_proto *p, struct oid *cap, char *descr,
		 uint descr_len, struct agentx_context *c)
{
  ASSUME(descr != NULL && descr_len > 0);
  sock *sk = p->sock;
  //byte *buf = sk->tbuf;
  //uint size = sk->tbsize;
  // TODO rename to pkt and add pkt_start
  byte *buf = sk->tpos;
  uint size = sk->tbuf + sk->tbsize - sk->tpos;

  if (size < AGENTX_HEADER_SIZE + snmp_context_size(c) + snmp_oid_size(cap) + snmp_str_size_from_len(descr_len))
  {
    /* TODO need more mem */
    return;
  }

  struct agentx_header *h;
  SNMP_CREATE(buf, struct agentx_header, h);
  SNMP_BLANK_HEADER(h, AGENTX_ADD_AGENT_CAPS_PDU);
  SNMP_SESSION(h, p);
  ADVANCE(buf, size, AGENTX_HEADER_SIZE);

  uint in_pkt;
  if (c && c->length)
  {
    SNMP_HAS_CONTEXT(h);
    in_pkt = snmp_put_nstr(buf, c->context, c->length) - buf;
    ADVANCE(buf, size, in_pkt);
  }

  memcpy(buf, cap, snmp_oid_size(cap));
  ADVANCE(buf, size, snmp_oid_size(cap));

  in_pkt = snmp_put_nstr(buf, descr, descr_len) - buf;
  ADVANCE(buf, size, in_pkt);

  // make a note in the snmp_proto structure

  //int ret = sk_send(sk, buf - sk->tbuf);
  int ret = sk_send(sk, buf - sk->tpos);
  if (ret == 0)
    snmp_log("sk_send sleep");
  else if (ret < 0)
    snmp_log("sk_send err");
  else
    log(L_INFO, "sk_send ok !!");
}

static void UNUSED
removeagentcaps_pdu(struct snmp_proto *p, struct oid *cap, struct agentx_context *c)
{
  sock *sk = p->sock;

  //byte *buf = sk->tbuf;
  //uint size = sk->tbsize;
  // TODO rename to pkt and add pkt_start
  byte *buf = sk->tpos;
  uint size = sk->tbuf + sk->tbsize - sk->tpos;

  if (size < AGENTX_HEADER_SIZE + snmp_context_size(c) + snmp_oid_size(cap))
  {
    /* TODO need more mem */
    return;
  }

  struct agentx_header *h;
  SNMP_CREATE(buf, struct agentx_header, h);
  SNMP_SESSION(h, p);
  ADVANCE(buf, size, AGENTX_HEADER_SIZE);

  uint in_pkt;
  if (c && c->length)
  {
    SNMP_HAS_CONTEXT(h);
    in_pkt = snmp_put_nstr(buf, c->context, c->length) - buf;
    ADVANCE(buf, size, in_pkt);
  }

  memcpy(buf, cap, snmp_oid_size(cap));
  ADVANCE(buf, size, snmp_oid_size(cap));

  // update state in snmp_proto structure

  //int ret = sk_send(sk, buf - sk->tbuf);
  int ret = sk_send(sk, buf - sk->tpos);
  if (ret == 0)
    snmp_log("sk_send sleep");
  else if (ret < 0)
    snmp_log("sk_send err");
  else
    log(L_INFO, "sk_send ok !!");
}
#endif

static inline void
refresh_ids(struct snmp_proto *p, struct agentx_header *h)
{
  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;
  p->transaction_id = LOAD_U32(h->transaction_id, byte_ord);
  p->packet_id = LOAD_U32(h->packet_id, byte_ord);
}

/**
 * parse_pkt - parse recieved response packet
 * @p:
 * @pkt: packet buffer
 * @size: number of packet bytes in buffer
 * retval number of byte parsed
 *
 * function parse_ptk() parses response-pdu and calls do_response().
 * returns number of bytes parsed by function excluding size of header.
 */
static uint
parse_pkt(struct snmp_proto *p, byte *pkt, uint size, uint *skip)
{
  snmp_log("parse_ptk() pkt start: %p", pkt);
  //snmp_dump_packet(p->sock->tbuf, 64);

  if (size < AGENTX_HEADER_SIZE)
    return 0;

  uint parsed_len = 0;
  struct agentx_header *h = (void *) pkt;

  snmp_log("parse_pkt got type %s", snmp_pkt_type[h->type]);
  snmp_dump_packet((void *)h, MIN(h->payload, 256));
  //snmp_dump_packet((void *)h, LOAD(h->payload, h->flags & AGENTX_NETWORK_BYTE_ORDER));
  switch (h->type)
  {
    case AGENTX_RESPONSE_PDU:
      snmp_log("parse_pkt returning parse_response");
      parsed_len = parse_response(p, pkt, size);
      break;

    /*
    case AGENTX_GET_PDU:
      refresh_ids(p, h);
      return parse_get_pdu(p, pkt, size);
    */

    case AGENTX_GET_PDU:
    case AGENTX_GET_NEXT_PDU:
    case AGENTX_GET_BULK_PDU:
      refresh_ids(p, h);
      //parsed_len = parse_gets_pdu(p, &c);
      //parsed_len = parse_gets_pdu(p, pkt, size, skip);
      parsed_len = parse_gets2_pdu(p, pkt, size, skip);
      break;

    /* during testing the connection should stay opened (we die if we screw up
     * and get CLOSE_PDU in response)

    case AGENTX_CLOSE_PDU:
      refresh_ids(p, h);
      parsed_len = parse_close_pdu(p, pkt, size);
      break;
    */

    /* should not happen */
    default:
      snmp_log("unknown packet type %u", h->type);
      return 0;
      //die("unknown packet type %u", h->type);
  }

  /* We will process the same header again later * /
  if (*skip || parsed_len < size)
  {
    / * We split our answer to multiple packet, we should differentiate them * /
    h->packet_id++;
  }
  */

  snmp_log("parse_pkt returning parsed length");
  //snmp_dump_packet(p->sock->tbuf, 64);
  return parsed_len;
}

static uint
parse_response(struct snmp_proto *p, byte *res, uint size)
{
  snmp_log("parse_response() g%u h%u", size, sizeof(struct agentx_header));

  //snmp_dump_packet(res, size);

  if (size < sizeof(struct agentx_response))
    return 0;

  struct agentx_response *r = (void *) res;
  struct agentx_header *h = &r->h;

  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

  uint pkt_size = LOAD_U32(h->payload, byte_ord);
  snmp_log("p_res pkt_size %u", pkt_size);
  if (size < pkt_size + AGENTX_HEADER_SIZE) {
    snmp_log("parse_response early return");
    return 0;
  }

  snmp_log("  endianity: %s, session %u, transaction: %u",
	   (h->flags & AGENTX_NETWORK_BYTE_ORDER) ? "big end": "little end",
	   h->session_id, h->transaction_id);
  snmp_log("  sid: %3u\ttid: %3u\tpid: %3u", p->session_id, p->transaction_id,
	   p->packet_id);

  snmp_log("  pkt size %u", h->payload);

  if (r->error == AGENTX_RES_NO_ERROR)
    do_response(p, res, size);
  else
    /* erronous packet should be dropped quietly */
    snmp_log("an error occured '%s'", snmp_errs[get_u16(&r->error) - SNMP_ERR_SHIFT]);

  return pkt_size + AGENTX_HEADER_SIZE;
}

static inline int
snmp_registered_all(struct snmp_proto *p)
{
  snmp_log("snmp_registered_all() %u", list_length(&p->register_queue));
  return p->register_to_ack == 0;
}

static void
snmp_register_mibs(struct snmp_proto *p)
{
  snmp_log("snmp_register_mibs()");

  snmp_bgp_register(p);

  snmp_log("registering all done");
}

static void
do_response(struct snmp_proto *p, byte *buf, uint size UNUSED)
{
  snmp_log("do_response()");
  struct agentx_response *r = (void *) buf;
  struct agentx_header *h = &r->h;
  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

  /* TO DO make it asynchronous for better speed */
  switch (p->state)
  {
    case SNMP_INIT:
      /* copy session info from recieved packet */
      p->session_id = LOAD_U32(h->session_id, byte_ord);
      refresh_ids(p, h);

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
}

u8
snmp_get_mib_class(const struct oid *oid)
{
  // TODO check code paths for oid->n_subid < 3
  if (oid->prefix != 2 && oid->ids[0] != SNMP_MIB_2)
    return SNMP_CLASS_INVALID;

  switch (oid->ids[1])
  {
    case SNMP_BGP4_MIB:
      return SNMP_CLASS_BGP;

    default:
      return SNMP_CLASS_END;
  }
}

#if 0
static byte *
snmp_get_next(struct snmp_proto *p, struct oid *o_start, struct oid *o_end,
	      u8 mib_class, struct snmp_pdu_context *c)
{
  snmp_log("type GetNext-PDU");
  enum snmp_search_res r;
  struct oid *o_copy = search_mib(p, o_start, o_end, NULL, c, &r);

  snmp_log("search result");
  snmp_oid_dump(o_copy);

  byte *read;
  if (o_copy)
  {
    read = snmp_mib_fill(p, o_copy, mib_class, c);
    mb_free(o_copy);
  }
  else
  {
    struct agentx_varbind *vb = snmp_create_varbind(c->buffer, o_start);
    c->buffer += snmp_varbind_header_size(vb);
    vb->type = snmp_search_res_to_type(r);
    //vb->type = AGENTX_NO_SUCH_OBJECT;
  }

  snmp_log("over HERE ");
  return read;
}
#endif

static void
snmp_get_next2(struct snmp_proto *p, struct oid *o_start, struct oid *o_end,
	       struct snmp_pdu_context *c)
{
  snmp_log("get_next2()");
  enum snmp_search_res r;
  snmp_log("next2() o_end %p", o_end);
  struct oid *o_copy = search_mib(p, o_start, o_end, NULL, c, &r);
  snmp_log("next2()2 o_end %p", o_end);

  struct agentx_varbind *vb = NULL;
  switch (r)
  {
    case SNMP_SEARCH_NO_OBJECT:
    case SNMP_SEARCH_NO_INSTANCE:
    case SNMP_SEARCH_END_OF_VIEW:;
      uint sz = snmp_varbind_hdr_size_from_oid(o_start);

      if (c->size < sz)
      {
	/* TODO manage insufficient buffer properly */
	c->error = AGENTX_RES_GEN_ERROR;
	return;
      }

      vb = snmp_create_varbind(c->buffer, o_start);
      vb->type = AGENTX_END_OF_MIB_VIEW;
      ADVANCE(c->buffer, c->size, snmp_varbind_header_size(vb));
      return;

    case SNMP_SEARCH_OK:
    default:	/* intentionaly left blank */
      break;
  }

  if (o_copy)
  {
    /* basicaly snmp_create_varbind(c->buffer, o_copy),
     * but without any copying */
    vb = (void *) c->buffer;
    snmp_mib_fill2(p, o_copy, c);

    /* override the error value for GetNext-PDU when object is not found */
    switch (vb->type)
    {
      case AGENTX_NO_SUCH_OBJECT:
      case AGENTX_NO_SUCH_INSTANCE:
      case AGENTX_END_OF_MIB_VIEW:
	vb->type = AGENTX_END_OF_MIB_VIEW;
	break;

      default:	/* intentionally left blank */
	break;
    }

    return;
  }

  if (c->size < snmp_varbind_hdr_size_from_oid(o_start))
  {
    // TODO FIXME this is a bit tricky as we need to renew all TX buffer pointers
    snmp_manage_tbuf(p, c);
  }

  vb = snmp_create_varbind(c->buffer, o_start);
  vb->type = AGENTX_END_OF_MIB_VIEW;
  ADVANCE(c->buffer, c->size, snmp_varbind_header_size(vb));
}

#if 0
static byte *
snmp_get_bulk(struct snmp_proto *p, struct oid *o_start, struct oid *o_end,
	      struct agentx_bulk_state *state, struct snmp_pdu_context *c)
{
  snmp_log("type GetBulk-PDU");
  // TODO add state cache (to prevent O(n^2) complexity)

  if (state->index <= state->getbulk.non_repeaters)
  {
    (void)0;
    //return snmp_get_next(p, o_start, o_end, mib_class, c);
    //return snmp_get_next(p, o_start, o_end, pkt, size, contid, mib_class, byte_ord);
    return NULL;
  }
  else
  {
    u8 mib_class;
    struct oid *o_curr = NULL;
    struct oid *o_predecessor = NULL;
    enum snmp_search_res r;

    uint i = 0;
    do
    {
      o_predecessor = o_curr;
      o_curr = search_mib(p, o_start, o_end, o_curr, c, &r);
      //o_curr = search_mib(p, o_start, o_end, o_curr, mib_class, contid);
      mib_class = snmp_get_mib_class(o_curr);
      i++;
    } while (o_curr != NULL && i < state->repetition);

    log("bulk search result - repeating");
    snmp_oid_dump(o_curr);

    if (!o_curr && i == 0)
    {
      //vb->name = o_start;
      //vb->type = AGENTX_RES_END_OF_MIB_VIEW;
      return NULL;
    }

    if (!o_curr)
    {
      ASSUME(o_predecessor != NULL);
      //vb->name = o_predecessor;
      //vb->type = AGENTX_RES_END_OF_MIB_VIEW;
      return NULL;
    }

    (void)mib_class;
    //return snmp_mib_fill(p, o_curr, mib_class, c);
    return NULL;
  }
}
#endif

static void
snmp_get_bulk2(struct snmp_proto *p, struct oid *o_start, struct oid *o_end,
	       struct agentx_bulk_state *state, struct snmp_pdu_context *c)
{
  if (state->index <= state->getbulk.non_repeaters)
    return snmp_get_next2(p, o_start, o_end, c);
  else
  {
    struct oid *o_curr = NULL;
    struct oid *o_predecessor = NULL;
    enum snmp_search_res r;

    uint i = 0;
    do
    {
      o_predecessor = o_curr;
      o_curr = search_mib(p, o_start, o_end, o_curr, c, &r);
      i++;
    } while (o_curr && i <= state->repetition);

    if (!o_curr && i == 1)
    {
      o_predecessor = o_start;
      goto abnormal;
    }

    if (!o_curr)
      goto abnormal;

    return snmp_mib_fill2(p, o_curr, c);

abnormal:;
    uint sz = snmp_varbind_hdr_size_from_oid(o_predecessor);

    if (c->size < sz)
    {
      snmp_log("snmp_get_bulk2() insufficient amount of memory in TX buffer, returning GET_ERROR");
      c->error = AGENTX_RES_GEN_ERROR;
      return;
    }

    struct agentx_varbind *vb = snmp_create_varbind(c->buffer, o_predecessor);
    vb->type = AGENTX_END_OF_MIB_VIEW;
    ADVANCE(c->buffer, c->size, snmp_varbind_size(vb, c->byte_ord));
  }
}

static uint UNUSED
parse_close_pdu(struct snmp_proto UNUSED *p, byte UNUSED *req, uint UNUSED size)
{
  /*
  snmp_log("parse_close_pdu()");

  // byte *pkt = req;
  // sock *sk = p->sock;

  if (size < sizeof(struct agentx_header))
  {
    snmp_log("p_close early return");
    return 0;
  }

  // struct agentx_header *h = (void *) req;
  ADVANCE(req, size, AGENTX_HEADER_SIZE);
  //snmp_log("after header %p", req);

  p->state = SNMP_ERR;

  */
  return 0;
}

static inline uint
update_packet_size(struct snmp_proto *p, byte *start, byte *end)
{
  /* work even for partial packets */
  struct agentx_header *h = (void *) p->sock->tpos;

  size_t s = snmp_pkt_len(start, end);
  STORE_U32(h->payload, s);
  return AGENTX_HEADER_SIZE + s;
}

static inline void
response_err_ind(struct agentx_response *res, uint err, uint ind)
{
  STORE_U32(res->error, err);
  if (err != AGENTX_RES_NO_ERROR && err != AGENTX_RES_PARSE_ERROR)
    STORE_U32(res->index, ind);
  else
    STORE_U32(res->index, 0);
}

static uint
parse_gets2_pdu(struct snmp_proto *p, byte * const pkt_start, uint size, uint *skip)
{
  snmp_log("parse_gets2_pdu()");

  struct oid *o_start = NULL, *o_end = NULL;
  byte *pkt = pkt_start;

  struct agentx_header *h = (void *) pkt;
  ADVANCE(pkt, size, AGENTX_HEADER_SIZE);
  uint pkt_size = LOAD_U32(h->payload, h->flags & AGENTX_NETWORK_BYTE_ORDER);

  sock *sk = p->sock;
  struct snmp_pdu_context c = {
    //.buffer = sk->tbuf,
    //.size = sk->tbsize,
    .buffer = sk->tpos,
    .size = sk->tbuf + sk->tbsize - sk->tpos,
    .byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER,
    .error = AGENTX_RES_NO_ERROR,
    .context = 0,
  };
  //snmp_dump_packet(sk->tbuf, 64);

  uint clen;	  /* count of characters in context (without last '\0') */
  char *context;  /* newly allocated string of character */
  /* alters pkt; assign context, clen */
  SNMP_LOAD_CONTEXT(p, h, pkt, context, clen);
  /*
   * We need more data; for valid response we need to know full
   * header picture, including the context octet string
   */
  if (size < clen)
  {
    snmp_log("size %u < %u clen, returning 0", size, clen);
    goto wait;
  }

  /*
   * It is a malformed packet if the context octet string should be longer than
   * whole packet.
   */
  if (pkt_size < clen)
  {
    /* for malformed packets consume full pkt_size [or size] */
    c.error = AGENTX_RES_PARSE_ERROR;
    goto send;
  }

  /* The RFC does not consider the context octet string as a part of a header */
  ADVANCE(pkt, pkt_size, clen);
  size -= clen;

  /* FIXME add support for c.context hashing
   c.context = ...
   */

  struct agentx_bulk_state bulk_state = { 0 };

  if (c.size < sizeof(struct agentx_response))
  {
    die("gets2: too small tx buffer");
    snmp_manage_tbuf(p, &c);
  }

  struct agentx_response *response_header = prepare_response(p, &c);

  uint ind = 1;
  while (c.error == AGENTX_RES_NO_ERROR && size > 0 && pkt_size > 0)
  {
    snmp_log("iter %u ``size'' %u", ind, c.buffer - ((byte *) response_header));

    if (size < snmp_oid_sizeof(0))
      goto partial;

    /* We load search range start OID */
    const struct oid *o_start_b = (void *) pkt;
    uint sz;
    if ((sz = snmp_oid_size(o_start_b)) > pkt_size)
    {
      /* for malformed packets consume full pkt_size [or size] */
      c.error = AGENTX_RES_PARSE_ERROR;  /* Packet error, inconsistent values */
      goto send;
    }

    /*
     * If we already have written same relevant data to the tx-buffer then
     * we send processed part, otherwise we don't have anything to send and
     * need to wait for more data to be recieved.
     */
    if (sz > size && ind > 1)
    {
      snmp_log("sz %u > %u size && ind %u > 1", sz, size, ind);
      goto partial;  /* send already processed part */
    }
    else if (sz > size)
    {
      snmp_log("sz %u > %u size; returning 0", sz, size);
      goto wait;
    }

    /* update buffer pointer and remaining size counters */
    ADVANCE(pkt, pkt_size, sz);
    size -= sz;

    /* We load search range end OID
     * The exactly same process of sanity checking is preformed while loading
     * the SearchRange's end OID
     */
    const struct oid *o_end_b = (void *) pkt;
    if ((sz = snmp_oid_size(o_end_b)) > pkt_size)
    {
      c.error = AGENTX_RES_PARSE_ERROR;  /* Packet error, inconsistent values */
      goto send;
    }

    if (sz > size && ind > 1)
    {
      snmp_log("sz2 %u > %u size && ind %u > 1", sz, size, ind);
      size += snmp_oid_size(o_start_b);
      goto partial;
    }
    else if (sz > size)
    {
      snmp_log("sz2 %u > %u size; returning 0", sz, size);
      goto wait;
    }

    ADVANCE(pkt, pkt_size, sz);
    size -= sz;

    // TODO check for oversized oids before any allocation (in prefixize())

    /* We create copy of OIDs outside of rx-buffer and also prefixize them */
    o_start = snmp_prefixize(p, o_start_b, c.byte_ord);
    o_end = snmp_prefixize(p, o_end_b, c.byte_ord);

    if (!snmp_is_oid_empty(o_end) && snmp_oid_compare(o_start, o_end) > 0)
    {
      snmp_log("snmp_gets2() o_start does not preceed o_end, returning GEN_ERROR");
      c.error = AGENTX_RES_GEN_ERROR;
      goto send;
    }

    /* TODO find mib_class, check if type is GET of GET_NEXT, act acordingly */
    switch (h->type)
    {
      case AGENTX_GET_PDU:
	snmp_mib_fill2(p, o_start, &c);
	break;

      case AGENTX_GET_NEXT_PDU:
	snmp_get_next2(p, o_start, o_end, &c);
	break;

      case AGENTX_GET_BULK_PDU:
	snmp_get_bulk2(p, o_start, o_end, &bulk_state, &c);
	break;

      default:
	die("incorrect usage");
    }

    mb_free(o_start);
    o_start = NULL;
    mb_free(o_end);
    o_end = NULL;

    ind++;
  } /* while (c.error == AGENTX_RES_NO_ERROR && size > 0) */

send:
  snmp_log("gets2: sending response ...");
  //response_err_ind(response_header, c.error, ind);
  // update_packet_size(&response_header->h, sk->tbuf, c.buffer);
  //update_packet_size(p, &response_header->h, (byte *) response_header, c.buffer);
  //snmp_dump_packet((byte *) response_header, AGENTX_HEADER_SIZE + LOAD(response_header->h.payload, c.byte_ord));

  //snmp_dump_packet((byte *) response_header, AGENTX_HEADER_SIZE + 16 + 8);
  //snmp_dump_packet(32 + ((byte *) response_header), 32);
  //snmp_dump_packet((byte *) response_header, c.buffer - ((byte *) response_header));
  /*

  byte b,d;
  b = *((byte *) response_header);
  d = *(c.buffer - 1);
  snmp_log("diff %d start byte %u end byte %u", c.buffer - ((byte *)
	    response_header), b, d);
  */
  response_err_ind(response_header, c.error, ind);
  uint s = update_packet_size(p, (byte *) response_header, c.buffer);

  /* number of bytes put into the tx-buffer */
  //int ret = sk_send(sk, c.buffer - sk->tbuf);
  snmp_log("sending response to Get-PDU, GetNext-PDU or GetBulk-PDU request ...");
  int ret = sk_send(sk, s);
  if (ret == 0)
    snmp_log("sk_send sleep (gets2");
  else if (ret < 0)
    snmp_log("sk_send err %d (gets2)", ret);
  else
    snmp_log("sk_send was successful (gets2) !");

  p->partial_response = NULL;

  mb_free(context);
  mb_free(o_start);
  mb_free(o_end);

  /* number of bytes parsed form rx-buffer */
  return pkt - pkt_start;

partial:
  snmp_log("partial packet");
  /* The context octet is not added into response pdu */

  /* need to tweak RX buffer packet size */
  snmp_log("old rx-buffer size %u", h->payload);
  (c.byte_ord) ? put_u32(&h->payload, pkt_size) : (h->payload = pkt_size);
  snmp_log("new rx-buffer size %u", h->payload);

  *skip = AGENTX_HEADER_SIZE;
  p->partial_response = response_header;
  return pkt - pkt_start;

wait:
  mb_free(context);
  mb_free(o_start);
  mb_free(o_end);
  return 0;
}

#if 0
// TODO FIXME retval
/* req is request */
/**
 * parse_gets_pdu - handle Get-PDU, GetNext-PDU and GetBulk-PDU
 * @p:
 * @req: request packet buffer
 * @size: request length
 *
 * Returns lenght of created response packet.
 */
static uint UNUSED
parse_gets_pdu(struct snmp_proto *p, byte *pkt_start, uint size, uint UNUSED *skip)
{
  snmp_log("parse_gets_pdu");

  sock *sk = p->sock;
  //byte  *res = sk->tbuf; /* res_pkt */
  // uint rsize = sk->tbsize;
  byte *res = sk->tpos;

  /* req (request) points at the beginning of packet list */
  // TODO is the pkt_start really needed ?!
  struct agentx_header *h = (void *) pkt_start;
  ADVANCE(pkt_start, size, AGENTX_HEADER_SIZE);
  snmp_log("advancing %p cause header", pkt_start);

  byte *pkt = pkt_start;

  uint clen;
  char *context;
  SNMP_LOAD_CONTEXT(p, h, pkt, context, clen);

  struct snmp_pdu_context c = {
    //.buffer = sk->tbuf,
    //.size = sk->tbsize,
    .buffer = sk->tpos,
    .size = sk->tbuf + sk->tbsize - sk->tpos,
    .byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER,
    .context = 0, // FIXME add context support
    .error = AGENTX_RES_NO_ERROR,
  };

  uint pkt_size = LOAD(h->payload, c.byte_ord);

  // NO! CHECKs: pkt_size + HEADER_SIZE == size


  if (c.size < sizeof(struct agentx_response))
  {
    // FIXME alloc more mem
    die("buffer too small");
  }

  struct agentx_response *response_header = prepare_response(p, &c);

  /* used only for state AGENTX_GET_BULK_PDU */
  struct agentx_bulk_state bulk_state;
  if (h->type == AGENTX_GET_BULK_PDU)
  {
    snmp_log("gets creating get bulk context BEWARE");
    struct agentx_getbulk *bulk = (void *) pkt;
    ADVANCE(pkt, pkt_size, sizeof(struct agentx_getbulk));
    bulk_state = (struct agentx_bulk_state) {
      .getbulk.non_repeaters = LOAD(bulk->non_repeaters, c.byte_ord),
      .getbulk.max_repetitions = LOAD(bulk->max_repetitions, c.byte_ord),
      .index = 1,
      .repetition = 1,
    };
  }
/*
  if (size < sizeof(struct agentx_getbulk))
    return 0;

  if (pkt_size < sizeof(struct agentx_getbulk))
  {
    c.error = AGENTX_RES_PARSE_ERROR;
    goto send;
  }

  struct agentx_bulk_state bulk_state;
  if (h->type == AGENTX_GET_BULK_PDU)
  {
    struct agentx_getbulk *bulk = pkt;
    ADVANCE(pkt, pkt_size, sizeof(struct agentx_getbulk));
    size -= sizeof(struct agentx_getbulk);

    bulk_state = (struct agentx_bulk_state) {
      .getbulk.non_repeaters = LOAD16(bulk->non_repeaters, c.byte_ord);
      .getbulk.max_repetitions = LOAD16(bulk->max_repetitions, c.byte_ord);
      .index = 1,
      .repetition = 1,
    };
  }
*/

  byte *tmp;

  uint ind = 1;
  while (c.error == AGENTX_RES_NO_ERROR && size > 0)
  {
    /* pkt_size is bigger that OID header */
    if (size < snmp_oid_sizeof(0))
    {
    }

    /* oids from message buffer */
    struct oid *o_start_b, *o_end_b;
    o_start_b = (struct oid *) pkt;
    pkt += snmp_oid_size(o_start_b);
    o_end_b = (struct oid *) pkt;
    pkt += snmp_oid_size(o_end_b);
    snmp_log("HERE pkt after oids %p (end %p)", pkt, pkt + size);

    /* advertised size of oid is greater then size of message */
    if (snmp_oid_size(o_start_b) > size || snmp_oid_size(o_end_b) > size)
    {
      snmp_log("too big o_start or o_end");
      snmp_log("o_start_b packet: %u  o_end_b packet: %u   packet size: %u",
      snmp_oid_size(o_start_b), snmp_oid_size(o_end_b), size);
      //err = -1;  /* parse error too big n_subid (greater than message) */
      continue;
    }

    snmp_oid_dump(o_start_b);
    snmp_oid_dump(o_end_b);

    /* object identifier (oid) normalization */
    struct oid *o_start = snmp_prefixize(p, o_start_b, c.byte_ord);
    struct oid *o_end = snmp_prefixize(p, o_end_b, c.byte_ord);

    snmp_oid_dump(o_start);
    snmp_oid_dump(o_end);

    snmp_log("gets buffer start size %u, buffer end size %u, program start size %u, "
	     "program end size %u", snmp_oid_size(o_start_b), snmp_oid_size(o_end_b),
	      snmp_oid_size(o_start), snmp_oid_size(o_end));

    // TODO handle NULL o_start and o_end

    u8 mib_class = snmp_get_mib_class(o_start);

    snmp_log("get mib_class () %d -> next pdu parsing ...", mib_class);

    switch (h->type)
    {
      case AGENTX_GET_PDU:
	snmp_log("type Get-PDU");

      /*
	struct snmp_error error = (struct snmp_error) {
	  .oid = o_start,
	  .type = AGENTX_NO_SUCH_OBJECT,
	};
      */

	//snmp_dump_packet(pkt, size);
	// TODO o_start NULL check
	//res_pkt = snmp_mib_fill(p, o_start, mib_class, res_pkt, rsize, &error, 0, byte_ord);
	tmp = snmp_mib_fill(p, o_start, mib_class, &c);
	//res_pkt = find_n_fill(p, o_start, res_pkt, rsize, 0, byte_ord);
	if (tmp)
	  c.buffer = tmp;
	else
	  {} // TODO

	break;

      case AGENTX_GET_NEXT_PDU:
	tmp = snmp_get_next(p, o_start, o_end, mib_class, &c);
	//res_pkt = snmp_get_next(p, o_start, o_end, res_pkt, rsize, 0, mib_class, byte_ord);
	if (tmp)
	  c.buffer = tmp;
	else
	  {} // TODO

	break;

      case AGENTX_GET_BULK_PDU:
	tmp = snmp_get_bulk(p, o_start, o_end, &bulk_state, &c);
	if (tmp)
	  c.buffer = tmp;
	else
	  {} // TODO

	break;
    }

    mb_free(o_start);
    mb_free(o_end);

    ind++;
  }

  snmp_log(" pasting size");
  response_err_ind(response_header, c.error, ind);
  update_packet_size(p, res, c.buffer);

  snmp_log("ttx %p  c.buffer - res %lu", p->sock->ttx, c.buffer - res);
  snmp_log("c.buffer %p res %p", c.buffer, res);
  snmp_log("dumping response packet (gets)");

  //snmp_dump_packet(res, c.buffer - res);

  // TODO need to send prepared packet here
  int ret = sk_send(sk, c.buffer - res);

  if (ret == 0)
    snmp_log("sk_send sleep (gets)");
  else if (ret < 0)
    snmp_log("sk_send err %d (gets)", ret);
  else
    snmp_log("sk_send ok ! (gets)");

  return pkt - pkt_start - AGENTX_HEADER_SIZE;
}
#endif

void
snmp_start_subagent(struct snmp_proto *p)
{
  snmp_log("snmp_start_subagent() starting subagent");
  snmp_log("DEBUG p->local_as %u", p->local_as);

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

#if 0
int
snmp_rx(sock *sk, uint size)
{
  snmp_log("snmp_rx()");
  struct snmp_proto *p = sk->data;
  byte *pkt = sk->rpos;

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
#endif

int
snmp_rx(sock *sk, uint size)
{
  snmp_log("snmp_rx() size %u", size);
  //snmp_dump_packet(sk->tbuf, 64);
  struct snmp_proto *p = sk->data;
  byte *pkt_start = sk->rbuf;
  byte *end = pkt_start + size;
  snmp_log("snmp_rx rbuf 0x%p  rpos 0x%p", sk->rbuf, sk->rpos);

  /*
   * In some cases we want to save the header for future parsing, skip is number
   * of bytes that should not be overriden by memmove()
   */
  uint skip = 0;

  //snmp_dump_packet(pkt_start, size);

  snmp_log("snmp_rx before loop");
  while (end >= pkt_start + AGENTX_HEADER_SIZE)
  {
    uint parsed_len = parse_pkt(p, pkt_start, size, &skip);

    snmp_log("snmp_rx loop end %p parsed >>>  %u  <<< curr %p", end, parsed_len,
	      pkt_start + parsed_len);

    if (parsed_len == 0)
      break;

    pkt_start += parsed_len;
    size -= parsed_len;
  }
  snmp_log("snmp_rx loop finished");

  /* Incomplete packets */
  if (skip != 0 || pkt_start != end)
  {
    snmp_log("snmp_rx memmove");
    snmp_dump_packet(sk->rbuf, SNMP_RX_BUFFER_SIZE);
    memmove(sk->rbuf + skip, pkt_start, size);
    snmp_log("after change; sk->rbuf 0x%p  sk->rpos 0x%p", sk->rbuf, sk->rpos);
    snmp_dump_packet(sk->rbuf, size + skip);
    snmp_log("tweaking rpos 0x%p  (size %u skip %u)", sk->rpos, size, skip);
    sk->rpos = sk->rbuf + size + skip;
    snmp_log("snmp_rx returing 0");
    return 0;
  }

  snmp_log("snmp_rx returning 1");
  return 1;
}

/* ping pdu */
void
snmp_ping(struct snmp_proto *p)
{
  /* this does not support non-default context */
  sock *sk = p->sock;
  struct snmp_pdu_context c = {
    .buffer = sk->tpos,
    .size = sk->tbuf + sk->tbsize - sk->tpos,
  };

  if (c.size < AGENTX_HEADER_SIZE)
    snmp_manage_tbuf(p, &c);

  snmp_log("ping_pdu()");
  struct agentx_header *h = (struct agentx_header *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);
  SNMP_BLANK_HEADER(h, AGENTX_PING_PDU);
  p->packet_id++;
  SNMP_SESSION(h, p);

  /* sending only header => pkt - buf */
  snmp_log("sending ping packet ...");
  uint s = update_packet_size(p, sk->tpos, c.buffer);
  int ret = sk_send(sk, s);
  if (ret > 0)
    snmp_log("sk_send OK!");
  else if (ret == 0)
    snmp_log("sk_send sleep");
  else
    snmp_log("sk_send error");
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

/**
 * snmp_search_check_end_oid - check if oid is before SearchRange end
 *
 * @found: best oid found in MIB tree
 * @bound: upper bound specified in SearchRange
 *
 * check if found oid meet the SearchRange upper bound condition in
 * lexicographical order, returns boolean value
 */
int snmp_search_check_end_oid(const struct oid *found, const struct oid *bound)
{
  snmp_log("upper_bound_check(*f, *b) %p %p is_empty() %d", found, bound,
	  snmp_is_oid_empty(bound));

  if (snmp_is_oid_empty(bound))
    return 1;

  return (snmp_oid_compare(found, bound) < 0);
}

/* tree is tree with "internet" prefix .1.3.6.1
   working only with o_start, o_end allocated in heap (not from buffer)*/
static struct oid *
search_mib(struct snmp_proto *p, const struct oid *o_start, const struct oid *o_end,
	   struct oid *o_curr, struct snmp_pdu_context *c,
	   enum snmp_search_res *result)
{
  snmp_log("search_mib()");
  ASSUME(o_start != NULL);

  if (o_curr && (o_curr->n_subid < 2 || o_curr->ids[0] != 1))
    return NULL;
  if (!o_curr && (o_start->n_subid < 2 || o_start->ids[0] != 1))
    return NULL;

  if (!o_curr)
  {
    o_curr = snmp_oid_duplicate(p->p.pool, o_start);
    // XXX is it right time to free o_start right now (here) ?
	// not for use in snmp_get_next2() the o_start comes and ends in _gets2_()
  }

  const struct oid *blank = NULL;
  if (!snmp_is_oid_empty(o_end) &&
      snmp_get_mib_class(o_curr) < snmp_get_mib_class(o_end))
  {
    o_end = blank = snmp_oid_blank(p);
    snmp_log("search_mib() o_end points to blank oid now %p", o_end);
  }

  enum snmp_search_res r;
  switch (o_curr->ids[1])
  {
    case SNMP_BGP4_MIB:
      r = snmp_bgp_search2(p, &o_curr, o_end, c->context);

      if (r == SNMP_SEARCH_OK)
      {
	*result = r;
	break;
	return o_curr;
      }

      // TODO add early break for o_end less then thinkable maximum in each tree

      /* fall through */

    default:
      if (o_curr) mb_free(o_curr);
      o_curr = snmp_oid_duplicate(p->p.pool, o_start);
      *result = SNMP_SEARCH_END_OF_VIEW;
      break;
  }

  //mb_free(blank);
  return o_curr;
}

/*
static byte *
find_ospf_record(struct snmp_proto *p, struct oid *o, byte *buf, uint size)
{
  // TO DO X XX
  return NULL;
}
*/

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
snmp_prefixize(struct snmp_proto *proto, const struct oid *oid, int byte_ord)
{
  ASSERT(oid != NULL);
  snmp_log("snmp_prefixize()");
  const u32 prefix[] = {1, 3, 6, 1};

  if (snmp_is_oid_empty(oid))
  {
    /* allocate new zeroed oid */
    snmp_log("blank");
    return snmp_oid_blank(proto);
  }

  /* already in prefixed form */
  else if (oid->prefix != 0) {
    struct oid *new = snmp_oid_duplicate(proto->p.pool, oid);
    snmp_log("already prefixed");
    return new;
  }

  if (oid->n_subid < 5)
  {  snmp_log("too small"); return NULL; }

  for (int i = 0; i < 4; i++)
    if (LOAD_U32(oid->ids[i], byte_ord) != prefix[i])
      { snmp_log("different prefix"); return NULL; }

  /* validity check here */
  if (oid->ids[4] >= 256)
    { snmp_log("outside byte first id"); return NULL; }

  struct oid *new = mb_alloc(proto->p.pool,
          sizeof(struct oid) + MAX((oid->n_subid - 5) * sizeof(u32), 0));
/*
  snmp_log(" new %p new->ids %p &new->ids %p   oid %p oid->ids %p oid->ids[5] %p"
"&oid->ids[5] %p &(oid->ids[5]) %p", new, new->ids, &new->ids, oid, oid->ids,
oid->ids[5], &oid->ids[5], &(oid->ids[5]));
*/

  memcpy(new, oid, sizeof(struct oid));
  new->n_subid = oid->n_subid - 5;

  /* validity check before allocation => ids[4] < 256
   * and can be copied to one byte new->prefix */
  new->prefix = oid->ids[4];

  memcpy(&new->ids, &oid->ids[5], new->n_subid * sizeof(u32));
  return new;
}

static void
snmp_mib_fill2(struct snmp_proto *p, struct oid *oid,
	       struct snmp_pdu_context *c)
{
  ASSUME(oid != NULL);

  if (c->size < snmp_varbind_hdr_size_from_oid(oid))
  {
    // FIXME need more mem
    snmp_log("snmp_mib_fill2() need more memory in TX buffer, returning with GEN_ERROR");
    c->error = AGENTX_RES_GEN_ERROR;
    return;
  }

  struct agentx_varbind *vb = snmp_create_varbind(c->buffer, oid);

  if (oid->n_subid < 2 || (oid->prefix != 2 && oid->ids[0] != 1))
  {
    vb->type = AGENTX_NO_SUCH_OBJECT;
    ADVANCE(c->buffer, c->size, snmp_varbind_header_size(vb));
    return;
  }

  u8 mib_class = snmp_get_mib_class(oid);
  switch (mib_class)
  {
    case SNMP_CLASS_BGP:
      snmp_bgp_fill(p, vb, c);
      break;

    case SNMP_CLASS_INVALID:
    case SNMP_CLASS_END:
    default:
      vb->type = AGENTX_NO_SUCH_OBJECT;
      ADVANCE(c->buffer, c->size, snmp_varbind_header_size(vb));
  }
}

#if 0
/**
 * snmp_mib_fill -
 */
static byte *
snmp_mib_fill(struct snmp_proto UNUSED *p, struct oid *oid, u8 mib_class,
	      struct snmp_pdu_context *c)
{
  ASSERT(oid != NULL);
  snmp_log("snmp_mib_fill()");

  struct agentx_varbind *vb = snmp_create_varbind(c->buffer, oid);
                       /* SNMPv2      mgmt		  mib-2 */
  if (oid->n_subid < 2 || (oid->prefix != 2 && oid->ids[0] != 1))
  {
    vb->type = AGENTX_NO_SUCH_OBJECT;
    return c->buffer + snmp_varbind_header_size(vb);
  }

  //byte *last = c->buffer;
  switch (mib_class)
  {
    case SNMP_CLASS_BGP:
      //return snmp_bgp_fill(p, vb, c);
      return NULL;

    default:
      return NULL;
  }
  return NULL;
}
#endif

/**
 *
 * Important note: After managing insufficient buffer size all in buffer pointers
 *  are invalidated!
 */
void
snmp_manage_tbuf(struct snmp_proto *p, struct snmp_pdu_context *c)
{
  snmp_log("snmp_manage_tbuf()");
  sock *sk = p->sock;

  sk_set_tbsize(sk , sk->tbsize + 2048);
  c->size += 2048;
}

void
snmp_tx(sock UNUSED *sk)
{
  snmp_log("snmp_tx() hook");
  //struct snmp_proto *p = sk->data;

  return;
}


static struct agentx_response *
prepare_response(struct snmp_proto *p, struct snmp_pdu_context *c)
{
  snmp_log("prepare_response()");

  if (p->partial_response)
    return p->partial_response;

  struct agentx_response *r = (void *) c->buffer;
  struct agentx_header *h = &r->h;

  SNMP_BLANK_HEADER(h, AGENTX_RESPONSE_PDU);
  SNMP_SESSION(h, p);

  /* protocol doesn't care about subagent upTime */
  STORE_U32(r->uptime, 0);
  STORE_U16(r->error, AGENTX_RES_NO_ERROR);
  STORE_U16(r->index, 0);

  ADVANCE(c->buffer, c->size, sizeof(struct agentx_response));
  return r;
}


#undef SNMP_ERR_SHIFT
