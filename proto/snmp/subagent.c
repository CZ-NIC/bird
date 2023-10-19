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

static void snmp_mib_fill2(struct snmp_proto *p, struct oid *oid, struct snmp_pdu *c);
static uint parse_response(struct snmp_proto *p, byte *buf, uint size);
static void do_response(struct snmp_proto *p, byte *buf, uint size);
static uint parse_gets2_pdu(struct snmp_proto *p, byte *buf, uint size, uint *skip);
static struct agentx_response *prepare_response(struct snmp_proto *p, struct snmp_pdu *c);
static void response_err_ind(struct agentx_response *res, uint err, uint ind);
static uint update_packet_size(struct snmp_proto *p, const byte *start, byte *end);
static struct oid *search_mib(struct snmp_proto *p, const struct oid *o_start, const struct oid *o_end, struct oid *o_curr, struct snmp_pdu *c, enum snmp_search_res *result);

u32 snmp_internet[] = { SNMP_ISO, SNMP_ORG, SNMP_DOD, SNMP_INTERNET };

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
  const struct snmp_config *cf = SKIP_BACK(struct snmp_config, cf, p->p.cf);
  sock *sk = p->sock;

  struct snmp_pdu c = SNMP_PDU_CONTEXT(sk);
  byte *buf = c.buffer;

#define TIMEOUT_SIZE 4 /* 1B timeout, 3B zero padding */
  if (c.size < AGENTX_HEADER_SIZE + TIMEOUT_SIZE + snmp_oid_size(oid) +
      + snmp_str_size(cf->description))
  {
    snmp_manage_tbuf(p, &c);
    buf = c.buffer;
  }

  struct agentx_header *h = (struct agentx_header *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);
  SNMP_BLANK_HEADER(h, AGENTX_OPEN_PDU);
  c.byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

  STORE_U32(h->session_id, 1);
  STORE_U32(h->transaction_id, 1);
  STORE_U32(h->packet_id, 1);

  c.size -= (4 + snmp_oid_size(oid) + snmp_str_size(cf->description));
  c.buffer = snmp_put_fbyte(c.buffer, p->timeout);
  c.buffer = snmp_put_oid(c.buffer, oid);
  c.buffer = snmp_put_str(c.buffer, cf->description);

  uint s = update_packet_size(p, buf, c.buffer);
  int ret = sk_send(sk, s);
  if (ret > 0)
    snmp_log("sk_send OK!");
  else if (ret == 0)
    snmp_log("sk_send sleep");
  else
    snmp_log("sk_send error");
#undef TIMEOUT_SIZE
}

void
snmp_notify_pdu(struct snmp_proto *p, struct oid *oid, void *data, uint size, int include_uptime)
{
  sock *sk = p->sock;

  struct snmp_pdu c = SNMP_PDU_CONTEXT(sk);

#define UPTIME_SIZE \
  (6 * sizeof(u32)) /* sizeof( { u32 vb_type, u32 oid_hdr, u32 ids[4] } )*/
#define TRAP0_HEADER_SIZE \
  (7 * sizeof(u32)) /* sizeof( { u32 vb_type, u32 oid_hdr, u32 ids[6] } ) */

  uint sz = AGENTX_HEADER_SIZE + TRAP0_HEADER_SIZE + snmp_oid_size(oid) \
    + size;

  if (include_uptime)
    sz += UPTIME_SIZE;

  if (c.size < sz)
    snmp_manage_tbuf(p, &c);

  struct agentx_header *h = (struct agentx_header *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);
  SNMP_BLANK_HEADER(h, AGENTX_NOTIFY_PDU);
  p->packet_id++;
  SNMP_SESSION(h, p);
  c.byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

  if (include_uptime)
  {
    /* sysUpTime.0 oid */
    struct oid uptime = {
      .n_subid = 4,
      .prefix = SNMP_MGMT,
      .include = 0,
      .pad = 0,
    };
    u32 uptime_ids[] = { 1, 1, 3, 0 };

    struct agentx_varbind *vb = snmp_create_varbind(c.buffer, &uptime);
    for (uint i = 0; i < uptime.n_subid; i++)
      STORE_U32(vb->name.ids[i], uptime_ids[i]);
    snmp_varbind_ticks(vb, c.size, (current_time() TO_S) / 100);
    ADVANCE(c.buffer, c.size, snmp_varbind_size(vb, c.byte_ord));
  }

  /* snmpTrapOID.0 oid */
  struct oid trap0 = {
    .n_subid = 6,
    .prefix = 6,
    .include = 0,
    .pad = 0,
  };
  u32 trap0_ids[] = { 3, 1, 1, 4, 1, 0 };

  struct agentx_varbind *trap_vb = snmp_create_varbind(c.buffer, &trap0);
  for (uint i = 0; i < trap0.n_subid; i++)
    STORE_U32(trap_vb->name.ids[i], trap0_ids[i]);
  trap_vb->type = AGENTX_OBJECT_ID;
  snmp_put_oid(SNMP_VB_DATA(trap_vb), oid);
  ADVANCE(c.buffer, c.size, snmp_varbind_size(trap_vb, c.byte_ord));

  memcpy(c.buffer, data, size);
  ADVANCE(c.buffer, c.size, size);

  uint s = update_packet_size(p, sk->tbuf, c.buffer);
  int ret = sk_send(sk, s);
  if (ret > 0)
    snmp_log("sk_send OK!");
  else if (ret == 0)
    snmp_log("sk_send sleep");
  else
    snmp_log("sk_send error");

#undef TRAP0_HEADER_SIZE
#undef UPTIME_SIZE
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
    //snmp_log("de_allocate_pdu()");

    struct agentx_header *h;
    SNMP_CREATE(pkt, struct agentx_header, h);
    SNMP_BLANK_HEADER(h, type);
    SNMP_SESSION(h,p);

    struct agentx_varbind *vb = (struct agentx_varbind *) pkt;
    STORE_16(vb->type, AGENTX_OBJECT_ID);
    STORE(vb->oid,
  }

  else
    {}//snmp_log("de_allocate_pdu(): insufficient size");
}
*/

/* Register-PDU / Unregister-PDU */
static void
un_register_pdu(struct snmp_proto *p, struct oid *oid, uint len, uint index, u8 type, u8 is_instance, uint contid)
{
  const struct snmp_config *cf = SKIP_BACK(struct snmp_config, cf, p->p.cf);
  sock *sk = p->sock;
  struct snmp_pdu c = SNMP_PDU_CONTEXT(sk);
  byte *buf = c.buffer;

  /* conditional +4 for upper-bound (optinal field) */
  uint sz = AGENTX_HEADER_SIZE + snmp_oid_size(oid) + ((len > 1) ? 4 : 0);

  const struct snmp_context *sc = NULL;
  if (contid)
  {
    sc = snmp_cont_get(p, contid);
    sz += snmp_str_size(sc->context);
  }

  if (c.size < sz)
  {
    //snmp_log("un_register_pdu() insufficient size");
    snmp_manage_tbuf(p, &c);
    buf = c.buffer;
  }

  //snmp_log("un_register_pdu()");
  struct agentx_header *h = (struct agentx_header *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);

  SNMP_HEADER(h, type, is_instance ? AGENTX_FLAG_INSTANCE_REGISTRATION : 0);
  p->packet_id++;
  SNMP_SESSION(h, p);
  c.byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

/*
  log("un_register_pdu contid %u s_cont (at 0x%p) %s", contid, sc, (sc &&
      sc->context) ? sc->context : "<not_avail>");
*/
  SNMP_NON_DEFAULT_CONTEXT(h, c, contid);

  struct agentx_un_register_hdr *ur = (struct agentx_un_register_hdr *) c.buffer;

  /* do not override timeout */
  STORE_U8(ur->timeout, p->timeout);
  /* default priority */
  STORE_U8(ur->priority, cf->priority);
  STORE_U8(ur->range_subid, (len > 1) ? index : 0);
  STORE_U8(ur->pad, 0);
  ADVANCE(c.buffer, c.size, sizeof(struct agentx_un_register_hdr));

  snmp_put_oid(c.buffer, oid);
  ADVANCE(c.buffer, c.size, snmp_oid_size(oid));

  /* place upper-bound if needed */
  if (len > 1)
  {
    STORE_PTR(c.buffer, len);
    ADVANCE(c.buffer, c.size, 4);
  }

  uint s = update_packet_size(p, buf, c.buffer);

  //snmp_log("sending (un)register %s", snmp_pkt_type[type]);
  int ret = sk_send(sk, s);
  if (ret > 0)
    snmp_log("sk_send OK!");
  else if (ret == 0)
    snmp_log("sk_send sleep");
  else
    snmp_log("sk_send error");
}

/* Register-PDU */
void
snmp_register(struct snmp_proto *p, struct oid *oid, uint len, uint index, u8 is_instance, uint contid)
{
  un_register_pdu(p, oid, len, index, AGENTX_REGISTER_PDU, is_instance, contid);
}

/* Unregister-PDU */
void UNUSED
snmp_unregister(struct snmp_proto *p, struct oid *oid, uint len, uint index, uint contid)
{
  un_register_pdu(p, oid, len, index, AGENTX_UNREGISTER_PDU, 0, contid);
}

static void
close_pdu(struct snmp_proto *p, u8 reason)
{
  sock *sk = p->sock;
  struct snmp_pdu c = SNMP_PDU_CONTEXT(sk);
  byte *buf = c.buffer;

  /*snmp_log("close_pdu() size: %u %c %u", c.size, (c.size > AGENTX_HEADER_SIZE + 4)
? '>':'<', AGENTX_HEADER_SIZE);
*/

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
  c.byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

  snmp_put_fbyte(c.buffer, reason);
  ADVANCE(c.buffer, c.size, 4);

  uint s = update_packet_size(p, buf, c.buffer);

  //snmp_log("preparing to sk_send() (close)");
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
addagentcaps_pdu(struct snmp_proto *p, struct oid *cap, char *descr,
		 uint descr_len, struct agentx_context *c)
{
  ASSUME(descr != NULL && descr_len > 0);
  sock *sk = p->sock;
  //byte *buf = sk->tbuf;
  //uint size = sk->tbsize;
  // TO-DO rename to pkt and add pkt_start
  byte *buf = sk->tpos;
  uint size = sk->tbuf + sk->tbsize - sk->tpos;

  if (size < AGENTX_HEADER_SIZE + snmp_context_size(c) + snmp_oid_size(cap) + snmp_str_size_from_len(descr_len))
  {
    /* TO-DO need more mem */
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

  // memcpy(buf, cap, snmp_oid_size(cap));
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
  // TO-DO rename to pkt and add pkt_start
  byte *buf = sk->tpos;
  uint size = sk->tbuf + sk->tbsize - sk->tpos;

  if (size < AGENTX_HEADER_SIZE + snmp_context_size(c) + snmp_oid_size(cap))
  {
    /* TO-DO need more mem */
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
 * Returns number of bytes parsed from RX-buffer.
 */
static uint
parse_pkt(struct snmp_proto *p, byte *pkt, uint size, uint *skip)
{
  //snmp_log("parse_pkt() pkt start: %p", pkt);

  if (size < AGENTX_HEADER_SIZE)
    return 0;

  uint parsed_len = 0;
  struct agentx_header *h = (void *) pkt;

  //snmp_log("parse_pkt got type %s (%d)", snmp_pkt_type[h->type], h->type);
  //snmp_log("parse_pkt rx size %u", size);
  //snmp_dump_packet((void *)h, MIN(h->payload, 256));
  switch (h->type)
  {
    case AGENTX_RESPONSE_PDU:
      //snmp_log("parse_pkt returning parse_response");
      parsed_len = parse_response(p, pkt, size);
      break;

    case AGENTX_GET_PDU:
    case AGENTX_GET_NEXT_PDU:
    case AGENTX_GET_BULK_PDU:
      refresh_ids(p, h);
      parsed_len = parse_gets2_pdu(p, pkt, size, skip);
      break;

    /* during testing the connection should stay opened (we die if we screw up
     * and get CLOSE_PDU in response)

    case AGENTX_CLOSE_PDU:
      refresh_ids(p, h);
      parsed_len = parse_close_pdu(p, pkt, size);
      break;
    */

    default:
      /* drop the packet with unknown type silently */
      //snmp_log("unknown packet type %u", h->type);
      return 0;
  }

  //snmp_log("parse_pkt returning parsed length");
  return parsed_len;
}

static uint
parse_response(struct snmp_proto *p, byte *res, uint size)
{
  //snmp_log("parse_response() g%u h%u", size, sizeof(struct agentx_header));

  if (size < sizeof(struct agentx_response))
    return 0;

  struct agentx_response *r = (void *) res;
  struct agentx_header *h = &r->h;

  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

  uint pkt_size = LOAD_U32(h->payload, byte_ord);
  //snmp_log("p_res pkt_size %u", pkt_size);
  if (size < pkt_size + AGENTX_HEADER_SIZE)
  {
    //snmp_log("parse_response early return");
    return 0;
  }

  /*snmp_log("  endianity: %s, session %u, transaction: %u",
	   (h->flags & AGENTX_NETWORK_BYTE_ORDER) ? "big end": "little end",
	   h->session_id, h->transaction_id);
*/
  /*snmp_log("  sid: %3u\ttid: %3u\tpid: %3u", p->session_id, p->transaction_id,
	   p->packet_id);
*/
  //snmp_log("  pkt size %u", h->payload);

  //snmp_log("  pkt size %u", h->payload);

  if (r->error == AGENTX_RES_NO_ERROR)
    do_response(p, res, size);
  else
    /* erronous packet should be dropped quietly */
    {}//snmp_log("an error occured '%s'", snmp_errs[get_u16(&r->error) - SNMP_ERR_SHIFT]);

  return pkt_size + AGENTX_HEADER_SIZE;
}

static void
snmp_register_mibs(struct snmp_proto *p)
{
  //snmp_log("snmp_register_mibs()");

  snmp_bgp_register(p);
  /* snmp_ospf_regsiter(p); ... */

  //snmp_log("registering all done");
}

static void
do_response(struct snmp_proto *p, byte *buf, uint size)
{
  //snmp_log("do_response()");
  struct agentx_response *r = (void *) buf;
  struct agentx_header *h = &r->h;
  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

  /* TODO make it asynchronous for better speed */
  switch (p->state)
  {
    case SNMP_INIT:
    case SNMP_LOCKED:
      /* silent drop of recieved packet */
      break;

    case SNMP_OPEN:
      /* copy session info from recieved packet */
      p->session_id = LOAD_U32(h->session_id, byte_ord);
      refresh_ids(p, h);

      /* the state needs to be changed before sending registering PDUs to
       * use correct do_response action on them
       */
      snmp_log("changing state to REGISTER");
      p->state = SNMP_REGISTER;
      snmp_register_mibs(p);
      //snmp_log("do_response state SNMP_INIT register list %u", list_length(&p->register_queue));
      break;

    case SNMP_REGISTER:;
      //snmp_log("do_response state SNMP_REGISTER register list %u", list_length(&p->register_queue));

      byte *pkt = buf;
      ADVANCE(pkt, size, AGENTX_HEADER_SIZE);

      uint clen;
      const char *context;
      SNMP_LOAD_CONTEXT((struct agentx_header *) buf, pkt, context, clen);

      if (size < snmp_str_size_from_len(clen))
	return;

      ADVANCE(pkt, size, snmp_str_size_from_len(clen));
      const struct oid *oid = (void *) pkt;

      snmp_register_ack(p, h, snmp_get_mib_class(oid));

      if (p->register_to_ack == 0)
      {
	snmp_log("changing state to CONNECTED");
	p->state = SNMP_CONN;
	proto_notify_state(&p->p, PS_UP);
      }
      break;

    case SNMP_CONN:
      break;

    case SNMP_STOP:
      break;

    default:
      die("unkonwn SNMP state");
  }
}

u8
snmp_get_mib_class(const struct oid *oid)
{
  // TODO check code paths for oid->n_subid < 3
  if (oid->prefix != SNMP_MGMT && oid->ids[0] != SNMP_MIB_2)
    return SNMP_CLASS_INVALID;

  switch (oid->ids[1])
  {
    case SNMP_BGP4_MIB:
      return SNMP_CLASS_BGP;

    default:
      return SNMP_CLASS_END;
  }
}

/* return 0 if the created varbind type is END_OF_MIB_VIEW, 1 otherwise */
static int
snmp_get_next2(struct snmp_proto *p, struct oid *o_start, struct oid *o_end,
	       struct snmp_pdu *c)
{
  //snmp_log("get_next2()");
  enum snmp_search_res r;
  //snmp_log("next2() o_end %p", o_end);
  struct oid *o_copy = search_mib(p, o_start, o_end, NULL, c, &r);
  //snmp_log("next2()2 o_end %p", o_end);

  struct agentx_varbind *vb = NULL;
  switch (r)
  {
    case SNMP_SEARCH_NO_OBJECT:
    case SNMP_SEARCH_NO_INSTANCE:
    case SNMP_SEARCH_END_OF_VIEW:;
      uint sz = snmp_varbind_hdr_size_from_oid(o_start);

      if (c->size < sz)
      {
	/* TODO create NULL varbind */
	c->error = AGENTX_RES_GEN_ERROR;
	return 0;
      }

      vb = snmp_create_varbind(c->buffer, o_start);
      vb->type = AGENTX_END_OF_MIB_VIEW;
      ADVANCE(c->buffer, c->size, snmp_varbind_header_size(vb));
      return 0;

    case SNMP_SEARCH_OK:
    default:
      break;
  }

  if (o_copy)
  {
    /* basicaly snmp_create_varbind(c->buffer, o_copy), but without any copying */
    vb = (void *) c->buffer;
    snmp_mib_fill2(p, o_copy, c);

    /* override the error for GetNext-PDU object not find */
    switch (vb->type)
    {
      case AGENTX_NO_SUCH_OBJECT:
      case AGENTX_NO_SUCH_INSTANCE:
      case AGENTX_END_OF_MIB_VIEW:
	vb->type = AGENTX_END_OF_MIB_VIEW;
	return 0;

      default:
	return 1;
    }
  }

  if (c->size < snmp_varbind_hdr_size_from_oid(o_start))
  {
    // TODO FIXME this is a bit tricky as we need to renew all TX buffer pointers
    snmp_manage_tbuf(p, c);
  }

  vb = snmp_create_varbind(c->buffer, o_start);
  vb->type = AGENTX_END_OF_MIB_VIEW;
  ADVANCE(c->buffer, c->size, snmp_varbind_header_size(vb));
  return 0;
}

/* returns 0 if the created varbind has type EndOfMibView, 1 otherwise */
static int
snmp_get_bulk2(struct snmp_proto *p, struct oid *o_start, struct oid *o_end,
	       struct agentx_bulk_state *state, struct snmp_pdu *c)
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
  } while (o_curr && i < state->repetition);

  // TODO check if the approach below works
  // it need to generate varbinds that will be only of type EndOfMibView
  /* Object Identifier fall-backs */
  if (!o_curr)
    o_curr = o_predecessor;

  if (!o_curr)
    o_curr = o_start;

  uint sz = snmp_varbind_hdr_size_from_oid(o_curr);

  if (c->size < sz)
  {
    c->error = AGENTX_RES_GEN_ERROR;
    return 0;
  }

  /* we need the varbind handle to be able to override it's type */
  struct agentx_varbind *vb = (void *) c->buffer;
  vb->type = AGENTX_END_OF_MIB_VIEW;

  if (r == SNMP_SEARCH_OK)
    /* the varbind will be recreated inside the snmp_mib_fill2() */
    snmp_mib_fill2(p, o_curr, c);
  else
    ADVANCE(c->buffer, c->size, snmp_varbind_header_size(vb));

  /* override the error for GetBulk-PDU object not found */
  switch (vb->type)
  {
    case AGENTX_NO_SUCH_OBJECT:
    case AGENTX_NO_SUCH_INSTANCE:
    case AGENTX_END_OF_MIB_VIEW:
      vb->type = AGENTX_END_OF_MIB_VIEW;
      return 0;

    default:
      return 1;
  }
}

static inline uint
update_packet_size(struct snmp_proto *p, const byte *start, byte *end)
{
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
  // TODO checks for c.size underflow
  //snmp_log("parse_gets2_pdu()");

  struct oid *o_start = NULL, *o_end = NULL;
  byte *pkt = pkt_start;

  struct agentx_header *h = (void *) pkt;
  ADVANCE(pkt, size, AGENTX_HEADER_SIZE);
  uint pkt_size = LOAD_U32(h->payload, h->flags & AGENTX_NETWORK_BYTE_ORDER);

  sock *sk = p->sock;
  struct snmp_pdu c = SNMP_PDU_CONTEXT(sk);
  // TODO better handling of endianness
  c.byte_ord = 0; /* use little-endian */

  uint clen;	  /* count of characters in context (without last '\0') */
  const char *context;  /* pointer to RX-buffer context */

  /* alters pkt; assign context, clen */
  SNMP_LOAD_CONTEXT(h, pkt, context, clen);

  /*
   * We need more data; for valid response we need to know full
   * header picture, including the context octet string
   */
  if (size < clen)
  {
    //snmp_log("size %u < %u clen, returning 0", size, clen);
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

  /*
   * Get-Bulk processing stops if all the varbind have type END_OF_MIB_VIEW
   * has_any is true if some varbind has type other than END_OF_MIB_VIEW
   */
  int has_any = 0;
  struct agentx_bulk_state bulk_state = { };
  if (h->type == AGENTX_GET_BULK_PDU)
  {
    if (size < sizeof(struct agentx_getbulk))
      goto wait;

    if (pkt_size < sizeof(struct agentx_getbulk))
    {
      c.error = AGENTX_RES_PARSE_ERROR;
      goto send;
    }

    struct agentx_getbulk *bulk_info = (void *) pkt;
    ADVANCE(pkt, pkt_size, sizeof(struct agentx_getbulk));

    bulk_state = (struct agentx_bulk_state) {
      .getbulk = {
	.non_repeaters = LOAD_U32(bulk_info->non_repeaters, c.byte_ord),
	.max_repetitions = LOAD_U32(bulk_info->max_repetitions, c.byte_ord),
      },
      /* In contrast to the RFC, we use 0-based indices. */
      .index = 0,
      .repetition = 0,
    };
  }

  if (c.size < sizeof(struct agentx_response))
  {
    snmp_manage_tbuf(p, &c);
    // TODO renew pkt, pkt_start pointers context clen
  }

  struct agentx_response *response_header = prepare_response(p, &c);

  uint ind = 0;
  while (c.error == AGENTX_RES_NO_ERROR && size > 0 && pkt_size > 0)
  {
    //snmp_log("iter %u  size %u remaining %u/%u", ind + 1, c.buffer - sk->tpos, size, pkt_size);

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
     * If we already have written same relevant data to the TX buffer, then
     * we send processed part, otherwise we don't have anything to send and
     * need to wait for more data to be recieved.
     */
    if (sz > size && ind > 0)
    {
      //snmp_log("sz %u > %u size && ind %u > 1", sz, size, ind + 1);
      goto partial;  /* send already processed part */
    }
    else if (sz > size)
    {
      //snmp_log("sz %u > %u size; returning 0", sz, size);
      goto wait;
    }

    /* Update buffer pointer and remaining size counters. */
    ADVANCE(pkt, pkt_size, sz);
    size -= sz;

    /*
     * We load search range end OID
     * The exactly same process of sanity checking is preformed while loading
     * the SearchRange's end OID
     */
    const struct oid *o_end_b = (void *) pkt;
    if ((sz = snmp_oid_size(o_end_b)) > pkt_size)
    {
      c.error = AGENTX_RES_PARSE_ERROR;  /* Packet error, inconsistent values */
      goto send;
    }

    if (sz > size && ind > 0)
    {
      //snmp_log("sz2 %u > %u size && ind %u > 1", sz, size, ind + 1);
      size += snmp_oid_size(o_start_b);
      goto partial;
    }
    else if (sz > size)
    {
      //snmp_log("sz2 %u > %u size; returning 0", sz, size);
      goto wait;
    }

    ADVANCE(pkt, pkt_size, sz);
    size -= sz;

    // TODO check for oversized OIDs before any allocation (in prefixize())

    /* We create copy of OIDs outside of rx-buffer and also prefixize them */
    o_start = snmp_prefixize(p, o_start_b, c.byte_ord);
    o_end = snmp_prefixize(p, o_end_b, c.byte_ord);

    if (!snmp_is_oid_empty(o_end) && snmp_oid_compare(o_start, o_end) > 0)
    {
      //snmp_log("snmp_gets2() o_start does not preceed o_end, returning GEN_ERROR");
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
	if (ind >= bulk_state.getbulk.non_repeaters)
	  bulk_state.repeaters++;

	// store the o_start, o_end

	/* The behavior of GetBulk pdu in the first iteration is
	 * identical to GetNext pdu. */
	has_any = has_any || snmp_get_next2(p, o_start, o_end, &c);
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

  if (h->type == AGENTX_GET_BULK_PDU)
  {
    for (bulk_state.repetition++;
	 has_any && bulk_state.repetition < bulk_state.getbulk.max_repetitions;
	 bulk_state.repetition++)
    {
      // TODO find propper start and end
      struct oid *start = NULL;
      struct oid *end = NULL;
      has_any = 0;
      for (bulk_state.index = 0; bulk_state.index < bulk_state.repeaters;
	   bulk_state.repeaters++)
	has_any = has_any || snmp_get_bulk2(p, start, end, &bulk_state, &c);
    }
  }

send:;
  //snmp_log("gets2: sending response ...");
  struct agentx_response *res = (void *) sk->tbuf;
  /* We update the error, index pair on the beginning of the packet. */
  response_err_ind(res, c.error, ind + 1);
  uint s = update_packet_size(p, (byte *) response_header, c.buffer);

  //snmp_log("sending response to Get-PDU, GetNext-PDU or GetBulk-PDU request (size %u)...", s);

  /* We send the message in TX-buffer. */
  int ret = sk_send(sk, s);
  if (ret > 0)
    snmp_log("sk_send OK!");
  else if (ret == 0)
    snmp_log("sk_send sleep");
  else
    snmp_log("sk_send error");
  // TODO think through the error state

  mb_free(o_start);
  mb_free(o_end);

  /* number of bytes parsed from RX-buffer */
  return pkt - pkt_start;


partial:
  //snmp_log("partial packet");
  /* The context octet is not added into response pdu. */

  /* need to tweak RX buffer packet size */
  //snmp_log("old rx-buffer size %u", h->payload);
  (c.byte_ord) ? put_u32(&h->payload, pkt_size) : (h->payload = pkt_size);
  //snmp_log("new rx-buffer size %u", h->payload);
  *skip = AGENTX_HEADER_SIZE;

  /* number of bytes parsed from RX-buffer */
  return pkt - pkt_start;


wait:
  mb_free(o_start);
  mb_free(o_end);
  p->packet_id--; /* we did not use the packetID */

  return 0;
}

void
snmp_start_subagent(struct snmp_proto *p)
{
  //snmp_log("snmp_start_subagent() starting subagent");
  //snmp_log("DEBUG p->bgp_local_as %u", p->bgp_local_as);

  /* blank oid means unsupported */
  struct oid *blank = snmp_oid_blank(p);
  open_pdu(p, blank);

  p->state = SNMP_OPEN;

  mb_free(blank);
}

void
snmp_stop_subagent(struct snmp_proto *p)
{
  //snmp_log("snmp_stop_subagent() state %d", p->state);

  if (p->state == SNMP_STOP)
    close_pdu(p, AGENTX_CLOSE_SHUTDOWN);
}

static inline int
oid_prefix(struct oid *o, u32 *prefix, uint len)
{
  for (uint i = 0; i < len; i++)
    if (o->ids[i] != prefix[i])
      return 0;

  return 1;
}

int
snmp_rx(sock *sk, uint size)
{
  //snmp_log("snmp_rx() size %u", size);
  //snmp_dump_packet(sk->tbuf, 64);
  struct snmp_proto *p = sk->data;
  byte *pkt_start = sk->rbuf;
  byte *end = pkt_start + size;
  //snmp_log("snmp_rx rbuf 0x%p  rpos 0x%p", sk->rbuf, sk->rpos);

  /*
   * In some cases we want to save the header for future parsing, skip is number
   * of bytes that should not be overriden by memmove()
   */
  uint skip = 0;

  //snmp_log("snmp_rx before loop");
  while (end >= pkt_start + AGENTX_HEADER_SIZE && skip == 0)
  {
    uint parsed_len = parse_pkt(p, pkt_start, size, &skip);

    /*snmp_log("snmp_rx loop end %p parsed >>>  %u  <<< curr %p", end, parsed_len,
	      pkt_start + parsed_len);
*/
    //snmp_log("snmp_rx loop2 rpos 0x%p", sk->rpos);

    if (parsed_len == 0)
      break;

    pkt_start += parsed_len;
    size -= parsed_len;
  }
  //snmp_log("snmp_rx loop finished");

  /* Incomplete packets */
  if (skip != 0 || pkt_start != end)
  {
    //snmp_log("snmp_rx memmove");
    //snmp_dump_packet(sk->rbuf, SNMP_RX_BUFFER_SIZE);
    memmove(sk->rbuf + skip, pkt_start, size);
    //snmp_log("after change; sk->rbuf 0x%p  sk->rpos 0x%p", sk->rbuf, sk->rpos);
    //snmp_dump_packet(sk->rbuf, size + skip);
    //snmp_log("tweaking rpos 0x%p  (size %u skip %u)", sk->rpos, size, skip);
    sk->rpos = sk->rbuf + size + skip;
    //snmp_log("snmp_rx returing 0");
    return 0;
  }

  //snmp_log("snmp_rx returning 1");
  return 1;
}

/* Ping-PDU */
void
snmp_ping(struct snmp_proto *p)
{
  sock *sk = p->sock;
  //snmp_dump_packet(sk->tpos, AGENTX_HEADER_SIZE + 4);
  //snmp_log("snmp_ping sk->tpos 0x%p", sk->tpos);
  struct snmp_pdu c = SNMP_PDU_CONTEXT(sk);

  if (c.size < AGENTX_HEADER_SIZE)
    snmp_manage_tbuf(p, &c);

  //snmp_log("ping_pdu()");
  struct agentx_header *h = (struct agentx_header *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);
  SNMP_BLANK_HEADER(h, AGENTX_PING_PDU);
  p->packet_id++;
  SNMP_SESSION(h, p);
  c.byte_ord = AGENTX_NETWORK_BYTE_ORDER;

  //snmp_log("sending ping packet ... tpos 0x%p", sk->tpos);
  //snmp_dump_packet(sk->tpos, AGENTX_HEADER_SIZE + 4);
  /* sending only header -> pkt - buf */
  uint s = update_packet_size(p, sk->tpos, c.buffer);

  int ret = sk_send(sk, s);
  if (ret > 0)
    snmp_log("sk_send OK!");
  else if (ret == 0)
    snmp_log("sk_send sleep");
  else
    snmp_log("sk_send error");
}

static inline int
is_bgp4_mib_prefix(struct oid *o)
{
  if (o->prefix == SNMP_MGMT && o->ids[0] == SNMP_MIB_2 &&
      o->ids[1] == SNMP_BGP4_MIB)
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
  /*snmp_log("upper_bound_check(*f, *b) %p %p is_empty() %d", found, bound,
	  snmp_is_oid_empty(bound));
*/

  if (snmp_is_oid_empty(bound))
    return 1;

  return (snmp_oid_compare(found, bound) < 0);
}

/* tree is tree with "internet" prefix .1.3.6.1
   working only with o_start, o_end allocated in heap (not from buffer)*/
static struct oid *
search_mib(struct snmp_proto *p, const struct oid *o_start, const struct oid *o_end,
	   struct oid *o_curr, struct snmp_pdu *c,
	   enum snmp_search_res *result)
{
  //snmp_log("search_mib()");
  ASSUME(o_start != NULL);

  if (o_curr && (o_curr->n_subid < 2 || o_curr->ids[0] != 1))
    return NULL;
  if (!o_curr && (o_start->n_subid < 2 || o_start->ids[0] != 1))
    return NULL;

  if (!o_curr)
  {
    o_curr = snmp_oid_duplicate(p->pool, o_start);
    // XXX is it right time to free o_start right now (here) ?
	// not for use in snmp_get_next2() the o_start comes and ends in _gets2_()
  }

  const struct oid *blank = NULL;
  if (!snmp_is_oid_empty(o_end) &&
      snmp_get_mib_class(o_curr) < snmp_get_mib_class(o_end))
  {
    o_end = blank = snmp_oid_blank(p);
    //snmp_log("search_mib() o_end points to blank oid now %p", o_end);
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
      o_curr = snmp_oid_duplicate(p->pool, o_start);
      *result = SNMP_SEARCH_END_OF_VIEW;
      break;
  }

  if (o_end == blank)
    mb_free((void *) blank);

  return o_curr;
}

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
  //snmp_log("snmp_prefixize()");

  if (snmp_is_oid_empty(oid))
  {
    /* allocate new zeroed oid */
    //snmp_log("blank");
    return snmp_oid_blank(proto);
  }

  /* already in prefixed form */
  else if (oid->prefix != 0) {
    struct oid *new = snmp_oid_duplicate(proto->pool, oid);
    //snmp_log("already prefixed");
    return new;
  }

  if (oid->n_subid < 5)
    return NULL;
  //{  snmp_log("too small"); return NULL; }

  for (int i = 0; i < 4; i++)
    if (LOAD_U32(oid->ids[i], byte_ord) != snmp_internet[i])
      return NULL;
      //{ snmp_log("different prefix"); return NULL; }

  /* validity check here */
  if (oid->ids[4] >= 256)
    return NULL;
    //{ snmp_log("outside byte first id"); return NULL; }

  struct oid *new = mb_alloc(proto->pool,
          sizeof(struct oid) + MAX((oid->n_subid - 5) * sizeof(u32), 0));

  memcpy(new, oid, sizeof(struct oid));
  new->n_subid = oid->n_subid - 5;

  /* validity check before allocation => ids[4] < 256
     and can be copied to one byte new->prefix */
  new->prefix = oid->ids[4];

  memcpy(&new->ids, &oid->ids[5], new->n_subid * sizeof(u32));
  return new;
}

static void
snmp_mib_fill2(struct snmp_proto *p, struct oid *oid,
	       struct snmp_pdu *c)
{
  ASSUME(oid != NULL);

  if (c->size < snmp_varbind_hdr_size_from_oid(oid))
    snmp_manage_tbuf(p, c);

  struct agentx_varbind *vb = snmp_create_varbind(c->buffer, oid);

  if (oid->n_subid < 2 || (oid->prefix != SNMP_MGMT && oid->ids[0] != SNMP_MIB_2))
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
      break;
      vb->type = AGENTX_NO_SUCH_OBJECT;
      ADVANCE(c->buffer, c->size, snmp_varbind_header_size(vb));
  }
}

/**
 *
 * Important note: After managing insufficient buffer size all in buffer pointers
 *  are invalidated!
 */
void
snmp_manage_tbuf(struct snmp_proto UNUSED *p, struct snmp_pdu *c)
{
  //snmp_log("snmp_manage_tbuf()");
  sock *sk = p->sock;

  sk_set_tbsize(sk, sk->tbsize + 2048);
  c->size += 2048;
}

static struct agentx_response *
prepare_response(struct snmp_proto *p, struct snmp_pdu *c)
{
  //snmp_log("prepare_response()");

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
