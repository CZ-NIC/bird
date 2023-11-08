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

/**
 * Handling of malformed packet:
 *  When we find an error in PDU data, we create and send a response with error
 *  defined by the RFC. We await until the packet is send and then we close the
 *  communication socket. This also closes the established session. We chose
 *  this approach because we cannot easily mark the boundary between packets.
 *  When we are reseting the connection, we change the snmp_state to SNMP_RESET.
 *  In SNMP_RESET state we skip all received bytes and wait for snmp_tx()
 *  to be called. The socket's tx_hook is called when the TX-buffer is empty,
 *  meaning our response (agentx-Response-PDU) was send.
 *
 */

static void snmp_mib_fill2(struct snmp_proto *p, struct oid *oid, struct snmp_pdu *c);
static uint parse_response(struct snmp_proto *p, byte *buf, uint size);
static void do_response(struct snmp_proto *p, byte *buf, uint size);
static uint parse_gets2_pdu(struct snmp_proto *p, byte *buf, uint size, uint *skip);
static struct agentx_response *prepare_response(struct snmp_proto *p, struct snmp_pdu *c);
static void response_err_ind(struct agentx_response *res, enum agentx_response_errs err, u16 ind);
static uint update_packet_size(struct snmp_proto *p, const byte *start, byte *end);
static struct oid *search_mib(struct snmp_proto *p, const struct oid *o_start, const struct oid *o_end, struct oid *o_curr, struct snmp_pdu *c, enum snmp_search_res *result);
static void snmp_tx(sock *sk);

u32 snmp_internet[] = { SNMP_ISO, SNMP_ORG, SNMP_DOD, SNMP_INTERNET };

static const char * const snmp_errs[] UNUSED = {
  [AGENTX_RES_NO_ERROR		    ] = "No error",
  [AGENTX_RES_GEN_ERROR		    ] = "General error",
  [AGENTX_RES_NO_ACCESS		    ] = "No access",
  [AGENTX_RES_WRONG_TYPE	    ] = "Wrong type",
  [AGENTX_RES_WRONG_LENGTH	    ] = "Wrong length",
  [AGENTX_RES_WRONG_ENCODING	    ] = "Wrong encoding",
  [AGENTX_RES_WRONG_VALUE	    ] = "Wrong value",
  [AGENTX_RES_NO_CREATION	    ] = "No creation",
  [AGENTX_RES_INCONSISTENT_VALUE    ] = "Inconsistent value",
  [AGENTX_RES_RESOURCE_UNAVAILABLE  ] = "Resource unavailable",
  [AGENTX_RES_COMMIT_FAILED	    ] = "Commit failed",
  [AGENTX_RES_UNDO_FAILED	    ] = "Undo failed",
  [AGENTX_RES_NOT_WRITABLE	    ] = "Not writable",
  [AGENTX_RES_INCONSISTENT_NAME	    ] = "Inconsistent name",
  [AGENTX_RES_OPEN_FAILED	    ] = "Open failed",
  [AGENTX_RES_NOT_OPEN		    ] = "Not open",
  [AGENTX_RES_INDEX_WRONG_TYPE	    ] = "Index wrong type",
  [AGENTX_RES_INDEX_ALREADY_ALLOC   ] = "Index already allocated",
  [AGENTX_RES_INDEX_NONE_AVAIL	    ] = "Index none availlable",
  [AGENTX_RES_NOT_ALLOCATED	    ] = "Not allocated",
  [AGENTX_RES_UNSUPPORTED_CONTEXT   ] = "Unsupported contex",
  [AGENTX_RES_DUPLICATE_REGISTER    ] = "Duplicate registration",
  [AGENTX_RES_UNKNOWN_REGISTER	    ] = "Unknown registration",
  [AGENTX_RES_UNKNOWN_AGENT_CAPS    ] = "Unknown agent caps",
  [AGENTX_RES_PARSE_ERROR	    ] = "Parse error",
  [AGENTX_RES_REQUEST_DENIED	    ] = "Request denied",
  [AGENTX_RES_PROCESSING_ERR	    ] = "Processing error",
};

static const char * const snmp_pkt_type[] UNUSED = {
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


/*
 * snmp_register_ok - registration of OID was successful
 * @p: SNMP protocol instance
 * @res: header of agentx-Response-PDU
 * @oid: OID that was successfully registered
 * @class: MIB subtree of @oid
 *
 * Send a notification to MIB (selected by @class) about successful registration
 * of @oid.
 */
static void
snmp_register_ok(struct snmp_proto *p, struct agentx_response *res, struct oid *oid, u8 UNUSED class)
{
  // TODO switch based on oid type
  snmp_bgp_reg_ok(p, res, oid);
}

/*
 * snmp_regsiter_failed - registration of OID failed
 * @p: SNMP protocol instance
 * @res: header of agentx-Response-PDU
 * @oid: OID whose registration failed
 * @class: MIB subtree of @oid
 *
 * Send a notification to MIB (selected by @class) about @oid registraion
 * failure.
 */
static void
snmp_register_failed(struct snmp_proto *p, struct agentx_response *res, struct oid *oid, u8 UNUSED class)
{
  // TODO switch based on oid type
  snmp_bgp_reg_failed(p, res, oid);
}

/*
 * snmp_register_ack - handle response to agentx-Register-PDU
 * @p: SNMP protocol instance
 * @res: header of agentx-Response-PDU
 * @class: MIB subtree associated with agentx-Register-PDU
 */
void
snmp_register_ack(struct snmp_proto *p, struct agentx_response *res, u8 class)
{
  struct snmp_register *reg;
  WALK_LIST(reg, p->register_queue)
  {
    // TODO add support for more mib trees (other than BGP)
    if (snmp_register_same(reg, &res->h, class))
    {
      struct snmp_registered_oid *ro = \
	 mb_alloc(p->p.pool, sizeof(struct snmp_registered_oid));

      ro->n.prev = ro->n.next = NULL;

      ro->oid = reg->oid;

      rem_node(&reg->n);
      mb_free(reg);
      p->register_to_ack--;

      add_tail(&p->bgp_registered, &ro->n);

      if (res->error == AGENTX_RES_NO_ERROR)
	snmp_register_ok(p, res, ro->oid, class);
      else
	snmp_register_failed(p, res, ro->oid, class);
      return;
    }
  }
}

/*
 * snmp_rx_skip - skip all received data
 * @sk: communication socket
 * @size: size of received PDUs
 *
 * Socket rx_hook used when we are reseting the connection due to malformed PDU.
 */
static int
snmp_rx_skip(sock UNUSED *sk, uint UNUSED size)
{
  return 1;
}

/*
 * snmp_error - handle a malformed packet
 * @p: SNMP protocol instance
 *
 * We wait until all packets are send. Then we close the socket which also
 * closes the established session on given socket. Finally we try to start a new
 * session.
 */
static inline void
snmp_error(struct snmp_proto *p)
{
  snmp_log("changing state to RESET");
  p->state = SNMP_RESET;

  p->sock->rx_hook = snmp_rx_skip;
  p->sock->tx_hook = snmp_tx;
}

/*
 * snmp_simple_response - send an agentx-Response-PDU with no data payload
 * @p: SNMP protocol instance
 * @error: PDU error fields value
 * @index: PDU error index field value
 */
static void
snmp_simple_response(struct snmp_proto *p, enum agentx_response_errs error, u16 index)
{
  sock *sk = p->sock;
  struct snmp_pdu c = SNMP_PDU_CONTEXT(sk);

  if (c.size < sizeof(struct agentx_response))
    snmp_manage_tbuf(p, &c);

  struct agentx_response *res = prepare_response(p, &c);
  response_err_ind(res, error, index);
  sk_send(sk, sizeof(struct agentx_response));
}

/*
 * open_pdu - send an agentx-Open-PDU
 * @p: SNMP protocol instance
 * @oid: PDU OID description field value
 *
 * Other fields are filled based on @p configuratin (timeout, subagent string
 * description)
 */
static void
open_pdu(struct snmp_proto *p, struct oid *oid)
{
  const struct snmp_config *cf = SKIP_BACK(struct snmp_config, cf, p->p.cf);
  sock *sk = p->sock;

  struct snmp_pdu c = SNMP_PDU_CONTEXT(sk);

#define TIMEOUT_SIZE 4 /* 1B timeout, 3B zero padding */
  if (c.size < AGENTX_HEADER_SIZE + TIMEOUT_SIZE + snmp_oid_size(oid) +
      + snmp_str_size(cf->description))
    snmp_manage_tbuf(p, &c);

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

  uint s = update_packet_size(p, sk->tpos, c.buffer);
  sk_send(sk, s);
#undef TIMEOUT_SIZE
}

/*
 * send_notify_pdu - send an agentx-Notify-PDU
 * @p: SNMP protocol instance
 * @oid: PDU notification Varbind name (OID)
 * @data: PDU Varbind payload
 * @size - PDU Varbind payload size
 * @include_uptime: flag enabling inclusion of sysUpTime.0 OID
 */
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
  sk_send(sk, s);

#undef TRAP0_HEADER_SIZE
#undef UPTIME_SIZE
}

#if 0
/*
 * de_allocate_pdu - common functionality for allocation PDUs
 * @p: SNMP protocol instance
 * @oid: OID to allocate/deallocate
 * @type: allocate/deacollcate PDU type
 * @flags: type of allocation (NEW_INDEX, ANY_INDEX)
 *
 * This function is internal and shouldn't be used outside the SNMP module.
 */
static void
de_allocate_pdu(struct snmp_proto *p, struct oid *oid, enum agentx_pdu_types type, u8 flags)
{
  sock *sk = p->sock;
  byte *buf, *pkt;
  buf = pkt = sk->tbuf;
  uint size = sk->tbsize;
  struct snmp_pdu = SNMP_PDU_CONTEXT(p->sock);


  if (size > AGENTX_HEADER_SIZE + 0)  // TODO additional size
  {
    struct agentx_header *h;
    SNMP_CREATE(pkt, struct agentx_header, h);
    SNMP_BLANK_HEADER(h, type);
    SNMP_SESSION(h,p);

    struct agentx_varbind *vb = (struct agentx_varbind *) pkt;

    // TODO
    STORE_16(vb->type, AGENTX_OBJECT_ID);
    STORE(vb->oid, 0);
  }
}

void
snmp_allocate(struct snmp_proto *p, struct oid *oid, u8 flags)
{
  /* TODO - call the de_allocate_pdu() */
}

void
snmp_deallocate(struct snmp_proto *p, struct oid *oid, u8 flags)
{
  /* TODO - call the de_allocate_pdu() */
}
#endif

/*
 * un_register_pdu - common functionality for registration PDUs
 * @p: SNMP protocol instance
 * @oid: OID to register/unregister
 * @bound: OIDs registration upper bound
 * @index: OIDs registration n_subid index
 * @type: register/unregister PDU type
 * @is_instance: flag enabling instance registration (used only for register)
 * @contid: context ID to register in (currently unsupported)
 *
 * Both register and unregister PDUs are capable of specifing a number of OIDs
 * by using pair of index and upper bound. The index (r.range_subid) points into
 * the OID's n_subid array to ID being threated as variable. The upper bound
 * (r.upper_bound) determins maximal value for n_subid selected by index.
 * The index and upper bound are passed as @index, and @bound respectively.
 *
 * Zero value for @is_instance means we want to register/unregister OID as a MIB
 * subtree, for nonzero value we are registering MIB tree an instance (leaf).
 *
 * This function in internal and shoulnd't be used outside the SNMP module,
 * see snmp_register() and snmp_unregister() functions.
 */
static void
un_register_pdu(struct snmp_proto *p, struct oid *oid, uint bound, uint index, enum agentx_pdu_types type, u8 is_instance, uint UNUSED contid)
{
  const struct snmp_config *cf = SKIP_BACK(struct snmp_config, cf, p->p.cf);
  sock *sk = p->sock;
  struct snmp_pdu c = SNMP_PDU_CONTEXT(sk);

  /* conditional +4 for upper-bound (optinal field) */
  uint sz = AGENTX_HEADER_SIZE + snmp_oid_size(oid) + ((bound > 1) ? 4 : 0);

  if (c.size < sz)
    snmp_manage_tbuf(p, &c);

  struct agentx_header *h = (struct agentx_header *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);

  SNMP_HEADER(h, (u8) type, is_instance ? AGENTX_FLAG_INSTANCE_REGISTRATION : 0);
  p->packet_id++;
  SNMP_SESSION(h, p);
  c.byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

  struct agentx_un_register_hdr *ur = (struct agentx_un_register_hdr *) c.buffer;

  /* do not override timeout */
  STORE_U8(ur->timeout, p->timeout);
  /* default priority */
  STORE_U8(ur->priority, cf->priority);
  STORE_U8(ur->range_subid, (bound > 1) ? index : 0);
  STORE_U8(ur->pad, 0);
  ADVANCE(c.buffer, c.size, sizeof(struct agentx_un_register_hdr));

  snmp_put_oid(c.buffer, oid);
  ADVANCE(c.buffer, c.size, snmp_oid_size(oid));

  /* place upper-bound if needed */
  if (bound > 1)
  {
    STORE_PTR(c.buffer, bound);
    ADVANCE(c.buffer, c.size, 4);
  }

  uint s = update_packet_size(p, sk->tpos, c.buffer);

  sk_send(sk, s);
}

/*
 * snmp_register - send an agentx-Register-PDU
 * @p: SNMP protocol instance
 * @oid: OID to register
 * @bound: OIDs registration upper bound
 * @index: OIDs registration n_subid index
 * @is_instance: flag enabling instance registration
 * @contid: context ID to register in (currently unsupported)
 *
 * For more detailed description see un_register_pdu() function.
 */
void
snmp_register(struct snmp_proto *p, struct oid *oid, uint bound, uint index, u8 is_instance, uint contid)
{
  un_register_pdu(p, oid, bound, index, AGENTX_REGISTER_PDU, is_instance, contid);
}

/*
 * snmp_unregister - send an agentx-Unregister-PDU
 * @p: SNMP protocol instance
 * @oid: OID to uregister
 * @bound: OIDs unregistration upper bound
 * @index: OIDs unregistration n_subid index
 * @contid: context ID to unregister from (currently unsupported)
 *
 * For more detailed description see un_register_pdu() function.
 */
void UNUSED
snmp_unregister(struct snmp_proto *p, struct oid *oid, uint len, uint index, uint contid)
{
  un_register_pdu(p, oid, len, index, AGENTX_UNREGISTER_PDU, 0, contid);
}

/*
 * close_pdu - send an agentx-Close-PDU
 * @p: SNMP protocol instance
 * @reason: reason for closure
 */
static void
close_pdu(struct snmp_proto *p, enum agentx_close_reasons reason)
{
  sock *sk = p->sock;
  struct snmp_pdu c = SNMP_PDU_CONTEXT(sk);

#define REASON_SIZE 4
  if (c.size < AGENTX_HEADER_SIZE + REASON_SIZE)
    snmp_manage_tbuf(p, &c);

  struct agentx_header *h = (struct agentx_header *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);
  SNMP_BLANK_HEADER(h, AGENTX_CLOSE_PDU);
  p->packet_id++;
  SNMP_SESSION(h, p);
  c.byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

  snmp_put_fbyte(c.buffer, (u8) reason);
  ADVANCE(c.buffer, c.size, 4);

  uint s = update_packet_size(p, sk->tpos, c.buffer);
  sk_send(sk, s);
#undef REASON_SIZE
}

/*
 * parse_close_pdu - parse an agentx-Close-PDU
 * @p: SNMP protocol instance
 * @pkt_start: pointer to first byte of PDU
 * @size: number of bytes received from a socket
 *
 * Return number of bytes parsed from RX-buffer.
 */
static uint
parse_close_pdu(struct snmp_proto *p, byte * const pkt_start, uint size)
{
  byte *pkt = pkt_start;
  struct agentx_header *h = (void *) pkt;
  ADVANCE(pkt, size, AGENTX_HEADER_SIZE);
  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;
  uint pkt_size = LOAD_U32(h->payload, byte_ord);

  if (pkt_size != 0)
  {
    snmp_simple_response(p, AGENTX_RES_GEN_ERROR, 0);
    // TODO: best solution for possibly malicious pkt_size
    //return AGENTX_HEADER_SIZE + MIN(size, pkt_size);
    return AGENTX_HEADER_SIZE;
  }

  snmp_simple_response(p, AGENTX_RES_NO_ERROR, 0);
  snmp_sock_disconnect(p, 1); // TODO: should we try to reconnect (2nd arg) ??
  return AGENTX_HEADER_SIZE;
}


/*
 * snmp_testset - check possibility of VarBind name and data setting
 * @p: SNMP protocol instance
 * @vb: checked VarBind
 * @oid: pool-allocated prefixed copy of VarBind name
 * @pkt_size: number of not parsed bytes in processed PDU
 *
 * Check done by specialized function for specific MIB subtree whether
 * the VarBind is valid for set action (changing to current value to value
 * in VarBind).
 *
 * Return 1 if the VarBind setting is possible, 0 otherwise.
 */
/* MUCH better signature would be
    static int snmp_testset(struct snmp_proto *p, const struct agentx_varbind *vb, uint pkt_size);
 */
static int UNUSED
snmp_testset(struct snmp_proto *p, const struct agentx_varbind *vb, struct oid *oid, uint pkt_size)
{
  /* Hard-coded no support for writing */
  (void)p;(void)vb;(void)oid;(void)pkt_size;
  return 0;
#if 0
  // TODO better logic
  if (!oid)
    return 0;

  switch (oid->ids[1])
  {
    case SNMP_BGP4_MIB:
      return snmp_bgp_testset(p, vb, oid, pkt_size);
    default:
      return 0;
  }
#endif
}


#if 0
static void UNUSED
addagentcaps_pdu(struct snmp_proto *p, struct oid *cap, char *descr,
		 uint descr_len)
{
  ASSUME(descr != NULL && descr_len > 0);
  sock *sk = p->sock;
  //byte *buf = sk->tbuf;
  //uint size = sk->tbsize;
  // TO-DO rename to pkt and add pkt_start
  byte *buf = sk->tpos;
  uint size = sk->tbuf + sk->tbsize - sk->tpos;

  if (size < AGENTX_HEADER_SIZE + snmp_oid_size(cap) + snmp_str_size_from_len(descr_len))
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
    ADVANCE(buf, size, in_pkt);
  }

  // memcpy(buf, cap, snmp_oid_size(cap));
  ADVANCE(buf, size, snmp_oid_size(cap));

  in_pkt = snmp_put_nstr(buf, descr, descr_len) - buf;
  ADVANCE(buf, size, in_pkt);

  // make a note in the snmp_proto structure

  //int ret = sk_send(sk, buf - sk->tbuf);
  sk_send(sk, buf - sk->tpos);
}

static void UNUSED
removeagentcaps_pdu(struct snmp_proto *p, struct oid *cap)
{
  sock *sk = p->sock;

  //byte *buf = sk->tbuf;
  //uint size = sk->tbsize;
  // TO-DO rename to pkt and add pkt_start
  byte *buf = sk->tpos;
  uint size = sk->tbuf + sk->tbsize - sk->tpos;

  if (size < AGENTX_HEADER_SIZE + snmp_oid_size(cap))
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
    ADVANCE(buf, size, in_pkt);
  }

  memcpy(buf, cap, snmp_oid_size(cap));
  ADVANCE(buf, size, snmp_oid_size(cap));

  // update state in snmp_proto structure

  sk_send(sk, buf - sk->tpos);
}
#endif

/*
 * refresh_ids - Copy current ids from packet to protocol
 * @p: SNMP protocol instance
 * @h: PDU header with new transaction_id and packet_id ids.
 */
static inline void
refresh_ids(struct snmp_proto *p, struct agentx_header *h)
{
  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;
  p->transaction_id = LOAD_U32(h->transaction_id, byte_ord);
  p->packet_id = LOAD_U32(h->packet_id, byte_ord);
}

/*
 * parse_test_set_pdu - parse an agentx-TestSet-PDU in buffer
 * @p: SNMP protocol instance
 * @pkt_start: first byte of test set PDU
 * @size: number of bytes received from a socket
 *
 * Return number of bytes parsed from RX-buffer.
 */
static uint
parse_test_set_pdu(struct snmp_proto *p, byte * const pkt_start, uint size)
{
  byte *pkt = pkt_start;  /* pointer to agentx-TestSet-PDU in RX-buffer */
  uint s; /* final packat size */
  struct agentx_response *res; /* pointer to reponse in TX-buffer */

  struct agentx_header *h = (void *) pkt;
  ADVANCE(pkt, size, AGENTX_HEADER_SIZE);
  uint pkt_size = LOAD_U32(h->payload, h->flags & AGENTX_NETWORK_BYTE_ORDER);

  if (pkt_size < size)
    return 0;

  sock *sk = p->sock;
  struct snmp_pdu c = SNMP_PDU_CONTEXT(sk);
  c.byte_ord = 0; /* use little-endian */

  if (c.size < AGENTX_HEADER_SIZE)
    snmp_manage_tbuf(p, &c);

  res = prepare_response(p, &c);

  /* 0 if there is piece, that we cannot set */
  int all_possible = 0;
  /* the all_possible is currently hard-coded with no support for writing to mib
   * variables, when implementing the mentioned support, change the initializer
   * to 1
   */
#if 0
  // TODO think about future value setting data structure
  //struct agentx_transaction *tr = mb_alloc(...);
  void *tr = mb_alloc(p->pool, 16);

  struct agentx_varbind *vb;
  uint sz;
  while (size > 0 && all_possible)
  {
    vb = (void *) pkt;
    sz = snmp_varbind_size(vb, 0);

    if (sz > size)
    /* wait for more data to arive */
      return 0;

    if (sz > pkt_size)
    {
      c.error = AGENTX_RES_PARSE_ERROR;
      all_possible = 0;
      break;
    }

    /* Unknown VarBind type check */
    if (!snmp_test_varbind(vb))
    {
      c.error = AGENTX_RES_PARSE_ERROR;
      all_possible = 0;
      break;
    }
    ADVANCE(pkt, size, snmp_varbind_size(vb, 0));

    // TODO remove the mb_alloc() in prefixize()
    struct oid *work = snmp_prefixize(p, &vb->name, c.byte_ord);
    (void)work;
    all_possible = snmp_testset(p, vb, tr, work, pkt_size);
    mb_free(work);
  }
  mb_free(tr);
#endif
  s = update_packet_size(p, sk->tpos, c.buffer);

  if (c.error != AGENTX_RES_NO_ERROR)
  {
    response_err_ind(res, c.error, c.index + 1);
    snmp_error(p);
  }
  else if (all_possible)
    response_err_ind(res, AGENTX_RES_NO_ERROR, 0);
  else
    /* This is an recoverable error, we do not need to reset the connection */
    //response_err_ind(res, AGENTX_RES_RESOURCE_UNAVAILABLE, c.index + 1);
    response_err_ind(res, AGENTX_RES_NOT_WRITABLE, c.index + 1);

  sk_send(sk, s);
  return pkt - pkt_start;
}

/*
 * parse_set_pdu - common functionality for commit set and undo set PDUs
 * @p: SNMP protocol instance
 * @pkt_start: pointer to first byte of on of set related PDU
 * @size: number of bytes received from a socket
 * @error: error status to use
 *
 * Return number of bytes parsed from RX-buffer.
 */
static uint
parse_set_pdu(struct snmp_proto *p, byte * const pkt_start, uint size, enum agentx_response_errs err)
{
  byte *pkt = pkt_start;
  struct agentx_header *h = (void *) pkt;
  ADVANCE(pkt, size, AGENTX_HEADER_SIZE);
  uint pkt_size = LOAD_U32(h->payload, h->flags & AGENTX_NETWORK_BYTE_ORDER);

  if (pkt_size != 0)
  {
    snmp_simple_response(p, AGENTX_RES_PARSE_ERROR, 0);
    // TODO: best solution for possibly malicious pkt_size
    return MIN(size, pkt_size + AGENTX_HEADER_SIZE);
    // use varbind_list_size()??
  }

  struct snmp_pdu c = SNMP_PDU_CONTEXT(p->sock);
  if (c.size < sizeof(struct agentx_response))
    snmp_manage_tbuf(p, &c);

  struct agentx_response *r = prepare_response(p, &c);

  if (size < pkt_size)
  {
    c.error = AGENTX_RES_PARSE_ERROR;
  }
  else
  {
    // TODO: free resource allocated by parse_test_set_pdu()
    // TODO: do something meaningful
    //mb_free(tr);
    c.error = err;
  }

  response_err_ind(r, c.error, 0);
  sk_send(p->sock, AGENTX_HEADER_SIZE);

  /* Reset the connection on unrecoverable error */
  if (c.error != AGENTX_RES_NO_ERROR && c.error != err)
    snmp_error(p);

  return pkt - pkt_start;
}

/*
 * parse_commit_set_pdu - parse an agentx-CommitSet-PDU
 * @p: SNMP protocol instance
 * @pkt: pointer to first byte of PDU inside RX-buffer
 * @size: number of bytes received from a socket
 *
 * Return number of bytes parsed from RX-buffer.
 */
static uint
parse_commit_set_pdu(struct snmp_proto *p, byte *pkt, uint size)
{
  // don't forget to free resoures allocated by parse_test_set_pdu()
  //mb_free(tr);
  return parse_set_pdu(p, pkt, size, AGENTX_RES_COMMIT_FAILED);
}

/*
 * parse_undo_set_pdu - parse an agentx-UndoSet-PDU
 * @p: SNMP protocol instance
 * @pkt: pointer to first byte of PDU inside RX-buffer
 * @size: number of bytes received from a socket
 *
 * Return number of bytes parsed from buffer.
 */
static uint
parse_undo_set_pdu(struct snmp_proto *p, byte *pkt, uint size)
{
  // don't forget to free resources allocated by parse_test_set_pdu()
  //mb_free(tr);
  return parse_set_pdu(p, pkt, size, AGENTX_RES_UNDO_FAILED);
}

/*
 * parse_cleanup_set_pdu - parse an agentx-CleanupSet-PDU
 * @p: SNMP protocol instance
 * @pkt_start: pointer to first byte of PDU inside RX-buffer
 * @size: number of bytes received from a socket
 *
 * Return number of bytes parsed from RX-buffer.
 */
static uint
parse_cleanup_set_pdu(struct snmp_proto *p, byte * const pkt_start, uint size)
{
  (void)p;
  //TODO:
  // don't forget to free resources allocated by parse_test_set_pdu()
  //mb_free(p->tr);

  byte *pkt = pkt_start;
  struct agentx_header *h = (void *) pkt;
  uint pkt_size = LOAD_U32(h->payload, h->flags & AGENTX_NETWORK_BYTE_ORDER);

  /* errors are dropped silently, we must not send any agentx-Response-PDU */
  if (pkt_size != 0)
  {
    // TODO should we free even for malformed packets ??
    return MIN(size, pkt_size + AGENTX_HEADER_SIZE);
  }

  /* No agentx-Response-PDU is sent in response to agentx-CleanupSet-PDU */
  return pkt_size;
}

/**
 * parse_pkt - parse received AgentX packet
 * @p: SNMP protocol instance
 * @pkt: first byte of PDU inside RX-buffer
 * @size: number of bytes received from a socket
 * @skip: length of header that stays still in partial processing
 *
 * Return number of bytes parsed from RX-buffer.
 */
static uint
parse_pkt(struct snmp_proto *p, byte *pkt, uint size, uint *skip)
{
  if (size < AGENTX_HEADER_SIZE)
    return 0;

  struct agentx_header *h = (void *) pkt;
  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;
  uint pkt_size = LOAD_U32(h->payload, byte_ord);

  /* We need to see the responses for PDU such as
   * agentx-Open-PDU, agentx-Register-PDU, ...
   * even when we are outside the SNMP_CONNECTED state
   */
  if (h->type == AGENTX_RESPONSE_PDU)
    return parse_response(p, pkt, size);

  if (p->state != SNMP_CONN ||
      p->session_id != LOAD_U32(h->session_id, byte_ord))
  {
    struct agentx_header copy = {
      .session_id = p->session_id,
      .transaction_id = p->transaction_id,
      .packet_id = p->packet_id,
    };

    snmp_simple_response(p, AGENTX_RES_NOT_OPEN, 0);

    p->session_id = copy.session_id;
    p->transaction_id = copy.transaction_id;
    p->packet_id = copy.packet_id;

    // TODO: fix the parsed size for possibly malitious packets
    // this could be broken when sender sends the packet in two parts
    // -> size < pkt_size;
    // maliciously large pkt_size -> breaks the size >= pkt_size
    // maybe move this test down to parse_*() functions
    return MIN(size, pkt_size + AGENTX_HEADER_SIZE);
  }

  if (h->flags & AGENTX_NON_DEFAULT_CONTEXT)
  {
    // TODO: shouldn't we return a parseError or genError for
    // packets that mustn't have a non-default context ??
    snmp_simple_response(p, AGENTX_RES_UNSUPPORTED_CONTEXT, 0);
    // TODO: fix the parsed size (as above)
    return MIN(size, pkt_size + AGENTX_HEADER_SIZE);
  }

  refresh_ids(p, h);
  switch (h->type)
  {
    case AGENTX_GET_PDU:
    case AGENTX_GET_NEXT_PDU:
    case AGENTX_GET_BULK_PDU:
      return parse_gets2_pdu(p, pkt, size, skip);

    case AGENTX_CLOSE_PDU:
      return parse_close_pdu(p, pkt, size);

    case AGENTX_TEST_SET_PDU:
      return parse_test_set_pdu(p, pkt, size);

    case AGENTX_COMMIT_SET_PDU:
      return parse_commit_set_pdu(p, pkt, size);

    case AGENTX_UNDO_SET_PDU:
      return parse_undo_set_pdu(p, pkt, size);

    case AGENTX_CLEANUP_SET_PDU:
      return parse_cleanup_set_pdu(p, pkt, size);

    default:
      /* drop the packet with unknown type silently */
      return AGENTX_HEADER_SIZE;
  }
}


/*
 * parse_response - parse an agentx-Response-PDU
 * @p: SNMP protocol instance
 * @res: pointer of agentx-Response-PDU header in RX-buffer
 * @size: number of bytes received from a socket
 *
 * Return number of bytes parsed from RX-buffer.
 */
static uint
parse_response(struct snmp_proto *p, byte *res, uint size)
{
  if (size < sizeof(struct agentx_response))
    return 0;

  struct agentx_response *r = (void *) res;
  struct agentx_header *h = &r->h;

  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

  uint pkt_size = LOAD_U32(h->payload, byte_ord);
  if (size < pkt_size + AGENTX_HEADER_SIZE)
    return 0;

  switch (r->error)
  {
    case AGENTX_RES_NO_ERROR:
      do_response(p, res, size);
      break;

    case AGENTX_RES_NOT_OPEN:
      if (p->state == SNMP_LOCKED || p->state == SNMP_INIT)
	snmp_startup(p);
      else
	snmp_connected(p->sock);
      break;

    case AGENTX_RES_OPEN_FAILED:
      if (p->state == SNMP_LOCKED || p->state == SNMP_INIT)
      {
	ASSUME(p->startup_timer);
	p->startup_timer->hook = snmp_startup_timeout;
	// TODO: better timeout
	tm_set(p->startup_timer, current_time() + p->timeout S);
      }
      else
      {
	ASSUME(p->startup_timer);
	p->startup_timer->hook = snmp_reconnect;
	// TODO: better timeout
	tm_set(p->startup_timer, current_time() + p->timeout S);
      }
      break;

    /* Registration errors */
    case AGENTX_RES_DUPLICATE_REGISTER:
    case AGENTX_RES_REQUEST_DENIED:
      // TODO: more direct path to mib-specifiec code
      snmp_register_ack(p, r, size);
      break;

    /* We are trying to unregister a MIB, the unknownRegistration has same
     * effect as success */
    case AGENTX_RES_UNKNOWN_REGISTER:
    case AGENTX_RES_UNKNOWN_AGENT_CAPS:
    case AGENTX_RES_UNSUPPORTED_CONTEXT:
    case AGENTX_RES_PARSE_ERROR:
    case AGENTX_RES_PROCESSING_ERR:
    default:
      /* erronous packet should be dropped quietly */
      // TODO correct error?
      snmp_log("received response with error '%s'", snmp_errs[get_u16(&r->error)]);
      break;
  }

  return pkt_size + AGENTX_HEADER_SIZE;
}

/*
 * snmp_register_mibs - register all MIB subtrees
 * @p: SNMP protocol instance
 */
static void
snmp_register_mibs(struct snmp_proto *p)
{
  snmp_bgp_register(p);
  /* snmp_ospf_regsiter(p); ... */
}

/*
 * do_response - act on agentx-Response-PDU and protocol state
 * @p: SNMP protocol instance
 * @buf: RX-buffer with PDU bytes
 * @size: number of bytes received from a socket
 *
 * Return number of bytes parsed from RX-buffer.
 */
static void
do_response(struct snmp_proto *p, byte *buf, uint size)
{
  struct agentx_response *r = (void *) buf;
  struct agentx_header *h = &r->h;
  int byte_ord = h->flags & AGENTX_NETWORK_BYTE_ORDER;

  /* TODO make it asynchronous for better speed */
  switch (p->state)
  {
    case SNMP_INIT:
    case SNMP_LOCKED:
      /* silent drop of received packet */
      break;

    case SNMP_OPEN:
      /* copy session info from received packet */
      p->session_id = LOAD_U32(h->session_id, byte_ord);
      refresh_ids(p, h);

      /* the state needs to be changed before sending registering PDUs to
       * use correct do_response action on them
       */
      snmp_log("changing state to REGISTER");
      p->state = SNMP_REGISTER;
      snmp_register_mibs(p);
      break;

    case SNMP_REGISTER:;
      byte *pkt = buf;
      ADVANCE(pkt, size, AGENTX_HEADER_SIZE);

      const struct oid *oid = (void *) pkt;

      snmp_register_ack(p, r, snmp_get_mib_class(oid));

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

/*
 * snmp_get_mib_class - classify MIB tree belongings of OID
 * @oid: OID to be classified based on prefix
 */
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

/*
 * snmp_get_next - process single agentx-GetNext-PDU search range
 * @p: SNMP protocol instance
 * @o_start: SearchRange start OID
 * @o_end: SearchRange end OID
 * @c: transmit PDU context to use
 *
 * Return 0 if the created VarBind type is endOfMibView, 1 otherwise.
 */
static int
snmp_get_next2(struct snmp_proto *p, struct oid *o_start, struct oid *o_end,
	       struct snmp_pdu *c)
{
  enum snmp_search_res r;
  struct oid *o_copy = search_mib(p, o_start, o_end, NULL, c, &r);

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

/*
 * snmp_get_bulk - process one iteration of get bulk PDU
 * @p: SNMP protocol instance
 * @o_start: SearchRange start OID
 * @o_end: SearchRange end OID
 * @state: state of get bulk PDU processing
 * @c: transmit PDU context to use
 *
 * Return 0 if the created VarBind has type endOfMibView, 1 otherwise.
 */
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
  // it need to generate varbinds that will be only of type endOfMibView
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

/*
 * update_packet_size - set PDU size
 * @p - SNMP protocol instance
 * @start - pointer to PDU data start (excluding header size)
 * @end - pointer after the last PDU byte
 *
 * Return number of bytes in TX-buffer (including header size).
 */
static inline uint
update_packet_size(struct snmp_proto *p, const byte *start, byte *end)
{
  struct agentx_header *h = (void *) p->sock->tpos;
  size_t s = snmp_pkt_len(start, end);
  STORE_U32(h->payload, s);
  return AGENTX_HEADER_SIZE + s;
}

/*
 * response_err_ind - update response error and index
 * @res: response PDU header
 * @err: error status
 * @ind: index of error, ignored for noAgentXError
 *
 * Update agentx-Response-PDU header fields res.error and it's res.index.
 */
static inline void
response_err_ind(struct agentx_response *res, enum agentx_response_errs err, u16 ind)
{
  STORE_U32(res->error, (u16) err);
  if (err != AGENTX_RES_NO_ERROR && err != AGENTX_RES_PARSE_ERROR)
    STORE_U32(res->index, ind);
  else
    STORE_U32(res->index, 0);
}

/*
 * parse_gets_pdu - parse received gets PDUs
 * @p: SNMP protocol instance
 * @pkt_start: pointer to first byte of received PDU
 * @size: number of bytes received from a socket
 * @skip: length of header that stays still in partial processing
 *
 * Gets PDUs are agentx-Get-PDU, agentx-GetNext-PDU, agentx-GetBulk-PDU.
 *
 * Return number of bytes parsed from RX-buffer
 */
static uint
parse_gets2_pdu(struct snmp_proto *p, byte * const pkt_start, uint size, uint *skip)
{
  // TODO checks for c.size underflow
  uint ret = 0;
  struct oid *o_start = NULL, *o_end = NULL;
  byte *pkt = pkt_start;

  struct agentx_header *h = (void *) pkt;
  ADVANCE(pkt, size, AGENTX_HEADER_SIZE);
  uint pkt_size = LOAD_U32(h->payload, h->flags & AGENTX_NETWORK_BYTE_ORDER);

  sock *sk = p->sock;
  struct snmp_pdu c = SNMP_PDU_CONTEXT(sk);
  // TODO better handling of endianness
  c.byte_ord = 0; /* use little-endian */

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
      c.index = 0;
      ret = MIN(size, pkt_size + AGENTX_HEADER_SIZE);
      goto error;
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
    // TODO renew pkt, pkt_start pointers
  }

  struct agentx_response *response_header = prepare_response(p, &c);

  while (c.error == AGENTX_RES_NO_ERROR && size > 0 && pkt_size > 0)
  {
    if (size < snmp_oid_sizeof(0))
      goto partial;

    /* We load search range start OID */
    const struct oid *o_start_b = (void *) pkt;
    uint sz;
    if ((sz = snmp_oid_size(o_start_b)) > pkt_size)
    {
      c.error = AGENTX_RES_PARSE_ERROR;
      ret = MIN(size, pkt_size + AGENTX_HEADER_SIZE);
      goto error;
    }

    /*
     * If we already have written same relevant data to the TX buffer, then
     * we send processed part, otherwise we don't have anything to send and
     * need to wait for more data to be received.
     */
    if (sz > size && c.index > 0)
    {
      goto partial;  /* send already processed part */
    }
    else if (sz > size)
    {
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
      c.error = AGENTX_RES_PARSE_ERROR;
      ret = MIN(size, pkt_size + AGENTX_HEADER_SIZE);
      goto error;
    }

    if (sz > size && c.index > 0)
    {
      size += snmp_oid_size(o_start_b);
      goto partial;
    }
    else if (sz > size)
    {
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
      c.error = AGENTX_RES_GEN_ERROR;
      ret = MIN(size, pkt_size + AGENTX_HEADER_SIZE);
      goto error;
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
	if (c.index >= bulk_state.getbulk.non_repeaters)
	  bulk_state.repeaters++;

	// store the o_start, o_end

	/* The behavior of GetBulk pdu in the first iteration is
	 * identical to GetNext pdu. */
	has_any = snmp_get_next2(p, o_start, o_end, &c) | has_any;
	break;

      default:
	die("incorrect usage");
    }

    mb_free(o_start);
    o_start = NULL;
    mb_free(o_end);
    o_end = NULL;

    c.index++;
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

  /* send the constructed packet */
  struct agentx_response *res = (void *) sk->tbuf;
  /* We update the error, index pair on the beginning of the packet. */
  response_err_ind(res, c.error, c.index + 1);
  uint s = update_packet_size(p, (byte *) response_header, c.buffer);

  /* We send the message in TX-buffer. */
  sk_send(sk, s);
  // TODO think through the error state

  /* number of bytes parsed from RX-buffer */
  ret = pkt - pkt_start;
  goto free;

partial:
  /* need to tweak RX buffer packet size */
  (c.byte_ord) ? put_u32(&h->payload, pkt_size) : (h->payload = pkt_size);
  *skip = AGENTX_HEADER_SIZE;

  /* number of bytes parsed from RX-buffer */
  ret = pkt - pkt_start;
  goto free;

wait:
  p->packet_id--; /* we did not use the packetID */
  ret = 0;
  goto free;

error:
  if (c.index > UINT16_MAX)
    snmp_simple_response(p, AGENTX_RES_GEN_ERROR, UINT16_MAX);
  else
    snmp_simple_response(p, c.error, c.index);

free:
  mb_free(o_start);
  mb_free(o_end);
  return ret;
}

/*
 * snmp_start_subagent - send session open request
 * @p: SNMP protocol instance
 *
 * Send agentx-Open-PDU with configured OID and string description.
 */
void
snmp_start_subagent(struct snmp_proto *p)
{
  /* blank oid means unsupported */
  struct oid *blank = snmp_oid_blank(p);
  open_pdu(p, blank);

  p->state = SNMP_OPEN;

  mb_free(blank);
}

/*
 * snmp_stop_subagent - close established session
 * @p: SNMP protocol instance
 *
 * Send agentx-Close-PDU on established session.
 */
void
snmp_stop_subagent(struct snmp_proto *p)
{
  if (p->state == SNMP_OPEN ||
      p->state == SNMP_REGISTER ||
      p->state == SNMP_CONN)
    close_pdu(p, AGENTX_CLOSE_SHUTDOWN);
}

/*
 * snmp_rx - handle received PDUs in RX-buffer in normal operation
 * @sk: communication socket
 * @size: number of bytes received
 */
int
snmp_rx(sock *sk, uint size)
{
  struct snmp_proto *p = sk->data;
  byte *pkt_start = sk->rbuf;
  byte *end = pkt_start + size;

  /*
   * In some cases we want to save the header for future parsing, skip is number
   * of bytes that should not be overriden by memmove()
   */
  uint skip = 0;

  while (end >= pkt_start + AGENTX_HEADER_SIZE && skip == 0)
  {
    uint parsed_len = parse_pkt(p, pkt_start, size, &skip);

    if (parsed_len == 0)
      break;

    pkt_start += parsed_len;
    size -= parsed_len;
  }

  /* Incomplete packets */
  if (skip != 0 || pkt_start != end)
  {
    memmove(sk->rbuf + skip, pkt_start, size);
    sk->rpos = sk->rbuf + size + skip;
    return 0;
  }

  return 1;
}

/*
 * snmp_tx - handle empty TX-buffer during session reset
 * @sk: communication socket
 *
 * The socket tx_hook is called when the TX-buffer is empty, i.e. all data was
 * send. This function is used only when we found malformed PDU and we are
 * resetting the established session. If called we direcly reset the session.
 */
static void
snmp_tx(sock *sk)
{
  struct snmp_proto *p = sk->data;
  snmp_sock_disconnect(p, 1);
}

/*
 * snmp_ping - send an agentx-Ping-PDU
 * @p: SNMP protocol instance
 */
void
snmp_ping(struct snmp_proto *p)
{
  sock *sk = p->sock;
  struct snmp_pdu c = SNMP_PDU_CONTEXT(sk);

  if (c.size < AGENTX_HEADER_SIZE)
    snmp_manage_tbuf(p, &c);

  struct agentx_header *h = (struct agentx_header *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);
  SNMP_BLANK_HEADER(h, AGENTX_PING_PDU);
  p->packet_id++;
  SNMP_SESSION(h, p);
  c.byte_ord = AGENTX_NETWORK_BYTE_ORDER;

  /* sending only header -> pkt - buf */
  uint s = update_packet_size(p, sk->tpos, c.buffer);

  sk_send(sk, s);
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
int
snmp_search_check_end_oid(const struct oid *found, const struct oid *bound)
{
  if (snmp_is_oid_empty(bound))
    return 1;

  return (snmp_oid_compare(found, bound) < 0);
}

/*
 * search_mib - search for successor of given OID
 * @p: SNMP protocol instance
 * @o_start: search starting OID
 * @o_end: search ending OID
 * @o_curr: current OID inside @o_start, @o_end interval
 * @c: transmit PDU context to use
 * @result: search result state
 *
 * Perform a search in MIB tree in SearchRange from @o_start to @o_end.
 * If the @o_start has set include the search is inclusive, the @o_end has
 * always the include flag cleared. For agentx-GetNext-PDU, the o_curr is always
 * NULL, for agentx-GetBulk-PDU it could have non-NULL value. In such case the
 * @o_curr effectively replaces the role of @o_start. It is mandatory to pass
 * @o_start and @o_end only allocated from @p protocol's memory pool.
 *
 * Return found OID or NULL.
 */
/* tree is tree with "internet" prefix .1.3.6.1
   working only with o_start, o_end allocated in heap (not from buffer)*/
static struct oid *
search_mib(struct snmp_proto *p, const struct oid *o_start, const struct oid *o_end,
	   struct oid *o_curr, struct snmp_pdu UNUSED *c,
	   enum snmp_search_res *result)
{
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
  }

  enum snmp_search_res r;
  switch (o_curr->ids[1])
  {
    case SNMP_BGP4_MIB:
      r = snmp_bgp_search2(p, &o_curr, o_end, 0);

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
    /* cast drops const qualifier */
    mb_free((struct oid *)blank);

  return o_curr;
}

/**
 * snmp_prefixize - return prefixed OID copy if possible
 * @proto: allocation pool holder
 * @oid: from packet loaded object identifier
 * @byte_ord: byte order of @oid
 *
 * Return prefixed (meaning with nonzero prefix field) oid copy of @oid if
 * possible, NULL otherwise. Returned pointer is always allocated from @proto's
 * pool not a pointer to RX-buffer (from which is most likely @oid).
 */
struct oid *
snmp_prefixize(struct snmp_proto *proto, const struct oid *oid, int byte_ord)
{
  ASSERT(oid != NULL);

  if (snmp_is_oid_empty(oid))
  {
    /* allocate new zeroed oid */
    return snmp_oid_blank(proto);
  }

  /* already in prefixed form */
  else if (oid->prefix != 0) {
    struct oid *new = snmp_oid_duplicate(proto->pool, oid);
    return new;
  }

  if (oid->n_subid < 5)
    return NULL;

  for (int i = 0; i < 4; i++)
    if (LOAD_U32(oid->ids[i], byte_ord) != snmp_internet[i])
      return NULL;

  /* validity check here */
  if (oid->ids[4] >= 256)
    return NULL;

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

/*
 * snmp_mib_fill - append a AgentX VarBind to PDU
 * @p: SNMP protocol instance
 * @oid: OID to use as VarBind v.name
 * @c: transmit PDU context to use
 *
 * Append new AgentX VarBind at the end of created PDU. The content (v.data)
 * is handled in function specialized for given MIB subtree. The binding is
 * created only if the v.name matches some variable name precisely.
 */
static void
snmp_mib_fill2(struct snmp_proto *p, struct oid *oid, struct snmp_pdu *c)
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

/*
 * snmp_manage_tbuf - handle situation with too short transmit buffer
 * @p: SNMP protocol instance
 * @c: transmit packet context to use
 *
 * Important note: After managing insufficient buffer size all in buffer pointers
 *  are invalidated!
 */
void
snmp_manage_tbuf(struct snmp_proto UNUSED *p, struct snmp_pdu *c)
{
  sock *sk = p->sock;

  sk_set_tbsize(sk, sk->tbsize + 2048);
  c->size += 2048;
}

/*
 * prepare_response - fill buffer with AgentX PDU header
 * @p: SNMP protocol instance
 * @c: transmit PDU context to use
 *
 * Prepare known parts of AgentX packet header into the TX-buffer held by @c.
 */
static struct agentx_response *
prepare_response(struct snmp_proto *p, struct snmp_pdu *c)
{
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
