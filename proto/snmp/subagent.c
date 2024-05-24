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
#include "mib_tree.h"
#include "snmp_utils.h"
#include "bgp4_mib.h"

/* =============================================================
 *  Problems
 *  ------------------------------------------------------------
 *
 *    change of remote ip -> no notification, no update (be careful in recofing)
 *    same ip, different ports
 *    distinct VRF (two interfaces with overlapping private addrs)
 *    posible link-local addresses in LOCAL_IP
 *
 *    context is allocated as copied, is it approach really needed? wouldn't it
 *	sufficient just use the context in rx-buffer?
 *
 */

/**
 *
 *
 *
 *
 * Handling of malformed packet:
 *
 * When we find an error in PDU data, we create and send a response with error
 * defined by the RFC. We await until the packet is send and then we close the
 * communication socket. This implicitly closes the established session. We
 * chose this approach because we cannot easily mark the boundary between packets.
 * When we are reseting the connection, we change the snmp_state to SNMP_RESET.
 * In SNMP_RESET state we skip all received bytes and wait for snmp_tx_skip()
 * to be called. The socket's tx_hook is called when the TX-buffer is empty,
 * meaning our response (agentx-Response-PDU) was send.
 *
 *
 * Partial parsing:
 *
 * It may happen that we received only staring part of some PDU from the
 * communication socket. In most cases, if we recognize this situation we
 * immediately return, waiting for rest of the PDU to arrive. But for packets
 * like agentx-Get-PDU, agentx-GetNext-PDU and agentx-GetBulk-PDU it could be
 * costly as they could hold many VarBinds. We don't want to process these
 * packet twice because it is a lot work. We parse all VarBinds until we hit the
 * first incomplete one. The logic behind this is to release as much as
 * possible space from receive buffer. When we hit the first incomplete VarBind,
 * we store information about the parsing state and move the header inside the
 * receive buffer.
 *
 * Transmit packet context
 *
 */

//static void snmp_mib_fill(struct snmp_proto *p, struct oid *oid, struct snmp_pdu *c);
static void snmp_mib_fill(struct snmp_proto *p, struct agentx_varbind **vb, struct snmp_pdu *c);
static uint parse_response(struct snmp_proto *p, byte *buf);
static void do_response(struct snmp_proto *p, byte *buf);
static uint parse_gets_pdu(struct snmp_proto *p, byte *pkt);
static struct agentx_response *prepare_response(struct snmp_proto *p, struct snmp_pdu *c);
static void response_err_ind(struct snmp_proto *p, struct agentx_response *res, enum agentx_response_errs err, u16 ind);
static uint update_packet_size(struct agentx_header *start, byte *end);
//static struct oid *search_mib2(struct snmp_proto *p, const struct oid *o_start, const struct oid *o_end, struct oid *o_curr, struct snmp_pdu *c, enum snmp_search_res *result);

static enum snmp_search_res search_mib(struct snmp_proto *p, struct agentx_varbind **vb_search, const struct oid *o_end, struct snmp_pdu *c);

const u32 snmp_internet[] = { SNMP_ISO, SNMP_ORG, SNMP_DOD, SNMP_INTERNET };

static inline int
snmp_is_active(struct snmp_proto *p)
{
  /* Note: states in which we have opened socket */
  return p->state == SNMP_OPEN || p->state == SNMP_REGISTER ||
      p->state == SNMP_CONN;
}

/*
 * snmp_header - store packet information into buffer
 * @h: pointer to created packet header in TX-buffer
 * @type: created PDU type
 * @flags: set flags
 *
 * Payload length is set to zero legth. Padding is also zeroed. Real stored
 * flags are dependent on compile-time message byte-order configuration.
 */
static inline void
snmp_header(struct agentx_header *h, enum agentx_pdu_types type, u8 flags)
{
  STORE_U8(h->version, AGENTX_VERSION);
  STORE_U8(h->type, type);
  STORE_U8(h->flags, flags | SNMP_ORDER);
  STORE_U8(h->reserved, 0);
  STORE_U32(h->payload, 0);
}

/*
 * snmp_blank_header - create header with no flags except default
 * @h: pointer to created header in TX-buffer
 * @type: create PDU type
 *
 * Only flag possibly set may be packet byte order configuration.
 */
static inline void
snmp_blank_header(struct agentx_header *h, enum agentx_pdu_types type)
{
  snmp_header(h, type, (u8) 0);
}

/*
 * snmp_register_ack - handle registration response
 * @p: SNMP protocol instance
 * @res: header of agentx-Response-PDU
 * @class: MIB subtree associated with agentx-Register-PDU
 */
void
snmp_register_ack(struct snmp_proto *p, struct agentx_response *res, u8 class)
{
  struct snmp_registration *reg;
  WALK_LIST(reg, p->registration_queue)
  {
    if (snmp_registration_match(reg, &res->h, class))
    {
      rem_node(&reg->n);
      p->registrations_to_ack--;

      if (res->error == AGENTX_RES_NO_ERROR)
	reg->reg_hook_ok(p, (const struct agentx_response *) res, reg);
      else
	reg->reg_hook_fail(p, (const struct agentx_response *) res, reg);

      mb_free(reg->oid);
      mb_free(reg);
      return;
    }
  }
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
  snmp_reset(p);
  //snmp_set_state(p, SNMP_RESET);
}

/*
 * snmp_simple_response - send an agentx-Response-PDU with no data payload
 * @p: SNMP protocol instance
 * @error: response PDU error fields value
 * @index: response PDU error index field value
 *
 * This function assumes that the buffer has enough space to fill in the AgentX
 * Response PDU. So it is the responsibility of the caller to provide that.
 */
static void
snmp_simple_response(struct snmp_proto *p, enum agentx_response_errs error, u16 index)
{
  sock *sk = p->sock;
  struct snmp_pdu c;
  snmp_pdu_context(&c, sk);

  ASSUME(c.size >= sizeof(struct agentx_response));

  struct agentx_response *res = prepare_response(p, &c);
  response_err_ind(p, res, error, index);
  sk_send(sk, sizeof(struct agentx_response));
}

/*
 * open_pdu - send an agentx-Open-PDU
 * @p: SNMP protocol instance
 * @oid: PDU OID description field value
 *
 * Other fields are filled based on @p configuration (timeout, subagent string
 * description)
 */
static void
open_pdu(struct snmp_proto *p, struct oid *oid)
{
  const struct snmp_config *cf = SKIP_BACK(struct snmp_config, cf, p->p.cf);
  sock *sk = p->sock;

  struct snmp_pdu c;
  snmp_pdu_context(&c, sk);

#define TIMEOUT_SIZE sizeof(u32) /* 1B timeout, 3B zero padding */

  /* Make sure that we have enough space in TX-buffer */
  if (c.size < AGENTX_HEADER_SIZE + TIMEOUT_SIZE + snmp_oid_size(oid) +
      + snmp_str_size(cf->description))
    snmp_manage_tbuf(p, &c);

  struct agentx_header *h = (void *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);
  snmp_blank_header(h, AGENTX_OPEN_PDU);

  STORE_U32(h->session_id, 1);
  STORE_U32(h->transaction_id, 1);
  STORE_U32(h->packet_id, 1);

  c.size -= (4 + snmp_oid_size(oid) + snmp_str_size(cf->description));

  if (p->timeout >= 1 S && p->timeout <= 255 S)
    /* use p->timeout ceiled up to whole second */
    c.buffer = snmp_put_fbyte(c.buffer,
      (p->timeout % (1 S) == 0) ? p->timeout TO_S : p->timeout TO_S + 1);
  /* out of range fallbacks */
  else if (p->timeout < 1 TO_US)
    c.buffer = snmp_put_fbyte(c.buffer, (u8) 1);
  else /* p->timeout > 255 TO_US */
    c.buffer = snmp_put_fbyte(c.buffer, (u8) 255);

  c.buffer = snmp_put_oid(c.buffer, oid);
  c.buffer = snmp_put_str(c.buffer, cf->description);

  uint s = update_packet_size(h, c.buffer);
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

  struct snmp_pdu c;
  snmp_pdu_context(&c, sk);

// TODO use more readable anonymous structure decl.
#define UPTIME_SIZE \
  (6 * sizeof(u32)) /* sizeof( { u32 vb_type, u32 oid_hdr, u32 ids[4] } ) */
#define TRAP0_HEADER_SIZE \
  (7 * sizeof(u32)) /* sizeof( { u32 vb_type, u32 oid_hdr, u32 ids[6] } ) */

  uint sz = AGENTX_HEADER_SIZE + TRAP0_HEADER_SIZE + snmp_oid_size(oid) \
    + size;

  if (include_uptime)
    sz += UPTIME_SIZE;

  /* Make sure that we have enough space in TX-buffer */
  if (c.size < sz)
    snmp_manage_tbuf(p, &c);

  struct agentx_header *h = (void *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);
  snmp_blank_header(h, AGENTX_NOTIFY_PDU);
  p->packet_id++;   /* New packet id */
  snmp_session(p, h);

  if (include_uptime)
  {
    /* sysUpTime.0 oid */
    struct oid uptime_oid = {
      .n_subid = 4,
      .prefix = SNMP_MGMT,
      .include = 0,
      .reserved = 0,
    };
    /* {mgmt}.mib-2.system.sysUpTime.sysUpTimeInstance (0) */
    u32 uptime_ids[] = { 1, 1, 3, 0 };

    struct agentx_varbind *vb = snmp_create_varbind(c.buffer, &uptime_oid);
    for (uint i = 0; i < uptime_oid.n_subid; i++)
      STORE_U32(vb->name.ids[i], uptime_ids[i]);

    /* TODO use time from last reconfiguration instead? [config->load_time] */
    btime uptime = current_time() - boot_time;
    snmp_varbind_ticks(&c, (uptime TO_S) / 100);
    ASSUME(snmp_test_varbind(vb));
    ADVANCE(c.buffer, c.size, snmp_varbind_size_unsafe(vb));
  }

  /* snmpTrapOID.0 oid */
  struct oid trap0 = {
    .n_subid = 6,
    .prefix = 6, /* snmpV2 */
    .include = 0,
    .reserved = 0,
  };
  /* {snmpV2}.snmpModules.snmpAlarmNextIndex.snmpMIBObjects.snmpTrap.snmpTrapIOD.0 */
  u32 trap0_ids[] = { 3, 1, 1, 4, 1, 0 };

  struct agentx_varbind *trap_vb = snmp_create_varbind(c.buffer, &trap0);
  for (uint i = 0; i < trap0.n_subid; i++)
    STORE_U32(trap_vb->name.ids[i], trap0_ids[i]);
  trap_vb->type = AGENTX_OBJECT_ID;
  snmp_put_oid(snmp_varbind_data(trap_vb), oid);
  ADVANCE(c.buffer, c.size, snmp_varbind_size_unsafe(trap_vb));

  memcpy(c.buffer, data, size);
  ADVANCE(c.buffer, c.size, size);

  uint s = update_packet_size(h, c.buffer);
  sk_send(sk, s);

#undef TRAP0_HEADER_SIZE
#undef UPTIME_SIZE
}

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
un_register_pdu(struct snmp_proto *p, struct oid *oid, u32 bound, uint index, enum agentx_pdu_types type, u8 is_instance, uint UNUSED contid)
{
  /* used for agentx-Register-PDU and agentx-Unregister-PDU */
  const struct snmp_config *cf = SKIP_BACK(struct snmp_config, cf, p->p.cf);
  sock *sk = p->sock;
  struct snmp_pdu c;
  snmp_pdu_context(&c, sk);

#define BOUND_SIZE sizeof(u32)
  /* conditional +4 for upper-bound (optinal field) */
  uint sz = AGENTX_HEADER_SIZE + snmp_oid_size(oid) +
      ((bound > 1) ? BOUND_SIZE : 0);

  if (c.size < sz)
    snmp_manage_tbuf(p, &c);

  struct agentx_header *h = (void *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);

  snmp_header(h, type, is_instance ? AGENTX_FLAG_INSTANCE_REGISTRATION : 0);
  p->packet_id++;
  snmp_session(p, h);

  struct agentx_un_register_hdr *ur = (struct agentx_un_register_hdr *) c.buffer;

  /* 0 = do not override session message timeout */
  STORE_U8(ur->timeout, 0);
  /* use selected priority */
  STORE_U8(ur->priority, cf->priority);
  STORE_U8(ur->range_subid, (bound > 1) ? index : 0);
  STORE_U8(ur->reserved, 0);
  ADVANCE(c.buffer, c.size, sizeof(struct agentx_un_register_hdr));

  snmp_put_oid(c.buffer, oid);
  ADVANCE(c.buffer, c.size, snmp_oid_size(oid));

  /* place upper-bound if needed */
  if (bound > 1)
  {
    STORE_PTR(c.buffer, bound);
    ADVANCE(c.buffer, c.size, BOUND_SIZE);
  }

  uint s = update_packet_size(h, c.buffer);

  sk_send(sk, s);
#undef BOUND_SIZE
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
snmp_register(struct snmp_proto *p, struct oid *oid, u32 bound, uint index, u8 is_instance, uint contid)
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
snmp_unregister(struct snmp_proto *p, struct oid *oid, u32 bound, uint index, uint contid)
{
  un_register_pdu(p, oid, bound, index, AGENTX_UNREGISTER_PDU, 0, contid);
}

/*
 * close_pdu - send an agentx-Close-PDU
 * @p: SNMP protocol instance
 * @reason: reason for closure
 */
static void UNUSED
close_pdu(struct snmp_proto *p, enum agentx_close_reasons reason)
{
  sock *sk = p->sock;
  struct snmp_pdu c;
  snmp_pdu_context(&c, sk);

#define REASON_SIZE sizeof(u32)
  if (c.size < AGENTX_HEADER_SIZE + REASON_SIZE)
    snmp_manage_tbuf(p, &c);

  struct agentx_header *h = (void *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);
  snmp_blank_header(h, AGENTX_CLOSE_PDU);
  p->packet_id++;
  snmp_session(p, h);

  snmp_put_fbyte(c.buffer, (u8) reason);
  ADVANCE(c.buffer, c.size, 4);

  uint s = update_packet_size(h, c.buffer);
  sk_send(sk, s);
#undef REASON_SIZE
}

/*
 * parse_close_pdu - parse an agentx-Close-PDU
 * @p: SNMP protocol instance
 * @pkt_start: pointer to first byte of PDU
 *
 * Return number of bytes parsed from RX-buffer.
 */
static uint
parse_close_pdu(struct snmp_proto *p, byte * const pkt_start)
{
  TRACE(D_PACKETS, "SNMP received agentx-Close-PDU");
  byte *pkt = pkt_start;

  struct agentx_close_pdu *pdu = (void *) pkt;
  pkt += sizeof(struct agentx_close_pdu);
  uint pkt_size = pdu->h.payload;

  if (pkt_size != sizeof(struct agentx_close_pdu))
  {
    TRACE(D_PACKETS, "SNMP malformed agentx-Close-PDU, closing anyway");
    snmp_simple_response(p, AGENTX_RES_GEN_ERROR, 0);
    snmp_set_state(p, SNMP_RESET);
    return MIN(pkt_size + AGENTX_HEADER_SIZE, sizeof(struct agentx_close_pdu));
  }

  if (!snmp_test_close_reason(pdu->reason))
  {
    TRACE(D_PACKETS, "SNMP invalid close reason %u", pdu->reason);
    snmp_simple_response(p, AGENTX_RES_GEN_ERROR, 0);
    snmp_set_state(p, SNMP_RESET);
    return pkt_size + AGENTX_HEADER_SIZE;
  }

  enum agentx_close_reasons reason = (enum agentx_close_reasons) pdu->reason;
  TRACE(D_PACKETS, "SNMP close reason %u", reason);
  snmp_simple_response(p, AGENTX_RES_NO_ERROR, 0);
  snmp_set_state(p, SNMP_RESET);
  return pkt_size + AGENTX_HEADER_SIZE;
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
  snmp_simple_response(p, AGENTX_RES_NOT_WRITABLE, 1);
  return pkt_size + AGENTX_HEADER_SIZE;
#if 0
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

/*
 * refresh_ids - Copy current ids from packet to protocol
 * @p: SNMP protocol instance
 * @h: PDU header with new transaction_id and packet_id ids.
 */
static inline void
refresh_ids(struct snmp_proto *p, struct agentx_header *h)
{
  p->transaction_id = LOAD_U32(h->transaction_id);
  p->packet_id = LOAD_U32(h->packet_id);
}

/*
 * parse_test_set_pdu - parse an agentx-TestSet-PDU in buffer
 * @p: SNMP protocol instance
 * @pkt_start: first byte of test set PDU
 * @size: number of bytes received from a socket
 *
 * Return number of bytes parsed from RX-buffer.
 */
static inline uint
parse_test_set_pdu(struct snmp_proto *p, byte * const pkt_start)
{
  TRACE(D_PACKETS, "SNMP received agentx-TestSet-PDU");
  byte *pkt = pkt_start;  /* pointer to agentx-TestSet-PDU in RX-buffer */
  uint s; /* final packat size */
  struct agentx_response *res; /* pointer to reponse in TX-buffer */

  struct agentx_header *h = (void *) pkt;
  pkt += AGENTX_HEADER_SIZE;
  //uint pkt_size = LOAD_U32(h->payload);

  sock *sk = p->sock;
  struct snmp_pdu c;
  snmp_pdu_context(&c, sk);

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
    sz = snmp_varbind_size(vb, size);

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
    ADVANCE(pkt, size, snmp_varbind_size(vb, size));

    // TODO remove the mb_alloc() in prefixize()
    struct oid *work = snmp_prefixize(p, &vb->name);
    (void)work;
    all_possible = snmp_testset(p, vb, tr, work, pkt_size);
    mb_free(work);
  }
  mb_free(tr);
#endif
  s = update_packet_size(h, c.buffer);

  if (c.error != AGENTX_RES_NO_ERROR)
  {
    response_err_ind(p, res, c.error, c.index + 1);
    snmp_error(p);
  }
  else if (all_possible)
  {
    response_err_ind(p, res, AGENTX_RES_NO_ERROR, 0);
  }
  else
  {
    TRACE(D_PACKETS, "SNMP SET action failed (not writable)");
    /* This is a recoverable error, we do not need to reset the connection */
    response_err_ind(p, res, AGENTX_RES_NOT_WRITABLE, c.index + 1);
  }

  sk_send(sk, s);
  return pkt - pkt_start;
}

/*
 * parse_sets_pdu - common functionality for commit set and undo set PDUs
 * @p: SNMP protocol instance
 * @pkt_start: pointer to first byte of on of set related PDU
 * @error: error status to use
 *
 * Return number of bytes parsed from RX-buffer.
 */
static uint
parse_sets_pdu(struct snmp_proto *p, byte * const pkt_start, enum agentx_response_errs err)
{
  byte *pkt = pkt_start;
  struct agentx_header *h = (void *) pkt;
  pkt += AGENTX_HEADER_SIZE;
  uint pkt_size = LOAD_U32(h->payload);

  if (pkt_size != 0)
  {
    TRACE(D_PACKETS, "SNMP received malformed set PDU (size)");
    snmp_simple_response(p, AGENTX_RES_PARSE_ERROR, 0);
    // TODO best solution for possibly malicious pkt_size
    return AGENTX_HEADER_SIZE;
    // use varbind_list_size()??
  }

  struct snmp_pdu c;
  snmp_pdu_context(&c, p->sock);
  if (c.size < sizeof(struct agentx_response))
    snmp_manage_tbuf(p, &c);

  struct agentx_response *r = prepare_response(p, &c);

  // TODO free resource allocated by parse_test_set_pdu()
  // TODO do something meaningful
  //mb_free(tr);
  c.error = err;

  TRACE(D_PACKETS, "SNMP received set PDU with error %u", c.error);
  response_err_ind(p, r, c.error, 0);
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
 *
 * Return number of bytes parsed from RX-buffer.
 */
static inline uint
parse_commit_set_pdu(struct snmp_proto *p, byte *pkt)
{
  // don't forget to free resoures allocated by parse_test_set_pdu()
  //mb_free(tr);
  TRACE(D_PACKETS, "SNMP received agentx-CommitSet-PDU");
  return parse_sets_pdu(p, pkt, AGENTX_RES_COMMIT_FAILED);
}

/*
 * parse_undo_set_pdu - parse an agentx-UndoSet-PDU
 * @p: SNMP protocol instance
 * @pkt: pointer to first byte of PDU inside RX-buffer
 *
 * Return number of bytes parsed from buffer.
 */
static inline uint
parse_undo_set_pdu(struct snmp_proto *p, byte *pkt)
{
  // don't forget to free resources allocated by parse_test_set_pdu()
  //mb_free(tr);
  TRACE(D_PACKETS, "SNMP received agentx-UndoSet-PDU");
  return parse_sets_pdu(p, pkt, AGENTX_RES_UNDO_FAILED);
}

/*
 * parse_cleanup_set_pdu - parse an agentx-CleanupSet-PDU
 * @p: SNMP protocol instance
 * @pkt_start: pointer to first byte of PDU inside RX-buffer
 *
 * Return number of bytes parsed from RX-buffer.
 */
static uint
parse_cleanup_set_pdu(struct snmp_proto *p, byte * const pkt_start)
{
  TRACE(D_PACKETS, "SNMP received agentx-CleanupSet-PDU");
  (void)p;
  // TODO don't forget to free resources allocated by parse_test_set_pdu()
  //mb_free(p->tr);

  byte *pkt = pkt_start;
  struct agentx_header *h = (void *) pkt;
  uint pkt_size = LOAD_U32(h->payload);

  /* errors are dropped silently, we must not send any agentx-Response-PDU */
  if (pkt_size != 0)
  {
    // TODO should we free even for malformed packets ??
    // TODO -> check that data is not freed
    return AGENTX_HEADER_SIZE;
  }

  /* No agentx-Response-PDU is sent in response to agentx-CleanupSet-PDU */
  return pkt_size;
}

/*
 * space_for_response - check if TX-buffer has space for agentx-Response-PDU
 * @sk: communication socket owned by SNMP protocol instance
 *
 * In some cases we send only the AgentX header but if we want to signal an
 * error, we need at least space for agentx-Response-PDU. This simplifies the
 * PDU space requirements testing.
 */
static inline int
space_for_response(const sock *sk)
{
  return (
    (uint) (sk->tbuf + sk->tbsize - sk->tpos) >= sizeof(struct agentx_response)
  );
}

/**
 * parse_pkt - parse received AgentX packet
 * @p: SNMP protocol instance
 * @pkt: first byte of PDU inside RX-buffer
 * @size: number of bytes received from a socket
 *
 * Return number of bytes parsed from RX-buffer.
 */
static uint
parse_pkt(struct snmp_proto *p, byte *pkt, uint size)
{
  /* TX-buffer free space */
  ASSERT(snmp_is_active(p));
  if (!space_for_response(p->sock))
    return 0;

  ASSERT(snmp_is_active(p));
  if (size < AGENTX_HEADER_SIZE)
    return 0;

  struct agentx_header *h = (void *) pkt;
  uint pkt_size = LOAD_U32(h->payload);

  /* RX side checks - too big packet */
  if (pkt_size > SNMP_PKT_SIZE_MAX)
  {
    snmp_simple_response(p, AGENTX_RES_GEN_ERROR, 0);
    snmp_reset(p);
    return 0; // TODO return size??
  }

  /* This guarantees that we have the full packet already received */
  if (size < pkt_size + AGENTX_HEADER_SIZE)
    return 0; /* no bytes parsed */

  /* We need to see the responses for PDU such as
   * agentx-Open-PDU, agentx-Register-PDU, ...
   * even when we are outside the SNMP_CONNECTED state
   */
  if (h->type == AGENTX_RESPONSE_PDU)
    return parse_response(p, pkt);

  ASSERT(snmp_is_active(p));
  if (p->state != SNMP_CONN ||
      p->session_id != LOAD_U32(h->session_id))
  {
    struct agentx_header copy = {
      .session_id = p->session_id,
      .transaction_id = p->transaction_id,
      .packet_id = p->packet_id,
    };

    TRACE(D_PACKETS, "SNMP received PDU with unknown session id");
    snmp_simple_response(p, AGENTX_RES_NOT_OPEN, 0);

    p->session_id = copy.session_id;
    p->transaction_id = copy.transaction_id;
    p->packet_id = copy.packet_id;
    log(L_INFO "restoring packet_id %u from temporal state", p->packet_id);

    /*
     * After unexpected state, we simply reset the session
     * only sending the agentx-Response-PDU.
     */
    snmp_reset(p);
    return 0; // return size??
  }

  ASSERT(snmp_is_active(p));
  if (h->flags & AGENTX_NON_DEFAULT_CONTEXT)
  {
    // TODO add non-default context support
    TRACE(D_PACKETS, "SNMP received PDU with unexpected byte order");
    snmp_simple_response(p, AGENTX_RES_UNSUPPORTED_CONTEXT, 0);
    /* We always accept the packet length as correct, up to set limit */
    // TODO limit
    return pkt_size + AGENTX_HEADER_SIZE;
  }

  refresh_ids(p, h);
  switch (h->type)
  {
    case AGENTX_GET_PDU:
    case AGENTX_GET_NEXT_PDU:
    case AGENTX_GET_BULK_PDU:
      return parse_gets_pdu(p, pkt);

    case AGENTX_CLOSE_PDU:
      return parse_close_pdu(p, pkt);

    case AGENTX_TEST_SET_PDU:
      return parse_test_set_pdu(p, pkt);

    case AGENTX_COMMIT_SET_PDU:
      return parse_commit_set_pdu(p, pkt);

    case AGENTX_UNDO_SET_PDU:
      return parse_undo_set_pdu(p, pkt);

    case AGENTX_CLEANUP_SET_PDU:
      return parse_cleanup_set_pdu(p, pkt);

    default:
      /* We reset the connection for malformed packet (Unknown packet type) */
      TRACE(D_PACKETS, "SNMP received unknown packet with type %u", h->type);
      snmp_set_state(p, SNMP_RESET);
      return 0;
  }
}


/*
 * parse_response - parse an agentx-Response-PDU
 * @p: SNMP protocol instance
 * @res: pointer of agentx-Response-PDU header in RX-buffer
 *
 * Return number of bytes parsed from RX-buffer.
 */
static uint
parse_response(struct snmp_proto *p, byte *res)
{
  struct agentx_response *r = (void *) res;
  struct agentx_header *h = (void *) r;

  // todo reject not compiled byte order
  uint pkt_size = LOAD_U32(h->payload);

  switch (r->error)
  {
    case AGENTX_RES_NO_ERROR:
      TRACE(D_PACKETS, "SNMP received agetnx-Response-PDU");
      do_response(p, res);
      break;

    /* Registration errors */
    case AGENTX_RES_DUPLICATE_REGISTER:
    case AGENTX_RES_REQUEST_DENIED:
    case AGENTX_RES_UNKNOWN_REGISTER:
      // TODO more direct path to mib-specific code
      TRACE(D_PACKETS, "SNMP received agentx-Response-PDU with error %u", r->error);
      byte *pkt = res + sizeof(struct agentx_response);
      struct oid *failed = (void *) pkt;
      snmp_register_ack(p, r, snmp_get_mib_class(failed));
      break;

    /*
     * We found ourselves in an unexpected situation. To enter a well defined
     * state as well as give the AgentX master agent room to fix the errors on
     * his side, we perform a hard reset of the connections.
     */
    case AGENTX_RES_NOT_OPEN:
    case AGENTX_RES_OPEN_FAILED:
    case AGENTX_RES_UNKNOWN_AGENT_CAPS:
    case AGENTX_RES_UNSUPPORTED_CONTEXT:  /* currently we don't use contexts */
    case AGENTX_RES_PARSE_ERROR:
    case AGENTX_RES_PROCESSING_ERR:
    default:
      DBG("SNMP agentx-Response-PDU with unexpected error %u", r->error);
      snmp_set_state(p, SNMP_DOWN);
      break;
  }

  return pkt_size + AGENTX_HEADER_SIZE;
}

/*
 * snmp_register_mibs - register all MIB subtrees
 * @p: SNMP protocol instance
 */
void
snmp_register_mibs(struct snmp_proto *p)
{
  snmp_bgp4_register(p);
}

/*
 * do_response - act on agentx-Response-PDU and protocol state
 * @p: SNMP protocol instance
 * @pkt: RX-buffer with PDU bytes
 *
 * Return number of bytes parsed from RX-buffer.
 */
static void
do_response(struct snmp_proto *p, byte *pkt)
{
  struct agentx_response *r = (void *) pkt;
  struct agentx_header *h = (void *) r;

  /* TODO make it asynchronous for better speed */
  switch (p->state)
  {
    case SNMP_INIT:
    case SNMP_LOCKED:
      /* silent drop of received packet */
      break;

    case SNMP_OPEN:
      /* copy session info from received packet */
      p->session_id = LOAD_U32(h->session_id);
      refresh_ids(p, h);

      tm_start(p->ping_timer, 0);

      /* the state needs to be changed before sending registering PDUs to
       * use correct do_response action on them
       */
      snmp_set_state(p, SNMP_REGISTER);
      break;

    case SNMP_REGISTER:;
      pkt += AGENTX_HEADER_SIZE;

      const struct oid *oid = (void *) pkt;

      snmp_register_ack(p, r, snmp_get_mib_class(oid));

      if (p->registrations_to_ack == 0)
	snmp_set_state(p, SNMP_CONN);
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
// TODO remove me
static int UNUSED
snmp_get_next2(struct snmp_proto *p, struct agentx_varbind **vb_search, struct oid *o_end, struct snmp_pdu *c)
{
  enum snmp_search_res r;

  //struct oid *o_copy = search_mib(p, o_start, o_end, NULL, c, &r);
  r = search_mib(p, vb_search, o_end, c);
  struct oid *o_start = &(*vb_search)->name;

  switch (r)
  {
    case SNMP_SEARCH_NO_OBJECT:
    case SNMP_SEARCH_NO_INSTANCE:
    case SNMP_SEARCH_END_OF_VIEW:;
      snmp_set_varbind_type(*vb_search, AGENTX_END_OF_MIB_VIEW);
      return 0;

    case SNMP_SEARCH_OK:
    default:
      break;
  }

  // TODO TODO different API
  snmp_mib_fill(p, vb_search, c);

  /* override the error for GetNext-PDU object not find */
  switch ((*vb_search)->type)
  {
    case AGENTX_NO_SUCH_OBJECT:
    case AGENTX_NO_SUCH_INSTANCE:
    case AGENTX_END_OF_MIB_VIEW:
      (*vb_search)->type = AGENTX_END_OF_MIB_VIEW;
      return 0;

    default:
      return 1;
  }

  o_start = &(*vb_search)->name;
  if (c->size < snmp_varbind_hdr_size_from_oid(o_start))
    snmp_manage_tbuf(p, c);

  snmp_set_varbind_type(*vb_search, AGENTX_END_OF_MIB_VIEW);
  return 0;
}

#if 0
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
snmp_get_next3(struct snmp_proto *p, struct oid *o_start, struct oid *o_end,
	       struct snmp_pdu *c)
{
  enum snmp_search_res r;
  struct oid *o_copy = search_mib2(p, o_start, o_end, NULL, c, &r);

  struct agentx_varbind *vb = NULL;
  switch (r)
  {
    case SNMP_SEARCH_NO_OBJECT:
    case SNMP_SEARCH_NO_INSTANCE:
    case SNMP_SEARCH_END_OF_VIEW:;
      uint sz = snmp_varbind_hdr_size_from_oid(o_start);

      if (c->size < sz && c->size >= sizeof(struct agentx_varbind))
      {
	struct agentx_varbind *vb_null = snmp_create_varbind_null(c->buffer);
	ADVANCE(c->buffer, c->size, snmp_varbind_size_unsafe(vb_null));
	c->error = AGENTX_RES_GEN_ERROR;
	return 0;
      }
      else if (c->size < sz)
      {
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
    snmp_mib_fill(p, o_copy, c);

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
    snmp_manage_tbuf(p, c);

  vb = snmp_create_varbind(c->buffer, o_start);
  vb->type = AGENTX_END_OF_MIB_VIEW;
  ADVANCE(c->buffer, c->size, snmp_varbind_header_size(vb));
  return 0;
}
#endif

#if 0
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
    /* the varbind will be recreated inside the snmp_mib_fill() */
    snmp_mib_fill(p, o_curr, c);
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
#endif

#if 0
static int
snmp_get_bulk2(struct snmp_proto *p, struct agentx_varbind **vb_search, const struct oid *o_end, struct agentx_bulk_state *state, struct snmp_pdu *c)
{
  //struct oid *o_curr = NULL;
  //struct oid *o_predecessor = NULL;
  enum snmp_search_res r;

  uint i = 0;
  r = search_mib(p, vb_search, o_end, c);
  while (r != SNMP_SEARCH_END_OF_VIEW && i < state->repetition)
  {
    snmp_mib_fill(p, vb_search, c);

    snmp_varbind_duplicate_hdr(p, vb_search, c);
    // renew all pointers here
    r = search_mib(p, vb_search, o_end, c);
  }

  return r == SNMP_SEARCH_END_OF_VIEW;
  do
  {
    r = search_mib(p, vb_search, o_end, c);
    snmp_mib_fill(p, vb_search, ;
    o_predecessor = o_curr;
    o_curr = search_mib(p, o_start, o_end, o_curr, c, &r);
    i++;
  } while (r != SNMP_SEARCH_END_OF_VIEW && i < state->repetition);

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
    /* the varbind will be recreated inside the snmp_mib_fill() */
    snmp_mib_fill(p, o_curr, c);
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
#endif

static inline struct oid *
snmp_oid_prefixize_unsafe(struct oid *dest, const struct oid *src)
{
  u8 subids = LOAD_U8(src->n_subid) - 5;
  dest->n_subid = subids;
  STORE_U8(dest->prefix, (u8) LOAD_U32(src->ids[ARRAY_SIZE(snmp_internet)]));
  STORE_U8(dest->include, (LOAD_U8(src->include)) ? 1 : 0);
  STORE_U8(dest->reserved, 0);

  /* The LOAD_U32() and STORE_U32() cancel out */
  memcpy(&dest->ids[0], &src->ids[5], subids * sizeof(u32));

  return dest;
}

#if 0
/*
 * snmp_oid_prefixize - convert oid to prefixed form
 * @p: SNMP protocol instance
 * @oid: object identifier to convert
 * @c: PDU context
 *
 * The function assumes that the supplied @oid is prefixable. The resulting OID
 * is allocated from PDU buffer inside @c.
 */
struct oid *
snmp_oid_prefixize(struct snmp_proto *p, const struct oid *oid, struct snmp_pdu *c)
{
  /* It may be beneficial to move to snmp_utils.c */
  uint subids = LOAD_U8(oid->n_subid) - 5;
  uint oid_size = snmp_oid_size(oid);

  if (c->size < oid_size)
    snmp_manage_tbuf(p, c);

  // TODO check if the @oid is prefixable
  ASSERT(c->size >= oid_size);
  struct oid *result = c->buffer;
  ADVANCE(c->buffer, c->size, oid_size);
  return snmp_oid_prefixize_unsafe(result, oid);
}
#endif

/*
 * snmp_vb_to_tx - create varbind from RX buffer OID
 * @p: SNMP protocol instance
 * @oid: object identifier located in RX buffer
 * @c: PDU context
 *
 * Create NULL initialized VarBind inside TX buffer (from @c) whose vb->name is
 * @oid. The @oid is not prefixed and is prefixable, the @oid is prefixed first.
 * The protocol @p is used in cases of TX buffer space shortage.
 */
struct agentx_varbind *
snmp_vb_to_tx(struct snmp_proto *p, const struct oid *oid, struct snmp_pdu *c)
{
  uint vb_hdr_size = snmp_varbind_hdr_size_from_oid(oid);
  if (c->size < vb_hdr_size)
    snmp_manage_tbuf(p, c);

  ASSERT(c->size >= vb_hdr_size);
  struct agentx_varbind *vb = (void *) c->buffer;
  ADVANCE(c->buffer, c->size, sizeof(struct agentx_varbind) - sizeof(struct oid));
  /* Move the c->buffer so that is points at &vb->name */
  snmp_set_varbind_type(vb, AGENTX_NULL);

  if (snmp_oid_is_prefixable(oid) && !snmp_oid_is_prefixed(oid))
  {
    u8 subids = LOAD_U8(oid->n_subid) - 5;
    ADVANCE(c->buffer, c->size, snmp_oid_size_from_len(subids));
    (void) snmp_oid_prefixize_unsafe(&vb->name, oid);
    return vb;
  }

  ADVANCE(c->buffer, c->size, snmp_oid_size(oid));
  snmp_oid_copy2(&vb->name, oid);
  return vb;
}

/*
 * snmp_oid_to_scratch - allocate temporal Object Identifier in prefixed form
 * @oid: prefixed Object Identifier if possible
 */
static struct oid *
snmp_oid_to_scratch(const struct oid *oid)
{
  struct oid *dest;
  if (snmp_oid_is_prefixable(oid) && !snmp_oid_is_prefixed(oid))
  {
    u8 subids = LOAD_U8(oid->n_subid) - 5;
    uint prefixed_size = sizeof(struct oid) + (subids * sizeof(u32));
    dest = tmp_alloc(prefixed_size);
    snmp_oid_prefixize_unsafe(dest, oid);

    return dest;
  }

  uint oid_size = snmp_oid_size(oid);
  dest = tmp_alloc(oid_size);
  snmp_oid_copy2(dest, oid);

  return dest;
}

/*
 * update_packet_size - set PDU size
 * @start - pointer to PDU data start (excluding header size)
 * @end - pointer after the last PDU byte
 *
 * Return number of bytes in TX-buffer (including header size).
 */
static inline uint
update_packet_size(struct agentx_header *start, byte *end)
{
  uint s = snmp_pkt_len((byte *) start, end);
  STORE_U32(start->payload, s);
  return AGENTX_HEADER_SIZE + s;
}

/*
 * response_err_ind - update response error and index
 * @p: SNMP protocol instance
 * @res: response PDU header
 * @err: error status
 * @ind: index of error, ignored for noAgentXError
 *
 * Update agentx-Response-PDU header fields res.error and it's res.index. If the
 * error is not noError, also set the corrent response PDU payload size.
 */
static inline void
response_err_ind(struct snmp_proto *p, struct agentx_response *res, enum agentx_response_errs err, u16 ind)
{
  STORE_U32(res->error, (u16) err);
  // TODO deal with auto-incrementing of snmp_pdu context c.ind
  if (err != AGENTX_RES_NO_ERROR && err != AGENTX_RES_GEN_ERROR)
  {
    TRACE(D_PACKETS, "Last PDU resulted in error %u", err);
    STORE_U32(res->index, ind);
    TRACE(D_PACKETS, "Storing packet size %u (was %u)", sizeof(struct agentx_response) - AGENTX_HEADER_SIZE, LOAD_U32(res->h.payload));
    STORE_U32(res->h.payload,
      sizeof(struct agentx_response) - AGENTX_HEADER_SIZE);
  }
  else if (err == AGENTX_RES_GEN_ERROR)
  {
    TRACE(D_PACKETS, "Last PDU resulted in error %u", err);
    STORE_U32(res->index, 0);
    TRACE(D_PACKETS, "Storing packet size %u (was %u)", sizeof(struct agentx_response) - AGENTX_HEADER_SIZE, LOAD_U32(res->h.payload));
    STORE_U32(res->h.payload,
      sizeof(struct agentx_response) - AGENTX_HEADER_SIZE);
  }
  else
    STORE_U32(res->index, 0);
}

static inline uint
parse_gets_error(struct snmp_proto *p, struct snmp_pdu *c, uint len)
{
  TRACE(D_PACKETS, "SNMP error %u while parsing gets PDU", c->error);
  if (c->index > UINT16_MAX)
    snmp_simple_response(p, AGENTX_RES_GEN_ERROR, UINT16_MAX);
  else
    snmp_simple_response(p, AGENTX_RES_GEN_ERROR, c->index);

  return len + AGENTX_HEADER_SIZE;
}

static enum snmp_search_res
snmp_mib_fill2(struct snmp_proto *p, struct snmp_pdu *c, mib_node_u *mib_node)
{
  if (!mib_node || !mib_node_is_leaf(mib_node))
  {
    snmp_set_varbind_type(c->sr_vb_start, AGENTX_NO_SUCH_OBJECT);
    ADVANCE(c->buffer, c->size, snmp_varbind_header_size(c->sr_vb_start));
    return AGENTX_NO_SUCH_OBJECT;
  }

  struct mib_leaf *leaf = &mib_node->leaf;

  return leaf->filler(p, c);
}

void
snmp_get_pdu(struct snmp_proto *p, struct snmp_pdu *c, struct mib_walk_state *walk)
{
  mib_node_u *node;
  node = mib_tree_find(p->mib_tree, walk, &c->sr_vb_start->name);

  (void) snmp_mib_fill2(p, c, node);
}

int
snmp_get_next_pdu(struct snmp_proto *p, struct snmp_pdu *c, struct mib_walk_state *walk)
{
  mib_node_u *node;
  node = mib_tree_find(p->mib_tree, walk, &c->sr_vb_start->name);

  int inclusive = c->sr_vb_start->name.include;

  int move_next;
  if (!node && inclusive)
    move_next = 1;
  else if (!node && !inclusive)
    move_next = 1;
  else if (node && inclusive && mib_node_is_leaf(node))
    move_next = 0;
  else if (node && inclusive)
    move_next = 1;
  else if (node && !inclusive)
    move_next = 0;

  struct mib_leaf *leaf = &node->leaf;
  if (move_next && node && mib_node_is_leaf(node))
    move_next = leaf->call_next(p, c, walk);

  if (move_next)
    node = (mib_node_u *) mib_tree_walk_next_leaf(p->mib_tree, walk);

  enum snmp_search_res res;
  res = snmp_mib_fill2(p, c, node);

  if (res != SNMP_SEARCH_OK)
    snmp_set_varbind_type(c->sr_vb_start, AGENTX_END_OF_MIB_VIEW);

  return res == SNMP_SEARCH_OK;
}

void
snmp_get_bulk_pdu(struct snmp_proto *p, struct snmp_pdu *c, struct mib_walk_state *walk, struct agentx_bulk_state *bulk)
{
  if (c->index >= bulk->getbulk.non_repeaters)
    bulk->repeaters++;

  // store the o_start and o_end

  bulk->has_any |= snmp_get_next_pdu(p, c, walk);
}

/*
 * parse_gets_pdu - parse received gets PDUs
 * @p: SNMP protocol instance
 * @pkt_start: pointer to first byte of received PDU
 *
 * Gets PDUs are agentx-Get-PDU, agentx-GetNext-PDU, agentx-GetBulk-PDU.
 *
 * Return number of bytes parsed from RX-buffer
 */
static uint
parse_gets_pdu(struct snmp_proto *p, byte * const pkt_start)
{
  // TODO checks for c.size underflow
  struct mib_walk_state walk;
  byte *pkt = pkt_start;

  struct agentx_header *h = (void *) pkt;
  pkt += AGENTX_HEADER_SIZE;
  uint pkt_size = LOAD_U32(h->payload);

  sock *sk = p->sock;
  struct snmp_pdu c;
  snmp_pdu_context(&c, sk);

  /*
   * Get-Bulk processing stops if all the varbind have type END_OF_MIB_VIEW
   * has_any is true if some varbind has type other than END_OF_MIB_VIEW
   */
  struct agentx_bulk_state bulk_state = { };
  if (h->type == AGENTX_GET_BULK_PDU)
  {
    if (pkt_size < sizeof(struct agentx_getbulk))
    {
      c.error = AGENTX_RES_PARSE_ERROR;
      c.index = 0;
      return parse_gets_error(p, &c, pkt_size);
    }

    struct agentx_getbulk *bulk_info = (void *) pkt;
    ADVANCE(pkt, pkt_size, sizeof(struct agentx_getbulk));

    //TODO: bulk_state = AGENTX_BULK_STATE_INITIALIZER(bulk_info);
    bulk_state = (struct agentx_bulk_state) {
      .getbulk = {
	.non_repeaters = LOAD_U32(bulk_info->non_repeaters),
	.max_repetitions = LOAD_U32(bulk_info->max_repetitions),
      },
      /* In contrast to the RFC, we use 0-based indices. */
      .index = 0,
      .repetition = 0,
      .has_any = 0,
    };
  }

  struct agentx_response *response_header = prepare_response(p, &c);

  lp_state tmps;
  lp_save(tmp_linpool, &tmps);
  while (c.error == AGENTX_RES_NO_ERROR && pkt_size > 0)
  {
    lp_restore(tmp_linpool, &tmps);

    /* We load search range start OID */
    const struct oid *o_start_rx = (void *) pkt;
    uint sz;
    if ((sz = snmp_oid_size(o_start_rx)) > pkt_size)
    {
      c.error = AGENTX_RES_PARSE_ERROR;
      return parse_gets_error(p, &c, pkt_size);
    }

    /* Update buffer pointer and remaining size counters. */
    ADVANCE(pkt, pkt_size, sz);

    /*
     * We load search range end OID
     * The exactly same process of sanity checking is preformed while loading
     * the SearchRange's end OID
     */
    const struct oid *o_end_rx = (void *) pkt;
    if ((sz = snmp_oid_size(o_end_rx)) > pkt_size)
    {
      c.error = AGENTX_RES_PARSE_ERROR;
      return parse_gets_error(p, &c, pkt_size);
    }

    ADVANCE(pkt, pkt_size, sz);

    /* We don't too to check for oversided OID because the PDU has 8k size limit */

    /* We create copy of OIDs outside of rx-buffer and also prefixize them */
    c.sr_vb_start = snmp_vb_to_tx(p, o_start_rx, &c);
    c.sr_o_end = snmp_oid_to_scratch(o_end_rx);

    ASSERT(c.sr_vb_start); // TODO implement failed parsing logic
    ASSERT(c.sr_o_end);

    if (!snmp_is_oid_empty(c.sr_o_end) &&
	snmp_oid_compare(&c.sr_vb_start->name, c.sr_o_end) > 0)
    {
      c.error = AGENTX_RES_GEN_ERROR;
      return parse_gets_error(p, &c, pkt_size);
    }

    switch (h->type)
    {
      case AGENTX_GET_PDU:
	snmp_get_pdu(p, &c, &walk);
	//snmp_mib_fill(p, &vb_start, &c);
	break;

      case AGENTX_GET_NEXT_PDU:
	snmp_get_next_pdu(p, &c, &walk);
	//snmp_get_next2(p, &vb_start, o_end, &c);
	break;

      case AGENTX_GET_BULK_PDU:
	snmp_get_bulk_pdu(p, &c, &walk, &bulk_state);
	#if 0
	if (c.index >= bulk_state.getbulk.non_repeaters)
	  bulk_state.repeaters++;

	// store the o_start, o_end

	/* The behavior of GetBulk pdu in the first iteration is
	 * identical to GetNext pdu. */
	has_any = snmp_get_next2(p, &vb_start, o_end, &c) || has_any;
	#endif
	break;

      default:
	die("incorrect usage");
    }

    c.sr_vb_start = NULL;
    c.sr_o_end = NULL;

    c.index++;
  } /* while (c.error == AGENTX_RES_NO_ERROR && size > 0) */

  lp_restore(tmp_linpool, &tmps);

  if (h->type == AGENTX_GET_BULK_PDU)
  {
  #if 0
    // TODO
    for (bulk_state.repetition++;
	 has_any && bulk_state.repetition < bulk_state.getbulk.max_repetitions;
	 bulk_state.repetition++)
    {
      vb_start = snmp_vb_copy_to_tx(p, vb_start, &c);
      has_any = 0;
      for (bulk_state.index = 0; bulk_state.index < bulk_state.repeaters;
	   bulk_state.repeaters++)
	has_any = snmp_get_bulk2(p, &vb_start, end, &bulk_state, &c) || has_any;
    }
  #endif
  }

  /* We update the error, index pair on the beginning of the packet. */
  response_err_ind(p, response_header, c.error, c.index + 1);
  uint s = update_packet_size(&response_header->h, c.buffer);

  /* We send the message in TX-buffer. */
  sk_send(sk, s);

  // TODO think through the error state

  /* number of bytes parsed from RX-buffer */
  return pkt - pkt_start;
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
  ASSUME(p->state == SNMP_OPEN);

  /* blank oid means unsupported */
  struct oid *blank = snmp_oid_blank(p);
  open_pdu(p, blank);

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
  tm_stop(p->ping_timer);
  /* This cause problems with net-snmp daemon witch halts afterwards */
  //close_pdu(p, AGENTX_CLOSE_SHUTDOWN);
}

/*
 * snmp_rx - handle received PDUs in RX-buffer in normal operation
 * @sk: communication socket
 * @size: number of bytes received
 */
int
snmp_rx(sock *sk, uint size)
{
  log(L_INFO "snmp_rx with size %u", size);
  struct snmp_proto *p = sk->data;
  byte *pkt_start = sk->rbuf;
  byte *end = pkt_start + size;

  while (snmp_is_active(p) && end >= pkt_start + AGENTX_HEADER_SIZE)
  {
    uint parsed_len = parse_pkt(p, pkt_start, size);

    if (parsed_len == 0)
      break;

    pkt_start += parsed_len;
    size -= parsed_len;
  }

  /* We flush the RX-buffer on errors */
  if (!snmp_is_active(p) || pkt_start == end)
    return 1; /* The whole RX-buffer was consumed */

  /* Incomplete packet parsing */
  memmove(sk->rbuf, pkt_start, size);
  sk->rpos = sk->rbuf + size;
  return 0;
}

/*
 * snmp_tx - handle TX-buffer
 * @sk: communication socket owned by SNMP protocol instance
 *
 * The snmp_tx hook is used only to delay the processing in cases we don't have
 * enough space in TX-buffer. Therefore we simply call the snmp_rx hook.
 */
void
snmp_tx(sock *sk)
{
  log(L_INFO "snmp_tx()");
  /* We still not have enough space */
  if (!space_for_response(sk))
    return;

  /* There is nothing to process, no bytes in RX-buffer */
  if (sk_tx_buffer_empty(sk))
    return;

  snmp_rx(sk, sk->tpos - sk->tbuf);
}


/*
 * snmp_ping - send an agentx-Ping-PDU
 * @p: SNMP protocol instance
 */
void
snmp_ping(struct snmp_proto *p)
{
  if (!snmp_is_active(p))
    return;

  sock *sk = p->sock;
  struct snmp_pdu c;
  snmp_pdu_context(&c, sk);

  if (c.size < AGENTX_HEADER_SIZE)
    return;

  int unused = sk->tbuf + sk->tbsize - c.buffer;
  if (unused < AGENTX_HEADER_SIZE)
    return;

  //struct agentx_header *h = (void *) sk->tpos;
  struct agentx_header *h = (void *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);
  snmp_blank_header(h, AGENTX_PING_PDU);
  p->packet_id++;
  log(L_INFO "incrementing packet_id to %u (ping)", p->packet_id);
  snmp_session(p, h);

  /* sending only header */
  uint s = update_packet_size(h, (byte *) h + AGENTX_HEADER_SIZE);

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
static enum snmp_search_res
search_mib(struct snmp_proto *p, struct agentx_varbind **vb_search, const struct oid *o_end, struct snmp_pdu *c)
{
  ASSUME(vb_search != NULL);
  struct oid *o_start = &(*vb_search)->name;
  ASSUME(o_start != NULL);

  (void)p;
  (void)o_end;
  (void)c;
  // TODO TODO
#if 0
  enum snmp_search_res r;
  switch (o_curr->ids[1])
  {
    case SNMP_BGP4_MIB:
      r = snmp_bgp_search(p, &o_curr, o_end, 0);

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
#endif
  return SNMP_SEARCH_NO_OBJECT;
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
#if 0
static struct oid *
search_mib2(struct snmp_proto *p, const struct oid *o_start, const struct oid *o_end,
	   struct oid *o_curr, struct snmp_pdu UNUSED *c,
	   enum snmp_search_res *result)
{
  // TODO flip retval and result (maybe on more place to stay consistent)
  // TODO remove unnecessary o_start/o_curr duplication
  ASSUME(o_start != NULL);

  if (o_curr && (o_curr->n_subid < 2 || o_curr->ids[0] != 1))
    return NULL;
  if (!o_curr && (o_start->n_subid < 2 || o_start->ids[0] != 1))
    return NULL;

  if (!o_curr)
  {
    o_curr = snmp_oid_duplicate(p->pool, o_start);
    // XXX is it right time to free o_start right now (here) ?
	// not for use in snmp_get_next2() the o_start comes and ends in _gets_()
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
      r = snmp_bgp_search(p, &o_curr, o_end, 0);

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
#endif



#if 0
/**
 * snmp_prefixize - return prefixed OID copy if possible
 * @proto: allocation pool holder
 * @oid: from packet loaded object identifier
 *
 * Return prefixed (meaning with nonzero prefix field) oid copy of @oid if
 * possible, NULL otherwise. Returned pointer is always allocated from @proto's
 * pool not a pointer to RX-buffer (from which is most likely @oid).
 */
struct oid *
snmp_prefixize(struct snmp_proto *proto, const struct oid *oid)
{
  ASSUME(oid != NULL);

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
    if (LOAD_U32(oid->ids[i]) != snmp_internet[i])
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
#endif

/*
 * snmp_mib_fill - append a AgentX VarBind to PDU
 * @p: SNMP protocol instance
 * @vb: indirect pointer to destination varbind
 * @c: transmit PDU context to use
 *
 * Append new AgentX VarBind at the end of created PDU. The content (v.data)
 * is handled in function specialized for given MIB subtree. The binding is
 * created only if the v.name matches some variable name precisely.
 */
static void
snmp_mib_fill(struct snmp_proto *p, struct agentx_varbind **vb, struct snmp_pdu *c)
{
  (void) p;
  ASSUME(vb != NULL && *vb != NULL);

  struct oid *oid = &((*vb)->name);

  if (oid->n_subid < 2 || (oid->prefix != SNMP_MGMT && oid->ids[0] != SNMP_MIB_2))
  {
    snmp_set_varbind_type(*vb, AGENTX_NO_SUCH_OBJECT);
    ADVANCE(c->buffer, c->size, snmp_varbind_header_size(*vb));
    return;
  }

  u8 mib_class = snmp_get_mib_class(oid);
  switch (mib_class)
  {
    case SNMP_CLASS_BGP:
      //snmp_bgp_fill(p, vb, c);
      break;

    case SNMP_CLASS_INVALID:
    case SNMP_CLASS_END:
    default:
      break;
      (*vb)->type = AGENTX_NO_SUCH_OBJECT;
      ADVANCE(c->buffer, c->size, snmp_varbind_header_size(*vb));
  }
}

/*
 * snmp_manage_tbuf - TODO
 */
void
snmp_manage_tbuf(struct snmp_proto *p, struct snmp_pdu *c)
{
  sock *sk = p->sock;
  int diff;
  if (c->sr_vb_start != NULL)
    diff = (void *) c->sr_vb_start - (void *) sk->tbuf;

  log(L_INFO "snmp_manage_tbuf2()");
  sk_set_tbsize(sk, sk->tbsize + 2048);
  c->size += 2048;

  if (c->sr_vb_start != NULL)
    c->sr_vb_start = (struct agentx_varbind *) (sk->tbuf + diff);
}

/*
 * snmp_manage_tbuf2 - handle situation with too short transmit buffer
 * @p: SNMP protocol instance
 * @c: transmit packet context to use
 *
 * Important note: After managing insufficient buffer size all in buffer pointers
 *  are invalidated!
 */
void
snmp_manage_tbuf2(struct snmp_proto *p, void **ptr, struct snmp_pdu *c)
{
  sock *sk = p->sock;
  int diff;
  if (ptr)
    diff = *ptr - (void *) sk->tbuf;

  log(L_INFO "snmp_manage_tbuf()");
  sk_set_tbsize(sk, sk->tbsize + 2048);
  c->size += 2048;

  if (ptr)
    *ptr = sk->tbuf + diff;
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

  snmp_blank_header(h, AGENTX_RESPONSE_PDU);
  snmp_session(p, h);

  /* protocol doesn't care about subagent upTime */
  STORE_U32(r->uptime, 0);
  STORE_U16(r->error, AGENTX_RES_NO_ERROR);
  STORE_U16(r->index, 0);

  ADVANCE(c->buffer, c->size, sizeof(struct agentx_response));
  return r;
}
