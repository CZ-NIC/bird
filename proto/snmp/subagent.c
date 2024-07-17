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

static uint parse_response(struct snmp_proto *p, byte *buf);
static void do_response(struct snmp_proto *p, byte *buf);
static uint parse_gets_pdu(struct snmp_proto *p, byte *pkt);
static struct agentx_response *prepare_response(struct snmp_proto *p, struct snmp_pdu *c);
static void response_err_ind(struct snmp_proto *p, struct agentx_response *res, enum agentx_response_errs err, u16 ind);
static uint update_packet_size(struct agentx_header *start, byte *end);

/* standard SNMP internet prefix (1.3.6.1) */
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
  snmp_pdu_context(&c, p, sk);

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
  snmp_pdu_context(&c, p, sk);

#define TIMEOUT_SIZE sizeof(u32) /* 1B timeout, 3B zero padding */

  /* Make sure that we have enough space in TX-buffer */
  if (c.size < AGENTX_HEADER_SIZE + TIMEOUT_SIZE + snmp_oid_size(oid) +
      + snmp_str_size(cf->description))
  {
    snmp_log("agentx-Open-PDU small buffer");
    snmp_manage_tbuf(p, &c);
  }

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
  snmp_pdu_context(&c, p, sk);

#define UPTIME_SIZE \
  sizeof( struct { u32 vb_type; u32 oid_hdr; u32 ids[4]; } )
#define TRAP0_HEADER_SIZE \
  sizeof( struct { u32 vb_type; u32 oid_hdr; u32 ids[6]; } )

  uint sz = AGENTX_HEADER_SIZE + TRAP0_HEADER_SIZE + snmp_oid_size(oid) \
    + size;

  if (include_uptime)
    sz += UPTIME_SIZE;

  /* Make sure that we have enough space in TX-buffer */
  if (c.size < sz)
  {
    snmp_log("agentx-Notify-PDU small buffer");
    snmp_manage_tbuf(p, &c);
  }

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
  snmp_pdu_context(&c, p, sk);

#define BOUND_SIZE sizeof(u32)
  /* conditional +4 for upper-bound (optinal field) */
  uint sz = AGENTX_HEADER_SIZE + snmp_oid_size(oid) +
      ((bound > 1) ? BOUND_SIZE : 0);

  if (c.size < sz)
  {
    snmp_log("agentx-Register-PDU small buffer");
    snmp_manage_tbuf(p, &c);
  }

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
void 
snmp_unregister(struct snmp_proto *p, struct oid *oid, u32 bound, uint index, uint contid)
{
  un_register_pdu(p, oid, bound, index, AGENTX_UNREGISTER_PDU, 0, contid);
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
  struct snmp_pdu c;
  snmp_pdu_context(&c, p, sk);

#define REASON_SIZE sizeof(u32)
  if (c.size < AGENTX_HEADER_SIZE + REASON_SIZE)
  {
    snmp_log("agentx-Close-PDU small buffer");
    snmp_manage_tbuf(p, &c);
  }

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

  sock *sk = p->sock;
  struct snmp_pdu c;
  snmp_pdu_context(&c, p, sk);

  if (c.size < AGENTX_HEADER_SIZE)
  {
    snmp_log("agentx-TestSet-PDU small buffer");
    snmp_manage_tbuf(p, &c);
  }

  res = prepare_response(p, &c);

  /* 0 if there is piece, that we cannot set */
  int all_possible = 0;
  /* the all_possible is currently hard-coded with no support for writing to mib
   * variables, when implementing the mentioned support, change the initializer
   * to 1
   */
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
  }

  struct snmp_pdu c;
  snmp_pdu_context(&c, p, p->sock);
  if (c.size < sizeof(struct agentx_response))
  {
    snmp_log("parse_sets_pdu small buffer");
    snmp_manage_tbuf(p, &c);
  }

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
  if (size < AGENTX_HEADER_SIZE)
    return 0;

  struct agentx_header *h = (void *) pkt;
  if (h->flags & AGENTX_NETWORK_BYTE_ORDER)
  {
    TRACE(D_PACKETS, "SNMP received PDU with unexpected byte order");
    snmp_reset(p);
    return 0;
  }

  uint pkt_size = LOAD_U32(h->payload);

  /* RX side checks - too big packet */
  if (pkt_size > SNMP_PKT_SIZE_MAX)
  {
    snmp_simple_response(p, AGENTX_RES_GEN_ERROR, 0);
    snmp_reset(p);
    return 0; /* no bytes parsed */
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
    snmp_log("restoring packet_id %u from temporal state", p->packet_id);

    /*
     * After unexpected state, we simply reset the session
     * only sending the agentx-Response-PDU.
     */
    snmp_reset(p);
    return 0;
  }

  if (h->flags & AGENTX_NON_DEFAULT_CONTEXT)
  {
    TRACE(D_PACKETS, "SNMP received PDU with non-default context");
    snmp_simple_response(p, AGENTX_RES_UNSUPPORTED_CONTEXT, 0);
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

/*
 * snmp_vb_to_tx - create varbind from RX buffer OID
 * @p: SNMP protocol instance
 * @oid: object identifier located in RX buffer
 * @c: PDU context
 *
 * Create NULL initialized VarBind inside TX buffer (from @c) whose vb->name is
 * @oid. The @oid prefixed if possible. The result is stored in @c->sr_vb_start.
 */
void
snmp_vb_to_tx(struct snmp_proto *p, const struct oid *oid, struct snmp_pdu *c)
{
  uint vb_hdr_size = snmp_varbind_hdr_size_from_oid(oid);
  if (c->size < vb_hdr_size)
  {
    snmp_log("SNMP vb_to_tx small buffer");
    snmp_manage_tbuf(p, c);
  }

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

    c->sr_vb_start = vb;
    return;
  }

  ADVANCE(c->buffer, c->size, snmp_oid_size(oid));
  snmp_oid_copy2(&vb->name, oid);

  c->sr_vb_start = vb;
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
  // FIXME for packets with errors reset reset payload size to null (by move c.buffer appropriately)
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
    TRACE(D_PACKETS, "Last PDU resulted in error %u genErr", err);
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

/*
 * AgentX GetPDU, GetNextPDU and GetBulkPDU
 */
void
snmp_get_pdu(struct snmp_proto *p, struct snmp_pdu *c, const struct oid *o_start, struct mib_walk_state *walk)
{
  snmp_log("snmp_get_pdu()");

  struct mib_leaf *leaf;
  leaf = snmp_walk_init(p->mib_tree, walk, o_start, c);

  snmp_log("found node %p", leaf);

  enum snmp_search_res res;
  res = snmp_walk_fill(leaf, walk, c);

  snmp_log("fill result %u", res);

  if (res != SNMP_SEARCH_OK)
    snmp_set_varbind_type(c->sr_vb_start, snmp_search_res_to_type(res));
}

int
snmp_get_next_pdu(struct snmp_proto *p, struct snmp_pdu *c, const struct oid *o_start, struct mib_walk_state *walk)
{
  (void) snmp_walk_init(p->mib_tree, walk, o_start, c);
  struct mib_leaf *leaf = snmp_walk_next(p->mib_tree, walk, c);

  enum snmp_search_res res;
  res = snmp_walk_fill(leaf, walk, c);

  if (res != SNMP_SEARCH_OK)
    snmp_set_varbind_type(c->sr_vb_start, AGENTX_END_OF_MIB_VIEW);

  return res == SNMP_SEARCH_OK;
}

void
snmp_get_bulk_pdu(struct snmp_proto *p, struct snmp_pdu *c, const struct oid *o_start, struct mib_walk_state *walk, struct agentx_bulk_state *bulk)
{
  if (c->index >= bulk->getbulk.non_repeaters)
    bulk->repeaters++;

  // store the o_start and o_end

  bulk->has_any |= snmp_get_next_pdu(p, c, o_start, walk);
}

static inline const struct oid *
snmp_load_oids(byte **pkt_ptr, uint *pkt_sz, struct snmp_pdu *c)
{
  byte *pkt = *pkt_ptr;
  uint pkt_size = *pkt_sz;

  uint sz;
  const struct oid *start = (const struct oid *) pkt;

  if ((sz = snmp_oid_size(start)) > pkt_size)
  {
    snmp_log("load_oids start %u / %u", sz, pkt_size);
    c->error = AGENTX_RES_PARSE_ERROR;
    *pkt_ptr = pkt;
    *pkt_sz = pkt_size;
    return NULL;
  }

  ADVANCE(pkt, pkt_size, sz);

  const struct oid *end = (const struct oid *) pkt;
  if ((sz = snmp_oid_size(end)) > pkt_size)
  {
    snmp_log("load_oids end %u / %u", sz, pkt_size);
    c->error = AGENTX_RES_PARSE_ERROR;
    *pkt_ptr = pkt;
    *pkt_sz = pkt_size;
    return NULL;
  }

  ADVANCE(pkt, pkt_size, sz);

  if (!snmp_is_oid_empty(end) &&
      snmp_oid_compare(start, end) > 0)
  {
    c->error = AGENTX_RES_GEN_ERROR;
    *pkt_ptr = pkt;
    *pkt_sz = pkt_size;
    return NULL;
  }

  ASSERT(start != NULL);
  ASSERT(end != NULL);

  c->sr_o_end = end;
  *pkt_ptr = pkt;
  *pkt_sz = pkt_size;
  return start;
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
  snmp_log("parse_gets_pdu msg");
  // TODO checks for c.size underflow
  struct mib_walk_state walk;
  byte *pkt = pkt_start;

  struct agentx_header *h = (void *) pkt;
  pkt += AGENTX_HEADER_SIZE;
  uint pkt_size = LOAD_U32(h->payload);

  sock *sk = p->sock;
  struct snmp_pdu c;
  snmp_pdu_context(&c, p, sk);

  /*
   * Get-Bulk processing stops if all the varbind have type END_OF_MIB_VIEW
   * has_any is true if some varbind has type other than END_OF_MIB_VIEW
   */
  struct agentx_bulk_state bulk_state = { 0 };
  if (h->type == AGENTX_GET_BULK_PDU)
  {
    if (pkt_size < sizeof(struct agentx_getbulk))
    {
      snmp_log("parse_gets GetBulkPDU prepare");
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

    const struct oid *start_rx;
    if (!(start_rx = snmp_load_oids(&pkt, &pkt_size, &c)))
    {
      snmp_log("snmp_load_oid ends with an error");
      return parse_gets_error(p, &c, pkt_size);
    }

    switch (h->type)
    {
      case AGENTX_GET_PDU:
	snmp_get_pdu(p, &c, start_rx, &walk);
	break;

      case AGENTX_GET_NEXT_PDU:
	snmp_get_next_pdu(p, &c, start_rx, &walk);
	break;

      case AGENTX_GET_BULK_PDU:
	snmp_get_bulk_pdu(p, &c, start_rx, &walk, &bulk_state);
	break;

      default:
	die("implementation failure");
    }

    c.sr_vb_start = NULL;
    c.sr_o_end = NULL;

    c.index++;
  } /* while (c.error == AGENTX_RES_NO_ERROR && size > 0) */

  lp_restore(tmp_linpool, &tmps);

  if (h->type == AGENTX_GET_BULK_PDU)
  {
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
  snmp_log("snmp_rx with size %u", size);
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
  snmp_log("snmp_tx()");
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
  snmp_pdu_context(&c, p, sk);

  if (c.size < AGENTX_HEADER_SIZE)
    return;

  int unused = sk->tbuf + sk->tbsize - c.buffer;
  if (unused < AGENTX_HEADER_SIZE)
    return;

  struct agentx_header *h = (void *) c.buffer;
  ADVANCE(c.buffer, c.size, AGENTX_HEADER_SIZE);
  snmp_blank_header(h, AGENTX_PING_PDU);
  p->packet_id++;
  snmp_log("incrementing packet_id to %u (ping)", p->packet_id);
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
 * snmp_manage_tbuf - TODO
 */
void
snmp_manage_tbuf(struct snmp_proto *p, struct snmp_pdu *c)
{
  sock *sk = p->sock;
  int diff;
  if (c->sr_vb_start != NULL)
    diff = (void *) c->sr_vb_start - (void *) sk->tbuf;

  snmp_log("snmp_manage_tbuf2()");
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

  snmp_log("snmp_manage_tbuf()");
  sk_set_tbsize(sk, sk->tbsize + 2048);
  c->size += 2048;

  if (ptr)
    *ptr = sk->tbuf + diff;
}

void
snmp_tbuf_reserve(struct snmp_pdu *c, size_t size)
{
  if (size > c->size)
  {
    snmp_manage_tbuf(c->p, c);
  }
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
