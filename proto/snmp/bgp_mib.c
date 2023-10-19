/*
 *	BIRD -- Simple Network Management Protocol (SNMP)
 *        BGP4-MIB bgpPeerTable
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "snmp.h"
#include "snmp_utils.h"
#include "subagent.h"
#include "bgp_mib.h"

static inline void ip4_to_oid(struct oid *oid, ip4_addr addr);

/* BGP_MIB states see enum BGP_INTERNAL_STATES */
static const char * const debug_bgp_states[] UNUSED = {
  [BGP_INTERNAL_INVALID]		 = "BGP_INTERNAL_INVALID",
  [BGP_INTERNAL_BGP]			 = "BGP_INTERNAL_BGP",
  [BGP_INTERNAL_VERSION]		 = "BGP_INTERNAL_VERSION",
  [BGP_INTERNAL_LOCAL_AS]		 = "BGP_INTERNAL_LOCAL_AS",
  [BGP_INTERNAL_PEER_TABLE]		 = "BGP_INTERNAL_PEER_TABLE",
  [BGP_INTERNAL_PEER_ENTRY]		 = "BGP_INTERNAL_PEER_ENTRY",
  [BGP_INTERNAL_PEER_IDENTIFIER]	 = "BGP_INTERNAL_PEER_IDENTIFIER",
  [BGP_INTERNAL_STATE]			 = "BGP_INTERNAL_STATE",
  [BGP_INTERNAL_ADMIN_STATUS]		 = "BGP_INTERNAL_ADMIN_STATUS",
  [BGP_INTERNAL_NEGOTIATED_VERSION]	 = "BGP_INTERNAL_NEGOTIATED_VERSION",
  [BGP_INTERNAL_LOCAL_ADDR]		 = "BGP_INTERNAL_LOCAL_ADDR",
  [BGP_INTERNAL_LOCAL_PORT]		 = "BGP_INTERNAL_LOCAL_PORT",
  [BGP_INTERNAL_REMOTE_ADDR]		 = "BGP_INTERNAL_REMOTE_ADDR",
  [BGP_INTERNAL_REMOTE_PORT]		 = "BGP_INTERNAL_REMOTE_PORT",
  [BGP_INTERNAL_REMOTE_AS]		 = "BGP_INTERNAL_REMOTE_AS",
  [BGP_INTERNAL_RX_UPDATES]		 = "BGP_INTERNAL_RX_UPDATES",
  [BGP_INTERNAL_TX_UPDATES]		 = "BGP_INTERNAL_TX_UPDATES",
  [BGP_INTERNAL_RX_MESSAGES]		 = "BGP_INTERNAL_RX_MESSAGES",
  [BGP_INTERNAL_TX_MESSAGES]		 = "BGP_INTERNAL_TX_MESSAGES",
  [BGP_INTERNAL_LAST_ERROR]		 = "BGP_INTERNAL_LAST_ERROR",
  [BGP_INTERNAL_FSM_TRANSITIONS]	 = "BGP_INTERNAL_FSM_TRANSITIONS",
  [BGP_INTERNAL_FSM_ESTABLISHED_TIME]	 = "BGP_INTERNAL_FSM_ESTABLISHED_TIME",
  [BGP_INTERNAL_RETRY_INTERVAL]		 = "BGP_INTERNAL_RETRY_INTERVAL",
  [BGP_INTERNAL_HOLD_TIME]		 = "BGP_INTERNAL_HOLD_TIME",
  [BGP_INTERNAL_KEEPALIVE]		 = "BGP_INTERNAL_KEEPALIVE",
  [BGP_INTERNAL_HOLD_TIME_CONFIGURED]	 = "BGP_INTERNAL_HOLD_TIME_CONFIGURED",
  [BGP_INTERNAL_KEEPALIVE_CONFIGURED]	 = "BGP_INTERNAL_KEEPALIVE_CONFIGURED",
  [BGP_INTERNAL_ORIGINATION_INTERVAL]	 = "BGP_INTERNAL_ORIGINATION_INTERVAL",
  [BGP_INTERNAL_MIN_ROUTE_ADVERTISEMENT] = "BGP_INTERNAL_MIN_ROUTE_ADVERTISEMENT",
  [BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME]	 = "BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME",
  [BGP_INTERNAL_PEER_TABLE_END]		 = "BGP_INTERNAL_PEER_TABLE_END",
  [BGP_INTERNAL_IDENTIFIER]		 = "BGP_INTERNAL_IDENTIFIER",
  [BGP_INTERNAL_END]			 = "BGP_INTERNAL_END",
  [BGP_INTERNAL_NO_VALUE]		 = "BGP_INTERNAL_NO_VALUE",
};

static void
snmp_bgp_notify_common(struct snmp_proto *p, uint type, ip4_addr ip4, char last_error[], uint state_val)
{
  // TODO remove heap allocation, put the data on stack

#define SNMP_OID_SIZE_FROM_LEN(x) (sizeof(struct oid) + (x) * sizeof(u32))

  /* trap OID bgpEstablishedNotification (.1.3.6.1.2.1.0.1) */
  struct oid *head = mb_alloc(p->pool, SNMP_OID_SIZE_FROM_LEN(3));
  head->n_subid = 3;
  head->prefix = 2;
  head->include = head->pad = 0;

  u32 trap_ids[] = { 1, 0, type };
  for (uint i = 0; i < head->n_subid; i++)
    head->ids[i] = trap_ids[i];

  /* OIDs, VB type headers, octet string, ip4 address, integer */
  uint sz = 3 * SNMP_OID_SIZE_FROM_LEN(9) + 3 * 4 + 8 + 8 + 4;

  /* Paylaod OIDs */

  void *data = mb_alloc(p->pool, sz);
  struct agentx_varbind *addr_vb = data;
  /* +4 for varbind header, +8 for octet string */
  struct agentx_varbind *error_vb = data + SNMP_OID_SIZE_FROM_LEN(9)  + 4 + 8;
  struct agentx_varbind *state_vb = (void *) error_vb + SNMP_OID_SIZE_FROM_LEN(9) + 4 + 8;

  addr_vb->pad = error_vb->pad = state_vb->pad = 0;

  struct oid *addr = &addr_vb->name;
  struct oid *error = &error_vb->name;
  struct oid *state = &state_vb->name;

  addr->n_subid = error->n_subid  = state->n_subid     = 9;
  addr->prefix  = error->prefix   = state->prefix      = 2;
  addr->include = error->include  = state->include     = 0;
  addr->pad      = error->pad      = state->pad        = 0;

  u32 oid_ids[] = {
    SNMP_MIB_2, SNMP_BGP4_MIB, SNMP_BGP_PEER_TABLE, SNMP_BGP_PEER_ENTRY
  };

  for (uint i = 0; i < sizeof(oid_ids) / sizeof(oid_ids[0]); i++)
    addr->ids[i] = error->ids[i] = state->ids[i] = oid_ids[i];

  addr->ids[4]  = SNMP_BGP_REMOTE_ADDR;
  error->ids[4] = SNMP_BGP_LAST_ERROR;
  state->ids[4] = SNMP_BGP_STATE;

  for (uint i = 0; i < 4; i++)
    addr->ids[5 + i] = error->ids[5 + i] = state->ids[5 + i] \
      = (ip4_to_u32(ip4) >> (8 * (3-i))) & 0xFF;

  snmp_varbind_ip4(addr_vb, 100, ip4);

  snmp_varbind_nstr(error_vb, 100, last_error, 2);

  snmp_varbind_int(state_vb, 100, state_val);

  snmp_notify_pdu(p, head, data, sz, 0);
  mb_free(head);
  mb_free(data);

#undef SNMP_OID_SIZE_FROM_LEN
}

static inline uint
snmp_bgp_fsm_state(struct bgp_proto *bgp_proto)
{
  const struct bgp_conn *bgp_conn = bgp_proto->conn;
  const struct bgp_conn *bgp_in = &bgp_proto->incoming_conn;
  const struct bgp_conn *bgp_out = &bgp_proto->outgoing_conn;

  if (bgp_conn)
    return bgp_conn->state;

  if (MAX(bgp_in->state, bgp_out->state) == BS_CLOSE &&
      MIN(bgp_in->state, bgp_out->state) != BS_CLOSE)
    return MIN(bgp_in->state, bgp_out->state);
  if (MIN(bgp_in->state, bgp_out->state) == BS_CLOSE)
    return BS_IDLE;

  return MAX(bgp_in->state, bgp_out->state);
}

static void
snmp_bgp_notify_wrapper(struct snmp_proto *p, struct bgp_proto *bgp, uint type)
{
  // possibly dangerous
  ip4_addr ip4 = ipa_to_ip4(bgp->remote_ip);
  char last_error[2] = SNMP_BGP_LAST_ERROR(bgp);
  uint state_val = snmp_bgp_fsm_state(bgp);
  snmp_bgp_notify_common(p, type, ip4, last_error, state_val);
}

void
snmp_bgp_notify_established(struct snmp_proto *p, struct bgp_proto *bgp)
{
  /* .1.3.6.1.2.15.0.>1<  i.e. BGP4-MIB::bgpEstablishedNotification */
  snmp_bgp_notify_wrapper(p, bgp, 1);
}

void
snmp_bgp_notify_backward_trans(struct snmp_proto *p, struct bgp_proto *bgp)
{
  /* .1.3.6.1.2.15.0.>2<  i.e. BGP4-MIB::bgpBackwardTransNotification */
  snmp_bgp_notify_wrapper(p, bgp, 2);
}

void
snmp_bgp_register(struct snmp_proto *p)
{
  //snmp_log("snmp_bgp_register()");

  //u32 bgp_mib_prefix[] = {1, 15, 1};
  u32 bgp_mib_prefix[] = { 1, 15 };

  {
    /* Register the whole BGP4-MIB::bgp root tree node */
    struct snmp_register *registering = snmp_register_create(p, SNMP_BGP4_MIB);

    struct oid *oid = mb_alloc(p->pool, snmp_oid_sizeof(2));
    STORE_U8(oid->n_subid, 2);
    STORE_U8(oid->prefix, SNMP_MGMT);

    memcpy(oid->ids, bgp_mib_prefix, 2 * sizeof(u32));

    registering->oid = oid;
    add_tail(&p->register_queue, &registering->n);
    p->register_to_ack++;

    /* snmp_register(struct snmp_proto *p, struct oid *oid, uint index, uint len, u8 is_instance, uint contid) */
    snmp_register(p, oid, 1, 0, SNMP_REGISTER_TREE, SNMP_DEFAULT_CONTEXT);
  }

#if 0
  u32 bgp_peer_entry[] = { 1, 15, 3, 1, 1 };
  u32 bound = 24;
  HASH_WALK(p->bgp_hash, next, peer)
  {
    if (peer->flags & SNMP_BGP_P_REGISTERED)
      continue;

    struct bgp_proto *bgp = (struct bgp_proto *) peer->config->c.proto;

    struct snmp_register *registering = snmp_register_create(p, SNMP_BGP4_MIB);

    struct oid *oid = mb_alloc(p->pool, snmp_oid_sizeof(9));
    STORE_U8(oid->n_subid, 9);
    STORE_U8(oid->prefix, SNMP_MGMT);

    for (uint i = 0; i < ARRAY_SIZE(bgp_peer_entry); i++)
      STORE_U32(oid->ids[i], bgp_peer_entry[i]);
    ip4_to_oid(oid, ipa_to_ip4(bgp->remote_ip));

    /* index is position of x in .1.3.6.1.2.15.3.1.x (1-based) */
    snmp_register(p, oid, bound, 9, SNMP_REGISTER_INSTANCE, peer->context_id);

    registering->oid = oid;
    add_tail(&p->register_queue, &registering->n);
    p->register_to_ack++;
  }
  HASH_WALK_END;
#endif
}

static int
snmp_bgp_valid_ip4(struct oid *o)
{
  return snmp_valid_ip4_index(o, 5);
}

static u8
bgp_get_candidate(u32 field)
{
  const u8 translation_table[] = {
    [SNMP_BGP_PEER_IDENTIFIER]		= BGP_INTERNAL_PEER_IDENTIFIER,
    [SNMP_BGP_STATE]			= BGP_INTERNAL_STATE,
    [SNMP_BGP_ADMIN_STATUS]		= BGP_INTERNAL_ADMIN_STATUS,
    [SNMP_BGP_NEGOTIATED_VERSION]	= BGP_INTERNAL_NEGOTIATED_VERSION,
    [SNMP_BGP_LOCAL_ADDR]		= BGP_INTERNAL_LOCAL_ADDR,
    [SNMP_BGP_LOCAL_PORT]		= BGP_INTERNAL_LOCAL_PORT,
    [SNMP_BGP_REMOTE_ADDR]		= BGP_INTERNAL_REMOTE_ADDR,
    [SNMP_BGP_REMOTE_PORT]		= BGP_INTERNAL_REMOTE_PORT,
    [SNMP_BGP_REMOTE_AS]		= BGP_INTERNAL_REMOTE_AS,
    [SNMP_BGP_RX_UPDATES]		= BGP_INTERNAL_RX_UPDATES,
    [SNMP_BGP_TX_UPDATES]		= BGP_INTERNAL_TX_UPDATES,
    [SNMP_BGP_RX_MESSAGES]		= BGP_INTERNAL_RX_MESSAGES,
    [SNMP_BGP_TX_MESSAGES]		= BGP_INTERNAL_TX_MESSAGES,
    [SNMP_BGP_LAST_ERROR]		= BGP_INTERNAL_LAST_ERROR,
    [SNMP_BGP_FSM_TRANSITIONS]		= BGP_INTERNAL_FSM_TRANSITIONS,
    [SNMP_BGP_FSM_ESTABLISHED_TIME]	= BGP_INTERNAL_FSM_ESTABLISHED_TIME,
    [SNMP_BGP_RETRY_INTERVAL]		= BGP_INTERNAL_RETRY_INTERVAL,
    [SNMP_BGP_HOLD_TIME]		= BGP_INTERNAL_HOLD_TIME,
    [SNMP_BGP_KEEPALIVE]		= BGP_INTERNAL_KEEPALIVE,
    [SNMP_BGP_HOLD_TIME_CONFIGURED]	= BGP_INTERNAL_HOLD_TIME_CONFIGURED,
    [SNMP_BGP_KEEPALIVE_CONFIGURED]     = BGP_INTERNAL_KEEPALIVE_CONFIGURED,
    [SNMP_BGP_ORIGINATION_INTERVAL]     = BGP_INTERNAL_ORIGINATION_INTERVAL,
    [SNMP_BGP_MIN_ROUTE_ADVERTISEMENT]  = BGP_INTERNAL_MIN_ROUTE_ADVERTISEMENT,
    [SNMP_BGP_IN_UPDATE_ELAPSED_TIME]   = BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME,
  };

  /*
   * First value is in secord cell of array translation_table, as the
   * SNMP_BPG_IDENTIFIER == 1
   */
  if (field > 0 && field <= sizeof(translation_table) / sizeof(translation_table[0]) - 1)
    return translation_table[field];
  if (field == 0)
    return BGP_INTERNAL_PEER_ENTRY;
  else
    return BGP_INTERNAL_PEER_TABLE_END;
}

static inline struct ip4_addr
ip4_from_oid(const struct oid *o)
{
  return ip4_build(
    o->n_subid > 5 ? (o->ids[5] & 0xff) : 0,
    o->n_subid > 6 ? (o->ids[6] & 0xff) : 0,
    o->n_subid > 7 ? (o->ids[7] & 0xff) : 0,
    o->n_subid > 8 ? (o->ids[8] & 0xff) : 0
  );
}

static inline void
ip4_to_oid(struct oid *o, ip4_addr addr)
{
  u32 tmp = ip4_to_u32(addr);
  ASSUME(o->n_subid >= 9);
  STORE_U32(o->ids[5], (tmp & 0xFF000000) >> 24);
  STORE_U32(o->ids[6], (tmp & 0x00FF0000) >> 16);
  STORE_U32(o->ids[7], (tmp & 0x0000FF00) >>  8);
  STORE_U32(o->ids[8], (tmp & 0x000000FF) >>  0);
}

static void
print_bgp_record(const struct bgp_config *config)
{
  struct proto_config *cf = (struct proto_config *) config;
  struct bgp_proto *bgp_proto = (struct bgp_proto *) cf->proto;
  struct bgp_conn *conn = bgp_proto->conn;

  snmp_log("    name: %s", cf->name);
  snmp_log(".");
  snmp_log("    rem. identifier: %u", bgp_proto->remote_id);
  snmp_log("    local ip: %I", config->local_ip);
  snmp_log("    remote ip: %I", config->remote_ip);
  snmp_log("    local port: %u", config->local_port);
  snmp_log("    remote port: %u", config->remote_port);

  if (conn) {
    snmp_log("    state: %u", conn->state);
    snmp_log("    remote as: %u", conn->remote_caps->as4_number);
  }

  snmp_log("    in updates: %u", bgp_proto->stats.rx_updates);
  snmp_log("    out updates: %u", bgp_proto->stats.tx_updates);
  snmp_log("    in total: %u", bgp_proto->stats.rx_messages);
  snmp_log("    out total: %u", bgp_proto->stats.tx_messages);
  snmp_log("    fsm transitions: %u",
      bgp_proto->stats.fsm_established_transitions);

  snmp_log("    fsm total time: -- (0)");   // not supported by bird
  snmp_log("    retry interval: %u", config->connect_retry_time);

  snmp_log("    hold configurated: %u", config->hold_time );
  snmp_log("    keep alive config: %u", config->keepalive_time );

  snmp_log("    min AS origin. int.: -- (0)");	// not supported by bird
  snmp_log("    min route advertisement: %u", 0 );
  snmp_log("    in update elapsed time: %u", 0 );

  if (!conn)
    snmp_log("  no connection established");

  snmp_log("  outgoinin_conn state %u", bgp_proto->outgoing_conn.state + 1);
  snmp_log("  incoming_conn state: %u", bgp_proto->incoming_conn.state + 1);
}

static void
print_bgp_record_all(struct snmp_proto *p)
{
  snmp_log("dumping watched bgp status");
  HASH_WALK(p->bgp_hash, next, peer)
  {
    print_bgp_record(peer->config);
  }
  HASH_WALK_END;
  snmp_log("dumping watched end");
}


/**
 * snmp_bgp_state - linearize oid from BGP4-MIB
 * @oid: prefixed object identifier from BGP4-MIB::bgp subtree
 *
 * Returns linearized state for Get-PDU, GetNext-PDU and GetBulk-PDU packets.
 */
static u8
snmp_bgp_state(const struct oid *oid)
{
  /*
   * Ids of Object Identifier that are already checked:
   *	    internet  oid.prefix
   *           v...... v
   *  (*oid): .1.3.6.1.2.1.15
   *   -> BGP4-MIB::bgp (root)
   */

  if (snmp_is_oid_empty(oid))
    return BGP_INTERNAL_END;

  u8 state = BGP_INTERNAL_NO_VALUE;

  u8 candidate;
  switch (oid->n_subid)
  {
    default:
      if (oid->n_subid < 2)
      {
	state = BGP_INTERNAL_INVALID;
	break;
      }

      /* fall through */

   /*
    * Between ids[5] and ids[8] (n_subid == 9) should be IP address.
    * Validity is checked later in execution because
    *  this field also could mean a query boundry (upper or lower).
    */
    case 9:
    case 8:
    case 7:
    case 6:
    case 5:
      state = bgp_get_candidate(oid->ids[4]);

      /* fall through */

    case 4:
      if (oid->ids[3] == SNMP_BGP_PEER_ENTRY)
	state = (state == BGP_INTERNAL_NO_VALUE) ?
	  BGP_INTERNAL_PEER_ENTRY : state;
      else
	state = BGP_INTERNAL_NO_VALUE;

      /* fall through */

    case 3:
      /* u8 candidate; */
      switch (oid->ids[2])
      {

	case SNMP_BGP_VERSION:
	  state = BGP_INTERNAL_VERSION;
	  break;
	case SNMP_BGP_LOCAL_AS:
	  state = BGP_INTERNAL_LOCAL_AS;
	  break;
	case SNMP_BGP_PEER_TABLE:
	  /* We use candidate to avoid overriding more specific state */
	  candidate = BGP_INTERNAL_PEER_TABLE;
	  break;
	case SNMP_BGP_IDENTIFIER:
	  state = BGP_INTERNAL_IDENTIFIER;
	  break;

	default:  /* test fails */
	  /* We force state invalidation */
	  if (oid->ids[2] < SNMP_BGP_VERSION)
	  {
	    state = BGP_INTERNAL_NO_VALUE;
	    candidate = BGP_INTERNAL_NO_VALUE;
	  }
	  else /* oid->ids[2] > SNMP_BGP_PEER_TABLE */
	    state = BGP_INTERNAL_END;
      }
      state = (state == BGP_INTERNAL_NO_VALUE) ?
	candidate : state;

      /* fall through */

    case 2: /* We found bare BGP4-MIB::bgp ObjectId */
      if (state == BGP_INTERNAL_NO_VALUE ||
	  state == BGP_INTERNAL_INVALID)
	state = BGP_INTERNAL_BGP;
  }

  return state;
}

static inline int
is_dynamic(u8 state)
{
  return (state >= BGP_INTERNAL_PEER_IDENTIFIER &&
	  state <= BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME);
}

static inline int
is_static(u8 state)
{
  return (state == BGP_INTERNAL_VERSION ||
	  state == BGP_INTERNAL_LOCAL_AS ||
	  state == BGP_INTERNAL_IDENTIFIER);
}

static inline int
snmp_bgp_has_value(u8 state)
{
  if (state <= BGP_INTERNAL_BGP ||
      state == BGP_INTERNAL_PEER_TABLE ||
      state == BGP_INTERNAL_PEER_ENTRY ||
      state == BGP_INTERNAL_PEER_TABLE_END ||
      state >= BGP_INTERNAL_END)
    return 0;
  else
    return 1;
}

/**
 * snmp_bgp_get_valid - only states with valid value
 * @state: BGP linearized state
 *
 * Returns @state if has value in BGP4-MIB, zero otherwise. Used for Get-PDU
 * ackets.
 */
u8
snmp_bgp_get_valid(u8 state)
{
  if (state == BGP_INTERNAL_INVALID ||
      state == BGP_INTERNAL_BGP ||
      state == BGP_INTERNAL_PEER_TABLE ||
      state == BGP_INTERNAL_PEER_ENTRY ||
      state == BGP_INTERNAL_PEER_TABLE_END ||
      state >= BGP_INTERNAL_END)
    return 0;
  else
    return state;
}

/**
 * snmp_bgp_next_state - next state that has value
 * @state: BGP linearized state
 *
 * Returns successor state of @state with valid value in BG4-MIB. Used for
 * GetNext-PDU and GetBulk-PDU packets.
 */
u8
snmp_bgp_next_state(u8 state)
{
  switch (state)
  {
    case BGP_INTERNAL_LOCAL_AS:
    case BGP_INTERNAL_PEER_TABLE:
    case BGP_INTERNAL_PEER_ENTRY:
      return BGP_INTERNAL_PEER_IDENTIFIER;

    case BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME:
    case BGP_INTERNAL_PEER_TABLE_END:
      return BGP_INTERNAL_IDENTIFIER;

    case BGP_INTERNAL_IDENTIFIER:
    case BGP_INTERNAL_END:
      return BGP_INTERNAL_END;

    default:
      return state + 1;
  }
}

int
snmp_bgp_is_supported(struct oid *o)
{
  if (o->prefix == 2 && o->n_subid > 0 && o->ids[0] == 1)
  {
    if (o->n_subid == 2 && (o->ids[1] == SNMP_BGP4_MIB ||
        o->ids[1] == SNMP_BGP_LOCAL_AS))
      return 1;
    else if (o->n_subid > 2 && o->ids[1] == SNMP_BGP_PEER_TABLE &&
	     o->ids[2] == SNMP_BGP_PEER_ENTRY)
    {
      if (o->n_subid == 3)
	return 1;
      if (o->n_subid == 8 && o->ids[3] > 0)
	return 1;
    }
    return 0;
  }
  return 0;
}

static int
oid_state_compare(const struct oid *oid, u8 state)
{
  ASSUME(oid != NULL);
  if (state >= BGP_INTERNAL_PEER_IDENTIFIER &&
      state <= BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME)
    return (oid->n_subid > 9) - (oid->n_subid < 9);
  if ((state >= BGP_INTERNAL_VERSION && state <= BGP_INTERNAL_PEER_TABLE) ||
      (state == BGP_INTERNAL_IDENTIFIER))
    return (oid->n_subid > 3) - (oid->n_subid < 3);
  if (state == BGP_INTERNAL_PEER_ENTRY)
    return (oid->n_subid > 4) - (oid->n_subid < 4);
  if (state == BGP_INTERNAL_BGP)
    return (oid->n_subid > 2) - (oid->n_subid < 2);

  return -1;
}

static struct oid *
update_bgp_oid(struct oid *oid, u8 state)
{
  //snmp_log("update_bgp_oid()");
  if (state == BGP_INTERNAL_END || state == BGP_INTERNAL_INVALID ||
      state == BGP_INTERNAL_NO_VALUE)
    return oid;

  /* No need to reallocate anything if the OID has same lin. state */
  if (snmp_bgp_state(oid) == state)
  {
    if (state >= BGP_INTERNAL_PEER_IDENTIFIER &&
	state <= BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME &&
	oid->n_subid == 9)
      return oid;
    if (state >= BGP_INTERNAL_VERSION &&
	state <= BGP_INTERNAL_PEER_TABLE && oid->n_subid == 3)
      return oid;
    if (state == BGP_INTERNAL_PEER_ENTRY && oid->n_subid == 4)
      return oid;
    if (state == BGP_INTERNAL_BGP && oid->n_subid == 2)
      return oid;
  }

  //snmp_log("update work");
  switch (state)
  {
    case BGP_INTERNAL_BGP:
      /* This could potentially destroy same old data */
      if (oid->n_subid != 2)
	oid = mb_realloc(oid, snmp_oid_sizeof(2));

      oid->n_subid = 2;
      oid->ids[0] = SNMP_MIB_2;
      oid->ids[1] = SNMP_BGP4_MIB;
      break;

    case BGP_INTERNAL_VERSION:
      if (oid->n_subid != 3)
	oid = mb_realloc(oid, snmp_oid_sizeof(3));

      oid->n_subid = 3;
      oid->ids[2] = SNMP_BGP_VERSION;
      break;

    case BGP_INTERNAL_LOCAL_AS:
      if (oid->n_subid != 3)
	oid = mb_realloc(oid, snmp_oid_sizeof(3));

      oid->n_subid = 3;
      oid->ids[2] = SNMP_BGP_LOCAL_AS;
      break;

    case BGP_INTERNAL_PEER_IDENTIFIER:
      if (oid->n_subid != 9)
      {
	oid = mb_realloc(oid, snmp_oid_sizeof(9));

	if (oid->n_subid < 6)
	  oid->ids[5] = 0;
	if (oid->n_subid < 7)
	  oid->ids[6] = 0;
	if (oid->n_subid < 8)
	  oid->ids[7] = 0;
	if (oid->n_subid < 9)
	  oid->ids[8] = 0;
      }

      oid->ids[2] = SNMP_BGP_PEER_TABLE;
      oid->ids[3] = SNMP_BGP_PEER_ENTRY;

      oid->ids[4] = SNMP_BGP_PEER_IDENTIFIER;
      oid->n_subid = 9;
      break;

#define SNMP_UPDATE_CASE(num, update)					    \
    case num:								    \
      if (oid->n_subid != 9)						    \
      {									    \
	oid = mb_realloc(oid, snmp_oid_sizeof(9));			    \
									    \
	if (oid->n_subid < 6)						    \
	  oid->ids[5] = 0;						    \
	if (oid->n_subid < 7)						    \
	  oid->ids[6] = 0;						    \
	if (oid->n_subid < 8)						    \
	  oid->ids[7] = 0;						    \
	if (oid->n_subid < 9)						    \
	  oid->ids[8] = 0;						    \
      }									    \
      oid->n_subid = 9;							    \
      oid->ids[4] = update;						    \
      break;

    SNMP_UPDATE_CASE(BGP_INTERNAL_STATE, SNMP_BGP_STATE)

    SNMP_UPDATE_CASE(BGP_INTERNAL_ADMIN_STATUS, SNMP_BGP_ADMIN_STATUS)

    SNMP_UPDATE_CASE(BGP_INTERNAL_NEGOTIATED_VERSION, SNMP_BGP_NEGOTIATED_VERSION)

    SNMP_UPDATE_CASE(BGP_INTERNAL_LOCAL_ADDR, SNMP_BGP_LOCAL_ADDR)

    SNMP_UPDATE_CASE(BGP_INTERNAL_LOCAL_PORT, SNMP_BGP_LOCAL_PORT)

    SNMP_UPDATE_CASE(BGP_INTERNAL_REMOTE_ADDR, SNMP_BGP_REMOTE_ADDR)

    SNMP_UPDATE_CASE(BGP_INTERNAL_REMOTE_PORT, SNMP_BGP_REMOTE_PORT)

    SNMP_UPDATE_CASE(BGP_INTERNAL_REMOTE_AS, SNMP_BGP_REMOTE_AS)

    SNMP_UPDATE_CASE(BGP_INTERNAL_RX_UPDATES, SNMP_BGP_RX_UPDATES)

    SNMP_UPDATE_CASE(BGP_INTERNAL_TX_UPDATES, SNMP_BGP_TX_UPDATES)

    SNMP_UPDATE_CASE(BGP_INTERNAL_RX_MESSAGES, SNMP_BGP_RX_MESSAGES)

    SNMP_UPDATE_CASE(BGP_INTERNAL_TX_MESSAGES, SNMP_BGP_TX_MESSAGES)

    SNMP_UPDATE_CASE(BGP_INTERNAL_LAST_ERROR, SNMP_BGP_LAST_ERROR)

    SNMP_UPDATE_CASE(BGP_INTERNAL_FSM_TRANSITIONS, SNMP_BGP_FSM_TRANSITIONS)

    SNMP_UPDATE_CASE(BGP_INTERNAL_FSM_ESTABLISHED_TIME, SNMP_BGP_FSM_ESTABLISHED_TIME)

    SNMP_UPDATE_CASE(BGP_INTERNAL_RETRY_INTERVAL, SNMP_BGP_RETRY_INTERVAL)

    SNMP_UPDATE_CASE(BGP_INTERNAL_HOLD_TIME, SNMP_BGP_HOLD_TIME)

    SNMP_UPDATE_CASE(BGP_INTERNAL_KEEPALIVE, SNMP_BGP_KEEPALIVE)

    SNMP_UPDATE_CASE(BGP_INTERNAL_HOLD_TIME_CONFIGURED, SNMP_BGP_HOLD_TIME_CONFIGURED)

    SNMP_UPDATE_CASE(BGP_INTERNAL_KEEPALIVE_CONFIGURED, SNMP_BGP_KEEPALIVE_CONFIGURED)

    SNMP_UPDATE_CASE(BGP_INTERNAL_ORIGINATION_INTERVAL, SNMP_BGP_ORIGINATION_INTERVAL)

    SNMP_UPDATE_CASE(BGP_INTERNAL_MIN_ROUTE_ADVERTISEMENT, SNMP_BGP_MIN_ROUTE_ADVERTISEMENT)

    SNMP_UPDATE_CASE(BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME, SNMP_BGP_IN_UPDATE_ELAPSED_TIME)

    case BGP_INTERNAL_IDENTIFIER:
      if (oid->n_subid != 3)
	oid = mb_realloc(oid, snmp_oid_sizeof(3));

      oid->n_subid = 3;
      oid->ids[2] = 4;
      break;

    default:
      /* intentionally left blank */
      break;
      //die("update unavailable");
  }

  return oid;
#undef SNMP_UPDATE_CASE
}

// TODO test bgp_find_dynamic_oid
static struct oid *
bgp_find_dynamic_oid(struct snmp_proto *p, struct oid *o_start, const struct oid *o_end, u8 start_state)
{
  ASSUME(o_start != NULL);
  ASSUME(o_end != NULL);

  //snmp_log("bgp_find_dynamic_oid()");
  ip4_addr ip4 = ip4_from_oid(o_start);
  ip4_addr dest;

  if (o_start->n_subid < 9)
    o_start->include = 1;

  int check_dest = snmp_is_oid_empty(o_end);
  if (check_dest)
  {
    u8 end_state = snmp_bgp_state(o_end);
    dest = (start_state == end_state && o_end->n_subid > 5) ?
      ip4_from_oid(o_end) :
      ip4_from_u32(UINT32_MAX);
  }

  //snmp_log("ip addresses build (ip4) %I (dest) %I", ipa_from_ip4(ip4), ipa_from_ip4(dest));

  net_addr net;
  net_fill_ip4(&net, ip4, IP4_MAX_PREFIX_LENGTH);

  //snmp_log("dynamic part of BGP mib");

  struct f_trie_walk_state ws;

  trie_walk_init(&ws, p->bgp_trie, NULL, 0);

  //snmp_log("walk init");

  if (trie_walk_next(&ws, &net))
  {
    //snmp_log("trie_walk_next() returned true");

    /*
     * If the o_end is empty, then there are no conditions on the ip4 address.
     */
    int cmp = ip4_compare(net4_prefix(&net), dest);
    if (cmp < 0 || (cmp == 0 && snmp_is_oid_empty(o_end)))
    {
      //snmp_log("ip4_less() returned true");

      // TODO repair
      struct oid *o = snmp_oid_duplicate(p->pool, o_start);
      snmp_oid_ip4_index(o, 5, net4_prefix(&net));

      return o;
    }
    else
      {}//snmp_log("ip4_less() returned false for %I >= %I", net4_prefix(&net), dest);
  }
  else
    {}//snmp_log("trie_walk_next() returned false, cleaning");

  return NULL;
}

static struct oid *
search_bgp_dynamic(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, uint contid
UNUSED, u8 next_state)
{
  //snmp_log("search_bgp_dynamic() dynamic part Yaaay!");

  struct oid *o_copy = o_start;
  do
  {
    //snmp_log("do-while state %u", next_state);
    //snmp_oid_dump(o_start);
    o_start = o_copy = update_bgp_oid(o_copy, next_state);

    o_start = bgp_find_dynamic_oid(p, o_start, o_end, next_state);
    //snmp_log("found");
    //snmp_oid_dump(o_start);

    next_state = snmp_bgp_next_state(next_state);
    /* The search in next state is done from beginning. */
    o_start->ids[5] = o_start->ids[6] = o_start->ids[7] = o_start->ids[8] = 0;
    o_start->include = 1;

    //snmp_log("looping");
  } while (o_start == NULL && next_state < BGP_INTERNAL_END);

  return o_start;
}

/**
 * snmp_bgp_find_next_oid - walk bgp peer addresses and update @o_start oid
 *
 * @p:
 * @oid:
 * @contid:
 */
static int
snmp_bgp_find_next_oid(struct snmp_proto *p, struct oid *oid, uint UNUSED contid)
{
  ip4_addr ip4 = ip4_from_oid(oid);
  //ip_add4 dest = ip4_from_u32(0xFFFFFFFF);

  net_addr net;
  net_fill_ip4(&net, ip4, IP4_MAX_PREFIX_LENGTH);
  struct f_trie_walk_state ws;

  int match = trie_walk_init(&ws, p->bgp_trie, &net, 1);

  //snmp_log("match %d include %u", match, oid->include);
  if (match && oid->include)
  {
    oid->include = 0;
    return 1;
  }

  /* We skip the first match as we should not include ip address in oid */
  if (match)
  {
    //snmp_log("continue");
    trie_walk_next(&ws, &net);
  }

  if (trie_walk_next(&ws, &net))
  {
    //snmp_oid_dump(oid);
    //snmp_log("setting up");
    u32 res = ipa_to_u32(net_prefix(&net));

    ASSUME(oid->n_subid == 9);
    oid->ids[5] = (res & 0xFF000000) >> 24;
    oid->ids[6] = (res & 0x00FF0000) >> 16;
    oid->ids[7] = (res & 0x0000FF00) >>  8;
    oid->ids[8] = (res & 0x000000FF) >>  0;
    return 1;
  }

  //snmp_log("bad");
  return 0;
}

static enum snmp_search_res
snmp_bgp_search_dynamic(struct snmp_proto *p, struct oid **searched, const struct oid *o_end, uint UNUSED contid, u8 next_state)
{
  struct oid *oid = *searched;
  //snmp_log(" **searched = 0x%p  *oid = 0x%p", searched, oid);
  //snmp_oid_dump(*searched);
  //snmp_oid_dump(oid);
  u8 end_state = MIN(snmp_bgp_state(o_end), BGP_INTERNAL_PEER_TABLE_END);

  //snmp_log("before assumption %s [%u] < %u INTERNAL_END", debug_bgp_states[end_state], end_state, BGP_INTERNAL_END);
  ASSUME(end_state <= BGP_INTERNAL_END);
  //snmp_log("before assupmtion oid 0x%p != NULL (0x0)", oid);
  ASSUME(oid != NULL);

  oid = update_bgp_oid(oid, next_state);

  //snmp_log("update bgp oid to state %s [%d]", debug_bgp_states[next_state], next_state);
  //snmp_oid_dump(*searched);
  //snmp_oid_dump(oid);

  int found;
  while (!(found = snmp_bgp_find_next_oid(p, oid, contid)) && next_state <= end_state)
  {
    //snmp_log("loop");

    next_state = snmp_bgp_next_state(next_state);
    if (next_state == BGP_INTERNAL_IDENTIFIER)
      break;
    oid = update_bgp_oid(oid, next_state);
    /* In case of search for next bgp state, we want to start from beginning. */
    oid->ids[5] = oid->ids[6] = oid->ids[7] = oid->ids[8] = 0;
  }

  if (next_state < BGP_INTERNAL_PEER_TABLE_END && next_state <= end_state)
  {
    *searched = oid;
    return SNMP_SEARCH_OK;
  }

  return SNMP_SEARCH_END_OF_VIEW;
}

enum snmp_search_res
snmp_bgp_search2(struct snmp_proto *p, struct oid **searched, const struct oid *o_end, uint contid)
{
  enum snmp_search_res r = SNMP_SEARCH_END_OF_VIEW;
  u8 bgp_state = snmp_bgp_state(*searched);
  u8 state;
  //snmp_log("snmp_bgp_search2() with state %s [%d]", debug_bgp_states[bgp_state], bgp_state);

  if (bgp_state == BGP_INTERNAL_END)
  {
    return SNMP_SEARCH_NO_OBJECT;
  }

  if (is_static(bgp_state) && (*searched)->include)
  {
    return SNMP_SEARCH_OK;
  }

  state = snmp_bgp_next_state(bgp_state);
  if (is_static(state) && !is_dynamic(bgp_state))
  {
    *searched = update_bgp_oid(*searched, state);
    return SNMP_SEARCH_OK;
  }

  if (is_dynamic(state) && !is_dynamic(bgp_state))
  {
    //snmp_log("searching a dynamic successor of static state");
    for (uint i = 5; i < MIN(9, (*searched)->n_subid); i++)
      (*searched)->ids[i] = 0;
    r = snmp_bgp_search_dynamic(p, searched, o_end, contid, state);
    if (r != SNMP_SEARCH_END_OF_VIEW)
      return r;
  }

  if (is_dynamic(bgp_state))
  {
    //snmp_log("searching the dynamic states (peers)");
    r = snmp_bgp_search_dynamic(p, searched, o_end, contid, bgp_state);

    if (r != SNMP_SEARCH_END_OF_VIEW)
      return r;
  }

  state = snmp_bgp_next_state(bgp_state);
  if (state <= BGP_INTERNAL_IDENTIFIER)
  {
    //snmp_log("returning the local identifier");
    *searched = update_bgp_oid(*searched, state);
    return SNMP_SEARCH_OK;
  }

  // TODO add route table

  /* end not found */
  //snmp_log("reached unguarded code, returning END_OF_VIEW");
  return SNMP_SEARCH_END_OF_VIEW;
}

struct oid *
snmp_bgp_search(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, uint contid UNUSED)
{
  u8 start_state = snmp_bgp_state(o_start);

  // print debugging information
  print_bgp_record_all(p);

  if (o_start->include && snmp_bgp_has_value(start_state) &&
      !is_dynamic(start_state) && o_start->n_subid == 3)
  {
    //snmp_log("snmp_bgp_search() first search element (due to include field) returned");
    /* We disable including for next time searching. */
    o_start->include = 0;
    return o_start;
  }
  else if (o_start->include && snmp_bgp_has_value(start_state) &&
	   is_dynamic(start_state))
  {
    //snmp_log("snmp_bgp_search() first search element matched dynamic entry!");
    return search_bgp_dynamic(p, o_start, o_end, contid, start_state);
  }

  /* o_start is not inclusive */

  u8 next_state = snmp_bgp_next_state(start_state);
  // TODO more checks ?!?
  if (!is_dynamic(next_state))
  {
    o_start = update_bgp_oid(o_start, next_state);
    //snmp_log("next state is also not dynamic");
    return o_start;
  }

  /* is_dynamic(next_state) == 1 */

  return search_bgp_dynamic(p, o_start, o_end, 0, next_state);
}

static byte *
bgp_fill_dynamic(struct snmp_proto UNUSED *p, struct agentx_varbind *vb,
		 struct snmp_pdu *c, u8 state)
{
  struct oid *oid = &vb->name;
  uint size = c->size - snmp_varbind_header_size(vb);
  uint UNUSED contid = c->context;
  byte *pkt;

  ip_addr addr;
  if (oid_state_compare(oid, state) == 0 && snmp_bgp_valid_ip4(oid))
    addr = ipa_from_ip4(ip4_from_oid(oid));
  else
  {
    vb->type = AGENTX_NO_SUCH_INSTANCE;
    pkt = ((byte *) vb) + snmp_varbind_header_size(vb);
    return pkt;
  }

  //snmp_log(" -> ip addr %I", addr);
  // TODO XXX deal with possible change of (remote) ip; BGP should restart and
  // disappear
  struct snmp_bgp_peer *pe = HASH_FIND(p->bgp_hash, SNMP_HASH, addr);

  struct bgp_proto *bgp_proto = NULL;
  struct proto *proto = NULL;
  if (pe)
  {
    proto = ((struct proto_config *) pe->config)->proto;
    if (proto->proto == &proto_bgp &&
        ipa_equal(addr, ((struct bgp_proto *) proto)->remote_ip))
    {
      bgp_proto = (struct bgp_proto *) proto;
      //snmp_log("bgp_dynamic_fill() using bgp_proto %p", bgp_proto);
    }
    /* We did not found binded BGP protocol. */
    else
    {
      die("Binded bgp protocol not found!");
      vb->type = AGENTX_NO_SUCH_INSTANCE;
      return ((byte *) vb) + snmp_varbind_header_size(vb);
    }
  }
  else
  {
    vb->type = AGENTX_NO_SUCH_INSTANCE;
    return ((byte *) vb) + snmp_varbind_header_size(vb);
  }

  const struct bgp_conn *bgp_conn = bgp_proto->conn;
  const struct bgp_stats *bgp_stats = &bgp_proto->stats;
  const struct bgp_config *bgp_conf = bgp_proto->cf;

  uint bgp_state = snmp_bgp_fsm_state(bgp_proto);

  char last_error[2] = SNMP_BGP_LAST_ERROR(bgp_proto);
  switch (state)
  {
    case BGP_INTERNAL_PEER_IDENTIFIER:
      if (bgp_state == BS_OPENCONFIRM || bgp_state == BS_ESTABLISHED)
	pkt = snmp_varbind_ip4(vb, size, ip4_from_u32(bgp_proto->remote_id));
      else
	pkt = snmp_varbind_ip4(vb, size, IP4_NONE);
      break;

    case BGP_INTERNAL_STATE:
      pkt = snmp_varbind_int(vb, size, bgp_state);
      break;

    case BGP_INTERNAL_ADMIN_STATUS:
      if (proto->disabled)
	pkt = snmp_varbind_int(vb, size, AGENTX_ADMIN_STOP);
      else
	pkt = snmp_varbind_int(vb, size, AGENTX_ADMIN_START);

      break;

    case BGP_INTERNAL_NEGOTIATED_VERSION:
      if (bgp_state == BS_OPENCONFIRM || bgp_state == BS_ESTABLISHED)
	pkt = snmp_varbind_int(vb, size, SNMP_BGP_NEGOTIATED_VER_VALUE);
      else
	pkt = snmp_varbind_int(vb, size, SNMP_BGP_NEGOTIATED_VER_NO_VALUE);

      break;

    case BGP_INTERNAL_LOCAL_ADDR:
      // TODO XXX bgp_proto->link_addr & zero local_ip
      pkt = snmp_varbind_ip4(vb, size, ipa_to_ip4(bgp_proto->local_ip));
      break;

    case BGP_INTERNAL_LOCAL_PORT:
      pkt = snmp_varbind_int(vb, size, bgp_conf->local_port);
      break;

    case BGP_INTERNAL_REMOTE_ADDR:
      pkt = snmp_varbind_ip4(vb, size, ipa_to_ip4(bgp_proto->remote_ip));
      break;

    case BGP_INTERNAL_REMOTE_PORT:
      pkt = snmp_varbind_int(vb, size, bgp_conf->remote_port);
      break;

    case BGP_INTERNAL_REMOTE_AS:
      pkt = snmp_varbind_int(vb, size, bgp_proto->remote_as);
      break;

    /* IN UPDATES */
    case BGP_INTERNAL_RX_UPDATES:
      pkt = snmp_varbind_counter32(vb, size, bgp_stats->rx_updates);
      break;

    /* OUT UPDATES */
    case BGP_INTERNAL_TX_UPDATES:
      pkt = snmp_varbind_counter32(vb, size, bgp_stats->tx_updates);
      break;

    /* IN MESSAGES */
    case BGP_INTERNAL_RX_MESSAGES:
      pkt = snmp_varbind_counter32(vb, size, bgp_stats->rx_messages);
      break;

    /* OUT MESSAGES */
    case BGP_INTERNAL_TX_MESSAGES:
      pkt = snmp_varbind_counter32(vb, size, bgp_stats->tx_messages);
      break;

    case BGP_INTERNAL_LAST_ERROR:
      pkt = snmp_varbind_nstr(vb, size, last_error, 2);
      break;

    case BGP_INTERNAL_FSM_TRANSITIONS:
      pkt = snmp_varbind_counter32(vb, size,
	  bgp_stats->fsm_established_transitions);
      break;

    case BGP_INTERNAL_FSM_ESTABLISHED_TIME:
      pkt = snmp_varbind_gauge32(vb, size,
	    (current_time() - bgp_proto->last_established) TO_S);
      break;

    case BGP_INTERNAL_RETRY_INTERVAL:
      // retry interval != 0
      pkt = snmp_varbind_int(vb, size, bgp_conf->connect_retry_time);
      break;

    case BGP_INTERNAL_HOLD_TIME:
      // (0, 3..65535)
      pkt = snmp_varbind_int(vb, size, (bgp_conn) ?  bgp_conn->hold_time : 0);
      break;

    case BGP_INTERNAL_KEEPALIVE:
      if (!bgp_conf->hold_time)
	pkt = snmp_varbind_int(vb, size, 0);
      else
	pkt = snmp_varbind_int(vb, size,
	  (bgp_conn) ? bgp_conn->keepalive_time : 0);
      break;

    case BGP_INTERNAL_HOLD_TIME_CONFIGURED:
      pkt = snmp_varbind_int(vb, size, bgp_conf->hold_time);
      break;

    case BGP_INTERNAL_KEEPALIVE_CONFIGURED:
      if (!bgp_conf->keepalive_time)
	pkt = snmp_varbind_int(vb, size, 0);
      else
	pkt = snmp_varbind_int(vb, size,
	  (bgp_conn) ? bgp_conn->keepalive_time : 0);
      break;

    case BGP_INTERNAL_ORIGINATION_INTERVAL:
      // (1..65535) but is not supported
      pkt = snmp_varbind_int(vb, size, 0);
      break;

    case BGP_INTERNAL_MIN_ROUTE_ADVERTISEMENT:
      // (1..65535) but is not supported
      pkt = snmp_varbind_int(vb, size, 0);
      break;

    case BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME:
      pkt = snmp_varbind_gauge32(vb, size,
	(current_time() - bgp_proto->last_rx_update) TO_S
      );
      break;

    case BGP_INTERNAL_END:
      break;

    case BGP_INTERNAL_INVALID:
      break;

    case BGP_INTERNAL_BGP:
      break;
    case BGP_INTERNAL_PEER_TABLE:
      break;
    case BGP_INTERNAL_PEER_ENTRY:
      break;
    case BGP_INTERNAL_NO_VALUE:
      break;
  }

  if (!pkt)
  {
    vb->type = AGENTX_NO_SUCH_INSTANCE;
    return ((byte *) vb) + snmp_varbind_header_size(vb);
  }

  return pkt;
}


static byte *
bgp_fill_static(struct snmp_proto *p, struct agentx_varbind *vb, byte *pkt, uint size
UNUSED, uint contid UNUSED, int byte_ord UNUSED, u8 state)
{
  ASSUME((void *) pkt == (void *) vb);
  //snmp_log("snmp bgp_fill_static ()\n");
  //snmp_log("bgp_fill_static: vb->type %u, ptk %02x", vb->type, *((u32 *) pkt));

  struct oid *oid = &vb->name;
  //snmp_oid_dump(oid);
  //snmp_log("bgp_fill_static");

  /*
   * snmp_bgp_state() check only prefix. To be sure on OID equivalence we need to
   * compare the oid->n_subid length. All BGP static fields have same n_subid.
   */
  if (oid_state_compare(oid, state) < 0 || state == BGP_INTERNAL_END)
  {
    vb->type = AGENTX_NO_SUCH_OBJECT;
    return pkt + snmp_varbind_header_size(vb);
  }
  else if (oid_state_compare(oid, state) > 0)
  {
    vb->type = AGENTX_NO_SUCH_INSTANCE;
    return pkt + snmp_varbind_header_size(vb);
  }

  switch (state)
  {
    case BGP_INTERNAL_VERSION:
      pkt = snmp_varbind_nstr(vb, size, BGP4_VERSIONS, 1);
      break;

    case BGP_INTERNAL_LOCAL_AS:
      pkt = snmp_varbind_int(vb, size, p->bgp_local_as);
      break;

    case BGP_INTERNAL_IDENTIFIER:
      // TODO make a check
      pkt = snmp_varbind_ip4(vb, size, ipa_to_ip4(p->bgp_local_id));
      break;

    default:
      vb->type = AGENTX_NO_SUCH_OBJECT;
      pkt += snmp_varbind_header_size(vb);
      break;
  }

#if 0
  snmp_log("bgp_fill_static: type %u  packet %p", vb->type, pkt);
  //snmp_oid_dump(oid);

  /*snmp_log("snmp ended with non empty pkt %u starting from %p to %p\n", pkt -
temp, temp, pkt);
*/
  //snmp_dump_packet(temp, pkt - temp);
#endif
  return pkt;
}

void
snmp_bgp_fill(struct snmp_proto *p, struct agentx_varbind *vb,
	      struct snmp_pdu *c)
{
  u8 state = snmp_bgp_state(&vb->name);

  byte *pkt;
  if (is_static(state))
  {
    pkt = bgp_fill_static(p, vb, c->buffer, c->size, c->context, c->byte_ord, state);
    ADVANCE(c->buffer, c->size, pkt - c->buffer);
    return;
  }

  if (is_dynamic(state))
  {
    pkt = bgp_fill_dynamic(p, vb, c, state);
    ADVANCE(c->buffer, c->size, pkt - c->buffer);
    return;
  }

  vb->type = AGENTX_NO_SUCH_OBJECT;  // TODO
  ADVANCE(c->buffer, c->size, snmp_varbind_header_size(vb));
}

#if 0
int
snmp_bgp_testset(struct snmp_proto *p, const struct agentx_varbind *vb, void *tr, struct oid *oid, uint pkt_size)
{
  // TODO: check the type of varbind vb and it's value correctness, don't overflow the pkt_size
  return 0;
}
#endif

