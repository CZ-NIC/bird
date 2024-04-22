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

/* hash table macros */
#define SNMP_HASH_KEY(n)  n->peer_ip
#define SNMP_HASH_NEXT(n) n->next
#define SNMP_HASH_EQ(ip1, ip2) ip4_equal(ip1, ip2)
#define SNMP_HASH_FN(ip)  ip4_hash(ip)

#define SNMP_HASH_LESS4(ip1, ip2) ip4_less(ip1, ip2)
#define SNMP_HASH_LESS6(ip1, ip2) ip6_less(ip1, ip2)

/* hash table only store ip4 addresses */
#define SNMP_HASH_LESS(ip1, ip2) SNMP_HASH_LESS4(ip1,ip2)


/* Simply discard type */
#define SNMP_MANAGE_TBUF(p, vb, c) snmp_manage_tbuf(p, (void **) vb, c)

static inline void ip4_to_oid(struct oid *oid, ip4_addr addr);


static inline void
snmp_hash_add_peer(struct snmp_proto *p, struct snmp_bgp_peer *peer)
{
  HASH_INSERT(p->bgp_hash, SNMP_HASH, peer);
}

static inline struct snmp_bgp_peer *
snmp_hash_find(struct snmp_proto *p, ip4_addr key)
{
  return HASH_FIND(p->bgp_hash, SNMP_HASH, key);
}

static inline void
snmp_bgp_last_error(const struct bgp_proto *bgp, char err[2])
{
  err[0] = bgp->last_error_code & 0x00FF0000 >> 16;
  err[1] = bgp->last_error_code & 0x000000FF;
}

static u8
bgp_get_candidate(u32 field)
{
  const u8 translation_table[] = {
    [BGP4_MIB_PEER_IDENTIFIER]		= BGP4_MIB_S_PEER_IDENTIFIER,
    [BGP4_MIB_STATE]			= BGP4_MIB_S_STATE,
    [BGP4_MIB_ADMIN_STATUS]		= BGP4_MIB_S_ADMIN_STATUS,
    [BGP4_MIB_NEGOTIATED_VERSION]	= BGP4_MIB_S_NEGOTIATED_VERSION,
    [BGP4_MIB_LOCAL_ADDR]		= BGP4_MIB_S_LOCAL_ADDR,
    [BGP4_MIB_LOCAL_PORT]		= BGP4_MIB_S_LOCAL_PORT,
    [BGP4_MIB_REMOTE_ADDR]		= BGP4_MIB_S_REMOTE_ADDR,
    [BGP4_MIB_REMOTE_PORT]		= BGP4_MIB_S_REMOTE_PORT,
    [BGP4_MIB_REMOTE_AS]		= BGP4_MIB_S_REMOTE_AS,
    [BGP4_MIB_RX_UPDATES]		= BGP4_MIB_S_RX_UPDATES,
    [BGP4_MIB_TX_UPDATES]		= BGP4_MIB_S_TX_UPDATES,
    [BGP4_MIB_RX_MESSAGES]		= BGP4_MIB_S_RX_MESSAGES,
    [BGP4_MIB_TX_MESSAGES]		= BGP4_MIB_S_TX_MESSAGES,
    [BGP4_MIB_LAST_ERROR]		= BGP4_MIB_S_LAST_ERROR,
    [BGP4_MIB_FSM_TRANSITIONS]		= BGP4_MIB_S_FSM_TRANSITIONS,
    [BGP4_MIB_FSM_ESTABLISHED_TIME]	= BGP4_MIB_S_FSM_ESTABLISHED_TIME,
    [BGP4_MIB_RETRY_INTERVAL]		= BGP4_MIB_S_RETRY_INTERVAL,
    [BGP4_MIB_HOLD_TIME]		= BGP4_MIB_S_HOLD_TIME,
    [BGP4_MIB_KEEPALIVE]		= BGP4_MIB_S_KEEPALIVE,
    [BGP4_MIB_HOLD_TIME_CONFIGURED]	= BGP4_MIB_S_HOLD_TIME_CONFIGURED,
    [BGP4_MIB_KEEPALIVE_CONFIGURED]     = BGP4_MIB_S_KEEPALIVE_CONFIGURED,
    [BGP4_MIB_ORIGINATION_INTERVAL]     = BGP4_MIB_S_ORIGINATION_INTERVAL,
    [BGP4_MIB_MIN_ROUTE_ADVERTISEMENT]  = BGP4_MIB_S_MIN_ROUTE_ADVERTISEMENT,
    [BGP4_MIB_IN_UPDATE_ELAPSED_TIME]   = BGP4_MIB_S_IN_UPDATE_ELAPSED_TIME,
  };

  /*
   * First value is in secord cell of array translation_table, as the
   * SNMP_BPG_IDENTIFIER == 1
   */
  if (field > 0 && field <= ARRAY_SIZE(translation_table)- 1)
    return translation_table[field];
  else if (field == 0)
    return BGP4_MIB_S_PEER_ENTRY;
  else
    return BGP4_MIB_S_PEER_TABLE_END;
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
    return BGP4_MIB_S_END;

  u8 state = BGP4_MIB_S_NO_VALUE;

  u8 candidate;
  switch (oid->n_subid)
  {
    default:
      if (oid->n_subid < 2)
      {
	state = BGP4_MIB_S_INVALID;
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
      if (oid->ids[3] == BGP4_MIB_PEER_ENTRY)
	state = (state == BGP4_MIB_S_NO_VALUE) ?
	  BGP4_MIB_S_PEER_ENTRY : state;
      else
	state = BGP4_MIB_S_NO_VALUE;

      /* fall through */

    case 3:
      /* u8 candidate; */
      switch (oid->ids[2])
      {

	case BGP4_MIB_VERSION:
	  state = BGP4_MIB_S_VERSION;
	  break;
	case BGP4_MIB_LOCAL_AS:
	  state = BGP4_MIB_S_LOCAL_AS;
	  break;
	case BGP4_MIB_PEER_TABLE:
	  /* We use candidate to avoid overriding more specific state */
	  candidate = BGP4_MIB_S_PEER_TABLE;
	  break;
	case BGP4_MIB_IDENTIFIER:
	  state = BGP4_MIB_S_IDENTIFIER;
	  break;

	default:  /* test fails */
	  /* We force state invalidation */
	  if (oid->ids[2] < BGP4_MIB_VERSION)
	  {
	    state = BGP4_MIB_S_NO_VALUE;
	    candidate = BGP4_MIB_S_NO_VALUE;
	  }
	  else /* oid->ids[2] > BGP4_MIB_PEER_TABLE */
	    state = BGP4_MIB_S_END;
      }
      state = (state == BGP4_MIB_S_NO_VALUE) ?
	candidate : state;

      /* fall through */

    case 2: /* We found bare BGP4-MIB::bgp ObjectId */
      if (state == BGP4_MIB_S_NO_VALUE ||
	  state == BGP4_MIB_S_INVALID)
	state = BGP4_MIB_S_BGP;
  }

  return state;
}

void
snmp_bgp_reg_ok(struct snmp_proto *p, struct agentx_response *r, struct oid *oid)
{
  (void)p;
  (void)r;
  (void)oid;
  /* TODO: EXPENSIVE_CHECK() that
  const struct oid *in_buf = ((void *) r) + sizeof(r);
  struct oid *dup = snmp_prefixize(p, in_buf);
    ASSUME(snmp_bgp_state(oid) == snmp_bgp_state(dup));
  mb_free(dup);
   */
}

void
snmp_bgp_reg_failed(struct snmp_proto *p, struct agentx_response UNUSED *r, struct oid UNUSED *oid)
{
  // TODO add more sensible action
  snmp_stop_subagent(p);
}

/*
 * snmp_bgp_notify_common - common functionaly for BGP4-MIB notifications
 * @p: SNMP protocol instance
 * @type: type of notification send - either established or backward transition
 * @ip4: IPv4 remote addr
 * @last_error: 2 bytes of BGP last error
 * @state_val: BGP peer state as defined in MIB
 */
static void
snmp_bgp_notify_common(struct snmp_proto *p, uint type, ip4_addr ip4, char last_error[], uint state_val)
{
  uint sz = (uint) (snmp_varbind_size_from_len(9, AGENTX_IP_ADDRESS, 0)
      + snmp_varbind_size_from_len(9, AGENTX_OCTET_STRING, 2)
      + snmp_varbind_size_from_len(9, AGENTX_INTEGER, 0));

  u32 trap_ids[] = { 1, 0, type };
  STATIC_ASSERT(ARRAY_SIZE(trap_ids) == 3);
  /* additional size for trap identification, here either
   *  bgpEstablishedNotification or bgpBackwardTransNotification (see below) */
  void *data = tmp_alloc(snmp_oid_size_from_len(ARRAY_SIZE(trap_ids)) + sz);
  struct oid *head = data;

  { /* trap id BGP4-MIB::bgpEstablishedNotification (.1.3.6.1.2.15.0.1)
     *	or BGP4-MIB::bgpBackwardTransNotification (.1.3.6.1.2.15.0.2) */
    head->n_subid = ARRAY_SIZE(trap_ids);
    head->prefix = SNMP_MGMT;
    head->include = head->reserved = 0;

    for (uint i = 0; i < head->n_subid; i++)
      head->ids[i] = trap_ids[i];
  }

  data += sz;
  struct agentx_varbind *addr_vb = data;
  struct agentx_varbind *error_vb = \
    data + snmp_varbind_size_from_len(9, AGENTX_IP_ADDRESS, 0);
  struct agentx_varbind *state_vb = \
    (void *) error_vb + snmp_varbind_size_from_len(9, AGENTX_OCTET_STRING, 2);

  u32 oid_ids[] = {
    SNMP_MIB_2, BGP4_MIB, BGP4_MIB_PEER_TABLE, BGP4_MIB_PEER_ENTRY
  };

  /*
   * The n_subid is 9 in all cases because all are rows entries of
   * BGP4-MIB::bgpPeerTable
   *  BGP4-MIB::bgpPeerRemoteAddr = .1.3.6.1.[2].1.15.3.1.7.a.b.c.d
   * where .1.3.6.1 is internet prefix, .[2] is SNMP_MGMT,
   * .1.15.3.1.7.a.b.c.d has 9 elements (a.b.c.d are IP addr bytes)
   *  Here subidentifier 7 is entry type bgpPeerRemoteAddr.
   */
  #define PEER_TABLE_ENTRY 9
  #define ENTRY_TYPE 4

  { /* BGP4-MIB::bgpPeerRemoteAddr */
    struct oid *addr = &addr_vb->name;
    *addr = (struct oid) {
      .n_subid = PEER_TABLE_ENTRY, .prefix = SNMP_MGMT, .include = 0,
      .reserved = 0,
    };
    for (uint i = 0; i < ARRAY_SIZE(oid_ids); i++)
      addr->ids[i] = oid_ids[i];
    addr->ids[ENTRY_TYPE] = BGP4_MIB_REMOTE_ADDR;
    ip4_to_oid(addr, ip4);
  }
  /* We have enough space inside the TX-buffer prepared */
  struct snmp_pdu sink = { 0 };
  snmp_varbind_ip4(addr_vb, &sink, ip4);

  { /* BGP4-MIB::bgpPeerLastError */
    struct oid *error = &error_vb->name;
    *error = (struct oid) {
      .n_subid = PEER_TABLE_ENTRY, .prefix = SNMP_MGMT, .include = 0,
      .reserved = 0,
    };
    for (uint i = 0; i < ARRAY_SIZE(oid_ids); i++)
      error->ids[i] = oid_ids[i];
    error->ids[ENTRY_TYPE] = BGP4_MIB_LAST_ERROR;
    ip4_to_oid(error, ip4);
  }
  snmp_varbind_nstr(error_vb, &sink, last_error, 2);

  { /* BGP4-MIB::bgpPeerState */
    struct oid *state = &state_vb->name;
    *state = (struct oid) {
      .n_subid = PEER_TABLE_ENTRY, .prefix = SNMP_MGMT, .include = 0,
      .reserved = 0,
    };
    for (uint i = 0; i < ARRAY_SIZE(oid_ids); i++)
      state->ids[i] = oid_ids[i];
    state->ids[ENTRY_TYPE] = BGP4_MIB_STATE;
    ip4_to_oid(state, ip4);
  }
  snmp_varbind_int(state_vb, &sink, state_val);

  /* We do not send the systemUpTime.0 */
  snmp_notify_pdu(p, head, data, sz, 0);

  #undef OID_N_SUBID
}

/*
 * snmp_bgp_fsm_state - extract BGP FSM state for SNMP BGP4-MIB
 * @bgp_proto: BGP instance
 *
 * Return FSM state in BGP4-MIB encoding
 */
static inline uint
snmp_bgp_fsm_state(const struct bgp_proto *bgp_proto)
{
  const struct bgp_conn *bgp_conn = bgp_proto->conn;
  const struct bgp_conn *bgp_in = &bgp_proto->incoming_conn;
  const struct bgp_conn *bgp_out = &bgp_proto->outgoing_conn;

  if (bgp_conn)
    return bgp_conn->state + 1;

  if (MAX(bgp_in->state, bgp_out->state) == BS_CLOSE &&
      MIN(bgp_in->state, bgp_out->state) != BS_CLOSE)
    return MIN(bgp_in->state, bgp_out->state) + 1;
  if (MIN(bgp_in->state, bgp_out->state) == BS_CLOSE)
    return BS_IDLE;

  return MAX(bgp_in->state, bgp_out->state) + 1;
}

static void
snmp_bgp_notify_wrapper(struct snmp_proto *p, struct bgp_proto *bgp, uint type)
{
  /* possibly incorrect cast */
  ip4_addr ip4 = ipa_to_ip4(bgp->remote_ip);
  char last_error[2];
  snmp_bgp_last_error(bgp, last_error);
  uint state_val = snmp_bgp_fsm_state(bgp);
  snmp_bgp_notify_common(p, type, ip4, last_error, state_val);
}

void
snmp_bgp_notify_established(struct snmp_proto *p, struct bgp_proto *bgp)
{
  snmp_bgp_notify_wrapper(p, bgp, BGP4_MIB_ESTABLISHED_NOTIFICATION);
}

void
snmp_bgp_notify_backward_trans(struct snmp_proto *p, struct bgp_proto *bgp)
{
  snmp_bgp_notify_wrapper(p, bgp, BGP4_MIB_BACKWARD_TRANS_NOTIFICATION);
}

void
snmp_bgp_register(struct snmp_proto *p)
{
  u32 bgp_mib_prefix[] = { 1, 15 };

  {
    /* Register the whole BGP4-MIB::bgp root tree node */
    struct snmp_registration *reg;
    reg = snmp_registration_create(p, BGP4_MIB);

    struct oid *oid = mb_allocz(p->pool,
      snmp_oid_size_from_len(ARRAY_SIZE(bgp_mib_prefix)));
    STORE_U8(oid->n_subid, ARRAY_SIZE(bgp_mib_prefix));
    STORE_U8(oid->prefix, SNMP_MGMT);

    memcpy(oid->ids, bgp_mib_prefix, sizeof(bgp_mib_prefix));
    reg->oid = oid;

    /*
     * We set both upper bound and index to zero, therefore only single OID
     * is being registered.
     */
    snmp_register(p, oid, 0, 0, SNMP_REGISTER_TREE, SNMP_DEFAULT_CONTEXT);
  }
}

static int
snmp_bgp_valid_ip4(struct oid *o)
{
  return snmp_valid_ip4_index(o, 5);
}


static inline ip4_addr
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
print_bgp_record(const struct bgp_proto *bgp_proto)
{
  //struct proto_config *cf = bgp_proto->p.cf;
  struct bgp_conn *conn = bgp_proto->conn;

  DBG("    name: %s", cf->name);
  DBG(".");
  DBG("    rem. identifier: %u", bgp_proto->remote_id);
  DBG("    local ip: %I", config->local_ip);
  DBG("    remote ip: %I", config->remote_ip);
  DBG("    local port: %u", config->local_port);
  DBG("    remote port: %u", config->remote_port);

  if (conn) {
    DBG("    state: %u", conn->state);
    DBG("    remote as: %u", conn->remote_caps->as4_number);
  }

  DBG("    in updates: %u", bgp_proto->stats.rx_updates);
  DBG("    out updates: %u", bgp_proto->stats.tx_updates);
  DBG("    in total: %u", bgp_proto->stats.rx_messages);
  DBG("    out total: %u", bgp_proto->stats.tx_messages);
  DBG("    fsm transitions: %u",
      bgp_proto->stats.fsm_established_transitions);

  DBG("    fsm total time: -- (0)");   // not supported by bird
  DBG("    retry interval: %u", config->connect_retry_time);

  DBG("    hold configurated: %u", config->hold_time );
  DBG("    keep alive config: %u", config->keepalive_time );

  DBG("    min AS origin. int.: -- (0)");	// not supported by bird
  DBG("    min route advertisement: %u", 0 );
  DBG("    in update elapsed time: %u", 0 );

  if (!conn)
    DBG("  no connection established");

  DBG("  outgoinin_conn state %u", bgp_proto->outgoing_conn.state + 1);
  DBG("  incoming_conn state: %u", bgp_proto->incoming_conn.state + 1);
}

static void UNUSED
print_bgp_record_all(struct snmp_proto *p)
{
  DBG("dumping watched bgp status");
  HASH_WALK(p->bgp_hash, next, peer)
  {
    print_bgp_record(peer->bgp_proto);
  }
  HASH_WALK_END;
  DBG("dumping watched end");
}



/*
 * is_dynamic - is state dependent on runtime BGP peer state
 * @state: tested bgp4_mib state
 *
 * Used to distinguish states that depend on runtime BGP peer states.
 *
 * Return nonzero for states with value that may change at runtime.
 */
static inline int
is_dynamic(u8 state)
{
  return (state >= BGP4_MIB_S_PEER_IDENTIFIER &&
	  state <= BGP4_MIB_S_IN_UPDATE_ELAPSED_TIME);
}

/*
 * is_static - logical inverse of is_dynamic() for states with value
 * @state: tested bgp4_mib state
 *
 * Return nonzero for states with value that do not change at runtime.
 */
static inline int
is_static(u8 state)
{
  return (state == BGP4_MIB_S_VERSION ||
	  state == BGP4_MIB_S_LOCAL_AS ||
	  state == BGP4_MIB_S_IDENTIFIER);
}

static inline int
snmp_bgp_has_value(u8 state)
{
  if (state <= BGP4_MIB_S_BGP ||
      state == BGP4_MIB_S_PEER_TABLE ||
      state == BGP4_MIB_S_PEER_ENTRY ||
      state == BGP4_MIB_S_PEER_TABLE_END ||
      state >= BGP4_MIB_S_END)
    return 0;
  else
    return 1;
}

/**
 * snmp_bgp_get_valid - only states with valid value
 * @state: BGP linearized state
 *
 * Returns @state if has value in BGP4-MIB, zero otherwise. Used for Get-PDU
 * packets.
 */
u8
snmp_bgp_get_valid(u8 state)
{
  if (state == BGP4_MIB_S_INVALID ||
      state == BGP4_MIB_S_BGP ||
      state == BGP4_MIB_S_PEER_TABLE ||
      state == BGP4_MIB_S_PEER_ENTRY ||
      state == BGP4_MIB_S_PEER_TABLE_END ||
      state >= BGP4_MIB_S_END)
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
    case BGP4_MIB_S_LOCAL_AS:
    case BGP4_MIB_S_PEER_TABLE:
    case BGP4_MIB_S_PEER_ENTRY:
      return BGP4_MIB_S_PEER_IDENTIFIER;

    case BGP4_MIB_S_IN_UPDATE_ELAPSED_TIME:
    case BGP4_MIB_S_PEER_TABLE_END:
      return BGP4_MIB_S_IDENTIFIER;

    case BGP4_MIB_S_IDENTIFIER:
    case BGP4_MIB_S_END:
      return BGP4_MIB_S_END;

    default:
      return state + 1;
  }
}

static int
oid_state_compare(const struct oid *oid, u8 state)
{
  ASSUME(oid != NULL);
  if (state >= BGP4_MIB_S_PEER_IDENTIFIER &&
      state <= BGP4_MIB_S_IN_UPDATE_ELAPSED_TIME)
    return (oid->n_subid > 9) - (oid->n_subid < 9);
  if ((state >= BGP4_MIB_S_VERSION && state <= BGP4_MIB_S_PEER_TABLE) ||
      (state == BGP4_MIB_S_IDENTIFIER))
    return (oid->n_subid > 3) - (oid->n_subid < 3);
  if (state == BGP4_MIB_S_PEER_ENTRY)
    return (oid->n_subid > 4) - (oid->n_subid < 4);
  if (state == BGP4_MIB_S_BGP)
    return (oid->n_subid > 2) - (oid->n_subid < 2);

  return -1;
}

static struct oid *
update_bgp_vb(struct snmp_proto *p, struct agentx_varbind **vb, u8 state, struct snmp_pdu *c)
{
  struct oid *oid = &(*vb)->name;

  if (state == BGP4_MIB_S_END || state == BGP4_MIB_S_INVALID ||
      state == BGP4_MIB_S_NO_VALUE)
    return &(*vb)->name;

  /* No need to reallocate anything if the OID has same lin. state */
  if (snmp_bgp_state(oid) == state)
  {
    if (state >= BGP4_MIB_S_PEER_IDENTIFIER &&
	state <= BGP4_MIB_S_IN_UPDATE_ELAPSED_TIME &&
	oid->n_subid == 9)
      return oid;
    if (state >= BGP4_MIB_S_VERSION &&
	state <= BGP4_MIB_S_PEER_TABLE && oid->n_subid == 3)
      return oid;
    if (state == BGP4_MIB_S_PEER_ENTRY && oid->n_subid == 4)
      return oid;
    if (state == BGP4_MIB_S_BGP && oid->n_subid == 2)
      return oid;
  }

  switch (state)
  {
    case BGP4_MIB_S_BGP:
      /* This could potentially destroy same old data */
      if (oid->n_subid != 2)
	oid = snmp_varbind_set_name_len(p, vb, 2, c);

      oid->ids[0] = SNMP_MIB_2;
      oid->ids[1] = BGP4_MIB;
      break;

    case BGP4_MIB_S_VERSION:
      if (oid->n_subid != 3)
	oid = snmp_varbind_set_name_len(p, vb, 3, c);

      oid->ids[2] = BGP4_MIB_VERSION;
      break;

    case BGP4_MIB_S_LOCAL_AS:
      if (oid->n_subid != 3)
	oid =snmp_varbind_set_name_len(p, vb, 3, c);

      oid->ids[2] = BGP4_MIB_LOCAL_AS;
      break;

    case BGP4_MIB_S_PEER_IDENTIFIER:
      if (oid->n_subid != 9)
      {
	u8 n_subid = LOAD_U8(oid->n_subid);
	oid = snmp_varbind_set_name_len(p, vb, 9, c);

	if (n_subid < 6)
	  oid->ids[5] = 0;
	if (n_subid < 7)
	  oid->ids[6] = 0;
	if (n_subid < 8)
	  oid->ids[7] = 0;
	if (n_subid < 9)
	  oid->ids[8] = 0;
      }

      oid->ids[2] = BGP4_MIB_PEER_TABLE;
      oid->ids[3] = BGP4_MIB_PEER_ENTRY;

      oid->ids[4] = BGP4_MIB_PEER_IDENTIFIER;
      break;

#define SNMP_UPDATE_CASE(num, update)					    \
    case num:								    \
      if (oid->n_subid != 9)						    \
      {									    \
	u8 n_subid = LOAD_U8(oid->n_subid);				    \
	oid = snmp_varbind_set_name_len(p, vb, 9, c);			    \
									    \
	if (n_subid < 6)						    \
	  oid->ids[5] = 0;						    \
	if (n_subid < 7)						    \
	  oid->ids[6] = 0;						    \
	if (n_subid < 8)						    \
	  oid->ids[7] = 0;						    \
	if (n_subid < 9)						    \
	  oid->ids[8] = 0;						    \
      }									    \
									    \
      oid->n_subid = 9;							    \
      oid->ids[4] = update;						    \
      break;

    SNMP_UPDATE_CASE(BGP4_MIB_S_STATE, BGP4_MIB_STATE)

    SNMP_UPDATE_CASE(BGP4_MIB_S_ADMIN_STATUS, BGP4_MIB_ADMIN_STATUS)

    SNMP_UPDATE_CASE(BGP4_MIB_S_NEGOTIATED_VERSION, BGP4_MIB_NEGOTIATED_VERSION)

    SNMP_UPDATE_CASE(BGP4_MIB_S_LOCAL_ADDR, BGP4_MIB_LOCAL_ADDR)

    SNMP_UPDATE_CASE(BGP4_MIB_S_LOCAL_PORT, BGP4_MIB_LOCAL_PORT)

    SNMP_UPDATE_CASE(BGP4_MIB_S_REMOTE_ADDR, BGP4_MIB_REMOTE_ADDR)

    SNMP_UPDATE_CASE(BGP4_MIB_S_REMOTE_PORT, BGP4_MIB_REMOTE_PORT)

    SNMP_UPDATE_CASE(BGP4_MIB_S_REMOTE_AS, BGP4_MIB_REMOTE_AS)

    SNMP_UPDATE_CASE(BGP4_MIB_S_RX_UPDATES, BGP4_MIB_RX_UPDATES)

    SNMP_UPDATE_CASE(BGP4_MIB_S_TX_UPDATES, BGP4_MIB_TX_UPDATES)

    SNMP_UPDATE_CASE(BGP4_MIB_S_RX_MESSAGES, BGP4_MIB_RX_MESSAGES)

    SNMP_UPDATE_CASE(BGP4_MIB_S_TX_MESSAGES, BGP4_MIB_TX_MESSAGES)

    SNMP_UPDATE_CASE(BGP4_MIB_S_LAST_ERROR, BGP4_MIB_LAST_ERROR)

    SNMP_UPDATE_CASE(BGP4_MIB_S_FSM_TRANSITIONS, BGP4_MIB_FSM_TRANSITIONS)

    SNMP_UPDATE_CASE(BGP4_MIB_S_FSM_ESTABLISHED_TIME, BGP4_MIB_FSM_ESTABLISHED_TIME)

    SNMP_UPDATE_CASE(BGP4_MIB_S_RETRY_INTERVAL, BGP4_MIB_RETRY_INTERVAL)

    SNMP_UPDATE_CASE(BGP4_MIB_S_HOLD_TIME, BGP4_MIB_HOLD_TIME)

    SNMP_UPDATE_CASE(BGP4_MIB_S_KEEPALIVE, BGP4_MIB_KEEPALIVE)

    SNMP_UPDATE_CASE(BGP4_MIB_S_HOLD_TIME_CONFIGURED, BGP4_MIB_HOLD_TIME_CONFIGURED)

    SNMP_UPDATE_CASE(BGP4_MIB_S_KEEPALIVE_CONFIGURED, BGP4_MIB_KEEPALIVE_CONFIGURED)

    SNMP_UPDATE_CASE(BGP4_MIB_S_ORIGINATION_INTERVAL, BGP4_MIB_ORIGINATION_INTERVAL)

    SNMP_UPDATE_CASE(BGP4_MIB_S_MIN_ROUTE_ADVERTISEMENT, BGP4_MIB_MIN_ROUTE_ADVERTISEMENT)

    SNMP_UPDATE_CASE(BGP4_MIB_S_IN_UPDATE_ELAPSED_TIME, BGP4_MIB_IN_UPDATE_ELAPSED_TIME)

    case BGP4_MIB_S_IDENTIFIER:
      if (oid->n_subid != 3)
	oid = snmp_varbind_set_name_len(p, vb, 3, c);

      oid->n_subid = 3;
      oid->ids[2] = 4;
      break;

    default:
      /* intentionally left blank */
      break;
  }

  return oid;
#undef SNMP_UPDATE_CASE
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

  net_addr net;
  net_fill_ip4(&net, ip4, IP4_MAX_PREFIX_LENGTH);
  struct f_trie_walk_state ws;

  int match = trie_walk_init(&ws, p->bgp_trie, &net, 1);

  if (match && oid->include)
  {
    oid->include = 0;
    return 1;
  }

  /* We skip the first match as we should not include ip address in oid */
  if (match)
  {
    trie_walk_next(&ws, &net);
  }

  if (trie_walk_next(&ws, &net))
  {
    ASSUME(oid->n_subid == 9);
    ip4_addr res = ipa_to_ip4(net_prefix(&net));
    ip4_to_oid(oid, res);
    return 1;
  }

  return 0;
}

static enum snmp_search_res UNUSED
snmp_bgp_search_dynamic(struct snmp_proto *p, struct oid **searched, const struct oid *o_end, uint UNUSED contid, u8 next_state, struct snmp_pdu *c)
{
  struct oid *oid = *searched;
  u8 end_state = MIN(snmp_bgp_state(o_end), BGP4_MIB_S_PEER_TABLE_END);

  ASSUME(end_state <= BGP4_MIB_S_END);
  ASSUME(oid != NULL);

  // TODO TODO remove me
  struct agentx_varbind data = { 0 };
  struct agentx_varbind *vb = &data;

  oid = update_bgp_vb(p, &vb, next_state, c);
  //oid = update_bgp_oid(oid, next_state);

  int found;
  while (!(found = snmp_bgp_find_next_oid(p, oid, contid)) && next_state <= end_state)
  {
    next_state = snmp_bgp_next_state(next_state);
    if (next_state == BGP4_MIB_S_IDENTIFIER)
      break;
    //oid = update_bgp_oid(oid, next_state);
    oid = update_bgp_vb(p, &vb, next_state, c);
    /* In case of search for next bgp state, we want to start from beginning. */
    oid->ids[5] = oid->ids[6] = oid->ids[7] = oid->ids[8] = 0;
  }

  if (next_state < BGP4_MIB_S_PEER_TABLE_END && next_state <= end_state)
  {
    *searched = oid;
    return SNMP_SEARCH_OK;
  }

  return SNMP_SEARCH_END_OF_VIEW;
}

enum snmp_search_res
snmp_bgp_search(struct snmp_proto *p, struct agentx_varbind **vb_search, const struct oid *o_end, struct snmp_pdu *c)
{
  (void)p;
  (void)vb_search;
  (void)o_end;
  (void)c;
  return SNMP_SEARCH_END_OF_VIEW;
#if 0
  enum snmp_search_res r = SNMP_SEARCH_END_OF_VIEW;
  u8 bgp_state = snmp_bgp_state(*searched);
  u8 state;

  if (bgp_state == BGP4_MIB_S_END)
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
    for (uint i = 5; i < MIN(9, (*searched)->n_subid); i++)
      (*searched)->ids[i] = 0;
    r = snmp_bgp_search_dynamic(p, searched, o_end, contid, state);
    if (r != SNMP_SEARCH_END_OF_VIEW)
      return r;
  }

  if (is_dynamic(bgp_state))
  {
    r = snmp_bgp_search_dynamic(p, searched, o_end, contid, bgp_state);

    if (r != SNMP_SEARCH_END_OF_VIEW)
      return r;
  }

  state = snmp_bgp_next_state(bgp_state);
  if (state <= BGP4_MIB_S_IDENTIFIER)
  {
    *searched = update_bgp_oid(*searched, state);
    return SNMP_SEARCH_OK;
  }

  // TODO add route table

  /* end not found */
  return SNMP_SEARCH_END_OF_VIEW;
#endif
}

static void
bgp_fill_dynamic(struct snmp_proto *p, struct agentx_varbind **vb, struct snmp_pdu *c, u8 state)
{
  struct oid *oid = &(*vb)->name;
  //byte *pkt;

  ip4_addr addr;
  if (oid_state_compare(oid, state) == 0 && snmp_bgp_valid_ip4(oid))
    addr = ip4_from_oid(oid);
  else
    return snmp_set_varbind_type(*vb, AGENTX_NO_SUCH_INSTANCE);

  struct snmp_bgp_peer *pe = snmp_hash_find(p, addr);

  if (!pe)
    return snmp_set_varbind_type(*vb, AGENTX_NO_SUCH_INSTANCE);

  const struct bgp_proto *bgp_proto = pe->bgp_proto;
  if (!ipa_is_ip4(bgp_proto->remote_ip))
  {
    log(L_ERR, "%s: Found BGP protocol instance with IPv6 address", bgp_proto->p.name);
    c->error = AGENTX_RES_GEN_ERROR;
    return snmp_set_varbind_type(*vb, AGENTX_NO_SUCH_INSTANCE);
  }

  ip4_addr proto_ip = ipa_to_ip4(bgp_proto->remote_ip);
  if (!ip4_equal(proto_ip, pe->peer_ip))
  {
    /* Here, we could be in problem as the bgp_proto IP address could be changed */
    log(L_ERR, "%s: Stored hash key IP address and peer remote address differ.",
      bgp_proto->p.name);
    c->error = AGENTX_RES_GEN_ERROR;
    return snmp_set_varbind_type(*vb, AGENTX_NO_SUCH_INSTANCE);
  }

  const struct bgp_conn *bgp_conn = bgp_proto->conn;
  const struct bgp_stats *bgp_stats = &bgp_proto->stats;
  const struct bgp_config *bgp_conf = bgp_proto->cf;

  uint fsm_state = snmp_bgp_fsm_state(bgp_proto);

  char last_error[2];
  snmp_bgp_last_error(bgp_proto, last_error);

  snmp_set_varbind_type(*vb, AGENTX_NO_SUCH_INSTANCE);
  switch (state)
  {
    case BGP4_MIB_S_PEER_IDENTIFIER:
      if (c->size < AGENTX_TYPE_IP4_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      if (fsm_state == BGP4_MIB_OPENCONFIRM || fsm_state == BGP4_MIB_ESTABLISHED)
	// TODO last
	snmp_varbind_ip4(*vb, c, ip4_from_u32(bgp_proto->remote_id));
      else
	snmp_varbind_ip4(*vb, c, IP4_NONE);
      break;

    case BGP4_MIB_S_STATE:
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_int(*vb, c, fsm_state);
      break;

    case BGP4_MIB_S_ADMIN_STATUS:
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      if (bgp_proto->p.disabled)
	snmp_varbind_int(*vb, c, AGENTX_ADMIN_STOP);
      else
	snmp_varbind_int(*vb, c, AGENTX_ADMIN_START);

      break;

    case BGP4_MIB_S_NEGOTIATED_VERSION:
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      if (fsm_state == BGP4_MIB_ESTABLISHED || fsm_state == BGP4_MIB_ESTABLISHED)
	snmp_varbind_int(*vb, c, BGP4_MIB_NEGOTIATED_VER_VALUE);
      else
	snmp_varbind_int(*vb, c, BGP4_MIB_NEGOTIATED_VER_NO_VALUE);

      break;

    case BGP4_MIB_S_LOCAL_ADDR:
      if (c->size < AGENTX_TYPE_IP4_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_ip4(*vb, c, ipa_to_ip4(bgp_proto->local_ip));
      break;

    case BGP4_MIB_S_LOCAL_PORT:
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_int(*vb, c, bgp_conf->local_port);
      break;

    case BGP4_MIB_S_REMOTE_ADDR:
      if (c->size < AGENTX_TYPE_IP4_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_ip4(*vb, c, ipa_to_ip4(bgp_proto->remote_ip));
      break;

    case BGP4_MIB_S_REMOTE_PORT:
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_int(*vb, c, bgp_conf->remote_port);
      break;

    case BGP4_MIB_S_REMOTE_AS:
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_int(*vb, c, bgp_proto->remote_as);
      break;

    case BGP4_MIB_S_RX_UPDATES:	  /* bgpPeerInUpdates */
      if (c->size < AGENTX_TYPE_COUNTER32_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_counter32(*vb, c, bgp_stats->rx_updates);
      break;

    case BGP4_MIB_S_TX_UPDATES:	  /* bgpPeerOutUpdate */
      if (c->size < AGENTX_TYPE_COUNTER32_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_counter32(*vb, c, bgp_stats->tx_updates);
      break;

    case BGP4_MIB_S_RX_MESSAGES:  /* bgpPeerInTotalMessages */
      if (c->size < AGENTX_TYPE_COUNTER32_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_counter32(*vb, c, bgp_stats->rx_messages);
      break;

    case BGP4_MIB_S_TX_MESSAGES:  /* bgpPeerOutTotalMessages */
      if (c->size < AGENTX_TYPE_COUNTER32_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_counter32(*vb, c, bgp_stats->tx_messages);
      break;

    case BGP4_MIB_S_LAST_ERROR:
      if (c->size < snmp_str_size_from_len(2))
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_nstr(*vb, c, last_error, 2);
      break;

    case BGP4_MIB_S_FSM_TRANSITIONS:
      if (c->size < AGENTX_TYPE_COUNTER32_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_counter32(*vb, c,
	  bgp_stats->fsm_established_transitions);
      break;

    case BGP4_MIB_S_FSM_ESTABLISHED_TIME:
      if (c->size < AGENTX_TYPE_COUNTER32_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);


      snmp_varbind_gauge32(*vb, c,
	    (current_time() - bgp_proto->last_established) TO_S);
      break;

    case BGP4_MIB_S_RETRY_INTERVAL: /* retry inverval value should be != 0 */
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_int(*vb, c, bgp_conf->connect_retry_time);
      break;

    case BGP4_MIB_S_HOLD_TIME:	/* hold time should be == 0 or in 3..65535 */
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_int(*vb, c, (bgp_conn) ?  bgp_conn->hold_time : 0);
      break;

    case BGP4_MIB_S_KEEPALIVE:
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      if (!bgp_conf->hold_time)
	snmp_varbind_int(*vb, c, 0);
      else
	snmp_varbind_int(*vb, c,
	  (bgp_conn) ? bgp_conn->keepalive_time : 0);
      break;

    case BGP4_MIB_S_HOLD_TIME_CONFIGURED:
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_int(*vb, c, bgp_conf->hold_time);
      break;

    case BGP4_MIB_S_KEEPALIVE_CONFIGURED:
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);


      if (!bgp_conf->keepalive_time)
	snmp_varbind_int(*vb, c, 0);
      else
	snmp_varbind_int(*vb, c,
	  (bgp_conn) ? bgp_conn->keepalive_time : 0);
      break;

    case BGP4_MIB_S_ORIGINATION_INTERVAL:
      /* value should be in 1..65535 but is not supported by bird */
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_int(*vb, c, 0);
      break;

    case BGP4_MIB_S_MIN_ROUTE_ADVERTISEMENT:
      /* value should be in 1..65535 but is not supported by bird */
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_int(*vb, c, 0);
      break;

    case BGP4_MIB_S_IN_UPDATE_ELAPSED_TIME:
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_gauge32(*vb, c,
	(current_time() - bgp_proto->last_rx_update) TO_S
      );
      break;

    case BGP4_MIB_S_END:
      break;

    case BGP4_MIB_S_INVALID:
      break;

    case BGP4_MIB_S_BGP:
      break;
    case BGP4_MIB_S_PEER_TABLE:
      break;
    case BGP4_MIB_S_PEER_ENTRY:
      break;
    case BGP4_MIB_S_NO_VALUE:
      break;
  }
}


void
bgp_fill_static(struct snmp_proto *p, struct agentx_varbind **vb, struct snmp_pdu *c, u8 state)
{
  ASSUME(c->buffer == snmp_varbind_data(*vb));

  struct oid *oid = &(*vb)->name;

  /*
   * snmp_bgp_state() check only prefix. To be sure on OID equivalence we need to
   * compare the oid->n_subid length. All BGP static fields have same n_subid.
   */
  if (oid_state_compare(oid, state) < 0 || state == BGP4_MIB_S_END)
    snmp_set_varbind_type(*vb, AGENTX_NO_SUCH_OBJECT);
  else if (oid_state_compare(oid, state) > 0)
    snmp_set_varbind_type(*vb, AGENTX_NO_SUCH_INSTANCE);

  switch (state)
  {
    case BGP4_MIB_S_VERSION:;
      uint sz = snmp_str_size_from_len(1);
      if (c->size < sz)
	SNMP_MANAGE_TBUF(p, vb, c);

      c->size -= sz;
      snmp_varbind_nstr(*vb, c, BGP4_VERSIONS, 1);
      break;

    case BGP4_MIB_S_LOCAL_AS:
      if (c->size < AGENTX_TYPE_INT_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_int(*vb, c, p->bgp_local_as);
      break;

    case BGP4_MIB_S_IDENTIFIER:
      if (c->size < AGENTX_TYPE_IP4_SIZE)
	SNMP_MANAGE_TBUF(p, vb, c);

      snmp_varbind_ip4(*vb, c, p->bgp_local_id);
      break;

    default:
      snmp_set_varbind_type(*vb, AGENTX_NO_SUCH_OBJECT);
      break;
  }
}

void
snmp_bgp_fill(struct snmp_proto *p, struct agentx_varbind **vb, struct snmp_pdu *c)
{
  ASSERT(vb != NULL);
  u8 state = snmp_bgp_state(&((*vb)->name));

  if (is_static(state))
  {
    bgp_fill_static(p, vb, c, state);
    return;
  }

  if (is_dynamic(state))
  {
    bgp_fill_dynamic(p, vb, c, state);
    return;
  }

  snmp_set_varbind_type(*vb, AGENTX_NO_SUCH_OBJECT);
}

/*
 * snmp_bgp_start - prepare BGP4-MIB
 * @p - SNMP protocol instance holding memory pool
 *
 * This function create all runtime bindings to BGP procotol structures.
 * It is gruaranteed that the BGP protocols exist.
 */
void
snmp_bgp_start(struct snmp_proto *p)
{
  struct snmp_config *cf = SKIP_BACK(struct snmp_config, cf, p->p.cf);
  /* Create binding to BGP protocols */

  struct snmp_bond *b;
  WALK_LIST(b, cf->bgp_entries)
  {
    const struct bgp_config *bgp_config = (struct bgp_config *) b->config;
    const struct bgp_proto *bgp = SKIP_BACK(struct bgp_proto, p,
      bgp_config->c.proto);

    struct snmp_bgp_peer *peer = \
      mb_alloc(p->pool, sizeof(struct snmp_bgp_peer));

    peer->bgp_proto = bgp;
    peer->peer_ip = ipa_to_ip4(bgp->remote_ip);

    struct net_addr net;
    net_fill_ip4(&net, ipa_to_ip4(bgp->remote_ip), IP4_MAX_PREFIX_LENGTH);
    trie_add_prefix(p->bgp_trie, &net, IP4_MAX_PREFIX_LENGTH,
      IP4_MAX_PREFIX_LENGTH);

    snmp_hash_add_peer(p, peer);
  }
}
