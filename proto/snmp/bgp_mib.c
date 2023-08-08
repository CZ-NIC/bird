/*
 *	BIRD -- Simple Network Management Protocol (SNMP)
 *        BGP4-MIB bgpPeerTable
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/* BGP_MIB states see enum BGP_INTERNAL_STATES */

#include "snmp.h"
#include "snmp_utils.h"
#include "subagent.h"
#include "bgp_mib.h"

static const char * const debug_bgp_states[] UNUSED = {
  [BGP_INTERNAL_INVALID]		 = "BGP_INTERNAL_INVALID",
  [BGP_INTERNAL_BGP]			 = "BGP_INTERNAL_BGP",
  [BGP_INTERNAL_VERSION]		 = "BGP_INTERNAL_VERSION",
  [BGP_INTERNAL_LOCAL_AS]		 = "BGP_INTERNAL_LOCAL_AS",
  [BGP_INTERNAL_PEER_TABLE]		 = "BGP_INTERNAL_PEER_TABLE",
  [BGP_INTERNAL_PEER_ENTRY]		 = "BGP_INTERNAL_PEER_ENTRY",
  [BGP_INTERNAL_IDENTIFIER]		 = "BGP_INTERNAL_IDENTIFIER",
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
  [BGP_INTERNAL_END]			 = "BGP_INTERNAL_END",
  [BGP_INTERNAL_NO_VALUE]		 = "BGP_INTERNAL_NO_VALUE",
};

void
snmp_bgp_register(struct snmp_proto *p)
{
  snmp_log("snmp_bgp_register()");

  u32 bgp_mib_prefix[] = {1, 15, 1};

  { /* registering whole BGP4-MIB subtree */
    //snmp_log("snmp_proto %p (%p)", p, p->p.pool);

    struct snmp_register *registering = snmp_register_create(p, SNMP_BGP4_MIB);

    struct oid *oid = mb_alloc(p->p.pool, snmp_oid_sizeof(2));
    put_u8(&oid->n_subid, 2);
    put_u8(&oid->prefix, 2);

    memcpy(oid->ids, bgp_mib_prefix, 2 * sizeof(u32));

    registering->oid = oid;
    add_tail(&p->register_queue, &registering->n);
    p->register_to_ack++;

    /* snmp_register(struct snmp_proto *p, struct oid *oid, uint index, uint len, u8 is_instance) */
    snmp_register(p, oid, 0, 1, 0);
  }

  /*
  // TODO squash bgpVersion and bgpLocalAs to one PDU
  { / * registering BGP4-MIB::bgpVersion * /
    //snmp_log("snmp_proto %p (%p)", p, p->p.pool);
    struct snmp_register *registering = snmp_register_create(p, SNMP_BGP4_MIB);

    struct oid *oid = mb_alloc(p->p.pool, snmp_oid_sizeof(3));
    put_u8(&oid->n_subid, 3);
    put_u8(&oid->prefix, 2);

    memcpy(oid->ids, bgp_mib_prefix, 3 * sizeof(u32));

    registering->oid = oid;
    add_tail(&p->register_queue, &registering->n);
    p->register_to_ack++;

    snmp_register(p, oid, 0, 1);
  }

  { / * registering BGP4-MIB::bgpLocalAs * /
    struct snmp_register *registering = snmp_register_create(p, SNMP_BGP4_MIB);

    struct oid *oid = mb_alloc(p->p.pool, snmp_oid_sizeof(3));
    put_u8(&oid->n_subid, 3);
    put_u8(&oid->prefix, 2);

    memcpy(oid->ids, bgp_mib_prefix, 2 * sizeof(u32));
    STORE(oid->ids[2], 2);

    registering->oid = oid;
    add_tail(&p->register_queue, &registering->n);
    p->register_to_ack++;

    snmp_register(p, oid, 0, 1);
  }

  { / * registering BGP4-MIB::bgpPeerTable * /
    struct snmp_register *registering = snmp_register_create(p, SNMP_BGP4_MIB);

    struct oid *oid = mb_alloc(p->p.pool, snmp_oid_sizeof(3));
    put_u8(&oid->n_subid, 3);
    put_u8(&oid->prefix, 2);

    memcpy(oid->ids, bgp_mib_prefix, 2 * sizeof(u32));
    STORE(oid->ids[2], 3);

    registering->oid = oid;
    add_tail(&p->register_queue, &registering->n);
    p->register_to_ack++;

    snmp_register(p, oid, 0, 1);
  }

  / * register dynamic BGP4-MIB::bgpPeerEntry.* * /

  u32 bgp_peer_entry[] = { 1, 15, 3, 1, 1};
  snmp_log("before hash walk - registering dynamic parts");
  HASH_WALK(p->bgp_hash, next, peer)
  {
    struct snmp_register *registering = snmp_register_create(p, SNMP_BGP4_MIB);

    struct oid *oid = mb_alloc(p->p.pool, snmp_oid_sizeof(10));

    put_u8(&oid->n_subid, 9);
    put_u8(&oid->prefix, 2);

    memcpy(oid->ids, bgp_peer_entry, 5 * sizeof(u32));

    snmp_oid_ip4_index(oid, 5, ipa_to_ip4(peer->peer_ip));

    registering->oid = oid;
    add_tail(&p->register_queue, &registering->n);

    snmp_register(p, oid, 0, 1);
  }
  HASH_WALK_END;
  snmp_log("after hash walk");

  */
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
    [SNMP_BGP_IDENTIFIER]		= BGP_INTERNAL_IDENTIFIER,
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

  /* first value is in secord cell of array translation_table (as the
   * SNMP_BPG_IDENTIFIER == 1
   */
  if (field > 0 && field <= sizeof(translation_table) / sizeof(translation_table[0]))
    return translation_table[field];
  if (field == 0)
    return BGP_INTERNAL_INVALID;
  else
    return BGP_INTERNAL_END;
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

static void
print_bgp_record(struct bgp_config *config)
{
  struct proto_config *cf = (struct proto_config *) config;
  // struct proto *P = cf->proto;
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
  /* already checked:
   *          xxxxxxxx p
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
      /* else oid->n_subid >= 2 */
        /* fall through */

   /* between ids[5] and ids[8] (n_subid == 9) should be IP address
    * validity is checked later in execution because
    *  this field also could mean a query boundry (upper or lower)
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
	  /* candidate avoid overriding more specific state */
	  candidate = BGP_INTERNAL_PEER_TABLE;
	  break;


	default:  /* test fails */
	  /* invalidate the state forcefully */
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

    case 2: /* bare BGP4-MIB::bgp */
      if (state == BGP_INTERNAL_NO_VALUE ||
	  state == BGP_INTERNAL_INVALID)
	state = BGP_INTERNAL_BGP;
  }

  return state;
}

static inline int
is_dynamic(u8 state)
{
  return (state >= BGP_INTERNAL_IDENTIFIER &&
	  state <= BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME);
}

static inline int
snmp_bgp_has_value(u8 state)
{
  if (state <= BGP_INTERNAL_BGP ||
      state == BGP_INTERNAL_PEER_TABLE ||
      state == BGP_INTERNAL_PEER_ENTRY ||
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
  /* invalid
   * SNMP_BGP SNMP_BGP_PEER_TABLE SNMP_BGP_PEER_ENTRY
   * SNMP_BGP_FSM_ESTABLISHED_TIME SNMP_BGP_IN_UPDATE_ELAPSED_TIME
   */
  if (state == 1 || state == 4 || state == 5 ||
      state == 21 || state == 29)
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
      return BGP_INTERNAL_IDENTIFIER;

    case BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME:
    case BGP_INTERNAL_END:
      return BGP_INTERNAL_END;

    default:
      return state + 1;
  }
}

int
snmp_bgp_is_supported(struct oid *o)
{
  /* most likely not functioning */
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
	    /* do not include bgpPeerInUpdatesElapsedTime
	       and bgpPeerFsmEstablishedTime */
	   //&& o->ids[3] < SNMP_BGP_IN_UPDATE_ELAPSED_TIME
	   //&& o->ids[3] != SNMP_BGP_FSM_ESTABLISHED_TIME)
	      return 1;
    }
    else
      return 0;
  }

  return 0;
}

static int
oid_state_compare(const struct oid *oid, u8 state)
{
  ASSUME(oid != NULL);
  if (state >= BGP_INTERNAL_IDENTIFIER &&
      state <= BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME)
    return (oid->n_subid > 9) - (oid->n_subid < 9);
  if (state >= BGP_INTERNAL_VERSION && state <= BGP_INTERNAL_PEER_TABLE)
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
  snmp_log("update_bgp_oid()");
  if (state == BGP_INTERNAL_END || state == BGP_INTERNAL_INVALID ||
      state == BGP_INTERNAL_NO_VALUE)
    return oid;

  /* if same state, no need to realloc anything */
  if (snmp_bgp_state(oid) == state)
  {
    if (state >= BGP_INTERNAL_IDENTIFIER &&
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

  snmp_log("update work");
  switch (state)
  {
    case BGP_INTERNAL_BGP:
      /* could destroy same old data */
      if (oid->n_subid != 2)
      {
	snmp_log("realloc");
	oid = mb_realloc(oid, snmp_oid_sizeof(2));
	snmp_log("/realloc");
      }

      oid->n_subid = 2;
      oid->ids[0] = 1;
      oid->ids[1] = SNMP_BGP4_MIB;
      break;

    case BGP_INTERNAL_VERSION:
      if (oid->n_subid != 3)
      { snmp_log("realloc");
	oid = mb_realloc(oid, snmp_oid_sizeof(3));
      snmp_log("/realloc"); }

      oid->n_subid = 3;
      oid->ids[2] = SNMP_BGP_VERSION;
      break;

    case BGP_INTERNAL_LOCAL_AS:
      if (oid->n_subid != 3)
      { snmp_log("realloc");
	oid = mb_realloc(oid, snmp_oid_sizeof(3));
      snmp_log("/realloc"); }

      oid->n_subid = 3;
      oid->ids[2] = 2;
      break;

    case BGP_INTERNAL_IDENTIFIER:
      if (oid->n_subid != 9)
      {
	snmp_log("realloc");
	oid = mb_realloc(oid, snmp_oid_sizeof(9));
	snmp_log("/realloc");

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

      oid->ids[4] = SNMP_BGP_IDENTIFIER;
      oid->n_subid = 9;
      break;

#define SNMP_UPDATE_CASE(num, update)					    \
    case num:								    \
      if (oid->n_subid != 9)						    \
      {									    \
	snmp_log("realloc");						    \
	oid = mb_realloc(oid, snmp_oid_sizeof(9));			    \
	snmp_log("/realloc");						    \
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

    default:
      die("update unavailable");
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

  snmp_log("bgp_find_dynamic_oid()");
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
      ip4_from_u32(0xFFFFFFFF);
  }

  snmp_log("ip addresses build (ip4) %I (dest) %I", ipa_from_ip4(ip4), ipa_from_ip4(dest));

  net_addr net;
  net_fill_ip4(&net, ip4, IP4_MAX_PREFIX_LENGTH);

  snmp_log("dynamic part of BGP mib");

  struct f_trie_walk_state ws;

  // TODO move to newer API
  trie_walk_init(&ws, p->bgp_trie, NULL, 0);

  snmp_log("walk init");

  if (trie_walk_next(&ws, &net)) // && ip4_less(net4_prefix(net), dest))
  {
    snmp_log("trie_walk_next() returned true");

    /*
     * if the o_end is empty then there are no conditions on the ip4 addr
     */
    //int cmp = (check_dest) ? ip4_compare(net4_prefix(&net), dest) : ;
    int cmp = ip4_compare(net4_prefix(&net), dest);
    if (cmp < 0 || (cmp == 0 && snmp_is_oid_empty(o_end)))
    {
      snmp_log("ip4_less() returned true");
      struct oid *o = mb_allocz(p->p.pool, snmp_oid_sizeof(9));
      o->n_subid = 9;

      memcpy(o, o_start, snmp_oid_size(o_start));
      snmp_oid_ip4_index(o, 5, net4_prefix(&net));

      return o;
    }

    // delete me
    else
    {
      snmp_log("ip4_less() returned false for %I >= %I", net4_prefix(&net), dest);
    }
    // delete me end
  }

  else
  {
    snmp_log("trie_walk_next() returned false, cleaning");
  }

  return NULL;
}

static struct oid *
search_bgp_dynamic(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, uint contid
UNUSED, u8 current_state)
{
  snmp_log("search_bgp_dynamic() dynamic part Yaaay!");

  /* TODO can be remove after implementing all BGP4-MIB::bgpPeerTable columns */
  u8 next_state = current_state;
  struct oid *o_copy = o_start;
  do
  {
    snmp_log("do-while state %u", next_state);
    snmp_oid_dump(o_start);
    o_start = o_copy = update_bgp_oid(o_copy, next_state);

    o_start = bgp_find_dynamic_oid(p, o_start, o_end, next_state);
    snmp_log("found");
    snmp_oid_dump(o_start);

    next_state = snmp_bgp_next_state(next_state);
    /* search in next state is done from beginning */
    o_start->ids[5] = o_start->ids[6] = o_start->ids[7] = o_start->ids[8] = 0;
    o_start->include = 1;

    snmp_log("looping");
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
  // TODO add o_end paramenter for faster searches
  ip4_addr ip4 = ip4_from_oid(oid);
  //ip_add4 dest = ip4_from_u32(0xFFFFFFFF);

  net_addr net;
  net_fill_ip4(&net, ip4, IP4_MAX_PREFIX_LENGTH);
  struct f_trie_walk_state ws;

  int match = trie_walk_init(&ws, p->bgp_trie, &net, 1);

  snmp_log("match %d include %u", match, oid->include);
  if (match && oid->include)
  {
    oid->include = 0;
    return 1;
  }

  /* We skip the first match as we should not include ip address in oid */
  if (match)
  {
    snmp_log("continue");
    trie_walk_next(&ws, &net);
  }

  if (trie_walk_next(&ws, &net))
  {
    snmp_oid_dump(oid);
    snmp_log("setting up");
    u32 res = ipa_to_u32(net_prefix(&net));

    ASSUME(oid->n_subid == 9);
    oid->ids[5] = (res & 0xFF000000) >> 24;
    oid->ids[6] = (res & 0x00FF0000) >> 16;
    oid->ids[7] = (res & 0x0000FF00) >>  8;
    oid->ids[8] = (res & 0x000000FF) >>  0;
    return 1;
  }

  snmp_log("bad");
  return 0;
}

static enum snmp_search_res
snmp_bgp_search_dynamic(struct snmp_proto *p, struct oid **searched, const struct oid *o_end, uint UNUSED contid, u8 next_state)
{
  struct oid *oid = *searched;
  snmp_log(" **searched = 0x%p  *oid = 0x%p", searched, oid);
  snmp_oid_dump(*searched);
  snmp_oid_dump(oid);
  u8 end_state = snmp_bgp_state(o_end);

  snmp_log("before assumption %s [%u] < %u INTERNAL_END", debug_bgp_states[end_state], end_state, BGP_INTERNAL_END);
  // failed
  ASSUME(end_state <= BGP_INTERNAL_END);
  snmp_log("before assupmtion oid 0x%p != NULL (0x0)", oid);
  ASSUME(oid != NULL);

  oid = update_bgp_oid(oid, next_state);

  snmp_log("update bgp oid to state %s [%d]", debug_bgp_states[next_state], next_state);
  snmp_oid_dump(*searched);
  snmp_oid_dump(oid);

  int found;
  while (!(found = snmp_bgp_find_next_oid(p, oid, contid)) && next_state <= end_state)
  {
    snmp_log("loop");

    next_state = snmp_bgp_next_state(next_state);
    if (next_state == BGP_INTERNAL_END)
      break;
    oid = update_bgp_oid(oid, next_state);
    /* in search for next bgp state, we want to start from beginning */
    oid->ids[5] = oid->ids[6] = oid->ids[7] = oid->ids[8] = 0;
  }

  if (next_state <= end_state)
  {
    *searched = oid;
    return SNMP_SEARCH_OK;
  }

  // free in the caller ?!
  mb_free(oid);
  *searched = NULL;
  return SNMP_SEARCH_END_OF_VIEW;
}

enum snmp_search_res
snmp_bgp_search2(struct snmp_proto *p, struct oid **searched, const struct oid *o_end, uint contid)
{
  u8 bgp_state = snmp_bgp_state(*searched);
  struct oid *oid = *searched;
  snmp_log("snmp_bgp_search2() with state %s [%d]", debug_bgp_states[bgp_state], bgp_state);

  /* TODO remove todo below, then remove this code */
  if (is_dynamic(bgp_state))
  {
    snmp_log("returning oid with dynamic state");
    return snmp_bgp_search_dynamic(p, searched, o_end, contid, bgp_state);
    //return snmp_bgp_search_dynamic(p, searched, contid, result, bgp_state);
  }

  /* TODO snmp_bgp_has_value is false only for state which are not dynamic */
  if (!snmp_bgp_has_value(bgp_state) || !oid->include)
  {
    bgp_state = snmp_bgp_next_state(bgp_state);
    snmp_log("altering searched oid with next state %s [%d]", debug_bgp_states[bgp_state], bgp_state);
    snmp_oid_dump(*searched);
    snmp_log("after oid update:");
    snmp_oid_dump(*searched);

    /* zero the ip address section for previously non-dynamic oid (search all peers) */
    for (int i = 5; i < MIN(9, oid->n_subid); i++)
      oid->ids[i] = 0;
  }

  if (is_dynamic(bgp_state))
  {
    snmp_log("returning oid with dynamic state 2");
    return snmp_bgp_search_dynamic(p, searched, o_end, contid, bgp_state);
    //return snmp_bgp_search_dynamic(p, o_start, contid, result, bgp_state);
  }

  oid = *searched = update_bgp_oid(*searched, bgp_state);
  if (oid->n_subid == 3 && oid->ids[2] >= SNMP_BGP_VERSION &&
      oid->ids[2] <= SNMP_BGP_LOCAL_AS)
  {
    snmp_log("oid matches static state");
    oid->include = 0;
    return SNMP_SEARCH_OK;
  }

  snmp_log("reached unguarded code, returning END_OF_VIEW");
  /* TODO */
  //if (


  return SNMP_SEARCH_END_OF_VIEW;
  // return SNMP_NO_SUCH_OBJECT;

#if 0
  if (is_dynamic(bgp_state))
    return snmp_bgp_search_dynamic(p, o_start, contid, res);

  if (!snmp_bgp_has_value(bgp_state))
  {
    bgp_state = x;
  }
  print_bgp_record_all(p);

  if (o_start->include)
    return snmp_bgp_search_included(p, o_start, contid, result, bgp_state);

  u8 next_state = snmp_bgp_next_state(bgp_state);
  if (!is_dynamic(next_state))
  {
    o_start = update_bgp_oid(o_start, next_state);
    snmp_log("next state is also not dynamic");
    *res = o_start;
    return SNMP_SEARCH_OK;
  }

  return search_bgp_dynamic(p, o_start, o_end, contid, bgp_state);


  if (o_start->include && snmp_bgp_has_value(bgp_state))
      && !is_dynamic(bgp_state))
  {
    if (o_start->n_subid == 3)
    {
      o_start->include = 0;
      *result = o_start;
      return SNMP_SEARCH_OK;
    }
    else if (o_start->n_subid > 3)
      return SNMP_SEARCH_NO_INSTANCE;
    else
      return SNMP_SEARCH_NO_OBJECT;
  }
  else if (o_start->include && snmp_bgp_has_value(bgp_state))
	   && is_dynamic(bgp_state))
    return search_bgp_dynamic1(p, o_start, contid, result);
  else if (o_start

  / * o_start is not inclusive * /
#endif
}

/* o_start could be o_curr, but has basically same meaning for searching */
struct oid *
snmp_bgp_search(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, uint contid UNUSED)
{
  u8 start_state = snmp_bgp_state(o_start);
  //u8 state_curr = snmp_bgp_state(o_start);
  //u8 state_end = (o_end) ? snmp_bgp_state(o_end) : 0;


  // print debugging information
  print_bgp_record_all(p);

  if (o_start->include && snmp_bgp_has_value(start_state) &&
      !is_dynamic(start_state) && o_start->n_subid == 3)
  {
    snmp_log("snmp_bgp_search() first search element (due to include field) returned");
    o_start->include = 0;  /* disable including for next time */
    return o_start;
  }
  else if (o_start->include && snmp_bgp_has_value(start_state) &&
	   is_dynamic(start_state))
  {
    snmp_log("snmp_bgp_search() first search element matched dynamic entry!");
    return search_bgp_dynamic(p, o_start, o_end, contid, start_state);
  }


  /* o_start is not inclusive */

  u8 next_state = snmp_bgp_next_state(start_state);
  // TODO more checks ?!?
  if (!is_dynamic(next_state))
  {
    o_start = update_bgp_oid(o_start, next_state);
    snmp_log("next state is also not dynamic");
    //snmp_oid_dump(o_start);
    return o_start;
  }

  /* is_dynamic(next_state) == 1 */
  return search_bgp_dynamic(p, o_start, o_end, 0, next_state);

//  // TODO readable rewrite
//  /* if state is_dynamic() then has more value and need find the right one */
//  else if (!is_dynamic(start_state))
//  {
//    snmp_log("seach_bgp_mib() static part");
//    u8 next_state = snmp_bgp_next_state(start_state);
//    snmp_log(" bgp states old %u new %u", start_state, next_state);
//    snmp_oid_dump(o_start);
//    o_start = update_bgp_oid(o_start, next_state);
//    snmp_oid_dump(o_start);
//
//    snmp_log("snmp_bgp_search() is NOT next_state dynamic %s",
//      !is_dynamic(next_state) ? "true" : "false");
//
//    if (!is_dynamic(next_state))
//      return o_start;
//
//    else
//      /* no need to check that retval < o_end -- done by bgp_find_dynamic_oid() */
//      return search_bgp_dynamic(p, o_start, o_end, 0, next_state);
//  }
//
//  /* no need to check that retval < o_end -- done by bgp_find_dynamic_oid() */
//  return search_bgp_dynamic(p, o_start, o_end, 0, start_state);
}

static byte *
bgp_fill_dynamic(struct snmp_proto UNUSED *p, struct agentx_varbind *vb,
		 struct snmp_pdu_context *c, u8 state)
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

  snmp_log(" -> ip addr %I", addr);
  // TODO XXX deal with possible change of (remote) ip
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
      snmp_log("bgp_dynamic_fill() using bgp_proto %p", bgp_proto);
    }
    /* binded bgp protocol not found */
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

  struct bgp_conn *bgp_conn = bgp_proto->conn;
  struct bgp_conn *bgp_in = &bgp_proto->incoming_conn;
  struct bgp_conn *bgp_out = &bgp_proto->outgoing_conn;

  struct bgp_stats *bgp_stats = &bgp_proto->stats;
  const struct bgp_config *bgp_conf = bgp_proto->cf;

  uint bgp_state;

  if (bgp_conn)
    bgp_state = bgp_conn->state;
  else if (MAX(bgp_in->state, bgp_out->state) == BS_CLOSE &&
	   MIN(bgp_in->state, bgp_out->state) != BS_CLOSE)
    bgp_state = MIN(bgp_in->state, bgp_out->state);
  else if (MIN(bgp_in->state, bgp_out->state) == BS_CLOSE)
    bgp_state = BS_IDLE;
  else
    bgp_state = MAX(bgp_in->state, bgp_out->state);

  char last_error[2] = { bgp_proto->last_error_code & 0x00FF0000 >> 16,
			 bgp_proto->last_error_code & 0x000000FF };
  switch (state)
  {
    case BGP_INTERNAL_IDENTIFIER:
      if (bgp_state == BS_OPENCONFIRM || bgp_state == BS_ESTABLISHED)
	pkt = snmp_varbind_ip4(vb, size, ip4_from_u32(bgp_proto->remote_id));
      else
	pkt = snmp_varbind_ip4(vb, size, IP4_NONE);
      break;

    case BGP_INTERNAL_STATE:
      pkt = snmp_varbind_int(vb, size, bgp_state);
      break;

    case BGP_INTERNAL_ADMIN_STATUS:
      /* struct proto ~ (struct proto *) bgp_proto */
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
  snmp_log("snmp bgp_fill_static ()\n");
  byte *temp = pkt;
  snmp_log("bgp_fill_static: vb->type %u, ptk %02x", vb->type, *((u32 *) pkt));

  struct oid *oid = &vb->name;
  snmp_oid_dump(oid);
  snmp_log("bgp_fill_static");

  /* snmp_bgp_state() check only prefix. To be sure on oid equivalence we need to
   * compare the oid->n_subid length. All BGP static fields have same n_subid.
   */
  if (oid_state_compare(oid, state) < 0 || state == BGP_INTERNAL_END)
  {
    vb->type = AGENTX_NO_SUCH_OBJECT;
    return ((byte *) vb) + snmp_varbind_header_size(vb);
  }
  else if (oid_state_compare(oid, state) > 0)
  {
    vb->type = AGENTX_NO_SUCH_INSTANCE;
    return ((byte *) vb) + snmp_varbind_header_size(vb);
  }

  switch (state)
  {
    case BGP_INTERNAL_VERSION:
      pkt = snmp_varbind_nstr(vb, size, BGP4_VERSIONS, 1);
      break;

    case BGP_INTERNAL_LOCAL_AS:
      pkt = snmp_varbind_int(vb, size, p->local_as);
      break;

    case BGP_INTERNAL_BGP:
    default:
      vb->type = AGENTX_NO_SUCH_OBJECT;
      pkt = ((byte *) vb) + snmp_varbind_header_size(vb);
      break;
  }

  snmp_log("bgp_fill_static: type %u  packet %p", vb->type, pkt);
  snmp_oid_dump(oid);

  snmp_log("snmp ended with non empty pkt %u starting from %p to %p\n", pkt -
temp, temp, pkt);
  snmp_dump_packet(temp, pkt - temp);
  return pkt;
}

void
snmp_bgp_fill(struct snmp_proto *p, struct agentx_varbind *vb,
	      struct snmp_pdu_context *c)
{
  u8 state = snmp_bgp_state(&vb->name);
  //byte *tmp;

  byte *pkt;
  if (!is_dynamic(state))
  {
    //return bgp_fill_static(p, vb, c->buffer, c->size, c->context, c->byte_ord, state);
    pkt = bgp_fill_static(p, vb, c->buffer, c->size, c->context, c->byte_ord, state);
    ADVANCE(c->buffer, c->size, pkt - c->buffer);
    return;
  }

  if (is_dynamic(state) && snmp_bgp_has_value(state))
  {
    pkt = bgp_fill_dynamic(p, vb, c, state);
    ADVANCE(c->buffer, c->size, pkt - c->buffer);
    return;
  }
  else
  {
    die("snmp_bgp_fill unreachable");
    // AGENTX_NO_SUCH_OBJECT
    ((void) c->buffer);
    return;
  }
}

