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
  [BGP_INTERNAL_INVALID] = "BGP_INTERNAL_INVALID",
  [BGP_INTERNAL_BGP] = "BGP_INTERNAL_BGP",
  [BGP_INTERNAL_VERSION] = "BGP_INTERNAL_VERSION",
  [BGP_INTERNAL_LOCAL_AS] = "BGP_INTERNAL_LOCAL_AS",
  [BGP_INTERNAL_PEER_TABLE] = "BGP_INTERNAL_PEER_TABLE",
  [BGP_INTERNAL_PEER_ENTRY] = "BGP_INTERNAL_PEER_ENTRY",
  [BGP_INTERNAL_IDENTIFIER] = "BGP_INTERNAL_IDENTIFIER",
  [BGP_INTERNAL_STATE] = "BGP_INTERNAL_STATE",
  [BGP_INTERNAL_ADMIN_STATUS] = "BGP_INTERNAL_ADMIN_STATUS",
  [BGP_INTERNAL_NEGOTIATED_VERSION] = "BGP_INTERNAL_NEGOTIATED_VERSION",
  [BGP_INTERNAL_LOCAL_ADDR] = "BGP_INTERNAL_LOCAL_ADDR",
  [BGP_INTERNAL_LOCAL_PORT] = "BGP_INTERNAL_LOCAL_PORT",
  [BGP_INTERNAL_REMOTE_ADDR] = "BGP_INTERNAL_REMOTE_ADDR",
  [BGP_INTERNAL_REMOTE_PORT] = "BGP_INTERNAL_REMOTE_PORT",
  [BGP_INTERNAL_REMOTE_AS] = "BGP_INTERNAL_REMOTE_AS",
  [BGP_INTERNAL_RX_UPDATES] = "BGP_INTERNAL_RX_UPDATES",
  [BGP_INTERNAL_TX_UPDATES] = "BGP_INTERNAL_TX_UPDATES",
  [BGP_INTERNAL_RX_MESSAGES] = "BGP_INTERNAL_RX_MESSAGES",
  [BGP_INTERNAL_TX_MESSAGES] = "BGP_INTERNAL_TX_MESSAGES",
  [BGP_INTERNAL_LAST_ERROR] = "BGP_INTERNAL_LAST_ERROR",
  [BGP_INTERNAL_FSM_TRANSITIONS] = "BGP_INTERNAL_FSM_TRANSITIONS",
  [BGP_INTERNAL_FSM_ESTABLISHED_TIME] = "BGP_INTERNAL_FSM_ESTABLISHED_TIME",
  [BGP_INTERNAL_RETRY_INTERVAL] = "BGP_INTERNAL_RETRY_INTERVAL",
  [BGP_INTERNAL_HOLD_TIME] = "BGP_INTERNAL_HOLD_TIME",
  [BGP_INTERNAL_KEEPALIVE] = "BGP_INTERNAL_KEEPALIVE",
  [BGP_INTERNAL_HOLD_TIME_CONFIGURED] = "BGP_INTERNAL_HOLD_TIME_CONFIGURED",
  [BGP_INTERNAL_KEEPALIVE_CONFIGURED] = "BGP_INTERNAL_KEEPALIVE_CONFIGURED",
  [BGP_INTERNAL_ORIGINATION_INTERVAL] = "BGP_INTERNAL_ORIGINATION_INTERVAL",
  [BGP_INTERNAL_MIN_ROUTE_ADVERTISEMENT] = "BGP_INTERNAL_MIN_ROUTE_ADVERTISEMENT",
  [BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME] = "BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME",
  [BGP_INTERNAL_END] = "BGP_INTERNAL_END",
  [BGP_INTERNAL_NO_VALUE] = "BGP_INTERNAL_NO_VALUE",
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

    snmp_register(p, oid, 0, 1);
  }

  // TODO squash bgpVersion and bgpLocalAs to one PDU
  { /* registering BGP4-MIB::bgpVersion */
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

  { /* registering BGP4-MIB::bgpLocalAs */
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

  { /* registering BGP4-MIB::bgpPeerTable */
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

  /* register dynamic BGP4-MIB::bgpPeerEntry.* */

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
}

int
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
  if (field > 0 && field < sizeof(translation_table) / sizeof(translation_table[0]))
    return translation_table[field];
  else
    return BGP_INTERNAL_NO_VALUE;
}

static inline struct ip4_addr
ip4_from_oid(const struct oid *o)
{
  return (o->n_subid == 9) ? ip4_build(o->ids[5], o->ids[6], o->ids[7],
o->ids[8]) : IP4_NONE;
}

static void
print_bgp_record(struct bgp_config *config)
{
  struct proto_config *cf = (struct proto_config *) config;
  // struct proto *P = cf->proto;
  struct bgp_proto *bgp_proto = (struct bgp_proto *) cf->proto;
  struct bgp_conn *conn = bgp_proto->conn;

  snmp_log("    name: %s", cf->name);
  snmp_log("");
  snmp_log("    rem. identifier: %u", bgp_proto->remote_id);
  snmp_log("    local ip: %I", config->local_ip);
  snmp_log("    remote ip: %I", config->remote_ip);
  snmp_log("    local port: %u", config->local_port);
  snmp_log("    remote port: %u", config->remote_port);

  // crashes ?
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

  // not supported yet
  snmp_log("    fsm total time: --");
  snmp_log("    retry interval: %u", config->connect_retry_time);

  snmp_log("    hold configurated: %u", config->hold_time );
  snmp_log("    keep alive config: %u", config->keepalive_time );

  // unknown
  snmp_log("    min AS origin. int.: --");
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
u8
snmp_bgp_state(struct oid *oid)
{
  /* already checked:
            xxxxxxxx p
   *  (*oid): .1.3.6.1.2.1.15
   *   -> BGP4-MIB::bgp (root)
   */

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
      if (oid->ids[3] == BGP4_PEER_ENTRY)
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

      /* unsupported fields */
      state == BGP_INTERNAL_FSM_ESTABLISHED_TIME ||
      state == BGP_INTERNAL_ORIGINATION_INTERVAL ||
      state == BGP_INTERNAL_MIN_ROUTE_ADVERTISEMENT ||
      state == BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME)
    return 0; /* hasn't value */
  else
    return 1; /* has value */
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

    case BGP_INTERNAL_FSM_TRANSITIONS:
    case BGP_INTERNAL_FSM_ESTABLISHED_TIME:
      return BGP_INTERNAL_RETRY_INTERVAL;


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
    if (o->n_subid == 2 && o->ids[1] == BGP4_MIB_VERSION ||
        o->ids[1] == BGP4_MIB_LOCAL_AS)
      return 1;
    else if (o->n_subid > 2 && o->ids[1] == BGP4_PEER_TABLE &&
             o->ids[2] == BGP4_PEER_ENTRY)
    {
	if (o->n_subid == 3)
	  return 1;
	if (o->n_subid == 8 &&
	    o->ids[3] > 0 &&
	    /* do not include bgpPeerInUpdatesElapsedTime
	       and bgpPeerFsmEstablishedTime */
	    o->ids[3] < SNMP_BGP_IN_UPDATE_ELAPSED_TIME &&
	    o->ids[3] != SNMP_BGP_FSM_ESTABLISHED_TIME)
	      return 1;
    }
    else
      return 0;
  }

  return 0;
}

static struct oid *
update_bgp_oid(struct oid *oid, u8 state)
{
  ASSERT (state != BGP_INTERNAL_INVALID);
  ASSERT (state != BGP_INTERNAL_NO_VALUE);
  ASSERT (state != BGP_INTERNAL_END);

  /* if same state, no need to realloc anything */
  if (snmp_bgp_state(oid) == state)
    return oid;

  switch (state)
  {
    case BGP_INTERNAL_BGP:
      /* could destroy same old data */
      oid = mb_realloc(oid, snmp_oid_sizeof(2));
      oid->n_subid = 2;
      oid->ids[0] = 1;
      oid->ids[1] = SNMP_BGP4_MIB;
      break;

    case BGP_INTERNAL_VERSION:
      oid = mb_realloc(oid, snmp_oid_sizeof(3));
      oid->n_subid = 3;
      oid->ids[2] = SNMP_BGP_VERSION;
      break;

    case BGP_INTERNAL_LOCAL_AS:
      oid->ids[2] = 2;
      break;

    case BGP_INTERNAL_IDENTIFIER:
      oid = mb_realloc(oid, snmp_oid_sizeof(9));
      oid->n_subid = 9;
      oid->ids[2] = SNMP_BGP_PEER_TABLE;
      oid->ids[3] = SNMP_BGP_PEER_ENTRY;
      oid->ids[4] = SNMP_BGP_IDENTIFIER;
      /* zero the ip */
      oid->ids[5] = oid->ids[6] = oid->ids[7] = oid->ids[8] = 0;
      break;

#define SNMP_UPDATE_CASE(num, update)	      \
    case num:				      \
      oid->ids[4] = update;		      \
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
  }

  return oid;
#undef SNMP_UPDATE_CASE
}

// TODO test bgp_find_dynamic_oid
static struct oid *
bgp_find_dynamic_oid(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, u8 state UNUSED)
{
  snmp_log("bgp_find_dynamic_oid()");
  ip4_addr ip4 = ip4_from_oid(o_start);
  ip4_addr dest = ip4_from_oid(o_end);

  snmp_log("ip addresses build (ip4) %I (dest) %I", ip4, dest);

  // why am I allocated dynamically ?!
  net_addr *net = mb_allocz(p->p.pool, sizeof(struct net_addr));
  net_fill_ip4(net, ip4, IP4_MAX_PREFIX_LENGTH);

  snmp_log("dynamic part of BGP mib");

  // why am I allocated dynamically ?!
  struct f_trie_walk_state *ws = mb_allocz(p->p.pool,
					   sizeof(struct f_trie_walk_state));

  trie_walk_init(ws, p->bgp_trie, NULL);

  snmp_log("walk init");

  if (trie_walk_next(ws, net)) // && ip4_less(net4_prefix(net), dest))
  {
    snmp_log("trie_walk_next() returned true");
    if (ip4_less(net4_prefix(net), dest))  // <- delete me
    {
      snmp_log("ip4_less() returned treu");
      struct oid *o = mb_allocz(p->p.pool, snmp_oid_sizeof(9));
      o->n_subid = 9;

      memcpy(o, o_start, snmp_oid_size(o_start));
      snmp_oid_ip4_index(o, 5, net4_prefix(net));

      mb_free(net);
      mb_free(ws);

      return o;
    }

    // delete me
    else
    {
      snmp_log("ip4_less() returned false");
      mb_free(net);
      mb_free(ws);
    }
    // delete me end
  }

  else
  {
    snmp_log("trie_walk_next() returned false, cleaning");
    mb_free(net);
    mb_free(ws);
  }

  return NULL;
}

static struct oid *
search_bgp_dynamic(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, uint contid
UNUSED, u8 next_state)
{
  snmp_log("search_bgp_dynamic() dynamic part Yaaay!");

  /* TODO can be remove after implementing all BGP4-MIB::bgpPeerTable columns */
  struct oid *copy = o_start;
  do {
    o_start = copy = update_bgp_oid(copy, next_state);

    o_start = bgp_find_dynamic_oid(p, o_start, o_end, next_state);

    next_state = snmp_bgp_next_state(next_state);

  } while (o_start == NULL && next_state < BGP_INTERNAL_END);

  return o_start;
}

/* o_start could be o_curr, but has basically same meaning for searching */
struct oid *
search_bgp_mib(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, uint contid UNUSED)
{
  u8 start_state = snmp_bgp_state(o_start);
  //u8 state_curr = snmp_bgp_state(o_start);
  //u8 state_end = (o_end) ? snmp_bgp_state(o_end) : 0;


  // print debugging information
  print_bgp_record_all(p);

  if (o_start->include && snmp_bgp_has_value(start_state) &&
      !is_dynamic(start_state) && o_start->n_subid == 3)
  {
    snmp_log("search_bgp_mib() first search element (due to include field) returned");
    o_start->include = 0;  /* disable including for next time */
    return o_start;
  }

  /* if state is_dynamic() then has more value and need find the right one */
  else if (!is_dynamic(start_state))
  {
    snmp_log("seach_bgp_mib() static part");
    u8 next_state = snmp_bgp_next_state(start_state);
    o_start = update_bgp_oid(o_start, next_state);

    snmp_log("search_bgp_mib() is NOT next_state dynamic %s",
      !is_dynamic(next_state) ? "true" : "false");

    if (!is_dynamic(next_state))
      return o_start;

    else
      /* no need to check that retval < o_end -- done by bgp_find_dynamic_oid() */
      return search_bgp_dynamic(p, o_start, o_end, 0, next_state);
  }

  /* no need to check that retval < o_end -- done by bgp_find_dynamic_oid() */
  return search_bgp_dynamic(p, o_start, o_end, 0, start_state);
}

static byte *
bgp_fill_dynamic(struct snmp_proto *p, struct agentx_varbind *vb, byte *pkt, uint size
UNUSED, uint contid UNUSED, int byte_ord UNUSED, u8 state)
{
  //snmp_log("bgp_fill_dynamic() valid ip %s", snmp_bgp_valid_ip4(oid) ? "true" : "false");

  struct oid *oid = &vb->name;

  ip_addr addr;
  if (snmp_bgp_valid_ip4(oid))
    addr = ipa_from_ip4(ip4_from_oid(oid));
  else
  {
    vb->type = AGENTX_NO_SUCH_OBJECT;
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
      vb->type = AGENTX_NO_SUCH_OBJECT;
      return pkt;
    }
  }

  else
  {
    vb->type = AGENTX_NO_SUCH_OBJECT;
    return pkt;
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

  switch (state)
  {

    case BGP_INTERNAL_IDENTIFIER:
      if (bgp_state == BS_OPENCONFIRM || bgp_state == BS_ESTABLISHED)
      {
	STORE_PTR(pkt, ipa_to_u32(bgp_proto->remote_ip));
	BGP_DATA(vb, AGENTX_IP_ADDRESS, pkt);
      }
      else
      {
	snmp_put_blank(pkt);	  /* stores 4B of zeroes */
	BGP_DATA(vb, AGENTX_IP_ADDRESS, pkt);
      }
      break;

    case BGP_INTERNAL_STATE:
      STORE_PTR(pkt, bgp_state);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case BGP_INTERNAL_ADMIN_STATUS:
      /* struct proto ~ (struct proto *) bgp_proto */
      if (proto->disabled)
	STORE_PTR(pkt, AGENTX_ADMIN_STOP);
      else
	STORE_PTR(pkt, AGENTX_ADMIN_START);

      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case BGP_INTERNAL_NEGOTIATED_VERSION:
      if (bgp_state == BS_OPENCONFIRM || bgp_state == BS_ESTABLISHED)
	STORE_PTR(pkt, 4); // TODO replace with MACRO
      else
	STORE_PTR(pkt, 0); /* zero dictated by rfc */

      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case BGP_INTERNAL_LOCAL_ADDR:
      // TODO XXX bgp_proto->link_addr & zero local_ip
      STORE_PTR(pkt, ipa_to_u32(bgp_proto->local_ip));
      BGP_DATA(vb, AGENTX_IP_ADDRESS, pkt);
      break;

    case BGP_INTERNAL_LOCAL_PORT:
      STORE_PTR(pkt, bgp_conf->local_port);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case BGP_INTERNAL_REMOTE_ADDR:
      STORE_PTR(pkt, ipa_to_u32(bgp_proto->remote_ip));
      BGP_DATA(vb, AGENTX_IP_ADDRESS, pkt);
      break;

    case BGP_INTERNAL_REMOTE_PORT:
      STORE_PTR(pkt, bgp_conf->remote_port);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case BGP_INTERNAL_REMOTE_AS:
      STORE_PTR(pkt, bgp_proto->remote_as);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    /* IN UPDATES */
    case BGP_INTERNAL_RX_UPDATES:
      STORE_PTR(pkt, bgp_stats->rx_updates);
      BGP_DATA(vb, AGENTX_COUNTER_32, pkt);
      break;

    /* OUT UPDATES */
    case BGP_INTERNAL_TX_UPDATES:
      STORE_PTR(pkt, bgp_stats->tx_updates);
      BGP_DATA(vb, AGENTX_COUNTER_32, pkt);
      break;

    /* IN MESSAGES */
    case BGP_INTERNAL_RX_MESSAGES:
      STORE_PTR(pkt, bgp_stats->rx_messages);
      BGP_DATA(vb, AGENTX_COUNTER_32, pkt);
      break;

    /* OUT MESSAGES */
    case BGP_INTERNAL_TX_MESSAGES:
      STORE_PTR(pkt, bgp_stats->tx_messages);
      BGP_DATA(vb, AGENTX_COUNTER_32, pkt);
      break;

    case BGP_INTERNAL_LAST_ERROR:
      STORE_PTR(pkt, 2);
      pkt += 4;

      if (bgp_proto->last_error_code)
      {
	/* force network order */
	put_u32(pkt, bgp_proto->last_error_code & 0x00FF0000 << 8 |
	  bgp_proto->last_error_code & 0x000000FF << 24);
      }
      else
	snmp_put_blank(pkt);

      BGP_DATA(vb, AGENTX_OCTET_STRING, pkt);
      break;

    case BGP_INTERNAL_FSM_TRANSITIONS:
      break;
    case BGP_INTERNAL_FSM_ESTABLISHED_TIME:
      break;
    case BGP_INTERNAL_RETRY_INTERVAL:
      break;
    case BGP_INTERNAL_HOLD_TIME:
      break;
    case BGP_INTERNAL_KEEPALIVE:
      break;
    case BGP_INTERNAL_HOLD_TIME_CONFIGURED:
      break;
    case BGP_INTERNAL_KEEPALIVE_CONFIGURED:
      break;
    case BGP_INTERNAL_ORIGINATION_INTERVAL:
      break;
    case BGP_INTERNAL_MIN_ROUTE_ADVERTISEMENT:
      break;
    case BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME:
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

  return pkt;
}

static byte *
bgp_fill_static(struct snmp_proto *p, struct agentx_varbind *vb, byte *pkt, uint size
UNUSED, uint contid UNUSED, int byte_ord UNUSED, u8 state)
{
  snmp_log("snmp bgp_fill_static ()\n");

  struct oid *oid = &vb->name;

  /* snmp_bgp_state() check only prefix. To be sure on oid equivalence we need to
   * compare the oid->n_subid length. All BGP static fields have same n_subid.
   */
  if (oid->n_subid != 3)
  {
    vb->type = AGENTX_NO_SUCH_OBJECT;
    return pkt;
  }

  switch (state)
  {
    case BGP_INTERNAL_VERSION:
      STORE_PTR(pkt, 1);   /* store string len */
      pkt += 4;
      STORE_PTR(pkt, BGP4_VERSIONS);

      /* real size is 8 but we already shifted the pkt by 4 */
      BGP_DATA(vb, AGENTX_OCTET_STRING, pkt);
      break;

    case BGP_INTERNAL_LOCAL_AS:
      // XXX local as to use

      STORE_PTR(pkt, p->local_as);
      BGP_DATA(vb, AGENTX_INTEGER, pkt);
      break;

    case BGP_INTERNAL_BGP:
      vb->type = AGENTX_NO_SUCH_OBJECT;
  }

  snmp_log("snmp ended with non empty pkt\n");
  return pkt;
}

byte *
snmp_bgp_fill(struct snmp_proto *p, struct agentx_varbind *vb, byte *buf UNUSED,
uint size UNUSED, uint contid UNUSED, int byte_ord UNUSED)
{
  u8 state = snmp_bgp_state(&vb->name);
  //snmp_log("snmp_bgp_fill() state %u is dynamic %s has value %s", state, is_dynamic(state) ? "true" : "false", snmp_bgp_has_value(state) ? "true" : "false");

  if (!is_dynamic(state))
    return bgp_fill_static(p, vb, buf, size, contid, byte_ord, state);

  if (is_dynamic(state) && snmp_bgp_has_value(state))
    return bgp_fill_dynamic(p, vb, buf, size, contid, byte_ord, state);

  else
  {
    return buf;
  }
  /*
  {
    snmp_log("has no value");
    struct agentx_varbind *vb = snmp_create_varbind(buf, oid);
    buf += snmp_varbind_size(vb);
    vb->type = AGENTX_NO_SUCH_OBJECT;
    return buf;
  }
  */
}
