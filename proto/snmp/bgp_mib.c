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
#include "subagent.h"
#include "bgp_mib.h"

static const char * const debug_bgp_states[] = {
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
snmp_bgp_register()
{}

int
snmp_bgp_valid_ip4(struct oid *o)
{
  return snmp_valid_ip4_index_safe(o, 6);
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

   /* between ids[6] and ids[9] should be IP address
    * validity is checked later in execution because
    *  this field also could mean a boundry (upper or lower)
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

inline int
is_dynamic(u8 state)
{
  return (state >= BGP_INTERNAL_IDENTIFIER && 
	  state <= BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME);
}

static inline int
snmp_bgp_has_value(u8 state)
{
  /* bitmap would be faster */
  if (state <= BGP_INTERNAL_BGP ||
      state == BGP_INTERNAL_PEER_TABLE ||
      state == BGP_INTERNAL_PEER_ENTRY)
    return 0; /* hasn't value */
  else
  {
    
  }
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
      oid = mb_realloc(oid, sizeof(struct oid) + 2 * sizeof(u32));
      oid->n_subid = 2;
      oid->ids[0] = 1;
      oid->ids[1] = SNMP_BGP4_MIB;
      break;

    case BGP_INTERNAL_VERSION:
      oid = mb_realloc(oid, sizeof(struct oid) + 3 * sizeof(u32));
      oid->n_subid = 3;
      oid->ids[2] = SNMP_BGP_VERSION;
      break;

    case BGP_INTERNAL_LOCAL_AS:
      oid->ids[2] = 2;
      break;

    case BGP_INTERNAL_IDENTIFIER:
      oid = mb_realloc(oid, sizeof(struct oid) + 9 * sizeof(u32));
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
  ip4_addr ip4 = ip4_from_oid(o_start);
  ip4_addr dest = ip4_from_oid(o_end);

  net_addr *net = mb_allocz(p->p.pool, sizeof(struct net_addr));
  net_fill_ip4(net, ip4, IP4_MAX_PREFIX_LENGTH);

  log(L_INFO "dynamic part of BGP mib");

  struct f_trie_walk_state *ws = mb_allocz(p->p.pool,
					   sizeof(struct f_trie_walk_state));

  trie_walk_init(ws, p->bgp_trie, NULL);

  if (trie_walk_next(ws, net) && ip4_less(net4_prefix(net), dest))
  {
    struct oid *o = mb_allocz(p->p.pool, sizeof(struct oid) + 9 * sizeof(u32));
    o->n_subid = 9;

    memcpy(o, o_start, snmp_oid_size(o_start));
    snmp_oid_ip4_index(o, net4_prefix(net));

    mb_free(net);
    mb_free(ws);

    return o;
  }

  else
  {
    mb_free(net);
    mb_free(ws);
  }

  return NULL;
}

byte *
snmp_bgp_fill(struct snmp_proto *p UNUSED, struct oid *oid, byte *buf UNUSED,
uint size UNUSED, uint contid UNUSED, int byte_ord UNUSED)
{
  u8 state = snmp_bgp_state(oid);
  (void)state;
  return NULL;
}

/* o_start could be o_curr, but has basically same meaning for searching */
struct oid *
search_bgp_mib(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, uint contid UNUSED)
{
  u8 start_state = snmp_bgp_state(o_start);
  //u8 state_curr = snmp_bgp_state(o_start);
  //u8 state_end = (o_end) ? snmp_bgp_state(o_end) : 0;

  if (o_start->include && snmp_bgp_has_value(start_state) &&
      !is_dynamic(start_state) && o_start->n_subid == 3)
  {
    o_start->include = 0;  /* disable including for next time */
    return o_start;
  }

  /* if state is_dynamic() then has more value and need find the right one */
  else if (!is_dynamic(start_state))
  {
    u8 next_state = snmp_bgp_next_state(start_state);
    o_start = update_bgp_oid(o_start, next_state);

    if (!is_dynamic(next_state))
      return o_start;

    else
    {
      struct oid *copy = o_start;
      do {
	/* update_bgp_oid can reallocate the underlaying struct */
	o_start = copy = update_bgp_oid(copy, next_state);

	o_start = bgp_find_dynamic_oid(p, o_start, o_end, next_state);

	next_state = snmp_bgp_next_state(next_state);

      } while (o_start != NULL && next_state < BGP_INTERNAL_END);

      return o_start;
    }
  }

  /* else - is_dynamic(start_state) */  
    /* ... (same as do ... while above) */


  return NULL;
  /* TODO not implemented yet */

  /* older implementation - untested */
  /* if o_curr is in invalid state, o_curr->include does't make any
   * difference; invalid state ~ no value to put in response packet 
   */
  /* indent \v/ */
  u8 state_curr = snmp_bgp_getnext_valid(state_curr);

  struct oid *o_curr = update_bgp_oid(o_curr, state_curr);

  /* static part of BGP4-MIB tree, not depending on BGP connections */
  if (state_curr <= 5)
  {
    return o_curr;
  }
  /* dynamic part of BGP4-MIB tree, depending on BGP connections */
  else /* state_curr > 5 */
  {
    ip4_addr ip4 = ip4_from_oid(o_curr);
    ip4_addr dest = ip4_from_oid(o_end);

    net_addr *net = mb_allocz(p->p.pool, sizeof(struct net_addr));
    net_fill_ip4(net, ip4, IP4_MAX_PREFIX_LENGTH);

    log(L_INFO "dynamic part of BGP mib");

    struct f_trie_walk_state *ws = mb_allocz(p->p.pool,
					     sizeof(struct f_trie_walk_state));

    struct oid *o = mb_allocz(p->p.pool, sizeof(struct oid) + 8 * sizeof(u32));
    o->n_subid = 9;
    trie_walk_init(ws, p->bgp_trie, NULL);

    if (trie_walk_next(ws, net) && ip4_less(net4_prefix(net), dest))
    {
      memcpy(o, o_curr, snmp_oid_size(o_curr));
      snmp_oid_ip4_index(o, net4_prefix(net));

      mb_free(net);
      mb_free(ws);

      return o;
    }

    else
    {
      mb_free(net);
      mb_free(ws);

      return NULL;
    }
  }
}
