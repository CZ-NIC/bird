/*
 *	BIRD -- Simple Network Management Protocol (SNMP)
 *        BGP4-MIB bgpPeerTable
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/cli.h"

#include "snmp.h"
#include "snmp_utils.h"
#include "subagent.h"
#include "bgp4_mib.h"
#include "mib_tree.h"

/* hash table macros */
#define SNMP_HASH_KEY(n)  n->peer_ip
#define SNMP_HASH_NEXT(n) n->next
#define SNMP_HASH_EQ(ip1, ip2) ip4_equal(ip1, ip2)
#define SNMP_HASH_FN(ip)  ip4_hash(ip)

#define SNMP_HASH_LESS4(ip1, ip2) ip4_less(ip1, ip2)
#define SNMP_HASH_LESS6(ip1, ip2) ip6_less(ip1, ip2)

/* hash table only store ip4 addresses */
#define SNMP_HASH_LESS(ip1, ip2) SNMP_HASH_LESS4(ip1,ip2)

#define DECLARE_BGP4(addr, proto, conn, stats, config) \
  ip4_addr addr; \
  const struct bgp_proto UNUSED *proto; \
  const struct bgp_conn UNUSED *conn; \
  const struct bgp_stats UNUSED *stats; \
  const struct bgp_config UNUSED *config

#define POPULATE_BGP4(addr, proto, conn, stats, config) populate_bgp4(c, &(addr), &(proto), &(conn), &(stats), &(config))

static inline void ip4_to_oid(struct oid *oid, ip4_addr addr);
static const STATIC_OID(2) bgp4_mib_oid = STATIC_OID_INITIALIZER(2, SNMP_MGMT, SNMP_MIB_2, SNMP_BGP4_MIB);

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

static void
snmp_bgp_reg_failed(struct snmp_proto *p, const struct agentx_response *res, struct snmp_registration *reg)
{
  (void) res;
  (void) reg;
  snmp_reset(p);
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
    SNMP_MIB_2, SNMP_BGP4_MIB, BGP4_MIB_PEER_TABLE, BGP4_MIB_PEER_ENTRY
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
  /* We have enough space inside the TX buffer prepared */
  struct snmp_pdu dummy = { 0 };
  dummy.sr_vb_start = addr_vb;
  snmp_varbind_ip4(&dummy, ip4);

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

  dummy.sr_vb_start = error_vb;
  snmp_varbind_nstr(&dummy, last_error, 2);

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

  dummy.sr_vb_start = state_vb;
  snmp_varbind_int(&dummy, state_val);

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
snmp_bgp4_register(struct snmp_proto *p)
{
  /* Register the whole BGP4-MIB::bgp root tree node */
  struct snmp_registration *reg;
  reg = snmp_registration_create(p, BGP4_MIB_ID);

  struct oid *oid = mb_allocz(p->pool, sizeof(bgp4_mib_oid));
  memcpy(oid, &bgp4_mib_oid, sizeof(bgp4_mib_oid));

  reg->reg_hook_ok = NULL;
  reg->reg_hook_fail = snmp_bgp_reg_failed;

  /*
   * We set both upper bound and index to zero, therefore only single OID
   * is being registered.
   */
  snmp_register(p, oid, 0, 0, SNMP_REGISTER_TREE);
}

static int
snmp_bgp_valid_ip4(const struct oid *o)
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
  o->ids[5] = (tmp & 0xFF000000) >> 24;
  o->ids[6] = (tmp & 0x00FF0000) >> 16;
  o->ids[7] = (tmp & 0x0000FF00) >>  8;
  o->ids[8] = (tmp & 0x000000FF) >>  0;
}

static void UNUSED
print_bgp_record(const struct bgp_proto *bgp_proto)
{
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

static inline enum snmp_search_res
populate_bgp4(struct snmp_pdu *c, ip4_addr *addr, const struct bgp_proto **proto, const struct bgp_conn
**conn, const struct bgp_stats **stats, const struct bgp_config **config)
{
  const struct oid * const oid = &c->sr_vb_start->name;
  if (snmp_bgp_valid_ip4(oid) && oid->n_subid == 9)
    *addr = ip4_from_oid(oid);
  else
    return SNMP_SEARCH_NO_INSTANCE;

  struct snmp_bgp_peer *pe = snmp_hash_find(c->p, *addr);
  if (!pe)
    return SNMP_SEARCH_NO_INSTANCE;

  const struct bgp_proto *bgp_proto;
  *proto = bgp_proto = pe->bgp_proto;
  if (!ipa_is_ip4(bgp_proto->remote_ip))
  {
    c->error = AGENTX_RES_GEN_ERROR;
    return SNMP_SEARCH_NO_INSTANCE;
  }

  ip4_addr proto_ip = ipa_to_ip4(bgp_proto->remote_ip);
  if (!ip4_equal(proto_ip, pe->peer_ip))
  {
    /* Here, we could be in problem as the bgp_proto IP address could be changed */
    c->error = AGENTX_RES_GEN_ERROR;
    return SNMP_SEARCH_NO_INSTANCE;
  }

  *conn = bgp_proto->conn;
  *stats = &bgp_proto->stats;
  *config = bgp_proto->cf;

  return SNMP_SEARCH_OK;
}

/*
 *
 *    MIB tree fill hooks
 *
 */

static enum snmp_search_res
fill_bgp_version(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  if (c->sr_vb_start->name.n_subid != 3)
    return SNMP_SEARCH_NO_INSTANCE;
  c->size -= snmp_str_size_from_len(1);
  snmp_varbind_nstr(c, BGP4_VERSIONS, 1);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_local_as(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  if (c->sr_vb_start->name.n_subid != 3)
    return SNMP_SEARCH_NO_INSTANCE;
  snmp_varbind_int(c, c->p->bgp_local_as);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_peer_id(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  uint fsm_state = snmp_bgp_fsm_state(bgp_proto);

  if (fsm_state == BGP4_MIB_OPENCONFIRM || fsm_state == BGP4_MIB_ESTABLISHED)
    // TODO last
    snmp_varbind_ip4(c, ip4_from_u32(bgp_proto->remote_id));
  else
    snmp_varbind_ip4(c, IP4_NONE);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_peer_state(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  uint fsm_state = snmp_bgp_fsm_state(bgp_proto);

  snmp_varbind_int(c, fsm_state);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_admin_status(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  if (bgp_proto->p.disabled)
    snmp_varbind_int(c, BGP4_ADMIN_STOP);
  else
    snmp_varbind_int(c, BGP4_ADMIN_START);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_neg_version(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  uint fsm_state = snmp_bgp_fsm_state(bgp_proto);

  if (fsm_state == BGP4_MIB_ESTABLISHED || fsm_state == BGP4_MIB_ESTABLISHED)
    snmp_varbind_int(c, BGP4_MIB_NEGOTIATED_VER_VALUE);
  else
    snmp_varbind_int(c, BGP4_MIB_NEGOTIATED_VER_NO_VALUE);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_local_addr(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);

  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_ip4(c, ipa_to_ip4(bgp_proto->local_ip));
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_local_port(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_int(c, bgp_conf->local_port);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_remote_addr(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_ip4(c, ipa_to_ip4(bgp_proto->remote_ip));
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_remote_port(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_int(c, bgp_conf->remote_port);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_remote_as(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_int(c, bgp_proto->remote_as);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_in_updates(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_counter32(c, bgp_stats->rx_updates);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_out_updates(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_counter32(c, bgp_stats->tx_updates);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_in_total_msg(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_counter32(c, bgp_stats->rx_messages);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_out_total_msg(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_counter32(c, bgp_stats->tx_messages);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_last_err(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  char last_error[2];
  snmp_bgp_last_error(bgp_proto, last_error);

  snmp_varbind_nstr(c, last_error, 2);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_established_trans(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_counter32(c,
      bgp_stats->fsm_established_transitions);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_established_time(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_gauge32(c,
	(current_time() - bgp_proto->last_established) TO_S);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_retry_interval(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_int(c, bgp_conf->connect_retry_time);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_hold_time(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_int(c, (bgp_conn) ?  bgp_conn->hold_time : 0);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_keep_alive(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  if (!bgp_conf->hold_time)
    snmp_varbind_int(c, 0);
  else
    snmp_varbind_int(c,
      (bgp_conn) ? bgp_conn->keepalive_time : 0);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_hold_time_conf(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_int(c, bgp_conf->hold_time);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_keep_alive_conf(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  if (!bgp_conf->keepalive_time)
    snmp_varbind_int(c, 0);
  else
    snmp_varbind_int(c,
      (bgp_conn) ? bgp_conn->keepalive_time : 0);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_min_as_org_interval(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  /* value should be in 1..65535 but is not supported by bird */
  snmp_varbind_int(c, 0);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_route_adv_interval(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  /* value should be in 1..65535 but is not supported by bird */
  snmp_varbind_int(c, 0);
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_in_update_elapsed_time(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  enum snmp_search_res res;
  DECLARE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  res = POPULATE_BGP4(addr, bgp_proto, bgp_conn, bgp_stats, bgp_conf);
  if (res != SNMP_SEARCH_OK)
    return res;

  snmp_varbind_gauge32(c,
    (current_time() - bgp_proto->last_rx_update) TO_S
  );
  return SNMP_SEARCH_OK;
}

static enum snmp_search_res
fill_local_id(struct mib_walk_state *walk UNUSED, struct snmp_pdu *c)
{
  if (c->sr_vb_start->name.n_subid != 3)
    return SNMP_SEARCH_NO_INSTANCE;
  snmp_varbind_ip4(c, c->p->bgp_local_id);
  return SNMP_SEARCH_OK;
}

/*
 * bgp4_next_peer - find next BGP peer with IPv4 address
 * @state: MIB tree walk state
 * @c: SNMP PDU context data
 *
 * Update TX buffer VarBind name to next peer address.
 */
static int
bgp4_next_peer(struct mib_walk_state *state, struct snmp_pdu *c)
{
  struct oid *oid = &c->sr_vb_start->name;

  /* BGP4-MIB::bgpPeerIdentifier */
  STATIC_OID(9) bgp4_peer_id = STATIC_OID_INITIALIZER(9, SNMP_MGMT,
    /* ids */ SNMP_MIB_2, SNMP_BGP4_MIB,
      BGP4_MIB_PEER_TABLE, BGP4_MIB_PEER_ENTRY, BGP4_MIB_PEER_IDENTIFIER);

  ip4_addr ip4 = ip4_from_oid(oid);

  const struct oid *peer_oid = (const struct oid *) &bgp4_peer_id;

  int precise = 1;
  if (oid->n_subid > 9)
    precise = 0;

  if (oid->n_subid != 9 || snmp_oid_compare(oid, peer_oid) < 0)
  {
    int old = snmp_oid_size(oid);
    int new = snmp_oid_size(peer_oid);

    if (new - old > 0 && snmp_tbuf_reserve(c, new - old))
      oid = &c->sr_vb_start->name;

    c->buffer += (new - old);

    snmp_oid_copy(oid, peer_oid);
    oid->include = 1;
  }

  ASSUME(oid->n_subid == 9);
  /* Stack has one more node for empty prefix (tree root) */
  ASSUME(state->stack_pos > 10);
  oid->ids[4] = state->stack[10]->empty.id;

  net_addr net;
  net_fill_ip4(&net, ip4, IP4_MAX_PREFIX_LENGTH);
  struct f_trie_walk_state ws;

  int match = trie_walk_init(&ws, c->p->bgp_trie, &net, 1);

  if (match && oid->include && precise)
  {
    oid->include = 0;
    ip4_to_oid(oid, ip4);
    return 0;
  }

  /* We skip the first match as we should not include ip address in oid */
  if (match)
   (void) trie_walk_next(&ws, &net);

  if (trie_walk_next(&ws, &net))
  {
    ASSUME(oid->n_subid == 9);
    ip4_addr res = ipa_to_ip4(net_prefix(&net));
    ip4_to_oid(oid, res);
    return 0;
  }

  return 1;
}

/*
 * snmp_bgp4_show_info - display info BGP4-MIB
 * @p: SNMP protocol instance
 *
 * Print info about BGP4-MIB status and bound bgp peers to cli.
 */
void
snmp_bgp4_show_info(struct snmp_proto *p)
{
  cli_msg(-1006, "    BGP4-MIB");
  cli_msg(-1006, "      Local AS %u", p->bgp_local_as);
  cli_msg(-1006, "      Local router id %R", p->bgp_local_id);
  cli_msg(-1006, "      BGP peers");

  if (!snmp_is_active(p))
    return;

  HASH_WALK(p->bgp_hash, next, peer)
  {
    cli_msg(-1006, "        protocol name: %s", peer->bgp_proto->p.name);
    cli_msg(-1006, "        Remote IPv4 address: %I4", peer->peer_ip);
    cli_msg(-1006, "        Remote router id %R", peer->bgp_proto->remote_id);
  }
  HASH_WALK_END;
}

/*
 * snmp_bgp4_start - prepare BGP4-MIB
 * @p: SNMP protocol instance holding memory pool
 *
 * This function create all runtime bindings to BGP procotol structures.
 * It is gruaranteed that the BGP protocols exist.
 */
void
snmp_bgp4_start(struct snmp_proto *p)
{
  agentx_available_mibs[BGP4_MIB_ID] = (struct oid *) &bgp4_mib_oid;

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

  const STATIC_OID(4) bgp4_mib_peer_entry = STATIC_OID_INITIALIZER(4, SNMP_MGMT,
    /* ids */ SNMP_MIB_2, SNMP_BGP4_MIB, BGP4_MIB_PEER_TABLE, BGP4_MIB_PEER_ENTRY);

  (void) mib_tree_hint(p->pool, p->mib_tree,
    (const struct oid *) &bgp4_mib_oid, BGP4_MIB_IDENTIFIER);
  (void) mib_tree_hint(p->pool, p->mib_tree,
    (const struct oid *) &bgp4_mib_peer_entry, BGP4_MIB_IN_UPDATE_ELAPSED_TIME);

  mib_node_u *node;
  struct mib_leaf *leaf;
  STATIC_OID(3) bgp4_var = STATIC_OID_INITIALIZER(3, SNMP_MGMT,
    /* ids */ SNMP_MIB_2, SNMP_BGP4_MIB, BGP4_MIB_VERSION);

  struct {
    u32 id;
    enum snmp_search_res (*filler)(struct mib_walk_state *state, struct snmp_pdu *c);
    enum agentx_type type;
    int size;
  } leafs[] = {
    {
      .id = BGP4_MIB_VERSION,
      .filler = fill_bgp_version,
      .type = AGENTX_OCTET_STRING,
      .size = snmp_str_size_from_len(sizeof(BGP4_VERSIONS)),
    },
    {
      .id =  BGP4_MIB_LOCAL_AS,
      .filler = fill_local_as,
      .type = AGENTX_INTEGER,
    },
    {
      .id =  BGP4_MIB_IDENTIFIER,
      .filler = fill_local_id,
      .type = AGENTX_IP_ADDRESS,
    },
  };

  for (uint i = 0; i < ARRAY_SIZE(leafs); i++)
  {
    bgp4_var.ids[ARRAY_SIZE(bgp4_var.ids) - 1] = leafs[i].id;
    node = mib_tree_add(p->pool, p->mib_tree, (const struct oid *) &bgp4_var, 1);

    ASSUME(mib_node_is_leaf(node));
    leaf = &node->leaf;

    leaf->filler = leafs[i].filler;
    leaf->call_next = NULL;
    leaf->type = leafs[i].type;
    leaf->size = leafs[i].size;
  }

  STATIC_OID(5) bgp4_entry_var = STATIC_OID_INITIALIZER(5, SNMP_MGMT,
    /* ids */ SNMP_MIB_2, SNMP_BGP4_MIB,
       BGP4_MIB_PEER_TABLE, BGP4_MIB_PEER_ENTRY, BGP4_MIB_PEER_IDENTIFIER);

  struct {
      enum snmp_search_res (*filler)(struct mib_walk_state *state, struct snmp_pdu *c);
      enum agentx_type type;
      int size;
  } entry_leafs[] = {
    [BGP4_MIB_PEER_IDENTIFIER] = {
      .filler =	fill_peer_id,
      .type = AGENTX_IP_ADDRESS,
    },
    [BGP4_MIB_STATE] = {
      .filler = fill_peer_state,
      .type = AGENTX_INTEGER,
    },
    [BGP4_MIB_ADMIN_STATUS] = {
      .filler = fill_admin_status,
      .type = AGENTX_INTEGER,
    },
    [BGP4_MIB_NEGOTIATED_VERSION] = {
      .filler = fill_neg_version,
      .type = AGENTX_INTEGER,
    },
    [BGP4_MIB_LOCAL_ADDR] = {
      .filler = fill_local_addr,
      .type = AGENTX_IP_ADDRESS,
    },
    [BGP4_MIB_LOCAL_PORT] = {
      .filler = fill_local_port,
      .type = AGENTX_INTEGER,
    },
    [BGP4_MIB_REMOTE_ADDR] = {
      .filler = fill_remote_addr,
      .type = AGENTX_IP_ADDRESS,
    },
    [BGP4_MIB_REMOTE_PORT] = {
      .filler = fill_remote_port,
      .type = AGENTX_INTEGER,
    },
    [BGP4_MIB_REMOTE_AS] = {
      .filler = fill_remote_as,
      .type = AGENTX_INTEGER,
    },
    [BGP4_MIB_RX_UPDATES] = {
      .filler = fill_in_updates,
      .type = AGENTX_COUNTER_32,
    },
    [BGP4_MIB_TX_UPDATES] = {
      .filler = fill_out_updates,
      .type = AGENTX_COUNTER_32,
    },
    [BGP4_MIB_RX_MESSAGES] = {
      .filler = fill_in_total_msg,
      .type = AGENTX_COUNTER_32,
    },
    [BGP4_MIB_TX_MESSAGES] = {
      .filler = fill_out_total_msg,
      .type = AGENTX_COUNTER_32,
    },
    [BGP4_MIB_LAST_ERROR] = {
      .filler = fill_last_err,
      .type = AGENTX_OCTET_STRING,
      .size = snmp_str_size_from_len(2),
    },
    [BGP4_MIB_FSM_TRANSITIONS] = {
      .filler = fill_established_trans,
      .type = AGENTX_COUNTER_32,
    },
    [BGP4_MIB_FSM_ESTABLISHED_TIME] = {
      .filler = fill_established_time,
      .type = AGENTX_GAUGE_32,
    },
    [BGP4_MIB_RETRY_INTERVAL] = {
      .filler = fill_retry_interval,
      .type = AGENTX_INTEGER,
    },
    [BGP4_MIB_HOLD_TIME] = {
      .filler = fill_hold_time,
      .type = AGENTX_INTEGER,
    },
    [BGP4_MIB_KEEPALIVE] = {
      .filler = fill_keep_alive,
      .type = AGENTX_INTEGER,
    },
    [BGP4_MIB_HOLD_TIME_CONFIGURED] = {
      .filler = fill_hold_time_conf,
      .type = AGENTX_INTEGER,
    },
    [BGP4_MIB_KEEPALIVE_CONFIGURED] = {
      .filler = fill_keep_alive_conf,
      .type = AGENTX_INTEGER,
    },
    [BGP4_MIB_ORIGINATION_INTERVAL] = {
      .filler = fill_min_as_org_interval,
      .type = AGENTX_INTEGER,
    },
    [BGP4_MIB_MIN_ROUTE_ADVERTISEMENT] = {
      .filler = fill_route_adv_interval,
      .type = AGENTX_INTEGER,
    },
    [BGP4_MIB_IN_UPDATE_ELAPSED_TIME] = {
      .filler = fill_in_update_elapsed_time,
      .type = AGENTX_GAUGE_32,
    },
  }; /* struct _anon entry_leafs[] */

  for (enum bgp4_mib_peer_entry_row e = BGP4_MIB_PEER_IDENTIFIER;
      e <= BGP4_MIB_IN_UPDATE_ELAPSED_TIME; e++)
  {
    bgp4_entry_var.ids[ARRAY_SIZE(bgp4_entry_var.ids) - 1] = (u32) e;
    node = mib_tree_add(p->pool, p->mib_tree, (const struct oid *) &bgp4_entry_var, 1);

    ASSUME(mib_node_is_leaf(node));
    leaf = &node->leaf;

    leaf->filler = entry_leafs[e].filler;
    leaf->call_next = bgp4_next_peer;
    leaf->type = entry_leafs[e].type;
    leaf->size = entry_leafs[e].size;
  }
}
