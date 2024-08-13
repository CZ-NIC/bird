/*
 *	BIRD -- Simple Network Management Procotol (SNMP)
 *
 *	(c) 2024 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *	(c) 2024 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Simple Network Management Protocol
 *
 * The SNMP protocol is divided into several parts: |snmp.c| which implements
 * the BIRD intergration, |subagent.c| contains functions for creating and
 * parsing packets, |bgp4_mib.c| takes care of the bgp MIB subtree of standard
 * BGP4-MIB and |snmp_utils.c| which is collections of helper functions for
 * working with OIDs, VarBinds.
 *
 * Althrough called SNMP the BIRD does not implement SNMP directly but acts as
 * an AgentX subagent. AgentX subagent connects to AgentX master agent that
 * processes incomming SNMP requests and passes them down to the correct
 * subagent. Therefore you need also a running master agent somewhere.
 * Advantages of this design are that you are capable of doing aggregation of
 * statuses of multiple BIRDs at the master agent level and much simpler
 * implementation.
 *
 * Before any of the SNMP request could be processed, the SNMP need to
 * established AgentX session with the master agent and need to register all
 * subtrees to make them accessible from the master agent. The establishement of
 * the of session is handled by snmp_start(), snmp_start_locked() and
 * snmp_start_subagent(). Then we register all MIBs from configuration in
 * snmp_register_mibs().
 *
 * The AgentX request are handled only during MIB subtree registrations and
 * after then on established session (in states SNMP_REGISTER and SNMP_CONN, see
 * below). It is also guaranteed that no request is received before MIB subtree
 * registration because the specific subagent is not authoratitave and also the
 * master agent has no info about MIB subtree supported by subagent. The AgentX
 * requests are handled by function snmp_rx() in |subagent.c|.
 *
 *
 *
 * SNMP State Machine
 *
 *  States with main transitions
 *
 *
 *    +-----------------+
 *    | SNMP_INIT	|     entry state after call snmp_start()
 *    +-----------------+
 *	  |
 *	  |   acquiring object lock for tcp communication socket
 *	  V
 *    +-----------------+
 *    | SNMP_LOCKED	|     object lock aquired
 *    +-----------------+
 *	  |
 *	  |   opening communication socket
 *	  V
 *    +-----------------+
 *    | SNMP_OPEN	|     socket created, starting subagent
 *    +-----------------+
 *	  |
 *	  |   BIRD receive response for agentx-Open-PDU
 *	  V
 *    +-----------------+
 *    | SNMP_REGISTER   |     session was established, subagent registers MIBs
 *    +-----------------+
 *	  |
 *	  |   subagent received response for any registration requests
 *	  V
 *    +-----------------+
 *    | SNMP_CONN	|     everything is set
 *    +-----------------+
 *	  |
 *	  |   received malformed PDU, protocol disabled,
 *	  |   BIRD sends agentx-Close-PDU or agentx-Response-PDU with an error
 *	  V
 *    +-----------------+
 *    | SNMP_STOP	|     waiting until the prepared PDUs are sent
 *    +-----------------+
 *	  |
 *	  |   cleaning protocol state
 *	  V
 *    +-----------------+
 *    | SNMP_DOWN	|     session is closed
 *    +-----------------+
 *
 *
 *
 *  Erroneous transitions:
 *    SNMP is UP (PS_UP) in states SNMP_CONN and also in SNMP_REGISTER because
 *    the session is establised and the GetNext request should be responsed
 *    without regards to MIB registration.
 *
 *    Reconfiguration is done in similar fashion to BGP, the reconfiguration
 *    request is declined, the protocols is stoped and started with new
 *    configuration.
 *
 */

#include "nest/bird.h"
#include "nest/cli.h"
#include "nest/locks.h"
#include "lib/socket.h"
#include "lib/lists.h"

#include "snmp.h"
#include "subagent.h"
#include "snmp_utils.h"
#include "mib_tree.h"
#include "bgp4_mib.h"

const char agentx_master_addr[] = AGENTX_MASTER_ADDR;
const struct oid *agentx_available_mibs[AGENTX_MIB_COUNT + 1] = { 0 };

static void snmp_start_locked(struct object_lock *lock);
static void snmp_sock_err(sock *sk, int err);
static void snmp_stop_timeout(timer *tm);
static void snmp_cleanup(struct snmp_proto *p);

static const char *snmp_state_str[] = {
  [SNMP_INIT]	  = "acquiring address lock",
  [SNMP_LOCKED]	  = "address lock acquired",
  [SNMP_OPEN]	  = "starting AgentX subagent",
  [SNMP_REGISTER] = "registering MIBs",
  [SNMP_CONN]	  = "AgentX session established",
  [SNMP_STOP]	  = "stopping AgentX subagent",
  [SNMP_DOWN]	  = "protocol down",
};

/*
 * agentx_get_mib_init - init function for agentx_get_mib()
 * @p: SNMP instance protocol pool
 */
void agentx_get_mib_init(pool *p)
{
  const struct oid *src = agentx_available_mibs[AGENTX_MIB_COUNT - 1];
  size_t size = snmp_oid_size(src);
  struct oid *dest = mb_alloc(p, size);

  memcpy(dest, src, size);
  u8 ids = src->n_subid;

  if (ids > 0)
    dest->ids[ids - 1] = src->ids[ids - 1] + 1;

  agentx_available_mibs[AGENTX_MIB_COUNT] = dest;
}

/*
 * agentx_get_mib - classify an OID based on MIB prefix
 * @o: Object Identifier to classify
 */
enum agentx_mibs agentx_get_mib(const struct oid *o)
{
  /* TODO: move me into MIB tree as hooks/MIB module root */
  enum agentx_mibs mib = AGENTX_MIB_UNKNOWN;
  for (uint i = 0; i < AGENTX_MIB_COUNT + 1; i++)
  {
    ASSERT(agentx_available_mibs[i]);
    if (snmp_oid_compare(o, agentx_available_mibs[i]) < 0)
      return mib;
    mib = (enum agentx_mibs) i;
  }

  return AGENTX_MIB_UNKNOWN;
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
 * snmp_tx_skip - handle empty TX buffer during session reset
 * @sk: communication socket
 *
 * The socket tx_hook is called when the TX buffer is empty, i.e. all data was
 * send. This function is used only when we found malformed PDU and we are
 * resetting the established session. If called, we perform a SNMP protocol
 * state change.
 */
static void
snmp_tx_skip(sock *sk)
{
  struct snmp_proto *p = sk->data;
  snmp_set_state(p, SNMP_STOP);
}

/*
 * snmp_set_state - change state with associated actions
 * @p: SNMP protocol instance
 * @state: new SNMP protocol state
 *
 * This function does not notify the bird about protocol state. Return current
 * protocol state (PS_UP, ...).
 */
int
snmp_set_state(struct snmp_proto *p, enum snmp_proto_state state)
{
  enum snmp_proto_state last = p->state;
  const struct snmp_config *cf = (struct snmp_config *) p->p.cf;

  p->state = state;

  switch (state)
  {
  case SNMP_INIT:
    TRACE(D_EVENTS, "TODO");
    ASSERT(last == SNMP_DOWN);

    proto_notify_state(&p->p, PS_START);
    if (cf->trans_type == SNMP_TRANS_TCP)
    {
      /* We need to lock the IP address */
      struct object_lock *lock;
      lock = p->lock = olock_new(p->pool);
      lock->addr = p->remote_ip;
      lock->port = p->remote_port;
      lock->type = OBJLOCK_TCP;
      lock->hook = snmp_start_locked;
      lock->data = p;
      olock_acquire(lock);
      return PS_START;
    }

    last = SNMP_INIT;
    p->state = state = SNMP_LOCKED;
    /* Fall thru */

  case SNMP_LOCKED:
    TRACE(D_EVENTS, "snmp %s: address lock acquired", p->p.name);
    ASSERT(last == SNMP_INIT);
    sock *s = sk_new(p->pool);

    if (cf->trans_type == SNMP_TRANS_TCP)
    {
      s->type = SK_TCP_ACTIVE;
      //s->saddr = ipa_from_ip4(p->local_ip);
      s->daddr = p->remote_ip;
      s->dport = p->remote_port;
      s->rbsize = SNMP_RX_BUFFER_SIZE;
      s->tbsize = SNMP_TX_BUFFER_SIZE;
    }
    else
    {
      s->type = SK_UNIX_ACTIVE;
      s->host = cf->remote_path; /* daddr */
      s->rbsize = SNMP_RX_BUFFER_SIZE;
      s->tbsize = SNMP_TX_BUFFER_SIZE;
    }

    /* s->tos = IP_PREC_INTERNET_CONTROL */
    s->tx_hook = snmp_connected;
    s->err_hook = snmp_sock_err;

    p->sock = s;
    s->data = p;

    /* Try opening the socket, schedule a retry on fail */
    if (sk_open(s) < 0)
    {
      TRACE(D_EVENTS, "opening of communication socket failed");
      rfree(s);
      p->sock = NULL;
      // TODO handle 0 timeout
      tm_start(p->startup_timer, p->timeout);
    }
    return PS_START;

  case SNMP_OPEN:
    TRACE(D_EVENTS, "communication socket opened, starting AgentX subagent");
    ASSERT(last == SNMP_LOCKED);

    p->sock->rx_hook = snmp_rx;
    p->sock->tx_hook = NULL;

    snmp_start_subagent(p);

    p->startup_timer->hook = snmp_stop_timeout;
    tm_start(p->startup_timer, 1 S);
    return PS_START;

  case SNMP_REGISTER:
    TRACE(D_EVENTS, "registering MIBs");
    ASSERT(last == SNMP_OPEN);

    tm_stop(p->startup_timer); /* stop timeout */

    p->sock->rx_hook = snmp_rx;
    p->sock->tx_hook = snmp_tx;

    snmp_register_mibs(p);
    return PS_START;

  case SNMP_CONN:
    TRACE(D_EVENTS, "MIBs registered");
    ASSERT(last == SNMP_REGISTER);
    proto_notify_state(&p->p, PS_UP);
    return PS_UP;

  case SNMP_STOP:
    if (p->sock && p->state != SNMP_OPEN && !sk_tx_buffer_empty(p->sock))
    {
      TRACE(D_EVENTS, "closing AgentX session");
      if (p->state == SNMP_OPEN || p->state == SNMP_REGISTER ||
	  p->state == SNMP_CONN)
	snmp_stop_subagent(p);

      p->sock->rx_hook = snmp_rx_skip;
      p->sock->tx_hook = snmp_tx_skip;

      p->startup_timer->hook = snmp_stop_timeout;
      tm_start(p->startup_timer, 150 MS);
      proto_notify_state(&p->p, PS_STOP);
      return PS_STOP;
    }

    p->state = state = SNMP_DOWN;
    /* Fall thru */

  case SNMP_DOWN:
    TRACE(D_EVENTS, "AgentX session closed");
    snmp_cleanup(p);
    proto_notify_state(&p->p, PS_DOWN);
    return PS_DOWN;

  default:
    die("unknown snmp state transition");
    return PS_DOWN;
  }
}

/*
 * snmp_init - preinitialize SNMP instance
 * @CF: SNMP configuration generic handle
 *
 * Returns a generic handle pointing to preinitialized SNMP procotol
 * instance.
 */
static struct proto *
snmp_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct snmp_proto *p = SKIP_BACK(struct snmp_proto, p, P);

  p->rl_gen = (struct tbf) TBF_DEFAULT_LOG_LIMITS;
  p->state = SNMP_DOWN;

  return P;
}

/*
 * snmp_cleanup - free all resources allocated by SNMP protocol
 * @p: SNMP protocol instance
 *
 * This function forcefully stops and cleans all resources and memory acqiured
 * by given SNMP protocol instance, such as timers, lists, hash tables etc.
 */
static inline void
snmp_cleanup(struct snmp_proto *p)
{
  /* Function tm_stop() is called inside rfree() */
  rfree(p->startup_timer);
  p->startup_timer = NULL;

  rfree(p->ping_timer);
  p->ping_timer = NULL;

  rfree(p->sock);
  p->sock = NULL;

  rfree(p->lock);
  p->lock = NULL;

  struct snmp_registration *r, *r2;
  WALK_LIST_DELSAFE(r, r2, p->registration_queue)
  {
    rem_node(&r->n);
    mb_free(r);
    r = NULL;
  }

  HASH_FREE(p->bgp_hash);

  rfree(p->lp);
  p->bgp_trie = NULL;

  rfree(p->end_oids);
  p->end_oids = NULL;

  p->state = SNMP_DOWN;
}

/*
 * snmp_connected - start AgentX session on created socket
 * @sk: socket owned by SNMP protocol instance
 *
 * Starts the AgentX communication by sending an agentx-Open-PDU.
 * This function is internal and shouldn't be used outside the SNMP module.
 */
void
snmp_connected(sock *sk)
{
  struct snmp_proto *p = sk->data;
  snmp_set_state(p, SNMP_OPEN);
}

/*
 * snmp_reset - reset AgentX session
 * @p: SNMP protocol instance
 *
 * We wait until the last PDU written into the socket is send while ignoring all
 * incomming PDUs. Then we hard reset the connection by socket closure. The
 * protocol instance is automatically restarted by nest.
 *
 * Return protocol state (PS_STOP, ...).
 */
int
snmp_reset(struct snmp_proto *p)
{
  return snmp_set_state(p, SNMP_STOP);
}

/*
 * snmp_up - AgentX session has registered all MIBs, protocols is up
 * @p: SNMP protocol instance
 */
void
snmp_up(struct snmp_proto *p)
{
  if (p->state == SNMP_REGISTER)
    snmp_set_state(p, SNMP_CONN);
}

/*
 * snmp_sock_err - handle errors on socket by reopenning the socket
 * @sk: socket owned by SNMP protocol instance
 * @err: socket error code
 */
static void
snmp_sock_err(sock *sk, int UNUSED err)
{
  struct snmp_proto *p = sk->data;
  if (err != 0)
    TRACE(D_EVENTS, "SNMP socket error (%d)", err);
  snmp_set_state(p, SNMP_DOWN);
}

/*
 * snmp_start_locked - open the socket on locked address
 * @lock: object lock guarding the communication mean (address, ...)
 *
 * This function is called when the object lock is acquired. Main goal is to set
 * socket parameters and try to open configured socket. Function
 * snmp_connected() handles next stage of SNMP protocol start. When the socket
 * coundn't be opened, a new try is scheduled after a small delay.
 */
static void
snmp_start_locked(struct object_lock *lock)
{
  struct snmp_proto *p = lock->data;
  if (p->startup_delay)
  {
    ASSERT(p->startup_timer);
    p->startup_timer->hook = snmp_startup_timeout;
    tm_start(p->startup_timer, p->startup_delay);
  }
  else
    snmp_set_state(p, SNMP_LOCKED);
}

/*
 * snmp_startup_timeout - start the initiliazed SNMP protocol
 * @tm: the startup_timer holding the SNMP protocol instance.
 *
 * When the timer rings, the function snmp_startup() is invoked.
 * This function is internal and shouldn't be used outside the SNMP module.
 * Used when we delaying the start procedure, or we want to retry opening
 * the communication socket.
 */
void
snmp_startup_timeout(timer *tm)
{
  struct snmp_proto *p = tm->data;
  snmp_set_state(p, SNMP_LOCKED);
}

/*
 * snmp_stop_timeout - a timeout for non-responding master agent
 * @tm: the startup_timer holding the SNMP protocol instance.
 *
 * We are trying to empty the TX buffer of communication socket. But if it is
 * not done in reasonable amount of time, the function is called by timeout
 * timer. We down the whole SNMP protocol with cleanup of associated data
 * structures.
 */
static void
snmp_stop_timeout(timer *tm)
{
  struct snmp_proto *p = tm->data;
  snmp_set_state(p, SNMP_DOWN);
}

/*
 * snmp_ping_timeout - send a agentx-Ping-PDU
 * @tm: the ping_timer holding the SNMP protocol instance.
 *
 * Send an agentx-Ping-PDU. This function is periodically called by ping
 * timer.
 */
static void
snmp_ping_timeout(timer *tm)
{
  struct snmp_proto *p = tm->data;
  snmp_ping(p);
}

/*
 * snmp_start - Initialize the SNMP protocol instance
 * @P: SNMP protocol generic handle
 *
 * The first step in AgentX subagent startup is protocol initialition.
 * We must prepare lists, find BGP peers and finally asynchronously start
 * a AgentX subagent session.
 */
static int
snmp_start(struct proto *P)
{
  struct snmp_proto *p = (void *) P;
  struct snmp_config *cf = (struct snmp_config *) P->cf;

  p->local_ip = cf->local_ip;
  p->remote_ip = cf->remote_ip;
  p->local_port = cf->local_port;
  p->remote_port = cf->remote_port;
  p->bgp_local_as = cf->bgp_local_as;
  p->bgp_local_id = cf->bgp_local_id;
  p->timeout = cf->timeout;
  p->startup_delay = cf->startup_delay;

  p->pool = p->p.pool;
  p->lp = lp_new(p->pool);
  p->mib_tree = mb_alloc(p->pool, sizeof(struct mib_tree));
  p->bgp_trie = f_new_trie(p->lp, 0);
  p->end_oids = lp_new(p->pool);

  p->startup_timer = tm_new_init(p->pool, snmp_startup_timeout, p, 0, 0);
  p->ping_timer = tm_new_init(p->pool, snmp_ping_timeout, p, p->timeout, 0);

  init_list(&p->registration_queue);

  /* We create copy of bonds to BGP protocols. */
  HASH_INIT(p->bgp_hash, p->pool, 10);

  mib_tree_init(p->pool, p->mib_tree);
  snmp_bgp4_start(p);
  agentx_get_mib_init(p->pool);

  return snmp_set_state(p, SNMP_INIT);
}

static inline int
snmp_reconfigure_logic(struct snmp_proto *p, const struct snmp_config *new)
{
  const struct snmp_config *old = SKIP_BACK(struct snmp_config, cf, p->p.cf);

  if (old->bonds != new->bonds)
    return 0;

  uint bonds = old->bonds;
  struct snmp_bond *b1, *b2;
  WALK_LIST(b1, new->bgp_entries)
  {
    WALK_LIST(b2, old->bgp_entries)
    {
      if (!bstrcmp(b1->config->name, b2->config->name))
	goto skip;
    }

    return 0;
skip:
    bonds--;
  }

  if (bonds != 0)
    return 0;

  if (old->trans_type != new->trans_type
      || ip4_compare(old->local_ip, new->local_ip)
      || old->local_port != new->local_port
      || ipa_compare(old->remote_ip, new->remote_ip)
      || !bstrcmp(old->remote_path, new->remote_path)
      || old->remote_port != new->remote_port
	  // TODO can be changed on the fly
      || !ip4_compare(old->bgp_local_id, new->bgp_local_id)
      || old->bgp_local_as != new->bgp_local_as // TODO can be changed on the fly
      || old->timeout != new->timeout
    //|| old->startup_delay != new->startup_delay
      || old->priority != new->priority
      || !strncmp(old->description, new->description, UINT32_MAX))
    return 0;

  return 1;

/*
  return !memcmp(((byte *) old) + sizeof(struct proto_config),
      ((byte *) new) + sizeof(struct proto_config),
      OFFSETOF(struct snmp_config, description) - sizeof(struct proto_config))
    && ! strncmp(old->description, new->description, UINT32_MAX);
*/
}

/*
 * snmp_reconfigure - Indicate instance reconfigurability
 * @P - SNMP protocol generic handle, current state
 * @CF - SNMP protocol configuration generic handle carring new values
 *
 * We accept the reconfiguration if the new configuration @CF is identical with
 * the currently deployed configuration. Otherwise we deny reconfiguration because
 * the implementation would be cumbersome.
 */
static int
snmp_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct snmp_proto *p = SKIP_BACK(struct snmp_proto, p, P);
  const struct snmp_config *new = SKIP_BACK(struct snmp_config, cf, CF);

  // TODO do not reject reconfiguration when only BGP peer list changed

  /* We are searching for configuration changes */
  int config_changed = snmp_reconfigure_logic(p, new);

  if (config_changed)
  {
    /* Reinitialize the hash after snmp_shutdown() */
    HASH_INIT(p->bgp_hash, p->pool, 10);
    snmp_bgp4_start(p);
  }

  return config_changed;
}

/*
 * snmp_show_proto_info - print basic information about SNMP protocol instance
 * @P: SNMP protocol generic handle
 */
static void
snmp_show_proto_info(struct proto *P)
{
  struct snmp_proto *p = (void *) P;

  cli_msg(-1006, "  SNMP state: %s", snmp_state_str[p->state]);
  cli_msg(-1006, "  MIBs");

  snmp_bgp4_show_info(p);
}

/*
 * snmp_postconfig - Check configuration correctness
 * @CF: SNMP procotol configuration generic handle
 */
static void
snmp_postconfig(struct proto_config *CF)
{
  const struct snmp_config *cf  = (struct snmp_config *) CF;

  /* Walk the BGP protocols and cache their references. */
  if (cf->bgp_local_as == 0)
    cf_error("local as not specified");
}

/*
 * snmp_shutdown - Forcefully stop the SNMP protocol instance
 * @P: SNMP protocol generic handle
 *
 * Simple cast-like wrapper around snmp_reset(), see more info there.
 */
static int
snmp_shutdown(struct proto *P)
{
  struct snmp_proto *p = SKIP_BACK(struct snmp_proto, p, P);
  return snmp_reset(p);
}


/*
 * Protocol infrastructure
 */

struct protocol proto_snmp = {
  .name =		"SNMP",
  .template =		"snmp%d",
  .channel_mask =	0,
  .proto_size =		sizeof(struct snmp_proto),
  .config_size =	sizeof(struct snmp_config),
  .postconfig =		snmp_postconfig,
  .init =		snmp_init,
  .start =		snmp_start,
  .reconfigure =	snmp_reconfigure,
  .shutdown =		snmp_shutdown,
  .show_proto_info = 	snmp_show_proto_info,
};

void
snmp_build(void)
{
  proto_build(&proto_snmp);
}

