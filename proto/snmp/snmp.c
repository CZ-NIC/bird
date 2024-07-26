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
 *	  |   acquiring object lock for communication socket
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
 *	  |   BIRD receive response for Open-PDU
 *	  V
 *    +-----------------+
 *    | SNMP_REGISTER   |     session was established, subagent registers MIBs
 *    +-----------------+
 *	  |
 *	  |   subagent received responses for all registration requests
 *	  V
 *    +-----------------+
 *    | SNMP_CONN	|     everything is set
 *    +-----------------+
 *	  |
 * 	  |   function snmp_shutdown() is called, BIRD sends Close-PDU
 *	  V
 *    +-----------------+
 *    | SNMP_STOP	|     waiting for response
 *    +-----------------+
 *	  |
 *	  |   cleaning old state information
 *	  V
 *    +-----------------+
 *    | SNMP_DOWN	|     session is closed
 *    +-----------------+
 *
 *
 *    +-----------------+
 *    | SNMP_RESET      |     waiting to transmit response to malformed packet
 *    +-----------------+
 *	 |
 *       |    response was send, reseting the session (with socket)
 *       |
 *	 \--> SNMP_LOCKED
 *
 *
 *  Erroneous transitions:
 *    SNMP is UP in states SNMP_CONN and also in SNMP_REGISTER because the
 *    session is establised and the GetNext request should be responsed
 *    without regard to MIB registration.
 *
 *    When the session has been closed for some reason (socket error, receipt of
 *    Close-PDU) SNMP cleans the session information and message queue and goes
 *    back to the SNMP_LOCKED state.
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

// TODO: remove me
#include "proto/bgp/bgp.h"

const char agentx_master_addr[] = AGENTX_MASTER_ADDR;
const struct oid *agentx_available_mibs[AGENTX_MIB_COUNT + 1] = { 0 };

static void snmp_start_locked(struct object_lock *lock);
static void snmp_sock_err(sock *sk, int err);
static void snmp_stop_timeout(timer *tm);
static void snmp_cleanup(struct snmp_proto *p);

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
  u8 ids = LOAD_U8(src->n_subid);

  if (ids > 0)
    STORE_U32(dest->ids[ids - 1], LOAD_U32(src->ids[ids - 1]) + 1);

  agentx_available_mibs[AGENTX_MIB_COUNT] = dest;
}

/*
 * agentx_get_mib - classify an OID based on MIB prefix
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
 * snmp_tx_skip - handle empty TX-buffer during session reset
 * @sk: communication socket
 *
 * The socket tx_hook is called when the TX-buffer is empty, i.e. all data was
 * send. This function is used only when we found malformed PDU and we are
 * resetting the established session. If called, we are reseting the session.
 */
static void
snmp_tx_skip(sock *sk)
{
  struct snmp_proto *p = sk->data;
  proto_notify_state(&p->p, snmp_set_state(p, SNMP_DOWN));
}

/*
 * snmp_set_state - change state with associated actions
 * @p - SNMP protocol instance
 * @state - new SNMP protocol state
 *
 * This function does not notify the bird about protocol state. It is therefore
 * a responsibility of the caller to use the returned value appropriately.
 *
 * Return current protocol state.
 */
int
snmp_set_state(struct snmp_proto *p, enum snmp_proto_state state)
{
  enum snmp_proto_state last = p->state;
  const struct snmp_config *cf = (struct snmp_config *) p->p.cf;

  TRACE(D_EVENTS, "SNMP changing state to %u", state);

  p->state = state;

  switch (state)
  {
  case SNMP_INIT:
    DBG("snmp -> SNMP_INIT\n");
    ASSERT(last == SNMP_DOWN);

    if (cf->trans_type == SNMP_TRANS_TCP)
    {
      /* We need to lock the IP address */
      struct object_lock *lock;
      lock = p->lock = olock_new(p->pool);

      /*
       * lock->iface
       * lock->vrf
       */
      lock->addr = ipa_from_ip4(cf->remote_ip);
      lock->port = cf->remote_port;
      lock->type = OBJLOCK_TCP;
      lock->hook = snmp_start_locked;
      lock->data = p;
      olock_acquire(lock);
      return PS_START;
    }

    p->state = state = SNMP_LOCKED;
    /* Fall thru */

  case SNMP_LOCKED:
    DBG("snmp -> SNMP_LOCKED\n");
    ASSERT(last == SNMP_INIT || SNMP_RESET);
    sock *s = sk_new(p->pool);

    if (cf->trans_type == SNMP_TRANS_TCP)
    {
      s->type = SK_TCP_ACTIVE;
      s->saddr = ipa_from_ip4(p->local_ip);
      s->daddr = ipa_from_ip4(p->remote_ip);
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
      rfree(s);
      p->sock = NULL;
      tm_start(p->startup_timer, p->timeout);
    }
    return PS_START;

  case SNMP_OPEN:
    DBG("snmp -> SNMP_OPEN\n");
    ASSERT(last == SNMP_LOCKED);
    p->sock->rx_hook = snmp_rx;
    p->sock->tx_hook = NULL;
    snmp_start_subagent(p);
    p->startup_timer->hook = snmp_stop_timeout;
    tm_start(p->startup_timer, 1 S);
    return PS_START;

  case SNMP_REGISTER:
    DBG("snmp -> SNMP_REGISTER\n");
    ASSERT(last == SNMP_OPEN);
    tm_stop(p->startup_timer); /* stop timeout */
    snmp_register_mibs(p);
    return PS_START;

  case SNMP_CONN:
    DBG("snmp -> SNMP_CONN\n");
    ASSERT(last == SNMP_REGISTER);
    return PS_UP;

  case SNMP_STOP:
    DBG("snmp -> SNMP_STOP\n");
    ASSUME(last == SNMP_REGISTER || last == SNMP_CONN);
    snmp_stop_subagent(p);
    // FIXME: special treatment for SNMP_OPEN last state?
    p->sock->rx_hook = snmp_rx_skip;
    p->sock->tx_hook = snmp_tx_skip;

    p->startup_timer->hook = snmp_stop_timeout;
    tm_start(p->startup_timer, p->timeout);
    return PS_STOP;

  case SNMP_DOWN:
    DBG("snmp -> SNMP_DOWN\n");
    ASSERT(last == SNMP_STOP || last == SNMP_RESET);
    snmp_cleanup(p);
    // FIXME: handle the state in which we call proto_notify_state and
    // immediately return PS_DOWN from snmp_shutdown()
    return PS_DOWN;

  case SNMP_RESET:
    // TODO remove SNMP_RESET state
    DBG("snmp -> SNMP_RESET\n");
    ASSUME(last == SNMP_REGISTER || last == SNMP_CONN);
    ASSUME(p->sock);
    snmp_stop_subagent(p);
    // FIXME: special treatment for SNMP_OPEN last state?
    p->sock->rx_hook = snmp_rx_skip;
    p->sock->tx_hook = snmp_tx_skip;
    return PS_STOP;

  default:
    die("unknown snmp state transition");
    return PS_DOWN;
  }
}

/*
 * snmp_init - preinitialize SNMP instance
 * @CF - SNMP configuration generic handle
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
 * @p - SNMP protocol instance
 *
 * This function forcefully stops and cleans all resources and memory acqiured
 * by given SNMP protocol instance, such as timers, lists, hash tables etc.
 * Function snmp_cleanup() does not change the protocol state to PS_DOWN for
 * practical reasons, it should be done by the caller.
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

  p->state = SNMP_DOWN;
}

/*
 * snmp_connected - start AgentX session on created socket
 * @sk - socket owned by SNMP protocol instance
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
 */
void
snmp_reset(struct snmp_proto *p)
{
  proto_notify_state(&p->p, snmp_set_state(p, SNMP_RESET));
}


/*
 * snmp_stop - close AgentX session
 * @p: SNMP protocol instance
 *
 * We write agentx-Close-PDU into the socket, wait until all written PDUs are
 * send and then close the socket. The protocol instance is automatically
 * restarted by nest.
 */
void
snmp_stop(struct snmp_proto *p)
{
  // TODO: add option for passing close reason for agentx-Close-PDU
  proto_notify_state(&p->p, snmp_set_state(p, SNMP_STOP));
}


/*
 * snmp_sock_err - handle errors on socket by reopenning the socket
 * @sk - socket owned by SNMP protocol instance
 * @err - socket error errno
 */
static void
snmp_sock_err(sock *sk, int UNUSED err)
{
  struct snmp_proto *p = sk->data;

  TRACE(D_EVENTS, "SNMP socket error %d", err);
  snmp_reset(p);
}

/*
 * snmp_start_locked - open the socket on locked address
 * @lock - object lock guarding the communication mean (address, ...)
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
 * snmp_reconnect - helper restarting the AgentX session on packet errors
 * @tm - the startup_timer holding the SNMP protocol instance
 *
 * Try to recover from an error by reseting the SNMP protocol. It is a simple
 * snmp_reset() wrapper for timers.
 */
void
snmp_reconnect(timer *tm)
{
  struct snmp_proto *p = tm->data;
  snmp_reset(p);
  return;
}

/*
 * snmp_startup_timeout - start the initiliazed SNMP protocol
 * @tm - the startup_timer holding the SNMP protocol instance.
 *
 * When the timer rings, the function snmp_startup() is invoked.
 * This function is internal and shouldn't be used outside the SNMP module.
 * Used when we delaying the start procedure, or we want to resend
 * an agentx-Open-PDU for non-responding master agent.
 */
void
snmp_startup_timeout(timer *tm)
{
  struct snmp_proto *p = tm->data;
  snmp_set_state(p, SNMP_LOCKED);
}

/*
 * snmp_stop_timeout - a timeout for nonresponding master agent
 * @tm - the startup_timer holding the SNMP protocol instance.
 *
 * We are shutting down the SNMP protocol instance and we sent the
 * agentx-Close-PDU. This function forcefully closes the AgentX session and
 * stops the SNMP protocol instance. Used only when we did not receive any
 * agentx-Response-PDU for the sent closed packet (before timeout).
 */
static void
snmp_stop_timeout(timer *tm)
{
  struct snmp_proto *p = tm->data;
  proto_notify_state(&p->p, snmp_set_state(p, SNMP_DOWN));
}

/*
 * snmp_ping_timeout - send a agentx-Ping-PDU
 * @tm - the ping_timer holding the SNMP protocol instance.
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
 * @P - SNMP protocol generic handle
 *
 * The first step in AgentX subagent startup is protocol initialition.
 * We must prepare lists, find BGP peers and finally asynchronously open
 * a AgentX subagent session through snmp_startup() function call.
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
      if (!strcmp(b1->config->name, b2->config->name))
	goto skip;
    }

    return 0;
skip:
    bonds--;
  }

  if (bonds != 0)
    return 0;

  return !memcmp(((byte *) old) + sizeof(struct proto_config),
      ((byte *) new) + sizeof(struct proto_config),
      OFFSETOF(struct snmp_config, description) - sizeof(struct proto_config))
    && ! strncmp(old->description, new->description, UINT32_MAX);
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

  cli_msg(-1006, "  SNMP state %u", p->state);
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
 * @P - SNMP protocol generic handle
 *
 * If we have established connection, we firstly stop the subagent and then
 * later cleanup the protocol. The subagent stopping consist of sending the
 * agentx-Close-PDU and changing the current protocol state to PS_STOP.
 * If we have no connection created, we simple do the cleanup.
 * The cleanup is transition straight to PS_DOWN state with snmp_cleanup() call.
 */
static int
snmp_shutdown(struct proto *P)
{
  struct snmp_proto *p = SKIP_BACK(struct snmp_proto, p, P);
  return snmp_set_state(p, SNMP_DOWN);
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

