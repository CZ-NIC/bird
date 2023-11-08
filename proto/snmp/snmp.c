/*
 *	BIRD -- Simple Network Management Protocol (SNMP)
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * Simple Network Management Protocol State Machine
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

static const char * const snmp_state[] = {
  [SNMP_INIT]	    = "SNMP INIT",
  [SNMP_LOCKED]	    = "SNMP LOCKED",
  [SNMP_OPEN]	    = "SNMP CONNECTION OPENED",
  [SNMP_REGISTER]   = "SNMP REGISTERING MIBS",
  [SNMP_CONN]	    = "SNMP CONNECTED",
  [SNMP_STOP]	    = "SNMP STOPPING",
  [SNMP_DOWN]	    = "SNMP DOWN",
};

/*
 * snmp_init - preinitialize SNMP instance
 * @CF - SNMP configuration generic handle
 *
 * Return value is generic handle pointing to preinitialized SNMP procotol
 * instance.
 */
static struct proto *
snmp_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct snmp_proto *p = SKIP_BACK(struct snmp_proto, p, P);
  const struct snmp_config *cf = SKIP_BACK(struct snmp_config, cf, CF);

  p->rl_gen = (struct tbf) TBF_DEFAULT_LOG_LIMITS;

  p->local_ip = cf->local_ip;
  p->remote_ip = cf->remote_ip;
  p->local_port = cf->local_port;
  p->remote_port = cf->remote_port;

  p->bgp_local_as = cf->bgp_local_as;
  p->bgp_local_id = cf->bgp_local_id;

  snmp_log("changing state to INIT");
  p->state = SNMP_INIT;

  p->timeout = cf->timeout;

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

  struct snmp_register *r, *r2;
  WALK_LIST_DELSAFE(r, r2, p->register_queue)
  {
    rem_node(&r->n);
    mb_free(r);
    r = NULL;
  }

  struct snmp_registered_oid *ro, *ro2;
  WALK_LIST_DELSAFE(ro, ro2, p->bgp_registered)
  {
    rem_node(&r->n);
    mb_free(ro);
    ro = NULL;
  }

  HASH_FREE(p->bgp_hash);

  rfree(p->lp);
  p->bgp_trie = NULL;

  p->state = SNMP_DOWN;
}

/*
 * snmp_down - stop the SNMP protocol and free resources
 * @p - SNMP protocol instance
 *
 * AgentX session is destroyed by closing underlying socket and all resources
 * are freed. Afterwards, the PS_DOWN protocol state is announced.
 */
void
snmp_down(struct snmp_proto *p)
{
  snmp_cleanup(p);
  proto_notify_state(&p->p, PS_DOWN);
}

/*
 * snmp_connected - start AgentX session on established channel
 * @sk - socket owned by SNMP protocol instance
 *
 * Starts the AgentX communication by sending an agentx-Open-PDU.
 * This function is internal and shouldn't be used outside the SNMP module.
 */
void
snmp_connected(sock *sk)
{
  struct snmp_proto *p = sk->data;

  p->state = SNMP_OPEN;

  sk->rx_hook = snmp_rx;
  sk->tx_hook = NULL;
  //sk->tx_hook = snmp_tx;

  snmp_start_subagent(p);

  // TODO ping interval <move to do_response()>
  tm_set(p->ping_timer, current_time() + p->timeout S);
}

/*
 * snmp_sock_disconnect - end or reset socket connection
 * @p - SNMP protocol instance
 *
 * If the @reconnect flags is set, we close the socket and then reestablish
 * the AgentX session by reentering the start procedure as from the
 * snmp_start_locked() function.
 * Otherwise we simply shutdown the SNMP protocol if the flag is clear.
 * This function is internal and shouldn't be used outside the SNMP module.
 */
void
snmp_sock_disconnect(struct snmp_proto *p, int reconnect)
{
  tm_stop(p->ping_timer);

  if (!reconnect)
    return snmp_down(p);

  proto_notify_state(&p->p, PS_START);
  rfree(p->sock);
  p->sock = NULL;

  snmp_log("changing state to LOCKED");
  p->state = SNMP_LOCKED;

  /* We try to reconnect after a short delay */
  p->startup_timer->hook = snmp_startup_timeout;
  tm_start(p->startup_timer, 4 S);  // TODO make me configurable
}

/*
 * snmp_sock_err - handle errors on socket by reopenning the socket
 * @sk - socket owned by SNMP protocol instance
 * @err - socket error errno
 */
static void
snmp_sock_err(sock *sk, int UNUSED err)
{
  snmp_log("socket error '%s' (errno: %d)", strerror(err), err);
  struct snmp_proto *p = sk->data;
  p->errs++;

  snmp_sock_disconnect(p, 1);
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

  snmp_log("changing state to LOCKED");
  p->state = SNMP_LOCKED;
  sock *s = p->sock;

  p->to_send = 0;
  p->errs = 0;


  if (!p->bgp_trie)
    p->bgp_trie = f_new_trie(p->lp, 0);  // TODO user-data attachment size

  if (!s)
  {
    s = sk_new(p->pool);
    s->type = SK_TCP_ACTIVE;
    s->saddr = p->local_ip;
    s->daddr = p->remote_ip;
    s->dport = p->remote_port;
    s->rbsize = SNMP_RX_BUFFER_SIZE;
    s->tbsize = SNMP_TX_BUFFER_SIZE;

    //s->tos = IP_PREC_INTERNET_CONTROL
    s->tx_hook = snmp_connected;
    s->err_hook = snmp_sock_err;

    p->sock = s;
    s->data = p;

    p->to_send = 0;
    p->errs = 0;
  }

  /* Try opening the socket, schedule a retry on fail */
  if (sk_open(s) < 0)
    tm_set(p->startup_timer, current_time() + p->timeout S);
}

/*
 * snmp_reconnect - helper restarting the AgentX session on packet errors
 * @tm - the startup_timer holding the SNMP protocol instance
 *
 * Rerun the SNMP module start procedure. Used in situations when the master
 * agent returns an agentx-Response-PDU with 'Not Opened' error. We do not close
 * the socket if have one.
 */
void
snmp_reconnect(timer *tm)
{
  struct snmp_proto *p = tm->data;
  if (p->state == SNMP_STOP ||
      p->state == SNMP_DOWN)
    return;

  // TODO is SNMP_RESET really needed ?
  if (p->state == SNMP_INIT ||
      p->state == SNMP_RESET)
    snmp_startup(p);

  if (!p->sock)
    snmp_start_locked(p->lock);
  else
    snmp_connected(p->sock);
}

/*
 * snmp_startup - start initialized SNMP protocol
 * @p - SNMP protocol to start
 *
 * Starting of SNMP protocols begins with address acqusition through object
 * lock. Next step is handled by snmp_start_locked() function.
 * This function is internal and shouldn't be used outside the SNMP
 * module.
 */
void
snmp_startup(struct snmp_proto *p)
{
  if (p->state == SNMP_OPEN ||
      p->state == SNMP_REGISTER ||
      p->state == SNMP_CONN)
  {
    return;
  }

  if (p->lock)
  {
    snmp_start_locked(p->lock);
    return;
  }

  p->state = SNMP_INIT;

  struct object_lock *lock;
  lock = p->lock = olock_new(p->pool);

  // lock->addr
  // lock->port
  // lock->iface
  // lock->vrf
  lock->type = OBJLOCK_TCP;
  lock->hook = snmp_start_locked;
  lock->data = p;

  olock_acquire(lock);
}

/*
 * snmp_startup_timeout - start the initiliazed SNMP protocol
 * @tm - the startup_timer holding the SNMP protocol instance.
 *
 * When the timer rings, the function snmp_startup() is invoked.
 * This function is internal and shoudln't be used outside the SNMP module.
 * Used when we delaying the start procedure, or we want to resend
 * an agentx-Open-PDU for non-responding master agent.
 */
void
snmp_startup_timeout(timer *tm)
{
  snmp_startup(tm->data);
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
  snmp_down(tm->data);
}

/*
 * snmp_ping_timeout - send a agentx-Ping-PDU
 * @tm - the ping_timer holding the SNMP protocol instance.
 *
 * Send an agentx-Ping-PDU and reset the timer for next ping.
 */
static void
snmp_ping_timeout(timer *tm)
{
  struct snmp_proto *p = tm->data;

  if (p->state == SNMP_REGISTER ||
      p->state == SNMP_CONN)
  {
    snmp_ping(p);
    tm_set(tm, current_time() + p->timeout S);
  }
}

/*
 * snmp_start - Initialize the SNMP protocol instance
 * @P - SNMP protocol generic handle
 *
 * The first step in AgentX subagent startup is protocol initialition.
 * We must prepare lists, find BGP peers and finally asynchornously open
 * a AgentX subagent session through snmp_startup() function call.
 */
static int
snmp_start(struct proto *P)
{
  struct snmp_proto *p = (void *) P;
  struct snmp_config *cf = (struct snmp_config *) P->cf;

  p->startup_timer = tm_new_init(p->pool, snmp_startup_timeout, p, 0, 0);
  p->ping_timer = tm_new_init(p->pool, snmp_ping_timeout, p, 0, 0);

  p->pool = p->p.pool;
  p->lp = lp_new(p->pool);
  p->bgp_trie = f_new_trie(p->lp, 0);
  //p->bgp_trie = f_new_trie(lp, cf->bonds);  // TODO user-data attachment size

  init_list(&p->register_queue);
  init_list(&p->bgp_registered);

  /* We create copy of bonds to BGP protocols. */
  HASH_INIT(p->bgp_hash, p->pool, 10);

  struct snmp_bond *b;
  WALK_LIST(b, cf->bgp_entries)
  {
    const struct bgp_config *bc = (struct bgp_config *) b->proto;
    if (bc && !ipa_zero(bc->remote_ip))
    {
      struct snmp_bgp_peer *peer = \
	mb_allocz(p->pool, sizeof(struct snmp_bgp_peer));
      peer->config = bc;
      peer->peer_ip = bc->remote_ip;

      struct net_addr net;
      net_fill_ip4(&net, ipa_to_ip4(peer->peer_ip), IP4_MAX_PREFIX_LENGTH);

      trie_add_prefix(p->bgp_trie, &net, IP4_MAX_PREFIX_LENGTH, IP4_MAX_PREFIX_LENGTH);

      HASH_INSERT(p->bgp_hash, SNMP_HASH, peer);
    }
  }

  snmp_startup(p);
  return PS_START;
}

/*
 * snmp_reconfigure - Test if SNMP instance is reconfigurable
 * @P - SNMP protocol generic handle, current state
 * @CF - SNMP protocol configuration generic handle carring new values
 *
 * We accept the reconfiguration if the new configuration @CF is identical with
 * the currently deployed. Otherwise we deny reconfiguration because
 * the implementation would be cumbersome.
 */
static int
snmp_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct snmp_proto *p = SKIP_BACK(struct snmp_proto, p, P);
  const struct snmp_config *new = SKIP_BACK(struct snmp_config, cf, CF);
  const struct snmp_config *old = SKIP_BACK(struct snmp_config, cf, p->p.cf);

  struct snmp_bond *b1, *b2;
  WALK_LIST(b1, new->bgp_entries)
  {
    WALK_LIST(b2, old->bgp_entries)
    {
      if (!strcmp(b1->proto->name, b2->proto->name))
	goto skip;
    }

    return 0;
skip:;
  }

  return !memcmp(((byte *) old) + sizeof(struct proto_config),
      ((byte *) new) + sizeof(struct proto_config),
      OFFSETOF(struct snmp_config, description) - sizeof(struct proto_config))
    && ! strncmp(old->description, new->description, UINT32_MAX);
}

/*
 * snmp_show_proto_info - Print basic information about SNMP protocol instance
 * @P - SNMP protocol generic handle
 */
static void
snmp_show_proto_info(struct proto *P)
{
  struct snmp_proto *sp = (void *) P;
  struct snmp_config *c = (void *) P->cf;

  cli_msg(-1006, "");
  cli_msg(-1006, " snmp status %s", snmp_state[sp->state]);
  cli_msg(-1006, " default local as %u",  sp->bgp_local_as);
  cli_msg(-1006, " default local id %I4", sp->bgp_local_id);
  cli_msg(-1006, "");
  cli_msg(-1006, "  BGP peers");

  struct snmp_bond *bond;
  WALK_LIST(bond, c->bgp_entries)
  {
    struct proto_config *cf = P->cf;
    struct bgp_config *bcf = (struct bgp_config *) cf;
    struct proto *p = cf->proto;
    struct bgp_proto *bp = (struct bgp_proto *) cf->proto;
    struct bgp_conn *conn = bp->conn;

    cli_msg(-1006, "    name: %s", cf->name);
    cli_msg(-1006, "");
    cli_msg(-1006, "	loc. identifier: %I4", bp->local_id);
    cli_msg(-1006, "    rem. identifier: %I4", bp->remote_id);
    cli_msg(-1006, "    admin status: %s", (p->disabled) ? "stop" :
	      "start");
    cli_msg(-1006, "    version: 4");
    cli_msg(-1006, "    local ip: %I4", bcf->local_ip);
    cli_msg(-1006, "    remote ip: %I4", bcf->remote_ip);
    cli_msg(-1006, "    local port: %I4", bcf->local_port);
    cli_msg(-1006, "    remote port: %I4", bcf->remote_port);

    /*
    if (conn) {
      cli_msg(-1006, "    state: %u", conn->state);
      cli_msg(-1006, "    remote as: %u", conn->remote_caps->as4_number);
    }
    */

    cli_msg(-1006, "    in updates: %u", bp->stats.rx_updates);
    cli_msg(-1006, "    out updates: %u", bp->stats.tx_updates);
    cli_msg(-1006, "    in total: %u", bp->stats.rx_messages);
    cli_msg(-1006, "    out total: %u", bp->stats.tx_messages);
    cli_msg(-1006, "    fsm transitions: %u",
      bp->stats.fsm_established_transitions);

    cli_msg(-1006, "    fsm total time: -- (0)");
    cli_msg(-1006, "    retry interval: %u", bcf->connect_retry_time);

    /*
    if (conn) {
      cli_msg(-1006, "    hold time: %u", conn->hold_time);
      cli_msg(-1006, "    keep alive: %u", conn->keepalive_time );
    }
    */

    cli_msg(-1006, "    hold configurated: %u", bcf->hold_time );
    cli_msg(-1006, "    keep alive config: %u", bcf->keepalive_time );

    cli_msg(-1006, "    min AS origin. int.: -- (0)");
    cli_msg(-1006, "    min route advertisement: %u", 0 );
    cli_msg(-1006, "    in update elapsed time: %u", 0 );

    if (!conn)
      cli_msg(-1006, "  no default connection");

    cli_msg(-1006, "  outgoinin_conn state %u", bp->outgoing_conn.state + 1);
    cli_msg(-1006, "  incoming_conn state: %u", bp->incoming_conn.state + 1);
    cli_msg(-1006, "");
  }
}

/*
 * snmp_postconfig - Check configuration correctness
 * @CF - SNMP procotol configuration generic handle
 */
static void
snmp_postconfig(struct proto_config *CF)
{
  /* Walk the BGP protocols and cache their references. */
  if (((struct snmp_config *) CF)->bgp_local_as == 0)
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

  tm_stop(p->ping_timer);

  if (p->state == SNMP_OPEN ||
      p->state == SNMP_REGISTER ||
      p->state == SNMP_CONN)
  {
    /* We have a connection established (at leased send out Open-PDU). */
    snmp_log("changing state to STOP");
    p->state = SNMP_STOP;
    p->startup_timer->hook = snmp_stop_timeout;
    tm_set(p->startup_timer, current_time() + p->timeout S);
    snmp_stop_subagent(p);

    return PS_STOP;
  }
  else
  {
    /* We did not create a connection, we clean the lock and other stuff. */
    snmp_cleanup(p);
    return PS_DOWN;
  }
}


/*
 * Protocol infrastructure
 */

struct protocol proto_snmp = {
  .name =		"Snmp",
  .template =		"snmp%d",
  .channel_mask =	NB_ANY,
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

