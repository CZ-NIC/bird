/*
 *	BIRD -- Simple Network Management Protocol (SNMP)
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "nest/cli.h"
#include "nest/locks.h"
#include "lib/socket.h"
#include "lib/lists.h"

#include "snmp.h"
#include "subagent.h"

static void snmp_connected(sock *sk);
static void snmp_sock_err(sock *sk, int err);
static void snmp_ping_timer(struct timer *tm);
static void snmp_startup(struct snmp_proto *p);
static void snmp_startup_timeout(timer *t);
static void snmp_start_locked(struct object_lock *lock);

static struct proto *
snmp_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct snmp_proto *p = SKIP_BACK(struct snmp_proto, p, P);
  struct snmp_config *cf = SKIP_BACK(struct snmp_config, cf, CF);

  p->rl_gen = (struct tbf) TBF_DEFAULT_LOG_LIMITS;

  p->local_ip = cf->local_ip;
  p->remote_ip = cf->remote_ip;
  p->local_port = cf->local_port;
  p->remote_port = cf->remote_port;
  p->state = SNMP_INIT;

  // p->timeout = cf->timeout;
  p->timeout = 15;

  log(L_INFO "snmp_reconfigure() lip: %I:%u rip: %I:%u",
    cf->local_ip, cf->local_port, cf->remote_ip, cf->remote_port);

  return P;
}

static void
snmp_startup_timeout(timer *t)
{
  snmp_startup(t->data);
}

static void
snmp_startup(struct snmp_proto *p)
{
  /* starting agentX communicaiton channel */
  log(L_INFO "preparing lock");
  struct object_lock *lock;
  lock = p->lock = olock_new(p->p.pool);

  lock->type = OBJLOCK_TCP;
  lock->hook = snmp_start_locked;
  lock->data = p;

  olock_acquire(lock);
  log(L_INFO "lock acquiring");

  log(L_INFO "local ip: %I:%u, remote ip: %I:%u",
    p->local_ip, p->local_port, p->remote_ip, p->remote_port);
}

static void
snmp_start_locked(struct object_lock *lock)
{
  log(L_INFO "snmp_start_locked() - preparing socket ");
  struct snmp_proto *p = lock->data;

  sock *s = sk_new(p->p.pool);
  s->type = SK_TCP_ACTIVE;
  s->saddr = p->local_ip;
  s->daddr = p->remote_ip;
  s->dport = p->remote_port;
  s->rbsize = SNMP_RX_BUFFER_SIZE;
  s->tbsize = SNMP_TX_BUFFER_SIZE;

  //s->tos = IP_PREC_INTERNET_CONTROL
  //s->rx_hook = snmp_connected;
  s->tx_hook = snmp_connected;
  s->err_hook = snmp_sock_err;

  p->sock = s;
  s->data = p;

  p->to_send = 0;
  p->errs = 0;

  snmp_startup(p);

  if (sk_open(s) < 0)
    log(L_ERR "Cannot open listening socket");

  log(L_INFO "socket ready!, trying to connect");
}

static void
snmp_tx(sock *sk UNUSED)
{
  log(L_INFO "snmp_tx() something, yay!");
}


static void
snmp_connected(sock *sk)
{
  struct snmp_proto *p = sk->data;
  log(L_INFO "snmp_connected() connection created");
  byte *buf UNUSED = sk->rbuf;

  sk->rx_hook = snmp_rx;
  sk->tx_hook = snmp_tx;

  snmp_start_subagent(p);
}

static void
snmp_sock_err(sock *sk, int err)
{
  log(L_INFO "snmp_sock_err() %s - err no: %d",  strerror(err), err);

  struct snmp_proto *p = sk->data;
  tm_stop(p->ping_timer);

  rfree(p->sock);
  p->sock = NULL;

  p->state = SNMP_ERR;
  tm_start(p->startup_timer, 15 S);
}

static int
snmp_start(struct proto *P)
{
  log(L_INFO "snmp_start() - starting timer (almost)");
  struct snmp_proto *p = (void *) P;
  struct snmp_config *cf = (struct snmp_config *) P->cf;

  p->startup_timer = tm_new_init(p->p.pool, snmp_startup_timeout, p, 0, 0);

  p->to_send = 0;
  p->errs = 0;

  p->pool = lp_new(p->p.pool);
  p->bgp_trie = f_new_trie(p->pool, cf->bonds);

  p->ping_timer = tm_new_init(p->p.pool, snmp_ping_timer, p, 0, 0);
  tm_set(p->ping_timer, current_time() + 2 S);


  /* starting agentX communicaiton channel */
  log(L_INFO "preparing lock");
  struct object_lock *lock;
  lock = p->lock = olock_new(p->p.pool);

  lock->type = OBJLOCK_TCP;
  lock->hook = snmp_start_locked;
  lock->data = p;

  olock_acquire(lock);
  log(L_INFO "lock acquired");

  log(L_INFO "local ip: %I:%u, remote ip: %I:%u",
    p->local_ip, p->local_port, p->remote_ip, p->remote_port);

  /* create copy of bonds to bgp */
  HASH_INIT(p->bgp_hash, p->p.pool, 10);

  struct snmp_bond *b;
  WALK_LIST(b, cf->bgp_entries)
  {
    struct bgp_config *bc = (struct bgp_config *) b->proto;
    if (bc && !ipa_zero(bc->remote_ip))
    {
      struct snmp_bgp_peer *peer =
	mb_allocz(p->p.pool, sizeof(struct snmp_bgp_peer));
      peer->config = (struct bgp_config *) b->proto;
      peer->peer_ip = bc->remote_ip;

      struct net_addr *net = mb_allocz(p->p.pool, sizeof(struct net_addr));
      net_fill_ip4(net, ipa_to_ip4(peer->peer_ip), IP4_MAX_PREFIX_LENGTH);

      trie_add_prefix(p->bgp_trie, net, IP4_MAX_PREFIX_LENGTH, IP4_MAX_PREFIX_LENGTH);

      HASH_INSERT(p->bgp_hash, SNMP_HASH, peer);
    }
  }

  return PS_START;
}

static int
snmp_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct snmp_proto *p = SKIP_BACK(struct snmp_proto, p, P);
  struct snmp_config *cf = SKIP_BACK(struct snmp_config, cf, CF);

  p->local_ip = cf->local_ip;
  p->remote_ip = cf->remote_ip;
  p->local_port = cf->local_port;
  p->remote_port = cf->remote_port;
  p->local_as = cf->local_as;
  p->timeout = 15;

  /* TODO walk all bind protocols and find their (new) IP
    to update HASH table */
  log(L_INFO "snmp_reconfigure() lip: %I:%u rip: %I:%u",
    p->local_ip, p->local_port, p->remote_ip, p->remote_port);
  return 1;
}

static void snmp_show_proto_info(struct proto *P)
{
  //struct snmp_proto *sp = (void *) P;
  struct snmp_config *c = (void *) P->cf;

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
    cli_msg(-1006, "    rem. identifier: %u", bp->remote_id);
    // learn more !!
    cli_msg(-1006, "    admin status: %s", (p->disabled) ? "start" :
	      "stop");
    // version ?
    cli_msg(-1006, "    version: 4");
    cli_msg(-1006, "    local ip: %u", bcf->local_ip);
    cli_msg(-1006, "    remote ip: %u", bcf->remote_ip);
    cli_msg(-1006, "    local port: %u", bcf->local_port);
    cli_msg(-1006, "    remote port: %u", bcf->remote_port);
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

    // not supported yet
    cli_msg(-1006, "    fsm total time: --");
    cli_msg(-1006, "    retry interval: %u", bcf->connect_retry_time);

    /*
    if (conn) {
      cli_msg(-1006, "    hold time: %u", conn->hold_time);
      cli_msg(-1006, "    keep alive: %u", conn->keepalive_time );
    }
    */

    cli_msg(-1006, "    hold configurated: %u", bcf->hold_time );
    cli_msg(-1006, "    keep alive config: %u", bcf->keepalive_time );

    // unknown
    cli_msg(-1006, "    min AS origin. int.: --");
    cli_msg(-1006, "    min route advertisement: %u", 0 );
    cli_msg(-1006, "    in update elapsed time: %u", 0 );

    if (!conn)
      cli_msg(-1006, "  no default connection");

    cli_msg(-1006, "  outgoinin_conn state %u", bp->outgoing_conn.state + 1);
    cli_msg(-1006, "  incoming_conn state: %u", bp->incoming_conn.state + 1);
  }
}

static void
snmp_postconfig(struct proto_config *CF)
{
  if (((struct snmp_config *) CF)->local_as == 0)
    cf_error("local as not specified");
}

static void
snmp_ping_timer(struct timer *tm)
{
  log(L_INFO "snmp_ping_timer() ");
  struct snmp_proto *p = tm->data;

  if (p->state == SNMP_CONN)
  {
    snmp_ping(p);
  }

  //tm_set(tm, current_time() + (15 S));
  tm_set(tm, current_time() + 15 S);
}

static int
snmp_shutdown(struct proto *P)
{
  struct snmp_proto *p = SKIP_BACK(struct snmp_proto, p, P);
  p->state = SNMP_INIT;

  tm_stop(p->ping_timer);
  tm_stop(p->startup_timer);

  snmp_stop_subagent(p);
  return PS_DOWN;
}

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