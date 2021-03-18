/*
 *	BIRD -- The Border Gateway Protocol
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *	(c) 2008--2016 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2008--2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Border Gateway Protocol
 *
 * The BGP protocol is implemented in three parts: |bgp.c| which takes care of
 * the connection and most of the interface with BIRD core, |packets.c| handling
 * both incoming and outgoing BGP packets and |attrs.c| containing functions for
 * manipulation with BGP attribute lists.
 *
 * As opposed to the other existing routing daemons, BIRD has a sophisticated
 * core architecture which is able to keep all the information needed by BGP in
 * the primary routing table, therefore no complex data structures like a
 * central BGP table are needed. This increases memory footprint of a BGP router
 * with many connections, but not too much and, which is more important, it
 * makes BGP much easier to implement.
 *
 * Each instance of BGP (corresponding to a single BGP peer) is described by a
 * &bgp_proto structure to which are attached individual connections represented
 * by &bgp_connection (usually, there exists only one connection, but during BGP
 * session setup, there can be more of them). The connections are handled
 * according to the BGP state machine defined in the RFC with all the timers and
 * all the parameters configurable.
 *
 * In incoming direction, we listen on the connection's socket and each time we
 * receive some input, we pass it to bgp_rx(). It decodes packet headers and the
 * markers and passes complete packets to bgp_rx_packet() which distributes the
 * packet according to its type.
 *
 * In outgoing direction, we gather all the routing updates and sort them to
 * buckets (&bgp_bucket) according to their attributes (we keep a hash table for
 * fast comparison of &rta's and a &fib which helps us to find if we already
 * have another route for the same destination queued for sending, so that we
 * can replace it with the new one immediately instead of sending both
 * updates). There also exists a special bucket holding all the route
 * withdrawals which cannot be queued anywhere else as they don't have any
 * attributes. If we have any packet to send (due to either new routes or the
 * connection tracking code wanting to send a Open, Keepalive or Notification
 * message), we call bgp_schedule_packet() which sets the corresponding bit in a
 * @packet_to_send bit field in &bgp_conn and as soon as the transmit socket
 * buffer becomes empty, we call bgp_fire_tx(). It inspects state of all the
 * packet type bits and calls the corresponding bgp_create_xx() functions,
 * eventually rescheduling the same packet type if we have more data of the same
 * type to send.
 *
 * The processing of attributes consists of two functions: bgp_decode_attrs()
 * for checking of the attribute blocks and translating them to the language of
 * BIRD's extended attributes and bgp_encode_attrs() which does the
 * converse. Both functions are built around a @bgp_attr_table array describing
 * all important characteristics of all known attributes.  Unknown transitive
 * attributes are attached to the route as %EAF_TYPE_OPAQUE byte streams.
 *
 * BGP protocol implements graceful restart in both restarting (local restart)
 * and receiving (neighbor restart) roles. The first is handled mostly by the
 * graceful restart code in the nest, BGP protocol just handles capabilities,
 * sets @gr_wait and locks graceful restart until end-of-RIB mark is received.
 * The second is implemented by internal restart of the BGP state to %BS_IDLE
 * and protocol state to %PS_START, but keeping the protocol up from the core
 * point of view and therefore maintaining received routes. Routing table
 * refresh cycle (rt_refresh_begin(), rt_refresh_end()) is used for removing
 * stale routes after reestablishment of BGP session during graceful restart.
 *
 * Supported standards:
 * RFC 4271 - Border Gateway Protocol 4 (BGP)
 * RFC 1997 - BGP Communities Attribute
 * RFC 2385 - Protection of BGP Sessions via TCP MD5 Signature
 * RFC 2545 - Use of BGP Multiprotocol Extensions for IPv6
 * RFC 2918 - Route Refresh Capability
 * RFC 3107 - Carrying Label Information in BGP
 * RFC 4360 - BGP Extended Communities Attribute
 * RFC 4364 - BGP/MPLS IPv4 Virtual Private Networks
 * RFC 4456 - BGP Route Reflection
 * RFC 4486 - Subcodes for BGP Cease Notification Message
 * RFC 4659 - BGP/MPLS IPv6 Virtual Private Networks
 * RFC 4724 - Graceful Restart Mechanism for BGP
 * RFC 4760 - Multiprotocol extensions for BGP
 * RFC 4798 - Connecting IPv6 Islands over IPv4 MPLS
 * RFC 5065 - AS confederations for BGP
 * RFC 5082 - Generalized TTL Security Mechanism
 * RFC 5492 - Capabilities Advertisement with BGP
 * RFC 5549 - Advertising IPv4 NLRI with an IPv6 Next Hop
 * RFC 5575 - Dissemination of Flow Specification Rules
 * RFC 5668 - 4-Octet AS Specific BGP Extended Community
 * RFC 6286 - AS-Wide Unique BGP Identifier
 * RFC 6608 - Subcodes for BGP Finite State Machine Error
 * RFC 6793 - BGP Support for 4-Octet AS Numbers
 * RFC 7311 - Accumulated IGP Metric Attribute for BGP
 * RFC 7313 - Enhanced Route Refresh Capability for BGP
 * RFC 7606 - Revised Error Handling for BGP UPDATE Messages
 * RFC 7911 - Advertisement of Multiple Paths in BGP
 * RFC 7947 - Internet Exchange BGP Route Server
 * RFC 8092 - BGP Large Communities Attribute
 * RFC 8203 - BGP Administrative Shutdown Communication
 * RFC 8212 - Default EBGP Route Propagation Behavior without Policies
 * RFC 8654 - Extended Message Support for BGP
 * draft-ietf-idr-ext-opt-param-07
 * draft-uttaro-idr-bgp-persistence-04
 * draft-walton-bgp-hostname-capability-02
 */

#undef LOCAL_DEBUG

#include <stdlib.h>

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "nest/locks.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "lib/socket.h"
#include "lib/resource.h"
#include "lib/string.h"

#include "bgp.h"


struct linpool *bgp_linpool;		/* Global temporary pool */
struct linpool *bgp_linpool2;		/* Global temporary pool for bgp_rt_notify() */
static list bgp_sockets;		/* Global list of listening sockets */


static void bgp_connect(struct bgp_proto *p);
static void bgp_active(struct bgp_proto *p);
static void bgp_setup_conn(struct bgp_proto *p, struct bgp_conn *conn);
static void bgp_setup_sk(struct bgp_conn *conn, sock *s);
static void bgp_send_open(struct bgp_conn *conn);
static void bgp_update_bfd(struct bgp_proto *p, const struct bfd_options *bfd);

static int bgp_incoming_connection(sock *sk, uint dummy UNUSED);
static void bgp_listen_sock_err(sock *sk UNUSED, int err);

/**
 * bgp_open - open a BGP instance
 * @p: BGP instance
 *
 * This function allocates and configures shared BGP resources, mainly listening
 * sockets. Should be called as the last step during initialization (when lock
 * is acquired and neighbor is ready). When error, caller should change state to
 * PS_DOWN and return immediately.
 */
static int
bgp_open(struct bgp_proto *p)
{
  struct bgp_socket *bs = NULL;
  struct iface *ifa = p->cf->strict_bind ? p->cf->iface : NULL;
  ip_addr addr = p->cf->strict_bind ? p->cf->local_ip :
    (p->ipv4 ? IPA_NONE4 : IPA_NONE6);
  uint port = p->cf->local_port;

  /* FIXME: Add some global init? */
  if (!bgp_linpool)
    init_list(&bgp_sockets);

  /* We assume that cf->iface is defined iff cf->local_ip is link-local */

  WALK_LIST(bs, bgp_sockets)
    if (ipa_equal(bs->sk->saddr, addr) && (bs->sk->sport == port) &&
	(bs->sk->iface == ifa) && (bs->sk->vrf == p->p.vrf))
    {
      bs->uc++;
      p->sock = bs;
      return 0;
    }

  sock *sk = sk_new(proto_pool);
  sk->type = SK_TCP_PASSIVE;
  sk->ttl = 255;
  sk->saddr = addr;
  sk->sport = port;
  sk->iface = ifa;
  sk->vrf = p->p.vrf;
  sk->flags = 0;
  sk->tos = IP_PREC_INTERNET_CONTROL;
  sk->rbsize = BGP_RX_BUFFER_SIZE;
  sk->tbsize = BGP_TX_BUFFER_SIZE;
  sk->rx_hook = bgp_incoming_connection;
  sk->err_hook = bgp_listen_sock_err;

  if (sk_open(sk) < 0)
    goto err;

  bs = mb_allocz(proto_pool, sizeof(struct bgp_socket));
  bs->sk = sk;
  bs->uc = 1;
  p->sock = bs;
  sk->data = bs;

  add_tail(&bgp_sockets, &bs->n);

  if (!bgp_linpool)
  {
    bgp_linpool  = lp_new_default(proto_pool);
    bgp_linpool2 = lp_new_default(proto_pool);
  }

  return 0;

err:
  sk_log_error(sk, p->p.name);
  log(L_ERR "%s: Cannot open listening socket", p->p.name);
  rfree(sk);
  return -1;
}

/**
 * bgp_close - close a BGP instance
 * @p: BGP instance
 *
 * This function frees and deconfigures shared BGP resources.
 */
static void
bgp_close(struct bgp_proto *p)
{
  struct bgp_socket *bs = p->sock;

  ASSERT(bs && bs->uc);

  if (--bs->uc)
    return;

  rfree(bs->sk);
  rem_node(&bs->n);
  mb_free(bs);

  if (!EMPTY_LIST(bgp_sockets))
    return;

  rfree(bgp_linpool);
  bgp_linpool = NULL;

  rfree(bgp_linpool2);
  bgp_linpool2 = NULL;
}

static inline int
bgp_setup_auth(struct bgp_proto *p, int enable)
{
  if (p->cf->password)
  {
    ip_addr prefix = p->cf->remote_ip;
    int pxlen = -1;

    if (p->cf->remote_range)
    {
      prefix = net_prefix(p->cf->remote_range);
      pxlen = net_pxlen(p->cf->remote_range);
    }

    int rv = sk_set_md5_auth(p->sock->sk,
			     p->cf->local_ip, prefix, pxlen, p->cf->iface,
			     enable ? p->cf->password : NULL, p->cf->setkey);

    if (rv < 0)
      sk_log_error(p->sock->sk, p->p.name);

    return rv;
  }
  else
    return 0;
}

static inline struct bgp_channel *
bgp_find_channel(struct bgp_proto *p, u32 afi)
{
  struct bgp_channel *c;
  WALK_LIST(c, p->p.channels)
    if (c->afi == afi)
      return c;

  return NULL;
}

static void
bgp_startup(struct bgp_proto *p)
{
  BGP_TRACE(D_EVENTS, "Started");
  p->start_state = BSS_CONNECT;

  if (!p->passive)
    bgp_active(p);

  if (p->postponed_sk)
  {
    /* Apply postponed incoming connection */
    bgp_setup_conn(p, &p->incoming_conn);
    bgp_setup_sk(&p->incoming_conn, p->postponed_sk);
    bgp_send_open(&p->incoming_conn);
    p->postponed_sk = NULL;
  }
}

static void
bgp_startup_timeout(timer *t)
{
  bgp_startup(t->data);
}


static void
bgp_initiate(struct bgp_proto *p)
{
  int err_val;

  if (bgp_open(p) < 0)
  { err_val = BEM_NO_SOCKET; goto err1; }

  if (bgp_setup_auth(p, 1) < 0)
  { err_val = BEM_INVALID_MD5; goto err2; }

  if (p->cf->bfd)
    bgp_update_bfd(p, p->cf->bfd);

  if (p->startup_delay)
  {
    p->start_state = BSS_DELAY;
    BGP_TRACE(D_EVENTS, "Startup delayed by %d seconds due to errors", p->startup_delay);
    bgp_start_timer(p->startup_timer, p->startup_delay);
  }
  else
    bgp_startup(p);

  return;

err2:
  bgp_close(p);
err1:
  p->p.disabled = 1;
  bgp_store_error(p, NULL, BE_MISC, err_val);
  proto_notify_state(&p->p, PS_DOWN);

  return;
}

/**
 * bgp_start_timer - start a BGP timer
 * @t: timer
 * @value: time (in seconds) to fire (0 to disable the timer)
 *
 * This functions calls tm_start() on @t with time @value and the amount of
 * randomization suggested by the BGP standard. Please use it for all BGP
 * timers.
 */
void
bgp_start_timer(timer *t, uint value)
{
  if (value)
  {
    /* The randomization procedure is specified in RFC 4271 section 10 */
    btime time = value S;
    btime randomize = random() % ((time / 4) + 1);
    tm_start(t, time - randomize);
  }
  else
    tm_stop(t);
}

/**
 * bgp_close_conn - close a BGP connection
 * @conn: connection to close
 *
 * This function takes a connection described by the &bgp_conn structure, closes
 * its socket and frees all resources associated with it.
 */
void
bgp_close_conn(struct bgp_conn *conn)
{
  // struct bgp_proto *p = conn->bgp;

  DBG("BGP: Closing connection\n");
  conn->packets_to_send = 0;
  conn->channels_to_send = 0;
  rfree(conn->connect_timer);
  conn->connect_timer = NULL;
  rfree(conn->keepalive_timer);
  conn->keepalive_timer = NULL;
  rfree(conn->hold_timer);
  conn->hold_timer = NULL;
  rfree(conn->tx_ev);
  conn->tx_ev = NULL;
  rfree(conn->sk);
  conn->sk = NULL;

  mb_free(conn->local_caps);
  conn->local_caps = NULL;
  mb_free(conn->remote_caps);
  conn->remote_caps = NULL;
}


/**
 * bgp_update_startup_delay - update a startup delay
 * @p: BGP instance
 *
 * This function updates a startup delay that is used to postpone next BGP
 * connect. It also handles disable_after_error and might stop BGP instance
 * when error happened and disable_after_error is on.
 *
 * It should be called when BGP protocol error happened.
 */
void
bgp_update_startup_delay(struct bgp_proto *p)
{
  const struct bgp_config *cf = p->cf;

  DBG("BGP: Updating startup delay\n");

  if (p->last_proto_error && ((current_time() - p->last_proto_error) >= cf->error_amnesia_time S))
    p->startup_delay = 0;

  p->last_proto_error = current_time();

  if (cf->disable_after_error)
  {
    p->startup_delay = 0;
    p->p.disabled = 1;
    return;
  }

  if (!p->startup_delay)
    p->startup_delay = cf->error_delay_time_min;
  else
    p->startup_delay = MIN(2 * p->startup_delay, cf->error_delay_time_max);
}

static void
bgp_graceful_close_conn(struct bgp_conn *conn, int subcode, byte *data, uint len)
{
  switch (conn->state)
  {
  case BS_IDLE:
  case BS_CLOSE:
    return;

  case BS_CONNECT:
  case BS_ACTIVE:
    bgp_conn_enter_idle_state(conn);
    return;

  case BS_OPENSENT:
  case BS_OPENCONFIRM:
  case BS_ESTABLISHED:
    if (subcode < 0)
    {
      bgp_conn_enter_close_state(conn);
      bgp_schedule_packet(conn, NULL, PKT_SCHEDULE_CLOSE);
    }
    else
      bgp_error(conn, 6, subcode, data, len);
    return;

  default:
    bug("bgp_graceful_close_conn: Unknown state %d", conn->state);
  }
}

static void
bgp_down(struct bgp_proto *p)
{
  if (p->start_state > BSS_PREPARE)
  {
    bgp_setup_auth(p, 0);
    bgp_close(p);
  }

  BGP_TRACE(D_EVENTS, "Down");
  proto_notify_state(&p->p, PS_DOWN);
}

static void
bgp_decision(void *vp)
{
  struct bgp_proto *p = vp;

  DBG("BGP: Decision start\n");
  if ((p->p.proto_state == PS_START) &&
      (p->outgoing_conn.state == BS_IDLE) &&
      (p->incoming_conn.state != BS_OPENCONFIRM) &&
      !p->passive)
    bgp_active(p);

  if ((p->p.proto_state == PS_STOP) &&
      (p->outgoing_conn.state == BS_IDLE) &&
      (p->incoming_conn.state == BS_IDLE))
    bgp_down(p);
}

static struct bgp_proto *
bgp_spawn(struct bgp_proto *pp, ip_addr remote_ip)
{
  struct symbol *sym;
  char fmt[SYM_MAX_LEN];

  bsprintf(fmt, "%s%%0%dd", pp->cf->dynamic_name, pp->cf->dynamic_name_digits);

  /* This is hack, we would like to share config, but we need to copy it now */
  new_config = config;
  cfg_mem = config->mem;
  conf_this_scope = config->root_scope;
  sym = cf_default_name(fmt, &(pp->dynamic_name_counter));
  proto_clone_config(sym, pp->p.cf);
  new_config = NULL;
  cfg_mem = NULL;

  /* Just pass remote_ip to bgp_init() */
  ((struct bgp_config *) sym->proto)->remote_ip = remote_ip;

  return (void *) proto_spawn(sym->proto, 0);
}

void
bgp_stop(struct bgp_proto *p, int subcode, byte *data, uint len)
{
  proto_notify_state(&p->p, PS_STOP);
  bgp_graceful_close_conn(&p->outgoing_conn, subcode, data, len);
  bgp_graceful_close_conn(&p->incoming_conn, subcode, data, len);
  ev_schedule(p->event);
}

static inline void
bgp_conn_set_state(struct bgp_conn *conn, uint new_state)
{
  if (conn->bgp->p.mrtdump & MD_STATES)
    bgp_dump_state_change(conn, conn->state, new_state);

  conn->state = new_state;
}

void
bgp_conn_enter_openconfirm_state(struct bgp_conn *conn)
{
  /* Really, most of the work is done in bgp_rx_open(). */
  bgp_conn_set_state(conn, BS_OPENCONFIRM);
}

static const struct bgp_af_caps dummy_af_caps = { };
static const struct bgp_af_caps basic_af_caps = { .ready = 1 };

void
bgp_conn_enter_established_state(struct bgp_conn *conn)
{
  struct bgp_proto *p = conn->bgp;
  struct bgp_caps *local = conn->local_caps;
  struct bgp_caps *peer = conn->remote_caps;
  struct bgp_channel *c;

  BGP_TRACE(D_EVENTS, "BGP session established");
  p->last_established = current_time();
  p->stats.fsm_established_transitions++;

  /* For multi-hop BGP sessions */
  if (ipa_zero(p->local_ip))
    p->local_ip = conn->sk->saddr;

  /* For promiscuous sessions */
  if (!p->remote_as)
    p->remote_as = conn->received_as;

  /* In case of LLv6 is not valid during BGP start */
  if (ipa_zero(p->link_addr) && p->neigh && p->neigh->iface && p->neigh->iface->llv6)
    p->link_addr = p->neigh->iface->llv6->ip;

  conn->sk->fast_rx = 0;

  p->conn = conn;
  p->last_error_class = 0;
  p->last_error_code = 0;

  p->as4_session = conn->as4_session;

  p->route_refresh = peer->route_refresh;
  p->enhanced_refresh = local->enhanced_refresh && peer->enhanced_refresh;

  /* Whether we may handle possible GR/LLGR of peer (it has some AF GR-able) */
  p->gr_ready = p->llgr_ready = 0;	/* Updated later */

  /* Whether peer is ready to handle our GR recovery */
  int peer_gr_ready = peer->gr_aware && !(peer->gr_flags & BGP_GRF_RESTART);

  if (p->gr_active_num)
    tm_stop(p->gr_timer);

  /* Number of active channels */
  int num = 0;

  /* Summary state of ADD_PATH RX for active channels */
  uint summary_add_path_rx = 0;

  WALK_LIST(c, p->p.channels)
  {
    const struct bgp_af_caps *loc = bgp_find_af_caps(local, c->afi);
    const struct bgp_af_caps *rem = bgp_find_af_caps(peer,  c->afi);

    /* Use default if capabilities were not announced */
    if (!local->length && (c->afi == BGP_AF_IPV4))
      loc = &basic_af_caps;

    if (!peer->length && (c->afi == BGP_AF_IPV4))
      rem = &basic_af_caps;

    /* Ignore AFIs that were not announced in multiprotocol capability */
    if (!loc || !loc->ready)
      loc = &dummy_af_caps;

    if (!rem || !rem->ready)
      rem = &dummy_af_caps;

    int active = loc->ready && rem->ready;
    c->c.disabled = !active;
    c->c.reloadable = p->route_refresh || c->cf->import_table;

    c->index = active ? num++ : 0;

    c->feed_state = BFS_NONE;
    c->load_state = BFS_NONE;

    /* Channels where peer may do GR */
    uint gr_ready = active && local->gr_aware && rem->gr_able;
    uint llgr_ready = active && local->llgr_aware && rem->llgr_able;

    c->gr_ready = gr_ready || llgr_ready;
    p->gr_ready = p->gr_ready || c->gr_ready;
    p->llgr_ready = p->llgr_ready || llgr_ready;

    /* Remember last LLGR stale time */
    c->stale_time = local->llgr_aware ? rem->llgr_time : 0;

    /* Channels not able to recover gracefully */
    if (p->p.gr_recovery && (!active || !peer_gr_ready))
      channel_graceful_restart_unlock(&c->c);

    /* Channels waiting for local convergence */
    if (p->p.gr_recovery && loc->gr_able && peer_gr_ready)
      c->c.gr_wait = 1;

    /* Channels where regular graceful restart failed */
    if ((c->gr_active == BGP_GRS_ACTIVE) &&
	!(active && rem->gr_able && (rem->gr_af_flags & BGP_GRF_FORWARDING)))
      bgp_graceful_restart_done(c);

    /* Channels where regular long-lived restart failed */
    if ((c->gr_active == BGP_GRS_LLGR) &&
	!(active && rem->llgr_able && (rem->gr_af_flags & BGP_LLGRF_FORWARDING)))
      bgp_graceful_restart_done(c);

    /* GR capability implies that neighbor will send End-of-RIB */
    if (peer->gr_aware)
      c->load_state = BFS_LOADING;

    c->ext_next_hop = c->cf->ext_next_hop && (bgp_channel_is_ipv6(c) || rem->ext_next_hop);
    c->add_path_rx = (loc->add_path & BGP_ADD_PATH_RX) && (rem->add_path & BGP_ADD_PATH_TX);
    c->add_path_tx = (loc->add_path & BGP_ADD_PATH_TX) && (rem->add_path & BGP_ADD_PATH_RX);

    if (active)
      summary_add_path_rx |= !c->add_path_rx ? 1 : 2;

    /* Update RA mode */
    if (c->add_path_tx)
      c->c.ra_mode = RA_ANY;
    else if (c->cf->secondary)
      c->c.ra_mode = RA_ACCEPTED;
    else
      c->c.ra_mode = RA_OPTIMAL;
  }

  p->afi_map = mb_alloc(p->p.pool, num * sizeof(u32));
  p->channel_map = mb_alloc(p->p.pool, num * sizeof(void *));
  p->channel_count = num;
  p->summary_add_path_rx = summary_add_path_rx;

  WALK_LIST(c, p->p.channels)
  {
    if (c->c.disabled)
      continue;

    p->afi_map[c->index] = c->afi;
    p->channel_map[c->index] = c;
  }

  /* proto_notify_state() will likely call bgp_feed_begin(), setting c->feed_state */

  bgp_conn_set_state(conn, BS_ESTABLISHED);
  proto_notify_state(&p->p, PS_UP);
}

static void
bgp_conn_leave_established_state(struct bgp_proto *p)
{
  BGP_TRACE(D_EVENTS, "BGP session closed");
  p->last_established = current_time();
  p->conn = NULL;

  if (p->p.proto_state == PS_UP)
    bgp_stop(p, 0, NULL, 0);
}

void
bgp_conn_enter_close_state(struct bgp_conn *conn)
{
  struct bgp_proto *p = conn->bgp;
  int os = conn->state;

  bgp_conn_set_state(conn, BS_CLOSE);
  tm_stop(conn->keepalive_timer);
  conn->sk->rx_hook = NULL;

  /* Timeout for CLOSE state, if we cannot send notification soon then we just hangup */
  bgp_start_timer(conn->hold_timer, 10);

  if (os == BS_ESTABLISHED)
    bgp_conn_leave_established_state(p);
}

void
bgp_conn_enter_idle_state(struct bgp_conn *conn)
{
  struct bgp_proto *p = conn->bgp;
  int os = conn->state;

  bgp_close_conn(conn);
  bgp_conn_set_state(conn, BS_IDLE);
  ev_schedule(p->event);

  if (os == BS_ESTABLISHED)
    bgp_conn_leave_established_state(p);
}

/**
 * bgp_handle_graceful_restart - handle detected BGP graceful restart
 * @p: BGP instance
 *
 * This function is called when a BGP graceful restart of the neighbor is
 * detected (when the TCP connection fails or when a new TCP connection
 * appears). The function activates processing of the restart - starts routing
 * table refresh cycle and activates BGP restart timer. The protocol state goes
 * back to %PS_START, but changing BGP state back to %BS_IDLE is left for the
 * caller.
 */
void
bgp_handle_graceful_restart(struct bgp_proto *p)
{
  ASSERT(p->conn && (p->conn->state == BS_ESTABLISHED) && p->gr_ready);

  BGP_TRACE(D_EVENTS, "Neighbor graceful restart detected%s",
	    p->gr_active_num ? " - already pending" : "");

  p->gr_active_num = 0;

  struct bgp_channel *c;
  WALK_LIST(c, p->p.channels)
  {
    /* FIXME: perhaps check for channel state instead of disabled flag? */
    if (c->c.disabled)
      continue;

    if (c->gr_ready)
    {
      p->gr_active_num++;

      switch (c->gr_active)
      {
      case BGP_GRS_NONE:
	c->gr_active = BGP_GRS_ACTIVE;
	rt_refresh_begin(c->c.table, &c->c);
	break;

      case BGP_GRS_ACTIVE:
	rt_refresh_end(c->c.table, &c->c);
	rt_refresh_begin(c->c.table, &c->c);
	break;

      case BGP_GRS_LLGR:
	rt_refresh_begin(c->c.table, &c->c);
	rt_modify_stale(c->c.table, &c->c);
	break;
      }
    }
    else
    {
      /* Just flush the routes */
      rt_refresh_begin(c->c.table, &c->c);
      rt_refresh_end(c->c.table, &c->c);
    }

    /* Reset bucket and prefix tables */
    bgp_free_bucket_table(c);
    bgp_free_prefix_table(c);
    bgp_init_bucket_table(c);
    bgp_init_prefix_table(c);
    c->packets_to_send = 0;
  }

  /* p->gr_ready -> at least one active channel is c->gr_ready */
  ASSERT(p->gr_active_num > 0);

  proto_notify_state(&p->p, PS_START);
  tm_start(p->gr_timer, p->conn->remote_caps->gr_time S);
}

/**
 * bgp_graceful_restart_done - finish active BGP graceful restart
 * @c: BGP channel
 *
 * This function is called when the active BGP graceful restart of the neighbor
 * should be finished for channel @c - either successfully (the neighbor sends
 * all paths and reports end-of-RIB for given AFI/SAFI on the new session) or
 * unsuccessfully (the neighbor does not support BGP graceful restart on the new
 * session). The function ends the routing table refresh cycle.
 */
void
bgp_graceful_restart_done(struct bgp_channel *c)
{
  struct bgp_proto *p = (void *) c->c.proto;

  ASSERT(c->gr_active);
  c->gr_active = 0;
  p->gr_active_num--;

  if (!p->gr_active_num)
    BGP_TRACE(D_EVENTS, "Neighbor graceful restart done");

  tm_stop(c->stale_timer);
  rt_refresh_end(c->c.table, &c->c);
}

/**
 * bgp_graceful_restart_timeout - timeout of graceful restart 'restart timer'
 * @t: timer
 *
 * This function is a timeout hook for @gr_timer, implementing BGP restart time
 * limit for reestablisment of the BGP session after the graceful restart. When
 * fired, we just proceed with the usual protocol restart.
 */

static void
bgp_graceful_restart_timeout(timer *t)
{
  struct bgp_proto *p = t->data;

  BGP_TRACE(D_EVENTS, "Neighbor graceful restart timeout");

  if (p->llgr_ready)
  {
    struct bgp_channel *c;
    WALK_LIST(c, p->p.channels)
    {
      /* Channel is not in GR and is already flushed */
      if (!c->gr_active)
	continue;

      /* Channel is already in LLGR from past restart */
      if (c->gr_active == BGP_GRS_LLGR)
	continue;

      /* Channel is in GR, but does not support LLGR -> stop GR */
      if (!c->stale_time)
      {
	bgp_graceful_restart_done(c);
	continue;
      }

      /* Channel is in GR, and supports LLGR -> start LLGR */
      c->gr_active = BGP_GRS_LLGR;
      tm_start(c->stale_timer, c->stale_time S);
      rt_modify_stale(c->c.table, &c->c);
    }
  }
  else
    bgp_stop(p, 0, NULL, 0);
}

static void
bgp_long_lived_stale_timeout(timer *t)
{
  struct bgp_channel *c = t->data;
  struct bgp_proto *p = (void *) c->c.proto;

  BGP_TRACE(D_EVENTS, "Long-lived stale timeout");

  bgp_graceful_restart_done(c);
}


/**
 * bgp_refresh_begin - start incoming enhanced route refresh sequence
 * @c: BGP channel
 *
 * This function is called when an incoming enhanced route refresh sequence is
 * started by the neighbor, demarcated by the BoRR packet. The function updates
 * the load state and starts the routing table refresh cycle. Note that graceful
 * restart also uses routing table refresh cycle, but RFC 7313 and load states
 * ensure that these two sequences do not overlap.
 */
void
bgp_refresh_begin(struct bgp_channel *c)
{
  struct bgp_proto *p = (void *) c->c.proto;

  if (c->load_state == BFS_LOADING)
  { log(L_WARN "%s: BEGIN-OF-RR received before END-OF-RIB, ignoring", p->p.name); return; }

  c->load_state = BFS_REFRESHING;
  rt_refresh_begin(c->c.table, &c->c);

  if (c->c.in_table)
    rt_refresh_begin(c->c.in_table, &c->c);
}

/**
 * bgp_refresh_end - finish incoming enhanced route refresh sequence
 * @c: BGP channel
 *
 * This function is called when an incoming enhanced route refresh sequence is
 * finished by the neighbor, demarcated by the EoRR packet. The function updates
 * the load state and ends the routing table refresh cycle. Routes not received
 * during the sequence are removed by the nest.
 */
void
bgp_refresh_end(struct bgp_channel *c)
{
  struct bgp_proto *p = (void *) c->c.proto;

  if (c->load_state != BFS_REFRESHING)
  { log(L_WARN "%s: END-OF-RR received without prior BEGIN-OF-RR, ignoring", p->p.name); return; }

  c->load_state = BFS_NONE;
  rt_refresh_end(c->c.table, &c->c);

  if (c->c.in_table)
    rt_prune_sync(c->c.in_table, 0);
}


static void
bgp_send_open(struct bgp_conn *conn)
{
  DBG("BGP: Sending open\n");
  conn->sk->rx_hook = bgp_rx;
  conn->sk->tx_hook = bgp_tx;
  tm_stop(conn->connect_timer);
  bgp_prepare_capabilities(conn);
  bgp_schedule_packet(conn, NULL, PKT_OPEN);
  bgp_conn_set_state(conn, BS_OPENSENT);
  bgp_start_timer(conn->hold_timer, conn->bgp->cf->initial_hold_time);
}

static void
bgp_connected(sock *sk)
{
  struct bgp_conn *conn = sk->data;
  struct bgp_proto *p = conn->bgp;

  BGP_TRACE(D_EVENTS, "Connected");
  bgp_send_open(conn);
}

static void
bgp_connect_timeout(timer *t)
{
  struct bgp_conn *conn = t->data;
  struct bgp_proto *p = conn->bgp;

  DBG("BGP: connect_timeout\n");
  if (p->p.proto_state == PS_START)
  {
    bgp_close_conn(conn);
    bgp_connect(p);
  }
  else
    bgp_conn_enter_idle_state(conn);
}

static void
bgp_sock_err(sock *sk, int err)
{
  struct bgp_conn *conn = sk->data;
  struct bgp_proto *p = conn->bgp;

  /*
   * This error hook may be called either asynchronously from main
   * loop, or synchronously from sk_send().  But sk_send() is called
   * only from bgp_tx() and bgp_kick_tx(), which are both called
   * asynchronously from main loop. Moreover, they end if err hook is
   * called. Therefore, we could suppose that it is always called
   * asynchronously.
   */

  bgp_store_error(p, conn, BE_SOCKET, err);

  if (err)
    BGP_TRACE(D_EVENTS, "Connection lost (%M)", err);
  else
    BGP_TRACE(D_EVENTS, "Connection closed");

  if ((conn->state == BS_ESTABLISHED) && p->gr_ready)
    bgp_handle_graceful_restart(p);

  bgp_conn_enter_idle_state(conn);
}

static void
bgp_hold_timeout(timer *t)
{
  struct bgp_conn *conn = t->data;
  struct bgp_proto *p = conn->bgp;

  DBG("BGP: Hold timeout\n");

  /* We are already closing the connection - just do hangup */
  if (conn->state == BS_CLOSE)
  {
    BGP_TRACE(D_EVENTS, "Connection stalled");
    bgp_conn_enter_idle_state(conn);
    return;
  }

  /* If there is something in input queue, we are probably congested
     and perhaps just not processed BGP packets in time. */

  if (sk_rx_ready(conn->sk) > 0)
    bgp_start_timer(conn->hold_timer, 10);
  else if ((conn->state == BS_ESTABLISHED) && p->llgr_ready)
  {
    BGP_TRACE(D_EVENTS, "Hold timer expired");
    bgp_handle_graceful_restart(p);
    bgp_conn_enter_idle_state(conn);
  }
  else
    bgp_error(conn, 4, 0, NULL, 0);
}

static void
bgp_keepalive_timeout(timer *t)
{
  struct bgp_conn *conn = t->data;

  DBG("BGP: Keepalive timer\n");
  bgp_schedule_packet(conn, NULL, PKT_KEEPALIVE);

  /* Kick TX a bit faster */
  if (ev_active(conn->tx_ev))
    ev_run(conn->tx_ev);
}

static void
bgp_setup_conn(struct bgp_proto *p, struct bgp_conn *conn)
{
  conn->sk = NULL;
  conn->bgp = p;

  conn->packets_to_send = 0;
  conn->channels_to_send = 0;
  conn->last_channel = 0;
  conn->last_channel_count = 0;

  conn->connect_timer	= tm_new_init(p->p.pool, bgp_connect_timeout,	 conn, 0, 0);
  conn->hold_timer 	= tm_new_init(p->p.pool, bgp_hold_timeout,	 conn, 0, 0);
  conn->keepalive_timer	= tm_new_init(p->p.pool, bgp_keepalive_timeout, conn, 0, 0);

  conn->tx_ev = ev_new_init(p->p.pool, bgp_kick_tx, conn);
}

static void
bgp_setup_sk(struct bgp_conn *conn, sock *s)
{
  s->data = conn;
  s->err_hook = bgp_sock_err;
  s->fast_rx = 1;
  conn->sk = s;
}

static void
bgp_active(struct bgp_proto *p)
{
  int delay = MAX(1, p->cf->connect_delay_time);
  struct bgp_conn *conn = &p->outgoing_conn;

  BGP_TRACE(D_EVENTS, "Connect delayed by %d seconds", delay);
  bgp_setup_conn(p, conn);
  bgp_conn_set_state(conn, BS_ACTIVE);
  bgp_start_timer(conn->connect_timer, delay);
}

/**
 * bgp_connect - initiate an outgoing connection
 * @p: BGP instance
 *
 * The bgp_connect() function creates a new &bgp_conn and initiates
 * a TCP connection to the peer. The rest of connection setup is governed
 * by the BGP state machine as described in the standard.
 */
static void
bgp_connect(struct bgp_proto *p)	/* Enter Connect state and start establishing connection */
{
  struct bgp_conn *conn = &p->outgoing_conn;
  int hops = p->cf->multihop ? : 1;

  DBG("BGP: Connecting\n");
  sock *s = sk_new(p->p.pool);
  s->type = SK_TCP_ACTIVE;
  s->saddr = p->local_ip;
  s->daddr = p->remote_ip;
  s->dport = p->cf->remote_port;
  s->iface = p->neigh ? p->neigh->iface : NULL;
  s->vrf = p->p.vrf;
  s->ttl = p->cf->ttl_security ? 255 : hops;
  s->rbsize = p->cf->enable_extended_messages ? BGP_RX_BUFFER_EXT_SIZE : BGP_RX_BUFFER_SIZE;
  s->tbsize = p->cf->enable_extended_messages ? BGP_TX_BUFFER_EXT_SIZE : BGP_TX_BUFFER_SIZE;
  s->tos = IP_PREC_INTERNET_CONTROL;
  s->password = p->cf->password;
  s->tx_hook = bgp_connected;
  BGP_TRACE(D_EVENTS, "Connecting to %I%J from local address %I%J",
	    s->daddr, ipa_is_link_local(s->daddr) ? p->cf->iface : NULL,
	    s->saddr, ipa_is_link_local(s->saddr) ? s->iface : NULL);
  bgp_setup_conn(p, conn);
  bgp_setup_sk(conn, s);
  bgp_conn_set_state(conn, BS_CONNECT);

  if (sk_open(s) < 0)
    goto err;

  /* Set minimal receive TTL if needed */
  if (p->cf->ttl_security)
    if (sk_set_min_ttl(s, 256 - hops) < 0)
      goto err;

  DBG("BGP: Waiting for connect success\n");
  bgp_start_timer(conn->connect_timer, p->cf->connect_retry_time);
  return;

err:
  sk_log_error(s, p->p.name);
  bgp_sock_err(s, 0);
  return;
}

static inline int bgp_is_dynamic(struct bgp_proto *p)
{ return ipa_zero(p->remote_ip); }

/**
 * bgp_find_proto - find existing proto for incoming connection
 * @sk: TCP socket
 *
 */
static struct bgp_proto *
bgp_find_proto(sock *sk)
{
  struct bgp_proto *best = NULL;
  struct bgp_proto *p;

  /* sk->iface is valid only if src or dst address is link-local */
  int link = ipa_is_link_local(sk->saddr) || ipa_is_link_local(sk->daddr);

  WALK_LIST(p, proto_list)
    if ((p->p.proto == &proto_bgp) &&
	(ipa_equal(p->remote_ip, sk->daddr) || bgp_is_dynamic(p)) &&
	(!p->cf->remote_range || ipa_in_netX(sk->daddr, p->cf->remote_range)) &&
	(p->p.vrf == sk->vrf) &&
	(p->cf->local_port == sk->sport) &&
	(!link || (p->cf->iface == sk->iface)) &&
	(ipa_zero(p->cf->local_ip) || ipa_equal(p->cf->local_ip, sk->saddr)))
    {
      best = p;

      if (!bgp_is_dynamic(p))
	break;
    }

  return best;
}

/**
 * bgp_incoming_connection - handle an incoming connection
 * @sk: TCP socket
 * @dummy: unused
 *
 * This function serves as a socket hook for accepting of new BGP
 * connections. It searches a BGP instance corresponding to the peer
 * which has connected and if such an instance exists, it creates a
 * &bgp_conn structure, attaches it to the instance and either sends
 * an Open message or (if there already is an active connection) it
 * closes the new connection by sending a Notification message.
 */
static int
bgp_incoming_connection(sock *sk, uint dummy UNUSED)
{
  struct bgp_proto *p;
  int acc, hops;

  DBG("BGP: Incoming connection from %I port %d\n", sk->daddr, sk->dport);
  p = bgp_find_proto(sk);
  if (!p)
  {
    log(L_WARN "BGP: Unexpected connect from unknown address %I%J (port %d)",
	sk->daddr, ipa_is_link_local(sk->daddr) ? sk->iface : NULL, sk->dport);
    rfree(sk);
    return 0;
  }

  /*
   * BIRD should keep multiple incoming connections in OpenSent state (for
   * details RFC 4271 8.2.1 par 3), but it keeps just one. Duplicate incoming
   * connections are rejected istead. The exception is the case where an
   * incoming connection triggers a graceful restart.
   */

  acc = (p->p.proto_state == PS_START || p->p.proto_state == PS_UP) &&
    (p->start_state >= BSS_CONNECT) && (!p->incoming_conn.sk);

  if (p->conn && (p->conn->state == BS_ESTABLISHED) && p->gr_ready)
  {
    bgp_store_error(p, NULL, BE_MISC, BEM_GRACEFUL_RESTART);
    bgp_handle_graceful_restart(p);
    bgp_conn_enter_idle_state(p->conn);
    acc = 1;

    /* There might be separate incoming connection in OpenSent state */
    if (p->incoming_conn.state > BS_ACTIVE)
      bgp_close_conn(&p->incoming_conn);
  }

  BGP_TRACE(D_EVENTS, "Incoming connection from %I%J (port %d) %s",
	    sk->daddr, ipa_is_link_local(sk->daddr) ? sk->iface : NULL,
	    sk->dport, acc ? "accepted" : "rejected");

  if (!acc)
  {
    rfree(sk);
    return 0;
  }

  hops = p->cf->multihop ? : 1;

  if (sk_set_ttl(sk, p->cf->ttl_security ? 255 : hops) < 0)
    goto err;

  if (p->cf->ttl_security)
    if (sk_set_min_ttl(sk, 256 - hops) < 0)
      goto err;

  if (p->cf->enable_extended_messages)
  {
    sk->rbsize = BGP_RX_BUFFER_EXT_SIZE;
    sk->tbsize = BGP_TX_BUFFER_EXT_SIZE;
    sk_reallocate(sk);
  }

  /* For dynamic BGP, spawn new instance and postpone the socket */
  if (bgp_is_dynamic(p))
  {
    p = bgp_spawn(p, sk->daddr);
    p->postponed_sk = sk;
    rmove(sk, p->p.pool);
    return 0;
  }

  rmove(sk, p->p.pool);
  bgp_setup_conn(p, &p->incoming_conn);
  bgp_setup_sk(&p->incoming_conn, sk);
  bgp_send_open(&p->incoming_conn);
  return 0;

err:
  sk_log_error(sk, p->p.name);
  log(L_ERR "%s: Incoming connection aborted", p->p.name);
  rfree(sk);
  return 0;
}

static void
bgp_listen_sock_err(sock *sk UNUSED, int err)
{
  if (err == ECONNABORTED)
    log(L_WARN "BGP: Incoming connection aborted");
  else
    log(L_ERR "BGP: Error on listening socket: %M", err);
}

static void
bgp_start_neighbor(struct bgp_proto *p)
{
  /* Called only for single-hop BGP sessions */

  if (ipa_zero(p->local_ip))
    p->local_ip = p->neigh->ifa->ip;

  if (ipa_is_link_local(p->local_ip))
    p->link_addr = p->local_ip;
  else if (p->neigh->iface->llv6)
    p->link_addr = p->neigh->iface->llv6->ip;

  bgp_initiate(p);
}

static void
bgp_neigh_notify(neighbor *n)
{
  struct bgp_proto *p = (struct bgp_proto *) n->proto;
  int ps = p->p.proto_state;

  if (n != p->neigh)
    return;

  if ((ps == PS_DOWN) || (ps == PS_STOP))
    return;

  int prepare = (ps == PS_START) && (p->start_state == BSS_PREPARE);

  if (n->scope <= 0)
  {
    if (!prepare)
    {
      BGP_TRACE(D_EVENTS, "Neighbor lost");
      bgp_store_error(p, NULL, BE_MISC, BEM_NEIGHBOR_LOST);
      /* Perhaps also run bgp_update_startup_delay(p)? */
      bgp_stop(p, 0, NULL, 0);
    }
  }
  else if (p->cf->check_link && !(n->iface->flags & IF_LINK_UP))
  {
    if (!prepare)
    {
      BGP_TRACE(D_EVENTS, "Link down");
      bgp_store_error(p, NULL, BE_MISC, BEM_LINK_DOWN);
      if (ps == PS_UP)
	bgp_update_startup_delay(p);
      bgp_stop(p, 0, NULL, 0);
    }
  }
  else
  {
    if (prepare)
    {
      BGP_TRACE(D_EVENTS, "Neighbor ready");
      bgp_start_neighbor(p);
    }
  }
}

static void
bgp_bfd_notify(struct bfd_request *req)
{
  struct bgp_proto *p = req->data;
  int ps = p->p.proto_state;

  if (req->down && ((ps == PS_START) || (ps == PS_UP)))
  {
    BGP_TRACE(D_EVENTS, "BFD session down");
    bgp_store_error(p, NULL, BE_MISC, BEM_BFD_DOWN);

    if (req->opts.mode == BGP_BFD_GRACEFUL)
    {
      /* Trigger graceful restart */
      if (p->conn && (p->conn->state == BS_ESTABLISHED) && p->gr_ready)
	bgp_handle_graceful_restart(p);

      if (p->incoming_conn.state > BS_IDLE)
	bgp_conn_enter_idle_state(&p->incoming_conn);

      if (p->outgoing_conn.state > BS_IDLE)
	bgp_conn_enter_idle_state(&p->outgoing_conn);
    }
    else
    {
      /* Trigger session down */
      if (ps == PS_UP)
	bgp_update_startup_delay(p);
      bgp_stop(p, 0, NULL, 0);
    }
  }
}

static void
bgp_update_bfd(struct bgp_proto *p, const struct bfd_options *bfd)
{
  if (bfd && p->bfd_req)
    bfd_update_request(p->bfd_req, bfd);

  if (bfd && !p->bfd_req && !bgp_is_dynamic(p))
    p->bfd_req = bfd_request_session(p->p.pool, p->remote_ip, p->local_ip,
				     p->cf->multihop ? NULL : p->neigh->iface,
				     p->p.vrf, bgp_bfd_notify, p, bfd);

  if (!bfd && p->bfd_req)
  {
    rfree(p->bfd_req);
    p->bfd_req = NULL;
  }
}

static void
bgp_reload_routes(struct channel *C)
{
  struct bgp_proto *p = (void *) C->proto;
  struct bgp_channel *c = (void *) C;

  ASSERT(p->conn && (p->route_refresh || c->c.in_table));

  if (c->c.in_table)
    channel_schedule_reload(C);
  else
    bgp_schedule_packet(p->conn, c, PKT_ROUTE_REFRESH);
}

static void
bgp_feed_begin(struct channel *C, int initial)
{
  struct bgp_proto *p = (void *) C->proto;
  struct bgp_channel *c = (void *) C;

  /* This should not happen */
  if (!p->conn)
    return;

  if (initial && p->cf->gr_mode)
    c->feed_state = BFS_LOADING;

  /* It is refeed and both sides support enhanced route refresh */
  if (!initial && p->enhanced_refresh)
  {
    /* BoRR must not be sent before End-of-RIB */
    if (c->feed_state == BFS_LOADING || c->feed_state == BFS_LOADED)
      return;

    c->feed_state = BFS_REFRESHING;
    bgp_schedule_packet(p->conn, c, PKT_BEGIN_REFRESH);
  }
}

static void
bgp_feed_end(struct channel *C)
{
  struct bgp_proto *p = (void *) C->proto;
  struct bgp_channel *c = (void *) C;

  /* This should not happen */
  if (!p->conn)
    return;

  /* Non-demarcated feed ended, nothing to do */
  if (c->feed_state == BFS_NONE)
    return;

  /* Schedule End-of-RIB packet */
  if (c->feed_state == BFS_LOADING)
    c->feed_state = BFS_LOADED;

  /* Schedule EoRR packet */
  if (c->feed_state == BFS_REFRESHING)
    c->feed_state = BFS_REFRESHED;

  /* Kick TX hook */
  bgp_schedule_packet(p->conn, c, PKT_UPDATE);
}


static void
bgp_start_locked(struct object_lock *lock)
{
  struct bgp_proto *p = lock->data;
  const struct bgp_config *cf = p->cf;

  if (p->p.proto_state != PS_START)
  {
    DBG("BGP: Got lock in different state %d\n", p->p.proto_state);
    return;
  }

  DBG("BGP: Got lock\n");

  if (cf->multihop || bgp_is_dynamic(p))
  {
    /* Multi-hop sessions do not use neighbor entries */
    bgp_initiate(p);
    return;
  }

  neighbor *n = neigh_find(&p->p, p->remote_ip, cf->iface, NEF_STICKY);
  if (!n)
  {
    log(L_ERR "%s: Invalid remote address %I%J", p->p.name, p->remote_ip, cf->iface);
    /* As we do not start yet, we can just disable protocol */
    p->p.disabled = 1;
    bgp_store_error(p, NULL, BE_MISC, BEM_INVALID_NEXT_HOP);
    proto_notify_state(&p->p, PS_DOWN);
    return;
  }

  p->neigh = n;

  if (n->scope <= 0)
    BGP_TRACE(D_EVENTS, "Waiting for %I%J to become my neighbor", p->remote_ip, cf->iface);
  else if (p->cf->check_link && !(n->iface->flags & IF_LINK_UP))
    BGP_TRACE(D_EVENTS, "Waiting for link on %s", n->iface->name);
  else
    bgp_start_neighbor(p);
}

static int
bgp_start(struct proto *P)
{
  struct bgp_proto *p = (struct bgp_proto *) P;
  const struct bgp_config *cf = p->cf;

  p->local_ip = cf->local_ip;
  p->local_as = cf->local_as;
  p->remote_as = cf->remote_as;
  p->public_as = cf->local_as;

  /* For dynamic BGP childs, remote_ip is already set */
  if (ipa_nonzero(cf->remote_ip))
    p->remote_ip = cf->remote_ip;

  /* Confederation ID is used for truly external peers */
  if (p->cf->confederation && !p->is_interior)
    p->public_as = cf->confederation;

  p->passive = cf->passive || bgp_is_dynamic(p);

  p->start_state = BSS_PREPARE;
  p->outgoing_conn.state = BS_IDLE;
  p->incoming_conn.state = BS_IDLE;
  p->neigh = NULL;
  p->bfd_req = NULL;
  p->postponed_sk = NULL;
  p->gr_ready = 0;
  p->gr_active_num = 0;

  /* Reset some stats */
  p->stats.rx_messages = p->stats.tx_messages = 0;
  p->stats.rx_updates = p->stats.tx_updates = 0;
  p->stats.rx_bytes = p->stats.tx_bytes = 0;
  p->last_rx_update = 0;

  p->event = ev_new_init(p->p.pool, bgp_decision, p);
  p->startup_timer = tm_new_init(p->p.pool, bgp_startup_timeout, p, 0, 0);
  p->gr_timer = tm_new_init(p->p.pool, bgp_graceful_restart_timeout, p, 0, 0);

  p->local_id = proto_get_router_id(P->cf);
  if (p->rr_client)
    p->rr_cluster_id = p->cf->rr_cluster_id ? p->cf->rr_cluster_id : p->local_id;

  p->remote_id = 0;
  p->link_addr = IPA_NONE;

  /* Lock all channels when in GR recovery mode */
  if (p->p.gr_recovery && p->cf->gr_mode)
  {
    struct bgp_channel *c;
    WALK_LIST(c, p->p.channels)
      channel_graceful_restart_lock(&c->c);
  }

  /*
   * Before attempting to create the connection, we need to lock the port,
   * so that we are the only instance attempting to talk with that neighbor.
   */
  struct object_lock *lock;
  lock = p->lock = olock_new(P->pool);
  lock->addr = p->remote_ip;
  lock->port = p->cf->remote_port;
  lock->iface = p->cf->iface;
  lock->vrf = p->cf->iface ? NULL : p->p.vrf;
  lock->type = OBJLOCK_TCP;
  lock->hook = bgp_start_locked;
  lock->data = p;

  /* For dynamic BGP, we use inst 1 to avoid collisions with regular BGP */
  if (bgp_is_dynamic(p))
  {
    lock->addr = net_prefix(p->cf->remote_range);
    lock->inst = 1;
  }

  olock_acquire(lock);

  return PS_START;
}

extern int proto_restart;

static int
bgp_shutdown(struct proto *P)
{
  struct bgp_proto *p = (struct bgp_proto *) P;
  int subcode = 0;

  char *message = NULL;
  byte *data = NULL;
  uint len = 0;

  BGP_TRACE(D_EVENTS, "Shutdown requested");

  switch (P->down_code)
  {
  case PDC_CF_REMOVE:
  case PDC_CF_DISABLE:
    subcode = 3; // Errcode 6, 3 - peer de-configured
    break;

  case PDC_CF_RESTART:
    subcode = 6; // Errcode 6, 6 - other configuration change
    break;

  case PDC_CMD_DISABLE:
  case PDC_CMD_SHUTDOWN:
  shutdown:
    subcode = 2; // Errcode 6, 2 - administrative shutdown
    message = P->message;
    break;

  case PDC_CMD_RESTART:
    subcode = 4; // Errcode 6, 4 - administrative reset
    message = P->message;
    break;

  case PDC_CMD_GR_DOWN:
    if ((p->cf->gr_mode != BGP_GR_ABLE) &&
	(p->cf->llgr_mode != BGP_LLGR_ABLE))
      goto shutdown;

    subcode = -1; // Do not send NOTIFICATION, just close the connection
    break;

  case PDC_RX_LIMIT_HIT:
  case PDC_IN_LIMIT_HIT:
    subcode = 1; // Errcode 6, 1 - max number of prefixes reached
    /* log message for compatibility */
    log(L_WARN "%s: Route limit exceeded, shutting down", p->p.name);
    goto limit;

  case PDC_OUT_LIMIT_HIT:
    subcode = proto_restart ? 4 : 2; // Administrative reset or shutdown

  limit:
    bgp_store_error(p, NULL, BE_AUTO_DOWN, BEA_ROUTE_LIMIT_EXCEEDED);
    if (proto_restart)
      bgp_update_startup_delay(p);
    else
      p->startup_delay = 0;
    goto done;
  }

  bgp_store_error(p, NULL, BE_MAN_DOWN, 0);
  p->startup_delay = 0;

  /* RFC 8203 - shutdown communication */
  if (message)
  {
    uint msg_len = strlen(message);
    msg_len = MIN(msg_len, 255);

    /* Buffer will be freed automatically by protocol shutdown */
    data = mb_alloc(p->p.pool, msg_len + 1);
    len = msg_len + 1;

    data[0] = msg_len;
    memcpy(data+1, message, msg_len);
  }

done:
  bgp_stop(p, subcode, data, len);
  return p->p.proto_state;
}

static struct proto *
bgp_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct bgp_proto *p = (struct bgp_proto *) P;
  struct bgp_config *cf = (struct bgp_config *) CF;

  P->rt_notify = bgp_rt_notify;
  P->preexport = bgp_preexport;
  P->neigh_notify = bgp_neigh_notify;
  P->reload_routes = bgp_reload_routes;
  P->feed_begin = bgp_feed_begin;
  P->feed_end = bgp_feed_end;
  P->rte_better = bgp_rte_better;
  P->rte_mergable = bgp_rte_mergable;
  P->rte_recalculate = cf->deterministic_med ? bgp_rte_recalculate : NULL;
  P->rte_modify = bgp_rte_modify_stale;

  p->cf = cf;
  p->is_internal = (cf->local_as == cf->remote_as);
  p->is_interior = p->is_internal || cf->confederation_member;
  p->rs_client = cf->rs_client;
  p->rr_client = cf->rr_client;

  p->ipv4 = ipa_nonzero(cf->remote_ip) ?
    ipa_is_ip4(cf->remote_ip) :
    (cf->remote_range && (cf->remote_range->type == NET_IP4));

  p->remote_ip = cf->remote_ip;
  p->remote_as = cf->remote_as;

  /* Hack: We use cf->remote_ip just to pass remote_ip from bgp_spawn() */
  if (cf->c.parent)
    cf->remote_ip = IPA_NONE;

  /* Add all channels */
  struct bgp_channel_config *cc;
  WALK_LIST(cc, CF->channels)
    proto_add_channel(P, &cc->c);

  return P;
}

static void
bgp_channel_init(struct channel *C, struct channel_config *CF)
{
  struct bgp_channel *c = (void *) C;
  struct bgp_channel_config *cf = (void *) CF;

  c->cf = cf;
  c->afi = cf->afi;
  c->desc = cf->desc;

  if (cf->igp_table_ip4)
    c->igp_table_ip4 = cf->igp_table_ip4->table;

  if (cf->igp_table_ip6)
    c->igp_table_ip6 = cf->igp_table_ip6->table;
}

static int
bgp_channel_start(struct channel *C)
{
  struct bgp_proto *p = (void *) C->proto;
  struct bgp_channel *c = (void *) C;
  ip_addr src = p->local_ip;

  if (c->igp_table_ip4)
    rt_lock_table(c->igp_table_ip4);

  if (c->igp_table_ip6)
    rt_lock_table(c->igp_table_ip6);

  c->pool = p->p.pool; // XXXX
  bgp_init_bucket_table(c);
  bgp_init_prefix_table(c);

  if (c->cf->import_table)
    channel_setup_in_table(C);

  if (c->cf->export_table)
    channel_setup_out_table(C);

  c->stale_timer = tm_new_init(c->pool, bgp_long_lived_stale_timeout, c, 0, 0);

  c->next_hop_addr = c->cf->next_hop_addr;
  c->link_addr = IPA_NONE;
  c->packets_to_send = 0;

  /* Try to use source address as next hop address */
  if (ipa_zero(c->next_hop_addr))
  {
    if (bgp_channel_is_ipv4(c) && (ipa_is_ip4(src) || c->ext_next_hop))
      c->next_hop_addr = src;

    if (bgp_channel_is_ipv6(c) && (ipa_is_ip6(src) || c->ext_next_hop))
      c->next_hop_addr = src;
  }

  /* Use preferred addresses associated with interface / source address */
  if (ipa_zero(c->next_hop_addr))
  {
    /* We know the iface for single-hop, we make lookup for multihop */
    struct neighbor *nbr = p->neigh ?: neigh_find(&p->p, src, NULL, 0);
    struct iface *iface = nbr ? nbr->iface : NULL;

    if (bgp_channel_is_ipv4(c) && iface && iface->addr4)
      c->next_hop_addr = iface->addr4->ip;

    if (bgp_channel_is_ipv6(c) && iface && iface->addr6)
      c->next_hop_addr = iface->addr6->ip;
  }

  /* Exit if no feasible next hop address is found */
  if (ipa_zero(c->next_hop_addr))
  {
    log(L_WARN "%s: Missing next hop address", p->p.name);
    return 0;
  }

  /* Set link-local address for IPv6 single-hop BGP */
  if (ipa_is_ip6(c->next_hop_addr) && p->neigh)
  {
    c->link_addr = p->link_addr;

    if (ipa_zero(c->link_addr))
      log(L_WARN "%s: Missing link-local address", p->p.name);
  }

  /* Link local address is already in c->link_addr */
  if (ipa_is_link_local(c->next_hop_addr))
    c->next_hop_addr = IPA_NONE;

  return 0; /* XXXX: Currently undefined */
}

static void
bgp_channel_shutdown(struct channel *C)
{
  struct bgp_channel *c = (void *) C;

  c->next_hop_addr = IPA_NONE;
  c->link_addr = IPA_NONE;
  c->packets_to_send = 0;
}

static void
bgp_channel_cleanup(struct channel *C)
{
  struct bgp_channel *c = (void *) C;

  if (c->igp_table_ip4)
    rt_unlock_table(c->igp_table_ip4);

  if (c->igp_table_ip6)
    rt_unlock_table(c->igp_table_ip6);

  c->index = 0;

  /* Cleanup rest of bgp_channel starting at pool field */
  memset(&(c->pool), 0, sizeof(struct bgp_channel) - OFFSETOF(struct bgp_channel, pool));
}

static inline struct bgp_channel_config *
bgp_find_channel_config(struct bgp_config *cf, u32 afi)
{
  struct bgp_channel_config *cc;

  WALK_LIST(cc, cf->c.channels)
    if (cc->afi == afi)
      return cc;

  return NULL;
}

struct rtable_config *
bgp_default_igp_table(struct bgp_config *cf, struct bgp_channel_config *cc, u32 type)
{
  struct bgp_channel_config *cc2;
  struct rtable_config *tab;

  /* First, try table connected by the channel */
  if (cc->c.table->addr_type == type)
    return cc->c.table;

  /* Find paired channel with the same SAFI but the other AFI */
  u32 afi2 = cc->afi ^ 0x30000;
  cc2 = bgp_find_channel_config(cf, afi2);

  /* Second, try IGP table configured in the paired channel */
  if (cc2 && (tab = (type == NET_IP4) ? cc2->igp_table_ip4 : cc2->igp_table_ip6))
    return tab;

  /* Third, try table connected by the paired channel */
  if (cc2 && (cc2->c.table->addr_type == type))
    return cc2->c.table;

  /* Last, try default table of given type */
  if (tab = cf->c.global->def_tables[type])
    return tab;

  cf_error("Undefined IGP table");
}


void
bgp_postconfig(struct proto_config *CF)
{
  struct bgp_config *cf = (void *) CF;

  /* Do not check templates at all */
  if (cf->c.class == SYM_TEMPLATE)
    return;


  /* Handle undefined remote_as, zero should mean unspecified external */
  if (!cf->remote_as && (cf->peer_type == BGP_PT_INTERNAL))
    cf->remote_as = cf->local_as;

  int internal = (cf->local_as == cf->remote_as);
  int interior = internal || cf->confederation_member;

  /* EBGP direct by default, IBGP multihop by default */
  if (cf->multihop < 0)
    cf->multihop = internal ? 64 : 0;

  /* LLGR mode default based on GR mode */
  if (cf->llgr_mode < 0)
    cf->llgr_mode = cf->gr_mode ? BGP_LLGR_AWARE : 0;

  /* Link check for single-hop BGP by default */
  if (cf->check_link < 0)
    cf->check_link = !cf->multihop;


  if (!cf->local_as)
    cf_error("Local AS number must be set");

  if (ipa_zero(cf->remote_ip) && !cf->remote_range)
    cf_error("Neighbor must be configured");

  if (ipa_zero(cf->local_ip) && cf->strict_bind)
    cf_error("Local address must be configured for strict bind");

  if (!cf->remote_as && !cf->peer_type)
    cf_error("Remote AS number (or peer type) must be set");

  if ((cf->peer_type == BGP_PT_INTERNAL) && !internal)
    cf_error("IBGP cannot have different ASNs");

  if ((cf->peer_type == BGP_PT_EXTERNAL) &&  internal)
    cf_error("EBGP cannot have the same ASNs");

  if (!cf->iface && (ipa_is_link_local(cf->local_ip) ||
		     ipa_is_link_local(cf->remote_ip)))
    cf_error("Link-local addresses require defined interface");

  if (!(cf->capabilities && cf->enable_as4) && (cf->remote_as > 0xFFFF))
    cf_error("Neighbor AS number out of range (AS4 not available)");

  if (!internal && cf->rr_client)
    cf_error("Only internal neighbor can be RR client");

  if (internal && cf->rs_client)
    cf_error("Only external neighbor can be RS client");

  if (!cf->confederation && cf->confederation_member)
    cf_error("Confederation ID must be set for member sessions");

  if (cf->multihop && (ipa_is_link_local(cf->local_ip) ||
		       ipa_is_link_local(cf->remote_ip)))
    cf_error("Multihop BGP cannot be used with link-local addresses");

  if (cf->multihop && cf->iface)
    cf_error("Multihop BGP cannot be bound to interface");

  if (cf->multihop && cf->check_link)
    cf_error("Multihop BGP cannot depend on link state");

  if (cf->multihop && cf->bfd && ipa_zero(cf->local_ip))
    cf_error("Multihop BGP with BFD requires specified local address");

  if (!cf->gr_mode && cf->llgr_mode)
    cf_error("Long-lived graceful restart requires basic graceful restart");

  if (internal && cf->enforce_first_as)
    cf_error("Enforce first AS check is requires EBGP sessions");


  struct bgp_channel_config *cc;
  WALK_LIST(cc, CF->channels)
  {
    /* Handle undefined import filter */
    if (cc->c.in_filter == FILTER_UNDEF)
      if (interior)
	cc->c.in_filter = FILTER_ACCEPT;
      else
	cf_error("EBGP requires explicit import policy");

    /* Handle undefined export filter */
    if (cc->c.out_filter == FILTER_UNDEF)
      if (interior)
	cc->c.out_filter = FILTER_REJECT;
      else
	cf_error("EBGP requires explicit export policy");

    /* Disable after error incompatible with restart limit action */
    if ((cc->c.in_limit.action == PLA_RESTART) && cf->disable_after_error)
      cc->c.in_limit.action = PLA_DISABLE;

    /* Different default based on rr_client, rs_client */
    if (cc->next_hop_keep == 0xff)
      cc->next_hop_keep = cf->rr_client ? NH_IBGP : (cf->rs_client ? NH_ALL : NH_NO);

    /* Different default for gw_mode */
    if (!cc->gw_mode)
      cc->gw_mode = cf->multihop ? GW_RECURSIVE : GW_DIRECT;

    /* Defaults based on proto config */
    if (cc->gr_able == 0xff)
      cc->gr_able = (cf->gr_mode == BGP_GR_ABLE);

    if (cc->llgr_able == 0xff)
      cc->llgr_able = (cf->llgr_mode == BGP_LLGR_ABLE);

    if (cc->llgr_time == ~0U)
      cc->llgr_time = cf->llgr_time;

    /* AIGP enabled by default on interior sessions */
    if (cc->aigp == 0xff)
      cc->aigp = interior;

    /* Default values of IGP tables */
    if ((cc->gw_mode == GW_RECURSIVE) && !cc->desc->no_igp)
    {
      if (!cc->igp_table_ip4 && (bgp_cc_is_ipv4(cc) || cc->ext_next_hop))
	cc->igp_table_ip4 = bgp_default_igp_table(cf, cc, NET_IP4);

      if (!cc->igp_table_ip6 && (bgp_cc_is_ipv6(cc) || cc->ext_next_hop))
	cc->igp_table_ip6 = bgp_default_igp_table(cf, cc, NET_IP6);

      if (cc->igp_table_ip4 && bgp_cc_is_ipv6(cc) && !cc->ext_next_hop)
	cf_error("Mismatched IGP table type");

      if (cc->igp_table_ip6 && bgp_cc_is_ipv4(cc) && !cc->ext_next_hop)
	cf_error("Mismatched IGP table type");
    }

    if (cf->multihop && (cc->gw_mode == GW_DIRECT))
      cf_error("Multihop BGP cannot use direct gateway mode");

    if ((cc->gw_mode == GW_RECURSIVE) && cc->c.table->sorted)
      cf_error("BGP in recursive mode prohibits sorted table");

    if (cf->deterministic_med && cc->c.table->sorted)
      cf_error("BGP with deterministic MED prohibits sorted table");

    if (cc->secondary && !cc->c.table->sorted)
      cf_error("BGP with secondary option requires sorted table");
  }
}

static int
bgp_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct bgp_proto *p = (void *) P;
  const struct bgp_config *new = (void *) CF;
  const struct bgp_config *old = p->cf;

  if (proto_get_router_id(CF) != p->local_id)
    return 0;

  int same = !memcmp(((byte *) old) + sizeof(struct proto_config),
		     ((byte *) new) + sizeof(struct proto_config),
		     // password item is last and must be checked separately
		     OFFSETOF(struct bgp_config, password) - sizeof(struct proto_config))
    && !bstrcmp(old->password, new->password)
    && ((!old->remote_range && !new->remote_range)
	|| (old->remote_range && new->remote_range && net_equal(old->remote_range, new->remote_range)))
    && !bstrcmp(old->dynamic_name, new->dynamic_name)
    && (old->dynamic_name_digits == new->dynamic_name_digits);

  /* FIXME: Move channel reconfiguration to generic protocol code ? */
  struct channel *C, *C2;
  struct bgp_channel_config *cc;

  WALK_LIST(C, p->p.channels)
    C->stale = 1;

  WALK_LIST(cc, new->c.channels)
  {
    C = (struct channel *) bgp_find_channel(p, cc->afi);
    same = proto_configure_channel(P, &C, &cc->c) && same;

    if (C)
      C->stale = 0;
  }

  WALK_LIST_DELSAFE(C, C2, p->p.channels)
    if (C->stale)
      same = proto_configure_channel(P, &C, NULL) && same;


  if (same && (p->start_state > BSS_PREPARE))
    bgp_update_bfd(p, new->bfd);

  /* We should update our copy of configuration ptr as old configuration will be freed */
  if (same)
    p->cf = new;

  /* Reset name counter */
  p->dynamic_name_counter = 0;

  return same;
}

#define IGP_TABLE(cf, sym) ((cf)->igp_table_##sym ? (cf)->igp_table_##sym ->table : NULL )

static int
bgp_channel_reconfigure(struct channel *C, struct channel_config *CC, int *import_changed, int *export_changed)
{
  struct bgp_proto *p = (void *) C->proto;
  struct bgp_channel *c = (void *) C;
  struct bgp_channel_config *new = (void *) CC;
  struct bgp_channel_config *old = c->cf;

  if ((new->secondary != old->secondary) ||
      (new->gr_able != old->gr_able) ||
      (new->llgr_able != old->llgr_able) ||
      (new->llgr_time != old->llgr_time) ||
      (new->ext_next_hop != old->ext_next_hop) ||
      (new->add_path != old->add_path) ||
      (new->import_table != old->import_table) ||
      (new->export_table != old->export_table) ||
      (IGP_TABLE(new, ip4) != IGP_TABLE(old, ip4)) ||
      (IGP_TABLE(new, ip6) != IGP_TABLE(old, ip6)))
    return 0;

  if (new->mandatory && !old->mandatory && (C->channel_state != CS_UP))
    return 0;

  if ((new->gw_mode != old->gw_mode) ||
      (new->aigp != old->aigp) ||
      (new->cost != old->cost))
  {
    /* import_changed itself does not force ROUTE_REFRESH when import_table is active */
    if (c->c.in_table && (c->c.channel_state == CS_UP))
      bgp_schedule_packet(p->conn, c, PKT_ROUTE_REFRESH);

    *import_changed = 1;
  }

  if (!ipa_equal(new->next_hop_addr, old->next_hop_addr) ||
      (new->next_hop_self != old->next_hop_self) ||
      (new->next_hop_keep != old->next_hop_keep) ||
      (new->aigp != old->aigp) ||
      (new->aigp_originate != old->aigp_originate))
    *export_changed = 1;

  c->cf = new;
  return 1;
}

static void
bgp_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct bgp_config *d = (void *) dest;
  struct bgp_config *s = (void *) src;

  /* Copy BFD options */
  if (s->bfd)
  {
    struct bfd_options *opts = cfg_alloc(sizeof(struct bfd_options));
    memcpy(opts, s->bfd, sizeof(struct bfd_options));
    d->bfd = opts;
  }
}


/**
 * bgp_error - report a protocol error
 * @c: connection
 * @code: error code (according to the RFC)
 * @subcode: error sub-code
 * @data: data to be passed in the Notification message
 * @len: length of the data
 *
 * bgp_error() sends a notification packet to tell the other side that a protocol
 * error has occurred (including the data considered erroneous if possible) and
 * closes the connection.
 */
void
bgp_error(struct bgp_conn *c, uint code, uint subcode, byte *data, int len)
{
  struct bgp_proto *p = c->bgp;

  if (c->state == BS_CLOSE)
    return;

  bgp_log_error(p, BE_BGP_TX, "Error", code, subcode, data, ABS(len));
  bgp_store_error(p, c, BE_BGP_TX, (code << 16) | subcode);
  bgp_conn_enter_close_state(c);

  c->notify_code = code;
  c->notify_subcode = subcode;
  c->notify_data = data;
  c->notify_size = (len > 0) ? len : 0;
  bgp_schedule_packet(c, NULL, PKT_NOTIFICATION);

  if (code != 6)
  {
    bgp_update_startup_delay(p);
    bgp_stop(p, 0, NULL, 0);
  }
}

/**
 * bgp_store_error - store last error for status report
 * @p: BGP instance
 * @c: connection
 * @class: error class (BE_xxx constants)
 * @code: error code (class specific)
 *
 * bgp_store_error() decides whether given error is interesting enough
 * and store that error to last_error variables of @p
 */
void
bgp_store_error(struct bgp_proto *p, struct bgp_conn *c, u8 class, u32 code)
{
  /* During PS_UP, we ignore errors on secondary connection */
  if ((p->p.proto_state == PS_UP) && c && (c != p->conn))
    return;

  /* During PS_STOP, we ignore any errors, as we want to report
   * the error that caused transition to PS_STOP
   */
  if (p->p.proto_state == PS_STOP)
    return;

  p->last_error_class = class;
  p->last_error_code = code;
}

static char *bgp_state_names[] = { "Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established", "Close" };
static char *bgp_err_classes[] = { "", "Error: ", "Socket: ", "Received: ", "BGP Error: ", "Automatic shutdown: ", ""};
static char *bgp_misc_errors[] = { "", "Neighbor lost", "Invalid next hop", "Kernel MD5 auth failed", "No listening socket", "Link down", "BFD session down", "Graceful restart"};
static char *bgp_auto_errors[] = { "", "Route limit exceeded"};
static char *bgp_gr_states[] = { "None", "Regular", "Long-lived"};

static const char *
bgp_last_errmsg(struct bgp_proto *p)
{
  switch (p->last_error_class)
  {
  case BE_MISC:
    return bgp_misc_errors[p->last_error_code];
  case BE_SOCKET:
    return (p->last_error_code == 0) ? "Connection closed" : strerror(p->last_error_code);
  case BE_BGP_RX:
  case BE_BGP_TX:
    return bgp_error_dsc(p->last_error_code >> 16, p->last_error_code & 0xFF);
  case BE_AUTO_DOWN:
    return bgp_auto_errors[p->last_error_code];
  default:
    return "";
  }
}

static const char *
bgp_state_dsc(struct bgp_proto *p)
{
  if (p->p.proto_state == PS_DOWN)
    return "Down";

  int state = MAX(p->incoming_conn.state, p->outgoing_conn.state);
  if ((state == BS_IDLE) && (p->start_state >= BSS_CONNECT) && p->passive)
    return "Passive";

  return bgp_state_names[state];
}

static void
bgp_get_status(struct proto *P, byte *buf)
{
  struct bgp_proto *p = (struct bgp_proto *) P;

  const char *err1 = bgp_err_classes[p->last_error_class];
  const char *err2 = bgp_last_errmsg(p);

  if (P->proto_state == PS_DOWN)
    bsprintf(buf, "%s%s", err1, err2);
  else
    bsprintf(buf, "%-14s%s%s", bgp_state_dsc(p), err1, err2);
}

static void
bgp_show_afis(int code, char *s, u32 *afis, uint count)
{
  buffer b;
  LOG_BUFFER_INIT(b);

  buffer_puts(&b, s);

  for (u32 *af = afis; af < (afis + count); af++)
  {
    const struct bgp_af_desc *desc = bgp_get_af_desc(*af);
    if (desc)
      buffer_print(&b, " %s", desc->name);
    else
      buffer_print(&b, " <%u/%u>", BGP_AFI(*af), BGP_SAFI(*af));
  }

  if (b.pos == b.end)
    strcpy(b.end - 32, " ... <too long>");

  cli_msg(code, b.start);
}

static void
bgp_show_capabilities(struct bgp_proto *p UNUSED, struct bgp_caps *caps)
{
  struct bgp_af_caps *ac;
  uint any_mp_bgp = 0;
  uint any_gr_able = 0;
  uint any_add_path = 0;
  uint any_ext_next_hop = 0;
  uint any_llgr_able = 0;
  u32 *afl1 = alloca(caps->af_count * sizeof(u32));
  u32 *afl2 = alloca(caps->af_count * sizeof(u32));
  uint afn1, afn2;

  WALK_AF_CAPS(caps, ac)
  {
    any_mp_bgp |= ac->ready;
    any_gr_able |= ac->gr_able;
    any_add_path |= ac->add_path;
    any_ext_next_hop |= ac->ext_next_hop;
    any_llgr_able |= ac->llgr_able;
  }

  if (any_mp_bgp)
  {
    cli_msg(-1006, "      Multiprotocol");

    afn1 = 0;
    WALK_AF_CAPS(caps, ac)
      if (ac->ready)
	afl1[afn1++] = ac->afi;

    bgp_show_afis(-1006, "        AF announced:", afl1, afn1);
  }

  if (caps->route_refresh)
    cli_msg(-1006, "      Route refresh");

  if (any_ext_next_hop)
  {
    cli_msg(-1006, "      Extended next hop");

    afn1 = 0;
    WALK_AF_CAPS(caps, ac)
      if (ac->ext_next_hop)
	afl1[afn1++] = ac->afi;

    bgp_show_afis(-1006, "        IPv6 nexthop:", afl1, afn1);
  }

  if (caps->ext_messages)
    cli_msg(-1006, "      Extended message");

  if (caps->gr_aware)
    cli_msg(-1006, "      Graceful restart");

  if (any_gr_able)
  {
    /* Continues from gr_aware */
    cli_msg(-1006, "        Restart time: %u", caps->gr_time);
    if (caps->gr_flags & BGP_GRF_RESTART)
      cli_msg(-1006, "        Restart recovery");

    afn1 = afn2 = 0;
    WALK_AF_CAPS(caps, ac)
    {
      if (ac->gr_able)
	afl1[afn1++] = ac->afi;

      if (ac->gr_af_flags & BGP_GRF_FORWARDING)
	afl2[afn2++] = ac->afi;
    }

    bgp_show_afis(-1006, "        AF supported:", afl1, afn1);
    bgp_show_afis(-1006, "        AF preserved:", afl2, afn2);
  }

  if (caps->as4_support)
    cli_msg(-1006, "      4-octet AS numbers");

  if (any_add_path)
  {
    cli_msg(-1006, "      ADD-PATH");

    afn1 = afn2 = 0;
    WALK_AF_CAPS(caps, ac)
    {
      if (ac->add_path & BGP_ADD_PATH_RX)
	afl1[afn1++] = ac->afi;

      if (ac->add_path & BGP_ADD_PATH_TX)
	afl2[afn2++] = ac->afi;
    }

    bgp_show_afis(-1006, "        RX:", afl1, afn1);
    bgp_show_afis(-1006, "        TX:", afl2, afn2);
  }

  if (caps->enhanced_refresh)
    cli_msg(-1006, "      Enhanced refresh");

  if (caps->llgr_aware)
    cli_msg(-1006, "      Long-lived graceful restart");

  if (any_llgr_able)
  {
    u32 stale_time = 0;

    afn1 = afn2 = 0;
    WALK_AF_CAPS(caps, ac)
    {
      stale_time = MAX(stale_time, ac->llgr_time);

      if (ac->llgr_able && ac->llgr_time)
	afl1[afn1++] = ac->afi;

      if (ac->llgr_flags & BGP_GRF_FORWARDING)
	afl2[afn2++] = ac->afi;
    }

    /* Continues from llgr_aware */
    cli_msg(-1006, "        LL stale time: %u", stale_time);

    bgp_show_afis(-1006, "        AF supported:", afl1, afn1);
    bgp_show_afis(-1006, "        AF preserved:", afl2, afn2);
  }

  if (caps->hostname)
    cli_msg(-1006, "      Hostname: %s", caps->hostname);
}

static void
bgp_show_proto_info(struct proto *P)
{
  struct bgp_proto *p = (struct bgp_proto *) P;

  cli_msg(-1006, "  BGP state:          %s", bgp_state_dsc(p));

  if (bgp_is_dynamic(p) && p->cf->remote_range)
    cli_msg(-1006, "    Neighbor range:   %N", p->cf->remote_range);
  else
    cli_msg(-1006, "    Neighbor address: %I%J", p->remote_ip, p->cf->iface);

  cli_msg(-1006, "    Neighbor AS:      %u", p->remote_as);
  cli_msg(-1006, "    Local AS:         %u", p->cf->local_as);

  if (p->gr_active_num)
    cli_msg(-1006, "    Neighbor graceful restart active");

  if (P->proto_state == PS_START)
  {
    struct bgp_conn *oc = &p->outgoing_conn;

    if ((p->start_state < BSS_CONNECT) &&
	(tm_active(p->startup_timer)))
      cli_msg(-1006, "    Error wait:       %t/%u",
	      tm_remains(p->startup_timer), p->startup_delay);

    if ((oc->state == BS_ACTIVE) &&
	(tm_active(oc->connect_timer)))
      cli_msg(-1006, "    Connect delay:    %t/%u",
	      tm_remains(oc->connect_timer), p->cf->connect_delay_time);

    if (p->gr_active_num && tm_active(p->gr_timer))
      cli_msg(-1006, "    Restart timer:    %t/-",
	      tm_remains(p->gr_timer));
  }
  else if (P->proto_state == PS_UP)
  {
    cli_msg(-1006, "    Neighbor ID:      %R", p->remote_id);
    cli_msg(-1006, "    Local capabilities");
    bgp_show_capabilities(p, p->conn->local_caps);
    cli_msg(-1006, "    Neighbor capabilities");
    bgp_show_capabilities(p, p->conn->remote_caps);
    cli_msg(-1006, "    Session:          %s%s%s%s%s",
	    p->is_internal ? "internal" : "external",
	    p->cf->multihop ? " multihop" : "",
	    p->rr_client ? " route-reflector" : "",
	    p->rs_client ? " route-server" : "",
	    p->as4_session ? " AS4" : "");
    cli_msg(-1006, "    Source address:   %I", p->local_ip);
    cli_msg(-1006, "    Hold timer:       %t/%u",
	    tm_remains(p->conn->hold_timer), p->conn->hold_time);
    cli_msg(-1006, "    Keepalive timer:  %t/%u",
	    tm_remains(p->conn->keepalive_timer), p->conn->keepalive_time);
  }

#if 0
  struct bgp_stats *s = &p->stats;
  cli_msg(-1006, "    FSM established transitions: %u",
	  s->fsm_established_transitions);
  cli_msg(-1006, "    Rcvd messages:    %u total / %u updates / %lu bytes",
	  s->rx_messages, s->rx_updates, s->rx_bytes);
  cli_msg(-1006, "    Sent messages:    %u total / %u updates / %lu bytes",
	  s->tx_messages, s->tx_updates, s->tx_bytes);
  cli_msg(-1006, "    Last rcvd update elapsed time: %t s",
	  p->last_rx_update ? (current_time() - p->last_rx_update) : 0);
#endif

  if ((p->last_error_class != BE_NONE) &&
      (p->last_error_class != BE_MAN_DOWN))
  {
    const char *err1 = bgp_err_classes[p->last_error_class];
    const char *err2 = bgp_last_errmsg(p);
    cli_msg(-1006, "    Last error:       %s%s", err1, err2);
  }

  {
    struct bgp_channel *c;
    WALK_LIST(c, p->p.channels)
    {
      channel_show_info(&c->c);

      if (p->gr_active_num)
	cli_msg(-1006, "    Neighbor GR:    %s", bgp_gr_states[c->gr_active]);

      if (c->stale_timer && tm_active(c->stale_timer))
	cli_msg(-1006, "    LL stale timer: %t/-", tm_remains(c->stale_timer));

      if (c->c.channel_state == CS_UP)
      {
	if (ipa_zero(c->link_addr))
	  cli_msg(-1006, "    BGP Next hop:   %I", c->next_hop_addr);
	else
	  cli_msg(-1006, "    BGP Next hop:   %I %I", c->next_hop_addr, c->link_addr);
      }

      if (c->igp_table_ip4)
	cli_msg(-1006, "    IGP IPv4 table: %s", c->igp_table_ip4->name);

      if (c->igp_table_ip6)
	cli_msg(-1006, "    IGP IPv6 table: %s", c->igp_table_ip6->name);
    }
  }
}

struct channel_class channel_bgp = {
  .channel_size =	sizeof(struct bgp_channel),
  .config_size =	sizeof(struct bgp_channel_config),
  .init =		bgp_channel_init,
  .start =		bgp_channel_start,
  .shutdown =		bgp_channel_shutdown,
  .cleanup =		bgp_channel_cleanup,
  .reconfigure =	bgp_channel_reconfigure,
};

struct protocol proto_bgp = {
  .name = 		"BGP",
  .template = 		"bgp%d",
  .class =		PROTOCOL_BGP,
  .preference = 	DEF_PREF_BGP,
  .channel_mask =	NB_IP | NB_VPN | NB_FLOW,
  .proto_size =		sizeof(struct bgp_proto),
  .config_size =	sizeof(struct bgp_config),
  .postconfig =		bgp_postconfig,
  .init = 		bgp_init,
  .start = 		bgp_start,
  .shutdown = 		bgp_shutdown,
  .reconfigure = 	bgp_reconfigure,
  .copy_config = 	bgp_copy_config,
  .get_status = 	bgp_get_status,
  .get_attr = 		bgp_get_attr,
  .get_route_info = 	bgp_get_route_info,
  .show_proto_info = 	bgp_show_proto_info
};
