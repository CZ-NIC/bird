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
 * RFC 5668 - 4-Octet AS Specific BGP Extended Community
 * RFC 5925 - TCP Authentication Option
 * RFC 6286 - AS-Wide Unique BGP Identifier
 * RFC 6608 - Subcodes for BGP Finite State Machine Error
 * RFC 6793 - BGP Support for 4-Octet AS Numbers
 * RFC 7311 - Accumulated IGP Metric Attribute for BGP
 * RFC 7313 - Enhanced Route Refresh Capability for BGP
 * RFC 7606 - Revised Error Handling for BGP UPDATE Messages
 * RFC 7911 - Advertisement of Multiple Paths in BGP
 * RFC 7947 - Internet Exchange BGP Route Server
 * RFC 8092 - BGP Large Communities Attribute
 * RFC 8212 - Default EBGP Route Propagation Behavior without Policies
 * RFC 8654 - Extended Message Support for BGP
 * RFC 8950 - Advertising IPv4 NLRI with an IPv6 Next Hop
 * RFC 8955 - Dissemination of Flow Specification Rules
 * RFC 8956 - Dissemination of Flow Specification Rules for IPv6
 * RFC 9003 - Extended BGP Administrative Shutdown Communication
 * RFC 9072 - Extended Optional Parameters Length for BGP OPEN Message
 * RFC 9117 - Revised Validation Procedure for BGP Flow Specifications
 * RFC 9234 - Route Leak Prevention and Detection Using Roles
 * RFC 9494 - Long-Lived Graceful Restart for BGP
 * RFC 9687 - Send Hold Timer
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
#include "proto/bmp/bmp.h"


static list STATIC_LIST_INIT(bgp_sockets);		/* Global list of listening sockets */


static void bgp_connect(struct bgp_proto *p);
static void bgp_active(struct bgp_proto *p);
static void bgp_setup_conn(struct bgp_proto *p, struct bgp_conn *conn);
static void bgp_setup_sk(struct bgp_conn *conn, sock *s);
static void bgp_send_open(struct bgp_conn *conn);
static void bgp_update_bfd(struct bgp_proto *p, const struct bfd_options *bfd);

static int bgp_disable_ao_keys(struct bgp_proto *p);
static int bgp_incoming_connection(sock *sk, uint dummy UNUSED);
static void bgp_listen_sock_err(sock *sk UNUSED, int err);
static int bgp_listen_open(struct bgp_proto *, struct bgp_listen_request *);
static void bgp_listen_close(struct bgp_proto *, struct bgp_listen_request *);

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
  /* Interface-patterned listening sockets are created from the
   * interface notifier. By default, listen to nothing.
   *
   * Also dynamically spawned protocol do not need a listening socket,
   * they already have their parent's one and the requests are actually
   * ignored when looking for the accepting protocol. */
  if (p->cf->ipatt || p->cf->c.parent)
    return 0;

  /* We assume that cf->iface is defined iff cf->local_ip is link-local */
  struct bgp_listen_request *req = mb_allocz(p->p.pool, sizeof *req);
  req->params = (struct bgp_socket_params) {
    .iface = p->cf->strict_bind ? p->cf->iface : NULL,
    .vrf = p->p.vrf,
    .addr = p->cf->strict_bind && ipa_nonzero(p->cf->local_ip) ? p->cf->local_ip :
      (p->ipv4 ? IPA_NONE4 : IPA_NONE6),
    .port = p->cf->local_port,
    .flags = p->cf->free_bind ? SKF_FREEBIND : 0,
  };

  return bgp_listen_open(p, req);
}

#define bgp_listen_debug(p, a, msg, args...) do { \
  if ((p)->p.debug & D_IFACES) \
    log(L_TRACE "%s: Listening socket at %I%J port %u (vrf %s) flags %u: " msg, \
	(p)->p.name, (a)->addr, (a)->iface, (a)->port, \
	(a)->vrf ? (a)->vrf->name : "default", (a)->flags, ## args); \
} while (0)

static int
bgp_socket_match(const struct bgp_socket_params *a, const struct bgp_socket_params *b)
{
  return
    ipa_equal(a->addr, b->addr) &&
    a->iface == b->iface &&
    a->vrf == b->vrf &&
    a->port == b->port &&
    a->flags == b->flags &&
    1;
}

static int
bgp_listen_open(struct bgp_proto *p, struct bgp_listen_request *req)
{
  ASSERT_DIE(!NODE_VALID(&req->pn));
  ASSERT_DIE(!NODE_VALID(&req->sn));

  struct bgp_socket *bs;
  WALK_LIST(bs, bgp_sockets)
    if (bgp_socket_match(&bs->params, &req->params))
    {
      bgp_listen_debug(p, &req->params, "exists: %p", bs);
      add_tail(&p->listen, &req->pn);
      add_tail(&bs->requests, &req->sn);
      req->sock = bs;
      return 0;
    }

  sock *sk = sk_new(proto_pool);
  sk->type = SK_TCP_PASSIVE;
  sk->ttl = 255;
  sk->saddr = req->params.addr;
  sk->sport = req->params.port;
  sk->iface = req->params.iface;
  sk->vrf = req->params.vrf;
  sk->flags = req->params.flags;
  sk->tos = IP_PREC_INTERNET_CONTROL;
  sk->rbsize = BGP_RX_BUFFER_SIZE;
  sk->tbsize = BGP_TX_BUFFER_SIZE;
  sk->rx_hook = bgp_incoming_connection;
  sk->err_hook = bgp_listen_sock_err;

  if (sk_open(sk) < 0)
    goto err;

  bs = mb_allocz(proto_pool, sizeof(struct bgp_socket));
  memcpy(&bs->params, &req->params, sizeof bs->params);
  bs->sk = sk;
  sk->data = bs;
  req->sock = bs;

  init_list(&bs->requests);
  add_tail(&bs->requests, &req->sn);

  add_tail(&p->listen, &req->pn);
  add_tail(&bgp_sockets, &bs->n);

  bgp_listen_debug(p, &req->params, "create: %p", bs);

  return 0;

err:
  sk_log_error(sk, p->p.name);
  log(L_ERR "%s: Cannot open listening socket", p->p.name);
  rfree(sk);
  return -1;
}

static void
bgp_listen_close(struct bgp_proto *p UNUSED, struct bgp_listen_request *req)
{
  struct bgp_socket *bs = req->sock;
  ASSERT(bs);

  rem_node(&req->pn);
  rem_node(&req->sn);
  if (!EMPTY_LIST(bs->requests))
  {
    bgp_listen_debug(p, &req->params, "unlink: %p", bs);
    return;
  }

  bgp_listen_debug(p, &req->params, "free: %p", bs);
  rfree(bs->sk);
  rem_node(&bs->n);
  mb_free(bs);
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
  struct bgp_listen_request *req;
  WALK_LIST_FIRST2(req, pn, p->listen)
    bgp_listen_close(p, req);

  ASSERT_DIE(EMPTY_LIST(p->listen));
}


/*
 *	TCP-AO keys
 */

static struct bgp_ao_key *
bgp_new_ao_key(struct bgp_proto *p, struct ao_config *cf)
{
  struct bgp_ao_key *key = mb_allocz(p->p.pool, sizeof(struct bgp_ao_key));

  key->key = cf->key;
  add_tail(&p->ao.keys, &key->n);

  return key;
}

static struct bgp_ao_key *
bgp_find_ao_key_(list *l, int send_id, int recv_id)
{
  WALK_LIST_(struct bgp_ao_key, key, *l)
    if ((key->key.send_id == send_id) && (key->key.recv_id == recv_id))
      return key;

  return NULL;
}

static inline struct bgp_ao_key * UNUSED
bgp_find_ao_key(struct bgp_proto *p, int send_id, int recv_id)
{ return bgp_find_ao_key_(&p->ao.keys, send_id, recv_id); }

static int
bgp_same_ao_key(struct ao_key *a, struct ao_key *b)
{
  return
    (a->send_id == b->send_id) &&
    (a->recv_id == b->recv_id) &&
    (a->algorithm == b->algorithm) &&
    (a->keylen == b->keylen) &&
    !memcmp(a->key, b->key, a->keylen);
}

static inline int
bgp_sk_add_ao_key(struct bgp_proto *p, sock *sk, struct bgp_ao_key *key, const char *kind)
{
  ip_addr prefix = p->cf->remote_ip;
  int pxlen = -1;

  int rv = sk_add_ao_key(sk, prefix, pxlen, p->cf->iface, &key->key, false, false);
  if (rv < 0)
  {
    sk_log_error(sk, p->p.name);
    log(L_ERR "%s: Cannot add TCP-AO key %d/%d to BGP %s socket",
	p->p.name, key->key.send_id, key->key.recv_id, kind);
  }

  return rv;
}

static int
bgp_sk_delete_ao_key(struct bgp_proto *p, sock *sk, struct bgp_ao_key *key,
		     struct bgp_ao_key *backup, int current_key_id, int rnext_key_id,
		     const char *kind);

static int
bgp_enable_ao_key(struct bgp_proto *p, struct bgp_ao_key *key)
{
  ASSERT(!key->active);

  BGP_TRACE(D_EVENTS, "Adding TCP-AO key %d/%d", key->key.send_id, key->key.recv_id);

  /* Handle listening sockets */
  struct bgp_listen_request *blr, *failed = NULL; node *nxt;
  WALK_LIST2(blr, nxt, p->listen, pn)
    if (bgp_sk_add_ao_key(p, blr->sock->sk, key, "listening") < 0)
    {
      failed = blr;
      goto failA;
    }

  /* Handle incoming socket */
  if (p->incoming_conn.sk)
    if (bgp_sk_add_ao_key(p, p->incoming_conn.sk, key, "session (in)") < 0)
      goto failA;

  /* Handle outgoing socket */
  if (p->outgoing_conn.sk)
    if (bgp_sk_add_ao_key(p, p->outgoing_conn.sk, key, "session (out)") < 0)
      goto failB;

  key->active = 1;
  return 0;

failB:
  /* Cleanup incoming socket */
  if (p->incoming_conn.sk)
    bgp_sk_delete_ao_key(p, p->incoming_conn.sk, key, NULL, -1, -1, "session (in)");

failA:
  /* Cleanup listening sockets */
  WALK_LIST2(blr, nxt, p->listen, pn)
  {
    if (blr == failed)
      break;

    bgp_sk_delete_ao_key(p, blr->sock->sk, key, NULL, -1, -1, "listening");
  }

  /* Mark as failed */
  key->failed = 1;
  return -1;
}

struct bgp_active_keys {
  int in_current, in_rnext;
  int out_current, out_rnext;
  struct bgp_ao_key *backup;
};

static int
bgp_sk_delete_ao_key(struct bgp_proto *p, sock *sk, struct bgp_ao_key *key,
		     struct bgp_ao_key *backup, int current_key_id, int rnext_key_id,
		     const char *kind)
{
  struct ao_key *set_current = NULL, *set_rnext = NULL;

  if ((key->key.send_id == current_key_id) && backup)
  {
    log(L_WARN "%s: Deleting TCP-AO Current key %d/%d, setting Current key to %d/%d",
	p->p.name, key->key.send_id, key->key.recv_id, backup->key.send_id, backup->key.recv_id);

    set_current = &backup->key;
  }

  if ((key->key.recv_id == rnext_key_id) && backup)
  {
    log(L_WARN "%s: Deleting TCP-AO RNext key %d/%d, setting RNext key to %d/%d",
	p->p.name, key->key.send_id, key->key.recv_id, backup->key.send_id, backup->key.recv_id);

    set_rnext = &backup->key;
  }

  ip_addr prefix = p->cf->remote_ip;
  int pxlen = -1;

  int rv = sk_delete_ao_key(sk, prefix, pxlen, p->cf->iface, &key->key, set_current, set_rnext);
  if (rv < 0)
  {
    sk_log_error(sk, p->p.name);
    log(L_ERR "%s: Cannot delete TCP-AO key %d/%d from BGP %s socket",
	p->p.name, key->key.send_id, key->key.recv_id, kind);
  }

  return rv;
}

static int
bgp_disable_ao_key(struct bgp_proto *p, struct bgp_ao_key *key, struct bgp_active_keys *info)
{
  ASSERT(key->active);

  BGP_TRACE(D_EVENTS, "Deleting TCP-AO key %d/%d", key->key.send_id, key->key.recv_id);

  /* Try to disable everywhere even if first fails */
  int rv = 0;

  /* Handle listening socket */
  struct bgp_listen_request *blr; node *nxt;
  WALK_LIST2(blr, nxt, p->listen, pn)
    if (bgp_sk_delete_ao_key(p, blr->sock->sk, key, NULL, -1, -1, "listening") < 0)
      rv = -1;

  key->active = 0;

  /* Handle incoming socket */
  if (p->incoming_conn.sk && info)
    if (bgp_sk_delete_ao_key(p, p->incoming_conn.sk, key, info->backup, info->in_current, info->in_rnext, "session (in)") < 0)
      rv = -1;

  /* Handle outgoing socket */
  if (p->outgoing_conn.sk && info)
    if (bgp_sk_delete_ao_key(p, p->outgoing_conn.sk, key, info->backup, info->out_current, info->out_rnext, "session (out)") < 0)
      rv = -1;

  return rv;
}

static int
bgp_remove_ao_key(struct bgp_proto *p, struct bgp_ao_key *key, struct bgp_active_keys *info)
{
  ASSERT(key != p->ao.best_key);

  if (key->active)
    if (bgp_disable_ao_key(p, key, info) < 0)
      return -1;

  rem_node(&key->n);
  mb_free(key);
  return 0;
}


static struct bgp_ao_key *
bgp_select_best_ao_key(struct bgp_proto *p)
{
  struct bgp_ao_key *best = NULL;

  WALK_LIST_(struct bgp_ao_key, key, p->ao.keys)
  {
    if (!key->active)
      continue;

    /* Never select deprecated keys */
    if (key->key.preference < 0)
      continue;

    if (!best || (best->key.preference < key->key.preference))
      best = key;
  }

  return best;
}

static int
bgp_sk_set_rnext_ao_key(struct bgp_proto *p, sock *sk, struct bgp_ao_key *key)
{
  int rv = sk_set_rnext_ao_key(sk, &key->key);
  if (rv < 0)
  {
    sk_log_error(sk, p->p.name);
    log(L_ERR "%s: Cannot set TCP-AO key %d/%d as RNext key",
	p->p.name, key->key.send_id, key->key.recv_id);
  }

  return rv;
}

static int
bgp_update_rnext_ao_key(struct bgp_proto *p)
{
  struct bgp_ao_key *best = bgp_select_best_ao_key(p);

  if (!best)
  {
    log(L_ERR "%s: No usable TCP-AO key", p->p.name);
    return -1;
  }

  if (best == p->ao.best_key)
    return 0;

  BGP_TRACE(D_EVENTS, "Setting TCP-AO key %d/%d as RNext key", best->key.send_id, best->key.recv_id);

  p->ao.best_key = best;

  /* Handle incoming socket */
  if (p->incoming_conn.sk)
    if (bgp_sk_set_rnext_ao_key(p, p->incoming_conn.sk, best) < 0)
      return -1;

  /* Handle outgoing socket */
  if (p->outgoing_conn.sk)
    if (bgp_sk_set_rnext_ao_key(p, p->outgoing_conn.sk, best) < 0)
      return -1;

  /* Schedule Keepalive to trigger RNext ID exchange */
  if (p->conn)
    bgp_schedule_packet(p->conn, NULL, PKT_KEEPALIVE);

  /* RFC 4271 4.4 says that Keepalive messages MUST NOT be sent more frequently
     than one per second, but since key change is rare, this is harmless. */

  return 0;
}


/**
 * bgp_enable_ao_keys - Enable TCP-AO keys
 * @p: BGP instance
 *
 * Enable all TCP-AO keys for the listening socket. We accept if some fail in
 * non-fatal way (e.g. kernel does not support specific algorithm), but there
 * must be at least one usable (non-deprecated) active key. In case of failure,
 * we remove all keys, so there is no lasting effect on the listening socket.
 * Returns: 0 for okay, -1 for failure.
 */
static int
bgp_enable_ao_keys(struct bgp_proto *p)
{
  ASSERT(!p->incoming_conn.sk && !p->outgoing_conn.sk);

  WALK_LIST_(struct bgp_ao_key, key, p->ao.keys)
    bgp_enable_ao_key(p, key);

  p->ao.best_key = bgp_select_best_ao_key(p);

  if (!p->ao.best_key)
  {
    log(L_ERR "%s: No usable TCP-AO key", p->p.name);
    goto fail;
  }

  return 0;

fail:
  bgp_disable_ao_keys(p);
  return -1;
}

/**
 * bgp_disable_ao_keys - Disable TCP-AO keys
 * @p: BGP instance
 *
 * Disable all TCP-AO keys for the listening socket. We assume there are no
 * active connection, so no issue with removal of the current key. Errors are
 * ignored.
 */
static int
bgp_disable_ao_keys(struct bgp_proto *p)
{
  ASSERT(!p->incoming_conn.sk && !p->outgoing_conn.sk);

  WALK_LIST_(struct bgp_ao_key, key, p->ao.keys)
    if (key->active)
      bgp_disable_ao_key(p, key, NULL);

  return 0;
}

static int
bgp_reconfigure_ao_keys(struct bgp_proto *p, const struct bgp_config *cf)
{
  /* TCP-AO not used */
  if (EMPTY_LIST(p->ao.keys) && !cf->ao_keys)
    return 1;

  /* Cannot enable/disable TCP-AO */
  if (EMPTY_LIST(p->ao.keys) || !cf->ao_keys)
    return 0;

  /* Too early, TCP-AO not yet enabled */
  if (p->start_state == BSS_PREPARE)
    return 0;

  /* Move existing keys to temporary list */
  list old_keys;
  init_list(&old_keys);
  add_tail_list(&old_keys, &p->ao.keys);
  init_list(&p->ao.keys);

  /* Clean up the best key */
  struct bgp_ao_key *old_best = p->ao.best_key;
  p->ao.best_key = NULL;

  /* Prepare new set of keys */
  for (struct ao_config *key_cf = cf->ao_keys; key_cf; key_cf = key_cf->next)
  {
    struct bgp_ao_key *key = bgp_find_ao_key_(&old_keys, key_cf->key.send_id, key_cf->key.recv_id);

    if (key && bgp_same_ao_key(&key->key, &key_cf->key))
    {
      /* Update key ptr and preference */
      key->key = key_cf->key;

      rem_node(&key->n);
      add_tail(&p->ao.keys, &key->n);

      if (key == old_best)
	p->ao.best_key = key;

      continue;
    }

    bgp_new_ao_key(p, key_cf);
  }

  /* Remove old keys */
  if (!EMPTY_LIST(old_keys))
  {
    struct bgp_active_keys info = { -1, -1, -1, -1, NULL};

    /* Find current/rnext keys on incoming connection */
    if (p->incoming_conn.sk)
      if (sk_get_active_ao_keys(p->incoming_conn.sk, &info.in_current, &info.in_rnext) < -1)
	sk_log_error(p->incoming_conn.sk, p->p.name);

    /* Find current/rnext keys on outgoing connection */
    if (p->outgoing_conn.sk)
      if (sk_get_active_ao_keys(p->outgoing_conn.sk, &info.out_current, &info.out_rnext) < -1)
	sk_log_error(p->outgoing_conn.sk, p->p.name);

    /*
     * Select backup key in case of removal of current/rnext key.
     *
     * It is possible that we cannot select an intermediate best key (e.g. when
     * the reconfiguration deprecates the old best key and adds the new one).
     * That is not necessary bad, we may not even need the backup key anyways.
     * In this case we use the old best key (ao.best_key) instead even if it may
     * be deprecated (but not removed).
     *
     * If neither one is available, that means we are going to remove rnext key
     * and we have no intermediate best key to switch to, therefore we fail
     * later during bgp_remove_ao_key().
     */
    info.backup = bgp_select_best_ao_key(p) ?: p->ao.best_key;
    if (!info.backup)
      log(L_WARN "%s: No usable backup key", p->p.name);

    struct bgp_ao_key *key, *key2;
    WALK_LIST_DELSAFE(key, key2, old_keys)
      bgp_remove_ao_key(p, key, &info);

    /* If some key removals failed, restart */
    if (!EMPTY_LIST(old_keys))
      return 0;
  }

  /* Enable new keys */
  WALK_LIST_(struct bgp_ao_key, key, p->ao.keys)
    if (!key->active && !key->failed)
      bgp_enable_ao_key(p, key);

  /* Update RNext key */
  if (bgp_update_rnext_ao_key(p) < 0)
    return 0;

  return 1;
}

/**
 * bgp_list_ao_keys - List active TCP-AO keys
 * @p: BGP instance
 * @ao_keys: Returns array of keys
 * @ao_keys_num: Returns number of keys
 *
 * Returns an array of pointers to active TCP-AO keys, for usage with socket
 * functions. The best key is at the first position. The array is allocated from
 * the temporary linpool. If there are no keys (or just no best key), the error
 * is logged and the function fails. Returns: 0 for success, -1 for failure.
 */
static int
bgp_list_ao_keys(struct bgp_proto *p, const struct ao_key ***ao_keys, int *ao_keys_num)
{
  int num = 0;
  WALK_LIST_(const struct bgp_ao_key, key, p->ao.keys)
    if (key->active)
      num++;

  const struct bgp_ao_key *best = p->ao.best_key;

  if (!num || !best)
  {
    log(L_ERR "%s: No usable TCP-AO key", p->p.name);
    return -1;
  }

  const struct ao_key **keys = tmp_alloc(num * sizeof(const struct ao_key *));
  int i = 0;

  keys[i++] = &best->key;
  WALK_LIST_(const struct bgp_ao_key, key, p->ao.keys)
    if (key->active && (key != best) && (i < num))
      keys[i++] = &key->key;

  *ao_keys = keys;
  *ao_keys_num = i;
  return 0;
}




static int
bgp_setup_auth(struct bgp_proto *p, int enable)
{
  if (p->cf->auth_type == BGP_AUTH_AO)
  {
    if (enable)
      return bgp_enable_ao_keys(p);
    else
      return bgp_disable_ao_keys(p);
  }

  if (p->cf->auth_type == BGP_AUTH_MD5)
  {
    ip_addr prefix = p->cf->remote_ip;
    int pxlen = -1;

    if (p->cf->remote_range)
    {
      prefix = net_prefix(p->cf->remote_range);
      pxlen = net_pxlen(p->cf->remote_range);
    }

    /* Set/reset the MD5 password at all listening sockets */
    int rv = 0;
    struct bgp_listen_request *blr; node *nxt;
    WALK_LIST2(blr, nxt, p->listen, pn)
    {
      rv = sk_set_md5_auth(blr->sock->sk,
	  p->cf->local_ip, prefix, pxlen, p->cf->iface,
	  enable ? p->cf->password : NULL, p->cf->setkey);

      if (rv < 0)
      {
	sk_log_error(blr->sock->sk, p->p.name);

	/* When disabling, just continue, there is nothing to salvage */
	if (!enable)
	  continue;

	/* Trying to rewind from the listening sockets */
	struct bgp_listen_request *failed = blr;
	bool emsg = false;
	WALK_LIST2(blr, nxt, p->listen, pn)
	{
	  if (blr == failed)
	    break;

	  int rrv = sk_set_md5_auth(blr->sock->sk,
	      p->cf->local_ip, prefix, pxlen, p->cf->iface,
	      NULL, p->cf->setkey);

	  if (rrv < 0)
	  {
	    if (!emsg)
	    {
	      log(L_ERR "%s: Trying to rewind MD5 auth failed as well.");
	      emsg = true;
	    }

	    sk_log_error(blr->sock->sk, p->p.name);
	  }
	}

	/* One socket failed while enabling, the whole protocol failed. */
	return rv;
      }
    }
  }

  return 0;
}

static inline struct bgp_channel *
bgp_find_channel(struct bgp_proto *p, u32 afi)
{
  struct bgp_channel *c;
  BGP_WALK_CHANNELS(p, c)
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
  { err_val = BEM_INVALID_AUTH; goto err2; }

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

  p->neigh = NULL;
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
  rfree(conn->send_hold_timer);
  conn->send_hold_timer = NULL;
  rfree(conn->tx_ev);
  conn->tx_ev = NULL;
  rfree(conn->sk);
  conn->sk = NULL;

  mb_free(conn->local_open_msg);
  conn->local_open_msg = NULL;
  mb_free(conn->remote_open_msg);
  conn->remote_open_msg = NULL;
  conn->local_open_length = 0;
  conn->remote_open_length = 0;

  mb_free(conn->local_caps);
  conn->local_caps = NULL;
  mb_free(conn->remote_caps);
  conn->remote_caps = NULL;

  conn->notify_data = NULL;
  conn->notify_size = 0;
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

  p->neigh = NULL;

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

static int
bgp_spawn(struct bgp_proto *pp, sock *sk)
{
  struct symbol *sym;
  char fmt[SYM_MAX_LEN];

  bsprintf(fmt, "%s%%0%dd", pp->cf->dynamic_name, pp->cf->dynamic_name_digits);

  /* This is hack, we would like to share config, but we need to copy it now */
  new_config = config;
  cfg_mem = config->mem;
  config->current_scope = config->root_scope;
  sym = cf_default_name(config, fmt, &(pp->dynamic_name_counter));
  proto_clone_config(sym, pp->p.cf);
  new_config = NULL;
  cfg_mem = NULL;

  /* Just pass remote_ip to bgp_init() */
  struct bgp_config *cf = SKIP_BACK(struct bgp_config, c, sym->proto);
  cf->remote_ip = sk->daddr;
  cf->local_ip = sk->saddr;
  cf->iface = sk->iface;

  struct bgp_proto *p = SKIP_BACK(struct bgp_proto, p, proto_spawn(sym->proto, 0));
  p->postponed_sk = sk;
  rmove(sk, p->p.pool);

  return 0;
}

void
bgp_stop(struct bgp_proto *p, int subcode, byte *data, uint len)
{
  proto_shutdown_mpls_map(&p->p, 1);

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

  BGP_WALK_CHANNELS(p, c)
  {
    const struct bgp_af_caps *loc = bgp_find_af_caps(local, c->afi);
    const struct bgp_af_caps *rem = bgp_find_af_caps(peer,  c->afi);

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
    c->stale_time = local->llgr_aware ?
      CLAMP(rem->llgr_time, c->cf->min_llgr_time, c->cf->max_llgr_time) : 0;

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

  BGP_WALK_CHANNELS(p, c)
  {
    if (c->c.disabled)
      continue;

    p->afi_map[c->index] = c->afi;
    p->channel_map[c->index] = c;
  }

  /* Breaking rx_hook for simulating receive problem */
  if (p->cf->disable_rx)
  {
    conn->sk->rx_hook = NULL;
    tm_stop(conn->hold_timer);
  }

  /* proto_notify_state() will likely call bgp_feed_begin(), setting c->feed_state */

  bgp_conn_set_state(conn, BS_ESTABLISHED);
  proto_notify_state(&p->p, PS_UP);
  bmp_peer_up(p, conn->local_open_msg, conn->local_open_length,
	      conn->remote_open_msg, conn->remote_open_length);
}

static void
bgp_conn_leave_established_state(struct bgp_conn *conn, struct bgp_proto *p)
{
  BGP_TRACE(D_EVENTS, "BGP session closed");
  p->last_established = current_time();
  p->conn = NULL;

  if (p->p.proto_state == PS_UP)
    bgp_stop(p, 0, NULL, 0);

  bmp_peer_down(p, p->last_error_class,
		conn->notify_code, conn->notify_subcode,
		conn->notify_data, conn->notify_size);
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
    bgp_conn_leave_established_state(conn, p);
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
    bgp_conn_leave_established_state(conn, p);
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
  BGP_WALK_CHANNELS(p, c)
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

  uint gr_time = CLAMP(p->conn->remote_caps->gr_time,
		       p->cf->min_gr_time, p->cf->max_gr_time);

  proto_notify_state(&p->p, PS_START);
  tm_start(p->gr_timer, gr_time S);
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
    BGP_WALK_CHANNELS(p, c)
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

void
bgp_send_hold_timeout(timer *t)
{
  struct bgp_conn *conn = t->data;
  struct bgp_proto *p = conn->bgp;

  DBG("BGP: Send hold timeout\n");

  if (conn->state == BS_CLOSE)
    return;

  uint code = 8;
  uint subcode = 0;

  /* Like bgp_error() but without NOTIFICATION */
  bgp_log_error(p, BE_BGP_TX, "Error", code, subcode, NULL, 0);
  bgp_store_error(p, conn, BE_BGP_TX, (code << 16) | subcode);
  bgp_conn_enter_idle_state(conn);
  bgp_update_startup_delay(p);
  bgp_stop(p, 0, NULL, 0);
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
  conn->send_hold_timer = tm_new_init(p->p.pool, bgp_send_hold_timeout, conn, 0, 0);

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
  int hops = p->cf->multihop ?: 1;

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
  s->tx_hook = bgp_connected;
  s->flags = p->cf->free_bind ? SKF_FREEBIND : 0;
  BGP_TRACE(D_EVENTS, "Connecting to %I%J from local address %I%J",
	    s->daddr, ipa_is_link_local(s->daddr) ? p->cf->iface : NULL,
	    s->saddr, ipa_is_link_local(s->saddr) ? s->iface : NULL);
  bgp_setup_conn(p, conn);
  bgp_setup_sk(conn, s);
  bgp_conn_set_state(conn, BS_CONNECT);

  if (p->cf->auth_type == BGP_AUTH_MD5)
    s->password = p->cf->password;

  if (p->cf->auth_type == BGP_AUTH_AO)
    if (bgp_list_ao_keys(p, &s->ao_keys_init, &s->ao_keys_num) < 0)
      goto err2;

  if (sk_open(s) < 0)
    goto err;

  /* Set minimal receive TTL if needed */
  if (p->cf->ttl_security)
    if (sk_set_min_ttl(s, 256 - hops) < 0)
      goto err;

  s->ao_keys_num = 0;
  s->ao_keys_init = NULL;

  DBG("BGP: Waiting for connect success\n");
  bgp_start_timer(conn->connect_timer, p->cf->connect_retry_time);
  return;

err:
  sk_log_error(s, p->p.name);
err2:
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

  /* sk->iface is valid only if src or dst address is link-local or if strict bind on interface is set */
  bool link = ipa_is_link_local(sk->saddr) || ipa_is_link_local(sk->daddr);

  WALK_LIST(p, proto_list)
  {
    /* Not a BGP */
    if (p->p.proto != &proto_bgp)
      continue;

    /* Remote address configured but not the right one */
    if (!ipa_equal(p->remote_ip, sk->daddr) && !bgp_is_dynamic(p))
      continue;

    /* Remote range configured but the remote address is not in it */
    if (p->cf->remote_range && !ipa_in_netX(sk->daddr, p->cf->remote_range))
      continue;

    /* Not the right VRF */
    if (p->p.vrf != sk->vrf)
      continue;

    /* Not the right local port */
    if (p->cf->local_port != sk->sport)
      continue;

    /* Local address set but not matching */
    if (!ipa_zero(p->cf->local_ip) && !ipa_equal(p->cf->local_ip, sk->saddr))
      continue;

    /* The interface set but not matching */
    if ((link || p->cf->strict_bind) && p->cf->iface && (p->cf->iface != sk->iface))
      continue;

    /* Interface pattern configured and not matching */
    if ((link || p->cf->strict_bind) && p->cf->ipatt && !iface_patt_match(p->cf->ipatt, sk->iface, NULL))
      continue;

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

  if ((p->p.proto_state != PS_DOWN) && !EMPTY_LIST(p->ao.keys))
  {
    int current = -1, rnext = -1;
    sk_get_active_ao_keys(sk, &current, &rnext);

    if (current < 0)
    {
      log(L_WARN "%s: Connection from address %I%J (port %d) has no TCP-AO key",
          p->p.name, sk->daddr, ipa_is_link_local(sk->daddr) ? sk->iface : NULL, sk->dport);
      rfree(sk);
      return 0;
    }
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

  hops = p->cf->multihop ?: 1;

  if (sk_set_ttl(sk, p->cf->ttl_security ? 255 : hops) < 0)
    goto err;

  if (p->cf->ttl_security)
    if (sk_set_min_ttl(sk, 256 - hops) < 0)
      goto err;

  if (!EMPTY_LIST(p->ao.keys))
  {
    const struct ao_key **ao_keys;
    int ao_keys_num;

    if (bgp_list_ao_keys(p, &ao_keys, &ao_keys_num) < 0)
      goto err2;

    if (sk_check_ao_keys(sk, ao_keys, ao_keys_num, p->p.name) < 0)
      goto err2;

    if (sk_set_rnext_ao_key(sk, ao_keys[0]) < 0)
      goto err;
  }

  if (p->cf->enable_extended_messages)
  {
    sk->rbsize = BGP_RX_BUFFER_EXT_SIZE;
    sk->tbsize = BGP_TX_BUFFER_EXT_SIZE;
    sk_reallocate(sk);
  }

  /* For dynamic BGP, spawn new instance and postpone the socket */
  if (bgp_is_dynamic(p))
    return bgp_spawn(p, sk);

  rmove(sk, p->p.pool);
  bgp_setup_conn(p, &p->incoming_conn);
  bgp_setup_sk(&p->incoming_conn, sk);
  bgp_send_open(&p->incoming_conn);
  return 0;

err:
  sk_log_error(sk, p->p.name);
err2:
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

static bool
bgp_iface_match(struct bgp_proto *p, struct iface *i)
{
  int ps = p->p.proto_state;

  ASSERT_DIE(p->cf->ipatt);
  ASSERT_DIE(p->cf->strict_bind);

  if ((ps == PS_DOWN) || (ps == PS_STOP))
    return false;

  if (!iface_patt_match(p->cf->ipatt, i, NULL))
    return false;

  return true;
}

static void
bgp_iface_update(struct bgp_proto *p, uint flags, struct iface *i)
{
  struct bgp_socket_params params = {
    .iface = i,
    .vrf = p->p.vrf,
    .addr = ipa_nonzero(p->cf->local_ip) ? p->cf->local_ip : (p->ipv4 ? IPA_NONE4 : IPA_NONE6),
    .port = p->cf->local_port,
    .flags = p->cf->free_bind ? SKF_FREEBIND : 0,
  };

  if (flags & IF_CHANGE_UP)
  {
    struct bgp_listen_request *req = mb_allocz(p->p.pool, sizeof *req);
    req->params = params;
    bgp_listen_open(p, req);
  }

  if (flags & IF_CHANGE_DOWN)
  {
    struct bgp_listen_request *req; node *nxt;
    WALK_LIST2(req, nxt, p->listen, pn)
      if (bgp_socket_match(&req->params, &params))
      {
	bgp_listen_close(p, req);
	mb_free(req);
	break;
      }
  }
}

static void
bgp_if_notify(struct proto *P, uint flags, struct iface *i)
{
  struct bgp_proto *p = (struct bgp_proto *) P;
  ASSERT_DIE(ipa_zero(p->cf->local_ip));
  if (bgp_iface_match(p, i))
    bgp_iface_update(p, flags, i);
}

static void
bgp_ifa_notify(struct proto *P, uint flags, struct ifa *i)
{
  struct bgp_proto *p = (struct bgp_proto *) P;
  ASSERT_DIE(!ipa_zero(p->cf->local_ip));

  if (ipa_equal(i->ip, p->cf->local_ip) && bgp_iface_match(p, i->iface))
    bgp_iface_update(p, flags, i->iface);
}

static void
bgp_if_reload(struct bgp_proto *p, struct iface_patt *patt)
{
  struct iface *iface;
  struct ifa *a;

  WALK_LIST(iface, iface_list)
  {
    bool old = iface_patt_match(p->cf->ipatt, iface, NULL);
    bool new = iface_patt_match(patt, iface, NULL);

    if (old == new)
      continue;

    if (ipa_zero(p->cf->local_ip) || p->cf->free_bind)
      bgp_iface_update(p, old ? IF_CHANGE_DOWN : IF_CHANGE_UP, iface);
    else
      WALK_LIST(a, iface->addrs)
	if (ipa_equal(a->ip, p->cf->local_ip))
	  bgp_iface_update(p, old ? IF_CHANGE_DOWN : IF_CHANGE_UP, iface);
  }
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

  /* For MPLS channel, reload all MPLS-aware channels */
  if (C == p->p.mpls_channel)
  {
    BGP_WALK_CHANNELS(p, c)
      if ((c->desc->mpls) && (p->route_refresh || c->c.in_table))
	bgp_reload_routes(&c->c);

    return;
  }

  /* Ignore non-BGP channels */
  if (C->channel != &channel_bgp)
    return;

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

  /* Ignore non-BGP channels */
  if (C->channel != &channel_bgp)
    return;

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

  /* Ignore non-BGP channels */
  if (C->channel != &channel_bgp)
    return;

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

  neighbor *n = neigh_find(&p->p, p->remote_ip, cf->iface, NEF_STICKY | (cf->onlink ? NEF_ONLINK : 0));
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

  p->hostname = proto_get_hostname(P->cf);

  p->local_id = proto_get_router_id(P->cf);
  if (p->rr_client)
    p->rr_cluster_id = p->cf->rr_cluster_id ? p->cf->rr_cluster_id : p->local_id;

  p->remote_id = 0;
  p->link_addr = IPA_NONE;

  /* Initialize listening socket list */
  init_list(&p->listen);

  /* Setup interface notification hooks */
  P->if_notify = NULL;
  P->ifa_notify = NULL;
  if (cf->ipatt) {
    if (ipa_zero(cf->local_ip) || cf->free_bind)
      P->if_notify = bgp_if_notify;
    else
      P->ifa_notify = bgp_ifa_notify;
  }

  /* Initialize TCP-AO keys */
  init_list(&p->ao.keys);
  if (cf->auth_type == BGP_AUTH_AO)
    for (struct ao_config *key_cf = cf->ao_keys; key_cf; key_cf = key_cf->next)
      bgp_new_ao_key(p, key_cf);

  proto_setup_mpls_map(P, RTS_BGP, 1);

  /* Lock all channels when in GR recovery mode */
  if (p->p.gr_recovery && p->cf->gr_mode)
  {
    struct bgp_channel *c;
    BGP_WALK_CHANNELS(p, c)
      channel_graceful_restart_lock(&c->c);
  }

  /*
   * Before attempting to create the connection, we need to lock the port,
   * so that we are the only instance attempting to talk with that neighbor.
   */
  struct object_lock *lock;
  lock = p->lock = olock_new(P->pool);
  lock->addr = p->remote_ip;
  lock->addr_local = p->cf->local_ip;
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

  /* RFC 9003 - shutdown communication */
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
  P->rte_igp_metric = bgp_rte_igp_metric;

  p->cf = cf;
  p->is_internal = (cf->local_as == cf->remote_as);
  p->is_interior = p->is_internal || cf->confederation_member;
  p->rs_client = cf->rs_client;
  p->rr_client = cf->rr_client;

  p->ipv4 = cf->ipv4;

  p->remote_ip = cf->remote_ip;
  p->remote_as = cf->remote_as;

  /* Hack: We use cf->remote_ip just to pass remote_ip from bgp_spawn() */
  if (cf->c.parent)
    cf->remote_ip = IPA_NONE;

  /* Add all BGP channels */
  struct bgp_channel_config *cc;
  BGP_CF_WALK_CHANNELS(cf, cc)
    proto_add_channel(P, &cc->c);

  /* Add MPLS channel */
  proto_configure_channel(P, &P->mpls_channel, proto_cf_mpls_channel(CF));

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

  if (cf->base_table)
    c->base_table = cf->base_table->table;
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

  if (c->base_table)
  {
    rt_lock_table(c->base_table);
    rt_flowspec_link(c->base_table, c->c.table);
  }

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

  if (c->base_table)
  {
    rt_flowspec_unlink(c->base_table, c->c.table);
    rt_unlock_table(c->base_table);
  }

  c->index = 0;

  /* Cleanup rest of bgp_channel starting at pool field */
  memset(&(c->pool), 0, sizeof(struct bgp_channel) - OFFSETOF(struct bgp_channel, pool));
}

static inline struct bgp_channel_config *
bgp_find_channel_config(struct bgp_config *cf, u32 afi)
{
  struct bgp_channel_config *cc;

  BGP_CF_WALK_CHANNELS(cf, cc)
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

static struct rtable_config *
bgp_default_base_table(struct bgp_config *cf, struct bgp_channel_config *cc)
{
  /* Expected table type */
  u32 type = (cc->afi == BGP_AF_FLOW4) ? NET_IP4 : NET_IP6;

  /* First, try appropriate IP channel */
  u32 afi2 = BGP_AF(BGP_AFI(cc->afi), BGP_SAFI_UNICAST);
  struct bgp_channel_config *cc2 = bgp_find_channel_config(cf, afi2);
  if (cc2 && (cc2->c.table->addr_type == type))
    return cc2->c.table;

  /* Last, try default table of given type */
  struct rtable_config *tab = cf->c.global->def_tables[type];
  if (tab)
    return tab;

  cf_error("Undefined base table");
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

  /* Detect IPv4 */
  cf->ipv4 = ipa_nonzero(cf->remote_ip) ?
    ipa_is_ip4(cf->remote_ip) :
    (cf->remote_range && (cf->remote_range->type == NET_IP4));

  if (!cf->local_as)
    cf_error("Local AS number must be set");

  if (ipa_zero(cf->remote_ip) && !cf->remote_range)
    cf_error("Neighbor must be configured");

  if (ipa_zero(cf->local_ip) && !cf->ipatt && !cf->iface && cf->strict_bind)
    cf_error("Local address or an interface must be configured for strict bind");

  if (!cf->remote_as && !cf->peer_type)
    cf_error("Remote AS number (or peer type) must be set");

  if ((cf->peer_type == BGP_PT_INTERNAL) && !internal)
    cf_error("IBGP cannot have different ASNs");

  if ((cf->peer_type == BGP_PT_EXTERNAL) &&  internal)
    cf_error("EBGP cannot have the same ASNs");

  if (!cf->iface && (ipa_is_link_local(cf->local_ip) ||
		     ipa_is_link_local(cf->remote_ip)))
    cf_error("Link-local addresses require defined interface");

  if (cf->iface && cf->ipatt)
    cf_error("Interface and interface range cannot be configured together");

  if (cf->ipatt && !cf->strict_bind)
    cf_error("Interface range needs strict bind");

  if (!(cf->capabilities && cf->enable_as4) && (cf->remote_as > 0xFFFF))
    cf_error("Neighbor AS number out of range (AS4 not available)");

  if (!internal && cf->rr_client)
    cf_error("Only internal neighbor can be RR client");

  if (internal && cf->rs_client)
    cf_error("Only external neighbor can be RS client");

  if (internal && (cf->local_role != BGP_ROLE_UNDEFINED))
    cf_error("Local role cannot be set on IBGP sessions");

  if (interior && (cf->local_role != BGP_ROLE_UNDEFINED))
    log(L_WARN "BGP roles are not recommended to be used within AS confederations");

  if (cf->require_enhanced_refresh && !(cf->enable_refresh && cf->enable_enhanced_refresh))
    cf_warn("Enhanced refresh required but disabled");

  if (cf->require_as4 && !cf->enable_as4)
    cf_warn("AS4 support required but disabled");

  if (cf->require_extended_messages && !cf->enable_extended_messages)
    cf_warn("Extended messages required but not enabled");

  if (cf->require_gr && !cf->gr_mode)
    cf_warn("Graceful restart required but not enabled");

  if (cf->require_llgr && !cf->llgr_mode)
    cf_warn("Long-lived graceful restart required but not enabled");

  if (cf->require_roles && (cf->local_role == BGP_ROLE_UNDEFINED))
    cf_error("Local role must be set if roles are required");

  if (!cf->confederation && cf->confederation_member)
    cf_error("Confederation ID must be set for member sessions");

  if (cf->multihop && (ipa_is_link_local(cf->local_ip) ||
		       ipa_is_link_local(cf->remote_ip)))
    cf_error("Multihop BGP cannot be used with link-local addresses");

  if (cf->multihop && (cf->iface || cf->ipatt))
    cf_error("Multihop BGP cannot be bound to interface");

  if (cf->multihop && cf->check_link)
    cf_error("Multihop BGP cannot depend on link state");

  if (cf->multihop && cf->bfd && ipa_zero(cf->local_ip))
    cf_error("Multihop BGP with BFD requires specified local address");

  if (cf->multihop && cf->onlink)
    cf_error("Multihop BGP cannot be configured onlink");

  if (cf->onlink && !cf->iface && !cf->ipatt &&
      !cf->passive && !ipa_zero(cf->remote_ip))
    cf_error("Active onlink BGP must have interface configured");

  if (!cf->gr_mode && cf->llgr_mode)
    cf_error("Long-lived graceful restart requires basic graceful restart");

  if (internal && cf->enforce_first_as)
    cf_error("Enforce first AS check is requires EBGP sessions");

  if (cf->keepalive_time > cf->hold_time)
    cf_error("Keepalive time must be at most hold time");

  if (cf->keepalive_time > (cf->hold_time / 2))
    log(L_WARN "Keepalive time should be at most 1/2 of hold time");

  if (cf->min_hold_time > cf->hold_time)
    cf_error("Min hold time (%u) exceeds hold time (%u)",
	     cf->min_hold_time, cf->hold_time);

  uint keepalive_time = cf->keepalive_time ?: cf->hold_time / 3;
  if (cf->min_keepalive_time > keepalive_time)
    cf_error("Min keepalive time (%u) exceeds keepalive time (%u)",
	     cf->min_keepalive_time, keepalive_time);

  if (cf->min_gr_time > cf->max_gr_time)
    cf_error("Min graceful restart time (%u) exceeds max graceful restart time (%u)",
	     cf->min_gr_time, cf->max_gr_time);

  if (cf->min_llgr_time > cf->max_llgr_time)
    cf_error("Min long-lived stale time (%u) exceeds max long-lived stale time (%u)",
	     cf->min_llgr_time, cf->max_llgr_time);

  /* Legacy case: password option without authentication option */
  if ((cf->auth_type == BGP_AUTH_NONE) && cf->password && !cf->ao_keys)
  {
    cf_warn("Missing authentication option, assuming MD5");
    cf->auth_type = BGP_AUTH_MD5;
  }

  if ((cf->auth_type == BGP_AUTH_MD5) != !!cf->password)
    cf_error("MD5 authentication and password option should be used together");

  if ((cf->auth_type == BGP_AUTH_AO) != !!cf->ao_keys)
    cf_error("AO authentication and keys option should be used together");

  if ((cf->auth_type == BGP_AUTH_AO) && cf->remote_range)
    cf_error("AO authentication not supported on dynamic BGP sessions");

  struct bgp_channel_config *cc;
  BGP_CF_WALK_CHANNELS(cf, cc)
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

    /* Different default for next_hop_prefer */
    if (!cc->next_hop_prefer)
      cc->next_hop_prefer = (cc->gw_mode == GW_DIRECT) ? NHP_GLOBAL : NHP_LOCAL;

    /* Defaults based on proto config */
    if (cc->gr_able == 0xff)
      cc->gr_able = (cf->gr_mode == BGP_GR_ABLE);

    if (cc->llgr_able == 0xff)
      cc->llgr_able = (cf->llgr_mode == BGP_LLGR_ABLE);

    if (cc->llgr_time == ~0U)
      cc->llgr_time = cf->llgr_time;

    if (cc->min_llgr_time == ~0U)
      cc->min_llgr_time = cf->min_llgr_time;

    if (cc->max_llgr_time == ~0U)
      cc->max_llgr_time = cf->max_llgr_time;

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

    /* Default value of base table */
    if ((BGP_SAFI(cc->afi) == BGP_SAFI_FLOW) && cc->validate && !cc->base_table)
      cc->base_table = bgp_default_base_table(cf, cc);

    if (cc->base_table && !cc->base_table->trie_used)
      cf_error("Flowspec validation requires base table (%s) with trie",
	       cc->base_table->name);

    if (cf->multihop && (cc->gw_mode == GW_DIRECT))
      cf_error("Multihop BGP cannot use direct gateway mode");

    if ((cc->gw_mode == GW_RECURSIVE) && cc->c.table->sorted)
      cf_error("BGP in recursive mode prohibits sorted table");

    if (cf->deterministic_med && cc->c.table->sorted)
      cf_error("BGP with deterministic MED prohibits sorted table");

    if (cc->secondary && !cc->c.table->sorted)
      cf_error("BGP with secondary option requires sorted table");

    if (cc->require_ext_next_hop && !cc->ext_next_hop)
      cf_warn("Extended next hop required but not enabled");

    if (cc->require_add_path && !cc->add_path)
      cf_warn("ADD-PATH required but not enabled");

    if (cc->min_llgr_time > cc->max_llgr_time)
      cf_error("Min long-lived stale time (%u) exceeds max long-lived stale time (%u)",
	       cc->min_llgr_time, cc->max_llgr_time);

  }
}

static int
bgp_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct bgp_proto *p = (void *) P;
  struct bgp_config *new = (void *) CF;
  const struct bgp_config *old = p->cf;

  /* XXX: There is a section in documentation describing which configuration
   * changes force BGP restart. When changing this function, you have to update
   * also that part of documentation. */

  if (proto_get_router_id(CF) != p->local_id)
    return 0;

  if (bstrcmp(proto_get_hostname(CF), p->hostname))
    return 0;

  /* Fix the virtual configuration so that memcpy does not fail */
  if (old->c.parent)
  {
    new->remote_ip = old->remote_ip;
    new->local_ip = old->local_ip;

    /* Pre-check interfaces */
    if (new->ipatt)
    {
      if (!old->iface || !iface_patt_match(new->ipatt, old->iface, NULL))
	return 0;
    }
    else if (new->iface)
    {
      if (old->iface != new->iface)
	return 0;
    }

    new->iface = old->iface;
  }

  int same = !memcmp(((byte *) old) + sizeof(struct proto_config),
		     ((byte *) new) + sizeof(struct proto_config),
		     // password item is last and must be checked separately
		     OFFSETOF(struct bgp_config, password) - sizeof(struct proto_config))
    && !bstrcmp(old->password, new->password)
    && ((!old->remote_range && !new->remote_range)
	|| (old->remote_range && new->remote_range && net_equal(old->remote_range, new->remote_range)))
    && !bstrcmp(old->dynamic_name, new->dynamic_name)
    && (old->dynamic_name_digits == new->dynamic_name_digits);

  /* Reconfigure interface notification hooks */
  same = same && (!P->if_notify == !(new->ipatt && ipa_zero(new->local_ip)));
  same = same && (!P->ifa_notify == !(new->ipatt && !ipa_zero(new->local_ip)));

  /* Differing pattern lists cause an update of the listening sockets
   * and also if the connection is up, then active sockets. */
  bool need_if_reload = same && new->ipatt && old->ipatt && !iface_plists_equal(new->ipatt, old->ipatt);
  if (need_if_reload && !bgp_is_dynamic(p) && (
	p->incoming_conn.sk && !iface_patt_match(new->ipatt, p->incoming_conn.sk->iface, NULL) ||
	p->outgoing_conn.sk && !iface_patt_match(new->ipatt, p->outgoing_conn.sk->iface, NULL)))
    same = 0;

  /* Reconfigure TCP-AO */
  same = same && bgp_reconfigure_ao_keys(p, new);

  /* FIXME: Move channel reconfiguration to generic protocol code ? */
  struct channel *C, *C2;
  struct bgp_channel_config *cc;

  WALK_LIST(C, p->p.channels)
    C->stale = 1;

  /* Reconfigure BGP channels */
  BGP_CF_WALK_CHANNELS(new, cc)
  {
    C = (struct channel *) bgp_find_channel(p, cc->afi);
    same = proto_configure_channel(P, &C, &cc->c) && same;
  }

  /* Reconfigure MPLS channel */
  same = proto_configure_channel(P, &P->mpls_channel, proto_cf_mpls_channel(CF)) && same;

  WALK_LIST_DELSAFE(C, C2, p->p.channels)
    if (C->stale)
      same = proto_configure_channel(P, &C, NULL) && same;

  /* Reset name counter */
  p->dynamic_name_counter = 0;

  if (!same)
    return 0;

  /* We should update our copy of configuration ptr as old configuration will be freed */
  p->cf = new;
  p->hostname = proto_get_hostname(CF);

  /* Check whether existing connections are compatible with required capabilities */
  struct bgp_conn *ci = &p->incoming_conn;
  if (((ci->state == BS_OPENCONFIRM) || (ci->state == BS_ESTABLISHED)) && !bgp_check_capabilities(ci))
    return 0;

  struct bgp_conn *co = &p->outgoing_conn;
  if (((co->state == BS_OPENCONFIRM) || (co->state == BS_ESTABLISHED)) && !bgp_check_capabilities(co))
    return 0;

  proto_setup_mpls_map(P, RTS_BGP, 1);

  if (p->start_state > BSS_PREPARE)
    bgp_update_bfd(p, new->bfd);

  if (need_if_reload)
    bgp_if_reload(p, new->ipatt);

  return 1;
}

#define TABLE(cf, NAME) ((cf)->NAME ? (cf)->NAME->table : NULL)

static int
bgp_channel_reconfigure(struct channel *C, struct channel_config *CC, int *import_changed, int *export_changed)
{
  struct bgp_proto *p = (void *) C->proto;
  struct bgp_channel *c = (void *) C;
  struct bgp_channel_config *new = (void *) CC;
  struct bgp_channel_config *old = c->cf;

  if ((new->secondary != old->secondary) ||
      (new->validate != old->validate) ||
      (new->gr_able != old->gr_able) ||
      (new->llgr_able != old->llgr_able) ||
      (new->llgr_time != old->llgr_time) ||
      (new->ext_next_hop != old->ext_next_hop) ||
      (new->add_path != old->add_path) ||
      (new->import_table != old->import_table) ||
      (new->export_table != old->export_table) ||
      (TABLE(new, igp_table_ip4) != TABLE(old, igp_table_ip4)) ||
      (TABLE(new, igp_table_ip6) != TABLE(old, igp_table_ip6)) ||
      (TABLE(new, base_table) != TABLE(old, base_table)))
    return 0;

  if (c->stale_time && ((new->min_llgr_time > c->stale_time) ||
			(new->max_llgr_time < c->stale_time)))
    return 0;

  if (new->mandatory && !old->mandatory && (C->channel_state != CS_UP))
    return 0;

  if ((new->gw_mode != old->gw_mode) ||
      (new->next_hop_prefer != old->next_hop_prefer) ||
      (new->aigp != old->aigp) ||
      (new->cost != old->cost) ||
      (new->c.preference != old->c.preference))
  {
    /* Route refresh needed, these attributes are set by BGP itself
     * and even if import table exists, we can't use it */

    /* Route refresh impossible, restart is needed */
    if ((c->c.channel_state == CS_UP) && !p->route_refresh)
      return 0;

    /* Force ROUTE_REFRESH with import table; otherwise
     * it will be forced by import_changed set to 1 later */
    if (c->c.in_table && (c->c.channel_state == CS_UP))
      bgp_schedule_packet(p->conn, c, PKT_ROUTE_REFRESH);

    /* Note that preference is already handled in channel_reconfigure(),
       but we need it handle again here for the ROUTE_REFRESH trigger */

    *import_changed = 1;
  }

  /* Outgoing next hop setting is too complex to update, forcing restart. */
  if (!ipa_equal(new->next_hop_addr, old->next_hop_addr))
    return 0;

  if ((new->next_hop_self != old->next_hop_self) ||
      (new->next_hop_keep != old->next_hop_keep) ||
      (new->llnh_format != old->llnh_format) ||
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

  c->notify_code = code;
  c->notify_subcode = subcode;
  c->notify_data = data;
  c->notify_size = (len > 0) ? len : 0;

  bgp_conn_enter_close_state(c);
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
static char *bgp_err_classes[] = { "", "Error: ", "Socket: ", "Received: ", "BGP Error: ", "Automatic shutdown: ", "" };
static char *bgp_misc_errors[] = { "", "Neighbor lost", "Invalid next hop", "Authentication failed", "No listening socket", "Link down", "BFD session down", "Graceful restart" };
static char *bgp_auto_errors[] = { "", "Route limit exceeded" };
static char *bgp_gr_states[] = { "None", "Regular", "Long-lived" };

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

const char *
bgp_format_role_name(u8 role)
{
  static const char *bgp_role_names[] = { "provider", "rs_server", "rs_client", "customer", "peer" };
  if (role == BGP_ROLE_UNDEFINED) return "undefined";
  if (role < ARRAY_SIZE(bgp_role_names)) return bgp_role_names[role];
  return "?";
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

  if (caps->role != BGP_ROLE_UNDEFINED)
    cli_msg(-1006, "      Role: %s", bgp_format_role_name(caps->role));
}

static void
bgp_show_proto_info(struct proto *P)
{
  struct bgp_proto *p = (struct bgp_proto *) P;

  cli_msg(-1006, "  BGP state:          %s", bgp_state_dsc(p));

  if (bgp_is_dynamic(p) && p->cf->remote_range)
    cli_msg(-1006, "    Neighbor range:   %N%s", p->cf->remote_range, p->cf->onlink ? " onlink" : "");
  else
    cli_msg(-1006, "    Neighbor address: %I%J%s", p->remote_ip, p->cf->iface, p->cf->onlink ? " onlink" : "");

  if ((p->conn == &p->outgoing_conn) && (p->cf->remote_port != BGP_PORT))
    cli_msg(-1006, "    Neighbor port:    %u", p->cf->remote_port);

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
    cli_msg(-1006, "    Send hold timer:  %t/%u",
	    tm_remains(p->conn->send_hold_timer), p->conn->send_hold_time);

    if (!EMPTY_LIST(p->ao.keys))
    {
      struct ao_info info;
      sk_get_ao_info(p->conn->sk, &info);

      cli_msg(-1006, "    TCP-AO:");
      cli_msg(-1006, "      Current key:    %i", info.current_key);
      cli_msg(-1006, "      RNext key:      %i", info.rnext_key);
      cli_msg(-1006, "      Good packets:   %lu", info.pkt_good);
      cli_msg(-1006, "      Bad packets:    %lu", info.pkt_bad);
    }
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

      if (c->c.channel != &channel_bgp)
	continue;

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

      /* After channel is deconfigured, these pointers are no longer valid */
      if (!p->p.reconfiguring || (c->c.channel_state != CS_DOWN))
      {
	if (c->igp_table_ip4)
	  cli_msg(-1006, "    IGP IPv4 table: %s", c->igp_table_ip4->name);

	if (c->igp_table_ip6)
	  cli_msg(-1006, "    IGP IPv6 table: %s", c->igp_table_ip6->name);

	if (c->base_table)
	  cli_msg(-1006, "    Base table:     %s", c->base_table->name);
      }
    }
  }
}

const struct channel_class channel_bgp = {
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
  .channel_mask =	NB_IP | NB_VPN | NB_FLOW | NB_MPLS,
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

void bgp_build(void)
{
  proto_build(&proto_bgp);
}
