/*
 *	BIRD -- Bidirectional Forwarding Detection (BFD)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Bidirectional Forwarding Detection
 *
 * The BFD protocol is implemented in two files: |bfd.c| containing the
 * protocol logic and the protocol glue with BIRD core, and |packets.c| handling BFD
 * packet processing, RX, TX and protocol sockets.
 *
 * The BFD implementation uses two birdloops, one standard for request pickup
 * and session state notification broadcast, and another one, low-latency,
 * to handle just the packets and timing.
 *
 * BFD sessions are represented by structure &bfd_session that contains a state
 * related to the session and two timers (TX timer for periodic packets and hold
 * timer for session timeout). These sessions are allocated from @session_slab
 * and are accessible by two hash tables, @session_hash_id (by session ID) and
 * @session_hash_ip (by IP addresses of neighbors and associated interfaces).
 * Slab and both hashes are in the main protocol structure &bfd_proto. The
 * protocol logic related to BFD sessions is implemented in internal functions
 * bfd_session_*(), which are expected to be called in the low-latency loop,
 * and external functions bfd_add_session(), bfd_remove_session() and
 * bfd_reconfigure_session(), which form an interface to the BFD core for the
 * rest and are called from the regular loop.
 *
 * Each BFD session has an associated BFD interface, represented by structure
 * &bfd_iface. A BFD interface contains a socket used for TX (the one for RX is
 * shared in &bfd_proto), an interface configuration and reference counter.
 * Compared to interface structures of other protocols, these structures are not
 * created and removed based on interface notification events, but according to
 * the needs of BFD sessions. When a new session is created, it requests a
 * proper BFD interface by function bfd_get_iface(), which either finds an
 * existing one in &iface_list (from &bfd_proto) or allocates a new one. When a
 * session is removed, an associated iface is discharged by bfd_free_iface().
 *
 * BFD requests are the external API for the other protocols. When a protocol
 * wants a BFD session, it calls bfd_request_session(), which creates a
 * structure &bfd_request containing approprite information and a notify callback.
 * Also a reference structure is allocated, which is a resource associated with
 * the caller's resource pool. Cancellation of the requests is done by freeing
 * the reference resource, the request itself is freed later to assure that
 * the low-latency routine is not activating its callback right now.
 *
 * The BFD protocols then pick up the requests, find or create appropriate BFD
 * sessions and the request is then attached to the session. When a session
 * changes state, all attached requests (and related protocols) are notified.
 *
 * Note that BFD requests do not depend on BFD protocol
 * running. When the BFD protocol is stopped or removed (or not available from
 * beginning), related BFD requests are stored in @bfd_global.pickup_list
 * where they wait for a suitable protocol to emerge.
 *
 * BFD neighbors are just a way to statically configure BFD sessions without
 * requests from another protocol. Structures &bfd_neighbor are part of BFD
 * configuration (like static routes in the static protocol). BFD neighbors are
 * handled by BFD protocol like it is a BFD client -- when a BFD neighbor is
 * ready, the protocol just creates a BFD request like any other protocol.
 *
 * Messages are passed around BFD as follows:
 * 
 * - Reconfiguration of BFD itself, as well as "show bfd" commands, are synchronous,
 *   and they directly enter the BFD context.
 * - Requests from other protocols to BFD are asynchronous; they lock the BFD
 *   global data structure and send events to the protocols to pickup possibly
 *   new requests.
 * - Notifications from BFD to other protocols are also asynchronous; they send
 *   the given callback when ready.
 * - Reconfiguration of BFD sessions based on the requests are synchronous.
 * - Notifications of session state from the session loop to the protocol loop
 *   are asynchronous, by sending an event.
 * - The session state itself is stored in an atomic structure (tiny enough to fit
 *   easily in u64) and accessed locklessly.
 * - There is a known data race in accessing the session state and last state
 *   change timestamp, which may happen to be inconsistent, yet we don't care
 *   much actually. The timestamp is there just for user information.
 *
 * There are a few other data races (e.g. accessing @p->p.debug from TRACE()
 * from the low-latency BFD loop and accessing some some private fields of
 * %bfd_session from * bfd_show_sessions() from the main thread, but these
 * should be harmless.
 *
 * TODO: document functions and access restrictions for fields in BFD structures.
 *
 * Supported standards:
 * - RFC 5880 - main BFD standard
 * - RFC 5881 - BFD for IP links
 * - RFC 5882 - generic application of BFD
 * - RFC 5883 - BFD for multihop paths
 */

#include "bfd.h"


#define HASH_ID_KEY(n)		n->loc_id
#define HASH_ID_NEXT(n)		n->next_id
#define HASH_ID_EQ(a,b)		a == b
#define HASH_ID_FN(k)		k

#define HASH_IP_KEY(n)		n->addr, n->ifindex
#define HASH_IP_NEXT(n)		n->next_ip
#define HASH_IP_EQ(a1,n1,a2,n2)	ipa_equal(a1, a2) && n1 == n2
#define HASH_IP_FN(a,n)		ipa_hash(a) ^ u32_hash(n)

#define BFD_GLOBAL_PUBLIC \
  DOMAIN(rtable) lock;	  \
  callback cleanup;	  \

struct bfd_global_private {
  BFD_GLOBAL_PUBLIC;
  pool *request_pool;
  slab *request_slab;
  struct bfd_global_private **locked_at;
  TLIST_LIST(bfd_request) pickup_list;
  TLIST_LIST(bfd_proto) proto_list;
};

static union bfd_global {
  struct { BFD_GLOBAL_PUBLIC; };
  struct bfd_global_private priv;
} bfd_global;

#define BFD_LOCKED(g)	LOBJ_LOCKED(&bfd_global, g, bfd_global, rtable)
LOBJ_UNLOCK_CLEANUP(bfd_global, rtable);

const char *bfd_state_names[] = { "AdminDown", "Down", "Init", "Up" };

const char *bfd_diag_names[] = {
  [BFD_DIAG_NOTHING] =		"None",
  [BFD_DIAG_TIMEOUT] =		"Time expired",
  [BFD_DIAG_ECHO_FAILED] =	"Echo failed",
  [BFD_DIAG_NEIGHBOR_DOWN] =	"Neighbor down",
  [BFD_DIAG_FWD_RESET] =	"Fwd plane reset",
  [BFD_DIAG_PATH_DOWN] =	"Path down",
  [BFD_DIAG_C_PATH_DOWN] =	"Concat path down",
  [BFD_DIAG_ADMIN_DOWN] =	"Admin down",
  [BFD_DIAG_RC_PATH_DOWN] =	"Rev concat path down",
};

const char *bfd_auth_names[] = {
  [BFD_AUTH_NONE] =			"None",
  [BFD_AUTH_SIMPLE] =			"Simple",
  [BFD_AUTH_KEYED_MD5] =		"Keyed MD5",
  [BFD_AUTH_METICULOUS_KEYED_MD5] =	"Meticulous keyed MD5",
  [BFD_AUTH_KEYED_SHA1] =		"Keyed SHA1",
  [BFD_AUTH_METICULOUS_KEYED_SHA1] =	"Meticulous keyed SHA1",
};

#define BFD_DIAG_BUFFER_SIZE	16

static inline const char *
bfd_diag_name(u8 id, char buf[BFD_DIAG_BUFFER_SIZE])
{
  return (id < ARRAY_SIZE(bfd_diag_names)) ?
    bfd_diag_names[id] :
    (bsprintf(buf, "Error #%u", (uint) id), buf);
}

static inline const char *
bfd_auth_name(u8 id)
{
  return (id < ARRAY_SIZE(bfd_auth_names)) ?  bfd_auth_names[id] : "?";
}

static void bfd_session_set_min_tx(struct bfd_session *s, u32 val);
static struct bfd_iface *bfd_get_iface(struct bfd_proto *p, ip_addr local, struct iface *iface);
static void bfd_free_iface(struct bfd_iface *ifa);


/*
 *	BFD sessions
 */

static inline struct bfd_options
bfd_merge_options(const struct bfd_options *bottom, const struct bfd_options *top)
{
  return (struct bfd_options) {
    .min_rx_int = top->min_rx_int ?: bottom->min_rx_int,
    .min_tx_int = top->min_tx_int ?: bottom->min_tx_int,
    .idle_tx_int = top->idle_tx_int ?: bottom->idle_tx_int,
    .multiplier = top->multiplier ?: bottom->multiplier,
    .passive = top->passive ?: bottom->passive,
    .auth_type = top->auth_type ?: bottom->auth_type,
    .passwords = top->passwords ?: bottom->passwords,
  };
}

static void
bfd_session_update_state(struct bfd_session *s, struct bfd_state_pair new)
{
  struct bfd_proto *p = s->ifa->bfd;
  struct bfd_state_pair old = atomic_load_explicit(&s->state, memory_order_relaxed);
  atomic_store_explicit(&s->state, new, memory_order_relaxed);

  if (new.loc.state == old.loc.state)
    return;

  TRACE(D_EVENTS, "Session to %I changed state from %s to %s",
	s->addr, bfd_state_names[old.loc.state], bfd_state_names[new.loc.state]);

  atomic_store_explicit(&s->last_state_change, current_time(), memory_order_relaxed);

  callback_activate(&s->notify);

  if (new.loc.state == BFD_STATE_UP)
    bfd_session_set_min_tx(s, s->cf.min_tx_int);

  if (old.loc.state == BFD_STATE_UP)
    bfd_session_set_min_tx(s, s->cf.idle_tx_int);
}

static void
bfd_session_update_tx_interval(struct bfd_session *s)
{
  u32 tx_int = MAX(s->des_min_tx_int, s->rem_min_rx_int);
  u32 tx_int_l = tx_int - (tx_int / 4);	 // 75 %
  u32 tx_int_h = tx_int - (tx_int / 10); // 90 %

  s->tx_timer->recurrent = tx_int_l;
  s->tx_timer->randomize = tx_int_h - tx_int_l;

  /* Do not set timer if no previous event */
  if (!s->last_tx)
    return;

  /* Set timer relative to last tx_timer event */
  tm_set_in(s->tx_timer, s->last_tx + tx_int_l, s->ifa->bfd->eloop);
}

static void
bfd_session_update_detection_time(struct bfd_session *s, int kick)
{
  btime timeout = (btime) MAX(s->req_min_rx_int, s->rem_min_tx_int) * s->rem_detect_mult;

  if (kick)
    s->last_rx = current_time();

  if (!s->last_rx)
    return;

  tm_set_in(s->hold_timer, s->last_rx + timeout, s->ifa->bfd->eloop);
}

static void
bfd_session_control_tx_timer(struct bfd_session *s, int reset)
{
  // if (!s->opened) goto stop;

  if (s->passive && (s->rem_id == 0))
    goto stop;

  struct bfd_state_pair sp = atomic_load_explicit(&s->state, memory_order_relaxed);

  if (s->rem_demand_mode &&
      !s->poll_active &&
      (sp.loc.state == BFD_STATE_UP) &&
      (sp.rem.state == BFD_STATE_UP))
    goto stop;

  if (s->rem_min_rx_int == 0)
    goto stop;

  /* So TX timer should run */
  if (reset || !tm_active(s->tx_timer))
  {
    s->last_tx = 0;
    tm_start_in(s->tx_timer, 0, s->ifa->bfd->eloop);
  }

  return;

stop:
  tm_stop(s->tx_timer);
  s->last_tx = 0;
}

static void
bfd_session_request_poll(struct bfd_session *s, u8 request)
{
  /* Not sure about this, but doing poll in this case does not make sense */
  if (s->rem_id == 0)
    return;

  s->poll_scheduled |= request;

  if (s->poll_active)
    return;

  s->poll_active = s->poll_scheduled;
  s->poll_scheduled = 0;

  bfd_session_control_tx_timer(s, 1);
}

static void
bfd_session_terminate_poll(struct bfd_session *s)
{
  u8 poll_done = s->poll_active & ~s->poll_scheduled;

  if (poll_done & BFD_POLL_TX)
    s->des_min_tx_int = s->des_min_tx_new;

  if (poll_done & BFD_POLL_RX)
    s->req_min_rx_int = s->req_min_rx_new;

  s->poll_active = s->poll_scheduled;
  s->poll_scheduled = 0;

  /* Timers are updated by caller - bfd_session_process_ctl() */
}

void
bfd_session_process_ctl(struct bfd_session *s, struct bfd_state_pair sp, u8 flags, u32 old_tx_int, u32 old_rx_int)
{
  ASSERT_DIE(birdloop_inside(s->ifa->bfd->eloop));

  if (s->poll_active && (flags & BFD_FLAG_FINAL))
    bfd_session_terminate_poll(s);

  if ((s->des_min_tx_int != old_tx_int) || (s->rem_min_rx_int != old_rx_int))
    bfd_session_update_tx_interval(s);

  bfd_session_update_detection_time(s, 1);

  /* Update session state */
  int orig_loc_state = sp.loc.state;
  sp.loc.state = 0;
  sp.loc.diag = BFD_DIAG_NOTHING;

  switch (orig_loc_state)
  {
  case BFD_STATE_ADMIN_DOWN:
    atomic_store_explicit(&s->state, sp, memory_order_release);
    return;

  case BFD_STATE_DOWN:
    if (sp.rem.state == BFD_STATE_DOWN)		sp.loc.state = BFD_STATE_INIT;
    else if (sp.rem.state == BFD_STATE_INIT)	sp.loc.state = BFD_STATE_UP;
    break;

  case BFD_STATE_INIT:
    if (sp.rem.state == BFD_STATE_ADMIN_DOWN)	sp.loc.state = BFD_STATE_DOWN, sp.loc.diag = BFD_DIAG_NEIGHBOR_DOWN;
    else if (sp.rem.state >= BFD_STATE_INIT)	sp.loc.state = BFD_STATE_UP;
    break;

  case BFD_STATE_UP:
    if (sp.rem.state <= BFD_STATE_DOWN)		sp.loc.state = BFD_STATE_DOWN, sp.loc.diag = BFD_DIAG_NEIGHBOR_DOWN;
    break;
  }

  if (sp.loc.state)
    bfd_session_update_state(s, sp);

  bfd_session_control_tx_timer(s, 0);

  if (flags & BFD_FLAG_POLL)
    bfd_send_ctl(s->ifa->bfd, s, 1);
}

static void
bfd_session_timeout(struct bfd_session *s)
{
  struct bfd_proto *p = s->ifa->bfd;

  TRACE(D_EVENTS, "Session to %I expired", s->addr);

  struct bfd_state_pair sp = atomic_load_explicit(&s->state, memory_order_relaxed);
  sp.rem.state = BFD_STATE_DOWN;
  sp.loc.state = BFD_STATE_DOWN;
  sp.loc.diag = BFD_DIAG_TIMEOUT;

  s->rem_id = 0;
  s->rem_min_tx_int = 0;
  s->rem_min_rx_int = 1;
  s->rem_demand_mode = 0;
  s->rem_detect_mult = 0;
  s->rx_csn_known = 0;

  s->poll_active = 0;
  s->poll_scheduled = 0;

  bfd_session_update_state(s, sp);

  bfd_session_control_tx_timer(s, 1);
}

static void
bfd_session_set_min_tx(struct bfd_session *s, u32 val)
{
  /* Note that des_min_tx_int <= des_min_tx_new */

  if (val == s->des_min_tx_new)
    return;

  s->des_min_tx_new = val;

  /* Postpone timer update if des_min_tx_int increases and the session is up */
  struct bfd_state_pair sp = atomic_load_explicit(&s->state, memory_order_relaxed);
  if ((sp.loc.state != BFD_STATE_UP) || (val < s->des_min_tx_int))
  {
    s->des_min_tx_int = val;
    bfd_session_update_tx_interval(s);
  }

  bfd_session_request_poll(s, BFD_POLL_TX);
}

static void
bfd_session_set_min_rx(struct bfd_session *s, u32 val)
{
  /* Note that req_min_rx_int >= req_min_rx_new */

  if (val == s->req_min_rx_new)
    return;

  s->req_min_rx_new = val;

  /* Postpone timer update if req_min_rx_int decreases and the session is up */
  struct bfd_state_pair sp = atomic_load_explicit(&s->state, memory_order_relaxed);
  if ((sp.loc.state != BFD_STATE_UP) || (val > s->req_min_rx_int))
  {
    s->req_min_rx_int = val;
    bfd_session_update_detection_time(s, 0);
  }

  bfd_session_request_poll(s, BFD_POLL_RX);
}

struct bfd_session *
bfd_find_session_by_id(struct bfd_proto *p, u32 id)
{
  ASSERT_DIE(birdloop_inside(p->eloop));
  return HASH_FIND(p->session_hash_id, HASH_ID, id);
}

struct bfd_session *
bfd_find_session_by_addr(struct bfd_proto *p, ip_addr addr, uint ifindex)
{
  ASSERT_DIE(birdloop_inside(p->eloop));
  return HASH_FIND(p->session_hash_ip, HASH_IP, addr, ifindex);
}

static void
bfd_notify_request(struct bfd_session *s, struct bfd_request *req)
{
  rcu_read_lock();
  callback *notify = atomic_load_explicit(&req->notify, memory_order_acquire);
  if (notify)
    callback_activate(notify);
  rcu_read_unlock();
  if (!notify)
  {
    bfd_request_rem_node(&s->request_list, req);
    BFD_LOCKED(g)
      sl_free(req);
  }
}

static void
bfd_notify_session(callback *cb)
{
  SKIP_BACK_DECLARE(struct bfd_session, s, notify, cb);

  struct bfd_proto *p = s->ifa->bfd;
  ASSERT_DIE(birdloop_inside(p->p.loop));
  ASSERT_DIE(!birdloop_inside(p->eloop));

  WALK_TLIST_DELSAFE(bfd_request, req, &s->request_list)
    bfd_notify_request(s, req);
}

static void
bfd_tx_timer_hook(timer *t)
{
  struct bfd_session *s = t->data;

  s->last_tx = current_time();
  bfd_send_ctl(s->ifa->bfd, s, 0);
}

static void
bfd_hold_timer_hook(timer *t)
{
  bfd_session_timeout(t->data);
}

static u32
bfd_get_free_id(struct bfd_proto *p)
{
  u32 id;
  for (id = random_u32(); 1; id++)
    if (id && !bfd_find_session_by_id(p, id))
      break;

  return id;
}

static struct bfd_session *
bfd_add_session(struct bfd_proto *p, ip_addr addr, ip_addr local, struct iface *iface, struct bfd_options *opts)
{
  ASSERT_DIE(birdloop_inside(p->p.loop));

  struct bfd_iface *ifa = bfd_get_iface(p, local, iface);

  struct bfd_session *s = sl_allocz(p->session_slab);
  s->addr = addr;
  s->ifa = ifa;
  s->ifindex = iface ? iface->index : 0;

  callback_init(&s->notify, bfd_notify_session, p->p.loop);

  s->cf = bfd_merge_options(&ifa->cf->opts, opts);

  atomic_store_explicit(&s->last_state_change, current_time(), memory_order_relaxed);

  s->tx_timer = tm_new_init(p->tpool, bfd_tx_timer_hook, s, 0, 0);
  s->hold_timer = tm_new_init(p->tpool, bfd_hold_timer_hook, s, 0, 0);

  /* This must be freakingly fast */
  birdloop_enter(p->eloop);

  s->loc_id = bfd_get_free_id(p);

  HASH_INSERT(p->session_hash_id, HASH_ID, s);
  HASH_INSERT(p->session_hash_ip, HASH_IP, s);

  /* Initialization of state variables - see RFC 5880 6.8.1 */
  atomic_store_explicit(&s->state, ((struct bfd_state_pair) {
      .loc = { .state = BFD_STATE_DOWN },
      .rem = { .state = BFD_STATE_DOWN },
      }), memory_order_relaxed);

  s->des_min_tx_int = s->des_min_tx_new = s->cf.idle_tx_int;
  s->req_min_rx_int = s->req_min_rx_new = s->cf.min_rx_int;
  s->rem_min_rx_int = 1;
  s->detect_mult = s->cf.multiplier;
  s->passive = s->cf.passive;
  s->tx_csn = random_u32();

  bfd_session_update_tx_interval(s);
  bfd_session_control_tx_timer(s, 1);

  /* End of the fast part */
  birdloop_leave(p->eloop);

  TRACE(D_EVENTS, "Session to %I added", s->addr);

  return s;
}

static void
bfd_remove_session_locked(struct bfd_proto *p, struct bfd_session *s)
{
  /* Caller should ensure that request list is empty */

  /* Remove session from notify list if scheduled for notification */
  /* No need for bfd_lock_sessions(), we are already protected by birdloop_enter() */
  if (NODE_VALID(&s->n))
    rem_node(&s->n);

  bfd_free_iface(s->ifa);

  rfree(s->tx_timer);
  rfree(s->hold_timer);

  callback_cancel(&s->notify);

  HASH_REMOVE(p->session_hash_id, HASH_ID, s);
  HASH_REMOVE(p->session_hash_ip, HASH_IP, s);

  TRACE(D_EVENTS, "Session to %I removed", s->addr);

  sl_free(s);
}

struct bfd_reconfigure_sessions_deferred_call {
  struct deferred_call dc;
  struct bfd_proto *p;
  config_ref old_config;
};

static void
bfd_reconfigure_sessions(struct deferred_call *dc)
{
  SKIP_BACK_DECLARE(struct bfd_reconfigure_sessions_deferred_call,
      brsdc, dc, dc);

  struct bfd_proto *p = brsdc->p;
  birdloop_enter(p->p.loop);
  birdloop_enter(p->eloop);
  
  /* Very much hoping that this is not too slow to cause significant delays. */

  HASH_WALK(p->session_hash_id, next_id, s)
  {
    if (!EMPTY_TLIST(bfd_request, &s->request_list))
    {
      struct bfd_request *req = THEAD(bfd_request, &s->request_list);
      struct bfd_options opts = bfd_merge_options(&s->ifa->cf->opts, &req->opts);

#define CHK(x)	(opts.x != s->cf.x) ||
      bool reload = MACRO_FOREACH(CHK,
	  min_rx_int,
	  min_tx_int,
	  idle_tx_int,
	  multiplier,
	  auth_type,
	  passwords,
	  passive) false; /* terminating the || chain */
#undef CHK

      s->cf = opts;

      if (reload)
      {
	struct bfd_state_pair sp = atomic_load_explicit(&s->state, memory_order_relaxed);
	u32 tx = (sp.loc.state == BFD_STATE_UP) ? s->cf.min_tx_int : s->cf.idle_tx_int;
	bfd_session_set_min_tx(s, tx);
	bfd_session_set_min_rx(s, s->cf.min_rx_int);
	s->detect_mult = s->cf.multiplier;
	s->passive = s->cf.passive;

	bfd_session_control_tx_timer(s, 0);

	TRACE(D_EVENTS, "Session to %I reconfigured", s->addr);
      }
    }
  }
  HASH_WALK_END;

  birdloop_leave(p->eloop);
  birdloop_leave(p->p.loop);

  /* Now the config is clean */
  OBSREF_CLEAR(brsdc->old_config);
}


/*
 *	BFD interfaces
 */

static struct bfd_iface_config bfd_default_iface = {
  .opts = {
    .min_rx_int = BFD_DEFAULT_MIN_RX_INT,
    .min_tx_int = BFD_DEFAULT_MIN_TX_INT,
    .idle_tx_int = BFD_DEFAULT_IDLE_TX_INT,
    .multiplier = BFD_DEFAULT_MULTIPLIER,
  },
};

static inline struct bfd_iface_config *
bfd_find_iface_config(struct bfd_config *cf, struct iface *iface)
{
  struct bfd_iface_config *ic;

  ic = iface ? (void *) iface_patt_find(&cf->patt_list, iface, NULL) : cf->multihop;

  return ic ? ic : &bfd_default_iface;
}

static struct bfd_iface *
bfd_get_iface(struct bfd_proto *p, ip_addr local, struct iface *iface)
{
  struct bfd_iface *ifa;

  WALK_LIST(ifa, p->iface_list)
    if (ipa_equal(ifa->local, local) && (ifa->iface == iface))
      return ifa->uc++, ifa;

  struct bfd_config *cf = (struct bfd_config *) (p->p.cf);
  struct bfd_iface_config *ic = bfd_find_iface_config(cf, iface);

  ifa = mb_allocz(p->tpool, sizeof(struct bfd_iface));
  ifa->local = local;
  ifa->iface = iface;
  ifa->cf = ic;
  ifa->bfd = p;

  birdloop_enter(p->eloop);
  ifa->sk = bfd_open_tx_sk(p, local, iface);
  ifa->uc = 1;

  if (cf->strict_bind)
    ifa->rx = bfd_open_rx_sk_bound(p, local, iface);
  birdloop_leave(p->eloop);

  add_tail(&p->iface_list, &ifa->n);

  return ifa;
}

static void
bfd_free_iface(struct bfd_iface *ifa)
{
  ASSERT_DIE(birdloop_inside(ifa->bfd->eloop));
  if (!ifa || --ifa->uc)
    return;

  if (ifa->sk)
    sk_close(ifa->sk);

  if (ifa->rx)
    sk_close(ifa->rx);

  rem_node(&ifa->n);
  mb_free(ifa);
}


/*
 *	BFD requests
 */

void
bfd_request_update_state(struct bfd_request *req)
{
  req->old = req->cur;

  rcu_read_lock();

  struct bfd_session *s = atomic_load_explicit(&req->session, memory_order_acquire);
  if (s)
    req->cur = atomic_load_explicit(&s->state, memory_order_acquire);
  else
    req->cur = (struct bfd_state_pair) {};

  rcu_read_unlock();

  req->down =
       (req->old.loc.state == BFD_STATE_UP)
    && (req->cur.loc.state == BFD_STATE_DOWN)
    && (req->cur.rem.state != BFD_STATE_ADMIN_DOWN);
}

static struct bfd_request *
bfd_pick_request(struct bfd_proto *p)
{
  BFD_LOCKED(g)
    WALK_TLIST(bfd_request, req, &g->pickup_list)
    {
      SKIP_BACK_DECLARE(struct bfd_config, cf, c, p->p.cf);
      if (p->p.vrf && (p->p.vrf != req->vrf))
      {
	TRACE(D_EVENTS, "Not accepting request to %I with different VRF", req->addr);
	continue;
      }

      if (ipa_is_ip4(req->addr) ? !cf->accept_ipv4 : !cf->accept_ipv6)
      {
	TRACE(D_EVENTS, "Not accepting request to %I (AF limit)", req->addr);
	continue;
      }

      if (req->iface ? !cf->accept_direct : !cf->accept_multihop)
      {
	TRACE(D_EVENTS, "Not accepting %s request to %I", req->iface ? "direct" : "multihop", req->addr);
	continue;
      }

      bfd_request_rem_node(&g->pickup_list, req);
      return req;
    }

  return NULL;
}

static void
bfd_add_request(struct bfd_proto *p, struct bfd_request *req)
{
  uint ifindex = req->iface ? req->iface->index : 0;

  birdloop_enter(p->eloop);
  struct bfd_session *s = bfd_find_session_by_addr(p, req->addr, ifindex);
  birdloop_leave(p->eloop);

  if (s)
    TRACE(D_EVENTS, "Session to %I reused", s->addr);
  else
    s = bfd_add_session(p, req->addr, req->local, req->iface, &req->opts);

  /* Register the request in the session */
  bfd_request_add_tail(&s->request_list, req);
  atomic_store_explicit(&req->session, s, memory_order_release);

  /* Inform the requestor */
  bfd_notify_request(s, req);
}

static void
bfd_pickup_requests(callback *cb)
{
  SKIP_BACK_DECLARE(struct bfd_proto, p, pickup, cb);
  for (
      struct bfd_request *req;
      req = bfd_pick_request(p);
      )
    bfd_add_request(p, req);
}

static void
bfd_cleanup_requests(callback *cb)
{
  SKIP_BACK_DECLARE(struct bfd_proto, p, cleanup, cb);

  ASSERT_DIE(p->p.proto_state == PS_UP);

  birdloop_enter(p->eloop);
  HASH_WALK_DELSAFE(p->session_hash_id, next_id, s)
  {
    WALK_TLIST_DELSAFE(bfd_request, req, &s->request_list)
      if (!atomic_load_explicit(&req->notify, memory_order_acquire))
      {
	bfd_request_rem_node(&s->request_list, req);
	BFD_LOCKED(g)
	  sl_free(req);
      }

    if (EMPTY_TLIST(bfd_request, &s->request_list))
      bfd_remove_session_locked(p, s);
  }
  HASH_WALK_END;
  birdloop_leave(p->eloop);
}

static void
bfd_drop_requests(struct bfd_proto *p)
{
  birdloop_enter(p->eloop);
  HASH_WALK_DELSAFE(p->session_hash_id, next_id, s)
  {
    WALK_TLIST_DELSAFE(bfd_request, req, &s->request_list)
    {
      bfd_request_rem_node(&s->request_list, req);
      atomic_store_explicit(&req->session, NULL, memory_order_release);
      BFD_LOCKED(g)
	bfd_request_add_tail(&g->pickup_list, req);
    }
  }
  HASH_WALK_END;

  synchronize_rcu();
  HASH_WALK_DELSAFE(p->session_hash_id, next_id, s)
    bfd_remove_session_locked(p, s);
  HASH_WALK_END;

  birdloop_leave(p->eloop);

  BFD_LOCKED(g)
    WALK_TLIST(bfd_proto, p, &g->proto_list)
      callback_activate(&p->pickup);
}

static void
bfd_request_ref_free(resource *r)
{
  struct bfd_request *req = SKIP_BACK(struct bfd_request_ref, r, r)->req;
  
  callback *cb = atomic_exchange_explicit(&req->notify, NULL, memory_order_release);
  synchronize_rcu();

  /* Now if anybody wanted to activate the callback, they did it
   * and the cancellation won't race. */
  callback_cancel(cb);

  /* Request global BFD cleanup. We can't reliably detect where the request
   * ended up, so we rather ping all. */
  callback_activate(&bfd_global.cleanup);
}

static void
bfd_request_ref_dump(struct dump_request *dreq, resource *r)
{
  struct bfd_request *req = SKIP_BACK(struct bfd_request_ref, r, r)->req;

  rcu_read_lock();
  struct bfd_session *s = atomic_load_explicit(&req->session, memory_order_acquire);
  RDUMP("addr=%I local=%I iface=%s vrf=%s notify=%p session=%p",
      req->addr, req->local,
      req->iface ? req->iface->name : "(none)",
      req->vrf ? req->vrf->name : "(none)",
      atomic_load_explicit(&req->notify, memory_order_relaxed),
      s);

  if (s)
  {
    struct bfd_state_pair sp = atomic_load_explicit(&s->state, memory_order_relaxed);
    btime last_update = atomic_load_explicit(&s->last_state_change, memory_order_relaxed);
    RDUMP("state=(loc %u d%u rem %u d%u) changed=%t\n", 
	sp.loc.state, sp.loc.diag, sp.rem.state, sp.rem.diag,
	last_update);
  }
  else
    RDUMP("\n");

  rcu_read_unlock();
}

static struct resclass bfd_request_ref_class = {
  .name = "BFD request reference",
  .size = sizeof(struct bfd_request_ref),
  .free = bfd_request_ref_free,
  .dump = bfd_request_ref_dump,
};

struct bfd_request_ref *
bfd_request_session(pool *p, ip_addr addr, ip_addr local,
		    struct iface *iface, struct iface *vrf,
		    callback *notify,
		    const struct bfd_options *opts)
{
  struct bfd_request *req;

  BFD_LOCKED(g)
    req = sl_allocz(g->request_slab);

  req->addr = addr;
  req->local = local;
  req->iface = iface;
  req->vrf = vrf;

  if (opts)
    req->opts = *opts;

  ASSERT_DIE(notify);
  atomic_store_explicit(&req->notify, notify, memory_order_relaxed);
  atomic_store_explicit(&req->session, NULL, memory_order_relaxed);

  BFD_LOCKED(g)
  {
    bfd_request_add_tail(&g->pickup_list, req);
    WALK_TLIST(bfd_proto, p, &g->proto_list)
      callback_activate(&p->pickup);
  }

  struct bfd_request_ref *rr = ralloc(p, &bfd_request_ref_class);
  rr->req = req;
  return rr;
}

void
bfd_update_request(struct bfd_request_ref *rr, const struct bfd_options *opts)
{
  rr->req->opts = *opts;
}

static void
bfd_cleanup_unpicked_requests(callback *cb)
{
  ASSERT_DIE(cb == &bfd_global.cleanup);
  BFD_LOCKED(g)
  {
    WALK_TLIST_DELSAFE(bfd_request, req, &g->pickup_list)
      if (!atomic_load_explicit(&req->notify, memory_order_acquire))
      {
	bfd_request_rem_node(&g->pickup_list, req);
	sl_free(req);
      }

    WALK_TLIST_DELSAFE(bfd_proto, p, &g->proto_list)
      callback_activate(&p->cleanup);
  }
}


/*
 *	BFD neighbors
 */

static void
bfd_neigh_notify(struct neighbor *nb)
{
  struct bfd_proto *p = (struct bfd_proto *) nb->proto;
  struct bfd_neighbor *n = nb->data;

  if (!n)
    return;

  if ((nb->scope > 0) && !n->req)
  {
    ip_addr local = ipa_nonzero(n->local) ? n->local : nb->ifa->ip;
    n->req = bfd_request_session(p->p.pool, n->addr, local, nb->iface, p->p.vrf, &n->notify, NULL);
  }

  if ((nb->scope <= 0) && n->req)
  {
    rfree(n->req);
    n->req = NULL;
  }
}

static void
bfd_start_neighbor(struct bfd_proto *p, struct bfd_neighbor *n)
{
  n->active = 1;

  if (n->multihop)
  {
    n->req = bfd_request_session(p->p.pool, n->addr, n->local, NULL, p->p.vrf, &n->notify, NULL);
    return;
  }

  struct neighbor *nb = neigh_find(&p->p, n->addr, n->iface, NEF_STICKY);
  if (!nb)
  {
    log(L_ERR "%s: Invalid remote address %I%J", p->p.name, n->addr, n->iface);
    return;
  }

  if (nb->data)
  {
    log(L_ERR "%s: Duplicate neighbor %I", p->p.name, n->addr);
    return;
  }

  neigh_link(nb);

  n->neigh = nb;
  nb->data = n;

  if (nb->scope > 0)
    bfd_neigh_notify(nb);
  else
    TRACE(D_EVENTS, "Waiting for %I%J to become my neighbor", n->addr, n->iface);
}

static void
bfd_stop_neighbor(struct bfd_proto *p UNUSED, struct bfd_neighbor *n)
{
  if (n->neigh)
  {
    n->neigh->data = NULL;
    neigh_unlink(n->neigh);
    n->neigh = NULL;
  }

  rfree(n->req);
  n->req = NULL;
}

void
bfd_neighbor_notify(callback *cb UNUSED)
{
  // SKIP_BACK_DECLARE(struct bfd_neighbor, n, bfd_notify, cb);
  // bfd_request_update_state(n->req->req);
  /* This may, in future, push the changed BFD state to our API.
   * We don't have any API yet, tho. Time to make some? */
}

static inline int
bfd_same_neighbor(struct bfd_neighbor *x, struct bfd_neighbor *y)
{
  return ipa_equal(x->addr, y->addr) && ipa_equal(x->local, y->local) &&
    (x->iface == y->iface) && (x->multihop == y->multihop);
}

static void
bfd_reconfigure_neighbors(struct bfd_proto *p, struct bfd_config *new)
{
  struct bfd_config *old = (struct bfd_config *) (p->p.cf);

  WALK_TLIST(bfd_neighbor, on, &old->neigh_list)
  {
    WALK_TLIST(bfd_neighbor, nn, &new->neigh_list)
      if (bfd_same_neighbor(nn, on))
      {
	nn->neigh = on->neigh;
	if (nn->neigh)
	  nn->neigh->data = nn;

	nn->req = on->req;
	nn->active = 1;
	goto next;
      }

    bfd_stop_neighbor(p, on);
  next:;
  }

  WALK_TLIST(bfd_neighbor, nn, &new->neigh_list)
    if (!nn->active)
      bfd_start_neighbor(p, nn);
}


/*
 *	BFD protocol glue
 */

static struct proto *
bfd_init(struct proto_config *c)
{
  struct proto *p = proto_new(c);

  p->iface_sub.neigh_notify = bfd_neigh_notify;

  return p;
}

static int
bfd_start(struct proto *P)
{
  struct bfd_proto *p = (struct bfd_proto *) P;
  struct bfd_config *cf = (struct bfd_config *) (P->cf);

  p->tpool = birdloop_pool(P->loop);
  p->eloop = birdloop_new(P->pool, DOMAIN_ORDER(service), cf->express_thread_group->group, "BFD Express %s", P->name);

  p->session_slab = sl_new(P->pool, birdloop_event_list(P->loop), sizeof(struct bfd_session));
  HASH_INIT(p->session_hash_id, P->pool, 8);
  HASH_INIT(p->session_hash_ip, P->pool, 8);

  init_list(&p->iface_list);

  callback_init(&p->pickup, bfd_pickup_requests, P->loop);
  callback_init(&p->cleanup, bfd_cleanup_requests, P->loop);

  BFD_LOCKED(g)
    bfd_proto_add_tail(&g->proto_list, p);

  if (!cf->strict_bind)
  {
    birdloop_enter(p->eloop);
    if (cf->accept_ipv4 && cf->accept_direct)
      p->rx4_1 = bfd_open_rx_sk(p, 0, SK_IPV4);

    if (cf->accept_ipv4 && cf->accept_multihop)
      p->rx4_m = bfd_open_rx_sk(p, 1, SK_IPV4);

    if (cf->accept_ipv6 && cf->accept_direct)
      p->rx6_1 = bfd_open_rx_sk(p, 0, SK_IPV6);

    if (cf->accept_ipv6 && cf->accept_multihop)
      p->rx6_m = bfd_open_rx_sk(p, 1, SK_IPV6);
    birdloop_leave(p->eloop);
  }

  callback_activate(&p->pickup);

  WALK_TLIST(bfd_neighbor, n, &cf->neigh_list)
    bfd_start_neighbor(p, n);

  return PS_UP;
}

static void
bfd_cleanup_eloop(void *_p)
{
  struct bfd_proto *p = _p;

  birdloop_enter(p->p.loop);
  birdloop_free(p->eloop);
  proto_notify_state(&p->p, PS_FLUSH);
  birdloop_leave(p->p.loop);
}

static int
bfd_shutdown(struct proto *P)
{
  struct bfd_proto *p = (struct bfd_proto *) P;
  struct bfd_config *cf = (struct bfd_config *) (p->p.cf);

  BFD_LOCKED(g)
    bfd_proto_rem_node(&g->proto_list, p);

  callback_cancel(&p->cleanup);
  callback_cancel(&p->pickup);

  WALK_TLIST(bfd_neighbor, bn, &cf->neigh_list)
    bfd_stop_neighbor(p, bn);

  bfd_drop_requests(p);
  birdloop_stop(p->eloop, bfd_cleanup_eloop, p);

  return PS_STOP;
}

static int
bfd_reconfigure(struct proto *P, struct proto_config *c)
{
  struct bfd_proto *p = (struct bfd_proto *) P;
  struct bfd_config *old = (struct bfd_config *) (P->cf);
  struct bfd_config *new = (struct bfd_config *) c;
  struct bfd_iface *ifa;

  /* TODO: Improve accept reconfiguration */
  if ((new->accept_ipv4 != old->accept_ipv4) ||
      (new->accept_ipv6 != old->accept_ipv6) ||
      (new->accept_direct != old->accept_direct) ||
      (new->accept_multihop != old->accept_multihop) ||
      (new->strict_bind != old->strict_bind) ||
      (new->zero_udp6_checksum_rx != old->zero_udp6_checksum_rx))
    return 0;

  WALK_LIST(ifa, p->iface_list)
    ifa->cf = bfd_find_iface_config(new, ifa->iface);

  bfd_reconfigure_neighbors(p, new);

  /* Sessions get reconfigured after all the config is applied */
  struct bfd_reconfigure_sessions_deferred_call brsdc = {
    .dc.hook = bfd_reconfigure_sessions,
    .p = p,
  };
  SKIP_BACK_DECLARE(struct bfd_reconfigure_sessions_deferred_call,
      brsdcp, dc, defer_call(&brsdc.dc, sizeof brsdc));

  /* We need to keep the old config alive until all the sessions get
   * reconfigured */
  OBSREF_SET(brsdcp->old_config, P->cf->global);

  return 1;
}

static void
bfd_copy_config(struct proto_config *dest, struct proto_config *src UNUSED)
{
  struct bfd_config *d = (struct bfd_config *) dest;
  // struct bfd_config *s = (struct bfd_config *) src;

  /* We clean up patt_list and neigh_list, neighbors and ifaces are non-sharable */
  init_list(&d->patt_list);
  d->neigh_list = (TLIST_LIST(bfd_neighbor)) {};
}

void
bfd_show_session(struct bfd_session *s, int details)
{
  struct bfd_state_pair sp = atomic_load_explicit(&s->state, memory_order_relaxed);
  uint loc_id = s->loc_id;
  uint rem_id = s->rem_id;

  const char *ifname = (s->ifa && s->ifa->iface) ? s->ifa->iface->name : "---";
  btime tx_int = s->last_tx ? MAX(s->des_min_tx_int, s->rem_min_rx_int) : 0;
  btime timeout = (btime) MAX(s->req_min_rx_int, s->rem_min_tx_int) * s->rem_detect_mult;
  u8 auth_type = s->cf.auth_type;

  sp.loc.state = (sp.loc.state < 4) ? sp.loc.state : 0;
  sp.rem.state = (sp.rem.state < 4) ? sp.rem.state : 0;

  byte dbuf[BFD_DIAG_BUFFER_SIZE];
  byte tbuf[TM_DATETIME_BUFFER_SIZE];

  rcu_read_lock();
  struct global_runtime *gr = atomic_load_explicit(&global_runtime, memory_order_relaxed);
  tm_format_time(tbuf, this_cli->tf ?: &gr->tf_proto,
      atomic_load_explicit(&s->last_state_change, memory_order_relaxed));
  rcu_read_unlock();

  if (!details)
  {
    cli_msg(-1020, "%-25I %-10s %-10s %-12s  %7t  %7t",
	    s->addr, ifname, bfd_state_names[sp.loc.state], tbuf, tx_int, timeout);

    return;
  }

  cli_msg(-1020, "  %-21s %I", "Address:", s->addr);
  cli_msg(-1020, "  %-21s %s", "Interface:", ifname);
  cli_msg(-1020, "  %-21s %s", "Session type:", s->ifa->iface ? "Direct" : "Multihop");
  cli_msg(-1020, "  %-21s %s", "Session state:", bfd_state_names[sp.loc.state]);
  cli_msg(-1020, "  %-21s %s", "Remote state:", bfd_state_names[sp.rem.state]);
  cli_msg(-1020, "  %-21s %s", "Last state change:", tbuf);
  cli_msg(-1020, "  %-21s %s", "Local diagnostic:", bfd_diag_name(sp.loc.diag, dbuf));
  cli_msg(-1020, "  %-21s %s", "Remote diagnostic:", bfd_diag_name(sp.rem.diag, dbuf));
  cli_msg(-1020, "  %-21s %u", "Local discriminator:", loc_id);
  cli_msg(-1020, "  %-21s %u", "Remote discriminator:", rem_id);

  if (tm_active(s->tx_timer))
    cli_msg(-1020, "  %-21s %t / %t", "Transmit timer:", tm_remains(s->tx_timer), tx_int);

  if (tm_active(s->hold_timer))
    cli_msg(-1020, "  %-21s %t / %t", "Detect timer:", tm_remains(s->hold_timer), timeout);

  cli_msg(-1020, "  Local parameters:");
  cli_msg(-1020, "    %-19s %t", "Min TX interval:", (btime) s->des_min_tx_int);
  cli_msg(-1020, "    %-19s %t", "Min RX interval:", (btime) s->req_min_rx_int);
  cli_msg(-1020, "    %-19s %s", "Demand mode:", s->demand_mode ? "Yes" : "No");
  cli_msg(-1020, "    %-19s %i", "Multiplier:", s->detect_mult);
  cli_msg(-1020, "  Remote parameters:");
  cli_msg(-1020, "    %-19s %t", "Min TX interval:", (btime) s->rem_min_tx_int);
  cli_msg(-1020, "    %-19s %t", "Min RX interval:", (btime) s->rem_min_rx_int);
  cli_msg(-1020, "    %-19s %s", "Demand mode:", s->rem_demand_mode ? "Yes" : "No");
  cli_msg(-1020, "    %-19s %i", "Multiplier:", s->rem_detect_mult);

  if (auth_type)
  {
    cli_msg(-1020, "  Authentication:");
    cli_msg(-1020, "    %-19s %s", "Type:", bfd_auth_name(auth_type));

    if (s->rx_csn_known)
      cli_msg(-1020, "    %-19s %u", "RX CSN:", s->rx_csn);

    if (auth_type > BFD_AUTH_SIMPLE)
      cli_msg(-1020, "    %-19s %u", "TX CSN:", s->tx_csn);
  }

  cli_msg(-1020, "");
}

void
bfd_show_sessions(struct proto *P, struct bfd_show_sessions_cmd *args)
{
  struct bfd_proto *p = (struct bfd_proto *) P;

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1020, "%s: is not up", p->p.name);
    return;
  }

  cli_msg(-1020, "%s:", p->p.name);
  if (!args->verbose)
    cli_msg(-1020, "%-25s %-10s %-10s %-12s  %8s %8s",
	  "IP address", "Interface", "State", "Since", "Interval", "Timeout");

  HASH_WALK(p->session_hash_id, next_id, s)
  {
    if (args->address.type && !ipa_in_netX(s->addr, &args->address))
      continue;

    if (args->iface && (s->ifa->iface != args->iface))
      continue;

    if (ipa_is_ip4(s->addr) ? args->ipv6 :  args->ipv4)
      continue;

    if (s->ifa->iface ? args->multihop : args->direct)
      continue;

    bfd_show_session(s, args->verbose);
  }
  HASH_WALK_END;
}


struct protocol proto_bfd = {
  .name =		"BFD",
  .template =		"bfd%d",
  .proto_size =		sizeof(struct bfd_proto),
  .config_size =	sizeof(struct bfd_config),
  .init =		bfd_init,
  .start =		bfd_start,
  .shutdown =		bfd_shutdown,
  .reconfigure =	bfd_reconfigure,
  .copy_config =	bfd_copy_config,
};

void
bfd_build(void)
{
  proto_build(&proto_bfd);

  callback_init(&bfd_global.cleanup, bfd_cleanup_unpicked_requests, &main_birdloop);

  bfd_global.lock = DOMAIN_NEW(rtable);
  DOMAIN_SETUP(rtable, bfd_global.lock, "BFD Global", NULL);

  BFD_LOCKED(g)
  {
    g->request_pool = rp_new(&root_pool, g->lock.rtable, "BFD Global");
    g->request_slab = sl_new(g->request_pool, &global_event_list, sizeof(struct bfd_request));
  }
}
