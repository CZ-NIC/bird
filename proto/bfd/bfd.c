/*
 *	BIRD -- Bidirectional Forwarding Detection (BFD)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "bfd.h"


#define HASH_ID_KEY(n)		n->loc_id
#define HASH_ID_NEXT(n)		n->next_id
#define HASH_ID_EQ(a,b)		(a == b)
#define HASH_ID_FN(k)		(k)

#define HASH_IP_KEY(n)		n->addr
#define HASH_IP_NEXT(n)		n->next_ip
#define HASH_IP_EQ(a,b)		ipa_equal(a,b)
#define HASH_IP_FN(k)		ipa_hash(k)

static inline void bfd_notify_kick(struct bfd_proto *p);

static void 
bfd_session_update_state(struct bfd_session *s, uint state, uint diag)
{
  struct bfd_proto *p = s->bfd;
  int notify;

  if (s->loc_state == state)
    return;

  //TRACE(D_EVENTS, "Session changed %I %d %d", s->addr, state, diag);
  debug("STATE %I %d %d %d\n", s->addr, s->loc_state, state, diag);
    
  bfd_lock_sessions(p);
  s->loc_state = state;
  s->loc_diag = diag;

  notify = !NODE_VALID(&s->n);
  if (notify)
    add_tail(&p->notify_list, &s->n);
  bfd_unlock_sessions(p);

  if (notify)
    bfd_notify_kick(p);
}

static void 
bfd_session_timeout(struct bfd_session *s)
{
  s->rem_state = BFD_STATE_DOWN;
  s->rem_id = 0;
  s->rem_min_tx_int = 0;
  s->rem_min_rx_int = 1;
  s->rem_demand_mode = 0;
  s->rem_detect_mult = 0;

  bfd_session_update_state(s, BFD_STATE_DOWN, BFD_DIAG_TIMEOUT);
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
  tm2_set(s->tx_timer, s->last_tx + tx_int_l);
}

static void
bfd_session_update_detection_time(struct bfd_session *s, int kick)
{
  btime timeout = (btime) MAX(s->req_min_rx_int, s->rem_min_tx_int) * s->rem_detect_mult;

  if (kick)
    s->last_rx = current_time();

  if (!s->last_rx)
    return;

  tm2_set(s->hold_timer, s->last_rx + timeout);
}

static void
bfd_session_control_tx_timer(struct bfd_session *s)
{
  if (!s->opened)
    goto stop;

  if (s->passive && (s->rem_id == 0))
    goto stop;

  if (s->rem_demand_mode && 
      !s->poll_active && 
      (s->loc_state == BFD_STATE_UP) &&
      (s->rem_state == BFD_STATE_UP))
    goto stop;

  if (s->rem_min_rx_int == 0)
    goto stop;

  /* So TX timer should run */
  if (tm2_active(s->tx_timer))
    return;

  tm2_start(s->tx_timer, 0);
  return;

 stop:
  tm2_stop(s->tx_timer);
  s->last_tx = 0;
}

static void
bfd_session_request_poll(struct bfd_session *s, u8 request)
{
  s->poll_scheduled |= request;

  if (s->poll_active)
    return;

  s->poll_active = s->poll_scheduled;
  s->poll_scheduled = 0;
  bfd_send_ctl(s->bfd, s, 0);
}

static void
bfd_session_terminate_poll(struct bfd_session *s)
{
  u8 poll_done = s->poll_active & ~s->poll_scheduled;

  if (poll_done & BFD_POLL_TX)
    s->des_min_tx_int = s->des_min_tx_new;

  if (poll_done & BFD_POLL_RX)
    s->req_min_rx_int = s->req_min_rx_new;

  s->poll_active = 0;

  /* Timers are updated by caller - bfd_session_process_ctl() */

  // xxx_restart_poll();
}

void
bfd_session_process_ctl(struct bfd_session *s, u8 flags, u32 old_tx_int, u32 old_rx_int)
{
  if (s->poll_active && (flags & BFD_FLAG_FINAL))
    bfd_session_terminate_poll(s);

  if ((s->des_min_tx_int != old_tx_int) || (s->rem_min_rx_int != old_rx_int))
    bfd_session_update_tx_interval(s);

  bfd_session_update_detection_time(s, 1);

  /* Update session state */
  int next_state = 0;
  int diag = BFD_DIAG_NOTHING;

  switch (s->loc_state)
  {
  case BFD_STATE_ADMIN_DOWN:
    return;

  case BFD_STATE_DOWN:
    if (s->rem_state == BFD_STATE_DOWN)		next_state = BFD_STATE_INIT;
    else if (s->rem_state == BFD_STATE_INIT)	next_state = BFD_STATE_UP;
    break;

  case BFD_STATE_INIT:
    if (s->rem_state == BFD_STATE_ADMIN_DOWN)	next_state = BFD_STATE_DOWN, diag = BFD_DIAG_NEIGHBOR_DOWN;
    else if (s->rem_state >= BFD_STATE_INIT)	next_state = BFD_STATE_UP;
    break;

  case BFD_STATE_UP:
    if (s->rem_state <= BFD_STATE_DOWN)		next_state = BFD_STATE_DOWN, diag = BFD_DIAG_NEIGHBOR_DOWN;
    break;
  }

  if (next_state)
    bfd_session_update_state(s, next_state, diag);

  bfd_session_control_tx_timer(s);

  if (flags & BFD_FLAG_POLL)
    bfd_send_ctl(s->bfd, s, 1);
}

static void
bfd_session_set_min_tx(struct bfd_session *s, u32 val)
{
  /* Note that des_min_tx_int <= des_min_tx_new */

  if (val == s->des_min_tx_new)
    return;

  s->des_min_tx_new = val;

  /* Postpone timer update if des_min_tx_int increases and the session is up */
  if ((s->loc_state != BFD_STATE_UP) || (val < s->des_min_tx_int))
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
  if ((s->loc_state != BFD_STATE_UP) || (val > s->req_min_rx_int))
  {
    s->req_min_rx_int = val;
    bfd_session_update_detection_time(s, 0);
  }

  bfd_session_request_poll(s, BFD_POLL_RX);
}

struct bfd_session *
bfd_find_session_by_id(struct bfd_proto *p, u32 id)
{
  return HASH_FIND(p->session_hash_id, HASH_ID, id);
}

struct bfd_session *
bfd_find_session_by_addr(struct bfd_proto *p, ip_addr addr)
{
  return HASH_FIND(p->session_hash_ip, HASH_IP, addr);
}

static void
bfd_tx_timer_hook(timer2 *t)
{
  struct bfd_session *s = t->data;

  s->last_tx = current_time();
  //  debug("TX %d\n", (s32)  (s->last_tx TO_MS));
  bfd_send_ctl(s->bfd, s, 0);
}

static void
bfd_hold_timer_hook(timer2 *t)
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
bfd_add_session(struct bfd_proto *p, ip_addr addr, struct bfd_session_config *opts)
{
  birdloop_enter(p->loop);

  struct bfd_session *s = sl_alloc(p->session_slab);
  bzero(s, sizeof(struct bfd_session));

  s->addr = addr;
  s->loc_id = bfd_get_free_id(p);
  debug("XXX INS1 %d %d %u %I\n", p->session_hash_id.count,  p->session_hash_ip.count, s->loc_id, s->addr);
  HASH_INSERT(p->session_hash_id, HASH_ID, s);
  debug("XXX INS2 %d %d\n", p->session_hash_id.count,  p->session_hash_ip.count);
  HASH_INSERT(p->session_hash_ip, HASH_IP, s);
  debug("XXX INS3 %d %d\n", p->session_hash_id.count,  p->session_hash_ip.count);
  s->bfd = p;

  /* Initialization of state variables - see RFC 5880 6.8.1 */
  s->loc_state = BFD_STATE_DOWN;
  s->rem_state = BFD_STATE_DOWN;
  s->des_min_tx_int = s->des_min_tx_new = opts->min_tx_int; // XXX  opts->idle_tx_int;
  s->req_min_rx_int = s->req_min_rx_new = opts->min_rx_int;
  s->rem_min_rx_int = 1;
  s->detect_mult = opts->multiplier;
  s->passive = opts->passive;

  s->tx_timer = tm2_new_init(p->tpool, bfd_tx_timer_hook, s, 0, 0);
  s->hold_timer = tm2_new_init(p->tpool, bfd_hold_timer_hook, s, 0, 0);
  bfd_session_update_tx_interval(s);

  birdloop_leave(p->loop);

  return s;
}

static void
bfd_open_session(struct bfd_proto *p, struct bfd_session *s, ip_addr local, struct iface *ifa)
{
  birdloop_enter(p->loop);

  s->bsock = bfd_get_socket(p, local, ifa);
  // s->local = local;
  // s->iface = ifa;
  s->opened = 1;

  bfd_session_control_tx_timer(s);

  birdloop_leave(p->loop);
}

static void
bfd_close_session(struct bfd_proto *p, struct bfd_session *s)
{
  birdloop_enter(p->loop);

  bfd_free_socket(s->bsock);
  s->bsock = NULL;
  // s->local = IPA_NONE;
  // s->iface = NULL;
  s->opened = 0;

  bfd_session_update_state(s, BFD_STATE_DOWN, BFD_DIAG_PATH_DOWN);
  bfd_session_control_tx_timer(s);

  birdloop_leave(p->loop);
}

static void
bfd_remove_session(struct bfd_proto *p, struct bfd_session *s)
{
  birdloop_enter(p->loop);

  bfd_free_socket(s->bsock);

  rfree(s->tx_timer);
  rfree(s->hold_timer);

  debug("XXX REM1 %d %d %u %I\n", p->session_hash_id.count,  p->session_hash_ip.count, s->loc_id, s->addr);
  HASH_REMOVE(p->session_hash_id, HASH_ID, s);
  debug("XXX REM2 %d %d\n", p->session_hash_id.count,  p->session_hash_ip.count);
  HASH_REMOVE(p->session_hash_ip, HASH_IP, s);
  debug("XXX REM3 %d %d\n", p->session_hash_id.count,  p->session_hash_ip.count);

  sl_free(p->session_slab, s);

  birdloop_leave(p->loop);
}

static void
bfd_configure_session(struct bfd_proto *p, struct bfd_session *s,
		      struct bfd_session_config *opts)
{
  birdloop_enter(p->loop);

 // XXX  opts->idle_tx_int;

  bfd_session_set_min_tx(s, opts->min_tx_int);
  bfd_session_set_min_rx(s, opts->min_rx_int);
  s->detect_mult = opts->multiplier;
  s->passive = opts->passive;

  bfd_session_control_tx_timer(s);

  birdloop_leave(p->loop);
}

static void
bfd_start_neighbor(struct bfd_proto *p, struct bfd_neighbor *n)
{
  n->session = bfd_add_session(p, n->addr, n->opts);

  if (n->opts->multihop)
  {
    bfd_open_session(p, n->session, n->local, NULL);
    return;
  }

  struct neighbor *nb = neigh_find2(&p->p, &n->addr, n->iface, NEF_STICKY);
  if (!nb)
  {
    log(L_ERR "%s: Invalid remote address %I%J", p->p.name, n->addr, n->iface);
    return;
  }

  if (nb->data)
  {
    log(L_ERR "%s: Duplicate remote address %I", p->p.name, n->addr);
    return;
  }

  nb->data = n->session;

  if (nb->scope > 0)
    bfd_open_session(p, n->session, nb->iface->addr->ip, nb->iface);
  else
    TRACE(D_EVENTS, "Waiting for %I%J to become my neighbor", n->addr, n->iface);
}

static void
bfd_stop_neighbor(struct bfd_proto *p, struct bfd_neighbor *n)
{
  if (!n->opts->multihop)
  {
    struct neighbor *nb = neigh_find2(&p->p, &n->addr, n->iface, 0);
    if (nb)
      nb->data = NULL;
  }

  bfd_remove_session(p, n->session);
}

static void
bfd_neigh_notify(struct neighbor *nb)
{
  struct bfd_proto *p = (struct bfd_proto *) nb->proto;
  struct bfd_session *s = nb->data;

  if (!s)
    return;

  if ((nb->scope > 0) && !s->opened)
    bfd_open_session(p, s, nb->iface->addr->ip, nb->iface);

  if ((nb->scope <= 0) && s->opened)
    bfd_close_session(p, s);
}


/* This core notify code should be replaced after main loop transition to birdloop */

int pipe(int pipefd[2]);
void pipe_drain(int fd);
void pipe_kick(int fd);

static int
bfd_notify_hook(sock *sk, int len)
{
  struct bfd_proto *p = sk->data;
  struct bfd_session *s;
  list tmp_list;

  pipe_drain(sk->fd);

  bfd_lock_sessions(p);
  init_list(&tmp_list);
  add_tail_list(&tmp_list, &p->notify_list);
  init_list(&p->notify_list);
  bfd_unlock_sessions(p);

  WALK_LIST_FIRST(s, tmp_list)
  {
    bfd_lock_sessions(p);
    rem2_node(&s->n);
    bfd_unlock_sessions(p);

    // XXX do something
    TRACE(D_EVENTS, "Notify: session changed %I %d %d", s->addr, s->loc_state, s->loc_diag);
  }

  return 0;
}

static inline void
bfd_notify_kick(struct bfd_proto *p)
{
  pipe_kick(p->notify_ws->fd);
}

static void
bfd_noterr_hook(sock *sk, int err)
{
  struct bfd_proto *p = sk->data;
  log(L_ERR "%s: Notify socket error: %m", p->p.name, err);
}

static void
bfd_notify_init(struct bfd_proto *p)
{
  int pfds[2];
  sock *sk;

  int rv = pipe(pfds);
  if (rv < 0)
    die("pipe: %m");

  sk = sk_new(p->p.pool);
  sk->type = SK_MAGIC;
  sk->rx_hook = bfd_notify_hook;
  sk->err_hook = bfd_noterr_hook;
  sk->fd = pfds[0];
  sk->data = p;
  if (sk_open(sk) < 0)
    die("bfd: sk_open failed");
  p->notify_rs = sk;

  /* The write sock is not added to any event loop */
  sk = sk_new(p->p.pool);
  sk->type = SK_MAGIC;
  sk->fd = pfds[1];
  sk->data = p;
  sk->flags = SKF_THREAD;
  if (sk_open(sk) < 0)
    die("bfd: sk_open failed");
  p->notify_ws = sk;
}


static struct proto *
bfd_init(struct proto_config *c)
{
  struct proto *p = proto_new(c, sizeof(struct bfd_proto));

  p->neigh_notify = bfd_neigh_notify;

  return p;
}

static int
bfd_start(struct proto *P)
{
  struct bfd_proto *p = (struct bfd_proto *) P;
  struct bfd_config *cf = (struct bfd_config *) (P->cf);

  p->loop = birdloop_new(P->pool);
  p->tpool = rp_new(NULL, "BFD thread root");
  pthread_spin_init(&p->lock, PTHREAD_PROCESS_PRIVATE);

  p->session_slab = sl_new(P->pool, sizeof(struct bfd_session));
  HASH_INIT(p->session_hash_id, P->pool, 4);
  HASH_INIT(p->session_hash_ip, P->pool, 4);

  init_list(&p->sock_list);


  birdloop_mask_wakeups(p->loop);

  init_list(&p->notify_list);
  bfd_notify_init(p);

  birdloop_enter(p->loop);
  p->rx_1 = bfd_open_rx_sk(p, 0);
  p->rx_m = bfd_open_rx_sk(p, 1);
  birdloop_leave(p->loop);

  struct bfd_neighbor *n;
  WALK_LIST(n, cf->neigh_list)
    bfd_start_neighbor(p, n);

  birdloop_unmask_wakeups(p->loop);

  return PS_UP;
}


static int
bfd_shutdown(struct proto *P)
{
  struct bfd_proto *p = (struct bfd_proto *) P;

  return PS_DOWN;
}

static inline int
bfd_same_neighbor(struct bfd_neighbor *x, struct bfd_neighbor *y)
{
  return ipa_equal(x->addr, y->addr) && ipa_equal(x->local, y->local) &&
    (x->iface == y->iface) && (x->opts->multihop == y->opts->multihop);
}

static void
bfd_match_neighbor(struct bfd_proto *p, struct bfd_neighbor *on, struct bfd_config *new)
{
  struct bfd_neighbor *nn;

  WALK_LIST(nn, new->neigh_list)
    if (bfd_same_neighbor(nn, on))
    {
      nn->session = on->session;
      bfd_configure_session(p, nn->session, nn->opts);
      return;
    }

  bfd_stop_neighbor(p, on);
}

static int
bfd_reconfigure(struct proto *P, struct proto_config *c)
{
  struct bfd_proto *p = (struct bfd_proto *) P;
  struct bfd_config *old = (struct bfd_config *) (P->cf);
  struct bfd_config *new = (struct bfd_config *) c;
  struct bfd_neighbor *n;

  birdloop_mask_wakeups(p->loop);

  WALK_LIST(n, old->neigh_list)
    bfd_match_neighbor(p, n, new);

  WALK_LIST(n, new->neigh_list)
    if (!n->session)
      bfd_start_neighbor(p, n);

  birdloop_unmask_wakeups(p->loop);

  return 1;
}

static void
bfd_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct bfd_config *d = (struct bfd_config *) dest;
  // struct bfd_config *s = (struct bfd_config *) src;

  /* We clean up neigh_list, ifaces are non-sharable */
  init_list(&d->neigh_list);

}

void
bfd_show_sessions(struct proto *P)
{
  struct bfd_proto *p = (struct bfd_proto *) P;
  uint state, diag;
  u32 tx_int, timeout;
  const char *ifname;

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1013, "%s: is not up", p->p.name);
    cli_msg(0, "");
    return;
  }

  cli_msg(-1013, "%s:", p->p.name);
  cli_msg(-1013, "%-12s\t%s\t%s\t%s\t%s", "Router IP", "Iface",
	  "State", "TX Int", "Timeout");

  debug("XXX WALK %d %d\n", p->session_hash_id.count,  p->session_hash_ip.count);

  HASH_WALK(p->session_hash_id, next_id, s)
  {
    // FIXME this is unsafe
    state = s->loc_state;
    diag = s->loc_diag;
    ifname = (s->bsock && s->bsock->sk->iface) ? s->bsock->sk->iface->name : "---";
    tx_int = (MAX(s->des_min_tx_int, s->rem_min_rx_int) TO_MS);
    timeout = (MAX(s->req_min_rx_int, s->rem_min_tx_int) TO_MS) * s->rem_detect_mult;

    cli_msg(-1013, "%I\t%s\t%d %d\t%u\t%u",
	    s->addr, ifname, state, diag, tx_int, timeout);
  }
  HASH_WALK_END;

  cli_msg(0, "");
}


struct protocol proto_bfd = {
  .name =		"BFD",
  .template =		"bfd%d",
  .init =		bfd_init,
  .start =		bfd_start,
  .shutdown =		bfd_shutdown,
  .reconfigure =	bfd_reconfigure,
  .copy_config =	bfd_copy_config,
};
