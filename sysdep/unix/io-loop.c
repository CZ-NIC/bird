/*
 *	BIRD -- I/O and event loop
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>

#include "nest/bird.h"

#include "lib/buffer.h"
#include "lib/defer.h"
#include "lib/lists.h"
#include "lib/locking.h"
#include "lib/resource.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/socket.h"

#include "lib/io-loop.h"
#include "sysdep/unix/io-loop.h"
#include "conf/conf.h"
#include "nest/cli.h"

#define THREAD_STACK_SIZE	65536	/* To be lowered in near future */

static struct birdloop *birdloop_new_no_pickup(pool *pp, uint order, const char *name, ...);

/*
 *	Nanosecond time for accounting purposes
 *
 *	A fixed point on startup is set as zero, all other values are relative to that.
 *	Caution: this overflows after like 500 years or so. If you plan to run
 *	BIRD for such a long time, please implement some means of overflow prevention.
 */

#if ! HAVE_CLOCK_MONOTONIC_COARSE
#define CLOCK_MONOTONIC_COARSE CLOCK_MONOTONIC
#endif

static struct timespec ns_begin;

static void ns_init(void)
{
  if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ns_begin))
    bug("clock_gettime: %m");
}

#define NSEC_IN_SEC	((u64) (1000 * 1000 * 1000))

u64 ns_now(void)
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts))
    bug("clock_gettime: %m");

  return (u64) (ts.tv_sec - ns_begin.tv_sec) * NSEC_IN_SEC + ts.tv_nsec - ns_begin.tv_nsec;
}

#define NSEC_TO_SEC(x)	((x) / NSEC_IN_SEC)
#define CURRENT_SEC	NSEC_TO_SEC(ns_now())

static _Thread_local struct spent_time *account_target_spent_time;
static _Thread_local u64 *account_target_total;
static _Thread_local u64 account_last;

static u64 account_finish(void)
{
  /* Get current time */
  u64 now = ns_now();
  u64 dif = now - account_last;

  /* Update second by second */
  if (account_target_spent_time)
  {
    /* Drop old time information if difference is too large */
    if (NSEC_TO_SEC(account_last) + TIME_BY_SEC_SIZE - 1 < NSEC_TO_SEC(now))
      account_last = (NSEC_TO_SEC(now) - TIME_BY_SEC_SIZE + 1) * NSEC_IN_SEC;

    /* Zero new records */
    if (NSEC_TO_SEC(account_target_spent_time->last_written_ns) + TIME_BY_SEC_SIZE < NSEC_TO_SEC(account_last))
      memset(account_target_spent_time->by_sec_ns, 0, sizeof(account_target_spent_time->by_sec_ns));
    else
      for (u64 fclr = NSEC_TO_SEC(account_target_spent_time->last_written_ns) + 1;
	  fclr <= NSEC_TO_SEC(now);
	  fclr++)
	account_target_spent_time->by_sec_ns[fclr % TIME_BY_SEC_SIZE] = 0;

    /* Add times second by second */
    while (NSEC_TO_SEC(account_last) != NSEC_TO_SEC(now))
    {
      u64 part = (NSEC_TO_SEC(account_last) + 1) * NSEC_IN_SEC - account_last;
      account_target_spent_time->by_sec_ns[NSEC_TO_SEC(account_last) % TIME_BY_SEC_SIZE] += part;
      account_last += part;
    }

    /* Update the last second */
    account_target_spent_time->by_sec_ns[NSEC_TO_SEC(account_last) % TIME_BY_SEC_SIZE] += now - account_last;

    /* Store the current time */
    account_target_spent_time->last_written_ns = now;
  }

  /* Update the total */
  if (account_target_total)
    *account_target_total += dif;

  /* Store current time */
  account_last = now;

  return dif;
}

static u64 account_to_spent_time(struct spent_time *st)
{
  u64 elapsed = account_finish();

  account_target_spent_time = st;
  account_target_total = &st->total_ns;

  return elapsed;
}

static u64 account_to_total(u64 *total)
{
  u64 elapsed = account_finish();

  account_target_spent_time = NULL;
  account_target_total = total;

  return elapsed;
}

#define account_to(_arg)	_Generic((_arg), \
    struct spent_time *: account_to_spent_time, \
    u64 *: account_to_total)(_arg)

/*
 *	Current thread context
 */

_Thread_local struct birdloop *birdloop_current;
static _Thread_local struct birdloop *birdloop_wakeup_masked;
static _Thread_local uint birdloop_wakeup_masked_count;

#define LOOP_NAME(loop)			domain_name((loop)->time.domain)
#define LATENCY_DEBUG(flags)		(atomic_load_explicit(&global_runtime, memory_order_relaxed)->latency_debug & (flags))

#define LOOP_TRACE(loop, flags, fmt, args...)	do { if (LATENCY_DEBUG(flags)) log(L_TRACE "%s (%p): " fmt, LOOP_NAME(loop), (loop), ##args); } while (0)
#define THREAD_TRACE(flags, ...)		do { if (LATENCY_DEBUG(flags)) log(L_TRACE "Thread: " __VA_ARGS__); } while (0)

#define LOOP_WARN(loop, fmt, args...)	log(L_WARN "%s (%p): " fmt, LOOP_NAME(loop), (loop), ##args)


event_list *
birdloop_event_list(struct birdloop *loop)
{
  return &loop->event_list;
}

struct timeloop *
birdloop_time_loop(struct birdloop *loop)
{
  return &loop->time;
}

pool *
birdloop_pool(struct birdloop *loop)
{
  return loop->pool;
}

bool
birdloop_inside(struct birdloop *loop)
{
  for (struct birdloop *c = birdloop_current; c; c = c->prev_loop)
    if (loop == c)
      return 1;

  return 0;
}

bool
birdloop_in_this_thread(struct birdloop *loop)
{
  return pthread_equal(pthread_self(), loop->thread->thread_id);
}

/*
 *	Wakeup code for birdloop
 */

void
pipe_new(struct pipe *p)
{
  int rv = pipe(p->fd);
  if (rv < 0)
    die("pipe: %m");

  if (fcntl(p->fd[0], F_SETFL, O_NONBLOCK) < 0)
    die("fcntl(O_NONBLOCK): %m");

  if (fcntl(p->fd[1], F_SETFL, O_NONBLOCK) < 0)
    die("fcntl(O_NONBLOCK): %m");
}

void
pipe_drain(struct pipe *p)
{
  while (1) {
    char buf[64];
    int rv = read(p->fd[0], buf, sizeof(buf));
    if ((rv < 0) && (errno == EAGAIN))
      return;

    if (rv == 0)
      bug("wakeup read eof");
    if ((rv < 0) && (errno != EINTR))
      bug("wakeup read: %m");
  }
}

int
pipe_read_one(struct pipe *p)
{
  while (1) {
    char v;
    int rv = read(p->fd[0], &v, sizeof(v));
    if (rv == 1)
      return 1;
    if ((rv < 0) && (errno == EAGAIN))
      return 0;
    if (rv > 1)
      bug("wakeup read more bytes than expected: %d", rv);
    if (rv == 0)
      bug("wakeup read eof");
    if (errno != EINTR)
      bug("wakeup read: %m");
  }
}

void
pipe_kick(struct pipe *p)
{
  char v = 1;
  int rv;

  while (1) {
    rv = write(p->fd[1], &v, sizeof(v));
    if ((rv >= 0) || (errno == EAGAIN))
      return;
    if (errno != EINTR)
      bug("wakeup write: %m");
  }
}

void
pipe_pollin(struct pipe *p, struct pfd *pfd)
{
  BUFFER_PUSH(pfd->pfd) = (struct pollfd) {
      .fd = p->fd[0],
      .events = POLLIN,
      };
  BUFFER_PUSH(pfd->loop) = NULL;
}

void
pipe_free(struct pipe *p)
{
  close(p->fd[0]);
  close(p->fd[1]);
}

static inline void
wakeup_init(struct bird_thread *loop)
{
  pipe_new(&loop->wakeup);
}

static inline void
wakeup_drain(struct bird_thread *loop)
{
  pipe_drain(&loop->wakeup);
}

static inline void
wakeup_do_kick(struct bird_thread *loop)
{
  pipe_kick(&loop->wakeup);
}

static inline void
wakeup_free(struct bird_thread *loop)
{
  pipe_free(&loop->wakeup);
}

static inline bool
birdloop_try_ping(struct birdloop *loop, u32 ltt)
{
  /* Somebody else is already pinging, be idempotent */
  if (ltt & LTT_PING)
  {
    LOOP_TRACE(loop, DL_PING, "already being pinged");
    return 0;
  }

  /* Thread moving is an implicit ping */
  if (ltt & LTT_MOVE)
  {
    LOOP_TRACE(loop, DL_PING, "ping while moving");
    return 1;
  }

  /* No more flags allowed */
  ASSERT_DIE(!ltt);

  /* No ping when not picked up */
  if (!loop->thread)
  {
    LOOP_TRACE(loop, DL_PING, "not picked up yet, can't ping");
    return 1;
  }

  /* No ping when masked */
  if (loop == birdloop_wakeup_masked)
  {
    LOOP_TRACE(loop, DL_PING, "wakeup masked, can't ping");
    birdloop_wakeup_masked_count++;
    return 1;
  }

  /* Send meta event to ping */
  if ((loop != loop->thread->meta) && (loop != &main_birdloop))
  {
    LOOP_TRACE(loop, DL_PING, "Ping by meta event to %p", loop->thread->meta);
    ev_send_loop(loop->thread->meta, &loop->event);
    return 1;
  }

  /* Do the real ping of Meta or Main */
  LOOP_TRACE(loop, DL_WAKEUP, "sending pipe ping");
  wakeup_do_kick(loop->thread);
  return 0;
}

static inline void
birdloop_do_ping(struct birdloop *loop)
{
  /* Register our ping effort */
  u32 ltt = atomic_fetch_or_explicit(&loop->thread_transition, LTT_PING, memory_order_acq_rel);

  /* Try to ping in multiple ways */
  if (birdloop_try_ping(loop, ltt))
    atomic_fetch_and_explicit(&loop->thread_transition, ~LTT_PING, memory_order_acq_rel);
}

void
birdloop_ping(struct birdloop *loop)
{
  if (!birdloop_inside(loop))
  {
    LOOP_TRACE(loop, DL_PING, "ping from outside");
    birdloop_do_ping(loop);
  }
  else
  {
    LOOP_TRACE(loop, DL_PING, "ping from inside, pending=%d", loop->ping_pending);
    if (!loop->ping_pending)
      loop->ping_pending++;
  }
}


/*
 *	Sockets
 */

static void
sockets_init(struct birdloop *loop)
{
  init_list(&loop->sock_list);
  loop->sock_num = 0;
}

void
socket_changed(struct birdsock *s, bool recalculate_sk_info)
{
  struct birdloop *loop = s->loop;
  ASSERT_DIE(birdloop_inside(loop));

  LOOP_TRACE(loop, DL_SOCKETS, "socket %p changed", s);
  loop->sock_changed = 1;
  birdloop_ping(loop);

  if (loop != &main_birdloop && recalculate_sk_info)
  {
    int size = loop->sock_num * sk_max_dump_len + 17;
    char *new_info = mb_alloc(loop->pool, size);

    node *n;
    buffer buf = {
      .start = new_info,
      .pos = new_info,
      .end = new_info + size,
    };

    buffer_print(&buf, "%p ", s);

    WALK_LIST(n, loop->sock_list)
    {
      SKIP_BACK_DECLARE(sock, s, n, n);
      sk_dump_to_buffer(&buf, s);
    }
    buf.pos[0] = '\0';

    char *old_info = NULL;
    if (loop->sockets_info)
      old_info = atomic_load_explicit(&loop->sockets_info, memory_order_relaxed);
    atomic_store_explicit(&loop->sockets_info, new_info, memory_order_relaxed);

    synchronize_rcu(); // We are about to free old_info, which might be in use in dumping right now

    if (old_info)
      mb_free(old_info);
  }
}

void
birdloop_add_socket(struct birdloop *loop, sock *s)
{
  ASSERT_DIE(birdloop_inside(loop));
  ASSERT_DIE(!s->loop);

  LOOP_TRACE(loop, DL_SOCKETS, "adding socket %p (total=%d)", s, loop->sock_num);
  add_tail(&loop->sock_list, &s->n);
  loop->sock_num++;

  s->loop = loop;
  s->index = -1;

  socket_changed(s, true);
}

extern sock *stored_sock; /* mainloop hack */

void
birdloop_remove_socket(struct birdloop *loop, sock *s)
{
  ASSERT_DIE(!enlisted(&s->n) == !s->loop);

  if (!s->loop)
    return;

  ASSERT_DIE(birdloop_inside(loop));
  ASSERT_DIE(s->loop == loop);

  /* Decouple the socket from the loop at all. */
  LOOP_TRACE(loop, DL_SOCKETS, "removing socket %p (total=%d)", s, loop->sock_num);

  if (loop->sock_active == s)
    loop->sock_active = sk_next(s);

  if ((loop == &main_birdloop) && (s == stored_sock))
    stored_sock = sk_next(s);

  rem_node(&s->n);
  loop->sock_num--;

  socket_changed(s, true);

  s->loop = NULL;
  s->index = -1;
}

void
sk_reloop(sock *s, struct birdloop *loop)
{
  ASSERT_DIE(birdloop_inside(loop));
  ASSERT_DIE(birdloop_inside(s->loop));

  if (loop == s->loop)
    return;

  birdloop_remove_socket(s->loop, s);
  birdloop_add_socket(loop, s);
}

void
sk_pause_rx(struct birdloop *loop, sock *s)
{
  ASSERT_DIE(birdloop_inside(loop));
  s->rx_hook = NULL;
  socket_changed(s, false);
}

void
sk_resume_rx(struct birdloop *loop, sock *s, int (*hook)(sock *, uint))
{
  ASSERT_DIE(birdloop_inside(loop));
  ASSERT_DIE(hook);
  s->rx_hook = hook;
  socket_changed(s, false);
}

static inline uint sk_want_events(sock *s)
{ return (s->rx_hook ? POLLIN : 0) | (sk_tx_pending(s) ? POLLOUT : 0); }

void
sockets_prepare(struct birdloop *loop, struct pfd *pfd)
{
  node *n;
  WALK_LIST(n, loop->sock_list)
  {
    SKIP_BACK_DECLARE(sock, s, n, n);
    uint w = sk_want_events(s);

    if (!w)
    {
      s->index = -1;
      continue;
    }

    s->index = pfd->pfd.used;
    LOOP_TRACE(loop, DL_SOCKETS, "socket %p poll index is %d", s, s->index);

    BUFFER_PUSH(pfd->pfd) = (struct pollfd) {
	.fd = s->fd,
	.events = sk_want_events(s),
    };
    BUFFER_PUSH(pfd->loop) = loop;
  }
}

int sk_read(sock *s, int revents);
int sk_write(sock *s);
void sk_err(sock *s, int revents);

static void
sockets_fire(struct birdloop *loop, bool read, bool write)
{
  if (EMPTY_LIST(loop->sock_list))
    return;

  times_update();

  struct pollfd *pfd = loop->thread->pfd->pfd.data;
  loop->sock_active = SKIP_BACK(sock, n, HEAD(loop->sock_list));

  while (loop->sock_active)
  {
    sock *s = loop->sock_active;

    int rev;
    if ((s->index >= 0) && (rev = pfd[s->index].revents) && !(rev & POLLNVAL))
    {
      int e = 1;

      if (write && (rev & POLLOUT))
      {
	/* Write until task limit is up */
	while ((s == loop->sock_active) && (e = sk_write(s)) && task_still_in_limit())
	  ;

	if (s != loop->sock_active)
	  continue;

	if (!sk_tx_pending(s))
	  loop->thread->sock_changed = 1;
      }

      /* Read until task limit is up */
      if (read && (rev & POLLIN))
	while ((s == loop->sock_active) && s->rx_hook && sk_read(s, rev) && (s->fast_rx || task_still_in_limit()))
	  ;

      if (s != loop->sock_active)
	continue;

      if (!(rev & (POLLOUT | POLLIN)) && (rev & POLLERR))
	sk_err(s, rev);

      if (s != loop->sock_active)
	continue;
    }

    loop->sock_active = sk_next(s);
  }
}

/*
 *	Threads
 */

#define TLIST_PREFIX thread_group
#define TLIST_TYPE union thread_group_public
#define TLIST_ITEM n
#define TLIST_WANT_ADD_TAIL
TLIST_DEFAULT_NODE;

#define THREAD_GROUP_PUBLIC	\
  DOMAIN(attrs) lock;		\
  const char *name;		\
  struct thread_group_node n;	\

struct thread_group_private {
  THREAD_GROUP_PUBLIC;

  struct thread_group_private **locked_at;
  TLIST_LIST(birdloop) loops;
  TLIST_LIST(thread) threads;

  uint thread_count;
  uint thread_busy_count;
  uint loop_count;
  uint loop_unassigned_count;
  struct thread_params params;
  struct thread_dropper {
    struct birdloop *loop;
    event event;
    OBSREF(struct config) conflock;
  } thread_dropper;
  const struct thread_group_config *cf;
};

typedef union thread_group_public {
  struct { THREAD_GROUP_PUBLIC; };
  struct thread_group_private priv;
} thread_group;

#include "lib/tlists.h"

#define TG_LOCKED(gpub, gpriv)	LOBJ_LOCKED(gpub, gpriv, thread_group, attrs)
#define TG_LOCK(gpub, gpriv)	LOBJ_LOCK(gpub, gpriv, thread_group, attrs)
#define TG_LOCKED_EXPR(gpub, gpriv, expr) ({ TG_LOCK(gpub, gpriv); expr; })

LOBJ_UNLOCK_CLEANUP(thread_group, attrs);

static thread_group *default_thread_group;
static TLIST_LIST(thread_group) global_thread_group_list;

const struct thread_group_config
thread_group_config_default_worker = {
  .params = {
    .max_time		= 300 MS_,
    .min_time		= 10 MS_,
    .max_latency	= 1 S_,
    /* 8 hours, 43 minutes and 35 seconds to not conincide with anything */
    .wakeup_time	= 31415 S_,
  },
  .thread_count	= 1,
},
thread_group_config_default_express = {
  .params = {
    .max_time		= 10 MS_,
    .min_time		= 1 MS_,
    .max_latency	= 10 MS_,
    .wakeup_time	= 60 S_,
  },
  .thread_count	= 1,
},
thread_group_shutdown = {};


static _Thread_local struct bird_thread *this_thread;

static void bird_thread_busy_set(struct thread_group_private *, int val);

static void
birdloop_set_thread(struct birdloop *loop, struct bird_thread *thr)
{
  struct bird_thread *old = loop->thread;

  /* We don't support direct reassignment from one thread to another */
  ASSERT_DIE(!thr || !old);

  /* We have to be in the thread we are trying to leave, for sure */
  if (old)
    ASSERT_DIE(birdloop_inside(old->meta));

  /* Signal our moving effort */
  u32 ltt = atomic_fetch_or_explicit(&loop->thread_transition, LTT_MOVE, memory_order_acq_rel);
  ASSERT_DIE((ltt & LTT_MOVE) == 0);

  /* Wait until all previously started pings end */
  while (ltt & LTT_PING)
  {
    birdloop_yield();
    ltt = atomic_load_explicit(&loop->thread_transition, memory_order_acquire);
    ASSERT_DIE(ltt & LTT_MOVE);
  }
  /* Now we are free of running pings */

  if (old)
  {
    /* Unschedule from Meta */
    ev_postpone(&loop->event);
    tm_stop(&loop->timer);

    /* Request local socket reload */
    this_thread->sock_changed = 1;
  }

  /* Update the thread value */
  loop->thread = thr;

  /* Allow pings */
  atomic_fetch_and_explicit(&loop->thread_transition, ~LTT_MOVE, memory_order_acq_rel);

  /* Put into appropriate lists */
  if (thr)
  {
    thr->loop_count++;
    birdloop_add_tail(&thr->loops, loop);

    if (!EMPTY_LIST(loop->sock_list))
      thr->sock_changed = 1;
    ev_send_loop(loop->thread->meta, &loop->event);
  }
  else
    TG_LOCKED(loop->thread_group, group)
    {
      /* Put into pickup list */
      birdloop_add_tail(&group->loops, loop);
      group->loop_unassigned_count++;
    }

  loop->last_transition_ns = ns_now();
}

static void
bird_thread_pickup_next(struct thread_group_private *group)
{
  /* This thread goes to the end of the pickup list */
  thread_rem_node(&group->threads, this_thread);
  thread_add_tail(&group->threads, this_thread);

  /* If there are more loops to be picked up, wakeup the next thread in order */
  if (!EMPTY_TLIST(birdloop, &group->loops))
    wakeup_do_kick(THEAD(thread, &group->threads));
}

static bool
birdloop_hot_potato(struct birdloop *loop)
{
  if (!loop)
    return 0;

  return ns_now() - loop->last_transition_ns < 1 S TO_NS;
}

static uint
birdloop_take_count(struct thread_group_private *group)
{
  if (EMPTY_TLIST(birdloop, &group->loops))
    return 0;

  THREAD_TRACE(DL_SCHEDULING, "Loop take requested");

  /* Take a proportional amount of loops from the pickup list and unlock */
  uint thread_count = group->thread_count + 1;
  if (group->thread_busy_count < group->thread_count)
    thread_count -= group->thread_busy_count;

  if (birdloop_hot_potato(this_thread->meta))
    return 1;
  else
    return 1 + group->loop_unassigned_count / thread_count;
}

static struct birdloop *
birdloop_take_one(struct thread_group_private *group)
{
  if (EMPTY_TLIST(birdloop, &group->loops))
    return NULL;

  struct birdloop *loop = THEAD(birdloop, &group->loops);
  birdloop_rem_node(&group->loops, loop);
  group->loop_unassigned_count--;

  return loop;
}

static void
birdloop_balancer(void)
{
  struct birdloop *pick_this = NULL;
  uint pick_amount = 0;
  bool drop_needed = 0;

  TG_LOCKED(this_thread->group, group)
  {
    /* Update timing parameters */
    this_thread->params = group->params;

    /* Check drop */
    drop_needed =
      this_thread->busy_active &&
      (group->thread_busy_count < group->thread_count) &&
      (this_thread->loop_count > 1) && (
	EMPTY_TLIST(birdloop, &group->loops) ||
	!birdloop_hot_potato(THEAD(birdloop, &group->loops))
      );

    if (drop_needed)
      THREAD_TRACE(DL_SCHEDULING, "Loop drop requested (tbc=%d, tc=%d, lc=%d)",
	  group->thread_busy_count, group->thread_count, this_thread->loop_count);
    else
      /* Immediately start taking new loops */
      pick_amount = birdloop_take_count(group);

    if (pick_amount--)
      pick_this = birdloop_take_one(group);
  }

  if (drop_needed)
  {
    ASSERT_DIE(!pick_this);

    uint dropped = 0;
    WALK_TLIST_DELSAFE(birdloop, loop, &this_thread->loops)
    {
      BIRDLOOP_ENTER(loop);
      if (ev_active(&loop->event) && !loop->stopped && !birdloop_hot_potato(loop))
      {
	/* Pass to another thread */
	birdloop_rem_node(&this_thread->loops, loop);
	this_thread->loop_count--;
	LOOP_TRACE(loop, DL_SCHEDULING, "Dropping from thread, remaining %u loops here", this_thread->loop_count);

	/* This also unschedules the loop from Meta */
	birdloop_set_thread(loop, NULL);

	dropped++;
	if ((dropped * dropped) / 2 > this_thread->loop_count)
	{
	  birdloop_leave(loop);

	  TG_LOCKED(this_thread->group, group)
	    bird_thread_pickup_next(group);

	  break;
	}
      }
    }

    if (dropped)
    {
      this_thread->meta->last_transition_ns = ns_now();
      return;
    }

    this_thread->busy_counter = 0;
    TG_LOCKED(this_thread->group, group)
    {
      bird_thread_busy_set(group, 0);

      /* And now we can possibly pick new loops if needed */
      pick_amount = birdloop_take_count(group);

      if (pick_amount--)
	pick_this = birdloop_take_one(group);
    }
  }

  while (pick_this)
  {
    struct birdloop *loop = pick_this;

    birdloop_enter(loop);

    if (loop->thread_group == this_thread->group)
    {
      birdloop_set_thread(loop, this_thread);
      LOOP_TRACE(loop, DL_SCHEDULING, "Picked up by thread");

      node *n;
      WALK_LIST(n, loop->sock_list)
	SKIP_BACK(sock, n, n)->index = -1;
    }
    else
      /* Transfer required, drop immediately */
      birdloop_set_thread(loop, NULL);

    birdloop_leave(loop);

    if (pick_amount--)
      TG_LOCKED(this_thread->group, group)
	pick_this = birdloop_take_one(group);
    else
      break;
  }

  this_thread->meta->last_transition_ns = ns_now();
}

static int
poll_timeout(struct birdloop *loop)
{
  timer *t = timers_first(&loop->time);
  if (!t)
  {
    THREAD_TRACE(DL_SCHEDULING, "No timers, no events in meta");
    return -1;
  }

  btime remains = tm_remains(t);
  int timeout = remains TO_MS + ((remains TO_MS) MS < remains);

  THREAD_TRACE(DL_SCHEDULING, "Next meta timer in %d ms for %s", timeout,
      LOOP_NAME(SKIP_BACK(struct birdloop, timer, t)));

  return timeout;
}

static void
bird_thread_busy_set(struct thread_group_private *group, int val)
{
  if (this_thread->busy_active = val)
    group->thread_busy_count++;
  else
    group->thread_busy_count--;
  ASSERT_DIE(group->thread_busy_count <= group->thread_count);
}

static void *
bird_thread_main(void *arg)
{
  struct bird_thread *thr = this_thread = arg;

  rcu_thread_start();

  account_to(&thr->overhead);

  birdloop_enter(thr->meta);
  this_birdloop = thr->meta;

  THREAD_TRACE(DL_SCHEDULING, "Started");

  tmp_init(thr->pool);

  defer_init(lp_new(thr->pool));

  thr->sock_changed = 1;

  struct pfd pfd;
  BUFFER_INIT(pfd.pfd, thr->pool, 16);
  BUFFER_INIT(pfd.loop, thr->pool, 16);
  thr->pfd = &pfd;

  while (1)
  {
    u64 thr_loop_start = ns_now();
    int timeout;

    /* Schedule all loops with timed out timers */
    timers_fire(&thr->meta->time, 0);

    /* Pickup new loops */
    birdloop_balancer();

    /* Compute maximal time per loop */
    u64 thr_before_run = ns_now();
    if (thr->loop_count > 0)
    {
      thr->max_loop_time_ns = ((thr->params.max_latency TO_NS) / 2 - (thr_before_run - thr_loop_start)) / (u64) thr->loop_count;
      if (thr->max_loop_time_ns NS > (u64) thr->params.max_time)
	thr->max_loop_time_ns = thr->params.max_time TO_NS;
      if (thr->max_loop_time_ns NS < (u64) thr->params.min_time)
	thr->max_loop_time_ns = thr->params.min_time TO_NS;
	/* TODO: put a warning about possible overload here */
    }

    /* Run all scheduled loops */
    int more_events = ev_run_list(&thr->meta->event_list);
    if (more_events)
    {
      THREAD_TRACE(DL_SCHEDULING, "More metaevents to run from %s",
	  LOOP_NAME(SKIP_BACK(struct birdloop, event,
	      atomic_load_explicit(&thr->meta->event_list.receiver, memory_order_relaxed)))
	  );
      timeout = 0;
    }
    else
      timeout = poll_timeout(thr->meta);

    /* Run priority events before sleeping */
    ev_run_list(&thr->priority_events);

    /* Do we have to refresh sockets? */
    if (thr->sock_changed)
    {
      THREAD_TRACE(DL_SOCKETS, "Recalculating socket poll");
      thr->sock_changed = 0;

      BUFFER_FLUSH(pfd.pfd);
      BUFFER_FLUSH(pfd.loop);

      pipe_pollin(&thr->wakeup, &pfd);

      WALK_TLIST(birdloop, loop, &thr->loops)
      {
	BIRDLOOP_ENTER(loop);
	sockets_prepare(loop, &pfd);
      }

      ASSERT_DIE(pfd.loop.used == pfd.pfd.used);
      THREAD_TRACE(DL_SOCKETS, "Total %d sockets", pfd.pfd.used);
    }

    /* Check thread busy indicator */
    int idle_force = (timeout < 0) || (timeout > 300);
    int busy_now = (timeout < 5) && !idle_force;

    /* Nothing to do right now but there may be some loops for pickup */
    TG_LOCKED(this_thread->group, group)
    {
      if (idle_force)
	if (!EMPTY_TLIST(birdloop, &group->loops))
	  timeout = 0;

      if (busy_now && !thr->busy_active && (++thr->busy_counter == 4))
	bird_thread_busy_set(group, 1);

      if (!busy_now && thr->busy_active && (idle_force || (--thr->busy_counter == 0)))
      {
	thr->busy_counter = 0;
	bird_thread_busy_set(group, 0);
      }
    }

    account_to(&this_thread->idle);
    birdloop_leave(thr->meta);
poll_retry:;
    int rv = poll(pfd.pfd.data, pfd.pfd.used, timeout);
    if (rv < 0)
    {
      if (errno == EINTR || errno == EAGAIN)
	goto poll_retry;
      bug("poll in %p: %m", thr);
    }

    account_to(&this_thread->overhead);
    birdloop_enter(thr->meta);

    /* Drain wakeup fd */
    if (pfd.pfd.data[0].revents & POLLIN)
    {
      THREAD_TRACE(DL_WAKEUP, "Ping received");
      ASSERT_DIE(rv > 0);
      rv--;
      wakeup_drain(thr);
    }

    /* Unset ping information for Meta */
    atomic_fetch_and_explicit(&thr->meta->thread_transition, ~LTT_PING, memory_order_acq_rel);

    /* Schedule loops with active sockets */
    if (rv)
      for (uint i = 1; i < pfd.pfd.used; i++)
	if (pfd.pfd.data[i].revents)
	{
	  LOOP_TRACE(pfd.loop.data[i], DL_SOCKETS, "socket id %d got revents=0x%x", i, pfd.pfd.data[i].revents);
	  ev_send_loop(thr->meta, &pfd.loop.data[i]->event);
	}
  }

  bug("An infinite loop has ended.");
}

static void
bird_thread_group_done(thread_group *gpub, TLIST_LIST(birdloop) *leftover_loops)
{
  /* Sanity checks */
  ASSERT_DIE(birdloop_inside(&main_birdloop));
  TG_LOCKED(gpub, group)
    ASSERT_DIE(EMPTY_TLIST(thread, &group->threads));

  /* Transfer loops left here to the default group */
  while (!EMPTY_TLIST(birdloop, leftover_loops))
  {
    struct birdloop *loop = THEAD(birdloop, leftover_loops);
    BIRDLOOP_ENTER(loop);
    if (loop->thread_group == gpub)
    {
      birdloop_transfer(loop, gpub, default_thread_group);
    }

    birdloop_rem_node(leftover_loops, loop);
    birdloop_set_thread(loop, NULL);
  }

  thread_group_rem_node(&global_thread_group_list, gpub);
  DOMAIN_FREE(attrs, gpub->lock);
  mb_free(gpub);
}

static void
bird_thread_cleanup(void *_thr)
{
  struct bird_thread *thr = _thr;
  struct birdloop *meta = thr->meta;
  thread_group *gpub = thr->group;

  ASSERT_DIE(birdloop_inside(&main_birdloop));

  /* Wait until the thread actually finishes */
  ASSERT_DIE(meta);
  birdloop_enter(meta);
  birdloop_leave(meta);

  /* No more wakeup */
  wakeup_free(thr);

  /* Thread attributes no longer needed */
  pthread_attr_destroy(&thr->thread_attr);

  /* Free the meta loop */
  thr->meta->thread = NULL;
  thr->meta = NULL;
  birdloop_free(meta);

  TLIST_LIST(birdloop) *leftover_loops = NULL;
  struct birdloop *tdf = NULL;

  TG_LOCKED(gpub, group) {
    if ((group->cf == &thread_group_shutdown) && EMPTY_TLIST(thread, &group->threads))
    {
      OBSREF_CLEAR(group->thread_dropper.conflock);
      tdf = group->thread_dropper.loop;
      birdloop_rem_node(&group->loops, tdf);
      group->thread_dropper.loop = NULL;
      group->thread_dropper.event = (event) {};
      leftover_loops = &group->loops;
    }
  }

  if (tdf)
    birdloop_free(tdf);

  if (leftover_loops)
    /* Happens only with the last thread */
    bird_thread_group_done(gpub, leftover_loops);
}

static void bird_thread_start(thread_group *);
static void
bird_thread_start_event(void *_data)
{
  thread_group *group = _data;
  bird_thread_start(group);
}

static void
bird_thread_start_indirect(struct thread_group_private *group)
{
  group->thread_dropper.event.hook = bird_thread_start_event;
  ev_send(&global_event_list, &group->thread_dropper.event);
}

static void
bird_thread_start(thread_group *gpub)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  while (true)
  {
    /* Already enough threads */
    TG_LOCKED(gpub, group)
      if (group->thread_count >= group->cf->thread_count)
	return;

    struct birdloop *meta = birdloop_new_no_pickup(&root_pool, DOMAIN_ORDER(meta), "Thread Meta");
    pool *p = birdloop_pool(meta);

    birdloop_enter(meta);
    struct bird_thread *thr = mb_allocz(p, sizeof(*thr));
    thr->pool = p;

    TG_LOCKED(gpub, group)
    {
      thr->cleanup_event = (event) { .hook = bird_thread_cleanup, .data = thr, };
      thr->group = gpub;
      thr->params = group->params;
      thr->meta = meta;
      thr->meta->thread = thr;

      wakeup_init(thr);
      ev_init_list(&thr->priority_events, NULL, "Thread direct event list");

      thread_add_tail(&group->threads, thr);

      int e = 0;

      if (e = pthread_attr_init(&thr->thread_attr))
	die("pthread_attr_init() failed: %M", e);

      /* We don't have to worry about thread stack size so much.
	 if (e = pthread_attr_setstacksize(&thr->thread_attr, THREAD_STACK_SIZE))
	 die("pthread_attr_setstacksize(%u) failed: %M", THREAD_STACK_SIZE, e);
	 */

      if (e = pthread_attr_setdetachstate(&thr->thread_attr, PTHREAD_CREATE_DETACHED))
	die("pthread_attr_setdetachstate(PTHREAD_CREATE_DETACHED) failed: %M", e);

      if (e = pthread_create(&thr->thread_id, &thr->thread_attr, bird_thread_main, thr))
	die("pthread_create() failed: %M", e);

      group->thread_count++;

    }

    birdloop_leave(meta);
  }
}

static void
bird_thread_dropper_free(void *data)
{
  struct birdloop *tdl_stop = data;
  birdloop_free(tdl_stop);
}

static void
bird_thread_shutdown(void * _ UNUSED)
{
  struct birdloop *tdl_stop = NULL;
  int dif;

  TG_LOCKED(this_thread->group, group)
  {
    dif = group->thread_count - group->cf->thread_count;

    if (dif > 0)
      ev_send_loop(group->thread_dropper.loop, &group->thread_dropper.event);
    else
    {
      ASSERT_DIE(dif == 0);
      tdl_stop = group->thread_dropper.loop;
      group->thread_dropper.loop = NULL;
      OBSREF_CLEAR(group->thread_dropper.conflock);
    }
  }

  THREAD_TRACE(DL_SCHEDULING, "Thread pickup size differs from dropper goal by %d%s", dif, tdl_stop ? ", stopping" : "");

  if (tdl_stop)
  {
    birdloop_stop_self(tdl_stop, bird_thread_dropper_free, tdl_stop);
    return;
  }

  struct bird_thread *thr = this_thread;

  TG_LOCKED(this_thread->group, group)
  {
    /* Leave the thread-picker list to get no more loops */
    thread_rem_node(&group->threads, thr);
    group->thread_count--;

    /* Fix the busy count */
    if (thr->busy_active)
      group->thread_busy_count--;

    tdl_stop = group->thread_dropper.loop;
  }

  /* Leave the thread-dropper loop as we aren't going to return. */
  birdloop_leave(tdl_stop);

  /* Last try to run the priority event list; ruin it then to be extra sure */
  ev_run_list(&this_thread->priority_events);
  memset(&this_thread->priority_events, 0xa5, sizeof(this_thread->priority_events));

  /* Drop loops including the thread dropper itself */
  while (!EMPTY_TLIST(birdloop, &thr->loops))
  {
    struct birdloop *loop = THEAD(birdloop, &thr->loops);

    /* Remove loop from this thread's list */
    this_thread->loop_count--;
    birdloop_rem_node(&thr->loops, loop);

    /* Unset loop's thread */
    birdloop_set_thread(loop, NULL);
  }

  /* Let others know about new loops */
  TG_LOCKED(this_thread->group, group)
    if (!EMPTY_TLIST(birdloop, &group->loops)
	&& !EMPTY_TLIST(thread, &group->threads))
      wakeup_do_kick(THEAD(thread, &group->threads));

  /* Request thread cleanup from main loop */
  ev_send_loop(&main_birdloop, &thr->cleanup_event);

  /* Local pages not needed anymore */
  flush_local_pages();

  /* Unregister from RCU */
  rcu_thread_stop();

  /* Now we can be cleaned up */
  birdloop_leave(thr->meta);

  /* Exit! */
  THREAD_TRACE(DL_SCHEDULING, "Stopped");
  pthread_exit(NULL);
}

static void
bird_thread_stop(thread_group *gpub, struct config *old_config)
{
  struct birdloop *tdl = birdloop_new(&root_pool, DOMAIN_ORDER(control), gpub, "Thread dropper");
  BIRDLOOP_ENTER(tdl);

  TG_LOCKED(gpub, group)
  {
    group->thread_dropper = (struct thread_dropper) {
      .loop = tdl,
      .event.hook = bird_thread_shutdown,
    };
    OBSREF_SET(group->thread_dropper.conflock, old_config);
    ev_send_loop(tdl, &group->thread_dropper.event);
  }
}

void
bird_thread_commit(struct config *new, struct config *old)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  if (new->shutdown)
    return;

  /* First, we match the new config to the existing groups */
  WALK_TLIST(thread_group_config, tgc, &new->thread_group)
  {
    thread_group *found = NULL;
    int dif = -tgc->thread_count;
    bool thread_dropper_running = false;

    WALK_TLIST(thread_group, gpub, &global_thread_group_list)
    {
      TG_LOCKED(gpub, group)
	if (!strcmp(group->name, tgc->symbol->name))
	{
	  ASSERT_DIE(thread_group_config_enlisted(group->cf) == &old->thread_group);
	  found = gpub;
	  group->cf = tgc;
	  tgc->group = gpub;
	  group->name = tgc->symbol->name;
	  /* Do not start threads for empty groups */
	  if ((group->thread_count == 0) && EMPTY_TLIST(birdloop, &group->loops))
	    dif = 0;
	  else
	    dif = group->thread_count - tgc->thread_count;
	  thread_dropper_running = !!group->thread_dropper.loop;
	  group->params = tgc->params;
	}

      if (found)
	break;
    }

    if (found)
    {
      if (dif < 0)
	bird_thread_start(found);
      else if ((dif > 0) && !thread_dropper_running)
	bird_thread_stop(found, old);
    }
    else
    {
      struct thread_group_private *group = mb_allocz(&root_pool, sizeof *group);
      SKIP_BACK_DECLARE(thread_group, gpub, priv, group);
      group->lock = DOMAIN_NEW(attrs);
      DOMAIN_SETUP(attrs, group->lock, "Thread Group", NULL);
      group->cf = tgc;
      tgc->group = gpub;
      group->params = tgc->params;
      group->name = tgc->symbol->name;
      group->thread_dropper.event = (event) { .data = group, };

      thread_group_add_tail(&global_thread_group_list, gpub);
      /* Will start threads when some loop emerges, not now. */
    }
  }

  ASSERT_DIE(new->default_thread_group);
  default_thread_group = new->default_thread_group->group;

  WALK_TLIST_DELSAFE(thread_group, gpub, &global_thread_group_list)
  {
    bool run_thread_dropper = false;
    TLIST_LIST(birdloop) *leftover_loops = NULL;

    TG_LOCKED(gpub, group)
    {
      if (group->cf && (thread_group_config_enlisted(group->cf) == &new->thread_group))
	break; /* Unlock, group already reconfigured */

      /* All shutting-down groups are expected to be finished
       * before another config commit */
      ASSERT_DIE(group->cf != &thread_group_shutdown);

      /* The thread dropper should not be running now,
       * it blocks config completion */
      ASSERT_DIE(!group->thread_dropper.loop);

      /* The only case the thread_dropper event runs,
       * is when it was recently summonned to start some new threads */
      ev_postpone(&group->thread_dropper.event);

      /* Needa stop the group */
      ASSERT_DIE(!group->cf || (thread_group_config_enlisted(group->cf) == &old->thread_group));
      group->cf = &thread_group_shutdown;

      if (EMPTY_TLIST(thread, &group->threads))
	leftover_loops = &group->loops;
      else
	run_thread_dropper = true;
    }

    /* Drop loops immediately, no thread to kill */
    if (leftover_loops)
      bird_thread_group_done(gpub, leftover_loops);

    /* Kill threads, loops get dropped later */
    if (run_thread_dropper)
      bird_thread_stop(gpub, old);
  }

  /* after bird_thread_stop(), the old config reference is blocked
   * until the threads have finished thread stopping. */
}

void
thread_group_finalize_config(void)
{
  if (EMPTY_TLIST(thread_group_config, &new_config->thread_group))
  {
    if (!new_config->thread_group_simple)
      new_config->thread_group_simple = -1;

    /* Default worker thread group */
    struct thread_group_config *tgc = cfg_alloc(sizeof *tgc);
    *tgc = thread_group_config_default_worker;
    tgc->thread_count = (new_config->thread_group_simple > 0) ?
      new_config->thread_group_simple : 1;
    thread_group_config_add_tail(&new_config->thread_group, tgc);
    new_config->default_thread_group = tgc;

    tgc->symbol = cf_define_symbol(
	new_config, cf_get_symbol(new_config, "worker"),
	SYM_THREAD_GROUP, thread_group, tgc);

    /* Default express thread group */
    tgc = cfg_alloc(sizeof *tgc);
    *tgc = thread_group_config_default_express;
    thread_group_config_add_tail(&new_config->thread_group, tgc);

    tgc->symbol = cf_define_symbol(
	new_config, cf_get_symbol(new_config, "express"),
	SYM_THREAD_GROUP, thread_group, tgc);
  }

  if (!new_config->default_thread_group)
    cf_error("No default thread group configured");
}

/* Cleanup after last thread */
static void
bird_thread_sync_finish(void *_sync)
{
  ASSERT_THE_BIRD_LOCKED;
  struct bird_thread_syncer *sync = _sync;

  /* Keep necessary pointers locally */
  pool *p = sync->pool;
  DOMAIN(control) lock = sync->lock;
  LOCK_DOMAIN(control, lock);

  /* This invalidates the `sync` pointer */
  CALL(sync->finish, sync);

  /* Free pool and domain */
  rp_free(p);
  UNLOCK_DOMAIN(control, lock);
  DOMAIN_FREE(control, lock);
}

/* Process regular one thread hook */
static void
bird_thread_sync_one(void *_sync)
{
  struct bird_thread_syncer *sync = _sync;

  LOCK_DOMAIN(control, sync->lock);
  CALL(sync->hook, sync);
  sync->done++;
  if (sync->done == sync->total)
    ev_send_loop(&main_birdloop, ev_new_init(sync->pool, bird_thread_sync_finish, sync));
  UNLOCK_DOMAIN(control, sync->lock);
}

void
bird_thread_sync_all(struct bird_thread_syncer *sync,
    void (*hook)(struct bird_thread_syncer *),
    void (*done)(struct bird_thread_syncer *), const char *name)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  sync->lock = DOMAIN_NEW(control);
  LOCK_DOMAIN(control, sync->lock);

  sync->pool = rp_new(&root_pool, sync->lock.control, name);
  sync->hook = hook;
  sync->finish = done;

  WALK_TLIST(thread_group, gpub, &global_thread_group_list)
    TG_LOCKED(gpub, group)
      WALK_TLIST(thread, thr, &group->threads)
      {
	sync->total++;
	ev_send(&thr->priority_events, ev_new_init(sync->pool, bird_thread_sync_one, sync));
	wakeup_do_kick(thr);
      }

  UNLOCK_DOMAIN(control, sync->lock);
}

struct bird_thread_show_data {
  struct bird_thread_syncer sync;
  cli *cli;
  linpool *lp;
  u8 show_loops;
  uint line_pos;
  uint line_max;
  const char **lines;
};

#define tsd_append(...)		do { \
  if (!tsd->lines) \
    tsd->lines = mb_allocz(tsd->sync.pool, sizeof(const char *) * tsd->line_max); \
  if (tsd->line_pos >= tsd->line_max) \
    tsd->lines = mb_realloc(tsd->lines, sizeof (const char *) * (tsd->line_max *= 2)); \
  tsd->lines[tsd->line_pos++] = lp_sprintf(tsd->lp, __VA_ARGS__); \
} while (0)

static void
bird_thread_show_cli_cont(struct cli *c UNUSED)
{
  /* Explicitly do nothing to prevent CLI from trying to parse another command. */
}

static bool
bird_thread_show_cli_cleanup(struct cli *c UNUSED)
{
  /* Defer the cleanup until the writeout is finished. */
  return false;
}

static void
bird_thread_show_spent_time(struct bird_thread_show_data *tsd, const char *name, struct spent_time *st)
{
  char b[TIME_BY_SEC_SIZE * sizeof("1234567890, ")], *bptr = b, *bend = b + sizeof(b);
  uint cs = CURRENT_SEC;
  uint fs = NSEC_TO_SEC(st->last_written_ns);

  for (uint i = 0; i <= cs && i < TIME_BY_SEC_SIZE; i++)
    bptr += bsnprintf(bptr, bend - bptr, "% 10lu ",
	(cs - i > fs) ? 0 : st->by_sec_ns[(cs - i) % TIME_BY_SEC_SIZE]);
  bptr[-1] = 0; /* Drop the trailing space */

  tsd_append("    %s total time: % 9t s; last %d secs [ns]: %s", name, st->total_ns NS, MIN(CURRENT_SEC+1, TIME_BY_SEC_SIZE), b);
}

static void
bird_thread_show_loop(struct bird_thread_show_data *tsd, struct birdloop *loop)
{
  tsd_append("  Loop %s", domain_name(loop->time.domain));
  bird_thread_show_spent_time(tsd, "Working ", &loop->working);
  bird_thread_show_spent_time(tsd, "Locking ", &loop->locking);
}

static void
bird_thread_show(struct bird_thread_syncer *sync)
{
  SKIP_BACK_DECLARE(struct bird_thread_show_data, tsd, sync, sync);

  if (!tsd->lp)
    tsd->lp = lp_new(tsd->sync.pool);

  if (tsd->show_loops)
    tsd_append("Thread %04x %s (busy counter %d)", THIS_THREAD_ID, this_thread->busy_active ? " [busy]" : "", this_thread->busy_counter);

  u64 total_time_ns = 0;

  WALK_TLIST(birdloop, loop, &this_thread->loops)
  {
    if (tsd->show_loops)
      bird_thread_show_loop(tsd, loop);

    total_time_ns += loop->working.total_ns + loop->locking.total_ns;
  }

  if (tsd->show_loops)
  {
    tsd_append("  Total working time: %t", total_time_ns NS);
    bird_thread_show_spent_time(tsd, "Overhead", &this_thread->overhead);
    bird_thread_show_spent_time(tsd, "Idle    ", &this_thread->idle);
  }
  else
    tsd_append("%04x%s     % 9.3t s   % 9.3t s   % 9.3t s",
	THIS_THREAD_ID, this_thread->busy_active ? " [busy]" : "       ",
	total_time_ns NS, this_thread->overhead.total_ns NS,
	(ns_now() - this_thread->meta->last_transition_ns) NS);
}

static void
cmd_show_threads_done(struct bird_thread_syncer *sync)
{
  SKIP_BACK_DECLARE(struct bird_thread_show_data, tsd, sync, sync);
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  /* The client lost their patience and dropped the session early. */
  if (!tsd->cli->sock)
  {
    mb_free(tsd);
    rp_free(tsd->cli->pool);
    return;
  }

  tsd->cli->cont = NULL;
  tsd->cli->cleanup = NULL;

  WALK_TLIST(thread_group, gpub, &global_thread_group_list)
  TG_LOCKED(gpub, group)
  {
    uint count = 0;
    u64 total_time_ns = 0;
    if (!EMPTY_TLIST(birdloop, &group->loops))
    {
      if (tsd->show_loops)
	tsd_append("Unassigned loops in group %s:", group->name);

      WALK_TLIST(birdloop, loop, &group->loops)
      {
	if (tsd->show_loops)
	  bird_thread_show_loop(tsd, loop);

	total_time_ns += loop->working.total_ns + loop->locking.total_ns;
	count++;
      }

      if (tsd->show_loops)
	tsd_append("  Total working time: %t", total_time_ns NS);
      else
	tsd_append("Unassigned %d loops in group %s, total time %t", count, group->name, total_time_ns NS);
    }
    else
      tsd_append("All loops in group %s are assigned.", group->name);
  }

  if (!tsd->show_loops)
    cli_printf(tsd->cli, -1027, "Thread ID       Working         Overhead        Last Pickup/Drop");

  for (uint i = 0; i < tsd->line_pos - 1; i++)
    cli_printf(tsd->cli, -1027, "%s", tsd->lines[i]);

  cli_printf(tsd->cli, 1027, "%s", tsd->lines[tsd->line_pos-1]);
  cli_write_trigger(tsd->cli);
  mb_free(tsd);
}

void
cmd_show_threads(int show_loops)
{
  struct bird_thread_show_data *tsd = mb_allocz(&root_pool, sizeof(struct bird_thread_show_data));
  tsd->cli = this_cli;
  tsd->show_loops = show_loops;
  tsd->line_pos = 0;
  tsd->line_max = 64;

  this_cli->cont = bird_thread_show_cli_cont;
  this_cli->cleanup = bird_thread_show_cli_cleanup;

  bird_thread_sync_all(&tsd->sync, bird_thread_show, cmd_show_threads_done, "Show Threads");
}


/*
  sk_dump_all uses cached info, because we need the dupms quickly and locking
  (especially for thread_group loops) would be too complicated and slow.

  sk_dump_ao_all has a different approach - in each thread we send an event to each loop
  and dump from the loops. We do this because ao dump changes much more often and caching
  would be too frequent. This means ao dump is slower than basic socket dump
  and the basic socket dump should be used for quick debugging.
*/

void
sk_dump_all(struct dump_request *dreq)
{
  RDUMP("Open sockets:\n");
  dreq->indent += 3;

  node *n;
  sock *s;

  /* Dump sockets in main_birdloop */
  WALK_LIST(n, main_birdloop.sock_list)
  {
    s = SKIP_BACK(sock, n, n);
    RDUMP("%p ", s);
    sk_dump(dreq, &s->r);
  }

  /* The rest of birdloops have the socket info cached */
  WALK_TLIST(thread_group, gpub, &global_thread_group_list)
    TG_LOCKED(gpub, group)
      WALK_TLIST(thread, thr, &group->threads)
        WALK_TLIST(birdloop, loop, &thr->loops)
        {
          /* The socket_info might be about to change (and free previous version) right now */
          rcu_read_lock();
            char *info = atomic_load_explicit(&loop->sockets_info, memory_order_relaxed);

            if (info)
              RDUMP(info);
          rcu_read_unlock();
        }

  WALK_TLIST_DELSAFE(thread_group, gpub, &global_thread_group_list)
  TG_LOCKED(gpub, group)
  {
    WALK_TLIST_DELSAFE(birdloop, loop, &group->loops)
    {
      rcu_read_lock();
        char *info = atomic_load_explicit(&loop->sockets_info, memory_order_relaxed);
      rcu_read_unlock();
      if (info)
        RDUMP(info);
    }
  }
  dreq->indent -= 3;
  RDUMP("\n");
}


struct bird_show_ao_socket {
  struct bird_thread_syncer sync;
  struct dump_request *dreq;
  DOMAIN(rtable) lock;
  struct pool *pool;

  _Atomic int dump_finished; // the dump is finished when reached zero
};

struct sk_dump_ao_event {
  event event;
  struct bird_show_ao_socket *bsas;
};

static void
_sk_dump_ao_for_loop(struct bird_show_ao_socket *bsas, list sock_list)
{
  struct dump_request *dreq = bsas->dreq;

  WALK_LIST_(node, n, sock_list)
  {
    sock *s = SKIP_BACK(sock, n, n);

    /* Skip non TCP-AO sockets / not supported */
    if (sk_get_ao_info(s, &(struct ao_info){}) < 0)
      continue;

    RDUMP("\n%p", s);
    sk_dump(dreq, &s->r);
    sk_dump_ao_info(s, dreq);
    sk_dump_ao_keys(s, dreq);
  }

  if (atomic_fetch_sub_explicit(&bsas->dump_finished, 1, memory_order_relaxed) == 1)
  {
    RDUMP("\n");
    mb_free(bsas);
  }
}

static void
sk_dump_ao_for_loop(void *data)
{
  struct sk_dump_ao_event *sdae = (struct sk_dump_ao_event*) data;
  _sk_dump_ao_for_loop(sdae->bsas, birdloop_current->sock_list);
}

static void
_sk_dump_ao_send_event(struct bird_show_ao_socket *bsas)
{
  WALK_TLIST(birdloop, loop, &this_thread->loops)
  {
    struct sk_dump_ao_event *sdae = mb_allocz(bsas->pool, sizeof(struct sk_dump_ao_event));
    sdae->event.hook = sk_dump_ao_for_loop;
    sdae->event.data = sdae;
    sdae->bsas = bsas;
    ev_send_loop(loop, &sdae->event);
  }
}

static void
sk_dump_ao_send_event(struct bird_thread_syncer *sync)
{
  SKIP_BACK_DECLARE(struct bird_show_ao_socket, bsas, sync, sync);
  LOCK_DOMAIN(rtable, bsas->lock);
  _sk_dump_ao_send_event(bsas);
  UNLOCK_DOMAIN(rtable, bsas->lock);
}

static void
sk_dump_ao_thread_sync_done(struct bird_thread_syncer *sync)
{
  SKIP_BACK_DECLARE(struct bird_show_ao_socket, bsas, sync, sync);

  if (atomic_fetch_sub_explicit(&bsas->dump_finished, 1, memory_order_relaxed) == 1)
  {
    struct dump_request *dreq = bsas->dreq;
    RDUMP("\n");
    DOMAIN(rtable) lock = bsas->lock;
    LOCK_DOMAIN(rtable, lock);
    mb_free(bsas->pool);
    UNLOCK_DOMAIN(rtable, lock);
  }
}

void
sk_dump_ao_all(struct dump_request *dreq)
{
  DOMAIN(rtable) lock = DOMAIN_NEW(rtable);
  LOCK_DOMAIN(rtable, lock);

  pool *pool = rp_new(&root_pool, lock.rtable, "Dump socket TCP-AO");

  struct bird_show_ao_socket *bsas = mb_allocz(pool, sizeof(struct bird_show_ao_socket));
  bsas->dreq = dreq;
  bsas->lock = lock;
  bsas->pool = pool;
  atomic_store_explicit(&bsas->dump_finished, 1, memory_order_relaxed);

  RDUMP("TCP-AO listening sockets:\n");
  _sk_dump_ao_for_loop(bsas, main_birdloop.sock_list);

  WALK_TLIST(thread_group, gpub, &global_thread_group_list)
  TG_LOCKED(gpub, group)
  {
    WALK_TLIST(birdloop, loop, &group->loops)
      _sk_dump_ao_send_event(bsas);
  }

  UNLOCK_DOMAIN(rtable, lock);

  bird_thread_sync_all(&bsas->sync, sk_dump_ao_send_event, sk_dump_ao_thread_sync_done, "Show ao sockets");
}


bool task_still_in_limit(void)
{
  static u64 main_counter = 0;
  if (this_birdloop == &main_birdloop)
    return (++main_counter % 2048);	/* This is a hack because of no accounting in mainloop */
  else
    return ns_now() < account_last + this_thread->max_loop_time_ns;
}

bool task_before_halftime(void)
{
  return ns_now() < account_last + this_thread->max_loop_time_ns / 2;
}


/*
 *	Birdloop
 */

static struct bird_thread main_thread;
struct birdloop main_birdloop = { .thread = &main_thread, };
_Thread_local struct birdloop *this_birdloop;

static void birdloop_enter_locked(struct birdloop *loop);

void
birdloop_init(void)
{
  ns_init();

  default_thread_group = mb_allocz(&root_pool, sizeof *default_thread_group);
  *default_thread_group = (thread_group) {
    .priv = {
      .name = "startup",
      .lock = DOMAIN_NEW(attrs),
      .thread_dropper.event = {
	.data = default_thread_group,
      },
    },
  };
  DOMAIN_SETUP(attrs, default_thread_group->priv.lock, "Startup Thread Group", NULL);
  thread_group_add_tail(&global_thread_group_list, default_thread_group);

  wakeup_init(main_birdloop.thread);

  main_birdloop.time.domain = the_bird_domain.the_bird;
  main_birdloop.time.loop = &main_birdloop;

  times_update();
  timers_init(&main_birdloop.time, &root_pool);

  birdloop_enter_locked(&main_birdloop);
  this_birdloop = &main_birdloop;
  this_thread = &main_thread;

  defer_init(lp_new(&root_pool));
}

static void
birdloop_stop_internal(struct birdloop *loop)
{
  LOOP_TRACE(loop, DL_SCHEDULING, "Stopping");

  /* Block incoming pings */
  u32 ltt = atomic_load_explicit(&loop->thread_transition, memory_order_acquire);
  while (!atomic_compare_exchange_strong_explicit(
	&loop->thread_transition, &ltt, LTT_PING,
	memory_order_acq_rel, memory_order_acquire))
    ;

  /* Flush remaining events */
  ASSERT_DIE(!ev_run_list(&loop->event_list));

  /* Drop timers */
  timer *t;
  while (t = timers_first(&loop->time))
    tm_stop(t);

  /* Drop sockets */
  sock *s;
  WALK_LIST_FIRST2(s, n, loop->sock_list)
    birdloop_remove_socket(loop, s);

  /* Unschedule from Meta */
  ev_postpone(&loop->event);
  tm_stop(&loop->timer);

  /* Remove from thread loop list */
  ASSERT_DIE(loop->thread == this_thread);
  birdloop_rem_node(&loop->thread->loops, loop);
  loop->thread = NULL;

  /* Uncount from thread group */
  TG_LOCKED(this_thread->group, group)
    group->loop_count--;

  /* Leave the loop context without causing any other fuss */
  ASSERT_DIE(!ev_active(&loop->event));
  loop->ping_pending = 0;
  account_to(&this_thread->overhead);
  this_birdloop = this_thread->meta;
  birdloop_leave(loop);

  /* Request local socket reload */
  this_thread->sock_changed = 1;

  /* Call the stopped hook from the main loop */
  loop->event.hook = loop->stopped;
  loop->event.data = loop->stop_data;
  ev_send_loop(&main_birdloop, &loop->event);
}

static void
birdloop_run(void *_loop)
{
  /* Run priority events before the loop is executed */
  ev_run_list(&this_thread->priority_events);

  struct birdloop *loop = _loop;
  account_to(&loop->locking);
  birdloop_enter(loop);
  this_birdloop = loop;

  /* Wait until pingers end to wait for all events to actually arrive */
  for (u32 ltt;
      ltt = atomic_load_explicit(&loop->thread_transition, memory_order_acquire);
      )
  {
    ASSERT_DIE(ltt == LTT_PING);
    birdloop_yield();
  }

  if (loop->thread_group != this_thread->group)
  {
    birdloop_rem_node(&this_thread->loops, loop);
    birdloop_set_thread(loop, NULL);
    goto leave;
  }

  /* Now we can actually do some work */
  u64 dif = account_to(&loop->working);

  struct global_runtime *gr = atomic_load_explicit(&global_runtime, memory_order_relaxed);
  if (dif > this_thread->max_loop_time_ns + gr->latency_limit TO_NS)
    LOOP_WARN(loop, "locked %lu us after its scheduled end time", dif NS TO_US);

  uint repeat, loop_runs = 0;
  do {
    LOOP_TRACE(loop, DL_SCHEDULING, "Regular run (%d)", loop_runs);
    loop_runs++;

    if (loop->stopped)
      /* Birdloop left inside the helper function */
      return birdloop_stop_internal(loop);

    /* Process socket TX */
    sockets_fire(loop, 0, 1);

    /* Run timers */
    timers_fire(&loop->time, 0);

    /* Run events */
    repeat = ev_run_list(&loop->event_list);

    /* Process socket RX */
    sockets_fire(loop, 1, 0);

    /* Flush deferred events */
    while (ev_run_list(&loop->defer_list))
      repeat++;

    /* Check end time */
  } while (repeat && task_still_in_limit());

  /* Request meta timer */
  timer *t = timers_first(&loop->time);
  if (t)
    tm_start_in(&loop->timer, tm_remains(t), this_thread->meta);
  else
    tm_stop(&loop->timer);

  /* Request re-run if needed */
  if (repeat)
    ev_send_loop(this_thread->meta, &loop->event);

  /* Collect socket change requests */
  this_thread->sock_changed |= loop->sock_changed;
  loop->sock_changed = 0;

leave:
  account_to(&this_thread->overhead);
  this_birdloop = this_thread->meta;
  birdloop_leave(loop);
}

static void
birdloop_run_timer(timer *tm)
{
  struct birdloop *loop = tm->data;
  LOOP_TRACE(loop, DL_TIMERS, "Meta timer ready, requesting run");
  ev_send_loop(loop->thread->meta, &loop->event);
}

static struct birdloop *
birdloop_vnew_internal(pool *pp, uint order, thread_group *gpub, const char *name, va_list args)
{
  struct domain_generic *dg = domain_new(order);
  DG_LOCK(dg);

  pool *p = rp_vnewf(pp, dg, name, args);
  struct birdloop *loop = mb_allocz(p, sizeof(struct birdloop));
  loop->pool = p;

  loop->time.domain = dg;
  loop->time.loop = loop;

  loop->thread_group = gpub;

  atomic_store_explicit(&loop->thread_transition, 0, memory_order_relaxed);

  birdloop_enter_locked(loop);

  ev_init_list(&loop->event_list, loop, p->name);
  timers_init(&loop->time, p);
  sockets_init(loop);

  loop->event = (event) { .hook = birdloop_run, .data = loop, };
  loop->timer = (timer) { .hook = birdloop_run_timer, .data = loop, };

  LOOP_TRACE(loop, DL_SCHEDULING, "New loop: %s", p->name);

  if (gpub)
    /* Send the loop to the requested thread group for execution */
    TG_LOCKED(gpub, group)
    {
      group->loop_count++;
      group->loop_unassigned_count++;
      birdloop_add_tail(&group->loops, loop);
      if (EMPTY_TLIST(thread, &group->threads))
	/* If no threads are there for the loop, request them to start */
	bird_thread_start_indirect(group);
      else
	/* Just wakeup the first one thread to pick us up */
	wakeup_do_kick(THEAD(thread, &group->threads));
    }

  birdloop_leave(loop);

  return loop;
}

static struct birdloop *
birdloop_new_no_pickup(pool *pp, uint order, const char *name, ...)
{
  va_list args;
  va_start(args, name);
  struct birdloop *loop = birdloop_vnew_internal(pp, order, NULL, name, args);
  va_end(args);
  return loop;
}

struct birdloop *
birdloop_new(pool *pp, uint order, thread_group *group, const char *name, ...)
{
  if (!group)
    group = default_thread_group;

  va_list args;
  va_start(args, name);
  struct birdloop *loop = birdloop_vnew_internal(pp, order, group, name, args);
  va_end(args);
  return loop;
}

static void
birdloop_transfer_dummy_event(void *_data)
{
  rfree(_data);
}

void
birdloop_transfer(struct birdloop *loop, thread_group *from, thread_group *to)
{
  ASSERT_DIE(birdloop_inside(loop));
  if (loop->thread_group != from)
  {
    log(L_WARN "Failed to transfer loop %s from group %s to %s, now in %s",
	LOOP_NAME(loop), from->name, to->name, loop->thread->group->name);
    birdloop_leave(loop);
    return;
  }

  /* Set the new group, actually */
  loop->thread_group = to;

  /* Request the loop to actually do something to get scheduled */
  event *e = ev_new(loop->pool);
  e->hook = birdloop_transfer_dummy_event;
  e->data = e;
  ev_send_loop(loop, e);

  /* Possibly start threads in that group */
  TG_LOCKED(to, group)
    if (EMPTY_TLIST(thread, &group->threads))
      bird_thread_start_indirect(group);
}

static void
birdloop_do_stop(struct birdloop *loop, void (*stopped)(void *data), void *data)
{
  LOOP_TRACE(loop, DL_SCHEDULING, "Stop requested");

  loop->stopped = stopped;
  loop->stop_data = data;

  birdloop_do_ping(loop);
}

void
birdloop_stop(struct birdloop *loop, void (*stopped)(void *data), void *data)
{
  DG_LOCK(loop->time.domain);
  birdloop_do_stop(loop, stopped, data);
  DG_UNLOCK(loop->time.domain);
}

void
birdloop_stop_self(struct birdloop *loop, void (*stopped)(void *data), void *data)
{
  ASSERT_DIE(loop == birdloop_current);
  ASSERT_DIE(DG_IS_LOCKED(loop->time.domain));

  birdloop_do_stop(loop, stopped, data);
}

void
birdloop_free(struct birdloop *loop)
{
  ASSERT_DIE(loop->thread == NULL);

  struct domain_generic *dg = loop->time.domain;
  DG_LOCK(dg);
  rp_free(loop->pool);
  DG_UNLOCK(dg);
  domain_free(dg);
}

static void
birdloop_enter_locked(struct birdloop *loop)
{
  ASSERT_DIE(DG_IS_LOCKED(loop->time.domain));
  ASSERT_DIE(!birdloop_inside(loop));

  /* Store the old context */
  loop->prev_loop = birdloop_current;

  /* Put the new context */
  birdloop_current = loop;
}

void
birdloop_enter(struct birdloop *loop)
{
  DG_LOCK(loop->time.domain);
  return birdloop_enter_locked(loop);
}

static void
birdloop_leave_locked(struct birdloop *loop)
{
  /* Check the current context */
  ASSERT_DIE(birdloop_current == loop);

  /* Send pending pings */
  if (loop->ping_pending)
  {
    LOOP_TRACE(loop, DL_PING, "sending pings on leave");
    loop->ping_pending = 0;
    birdloop_do_ping(loop);
  }

  /* Restore the old context */
  birdloop_current = loop->prev_loop;
}

void
birdloop_leave(struct birdloop *loop)
{
  birdloop_leave_locked(loop);
  DG_UNLOCK(loop->time.domain);
}

void
birdloop_leave_cleanup(struct birdloop **loop)
{
  if (*loop)
    birdloop_leave(*loop);
}

void
birdloop_mask_wakeups(struct birdloop *loop)
{
  ASSERT_DIE(birdloop_wakeup_masked == NULL);
  birdloop_wakeup_masked = loop;
}

void
birdloop_unmask_wakeups(struct birdloop *loop)
{
  ASSERT_DIE(birdloop_wakeup_masked == loop);
  birdloop_wakeup_masked = NULL;
  if (birdloop_wakeup_masked_count)
    wakeup_do_kick(loop->thread);

  birdloop_wakeup_masked_count = 0;
}

void
birdloop_yield(void)
{
  usleep(100);
}

void
ev_send_defer(event *e)
{
  if (this_thread == &main_thread)
    ev_send_loop(&main_birdloop, e);
  else
    ev_send(&this_birdloop->defer_list, e);
}
