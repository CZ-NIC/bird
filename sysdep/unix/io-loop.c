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

u64 ns_now(void)
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts))
    bug("clock_gettime: %m");

  return (u64) (ts.tv_sec - ns_begin.tv_sec) * NSEC_IN_SEC + ts.tv_nsec - ns_begin.tv_nsec;
}

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

static inline void
wakeup_forked(struct bird_thread *thr)
{
  struct pipe new;
  pipe_new(&new);

  /* This is kinda sketchy but there is probably
   * no actual architecture where copying an int
   * would create an invalid inbetween value */
  struct pipe old = thr->wakeup;
  thr->wakeup = new;
  synchronize_rcu();

  pipe_free(&old);
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
socket_changed(sock *s)
{
  struct birdloop *loop = s->loop;
  ASSERT_DIE(birdloop_inside(loop));

  LOOP_TRACE(loop, DL_SOCKETS, "socket %p changed", s);
  loop->sock_changed = 1;
  birdloop_ping(loop);
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

  socket_changed(s);
}

sock *stored_sock; /* mainloop hack */

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

  socket_changed(s);

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
  ASSERT_DIE(!s->rx_paused);
  ASSERT_DIE(s->rx_hook);
  s->rx_paused = s->rx_hook;
  s->rx_hook = NULL;
  socket_changed(s);
}

void
sk_resume_rx(struct birdloop *loop, sock *s)
{
  ASSERT_DIE(birdloop_inside(loop));
  ASSERT_DIE(s->rx_paused);
  ASSERT_DIE(!s->rx_hook);
  s->rx_hook = s->rx_paused;
  s->rx_paused = NULL;
  socket_changed(s);
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

static void bird_thread_start_event(void *_data);
static void bird_thread_busy_set(struct bird_thread *thr, int val);

struct birdloop_pickup_group pickup_groups[2] = {
  {
    /* all zeroes */
    .start_threads.hook = bird_thread_start_event,
  },
  {
    /* FIXME: make this dynamic, now it copies the loop_max_latency value from proto/bfd/config.Y */
    .max_latency = 10 MS,
    .start_threads.hook = bird_thread_start_event,
    .start_threads.data = &pickup_groups[1],
  },
};

_Thread_local struct bird_thread *this_thread;

static void
birdloop_set_thread(struct birdloop *loop, struct bird_thread *thr, struct birdloop_pickup_group *group)
{
  struct bird_thread *old = loop->thread;
  ASSERT_DIE(!thr != !old);

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

  if (!thr)
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
    add_tail(&thr->loops, &loop->n);

    if (!EMPTY_LIST(loop->sock_list))
      thr->sock_changed = 1;
    ev_send_loop(loop->thread->meta, &loop->event);
  }
  else
  {
    /* Put into pickup list */
    LOCK_DOMAIN(attrs, group->domain);
    add_tail(&group->loops, &loop->n);
    group->loop_unassigned_count++;
    UNLOCK_DOMAIN(attrs, group->domain);
  }

  loop->last_transition_ns = ns_now();
}

static void
bird_thread_pickup_next(struct birdloop_pickup_group *group)
{
  /* This thread goes to the end of the pickup list */
  rem_node(&this_thread->n);
  add_tail(&group->threads, &this_thread->n);

  /* If there are more loops to be picked up, wakeup the next thread in order */
  if (!EMPTY_LIST(group->loops))
    wakeup_do_kick(SKIP_BACK(struct bird_thread, n, HEAD(group->threads)));
}

static bool
birdloop_hot_potato(struct birdloop *loop)
{
  if (!loop)
    return 0;

  return ns_now() - loop->last_transition_ns < 1 S TO_NS;
}

static void
birdloop_take(struct birdloop_pickup_group *group)
{
  struct birdloop *loop = NULL;

  LOCK_DOMAIN(attrs, group->domain);

  if (this_thread->busy_active &&
      (group->thread_busy_count < group->thread_count) &&
      (this_thread->loop_count > 1) &&
      (EMPTY_LIST(group->loops) ||
      !birdloop_hot_potato(HEAD(group->loops))))
  {
    THREAD_TRACE(DL_SCHEDULING, "Loop drop requested (tbc=%d, tc=%d, lc=%d)",
	group->thread_busy_count, group->thread_count, this_thread->loop_count);
    UNLOCK_DOMAIN(attrs, group->domain);

    uint dropped = 0;
    node *n, *_nxt;
    WALK_LIST2_DELSAFE(loop, n, _nxt, this_thread->loops, n)
    {
      birdloop_enter(loop);
      if (ev_active(&loop->event) && !loop->stopped && !birdloop_hot_potato(loop))
      {
	/* Pass to another thread */
	rem_node(&loop->n);
	this_thread->loop_count--;
	LOOP_TRACE(loop, DL_SCHEDULING, "Dropping from thread, remaining %u loops here", this_thread->loop_count);

	/* This also unschedules the loop from Meta */
	birdloop_set_thread(loop, NULL, group);

	dropped++;
	if ((dropped * dropped) / 2 > this_thread->loop_count)
	{
	  birdloop_leave(loop);

	  LOCK_DOMAIN(attrs, group->domain);
	  bird_thread_pickup_next(group);
	  UNLOCK_DOMAIN(attrs, group->domain);

	  break;
	}
      }
      birdloop_leave(loop);
    }

    if (dropped)
    {
      this_thread->meta->last_transition_ns = ns_now();
      return;
    }

    this_thread->busy_counter = 0;
    bird_thread_busy_set(this_thread, 0);
    LOCK_DOMAIN(attrs, group->domain);
  }

  if (!EMPTY_LIST(group->loops))
  {
    THREAD_TRACE(DL_SCHEDULING, "Loop take requested");

    /* Take a proportional amount of loops from the pickup list and unlock */
    uint thread_count = group->thread_count + 1;
    if (group->thread_busy_count < group->thread_count)
      thread_count -= group->thread_busy_count;

    uint assign = birdloop_hot_potato(this_thread->meta) ? 1 :
		  1 + group->loop_unassigned_count / thread_count;

    for (uint i=0; !EMPTY_LIST(group->loops) && i<assign; i++)
    {
      loop = SKIP_BACK(struct birdloop, n, HEAD(group->loops));
      rem_node(&loop->n);
      group->loop_unassigned_count--;
      UNLOCK_DOMAIN(attrs, group->domain);

      birdloop_enter(loop);
      birdloop_set_thread(loop, this_thread, group);
      LOOP_TRACE(loop, DL_SCHEDULING, "Picked up by thread");

      node *n;
      WALK_LIST(n, loop->sock_list)
	SKIP_BACK(sock, n, n)->index = -1;

      birdloop_leave(loop);

      LOCK_DOMAIN(attrs, group->domain);
    }

    bird_thread_pickup_next(group);

    if (assign)
      this_thread->meta->last_transition_ns = ns_now();
  }

  UNLOCK_DOMAIN(attrs, group->domain);
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
bird_thread_busy_set(struct bird_thread *thr, int val)
{
  LOCK_DOMAIN(attrs, thr->group->domain);
  if (thr->busy_active = val)
    thr->group->thread_busy_count++;
  else
    thr->group->thread_busy_count--;
  ASSERT_DIE(thr->group->thread_busy_count <= thr->group->thread_count);
  UNLOCK_DOMAIN(attrs, thr->group->domain);
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
  init_list(&thr->loops);

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
    timers_fire(&thr->meta->time);

    /* Pickup new loops */
    birdloop_take(thr->group);

    /* Compute maximal time per loop */
    u64 thr_before_run = ns_now();
    if (thr->loop_count > 0)
    {
      thr->max_loop_time_ns = (thr->max_latency_ns / 2 - (thr_before_run - thr_loop_start)) / (u64) thr->loop_count;
      if (thr->max_loop_time_ns NS > 300 MS)
	thr->max_loop_time_ns = 300 MS TO_NS;
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

      node *nn;
      struct birdloop *loop;
      WALK_LIST2(loop, nn, thr->loops, n)
      {
	birdloop_enter(loop);
	sockets_prepare(loop, &pfd);
	birdloop_leave(loop);
      }

      ASSERT_DIE(pfd.loop.used == pfd.pfd.used);
      THREAD_TRACE(DL_SOCKETS, "Total %d sockets", pfd.pfd.used);
    }

    /* Check thread busy indicator */
    int idle_force = (timeout < 0) || (timeout > 300);
    int busy_now = (timeout < 5) && !idle_force;

    /* Nothing to do right now but there may be some loops for pickup */
    if (idle_force)
    {
      LOCK_DOMAIN(attrs, thr->group->domain);
      if (!EMPTY_LIST(thr->group->loops))
	timeout = 0;
      UNLOCK_DOMAIN(attrs, thr->group->domain);
    }

    if (busy_now && !thr->busy_active && (++thr->busy_counter == 4))
      bird_thread_busy_set(thr, 1);

    if (!busy_now && thr->busy_active && (idle_force || (--thr->busy_counter == 0)))
    {
      thr->busy_counter = 0;
      bird_thread_busy_set(thr, 0);
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
bird_thread_cleanup(void *_thr)
{
  struct bird_thread *thr = _thr;
  struct birdloop *meta = thr->meta;
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
}

static struct bird_thread *
bird_thread_start(struct birdloop_pickup_group *group)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  struct birdloop *meta = birdloop_new_no_pickup(&root_pool, DOMAIN_ORDER(meta), "Thread Meta");
  pool *p = birdloop_pool(meta);

  birdloop_enter(meta);
  LOCK_DOMAIN(attrs, group->domain);

  struct bird_thread *thr = mb_allocz(p, sizeof(*thr));
  thr->pool = p;
  thr->cleanup_event = (event) { .hook = bird_thread_cleanup, .data = thr, };
  thr->group = group;
  thr->max_latency_ns = (group->max_latency ?: 5 S) TO_NS;
  thr->meta = meta;
  thr->meta->thread = thr;

  wakeup_init(thr);
  ev_init_list(&thr->priority_events, NULL, "Thread direct event list");

  add_tail(&group->threads, &thr->n);

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

  UNLOCK_DOMAIN(attrs, group->domain);
  birdloop_leave(meta);
  return thr;
}

static void
bird_thread_start_event(void *_data)
{
  struct birdloop_pickup_group *group = _data;
  if (group)
    bird_thread_start(group);
}

static struct birdloop *thread_dropper;
static event *thread_dropper_event;
static uint thread_dropper_goal;

static void
bird_thread_dropper_free(void *data)
{
  struct birdloop *tdl_stop = data;
  birdloop_free(tdl_stop);
}

static void
bird_thread_shutdown(void * _ UNUSED)
{
  struct birdloop_pickup_group *group = this_thread->group;
  LOCK_DOMAIN(attrs, group->domain);
  int dif = group->thread_count - thread_dropper_goal;
  struct birdloop *tdl_stop = NULL;

  if (dif > 0)
    ev_send_loop(thread_dropper, thread_dropper_event);
  else
  {
    tdl_stop = thread_dropper;
    thread_dropper = NULL;
  }

  UNLOCK_DOMAIN(attrs, group->domain);

  THREAD_TRACE(DL_SCHEDULING, "Thread pickup size differs from dropper goal by %d%s", dif, tdl_stop ? ", stopping" : "");

  if (tdl_stop)
  {
    birdloop_stop_self(tdl_stop, bird_thread_dropper_free, tdl_stop);
    return;
  }

  struct bird_thread *thr = this_thread;

  LOCK_DOMAIN(attrs, group->domain);
  /* Leave the thread-picker list to get no more loops */
  rem_node(&thr->n);
  group->thread_count--;

  /* Fix the busy count */
  if (thr->busy_active)
    group->thread_busy_count--;

  UNLOCK_DOMAIN(attrs, group->domain);

  /* Leave the thread-dropper loop as we aren't going to return. */
  birdloop_leave(thread_dropper);

  /* Last try to run the priority event list; ruin it then to be extra sure */
  ev_run_list(&this_thread->priority_events);
  memset(&this_thread->priority_events, 0xa5, sizeof(this_thread->priority_events));

  /* Drop loops including the thread dropper itself */
  while (!EMPTY_LIST(thr->loops))
  {
    struct birdloop *loop = HEAD(thr->loops);

    /* Remove loop from this thread's list */
    this_thread->loop_count--;
    rem_node(&loop->n);

    /* Unset loop's thread */
    birdloop_set_thread(loop, NULL, group);
  }

  /* Let others know about new loops */
  LOCK_DOMAIN(attrs, group->domain);
  if (!EMPTY_LIST(group->loops))
    wakeup_do_kick(SKIP_BACK(struct bird_thread, n, HEAD(group->threads)));
  UNLOCK_DOMAIN(attrs, group->domain);

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

void
bird_thread_commit(struct thread_config *new)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  if (!new->count)
    new->count = 1;

  while (1)
  {
    struct birdloop_pickup_group *group = &pickup_groups[0];
    LOCK_DOMAIN(attrs, group->domain);

    int dif = group->thread_count - (thread_dropper_goal = new->count);
    bool thread_dropper_running = !!thread_dropper;

    UNLOCK_DOMAIN(attrs, group->domain);

    if (dif < 0)
    {
      bird_thread_start(group);
      continue;
    }

    if ((dif > 0) && !thread_dropper_running)
    {
      struct birdloop *tdl = birdloop_new(&root_pool, DOMAIN_ORDER(control), group->max_latency, "Thread dropper");
      birdloop_enter(tdl);
      event *tde = ev_new_init(tdl->pool, bird_thread_shutdown, NULL);

      LOCK_DOMAIN(attrs, group->domain);
      thread_dropper = tdl;
      thread_dropper_event = tde;
      UNLOCK_DOMAIN(attrs, group->domain);

      ev_send_loop(thread_dropper, thread_dropper_event);
      birdloop_leave(tdl);
    }

    return;
  }
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
  sync->lock = DOMAIN_NEW(control);
  LOCK_DOMAIN(control, sync->lock);

  sync->pool = rp_new(&root_pool, sync->lock.control, name);
  sync->hook = hook;
  sync->finish = done;

  for (int i=0; i<2; i++)
  {
    struct birdloop_pickup_group *group = &pickup_groups[i];

    LOCK_DOMAIN(attrs, group->domain);

    struct bird_thread *thr;
    WALK_LIST(thr, group->threads)
    {
      sync->total++;
      ev_send(&thr->priority_events, ev_new_init(sync->pool, bird_thread_sync_one, sync));
      wakeup_do_kick(thr);
    }

    UNLOCK_DOMAIN(attrs, group->domain);
  }

  UNLOCK_DOMAIN(control, sync->lock);
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

  for (int i=0; i<2; i++)
  {
    struct birdloop_pickup_group *group = &pickup_groups[i];

    group->domain = DOMAIN_NEW(attrs);
    DOMAIN_SETUP(attrs, group->domain, "Loop Pickup", NULL);
    init_list(&group->loops);
    init_list(&group->threads);
  }

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
  rem_node(&loop->n);
  loop->thread = NULL;

  /* Uncount from thread group */
  LOCK_DOMAIN(attrs, this_thread->group->domain);
  this_thread->group->loop_count--;
  UNLOCK_DOMAIN(attrs, this_thread->group->domain);

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
    timers_fire(&loop->time);

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
birdloop_vnew_internal(pool *pp, uint order, struct birdloop_pickup_group *group, const char *name, va_list args)
{
  struct domain_generic *dg = domain_new(order);
  DG_LOCK(dg);

  pool *p = rp_vnewf(pp, dg, name, args);
  struct birdloop *loop = mb_allocz(p, sizeof(struct birdloop));
  loop->pool = p;

  loop->time.domain = dg;
  loop->time.loop = loop;

  atomic_store_explicit(&loop->thread_transition, 0, memory_order_relaxed);

  birdloop_enter_locked(loop);

  ev_init_list(&loop->event_list, loop, p->name);
  timers_init(&loop->time, p);
  sockets_init(loop);

  loop->event = (event) { .hook = birdloop_run, .data = loop, };
  loop->timer = (timer) { .hook = birdloop_run_timer, .data = loop, };

  LOOP_TRACE(loop, DL_SCHEDULING, "New loop: %s", p->name);

  if (group)
  {
    LOCK_DOMAIN(attrs, group->domain);
    group->loop_count++;
    group->loop_unassigned_count++;
    add_tail(&group->loops, &loop->n);
    if (EMPTY_LIST(group->threads))
      ev_send(&global_event_list, &group->start_threads);
    else
      wakeup_do_kick(SKIP_BACK(struct bird_thread, n, HEAD(group->threads)));
    UNLOCK_DOMAIN(attrs, group->domain);
  }
  else
    loop->n.next = loop->n.prev = &loop->n;

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
birdloop_new(pool *pp, uint order, btime max_latency, const char *name, ...)
{
  va_list args;
  va_start(args, name);
  struct birdloop *loop = birdloop_vnew_internal(pp, order, max_latency ? &pickup_groups[1] : &pickup_groups[0], name, args);
  va_end(args);
  return loop;
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

/*
 * Minimalist mainloop with no sockets
 */

void
birdloop_minimalist_main(void)
{
  /* In case we got forked (hack for Flock) */
  wakeup_forked(&main_thread);

  while (1)
  {
    /* Unset ping information */
    atomic_fetch_and_explicit(&main_birdloop.thread_transition, ~LTT_PING, memory_order_acq_rel);

    times_update();
    ev_run_list(&global_event_list);
    ev_run_list(&global_work_list);
    ev_run_list(&main_birdloop.event_list);
    timers_fire(&main_birdloop.time);

    bool events =
      !ev_list_empty(&global_event_list) ||
      !ev_list_empty(&global_work_list) ||
      !ev_list_empty(&main_birdloop.event_list);

    int poll_tout = (events ? 0 : 3000); /* Time in milliseconds */
    timer *t;
    if (t = timers_first(&main_birdloop.time))
    {
      times_update();
      int timeout = (tm_remains(t) TO_MS) + 1;
      poll_tout = MIN(poll_tout, timeout);
    }

    struct pollfd pfd = {
      .fd = main_birdloop.thread->wakeup.fd[0],
      .events = POLLIN,
    };

    int rv = poll(&pfd, 1, poll_tout);
    if ((rv < 0) && (errno != EINTR) && (errno != EAGAIN))
      bug("poll in main birdloop: %m");

    /* Drain wakeup fd */
    if (pfd.revents & POLLIN)
    {
      THREAD_TRACE(DL_WAKEUP, "Ping received");
      ASSERT_DIE(rv == 1);
      wakeup_drain(main_birdloop.thread);
    }
  }
}
