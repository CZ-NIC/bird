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

static struct timespec ns_begin;

static void ns_init(void)
{
  if (clock_gettime(CLOCK_MONOTONIC, &ns_begin))
    bug("clock_gettime: %m");
}

#define NSEC_IN_SEC	((u64) (1000 * 1000 * 1000))

static u64 ns_now(void)
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts))
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

#define LOOP_TRACE(loop, fmt, args...)	do { if (config && config->latency_debug) log(L_TRACE "%s (%p): " fmt, LOOP_NAME(loop), (loop), ##args); } while (0)
#define THREAD_TRACE(...)		do { if (config && config->latency_debug) log(L_TRACE "Thread: " __VA_ARGS__); } while (0)

#define LOOP_WARN(loop, fmt, args...)	log(L_TRACE "%s (%p): " fmt, LOOP_NAME(loop), (loop), ##args)


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

_Bool
birdloop_inside(struct birdloop *loop)
{
  for (struct birdloop *c = birdloop_current; c; c = c->prev_loop)
    if (loop == c)
      return 1;

  return 0;
}

_Bool
birdloop_in_this_thread(struct birdloop *loop)
{
  return pthread_equal(pthread_self(), loop->thread->thread_id);
}

void
birdloop_flag(struct birdloop *loop, u32 flag)
{
  atomic_fetch_or_explicit(&loop->flags, flag, memory_order_acq_rel);
  birdloop_ping(loop);
}

void
birdloop_flag_set_handler(struct birdloop *loop, struct birdloop_flag_handler *fh)
{
  ASSERT_DIE(birdloop_inside(loop));
  loop->flag_handler = fh;
}

static int
birdloop_process_flags(struct birdloop *loop)
{
  if (!loop->flag_handler)
    return 0;

  u32 flags = atomic_exchange_explicit(&loop->flags, 0, memory_order_acq_rel);
  if (!flags)
    return 0;

  loop->flag_handler->hook(loop->flag_handler, flags);
  return 1;
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

static inline _Bool
birdloop_try_ping(struct birdloop *loop, u32 ltt)
{
  /* Somebody else is already pinging, be idempotent */
  if (ltt & LTT_PING)
  {
    LOOP_TRACE(loop, "already being pinged");
    return 0;
  }

  /* Thread moving is an implicit ping */
  if (ltt & LTT_MOVE)
  {
    LOOP_TRACE(loop, "ping while moving");
    return 1;
  }

  /* No more flags allowed */
  ASSERT_DIE(!ltt);

  /* No ping when not picked up */
  if (!loop->thread)
  {
    LOOP_TRACE(loop, "not picked up yet, can't ping");
    return 1;
  }

  /* No ping when masked */
  if (loop == birdloop_wakeup_masked)
  {
    LOOP_TRACE(loop, "wakeup masked, can't ping");
    birdloop_wakeup_masked_count++;
    return 1;
  }

  /* Send meta event to ping */
  if ((loop != loop->thread->meta) && (loop != &main_birdloop))
  {
    LOOP_TRACE(loop, "Ping by meta event to %p", loop->thread->meta);
    ev_send_loop(loop->thread->meta, &loop->event);
    return 1;
  }

  /* Do the real ping */
  LOOP_TRACE(loop, "sending pipe ping");
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
    LOOP_TRACE(loop, "ping from outside");
    birdloop_do_ping(loop);
  }
  else
  {
    LOOP_TRACE(loop, "ping from inside, pending=%d", loop->ping_pending);
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

  loop->sock_changed++;
  birdloop_ping(loop);
}

void
birdloop_add_socket(struct birdloop *loop, sock *s)
{
  ASSERT_DIE(birdloop_inside(loop));
  ASSERT_DIE(!s->loop);

  LOOP_TRACE(loop, "adding socket %p (total=%d)", s, loop->sock_num);
  add_tail(&loop->sock_list, &s->n);
  loop->sock_num++;

  s->loop = loop;
  s->index = -1;

  socket_changed(s);
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
  LOOP_TRACE(loop, "removing socket %p (total=%d)", s, loop->sock_num);

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
  s->rx_hook = NULL;
  socket_changed(s);
}

void
sk_resume_rx(struct birdloop *loop, sock *s, int (*hook)(sock *, uint))
{
  ASSERT_DIE(birdloop_inside(loop));
  ASSERT_DIE(hook);
  s->rx_hook = hook;
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
    sock *s = SKIP_BACK(sock, n, n);
    uint w = sk_want_events(s);

    if (!w)
    {
      s->index = -1;
      continue;
    }

    s->index = pfd->pfd.used;
    LOOP_TRACE(loop, "socket %p poll index is %d", s, s->index);

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

static int
sockets_fire(struct birdloop *loop)
{
  if (EMPTY_LIST(loop->sock_list))
    return 0;

  int repeat = 0;

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

      if (rev & POLLOUT)
      {
	/* Write everything. */
	while ((s == loop->sock_active) && (e = sk_write(s)))
	  ;

	if (s != loop->sock_active)
	  continue;

	if (!sk_tx_pending(s))
	  loop->thread->sock_changed++;
      }

      if (rev & POLLIN)
	/* Read just one packet and request repeat. */
	if ((s == loop->sock_active) && s->rx_hook)
	  if (sk_read(s, rev))
	    repeat++;

      if (s != loop->sock_active)
	continue;

      if (!(rev & (POLLOUT | POLLIN)) && (rev & POLLERR))
	sk_err(s, rev);

      if (s != loop->sock_active)
	continue;
    }

    loop->sock_active = sk_next(s);
  }

  return repeat;
}

/*
 *	Threads
 */

DEFINE_DOMAIN(resource);
static void bird_thread_start_event(void *_data);

struct birdloop_pickup_group {
  DOMAIN(resource) domain;
  list loops;
  list threads;
  uint thread_count;
  uint loop_count;
  btime max_latency;
  event start_threads;
} pickup_groups[2] = {
  {
    /* all zeroes */
  },
  {
    /* FIXME: make this dynamic, now it copies the loop_max_latency value from proto/bfd/config.Y */
    .max_latency = 10 MS,
    .start_threads.hook = bird_thread_start_event,
    .start_threads.data = &pickup_groups[1],
  },
};

static _Thread_local struct bird_thread *this_thread;

static void
birdloop_set_thread(struct birdloop *loop, struct bird_thread *thr, struct birdloop_pickup_group *group)
{
  struct bird_thread *old = loop->thread;
  ASSERT_DIE(!thr != !old);

  /* Signal our moving effort */
  u32 ltt = atomic_fetch_or_explicit(&loop->thread_transition, LTT_MOVE, memory_order_acq_rel);
  ASSERT_DIE((ltt & LTT_MOVE) == 0);

  while (ltt & LTT_PING)
  {
    birdloop_yield();
    ltt = atomic_load_explicit(&loop->thread_transition, memory_order_acquire);
    ASSERT_DIE(ltt & LTT_MOVE);
  }
  /* Now we are free of running pings */

  if (loop->thread = thr)
  {
    add_tail(&thr->loops, &loop->n);
    thr->loop_count++;
  }
  else
  {
    old->loop_count--;

    LOCK_DOMAIN(resource, group->domain);
    add_tail(&group->loops, &loop->n);
    UNLOCK_DOMAIN(resource, group->domain);
  }

  /* Finished */
  atomic_fetch_and_explicit(&loop->thread_transition, ~LTT_MOVE, memory_order_acq_rel);

  /* Request to run by force */
  ev_send_loop(loop->thread->meta, &loop->event);
}

static struct birdloop *
birdloop_take(struct birdloop_pickup_group *group)
{
  struct birdloop *loop = NULL;

  LOCK_DOMAIN(resource, group->domain);
  if (!EMPTY_LIST(group->loops))
  {
    /* Take the first loop from the pickup list and unlock */
    loop = SKIP_BACK(struct birdloop, n, HEAD(group->loops));
    rem_node(&loop->n);
    UNLOCK_DOMAIN(resource, group->domain);

    birdloop_set_thread(loop, this_thread, group);

    /* This thread goes to the end of the pickup list */
    LOCK_DOMAIN(resource, group->domain);
    rem_node(&this_thread->n);
    add_tail(&group->threads, &this_thread->n);

    /* If there are more loops to be picked up, wakeup the next thread in order */
    if (!EMPTY_LIST(group->loops))
      wakeup_do_kick(SKIP_BACK(struct bird_thread, n, HEAD(group->threads)));
  }
  UNLOCK_DOMAIN(resource, group->domain);

  return loop;
}

static void
birdloop_drop(struct birdloop *loop, struct birdloop_pickup_group *group)
{
  /* Remove loop from this thread's list */
  rem_node(&loop->n);

  /* Unset loop's thread */
  if (birdloop_inside(loop))
    birdloop_set_thread(loop, NULL, group);
  else
  {
    birdloop_enter(loop);
    birdloop_set_thread(loop, NULL, group);
    birdloop_leave(loop);
  }

  /* Put loop into pickup list */
  LOCK_DOMAIN(resource, group->domain);
  add_tail(&group->loops, &loop->n);
  UNLOCK_DOMAIN(resource, group->domain);
}

static int
poll_timeout(struct birdloop *loop)
{
  timer *t = timers_first(&loop->time);
  if (!t)
    return -1;

  btime remains = tm_remains(t);
  return remains TO_MS + ((remains TO_MS) MS < remains);
}

static void *
bird_thread_main(void *arg)
{
  struct bird_thread *thr = this_thread = arg;

  rcu_thread_start(&thr->rcu);
  synchronize_rcu();

  account_to(&thr->overhead);

  birdloop_enter(thr->meta);

  tmp_init(thr->pool, birdloop_domain(thr->meta));
  init_list(&thr->loops);

  thr->sock_changed = 1;

  struct pfd pfd;
  BUFFER_INIT(pfd.pfd, thr->pool, 16);
  BUFFER_INIT(pfd.loop, thr->pool, 16);
  thr->pfd = &pfd;

  while (1)
  {
    u64 thr_loop_start = ns_now();
    int timeout;

    /* Pickup new loops */
    struct birdloop *loop = birdloop_take(thr->group);
    if (loop)
    {
      birdloop_enter(loop);
      if (!EMPTY_LIST(loop->sock_list))
	thr->sock_changed = 1;
      birdloop_leave(loop);
    }

    /* Schedule all loops with timed out timers */
    timers_fire(&thr->meta->time, 0);

    /* Compute maximal time per loop */
    u64 thr_before_run = ns_now();
    if (thr->loop_count > 0)
      thr->max_loop_time_ns = (thr->max_latency_ns / 2 - (thr_before_run - thr_loop_start)) / (u64) thr->loop_count;

    /* Run all scheduled loops */
    int more_events = ev_run_list(&thr->meta->event_list);
    if (more_events)
    {
      THREAD_TRACE("More events to run");
      timeout = 0;
    }
    else
    {
      timeout = poll_timeout(thr->meta);
      if (timeout == -1)
	THREAD_TRACE("No timers, no events");
      else
	THREAD_TRACE("Next timer in %d ms", timeout);
    }

    /* Run priority events before sleeping */
    ev_run_list(&thr->priority_events);

    /* Do we have to refresh sockets? */
    if (thr->sock_changed)
    {
      thr->sock_changed = 0;

      BUFFER_FLUSH(pfd.pfd);
      BUFFER_FLUSH(pfd.loop);

      pipe_pollin(&thr->wakeup, &pfd);

      node *nn;
      WALK_LIST2(loop, nn, thr->loops, n)
      {
	birdloop_enter(loop);
	sockets_prepare(loop, &pfd);
	birdloop_leave(loop);
      }

      ASSERT_DIE(pfd.loop.used == pfd.pfd.used);
    }
    /* Nothing to do in at least 5 seconds, flush local hot page cache */
    else if (timeout > 5000)
      flush_local_pages();

poll_retry:;
    int rv = poll(pfd.pfd.data, pfd.pfd.used, timeout);
    if (rv < 0)
    {
      if (errno == EINTR || errno == EAGAIN)
	goto poll_retry;
      bug("poll in %p: %m", thr);
    }

    /* Drain wakeup fd */
    if (pfd.pfd.data[0].revents & POLLIN)
    {
      ASSERT_DIE(rv > 0);
      rv--;
      wakeup_drain(thr);
    }

    atomic_fetch_and_explicit(&thr->meta->thread_transition, ~LTT_PING, memory_order_acq_rel);

    /* Schedule loops with active sockets */
    if (rv)
      for (uint i = 1; i < pfd.pfd.used; i++)
	if (pfd.pfd.data[i].revents)
	{
	  LOOP_TRACE(pfd.loop.data[i], "socket id %d got revents=%d", i, pfd.pfd.data[i].revents);
	  ev_send_loop(thr->meta, &pfd.loop.data[i]->event);
	}
  }

  bug("An infinite loop has ended.");
}

static void
bird_thread_cleanup(void *_thr)
{
  struct bird_thread *thr = _thr;
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  /* Thread attributes no longer needed */
  pthread_attr_destroy(&thr->thread_attr);

  /* Free all remaining memory */
  rp_free(thr->pool);
}

static struct bird_thread *
bird_thread_start(struct birdloop_pickup_group *group)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  struct birdloop *meta = birdloop_new_no_pickup(&root_pool, DOMAIN_ORDER(meta), "Thread Meta");
  pool *p = birdloop_pool(meta);

  birdloop_enter(meta);
  LOCK_DOMAIN(resource, group->domain);

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

  UNLOCK_DOMAIN(resource, group->domain);
  birdloop_leave(meta);
  return thr;
}

static void
bird_thread_start_event(void *_data)
{
  struct birdloop_pickup_group *group = _data;
  bird_thread_start(group);
}

static struct birdloop *thread_dropper;
static event *thread_dropper_event;
static uint thread_dropper_goal;

static void
bird_thread_shutdown(void * _ UNUSED)
{
  struct birdloop_pickup_group *group = this_thread->group;
  LOCK_DOMAIN(resource, group->domain);
  int dif = group->thread_count - thread_dropper_goal;
  struct birdloop *tdl_stop = NULL;

  if (dif > 0)
    ev_send_loop(thread_dropper, thread_dropper_event);
  else
  {
    tdl_stop = thread_dropper;
    thread_dropper = NULL;
  }

  UNLOCK_DOMAIN(resource, group->domain);

  DBG("Thread pickup size differs from dropper goal by %d%s\n", dif, tdl_stop ? ", stopping" : "");

  if (tdl_stop)
  {
    birdloop_stop_self(tdl_stop, NULL, NULL);
    return;
  }

  struct bird_thread *thr = this_thread;

  /* Leave the thread-picker list to get no more loops */
  LOCK_DOMAIN(resource, group->domain);
  rem_node(&thr->n);
  group->thread_count--;
  UNLOCK_DOMAIN(resource, group->domain);

  /* Drop loops including the thread dropper itself */
  while (!EMPTY_LIST(thr->loops))
    birdloop_drop(HEAD(thr->loops), group);

  /* Let others know about new loops */
  LOCK_DOMAIN(resource, group->domain);
  if (!EMPTY_LIST(group->loops))
    wakeup_do_kick(SKIP_BACK(struct bird_thread, n, HEAD(group->threads)));
  UNLOCK_DOMAIN(resource, group->domain);

  /* Leave the thread-dropper loop as we aren't going to return. */
  birdloop_leave(thread_dropper);

  /* Stop the meta loop */
  birdloop_leave(thr->meta);
  domain_free(thr->meta->time.domain);
  rp_free(thr->meta->pool);

  /* Local pages not needed anymore */
  flush_local_pages();

  /* Unregister from RCU */
  rcu_thread_stop(&thr->rcu);

  /* Request thread cleanup from main loop */
  ev_send_loop(&main_birdloop, &thr->cleanup_event);

  /* Exit! */
  pthread_exit(NULL);
}


void
bird_thread_commit(struct config *new, struct config *old UNUSED)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  if (new->shutdown)
    return;

  if (!new->thread_count)
    new->thread_count = 1;

  while (1)
  {
    struct birdloop_pickup_group *group = &pickup_groups[0];
    LOCK_DOMAIN(resource, group->domain);

    int dif = group->thread_count - (thread_dropper_goal = new->thread_count);
    _Bool thread_dropper_running = !!thread_dropper;

    UNLOCK_DOMAIN(resource, group->domain);

    if (dif < 0)
    {
      bird_thread_start(group);
      continue;
    }

    if ((dif > 0) && !thread_dropper_running)
    {
      struct birdloop *tdl = birdloop_new(&root_pool, DOMAIN_ORDER(control), group->max_latency, "Thread dropper");
      event *tde = ev_new_init(tdl->pool, bird_thread_shutdown, NULL);

      LOCK_DOMAIN(resource, group->domain);
      thread_dropper = tdl;
      thread_dropper_event = tde;
      UNLOCK_DOMAIN(resource, group->domain);

      ev_send_loop(thread_dropper, thread_dropper_event);
    }

    return;
  }
}


DEFINE_DOMAIN(control);

struct bird_thread_show_data {
  cli *cli;
  pool *pool;
  DOMAIN(control) lock;
  uint total;
  uint done;
  event finish_event;
  u8 show_loops;
};

static void
bird_thread_show_cli_cont(struct cli *c UNUSED)
{
  /* Explicitly do nothing to prevent CLI from trying to parse another command. */
}

static int
bird_thread_show_cli_cleanup(struct cli *c UNUSED)
{
  return 1; /* Defer the cleanup until the writeout is finished. */
}

static void
bird_thread_show_spent_time(struct cli *c, const char *name, struct spent_time *st)
{
  char b[TIME_BY_SEC_SIZE * sizeof("1234567890, ")], *bptr = b, *bend = b + sizeof(b);
  uint cs = CURRENT_SEC;
  uint fs = NSEC_TO_SEC(st->last_written_ns);

  for (uint i = 0; i <= cs && i < TIME_BY_SEC_SIZE; i++)
    bptr += bsnprintf(bptr, bend - bptr, "% 10lu ",
	(cs - i > fs) ? 0 : st->by_sec_ns[(cs - i) % TIME_BY_SEC_SIZE]);
  bptr[-1] = 0; /* Drop the trailing space */

  cli_printf(c, -1026, "    %s total time: % 9t s; last %d secs [ns]: %s", name, st->total_ns NS, MIN(CURRENT_SEC+1, TIME_BY_SEC_SIZE), b);
}

static void
bird_thread_show_loop(struct cli *c, struct birdloop *loop)
{
  cli_printf(c, -1026, "  Loop %s", domain_name(loop->time.domain));
  bird_thread_show_spent_time(c, "    Working", &loop->working);
  bird_thread_show_spent_time(c, "    Locking", &loop->locking);
}

static void
bird_thread_show(void *data)
{
  struct bird_thread_show_data *tsd = data;

  LOCK_DOMAIN(control, tsd->lock);
  if (tsd->show_loops)
    cli_printf(tsd->cli, -1026, "Thread %p", this_thread);

  u64 total_time_ns = 0;
  struct birdloop *loop;
  WALK_LIST(loop, this_thread->loops)
  {
    if (tsd->show_loops)
      bird_thread_show_loop(tsd->cli, loop);
    
    total_time_ns += loop->working.total_ns + loop->locking.total_ns;
  }

  int last = (++tsd->done == tsd->total);

  if (tsd->show_loops)
  {
    cli_printf(tsd->cli, (last ? 1 : -1) * 1026, "  Total working time: %t", total_time_ns NS);
    bird_thread_show_spent_time(tsd->cli, "  Overhead", &this_thread->overhead);
  }
  else
    cli_printf(tsd->cli, (last ? 1 : -1) * 1026, "Thread %p working %t s overhead %t s",
	this_thread, total_time_ns NS, this_thread->overhead.total_ns NS);

  if (last)
  {
    tsd->cli->cont = NULL;
    tsd->cli->cleanup = NULL;
    ev_send(&global_event_list, &tsd->finish_event);
  }

  UNLOCK_DOMAIN(control, tsd->lock);
}

static void
bird_thread_show_finish(void *data)
{
  struct bird_thread_show_data *tsd = data;

    for (int i=0; i<2; i++)
    {
      struct birdloop_pickup_group *group = &pickup_groups[i];

      LOCK_DOMAIN(resource, group->domain);
      uint count = 0;
      u64 total_time_ns = 0;
      if (!EMPTY_LIST(group->loops))
      {
	if (tsd->show_loops)
	  cli_printf(tsd->cli, -1026, "Unassigned loops:");

	struct birdloop *loop;
	WALK_LIST(loop, group->loops)
	{
	  if (tsd->show_loops)
	    bird_thread_show_loop(tsd->cli, loop);

	  total_time_ns += loop->working.total_ns + loop->locking.total_ns;
	  count++;
	}

	if (tsd->show_loops)
	  cli_printf(tsd->cli, 1026, "  Total working time: %t", total_time_ns NS);
	else
	  cli_printf(tsd->cli, 1026, "Unassigned %d loops, total time %t", count, total_time_ns NS);
      }
      else
	cli_printf(tsd->cli, 1026, "All loops are assigned.");

      UNLOCK_DOMAIN(resource, group->domain);
    }

    cli_write_trigger(tsd->cli);

    DOMAIN(control) lock = tsd->lock;
    LOCK_DOMAIN(control, lock);
    rp_free(tsd->pool);
    UNLOCK_DOMAIN(control, lock);
    DOMAIN_FREE(control, lock);
}

void
cmd_show_threads(int show_loops)
{
  DOMAIN(control) lock = DOMAIN_NEW(control);
  LOCK_DOMAIN(control, lock);
  pool *p = rp_new(&root_pool, lock.control, "Show Threads");

  struct bird_thread_show_data *tsd = mb_allocz(p, sizeof(struct bird_thread_show_data));
  tsd->cli = this_cli;
  tsd->pool = p;
  tsd->lock = lock;
  tsd->show_loops = show_loops;
  tsd->finish_event = (event) {
    .hook = bird_thread_show_finish,
    .data = tsd,
  };

  this_cli->cont = bird_thread_show_cli_cont;
  this_cli->cleanup = bird_thread_show_cli_cleanup;

  for (int i=0; i<2; i++)
  {
    struct birdloop_pickup_group *group = &pickup_groups[i];

    LOCK_DOMAIN(resource, group->domain);

    struct bird_thread *thr;
    WALK_LIST(thr, group->threads)
    {
      tsd->total++;
      ev_send(&thr->priority_events, ev_new_init(p, bird_thread_show, tsd));
      wakeup_do_kick(thr);
    }

    UNLOCK_DOMAIN(resource, group->domain);
  }

  UNLOCK_DOMAIN(control, lock);
}

/*
 *	Birdloop
 */

static struct bird_thread main_thread;
struct birdloop main_birdloop = { .thread = &main_thread, };

static void birdloop_enter_locked(struct birdloop *loop);

void
birdloop_init(void)
{
  ns_init();

  for (int i=0; i<2; i++)
  {
    struct birdloop_pickup_group *group = &pickup_groups[i];

    group->domain = DOMAIN_NEW(resource);
    DOMAIN_SETUP(resource, group->domain, "Loop Pickup", NULL);
    init_list(&group->loops);
    init_list(&group->threads);
  }

  wakeup_init(main_birdloop.thread);

  main_birdloop.time.domain = the_bird_domain.the_bird;
  main_birdloop.time.loop = &main_birdloop;

  times_update();
  timers_init(&main_birdloop.time, &root_pool);

  birdloop_enter_locked(&main_birdloop);
}

static void
birdloop_stop_internal(struct birdloop *loop)
{
  LOOP_TRACE(loop, "Stopping");

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
  LOCK_DOMAIN(resource, this_thread->group->domain);
  this_thread->group->loop_count--;
  UNLOCK_DOMAIN(resource, this_thread->group->domain);

  /* Leave the loop context without causing any other fuss */
  ASSERT_DIE(!ev_active(&loop->event));
  loop->ping_pending = 0;
  account_to(&this_thread->overhead);
  birdloop_leave(loop);

  /* Request local socket reload */
  this_thread->sock_changed++;

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
  u64 dif = account_to(&loop->working);

  if (dif > this_thread->max_loop_time_ns)
    LOOP_WARN(loop, "locked %lu ns after its scheduled end time", dif);

  uint repeat, loop_runs = 0;
  do {
    repeat = 0;
    LOOP_TRACE(loop, "Regular run");
    loop_runs++;

    if (loop->stopped)
      /* Birdloop left inside the helper function */
      return birdloop_stop_internal(loop);

    /* Process sockets */
    repeat += sockets_fire(loop);

    /* Run timers */
    timers_fire(&loop->time, 0);

    /* Run flag handlers */
    repeat += birdloop_process_flags(loop);

    /* Run events */
    repeat += ev_run_list(&loop->event_list);

    /* Check end time */
  } while (repeat && (ns_now() < account_last + this_thread->max_loop_time_ns));

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
  this_thread->sock_changed += loop->sock_changed;
  loop->sock_changed = 0;

  account_to(&this_thread->overhead);
  birdloop_leave(loop);
}

static void
birdloop_run_timer(timer *tm)
{
  struct birdloop *loop = tm->data;
  LOOP_TRACE(loop, "Timer ready, requesting run");
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

  ev_init_list(&loop->event_list, loop, name);
  timers_init(&loop->time, p);
  sockets_init(loop);

  loop->event = (event) { .hook = birdloop_run, .data = loop, };
  loop->timer = (timer) { .hook = birdloop_run_timer, .data = loop, };

  if (group)
  {
    LOCK_DOMAIN(resource, group->domain);
    group->loop_count++;
    add_tail(&group->loops, &loop->n);
    if (EMPTY_LIST(group->threads))
      ev_send(&global_event_list, &group->start_threads);
    wakeup_do_kick(SKIP_BACK(struct bird_thread, n, HEAD(group->threads)));
    UNLOCK_DOMAIN(resource, group->domain);
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
  LOOP_TRACE(loop, "Stop requested");

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
    LOOP_TRACE(loop, "sending pings on leave");
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
