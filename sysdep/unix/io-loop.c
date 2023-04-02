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

static struct birdloop *birdloop_new_internal(pool *pp, uint order, const char *name, int request_pickup);

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

static u64 ns_now(void)
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts))
    bug("clock_gettime: %m");

  return (u64) (ts.tv_sec - ns_begin.tv_sec) * 1000000000 + ts.tv_nsec - ns_begin.tv_nsec;
}


/*
 *	Current thread context
 */

_Thread_local struct birdloop *birdloop_current;
static _Thread_local struct birdloop *birdloop_wakeup_masked;
static _Thread_local uint birdloop_wakeup_masked_count;

#define LOOP_TRACE(loop, fmt, args...)	do { if (config && config->latency_debug) log(L_TRACE "%s (%p): " fmt, domain_name((loop)->time.domain), (loop), ##args); } while (0)
#define THREAD_TRACE(...)		do { if (config && config->latency_debug) log(L_TRACE "Thread: " __VA_ARGS__); } while (0)

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

  int sch = 0;

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
	while ((s == loop->sock_active) && (e = sk_write(s)))
	  ;

	if (s != loop->sock_active)
	  continue;

	if (!sk_tx_pending(s))
	  sch++;
      }

      if (rev & POLLIN)
	while (e && (s == loop->sock_active) && s->rx_hook)
	  e = sk_read(s, rev);

      if (s != loop->sock_active)
	continue;

      if (!(rev & (POLLOUT | POLLIN)) && (rev & POLLERR))
	sk_err(s, rev);

      if (s != loop->sock_active)
	continue;
    }

    loop->sock_active = sk_next(s);
  }

  return sch;
}

/*
 *	Threads
 */

DEFINE_DOMAIN(resource);
static DOMAIN(resource) birdloop_domain;
static list birdloop_pickup;
static list bird_thread_pickup;

static _Thread_local struct bird_thread *this_thread;

static void
birdloop_set_thread(struct birdloop *loop, struct bird_thread *thr)
{
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
    add_tail(&thr->loops, &loop->n);
  else
  {
    LOCK_DOMAIN(resource, birdloop_domain);
    add_tail(&birdloop_pickup, &loop->n);
    UNLOCK_DOMAIN(resource, birdloop_domain);
  }

  /* Finished */
  atomic_fetch_and_explicit(&loop->thread_transition, ~LTT_MOVE, memory_order_acq_rel);

  /* Request to run by force */
  ev_send_loop(loop->thread->meta, &loop->event);
}

static struct birdloop *
birdloop_take(void)
{
  struct birdloop *loop = NULL;

  LOCK_DOMAIN(resource, birdloop_domain);
  if (!EMPTY_LIST(birdloop_pickup))
  {
    /* Take the first loop from the pickup list and unlock */
    loop = SKIP_BACK(struct birdloop, n, HEAD(birdloop_pickup));
    rem_node(&loop->n);
    UNLOCK_DOMAIN(resource, birdloop_domain);

    birdloop_set_thread(loop, this_thread);

    /* This thread goes to the end of the pickup list */
    LOCK_DOMAIN(resource, birdloop_domain);
    rem_node(&this_thread->n);
    add_tail(&bird_thread_pickup, &this_thread->n);

    /* If there are more loops to be picked up, wakeup the next thread in order */
    if (!EMPTY_LIST(birdloop_pickup))
      wakeup_do_kick(SKIP_BACK(struct bird_thread, n, HEAD(bird_thread_pickup)));
  }
  UNLOCK_DOMAIN(resource, birdloop_domain);

  return loop;
}

static void
birdloop_drop(struct birdloop *loop)
{
  /* Remove loop from this thread's list */
  rem_node(&loop->n);

  /* Unset loop's thread */
  if (birdloop_inside(loop))
    birdloop_set_thread(loop, NULL);
  else
  {
    birdloop_enter(loop);
    birdloop_set_thread(loop, NULL);
    birdloop_leave(loop);
  }

  /* Put loop into pickup list */
  LOCK_DOMAIN(resource, birdloop_domain);
  add_tail(&birdloop_pickup, &loop->n);
  UNLOCK_DOMAIN(resource, birdloop_domain);
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

  tmp_init(thr->pool);
  init_list(&thr->loops);

  thr->meta = birdloop_new_internal(thr->pool, DOMAIN_ORDER(meta), "Thread Meta", 0);
  thr->meta->thread = thr;
  birdloop_enter(thr->meta);

  thr->sock_changed = 1;

  struct pfd pfd;
  BUFFER_INIT(pfd.pfd, thr->pool, 16);
  BUFFER_INIT(pfd.loop, thr->pool, 16);
  thr->pfd = &pfd;

  while (1)
  {
    int timeout;

    /* Pickup new loops */
    struct birdloop *loop = birdloop_take();
    if (loop)
    {
      birdloop_enter(loop);
      if (!EMPTY_LIST(loop->sock_list))
	thr->sock_changed = 1;
      birdloop_leave(loop);
    }

    /* Schedule all loops with timed out timers */
    timers_fire(&thr->meta->time, 0);

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
  rfree(thr->pool);
}

static struct bird_thread *
bird_thread_start(void)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  pool *p = rp_new(&root_pool, "Thread");

  struct bird_thread *thr = mb_allocz(p, sizeof(*thr));
  thr->pool = p;
  thr->cleanup_event = (event) { .hook = bird_thread_cleanup, .data = thr, };

  wakeup_init(thr);
  ev_init_list(&thr->priority_events, NULL, "Thread direct event list");

  LOCK_DOMAIN(resource, birdloop_domain);
  add_tail(&bird_thread_pickup, &thr->n);
  UNLOCK_DOMAIN(resource, birdloop_domain);

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

  return thr;
}

static struct birdloop *thread_dropper;
static event *thread_dropper_event;
static uint thread_dropper_goal;

static void
bird_thread_shutdown(void * _ UNUSED)
{
  LOCK_DOMAIN(resource, birdloop_domain);
  int dif = list_length(&bird_thread_pickup) - thread_dropper_goal;
  struct birdloop *tdl_stop = NULL;

  if (dif > 0)
    ev_send_loop(thread_dropper, thread_dropper_event);
  else
  {
    tdl_stop = thread_dropper;
    thread_dropper = NULL;
  }

  UNLOCK_DOMAIN(resource, birdloop_domain);

  DBG("Thread pickup size differs from dropper goal by %d%s\n", dif, tdl_stop ? ", stopping" : "");

  if (tdl_stop)
  {
    birdloop_stop_self(tdl_stop, NULL, NULL);
    return;
  }

  struct bird_thread *thr = this_thread;

  /* Leave the thread-picker list to get no more loops */
  LOCK_DOMAIN(resource, birdloop_domain);
  rem_node(&thr->n);
  UNLOCK_DOMAIN(resource, birdloop_domain);

  /* Drop loops including the thread dropper itself */
  while (!EMPTY_LIST(thr->loops))
    birdloop_drop(HEAD(thr->loops));

  /* Let others know about new loops */
  if (!EMPTY_LIST(birdloop_pickup))
    wakeup_do_kick(SKIP_BACK(struct bird_thread, n, HEAD(bird_thread_pickup)));
  UNLOCK_DOMAIN(resource, birdloop_domain);

  /* Leave the thread-dropper loop as we aren't going to return. */
  birdloop_leave(thread_dropper);

  /* Stop the meta loop */
  birdloop_leave(thr->meta);
  domain_free(thr->meta->time.domain);
  rfree(thr->meta->pool);

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
    LOCK_DOMAIN(resource, birdloop_domain);
    int dif = list_length(&bird_thread_pickup) - (thread_dropper_goal = new->thread_count);
    _Bool thread_dropper_running = !!thread_dropper;
    UNLOCK_DOMAIN(resource, birdloop_domain);

    if (dif < 0)
    {
      bird_thread_start();
      continue;
    }

    if ((dif > 0) && !thread_dropper_running)
    {
      struct birdloop *tdl = birdloop_new(&root_pool, DOMAIN_ORDER(control), "Thread dropper");
      event *tde = ev_new_init(tdl->pool, bird_thread_shutdown, NULL);

      LOCK_DOMAIN(resource, birdloop_domain);
      thread_dropper = tdl;
      thread_dropper_event = tde;
      UNLOCK_DOMAIN(resource, birdloop_domain);

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
      cli_printf(tsd->cli, -1026, "  Loop %s time: %t", domain_name(loop->time.domain), loop->total_time_spent_ns NS);
    total_time_ns += loop->total_time_spent_ns;
  }

  tsd->done++;
  int last = (tsd->done == tsd->total);

  if (last)
  {
    tsd->cli->cont = NULL;
    tsd->cli->cleanup = NULL;
  }

  if (tsd->show_loops)
    cli_printf(tsd->cli, (last ? 1 : -1) * 1026, "  Total time: %t", total_time_ns NS);
  else
    cli_printf(tsd->cli, (last ? 1 : -1) * 1026, "Thread %p time %t", this_thread, total_time_ns NS);

  UNLOCK_DOMAIN(control, tsd->lock);

  if (last)
  {
    the_bird_lock();

    LOCK_DOMAIN(resource, birdloop_domain);
    if (!EMPTY_LIST(birdloop_pickup))
      if (tsd->show_loops)
      {
	cli_printf(tsd->cli, -1026, "Unassigned loops");
	WALK_LIST(loop, birdloop_pickup)
	  cli_printf(tsd->cli, -1026, "  Loop %s time: %t", domain_name(loop->time.domain), loop->total_time_spent_ns NS);
      }
      else
      {
	uint count = 0;
	u64 total_time_ns = 0;
	WALK_LIST(loop, birdloop_pickup)
	{
	  count++;
	  total_time_ns += loop->total_time_spent_ns;
	}
	cli_printf(tsd->cli, -1026, "Unassigned loops: %d, total time %t", count, total_time_ns NS);
      }
    UNLOCK_DOMAIN(resource, birdloop_domain);

    cli_write_trigger(tsd->cli);
    DOMAIN_FREE(control, tsd->lock);
    rfree(tsd->pool);

    the_bird_unlock();
  }
}


void
cmd_show_threads(int show_loops)
{
  pool *p = rp_new(&root_pool, "Show Threads");

  struct bird_thread_show_data *tsd = mb_allocz(p, sizeof(struct bird_thread_show_data));
  tsd->lock = DOMAIN_NEW(control, "Show Threads");
  tsd->cli = this_cli;
  tsd->pool = p;
  tsd->show_loops = show_loops;

  this_cli->cont = bird_thread_show_cli_cont;
  this_cli->cleanup = bird_thread_show_cli_cleanup;

  LOCK_DOMAIN(control, tsd->lock);
  LOCK_DOMAIN(resource, birdloop_domain);

  struct bird_thread *thr;
  WALK_LIST(thr, bird_thread_pickup)
  {
    tsd->total++;
    ev_send(&thr->priority_events, ev_new_init(p, bird_thread_show, tsd));
    wakeup_do_kick(thr);
  }

  UNLOCK_DOMAIN(resource, birdloop_domain);
  UNLOCK_DOMAIN(control, tsd->lock);
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

  birdloop_domain = DOMAIN_NEW(resource, "Loop Pickup");
  init_list(&birdloop_pickup);
  init_list(&bird_thread_pickup);

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
  rem_node(&loop->n);
  loop->thread = NULL;

  /* Leave the loop context without causing any other fuss */
  ASSERT_DIE(!ev_active(&loop->event));
  loop->ping_pending = 0;
  birdloop_leave(loop);

  /* Request local socket reload */
  this_thread->sock_changed++;

  /* Tail-call the stopped hook */
  loop->stopped(loop->stop_data);
}

static void
birdloop_run(void *_loop)
{
  /* Run priority events before the loop is executed */
  ev_run_list(&this_thread->priority_events);

  struct birdloop *loop = _loop;
  birdloop_enter(loop);

  LOOP_TRACE(loop, "Regular run");

  if (loop->stopped)
    /* Birdloop left inside the helper function */
    return birdloop_stop_internal(loop);

  /* Process sockets */
  this_thread->sock_changed += sockets_fire(loop);

  /* Run timers */
  timers_fire(&loop->time, 0);

  /* Run flag handlers */
  if (birdloop_process_flags(loop))
  {
    LOOP_TRACE(loop, "Flag processing needs another run");
    ev_send_loop(this_thread->meta, &loop->event);
  }

  /* Run events */
  ev_run_list(&loop->event_list);

  /* Request meta timer */
  timer *t = timers_first(&loop->time);
  if (t)
    tm_start_in(&loop->timer, tm_remains(t), this_thread->meta);
  else
    tm_stop(&loop->timer);

  /* Collect socket change requests */
  this_thread->sock_changed += loop->sock_changed;
  loop->sock_changed = 0;

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
birdloop_new_internal(pool *pp, uint order, const char *name, int request_pickup)
{
  struct domain_generic *dg = domain_new(name, order);

  pool *p = rp_new(pp, name);
  struct birdloop *loop = mb_allocz(p, sizeof(struct birdloop));
  loop->pool = p;

  loop->time.domain = dg;
  loop->time.loop = loop;

  atomic_store_explicit(&loop->thread_transition, 0, memory_order_relaxed);

  birdloop_enter(loop);

  ev_init_list(&loop->event_list, loop, name);
  timers_init(&loop->time, p);
  sockets_init(loop);

  loop->event = (event) { .hook = birdloop_run, .data = loop, };
  loop->timer = (timer) { .hook = birdloop_run_timer, .data = loop, };

  if (request_pickup)
  {
    LOCK_DOMAIN(resource, birdloop_domain);
    add_tail(&birdloop_pickup, &loop->n);
    wakeup_do_kick(SKIP_BACK(struct bird_thread, n, HEAD(bird_thread_pickup)));
    UNLOCK_DOMAIN(resource, birdloop_domain);
  }
  else
    loop->n.next = loop->n.prev = &loop->n;

  birdloop_leave(loop);

  return loop;
}

struct birdloop *
birdloop_new(pool *pp, uint order, const char *name)
{
  return birdloop_new_internal(pp, order, name, 1);
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

  domain_free(loop->time.domain);
  rfree(loop->pool);
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
