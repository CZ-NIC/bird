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
pipe_pollin(struct pipe *p, struct pollfd *pfd)
{
  pfd->fd = p->fd[0];
  pfd->events = POLLIN;
  pfd->revents = 0;
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
birdloop_do_ping(struct birdloop *loop)
{
  if (!loop->thread)
    return;

  if (atomic_fetch_add_explicit(&loop->thread->ping_sent, 1, memory_order_acq_rel))
    return;

  if (loop == birdloop_wakeup_masked)
    birdloop_wakeup_masked_count++;
  else
    wakeup_do_kick(loop->thread);
}

void
birdloop_ping(struct birdloop *loop)
{
  if (birdloop_inside(loop) && !loop->ping_pending)
    loop->ping_pending++;
  else
    birdloop_do_ping(loop);
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

static void
sockets_add(struct birdloop *loop, sock *s)
{
  add_tail(&loop->sock_list, &s->n);
  loop->sock_num++;

  s->index = -1;
  if (loop->thread)
    atomic_store_explicit(&loop->thread->poll_changed, 1, memory_order_release);

  birdloop_ping(loop);
}

void
sk_start(sock *s)
{
  ASSERT_DIE(birdloop_current != &main_birdloop);
  sockets_add(birdloop_current, s);
}

static void
sockets_remove(struct birdloop *loop, sock *s)
{
  if (!enlisted(&s->n))
    return;

  /* Decouple the socket from the loop at all. */
  rem_node(&s->n);
  loop->sock_num--;
  if (loop->thread)
    atomic_store_explicit(&loop->thread->poll_changed, 1, memory_order_release);

  s->index = -1;

  /* Close the filedescriptor. If it ever gets into the poll(), it just returns
   * POLLNVAL for this fd which then is ignored because nobody checks for
   * that result. Or some other routine opens another fd, getting this number,
   * yet also in this case poll() at worst spuriously returns and nobody checks
   * for the result in this fd. No further precaution is needed. */
  close(s->fd);
}

void
sk_stop(sock *s)
{
  sockets_remove(birdloop_current, s);
}

static inline uint sk_want_events(sock *s)
{ return (s->rx_hook ? POLLIN : 0) | ((s->ttx != s->tpos) ? POLLOUT : 0); }

static struct pollfd *
sockets_prepare(struct birdloop *loop, struct pollfd *pfd, struct pollfd *end)
{
  node *n;
  loop->pfd = pfd;

  WALK_LIST(n, loop->sock_list)
  {
    sock *s = SKIP_BACK(sock, n, n);

    /* Out of space for pfds. Force reallocation. */
    if (pfd >= end)
      return NULL;

    s->index = pfd - loop->pfd;

    pfd->fd = s->fd;
    pfd->events = sk_want_events(s);
    pfd->revents = 0;

    pfd++;
  }

  return pfd;
}

int sk_read(sock *s, int revents);
int sk_write(sock *s);

static void
sockets_fire(struct birdloop *loop)
{
  struct pollfd *pfd = loop->pfd;

  times_update();

  sock *s; node *n, *nxt;
  WALK_LIST2_DELSAFE(s, n, nxt, loop->sock_list, n)
  {
    if (s->index < 0)
      continue;

    int rev = pfd[s->index].revents;

    if (!rev)
      continue;

    if (rev & POLLNVAL)
      bug("poll: invalid fd %d", s->fd);

    int e = 1;

    if (rev & POLLIN)
      while (e && s->rx_hook)
	e = sk_read(s, rev);

    if (rev & POLLOUT)
    {
      atomic_store_explicit(&loop->thread->poll_changed, 1, memory_order_release);
      while (e = sk_write(s))
	;
    }
  }
}

/*
 *	Threads
 */

DEFINE_DOMAIN(resource);
static DOMAIN(resource) birdloop_domain;
static list birdloop_pickup;
static list bird_thread_pickup;

static _Thread_local struct bird_thread *this_thread;

static void *
bird_thread_main(void *arg)
{
  struct bird_thread *thr = this_thread = arg;

  rcu_thread_start(&thr->rcu);
  synchronize_rcu();

  tmp_init(thr->pool);
  init_list(&thr->loops);

  u32 refresh_sockets = 1;

  struct pollfd *pfd, *end;

  while (1)
  {
    /* Wakeup at least once a minute. */
    int timeout = 60000;

    /* Pickup new loops */
    LOCK_DOMAIN(resource, birdloop_domain);
    if (!EMPTY_LIST(birdloop_pickup))
    {
      struct birdloop *loop = SKIP_BACK(struct birdloop, n, HEAD(birdloop_pickup));
      rem_node(&loop->n);
      UNLOCK_DOMAIN(resource, birdloop_domain);

      add_tail(&thr->loops, &loop->n);

      birdloop_enter(loop);
      loop->thread = thr;
      if (!EMPTY_LIST(loop->sock_list))
	refresh_sockets = 1;
      birdloop_leave(loop);

      /* If there are more loops to be picked up, wakeup the next thread */
      LOCK_DOMAIN(resource, birdloop_domain);
      rem_node(&thr->n);
      add_tail(&bird_thread_pickup, &thr->n);

      if (!EMPTY_LIST(birdloop_pickup))
	wakeup_do_kick(SKIP_BACK(struct bird_thread, n, HEAD(bird_thread_pickup)));
    }
    UNLOCK_DOMAIN(resource, birdloop_domain);

    struct birdloop *loop; node *nn;
    WALK_LIST2(loop, nn, thr->loops, n)
    {
      birdloop_enter(loop);
      u64 after_enter = ns_now();

      timer *t;

      times_update();
      timers_fire(&loop->time, 0);
      int again = birdloop_process_flags(loop) + ev_run_list(&loop->event_list);

#if 0
      if (loop->n.next->next)
	__builtin_prefetch(SKIP_BACK(struct birdloop, n, loop->n.next)->time.domain);
#endif

      if (again)
	timeout = MIN(0, timeout);
      else if (t = timers_first(&loop->time))
	timeout = MIN(((tm_remains(t) TO_MS) + 1), timeout);

      u64 before_leave = ns_now();
      loop->total_time_spent_ns += (before_leave - after_enter);
      birdloop_leave(loop);

      ev_run_list(&thr->priority_events);
    }

    refresh_sockets += atomic_exchange_explicit(&thr->poll_changed, 0, memory_order_acq_rel);

    if (!refresh_sockets && ((timeout < 0) || (timeout > 5000)))
      flush_local_pages();

    while (refresh_sockets)
    {
sock_retry:;
      end = (pfd = thr->pfd) + thr->pfd_max;

      /* Add internal wakeup fd */
      pipe_pollin(&thr->wakeup, pfd);
      pfd++;

      WALK_LIST2(loop, nn, thr->loops, n)
      {
	birdloop_enter(loop);
	pfd = sockets_prepare(loop, pfd, end);
	birdloop_leave(loop);

	if (!pfd)
	{
	  mb_free(thr->pfd);
	  thr->pfd = mb_alloc(thr->pool, sizeof(struct pollfd) * (thr->pfd_max *= 2));
	  goto sock_retry;
	}
      }

      refresh_sockets = 0;
    }

poll_retry:;
    int rv = poll(thr->pfd, pfd - thr->pfd, timeout);
    if (rv < 0)
    {
      if (errno == EINTR || errno == EAGAIN)
	goto poll_retry;
      bug("poll in %p: %m", thr);
    }

    /* Drain wakeup fd */
    if (thr->pfd[0].revents & POLLIN)
    {
      ASSERT_DIE(rv > 0);
      rv--;
      wakeup_drain(thr);
    }

    atomic_exchange_explicit(&thr->ping_sent, 0, memory_order_acq_rel);

    if (!rv && !atomic_exchange_explicit(&thr->run_cleanup, 0, memory_order_acq_rel))
      continue;

    /* Process stops and regular sockets */
    node *nxt;
    WALK_LIST2_DELSAFE(loop, nn, nxt, thr->loops, n)
    {
      birdloop_enter(loop);

      if (loop->stopped)
      {
	/* Flush remaining events */
	ASSERT_DIE(!ev_run_list(&loop->event_list));

	/* Drop timers */
	timer *t;
	while (t = timers_first(&loop->time))
	  tm_stop(t);

	/* No sockets allowed */
	ASSERT_DIE(EMPTY_LIST(loop->sock_list));
	
	/* Declare loop stopped */
	rem_node(&loop->n);
	birdloop_leave(loop);
	loop->stopped(loop->stop_data);

	/* Birdloop already left */
	continue;
      }
      else if (rv)
	sockets_fire(loop);

      birdloop_leave(loop);
    }
  }
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
  thr->pfd = mb_alloc(p, sizeof(struct pollfd) * (thr->pfd_max = 16));
  thr->cleanup_event = (event) { .hook = bird_thread_cleanup, .data = thr, };

  atomic_store_explicit(&thr->ping_sent, 0, memory_order_relaxed);

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

  log(L_INFO "Thread pickup size differs from dropper goal by %d%s", dif, tdl_stop ? ", stopping" : "");

  if (tdl_stop)
  {
    birdloop_stop_self(tdl_stop, NULL, NULL);
    return;
  }

  struct bird_thread *thr = this_thread;

  /* Leave the thread-picker list to get no more loops */
  LOCK_DOMAIN(resource, birdloop_domain);
  rem_node(&thr->n);

  /* Drop loops including the thread dropper itself */
  while (!EMPTY_LIST(thr->loops))
  {
    /* Remove loop from this thread's list */
    struct birdloop *loop = HEAD(thr->loops);
    rem_node(&loop->n);
    UNLOCK_DOMAIN(resource, birdloop_domain);

    /* Unset loop's thread */
    if (birdloop_inside(loop))
      loop->thread = NULL;
    else
    {
      birdloop_enter(loop);
      loop->thread = NULL;
      birdloop_leave(loop);
    }

    /* Put loop into pickup list */
    LOCK_DOMAIN(resource, birdloop_domain);
    add_tail(&birdloop_pickup, &loop->n);
  }

  /* Let others know about new loops */
  if (!EMPTY_LIST(birdloop_pickup))
    wakeup_do_kick(SKIP_BACK(struct bird_thread, n, HEAD(bird_thread_pickup)));
  UNLOCK_DOMAIN(resource, birdloop_domain);

  /* Leave the thread-dropper loop as we aren't going to return. */
  birdloop_leave(thread_dropper);

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

struct birdloop *
birdloop_new(pool *pp, uint order, const char *name)
{
  struct domain_generic *dg = domain_new(name, order);

  pool *p = rp_new(pp, name);
  struct birdloop *loop = mb_allocz(p, sizeof(struct birdloop));
  loop->pool = p;

  loop->time.domain = dg;
  loop->time.loop = loop;

  birdloop_enter(loop);

  ev_init_list(&loop->event_list, loop, name);
  timers_init(&loop->time, p);
  sockets_init(loop);

  LOCK_DOMAIN(resource, birdloop_domain);
  add_tail(&birdloop_pickup, &loop->n);
  wakeup_do_kick(SKIP_BACK(struct bird_thread, n, HEAD(bird_thread_pickup)));
  UNLOCK_DOMAIN(resource, birdloop_domain);

  birdloop_leave(loop);

  return loop;
}

static void
birdloop_do_stop(struct birdloop *loop, void (*stopped)(void *data), void *data)
{
  loop->stopped = stopped;
  loop->stop_data = data;
  if (loop->thread)
  {
    atomic_store_explicit(&loop->thread->run_cleanup, 1, memory_order_release);
    wakeup_do_kick(loop->thread);
  }
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
  ASSERT_DIE(loop->links == 0);
  ASSERT_DIE(birdloop_in_this_thread(loop));

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
birdloop_link(struct birdloop *loop)
{
  ASSERT_DIE(birdloop_inside(loop));
  loop->links++;
}

void
birdloop_unlink(struct birdloop *loop)
{
  ASSERT_DIE(birdloop_inside(loop));
  loop->links--;
}

void
birdloop_yield(void)
{
  usleep(100);
}
