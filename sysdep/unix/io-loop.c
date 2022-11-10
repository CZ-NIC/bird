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
#include "lib/resource.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/socket.h"

#include "lib/io-loop.h"
#include "sysdep/unix/io-loop.h"
#include "conf/conf.h"

#define THREAD_STACK_SIZE	65536	/* To be lowered in near future */

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
  return pthread_equal(pthread_self(), loop->thread_id);
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
  loop->flag_handler->hook(loop->flag_handler, flags);
  return !!flags;
}

static int
birdloop_run_events(struct birdloop *loop)
{
  btime begin = current_time();
  while (current_time() - begin < 5 MS)
  {
    if (!ev_run_list(&loop->event_list))
      return 0;

    times_update();
  }

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
wakeup_init(struct birdloop *loop)
{
  pipe_new(&loop->wakeup);
}

static inline void
wakeup_drain(struct birdloop *loop)
{
  pipe_drain(&loop->wakeup);
}

static inline void
wakeup_do_kick(struct birdloop *loop)
{
  pipe_kick(&loop->wakeup);
}

static inline void
birdloop_do_ping(struct birdloop *loop)
{
  if (atomic_fetch_add_explicit(&loop->ping_sent, 1, memory_order_acq_rel))
    return;

  if (loop == birdloop_wakeup_masked)
    birdloop_wakeup_masked_count++;
  else
    wakeup_do_kick(loop);
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
  atomic_store_explicit(&loop->sock_close_requests, 0, memory_order_relaxed);
  sem_init(&loop->sock_close_sem, 0, 0);

  BUFFER_INIT(loop->poll_fd, loop->pool, 4);
  loop->poll_changed = 1;	/* add wakeup fd */
  loop->poll_domain = DOMAIN_NEW(resource, "Poll");
}

static void
sockets_add(struct birdloop *loop, sock *s)
{
  add_tail(&loop->sock_list, &s->n);
  loop->sock_num++;

  s->index = -1;
  loop->poll_changed = 1;

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

  rem_node(&s->n);
  loop->sock_num--;

  if (birdloop_in_this_thread(loop))
  {
    if (s->index >= 0)
    {
      s->index = -1;
      loop->poll_changed = 1;
    }
    close(s->fd);
  }
  else
  {
    atomic_fetch_add_explicit(&loop->sock_close_requests, 1, memory_order_acq_rel);
    wakeup_do_kick(loop);
    LOCK_DOMAIN(resource, loop->poll_domain);
    s->index = -1;
    close(s->fd);
    UNLOCK_DOMAIN(resource, loop->poll_domain);
    sem_post(&loop->sock_close_sem);
  }
}

void
sk_stop(sock *s)
{
  sockets_remove(birdloop_current, s);
}

static inline uint sk_want_events(sock *s)
{ return (s->rx_hook ? POLLIN : 0) | ((s->ttx != s->tpos) ? POLLOUT : 0); }

static void
sockets_prepare(struct birdloop *loop)
{
  LOCK_DOMAIN(resource, loop->poll_domain);
  BUFFER_SET(loop->poll_fd, loop->sock_num + 1);

  struct pollfd *pfd = loop->poll_fd.data;
  uint i = 0;
  node *n;

  WALK_LIST(n, loop->sock_list)
  {
    sock *s = SKIP_BACK(sock, n, n);

    ASSERT(i < loop->sock_num);

    s->index = i;
    pfd->fd = s->fd;
    pfd->events = sk_want_events(s);
    pfd->revents = 0;

    pfd++;
    i++;
  }

  ASSERT(i == loop->sock_num);

  /* Add internal wakeup fd */
  pipe_pollin(&loop->wakeup, pfd);

  loop->poll_changed = 0;
  UNLOCK_DOMAIN(resource, loop->poll_domain);
}

int sk_read(sock *s, int revents);
int sk_write(sock *s);

static void
sockets_fire(struct birdloop *loop)
{
  struct pollfd *pfd = loop->poll_fd.data;
  int poll_num = loop->poll_fd.used - 1;

  times_update();

  /* Last fd is internal wakeup fd */
  if (pfd[poll_num].revents & POLLIN)
    wakeup_drain(loop);

  sock *s; node *n, *nxt;
  WALK_LIST2_DELSAFE(s, n, nxt, loop->sock_list, n)
  {
    if (s->index < 0)
      continue;

    LOCK_DOMAIN(resource, loop->poll_domain);
    int rev = loop->poll_fd.data[s->index].revents;
    UNLOCK_DOMAIN(resource, loop->poll_domain);

    if (! rev)
      continue;

    if (rev & POLLNVAL)
      bug("poll: invalid fd %d", s->fd);

    int e = 1;

    if (rev & POLLIN)
      while (e && s->rx_hook)
	e = sk_read(s, rev);

    if (rev & POLLOUT)
    {
      loop->poll_changed = 1;
      while (e = sk_write(s))
	;
    }
  }
}


/*
 *	Birdloop
 */

struct birdloop main_birdloop;

static void birdloop_enter_locked(struct birdloop *loop);

void
birdloop_init(void)
{
  wakeup_init(&main_birdloop);

  main_birdloop.time.domain = the_bird_domain.the_bird;
  main_birdloop.time.loop = &main_birdloop;

  times_update();
  timers_init(&main_birdloop.time, &root_pool);

  birdloop_enter_locked(&main_birdloop);
}

static void *birdloop_main(void *arg);

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

  wakeup_init(loop);
  ev_init_list(&loop->event_list, loop, name);
  timers_init(&loop->time, p);
  sockets_init(loop);

  int e = 0;

  if (e = pthread_attr_init(&loop->thread_attr))
    die("pthread_attr_init() failed: %M", e);

  if (e = pthread_attr_setstacksize(&loop->thread_attr, THREAD_STACK_SIZE))
    die("pthread_attr_setstacksize(%u) failed: %M", THREAD_STACK_SIZE, e);

  if (e = pthread_attr_setdetachstate(&loop->thread_attr, PTHREAD_CREATE_DETACHED))
    die("pthread_attr_setdetachstate(PTHREAD_CREATE_DETACHED) failed: %M", e);

  if (e = pthread_create(&loop->thread_id, &loop->thread_attr, birdloop_main, loop))
    die("pthread_create() failed: %M", e);

  birdloop_leave(loop);

  return loop;
}

static void
birdloop_do_stop(struct birdloop *loop, void (*stopped)(void *data), void *data)
{
  loop->stopped = stopped;
  loop->stop_data = data;
  wakeup_do_kick(loop);
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

  rcu_birdloop_stop(&loop->rcu);
  pthread_attr_destroy(&loop->thread_attr);

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
    wakeup_do_kick(loop);

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

static void *
birdloop_main(void *arg)
{
  struct birdloop *loop = arg;
  timer *t;
  int rv, timeout;

  rcu_birdloop_start(&loop->rcu);

  btime loop_begin = current_time();

  tmp_init(loop->pool);

  birdloop_enter(loop);
  while (1)
  {
    timers_fire(&loop->time, 0);
    if (birdloop_process_flags(loop) + birdloop_run_events(loop))
      timeout = 0;
    else if (t = timers_first(&loop->time))
      timeout = (tm_remains(t) TO_MS) + 1;
    else
      timeout = -1;

    if (loop->poll_changed)
      sockets_prepare(loop);
    else
      if ((timeout < 0) || (timeout > 5000))
	flush_local_pages();

    btime duration = current_time() - loop_begin;
    if (duration > config->watchdog_warning)
      log(L_WARN "I/O loop cycle took %d ms", (int) (duration TO_MS));

    birdloop_leave(loop);

    LOCK_DOMAIN(resource, loop->poll_domain);
  try:
    rv = poll(loop->poll_fd.data, loop->poll_fd.used, timeout);
    if (rv < 0)
    {
      if (errno == EINTR || errno == EAGAIN)
	goto try;
      bug("poll: %m");
    }
    UNLOCK_DOMAIN(resource, loop->poll_domain);

    /* Wait until remote requestors close their sockets */
    int close_count = atomic_exchange_explicit(&loop->sock_close_requests, 0, memory_order_acq_rel);
    while (close_count--)
      sem_wait(&loop->sock_close_sem);

    birdloop_enter(loop);

    if (loop->stopped)
      break;

    loop_begin = current_time();

    if (rv && !loop->poll_changed)
      sockets_fire(loop);

    atomic_exchange_explicit(&loop->ping_sent, 0, memory_order_acq_rel);
  }

  /* Flush remaining events */
  ASSERT_DIE(!ev_run_list(&loop->event_list));

  /* Drop timers */
  while (t = timers_first(&loop->time))
    tm_stop(t);

  /* No sockets allowed */
  ASSERT_DIE(EMPTY_LIST(loop->sock_list));
  ASSERT_DIE(loop->sock_num == 0);

  birdloop_leave(loop);
  loop->stopped(loop->stop_data);

  flush_local_pages();
  return NULL;
}

void
birdloop_yield(void)
{
  usleep(100);
}
