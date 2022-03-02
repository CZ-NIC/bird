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
#include "proto/bfd/io.h"

#include "lib/buffer.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/socket.h"


struct birdloop
{
  pool *pool;
  pthread_t thread;
  pthread_mutex_t mutex;

  u8 stop_called;
  u8 poll_active;
  u8 wakeup_masked;
  int wakeup_fds[2];

  struct timeloop time;
  list event_list;
  list sock_list;
  uint sock_num;

  BUFFER(sock *) poll_sk;
  BUFFER(struct pollfd) poll_fd;
  u8 poll_changed;
  u8 close_scheduled;
};


/*
 *	Current thread context
 */

static pthread_key_t current_loop_key;
extern pthread_key_t current_time_key;

static inline struct birdloop *
birdloop_current(void)
{
  return pthread_getspecific(current_loop_key);
}

static inline void
birdloop_set_current(struct birdloop *loop)
{
  pthread_setspecific(current_loop_key, loop);
  pthread_setspecific(current_time_key, loop ? &loop->time : &main_timeloop);
}

static inline void
birdloop_init_current(void)
{
  pthread_key_create(&current_loop_key, NULL);
}


/*
 *	Wakeup code for birdloop
 */

static void
pipe_new(int *pfds)
{
  int rv = pipe(pfds);
  if (rv < 0)
    die("pipe: %m");

  if (fcntl(pfds[0], F_SETFL, O_NONBLOCK) < 0)
    die("fcntl(O_NONBLOCK): %m");

  if (fcntl(pfds[1], F_SETFL, O_NONBLOCK) < 0)
    die("fcntl(O_NONBLOCK): %m");
}

void
pipe_drain(int fd)
{
  char buf[64];
  int rv;
  
 try:
  rv = read(fd, buf, 64);
  if (rv < 0)
  {
    if (errno == EINTR)
      goto try;
    if (errno == EAGAIN)
      return;
    die("wakeup read: %m");
  }
  if (rv == 64)
    goto try;
}

void
pipe_kick(int fd)
{
  u64 v = 1;
  int rv;

 try:
  rv = write(fd, &v, sizeof(u64));
  if (rv < 0)
  {
    if (errno == EINTR)
      goto try;
    if (errno == EAGAIN)
      return;
    die("wakeup write: %m");
  }
}

static inline void
wakeup_init(struct birdloop *loop)
{
  pipe_new(loop->wakeup_fds);
}

static inline void
wakeup_drain(struct birdloop *loop)
{
  pipe_drain(loop->wakeup_fds[0]);
}

static inline void
wakeup_do_kick(struct birdloop *loop)
{
  pipe_kick(loop->wakeup_fds[1]);
}

static inline void
wakeup_kick(struct birdloop *loop)
{
  if (!loop->wakeup_masked)
    wakeup_do_kick(loop);
  else
    loop->wakeup_masked = 2;
}

/* For notifications from outside */
void
wakeup_kick_current(void)
{
  struct birdloop *loop = birdloop_current();

  if (loop && loop->poll_active)
    wakeup_kick(loop);
}


/*
 *	Events
 */

static inline uint
events_waiting(struct birdloop *loop)
{
  return !EMPTY_LIST(loop->event_list);
}

static inline void
events_init(struct birdloop *loop)
{
  init_list(&loop->event_list);
}

static void
events_fire(struct birdloop *loop)
{
  times_update(&loop->time);
  ev_run_list(&loop->event_list);
}

void
ev2_schedule(event *e)
{
  struct birdloop *loop = birdloop_current();

  if (loop->poll_active && EMPTY_LIST(loop->event_list))
    wakeup_kick(loop);

  if (e->n.next)
    rem_node(&e->n);

  add_tail(&loop->event_list, &e->n);
}


/*
 *	Sockets
 */

static void
sockets_init(struct birdloop *loop)
{
  init_list(&loop->sock_list);
  loop->sock_num = 0;

  BUFFER_INIT(loop->poll_sk, loop->pool, 4);
  BUFFER_INIT(loop->poll_fd, loop->pool, 4);
  loop->poll_changed = 1;	/* add wakeup fd */
}

static void
sockets_add(struct birdloop *loop, sock *s)
{
  add_tail(&loop->sock_list, &s->n);
  loop->sock_num++;

  s->index = -1;
  loop->poll_changed = 1;

  if (loop->poll_active)
    wakeup_kick(loop);
}

void
sk_start(sock *s)
{
  struct birdloop *loop = birdloop_current();

  sockets_add(loop, s);
}

static void
sockets_remove(struct birdloop *loop, sock *s)
{
  rem_node(&s->n);
  loop->sock_num--;

  if (s->index >= 0)
    loop->poll_sk.data[s->index] = NULL;

  s->index = -1;
  loop->poll_changed = 1;

  /* Wakeup moved to sk_stop() */
}

void
sk_stop(sock *s)
{
  struct birdloop *loop = birdloop_current();

  sockets_remove(loop, s);

  if (loop->poll_active)
  {
    loop->close_scheduled = 1;
    wakeup_kick(loop);
  }
  else
    close(s->fd);

  s->fd = -1;
}

static inline uint sk_want_events(sock *s)
{ return (s->rx_hook ? POLLIN : 0) | ((s->ttx != s->tpos) ? POLLOUT : 0); }

/*
FIXME: this should be called from sock code

static void
sockets_update(struct birdloop *loop, sock *s)
{
  if (s->index >= 0)
    loop->poll_fd.data[s->index].events = sk_want_events(s);
}
*/

static void
sockets_prepare(struct birdloop *loop)
{
  BUFFER_SET(loop->poll_sk, loop->sock_num + 1);
  BUFFER_SET(loop->poll_fd, loop->sock_num + 1);

  struct pollfd *pfd = loop->poll_fd.data;
  sock **psk = loop->poll_sk.data;
  uint i = 0;
  node *n;

  WALK_LIST(n, loop->sock_list)
  {
    sock *s = SKIP_BACK(sock, n, n);

    ASSERT(i < loop->sock_num);

    s->index = i;
    *psk = s;
    pfd->fd = s->fd;
    pfd->events = sk_want_events(s);
    pfd->revents = 0;

    pfd++;
    psk++;
    i++;
  }

  ASSERT(i == loop->sock_num);

  /* Add internal wakeup fd */
  *psk = NULL;
  pfd->fd = loop->wakeup_fds[0];
  pfd->events = POLLIN;
  pfd->revents = 0;

  loop->poll_changed = 0;
}

static void
sockets_close_fds(struct birdloop *loop)
{
  struct pollfd *pfd = loop->poll_fd.data;
  sock **psk = loop->poll_sk.data;
  int poll_num = loop->poll_fd.used - 1;

  int i;
  for (i = 0; i < poll_num; i++)
    if (psk[i] == NULL)
      close(pfd[i].fd);

  loop->close_scheduled = 0;
}

int sk_read(sock *s, int revents);
int sk_write(sock *s);

static void
sockets_fire(struct birdloop *loop)
{
  struct pollfd *pfd = loop->poll_fd.data;
  sock **psk = loop->poll_sk.data;
  int poll_num = loop->poll_fd.used - 1;

  times_update(&loop->time);

  /* Last fd is internal wakeup fd */
  if (pfd[poll_num].revents & POLLIN)
    wakeup_drain(loop);

  int i;
  for (i = 0; i < poll_num; pfd++, psk++, i++)
  {
    int e = 1;

    if (! pfd->revents)
      continue;

    if (pfd->revents & POLLNVAL)
      die("poll: invalid fd %d", pfd->fd);

    if (pfd->revents & POLLIN)
      while (e && *psk && (*psk)->rx_hook)
	e = sk_read(*psk, 0);

    e = 1;
    if (pfd->revents & POLLOUT)
      while (e && *psk)
	e = sk_write(*psk);
  }
}


/*
 *	Birdloop
 */

static void * birdloop_main(void *arg);

struct birdloop *
birdloop_new(void)
{
  /* FIXME: this init should be elsewhere and thread-safe */
  static int init = 0;
  if (!init)
    { birdloop_init_current(); init = 1; }

  pool *p = rp_new(NULL, "Birdloop root");
  struct birdloop *loop = mb_allocz(p, sizeof(struct birdloop));
  loop->pool = p;
  pthread_mutex_init(&loop->mutex, NULL);

  wakeup_init(loop);

  events_init(loop);
  timers_init(&loop->time, p);
  sockets_init(loop);

  return loop;
}

void
birdloop_start(struct birdloop *loop)
{
  int rv = pthread_create(&loop->thread, NULL, birdloop_main, loop);
  if (rv)
    die("pthread_create(): %M", rv);
}

void
birdloop_stop(struct birdloop *loop)
{
  pthread_mutex_lock(&loop->mutex);
  loop->stop_called = 1;
  wakeup_do_kick(loop);
  pthread_mutex_unlock(&loop->mutex);

  int rv = pthread_join(loop->thread, NULL);
  if (rv)
    die("pthread_join(): %M", rv);
}

void
birdloop_free(struct birdloop *loop)
{
  rfree(loop->pool);
}


void
birdloop_enter(struct birdloop *loop)
{
  /* TODO: these functions could save and restore old context */
  pthread_mutex_lock(&loop->mutex);
  birdloop_set_current(loop);
}

void
birdloop_leave(struct birdloop *loop)
{
  /* TODO: these functions could save and restore old context */
  birdloop_set_current(NULL);
  pthread_mutex_unlock(&loop->mutex);
}

void
birdloop_mask_wakeups(struct birdloop *loop)
{
  pthread_mutex_lock(&loop->mutex);
  loop->wakeup_masked = 1;
  pthread_mutex_unlock(&loop->mutex);
}

void
birdloop_unmask_wakeups(struct birdloop *loop)
{
  pthread_mutex_lock(&loop->mutex);
  if (loop->wakeup_masked == 2)
    wakeup_do_kick(loop);
  loop->wakeup_masked = 0;
  pthread_mutex_unlock(&loop->mutex);
}

static void *
birdloop_main(void *arg)
{
  struct birdloop *loop = arg;
  timer *t;
  int rv, timeout;

  birdloop_set_current(loop);

  tmp_init(loop->pool);

  pthread_mutex_lock(&loop->mutex);
  while (1)
  {
    events_fire(loop);
    timers_fire(&loop->time);

    times_update(&loop->time);
    if (events_waiting(loop))
      timeout = 0;
    else if (t = timers_first(&loop->time))
      timeout = (tm_remains(t) TO_MS) + 1;
    else
      timeout = -1;

    if (loop->poll_changed)
      sockets_prepare(loop);

    loop->poll_active = 1;
    pthread_mutex_unlock(&loop->mutex);

  try:
    rv = poll(loop->poll_fd.data, loop->poll_fd.used, timeout);
    if (rv < 0)
    {
      if (errno == EINTR || errno == EAGAIN)
	goto try;
      die("poll: %m");
    }

    pthread_mutex_lock(&loop->mutex);
    loop->poll_active = 0;

    if (loop->close_scheduled)
      sockets_close_fds(loop);

    if (loop->stop_called)
      break;

    if (rv)
      sockets_fire(loop);

    timers_fire(&loop->time);
  }

  loop->stop_called = 0;
  pthread_mutex_unlock(&loop->mutex);

  return NULL;
}


