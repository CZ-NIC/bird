/*
 *	BIRD Coroutines
 *
 *	(c) 2017 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>

#include "nest/bird.h"
#include "lib/coroutine.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/timer.h"
#include "sysdep/unix/unix.h"

#define CORO_STACK_SIZE 65536

/*
 *	Implementation of coroutines based on POSIX threads
 */

#include <pthread.h>
#include <semaphore.h>

#define CORO_STOP 1	/* The coroutine should stop at first coro_suspend(). */
#define CORO_DONE 2	/* The coroutine has already stopped. */

struct coroutine {
  resource r;
  pthread_t thread;
  void (*entry_point)(void *arg);
  void *arg;
  event *ev;
  sem_t sem;
  uint flags;
};

static coroutine *coro_current;		// NULL for main context
static int coro_inited;
static sem_t coro_main_sem;
static pthread_attr_t coro_thread_attrs;

static void
coro_free(resource *r)
{
  coroutine *c = (coroutine *) r;
  ASSERT(coro_current != c);

  if (!(c->flags & CORO_DONE))
    {
      c->flags |= CORO_STOP;
      coro_resume(c);
    }

  ASSERT(c->flags & CORO_DONE);
  pthread_join(c->thread, NULL);
}

static void
coro_dump(resource *r UNUSED)
{
  debug("\n");
}

static size_t
coro_memsize(resource *r)
{
  coroutine *c = (coroutine *) r;
  return sizeof(*c) + CORO_STACK_SIZE + 2*ALLOC_OVERHEAD;
}

static struct resclass coro_class = {
  .name = "Coroutine",
  .size = sizeof(struct coroutine),
  .free = coro_free,
  .dump = coro_dump,
  .memsize = coro_memsize,
};

extern pthread_key_t current_time_key;

static void *
coro_do_start(void *c_)
{
  coroutine *c = c_;
  pthread_setspecific(current_time_key, &main_timeloop);
  while (sem_wait(&c->sem) < 0)
    ;
  coro_current = c;
  c->entry_point(c->arg);
  bug("Coroutine returned unexpectedly");
}

struct coroutine *
coro_new(pool *p, void (*entry_point)(void *), void *arg)
{
  if (!coro_inited)
    {
      if (sem_init(&coro_main_sem, 0, 0) < 0)
	bug("sem_init() failed");
      if (pthread_attr_init(&coro_thread_attrs))
	bug("pthread_attr_init() failed");
      if (pthread_attr_setstacksize(&coro_thread_attrs, CORO_STACK_SIZE))
	bug("pthread_attr_setstacksize() failed");
      coro_inited = 1;
    }

  coroutine *c = ralloc(p, &coro_class);
  c->entry_point = entry_point;
  c->arg = arg;
  if (sem_init(&c->sem, 0, 0) < 0)
    bug("sem_init() failed");
  if (pthread_create(&c->thread, &coro_thread_attrs, coro_do_start, c))
    bug("pthread_create() failed");

  return c;
}

static inline void
coro_check_stop(void)
{
  ASSERT(coro_inited);
  ASSERT(coro_current);
  coroutine *c = coro_current;
  if (c->flags & CORO_STOP)
    coro_done(NULL);
}

void
coro_done(event *e)
{
  ASSERT(coro_inited);
  ASSERT(coro_current);
  coroutine *c = coro_current;
  c->flags |= CORO_DONE;
  c->ev = e;
  if (e)
    ev_schedule(e);
  sem_post(&coro_main_sem);
  pthread_exit(NULL);
  bug("pthread_exit should never return");
}

void
coro_suspend(void)
{
  ASSERT(coro_inited);
  ASSERT(coro_current);
  coroutine *c = coro_current;
  coro_check_stop();
  sem_post(&coro_main_sem);
  while (sem_wait(&c->sem) < 0)
    ;
  coro_current = c;
  coro_check_stop();
}

void
coro_resume(coroutine *c)
{
  ASSERT(coro_inited);
  ASSERT(!coro_current);
  sem_post(&c->sem);
  while (sem_wait(&coro_main_sem) < 0)
    ;
  coro_current = NULL;
}

/* Coroutine-based I/O */

static int
coro_sk_rx_hook(sock *sk, uint size UNUSED)
{
  ASSERT(sk->rx_coroutine);
  ASSERT(!coro_current);
  coro_resume(sk->rx_coroutine);
  return 0;
}

static void
coro_sk_tx_hook(sock *sk)
{
  ASSERT(sk->tx_coroutine);
  ASSERT(!coro_current);
  coro_resume(sk->tx_coroutine);
}

int
coro_sk_read(sock *s)
{
  ASSERT(coro_current);
  s->rx_coroutine = coro_current;
  s->rx_hook = coro_sk_rx_hook;
  coro_suspend();
  s->rx_hook = NULL;
  return s->rpos - s->rbuf;
}

void
coro_sk_write(sock *s, unsigned len)
{
  ASSERT(coro_current);
  s->tx_coroutine = coro_current;
  s->tx_hook = coro_sk_tx_hook;
  s->ttx = s->tbuf;
  s->tpos = s->tbuf + len;
  coro_suspend();
  s->tx_hook = NULL;
}
