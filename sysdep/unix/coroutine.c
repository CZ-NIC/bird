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
#include "sysdep/unix/unix.h"

#define CORO_STACK_SIZE 65536

#if 1

/*
 *	Implementation of coroutines based on <ucontext.h>
 */

#include <ucontext.h>

struct coroutine {
  resource r;
  ucontext_t ctx;
  void *stack;
  void (*entry_point)(void *arg);
  void *arg;
};

static ucontext_t *main_context;
static coroutine *coro_current;		// NULL for main context

static void
coro_free(resource *r)
{
  coroutine *c = (coroutine *) r;
  xfree(c->stack);
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

static void
coro_do_start(void)
{
  ASSERT(coro_current);
  coro_current->entry_point(coro_current->arg);
  bug("Coroutine returned unexpectedly");
}

struct coroutine *
coro_new(pool *p, void (*entry_point)(void *), void *arg)
{
  if (!main_context)
    {
      main_context = xmalloc(sizeof(*main_context));
      if (getcontext(main_context) < 0)
	bug("getcontext() failed");
    }

  coroutine *c = ralloc(p, &coro_class);
  c->entry_point = entry_point;
  c->arg = arg;
  if (getcontext(&c->ctx) < 0)
    bug("getcontext() failed");
  c->stack = xmalloc(CORO_STACK_SIZE);
  c->ctx.uc_stack.ss_sp = c->stack;
  c->ctx.uc_stack.ss_size = CORO_STACK_SIZE;

  makecontext(&c->ctx, coro_do_start, 0);

  return c;
}

void
coro_suspend(void)
{
  ASSERT(coro_current);
  ASSERT(main_context);
  coroutine *c = coro_current;
  coro_current = NULL;
  swapcontext(&c->ctx, main_context);
  ASSERT(coro_current == c);
}

void
coro_resume(coroutine *c)
{
  ASSERT(!coro_current);
  coro_current = c;
  swapcontext(main_context, &c->ctx);
  ASSERT(!coro_current);
}

#else

/*
 *	Implementation of coroutines based on POSIX threads
 */

#include <pthread.h>
#include <semaphore.h>

struct coroutine {
  resource r;
  pthread_t thread;
  void (*entry_point)(void *arg);
  void *arg;
  sem_t sem;
};

static coroutine *coro_current;		// NULL for main context
static int coro_inited;
static sem_t coro_main_sem;
static pthread_attr_t coro_thread_attrs;

static void
coro_free(resource *r)
{
  coroutine *c = (coroutine *) r;
  pthread_cancel(c->thread);
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

static void *
coro_do_start(void *c_)
{
  coroutine *c = c_;
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

void
coro_suspend(void)
{
  ASSERT(coro_inited);
  ASSERT(coro_current);
  coroutine *c = coro_current;
  sem_post(&coro_main_sem);
  while (sem_wait(&c->sem) < 0)
    ;
  coro_current = c;
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

#endif

/* Coroutine-based I/O */

static int
coro_sk_rx_hook(sock *sk, uint size UNUSED)
{
  ASSERT(sk->rx_coroutine);
  ASSERT(!coro_current);
  coro_resume(sk->rx_coroutine);
  return 0;
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
