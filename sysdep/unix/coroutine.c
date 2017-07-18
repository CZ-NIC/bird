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
#include <ucontext.h>

#include "nest/bird.h"
#include "lib/coroutine.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "sysdep/unix/unix.h"

struct coroutine {
  resource r;
  ucontext_t ctx;
  void *stack;
  void (*entry_point)(void *arg);
  void *arg;
};

static ucontext_t *main_context;
static coroutine *coro_current;		// NULL for main context

#define CORO_STACK_SIZE 65536

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
