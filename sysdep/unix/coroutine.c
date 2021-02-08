/*
 *	BIRD Coroutines
 *
 *	(c) 2017 Martin Mares <mj@ucw.cz>
 *	(c) 2020 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#undef LOCAL_DEBUG

#undef DEBUG_LOCKING

#include "lib/birdlib.h"
#include "lib/locking.h"
#include "lib/coro.h"
#include "lib/resource.h"
#include "lib/timer.h"

/* Using a rather big stack for coroutines to allow for stack-local allocations.
 * In real world, the kernel doesn't alloc this memory until it is used.
 * */
#define CORO_STACK_SIZE	1048576

/*
 *	Implementation of coroutines based on POSIX threads
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 *	Locking subsystem
 */

#define ASSERT_NO_LOCK	ASSERT_DIE(last_locked == NULL)

struct domain_generic {
  pthread_mutex_t mutex;
  struct domain_generic **prev;
  struct lock_order *locked_by;
  const char *name;
};

#define DOMAIN_INIT(_name) { .mutex = PTHREAD_MUTEX_INITIALIZER, .name = _name }

static struct domain_generic the_bird_domain_gen = DOMAIN_INIT("The BIRD");

DOMAIN(the_bird) the_bird_domain = { .the_bird = &the_bird_domain_gen };

struct domain_generic *
domain_new(const char *name)
{
  struct domain_generic *dg = xmalloc(sizeof(struct domain_generic));
  *dg = (struct domain_generic) DOMAIN_INIT(name);
  return dg;
}

void
domain_free(struct domain_generic *dg)
{
  pthread_mutex_destroy(&dg->mutex);
  xfree(dg);
}

_Thread_local struct lock_order locking_stack = {};
_Thread_local struct domain_generic **last_locked = NULL;

void do_lock(struct domain_generic *dg, struct domain_generic **lsp)
{
  if (lsp <= last_locked)
    bug("Trying to lock in a bad order");
  if (*lsp)
    bug("Inconsistent locking stack state on lock");

  pthread_mutex_lock(&dg->mutex);

  if (dg->prev || dg->locked_by)
    bug("Previous unlock not finished correctly");
  dg->prev = last_locked;
  *lsp = dg;
  last_locked = lsp;
  dg->locked_by = &locking_stack;
}

void do_unlock(struct domain_generic *dg, struct domain_generic **lsp)
{
  if (dg->locked_by != &locking_stack)
    bug("Inconsistent domain state on unlock");
  if ((last_locked != lsp) || (*lsp != dg))
    bug("Inconsistent locking stack state on unlock");
  dg->locked_by = NULL;
  last_locked = dg->prev;
  *lsp = NULL;
  dg->prev = NULL;
  pthread_mutex_unlock(&dg->mutex);
}

/* Coroutines */
struct coroutine {
  resource r;
  pthread_t id;
  pthread_attr_t attr;
  void (*entry)(void *);
  void *data;
};

static _Thread_local _Bool coro_cleaned_up = 0;

static void coro_free(resource *r)
{
  struct coroutine *c = (void *) r;
  ASSERT_DIE(pthread_equal(pthread_self(), c->id));
  pthread_attr_destroy(&c->attr);
  coro_cleaned_up = 1;
}

static struct resclass coro_class = {
  .name = "Coroutine",
  .size = sizeof(struct coroutine),
  .free = coro_free,
};

extern pthread_key_t current_time_key;

static void *coro_entry(void *p)
{
  struct coroutine *c = p;
  ASSERT_DIE(c->entry);

  pthread_setspecific(current_time_key, &main_timeloop);

  c->entry(c->data);
  ASSERT_DIE(coro_cleaned_up);

  return NULL;
}

struct coroutine *coro_run(pool *p, void (*entry)(void *), void *data)
{
  ASSERT_DIE(entry);
  ASSERT_DIE(p);

  struct coroutine *c = ralloc(p, &coro_class);

  c->entry = entry;
  c->data = data;

  int e = 0;

  if (e = pthread_attr_init(&c->attr))
    die("pthread_attr_init() failed: %M", e);

  if (e = pthread_attr_setstacksize(&c->attr, CORO_STACK_SIZE))
    die("pthread_attr_setstacksize(%u) failed: %M", CORO_STACK_SIZE, e);

  if (e = pthread_attr_setdetachstate(&c->attr, PTHREAD_CREATE_DETACHED))
    die("pthread_attr_setdetachstate(PTHREAD_CREATE_DETACHED) failed: %M", e);

  if (e = pthread_create(&c->id, &c->attr, coro_entry, c))
    die("pthread_create() failed: %M", e);

  return c;
}
