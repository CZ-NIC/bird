/*
 *	BIRD Locking
 *
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
#include "lib/resource.h"
#include "lib/timer.h"

#include "conf/conf.h"

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

_Thread_local struct lock_order locking_stack = {};
_Thread_local struct domain_generic **last_locked = NULL;

#define ASSERT_NO_LOCK	ASSERT_DIE(last_locked == NULL)

struct domain_generic {
  pthread_mutex_t mutex;
  uint order;
  _Bool forbidden_when_reading_rcu;
  struct domain_generic **prev;
  struct lock_order *locked_by;
  const char *name;
  pool *pool;
};

#define DOMAIN_INIT(_order, _allow_rcu) { \
  .mutex = PTHREAD_MUTEX_INITIALIZER, \
  .order = _order, \
  .forbidden_when_reading_rcu = !_allow_rcu, \
}

static struct domain_generic the_bird_domain_gen = DOMAIN_INIT(OFFSETOF(struct lock_order, the_bird), 1);

DOMAIN(the_bird) the_bird_domain = { .the_bird = &the_bird_domain_gen };

struct domain_generic *
domain_new(uint order, _Bool allow_rcu)
{
  ASSERT_DIE(order < sizeof(struct lock_order));
  struct domain_generic *dg = xmalloc(sizeof(struct domain_generic));
  *dg = (struct domain_generic) DOMAIN_INIT(order, allow_rcu);
  return dg;
}

void
domain_free(struct domain_generic *dg)
{
  pthread_mutex_destroy(&dg->mutex);
  xfree(dg);
}

const char *
domain_name(struct domain_generic *dg)
{
  return dg->name;
}

uint dg_order(struct domain_generic *dg)
{
  return dg->order;
}

void
domain_setup(struct domain_generic *dg, const char *name, pool *p)
{
  ASSERT_DIE(dg->pool == NULL);
  dg->pool = p;
  dg->name = name;
}

void do_lock(struct domain_generic *dg, struct domain_generic **lsp)
{
  struct lock_order stack_copy;
  memcpy(&stack_copy, &locking_stack, sizeof(stack_copy));
  struct domain_generic **lll = last_locked;

  if (dg->forbidden_when_reading_rcu)
    if (rcu_read_active())
      bug("Locking of this lock forbidden while RCU reader is active");
    else
      rcu_blocked++;

  if ((char *) lsp - (char *) &locking_stack != dg->order)
    bug("Trying to lock on bad position: order=%u, lsp=%p, base=%p", dg->order, lsp, &locking_stack);

  if (lsp <= last_locked)
    bug("Trying to lock in a bad order: %p %p", &stack_copy, lll);
  if (*lsp)
    bug("Inconsistent locking stack state on lock");

  btime lock_begin = current_time();
  pthread_mutex_lock(&dg->mutex);
  btime duration = current_time() - lock_begin;
  if (config && (duration > config->watchdog_warning))
    log(L_WARN "Locking of %s took %d ms", dg->name, (int) (duration TO_MS));

  if (dg->prev || dg->locked_by)
    bug("Previous unlock not finished correctly");
  dg->prev = last_locked;
  *lsp = dg;
  last_locked = lsp;
  dg->locked_by = &locking_stack;
}

void do_unlock(struct domain_generic *dg, struct domain_generic **lsp)
{
  if ((char *) lsp - (char *) &locking_stack != dg->order)
    bug("Trying to unlock on bad position: order=%u, lsp=%p, base=%p", dg->order, lsp, &locking_stack);

  if (dg->locked_by != &locking_stack)
    bug("Inconsistent domain state on unlock");
  if ((last_locked != lsp) || (*lsp != dg))
    bug("Inconsistent locking stack state on unlock");
  dg->locked_by = NULL;
  last_locked = dg->prev;
  *lsp = NULL;
  dg->prev = NULL;
  pthread_mutex_unlock(&dg->mutex);

  if (dg->forbidden_when_reading_rcu)
    ASSERT_DIE(rcu_blocked--);
}
