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
#define LOCAL_DEBUG

#undef DEBUG_LOCKING

#include "lib/birdlib.h"
#include "lib/event.h"

//#define CORO_STACK_SIZE 65536
#define CORO_STACK_SIZE 32768

/*
 *	Implementation of coroutines based on POSIX threads
 */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 *	Locking subsystem
 */

#define DOMAIN(type) struct domain__##type
#define ASSERT_NO_LOCK	ASSERT_DIE(last_locked == NULL)

struct domain_generic {
  pthread_mutex_t mutex;
  struct domain_generic **prev;
  struct lock_order *locked_by;
};

#define DOMAIN_INIT { .mutex = PTHREAD_MUTEX_INITIALIZER }

static struct domain_generic event_state_domain_gen = DOMAIN_INIT,
			     the_bird_domain_gen = DOMAIN_INIT;

DEFINE_DOMAIN(event_state);
static DOMAIN(event_state) event_state_domain = { .event_state = &event_state_domain_gen };

DOMAIN(the_bird) the_bird_domain = { .the_bird = &the_bird_domain_gen };

#define EVENT_LOCKED LOCKED_DO(event_state, &event_state_domain)
#define EVENT_UNLOCKED for ( \
  _Bool _bird_aux = (do_unlock(event_state_domain.event_state, &locking_stack.event_state), 1); \
  _bird_aux ? ((_bird_aux = 0), 1) : 0; \
  do_lock(event_state_domain.event_state, &locking_stack.event_state))

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

static _Thread_local struct coroutine *coro_local = NULL;
static _Thread_local event *ev_local = NULL;

struct coroutine {
  pthread_t id;				/* The appropriate pthread */
  pthread_attr_t attr;			/* Attributes (stack size, detachable, etc.) */
  pool *pool;				/* Memory pool for coro-local allocations */
  event *ev;				/* The event this coroutine is assigned to */
  union {
    sem_t cancel_sem;			/* Semaphore to post on coroutine cancellation */
    int cancel_pipe[2];			/* Pipe to ping on coroutine cancellation */
  };
  enum coro_flags {
    CORO_REPEAT = 0x2,			/* Run once more */
    CORO_STOP = 0x4,			/* Canceled by self */
    CORO_CANCEL_BY_SEMAPHORE = 0x10,	/* Cancel by posting a semaphore */
    CORO_CANCEL_BY_PIPE = 0x20,		/* Cancel by sending a byte into a pipe */
  } flags;
};

static const char ev_dump_coro_flagset[] = "0RS3sp";

static const char *ev_dump_coro(event *e)
{
  if (!e->coro)
    return "";

  _Thread_local static char buf[sizeof(ev_dump_coro_flagset)];

  uint pos = 0, i = 0;
  for (uint flags = e->coro->flags; flags; i++, flags >>= 1)
    if (i >= sizeof(ev_dump_coro_flagset))
      bug("Unknown coroutine flagset: 0x%x", e->coro->flags);
    else if (flags & 1)
      buf[pos++] = ev_dump_coro_flagset[i];

  buf[pos] = 0;
  return buf;
}

#define EV_DEBUG_FMT "(ev %p, code %p (%s), data %p, init %s:%u, %s)\n"
#define EV_DEBUG_ARGS(e) e, e->hook, e->name, e->data, e->file, e->line, ev_dump_coro(e)

#define EV_DEBUG(e, s, a...) DBG("%.6T: " s " " EV_DEBUG_FMT, ##a, EV_DEBUG_ARGS(e))

void
ev_dump(event *e)
{
  LOCKED_DO(event_state, &event_state_domain)
    debug(EV_DEBUG_FMT, EV_DEBUG_ARGS(e));
}

void *ev_alloc(uint size)
{
  if (coro_local)
  {
    EV_DEBUG(ev_local, "event alloc(%u)", size);
    return mb_alloc(coro_local->pool, size);
  }
  else
  {
    DBG("ev_alloc(%u) in main", size);
    return mb_alloc(&root_pool, size);
  }
}

static void coro_free(void)
{
  the_bird_lock();
  rfree(coro_local->pool);
  the_bird_unlock();
  if (coro_local->flags & CORO_CANCEL_BY_SEMAPHORE)
    sem_destroy(&coro_local->cancel_sem);
  else if (coro_local->flags & CORO_CANCEL_BY_PIPE)
  {
    close(coro_local->cancel_pipe[0]);
    close(coro_local->cancel_pipe[1]);
  }
  else
    bug("Coroutine with no cancellation mechanism!");

  pthread_attr_destroy(&coro_local->attr);
  xfree(coro_local);
  coro_local = NULL;
}

/* From sysdep/unix/io.c */
void io_update_time(void);
void io_log_event(void *hook, void *data);

static _Bool ev_get_cancelled(LOCKED(event_state))
{
  if (coro_local->flags & CORO_STOP)
    return 1;

  int e = sem_trywait(&coro_local->cancel_sem);
  if ((e < 0) && (errno == EAGAIN))
    return 0;

  if ((e < 0) && (errno == EINTR))
    return ev_get_cancelled(CURRENT_LOCK);

  if (e < 0)
    die("sem_trywait() failed in ev_get_cancelled: %M");

  ASSERT_DIE(e == 0);
  return 1;
}

static NORET void ev_do_cancel(LOCKED(event_state) UNUSED)
{
  /* Here the ev_local pointer is not a valid pointer, maybe */
  DBG("stopping cancelled event: %p\n", coro_local->ev);
  ev_local = NULL;

  EVENT_UNLOCKED
  {
    ASSERT_NO_LOCK;
    coro_free();
    pthread_exit(NULL);
  }

  bug("There shall happen nothing after pthread_exit()");
}

static void ev_check_cancelled(LOCKED(event_state))
{
  if (ev_get_cancelled(CURRENT_LOCK))
    ev_do_cancel(CURRENT_LOCK);
}

void ev_suspend(void)
{
  struct suspend_lock {
    struct domain_generic *lock, **slot;
  } stored[LOCK_ORDER_DEPTH];

  uint N = 0;
  while (last_locked)
  {
    stored[N++] = (struct suspend_lock) {
      .lock = *last_locked,
      .slot = last_locked,
    };

    do_unlock(*last_locked, last_locked);
  }

  while (N--)
  {
    do_lock(stored[N].lock, stored[N].slot);
    _Bool cancelled;
    EVENT_LOCKED cancelled = ev_get_cancelled(CURRENT_LOCK);
    if (!cancelled)
      continue;

    while (last_locked)
      do_unlock(*last_locked, last_locked);
    EVENT_LOCKED ev_do_cancel(CURRENT_LOCK);
  }
}

_Bool ev_active(event *e)
{
  _Bool out;

  EVENT_LOCKED
    out = !!e->coro;

  return out;
}

void ev_cancel(event *e)
{
  EVENT_LOCKED
  {
    if (e == ev_local)
      EV_DEBUG(e, "cancel from self");
    else if (ev_local)
      EV_DEBUG(e, "cancel from %p", ev_local);
    else
      EV_DEBUG(e, "cancel from main");

    if (e->coro)
    {
      e->coro->flags &= ~CORO_REPEAT;

      if (e == ev_local)
	e->coro->flags |= CORO_STOP;
      else if (e->coro->flags & CORO_CANCEL_BY_SEMAPHORE)
	sem_post(&(e->coro->cancel_sem));
      else if (e->coro->flags & CORO_CANCEL_BY_PIPE)
	write(e->coro->cancel_pipe[1], "", 1);
      else
	bug("Coroutine cancellation mode not set");

      e->coro = NULL;
    }
  }
}

extern _Thread_local struct timeloop *timeloop_current;

static void *coro_entry(void *data)
{
  EVENT_LOCKED
  {
    DBG("coro_entry(%p)\n", data);
    coro_local = data;

    ev_check_cancelled(CURRENT_LOCK);

    ev_local = coro_local->ev;
    timeloop_current = ev_local->timeloop;

    do {
      coro_local->flags &= ~CORO_REPEAT;
      io_log_event(ev_local->hook, ev_local->data);

      EV_DEBUG(ev_local, "event entry");

      EVENT_UNLOCKED
      {
	ASSERT_NO_LOCK;
	the_bird_lock();
	EV_DEBUG(ev_local, "event locked");

	_Bool cancelled;
	EVENT_LOCKED cancelled = ev_get_cancelled(CURRENT_LOCK);
	if (cancelled)
	{
	  the_bird_unlock();
	  EVENT_LOCKED ev_do_cancel(CURRENT_LOCK);
	}

	ev_local->hook(ev_local->data);

	EV_DEBUG(ev_local, "event unlocked");
	the_bird_unlock();
	ASSERT_NO_LOCK;
      }

      DBG("event %p exit\n", ev_local);
      io_update_time();
    } while (coro_local->flags & CORO_REPEAT);

    ev_check_cancelled(CURRENT_LOCK);

    DBG("coro_free(%p)\n", data);
    ev_local->coro = NULL;
  }

  coro_free();
  return NULL;
}

#ifdef DEBUGGING
void ev_schedule_(event *ev, const char *name, const char *file, uint line)
#else
void ev_schedule(event *ev)
#endif
{
  EVENT_LOCKED
  {
  int e = 0;
#ifdef DEBUGGING
  if (ev_local)
    EV_DEBUG(ev, "scheduling from %p event %s in %s:%u", ev_local, name, file, line);
  else
    EV_DEBUG(ev, "scheduling from main event %s in %s:%u", name, file, line);
#else
  if (ev_local)
    EV_DEBUG(ev, "scheduling from %p", ev_local);
  else
    EV_DEBUG(ev, "scheduling from main");
#endif

  if (ev->coro)
  {
    ev->coro->flags |= CORO_REPEAT;
    EV_DEBUG(ev, "repeat");
    LOCKED_BREAK;
  }

  struct coroutine *coro = ev->coro = xmalloc(sizeof(struct coroutine));
  memset(coro, 0, sizeof(struct coroutine));
  coro->ev = ev;
  coro->pool = rp_new(&root_pool, "Event pool");
  coro->flags |= CORO_CANCEL_BY_SEMAPHORE;
  sem_init(&coro->cancel_sem, 0, 0);

  if (e = pthread_attr_init(&coro->attr))
    die("pthread_attr_init() failed: %M", e);

  if (e = pthread_attr_setstacksize(&coro->attr, CORO_STACK_SIZE))
    die("pthread_attr_setstacksize(%u) failed: %M", CORO_STACK_SIZE, e);

  if (e = pthread_attr_setdetachstate(&coro->attr, PTHREAD_CREATE_DETACHED))
    die("pthread_attr_setdetachstate(PTHREAD_CREATE_DETACHED) failed: %M", e);

  if (e = pthread_create(&coro->id, &coro->attr, coro_entry, coro))
    die("pthread_create() failed: %M", e);
  
  EV_DEBUG(ev, "spawned");
  }
}
