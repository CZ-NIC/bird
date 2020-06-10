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

#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>

pthread_mutex_t event_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static inline void event_state_lock(void)
{
  pthread_mutex_lock(&event_state_mutex);
}

static inline void event_state_unlock(void)
{
  pthread_mutex_unlock(&event_state_mutex);
}

static _Thread_local struct coroutine *coro_local = NULL;
static _Thread_local event *ev_local = NULL;

void the_bird_lock(void);
void the_bird_unlock(void);

struct coroutine {
  pthread_t id;
  pthread_attr_t attr;
  pool *pool;
  event *ev;
  uint flags;
};

#define CORO_CANCEL 0x1	  /* Finish this run and stop */
#define CORO_REPEAT 0x2	  /* Run once more */

static const char *ev_dump_coro_flagset[] = {
  "T", "TC", "TR", "TCR",
};

static const char *ev_dump_coro(event *e)
{
  if (e->coro)
    return ev_dump_coro_flagset[e->coro->flags];
  else
    return "";
}

#define EV_DEBUG_FMT "(ev %p, code %p (%s), data %p, init %s:%u, %s)\n"
#define EV_DEBUG_ARGS(e) e, e->hook, e->name, e->data, e->file, e->line, ev_dump_coro(e)

#define EV_DEBUG(e, s, a...) DBG("%.6T: " s " " EV_DEBUG_FMT, ##a, EV_DEBUG_ARGS(e))

void
ev_dump(event *e)
{
  event_state_lock();
  debug(EV_DEBUG_FMT, EV_DEBUG_ARGS(e));
  event_state_unlock();
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
  pthread_attr_destroy(&coro_local->attr);
  rfree(coro_local->pool);
  xfree(coro_local);
  coro_local = NULL;
}

/* From sysdep/unix/io.c */
void io_update_time(void);
void io_log_event(void *hook, void *data);

static void NORET ev_finish_cancelled(void)
{
  /* Here the ev_local pointer is not a valid pointer */
  DBG("stopping cancelled event: %p\n", coro_local->ev);
  ev_local = NULL;

  coro_free();
  event_state_unlock();
  the_bird_unlock();
  pthread_exit(NULL);
}

void ev_suspend(void)
{
  ASSERT(coro_local);
  EV_DEBUG(ev_local, "event suspend");
  io_update_time();
  the_bird_unlock();

  the_bird_lock();
  event_state_lock();
  if (coro_local->flags & CORO_CANCEL)
    ev_finish_cancelled();

  io_log_event(ev_local->hook, ev_local->data);
  EV_DEBUG(ev_local, "event continued");
  event_state_unlock();
}

_Bool ev_active(event *e)
{
  event_state_lock();
  _Bool out = !!e->coro;
  event_state_unlock();
  return out;
}

void ev_cancel(event *e)
{
  event_state_lock();
  if (e == ev_local)
    EV_DEBUG(e, "cancel from self");
  else if (ev_local)
    EV_DEBUG(e, "cancel from %p", ev_local);
  else
    EV_DEBUG(e, "cancel from main");

  if (e->coro)
  {
    e->coro->flags |= CORO_CANCEL;
    e->coro->flags &= ~CORO_REPEAT;
    e->coro = NULL;
  }
  event_state_unlock();
}

extern _Thread_local struct timeloop *timeloop_current;

static void *coro_entry(void *data)
{
  DBG("coro_entry(%p)\n", data);
  coro_local = data;
  the_bird_lock();
  event_state_lock();

  if (coro_local->flags & CORO_CANCEL)
    ev_finish_cancelled();

  ev_local = coro_local->ev;
  timeloop_current = ev_local->timeloop;

  do {
    coro_local->flags &= ~CORO_REPEAT;
    io_log_event(ev_local->hook, ev_local->data);

    EV_DEBUG(ev_local, "event entry");
    event_state_unlock();

    ev_local->hook(ev_local->data);

    DBG("event %p exit\n", ev_local);
    io_update_time();
    the_bird_unlock();

    /* Yield here */

    the_bird_lock();
    event_state_lock();

  } while (coro_local->flags & CORO_REPEAT);

  if (coro_local->flags & CORO_CANCEL)
    ev_finish_cancelled();

  DBG("coro_free(%p)\n", data);
  ev_local->coro = NULL;
  event_state_unlock();
  the_bird_unlock();
  coro_free();
  pthread_exit(NULL);
}

void ev_schedule(event *ev)
{
  event_state_lock();
  int e = 0;
  if (ev_local)
    EV_DEBUG(ev, "scheduling from %p", ev_local);
  else
    EV_DEBUG(ev, "scheduling from main");

  if (ev->coro)
  {
    ev->coro->flags |= CORO_REPEAT;
    EV_DEBUG(ev, "repeat");
    event_state_unlock();
    return;
  }

  struct coroutine *coro = ev->coro = xmalloc(sizeof(struct coroutine));
  memset(coro, 0, sizeof(struct coroutine));
  coro->ev = ev;
  coro->pool = rp_new(&root_pool, "Event pool");

  if (e = pthread_attr_init(&coro->attr))
    die("pthread_attr_init() failed: %M", e);

  if (e = pthread_attr_setstacksize(&coro->attr, CORO_STACK_SIZE))
    die("pthread_attr_setstacksize(%u) failed: %M", CORO_STACK_SIZE, e);

  if (e = pthread_attr_setdetachstate(&coro->attr, PTHREAD_CREATE_DETACHED))
    die("pthread_attr_setdetachstate(PTHREAD_CREATE_DETACHED) failed: %M", e);

  if (e = pthread_create(&coro->id, &coro->attr, coro_entry, coro))
    die("pthread_create() failed: %M", e);
  
  EV_DEBUG(ev, "spawned");
  event_state_unlock();
}

pthread_mutex_t the_bird_global_lock = PTHREAD_MUTEX_INITIALIZER;

void the_bird_lock(void)
{
  pthread_mutex_lock(&the_bird_global_lock);
#ifdef DEBUG_LOCKING
  DBG("the_bird_lock() in %p\n", ev_local);
#endif
}

void the_bird_unlock(void)
{
#ifdef DEBUG_LOCKING
  DBG("the_bird_unlock() in %p\n", ev_local);
#endif
  pthread_mutex_unlock(&the_bird_global_lock);
}
