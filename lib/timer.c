/*
 *	BIRD -- Timers
 *
 *	(c) 2013--2017 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2013--2017 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */


#include <stdlib.h>

#include "nest/bird.h"

#include "lib/heap.h"
#include "lib/resource.h"
#include "lib/timer.h"


struct timeloop main_timeloop;


#ifdef USE_PTHREADS

#include <pthread.h>

/* Data accessed and modified from proto/bfd/io.c */
pthread_key_t current_time_key;

static inline struct timeloop *
timeloop_current(void)
{
  return pthread_getspecific(current_time_key);
}

static inline void
timeloop_init_current(void)
{
  pthread_key_create(&current_time_key, NULL);
  pthread_setspecific(current_time_key, &main_timeloop);
}

void wakeup_kick_current(void);

#else

/* Just use main timelooop */
static inline struct timeloop * timeloop_current(void) { return &main_timeloop; }
static inline void timeloop_init_current(void) { }

#endif

btime
current_time(void)
{
  return timeloop_current()->last_time;
}


#define TIMER_LESS(a,b)		((a)->expires < (b)->expires)
#define TIMER_SWAP(heap,a,b,t)	(t = heap[a], heap[a] = heap[b], heap[b] = t, \
				   heap[a]->index = (a), heap[b]->index = (b))


static void
tm2_free(resource *r)
{
  timer2 *t = (timer2 *) r;

  tm2_stop(t);
}

static void
tm2_dump(resource *r)
{
  timer2 *t = (timer2 *) r;

  debug("(code %p, data %p, ", t->hook, t->data);
  if (t->randomize)
    debug("rand %d, ", t->randomize);
  if (t->recurrent)
    debug("recur %d, ", t->recurrent);
  if (t->expires)
    debug("expires in %d ms)\n", (t->expires - current_time()) TO_MS);
  else
    debug("inactive)\n");
}


static struct resclass tm2_class = {
  "Timer",
  sizeof(timer2),
  tm2_free,
  tm2_dump,
  NULL,
  NULL
};

timer2 *
tm2_new(pool *p)
{
  timer2 *t = ralloc(p, &tm2_class);
  t->index = -1;
  return t;
}

void
tm2_set(timer2 *t, btime when)
{
  struct timeloop *loop = timeloop_current();
  uint tc = timers_count(loop);

  if (!t->expires)
  {
    t->index = ++tc;
    t->expires = when;
    BUFFER_PUSH(loop->timers) = t;
    HEAP_INSERT(loop->timers.data, tc, timer2 *, TIMER_LESS, TIMER_SWAP);
  }
  else if (t->expires < when)
  {
    t->expires = when;
    HEAP_INCREASE(loop->timers.data, tc, timer2 *, TIMER_LESS, TIMER_SWAP, t->index);
  }
  else if (t->expires > when)
  {
    t->expires = when;
    HEAP_DECREASE(loop->timers.data, tc, timer2 *, TIMER_LESS, TIMER_SWAP, t->index);
  }

#ifdef CONFIG_BFD
  /* Hack to notify BFD loops */
  if ((loop != &main_timeloop) && (t->index == 1))
    wakeup_kick_current();
#endif
}

void
tm2_start(timer2 *t, btime after)
{
  tm2_set(t, current_time() + MAX(after, 0));
}

void
tm2_stop(timer2 *t)
{
  if (!t->expires)
    return;

  struct timeloop *loop = timeloop_current();
  uint tc = timers_count(loop);

  HEAP_DELETE(loop->timers.data, tc, timer2 *, TIMER_LESS, TIMER_SWAP, t->index);
  BUFFER_POP(loop->timers);

  t->index = -1;
  t->expires = 0;
}

void
timers_init(struct timeloop *loop, pool *p)
{
  times_init(loop);

  BUFFER_INIT(loop->timers, p, 4);
  BUFFER_PUSH(loop->timers) = NULL;
}

void io_log_event(void *hook, void *data);

void
timers_fire(struct timeloop *loop)
{
  btime base_time;
  timer2 *t;

  times_update(loop);
  base_time = loop->last_time;

  while (t = timers_first(loop))
  {
    if (t->expires > base_time)
      return;

    if (t->recurrent)
    {
      btime when = t->expires + t->recurrent;

      if (when <= loop->last_time)
	when = loop->last_time + t->recurrent;

      if (t->randomize)
	when += random() % (t->randomize + 1);

      tm2_set(t, when);
    }
    else
      tm2_stop(t);

    /* This is ugly hack, we want to log just timers executed from the main I/O loop */
    if (loop == &main_timeloop)
      io_log_event(t->hook, t->data);

    t->hook(t);
  }
}

void
timer_init(void)
{
  timers_init(&main_timeloop, &root_pool);
  timeloop_init_current();
}
