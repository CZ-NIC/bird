/*
 *	BIRD Library -- Event Processing
 *
 *	(c) 1999-2017 Martin Mares <mj@ucw.cz>
 *	(c) 2020 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_EVENT_H_
#define _BIRD_EVENT_H_

#include "lib/resource.h"

// The structure is completely opaque, implemented by sysdep
typedef struct coroutine coroutine;

typedef struct event {
  resource r;
  void (*hook)(void *);
  void *data;
  struct timeloop *timeloop;
  coroutine *coro;
  const char *name;
  const char *file;
  uint line;
} event;

/* These routines are called from outside */
/* Create a new event */
event *ev_new(pool *);

/* Initialize an event; run only if event is inactive. */
#define ev_setup(e, _hook, _data) ({ \
    e->hook = _hook; \
    e->data = _data; \
    e->name = #_hook; \
    e->file = __FILE__; \
    e->line = __LINE__; \
    })

/* Create and initialize a new event */
#define ev_new_init(p, hook, data) ({ \
    event *e = ev_new(p); \
    ev_setup(e, hook, data); \
    e; })

/* Schedule the event */
void ev_schedule(event *);

/* Run the event directly */
static inline void __attribute__((deprecated)) ev_run(event *e)
{ e->hook(e->data); }

/* Cancel an event */
void ev_cancel(event *);

/* Check whether an event is active or not */
_Bool ev_active(event *e);

/* These routines are called from inside the event */
/* Yield */
void ev_suspend(void);

/* Allocate some memory with event-long duration and automagic release.
 * If called from the main thread, it allocates a memory block
 * from the root pool. */
void *ev_alloc(uint size);
static inline void *ev_realloc(void *mem, uint size)
{ return mb_realloc(mem, size); }

/* Dump event info on debug console */
void ev_dump(event *r);

#endif
