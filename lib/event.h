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
#ifdef DEBUGGING
void ev_schedule_(event *, const char *, const char *, uint);
#define ev_schedule(e) ev_schedule_(e, #e, __FILE__, __LINE__)
#else
void ev_schedule(event *);
#endif

/* Run the event directly */
static inline void __attribute__((deprecated)) ev_run(event *e)
{ e->hook(e->data); }

/* Cancel an event */
void ev_cancel(event *);

/* Check whether an event is active or not from outside */
_Bool ev_active(event *e);

/* Suspend and wait for current locks.
 * This is an explicit cancellation point. */
void ev_suspend(void);

/* Allocate some memory with event-long duration and automagic release.
 * If called from the main thread, it allocates a memory block
 * from the root pool. */
void *ev_alloc(uint size);
static inline void *ev_realloc(void *mem, uint size)
{ return mb_realloc(mem, size); }

/* Dump event info on debug console */
void ev_dump(event *r);

/* Locking */
struct domain_generic;

/* Here define the global lock order; first to last. */
#define LOI(type) struct domain_generic *type;
struct lock_order {
  LOI(the_bird);
  LOI(event_state);
};
#undef LOI

#define LOCK_ORDER_DEPTH  (sizeof(struct lock_order) / sizeof(struct domain_generic *))

extern _Thread_local struct lock_order locking_stack;

/* Internal for locking */
void do_lock(struct domain_generic *dg, struct domain_generic **lsp);
void do_unlock(struct domain_generic *dg, struct domain_generic **lsp);

#define DOMAIN(type) struct domain__##type
#define DEFINE_DOMAIN(type) DOMAIN(type) { struct domain_generic *type; }

/* Pass a locked context to a subfunction */
#define LOCKED(type) DOMAIN(type) *_bird_current_lock
#define CURRENT_LOCK _bird_current_lock
#define ASSERT_LOCK(type) ASSERT_DIE(_bird_current_lock)

/* Do something in a locked context */
#define LOCKED_DO(type, d) for ( \
    UNUSED LOCKED(type) = (do_lock((d)->type, &(locking_stack.type)), (d)), *_bird_aux = (d); \
    _bird_aux ? ((_bird_aux = NULL), 1) : 0; \
    do_unlock((d)->type, &(locking_stack.type)))

/* Break from the locked context */
#define LOCKED_BREAK  continue

DEFINE_DOMAIN(the_bird);
extern DOMAIN(the_bird) the_bird_domain;

#define the_bird_lock()		do_lock(the_bird_domain.the_bird, &locking_stack.the_bird)
#define the_bird_unlock()	do_unlock(the_bird_domain.the_bird, &locking_stack.the_bird)

#endif
