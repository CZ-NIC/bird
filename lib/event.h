/*
 *	BIRD Library -- Event Processing
 *
 *	(c) 1999 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_EVENT_H_
#define _BIRD_EVENT_H_

#include "lib/resource.h"
#include "lib/locking.h"

#include <stdatomic.h>

struct birdloop;

typedef struct event {
  resource r;
  void (*hook)(void *);
  void *data;
  struct event * _Atomic next;
} event;

typedef union event_list {
  struct {
    event * _Atomic receiver;	/* Event receive list */
    event * _Atomic _executor;	/* Event execute list */
    const char *name;
    struct birdloop *loop;	/* The executor loop */
    char _end[0];
  };
  event _sentinel;	/* Sentinel node to actively detect list end */
} event_list;

extern event_list global_event_list;
extern event_list global_work_list;

event *ev_new(pool *);
void ev_run(event *);
void ev_init_list(event_list *, struct birdloop *loop, const char *name);
void ev_enqueue(event_list *, event *);
#define ev_send ev_enqueue
#define ev_send_loop(l, e) ev_send(birdloop_event_list((l)), (e))

#define ev_schedule(e) ({ ASSERT_THE_BIRD_LOCKED; if (!ev_active((e))) ev_send(&global_event_list, (e)); })
#define ev_schedule_work(e) ({ ASSERT_THE_BIRD_LOCKED; if (!ev_active((e))) ev_send(&global_work_list, (e)); })

void ev_postpone(event *);
int ev_run_list_limited(event_list *, uint);
#define ev_run_list(l)	ev_run_list_limited((l), ~0)

#define LEGACY_EVENT_LIST(l)  (((l) == &global_event_list) || ((l) == &global_work_list))

static inline int
ev_active(event *e)
{
  return atomic_load_explicit(&e->next, memory_order_relaxed) != NULL;
}

static inline event_list *
ev_get_list(event *e)
{
  /* We are looking for the sentinel node at the list end.
   * After this, we have s->next == NULL */
  event *s = e;
  for (event *sn; sn = atomic_load_explicit(&s->next, memory_order_acquire); s = sn)
    ;

  /* No sentinel, no list. */
  if (s == e)
    return NULL;
  else
    return SKIP_BACK(event_list, _sentinel, s);
}

static inline event*
ev_new_init(pool *p, void (*hook)(void *), void *data)
{
  event *e = ev_new(p);
  e->hook = hook;
  e->data = data;
  return e;
}


#endif
