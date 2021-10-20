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

DEFINE_DOMAIN(event);
DEFINE_DOMAIN(cork);

typedef struct event {
  resource r;
  void (*hook)(void *);
  void *data;
  node n;				/* Internal link */
  struct event_list *list;		/* List where this event is put in */
  struct event_cork *cork;		/* Event execution limiter */
  node cork_node;
} event;

typedef struct event_list {
  list events;
  pool *pool;
  struct birdloop *loop;
  DOMAIN(event) lock;
} event_list;

struct event_cork {
  DOMAIN(cork) lock;
  u32 count;
  list events;
};

extern event_list global_event_list;
extern event_list global_work_list;

event *ev_new(pool *);
void ev_run(event *);

static inline void ev_init_list(event_list *el, struct birdloop *loop, const char *name)
{
  init_list(&el->events);
  el->loop = loop;
  el->lock = DOMAIN_NEW(event, name);
}

static inline void ev_init_cork(struct event_cork *ec, const char *name)
{
  init_list(&ec->events);
  ec->lock = DOMAIN_NEW(cork, name);
  ec->count = 0;
};

void ev_send(event_list *, event *);
#define ev_send_loop(l, e) ev_send(birdloop_event_list((l)), (e))

#define ev_schedule(e) ({ ASSERT_THE_BIRD_LOCKED; if (!ev_active((e))) ev_send(&global_event_list, (e)); })
#define ev_schedule_work(e) ({ ASSERT_THE_BIRD_LOCKED; if (!ev_active((e))) ev_send(&global_work_list, (e)); })

void ev_postpone(event *);
int ev_run_list(event_list *);
int ev_run_list_limited(event_list *, uint);

#define LEGACY_EVENT_LIST(l)  (((l) == &global_event_list) || ((l) == &global_work_list))

void ev_cork(struct event_cork *);
void ev_uncork(struct event_cork *);

static inline u32 ev_corked(struct event_cork *ec)
{
  if (!ec)
    return 0;

  LOCK_DOMAIN(cork, ec->lock);
  u32 out = ec->count;
  UNLOCK_DOMAIN(cork, ec->lock);
  return out;
}

_Bool birdloop_inside(struct birdloop *loop);

static inline int
ev_active(event *e)
{
  if (e->list == NULL)
    return 0;

  ASSERT_DIE(birdloop_inside(e->list->loop));
  return enlisted(&e->n);
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
