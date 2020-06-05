/*
 *	BIRD Library -- Event Processing
 *
 *	(c) 1999 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Events
 *
 * Events are there to keep track of deferred execution.
 * Since BIRD is single-threaded, it requires long lasting tasks to be split to smaller
 * parts, so that no module can monopolize the CPU. To split such a task, just create
 * an &event resource, point it to the function you want to have called and call ev_schedule()
 * to ask the core to run the event when nothing more important requires attention.
 *
 * You can also define your own event lists (the &event_list structure), enqueue your
 * events in them and explicitly ask to run them.
 */

#include "nest/bird.h"
#include "lib/event.h"

extern _Thread_local struct timeloop *timeloop_current;

static void
ev_free(resource *r)
{
  event *e = (event *) r;

  if (ev_active(e))
    ev_cancel(e);
}

static void ev_dump_res(resource *r)
{
  event *e = (event *) r;
  ev_dump(e);
}

static struct resclass ev_class = {
  "Event",
  sizeof(event),
  ev_free,
  ev_dump_res,
  NULL,
  NULL
};

/**
 * ev_new - create a new event
 * @p: resource pool
 *
 * This function creates a new event resource. To use it,
 * you need to fill the structure fields and call ev_schedule().
 */
event *
ev_new(pool *p)
{
  event *e = ralloc(p, &ev_class);
  e->timeloop = timeloop_current;
  e->coro = NULL;
  return e;
}
