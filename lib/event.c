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

event_list global_event_list;
event_list global_work_list;

inline void
ev_postpone(event *e)
{
  if (ev_active(e))
    {
      rem_node(&e->n);
      e->n.next = NULL;
    }
}

static void
ev_dump(resource *r)
{
  event *e = (event *) r;

  debug("(code %p, data %p, %s)\n",
	e->hook,
	e->data,
	e->n.next ? "scheduled" : "inactive");
}

static struct resclass ev_class = {
  "Event",
  sizeof(event),
  (void (*)(resource *)) ev_postpone,
  ev_dump,
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
  return e;
}

/**
 * ev_run - run an event
 * @e: an event
 *
 * This function explicitly runs the event @e (calls its hook
 * function) and removes it from an event list if it's linked to any.
 *
 * From the hook function, you can call ev_enqueue() or ev_schedule()
 * to re-add the event.
 */
inline void
ev_run(event *e)
{
  ev_postpone(e);
  e->hook(e->data);
}

/**
 * ev_enqueue - enqueue an event
 * @l: an event list
 * @e: an event
 *
 * ev_enqueue() stores the event @e to the specified event
 * list @l which can be run by calling ev_run_list().
 */
inline void
ev_enqueue(event_list *l, event *e)
{
  ev_postpone(e);
  add_tail(l, &e->n);
}

/**
 * ev_schedule - schedule an event
 * @e: an event
 *
 * This function schedules an event by enqueueing it to a system-wide
 * event list which is run by the platform dependent code whenever
 * appropriate.
 */
void
ev_schedule(event *e)
{
  ev_enqueue(&global_event_list, e);
}

/**
 * ev_schedule_work - schedule a work-event.
 * @e: an event
 *
 * This function schedules an event by enqueueing it to a system-wide work-event
 * list which is run by the platform dependent code whenever appropriate. This
 * is designated for work-events instead of regular events. They are executed
 * less often in order to not clog I/O loop.
 */
void
ev_schedule_work(event *e)
{
  if (!ev_active(e))
    add_tail(&global_work_list, &e->n);
}

void io_log_event(void *hook, void *data);

/**
 * ev_run_list - run an event list
 * @l: an event list
 *
 * This function calls ev_run() for all events enqueued in the list @l.
 */
int
ev_run_list(event_list *l)
{
  node *n;
  list tmp_list;

  init_list(&tmp_list);
  add_tail_list(&tmp_list, l);
  init_list(l);
  WALK_LIST_FIRST(n, tmp_list)
    {
      event *e = SKIP_BACK(event, n, n);

      /* This is ugly hack, we want to log just events executed from the main I/O loop */
      if ((l == &global_event_list) || (l == &global_work_list))
	io_log_event(e->hook, e->data);

      ev_run(e);
    }

  return !EMPTY_LIST(*l);
}

int
ev_run_list_limited(event_list *l, uint limit)
{
  node *n;
  list tmp_list;

  init_list(&tmp_list);
  add_tail_list(&tmp_list, l);
  init_list(l);

  WALK_LIST_FIRST(n, tmp_list)
    {
      event *e = SKIP_BACK(event, n, n);

      if (!limit)
	break;

      /* This is ugly hack, we want to log just events executed from the main I/O loop */
      if ((l == &global_event_list) || (l == &global_work_list))
	io_log_event(e->hook, e->data);

      ev_run(e);
      limit--;
    }

  if (!EMPTY_LIST(tmp_list))
  {
    /* Attach new items after the unprocessed old items */
    add_tail_list(&tmp_list, l);
    init_list(l);
    add_tail_list(l, &tmp_list);
  }

  return !EMPTY_LIST(*l);
}
