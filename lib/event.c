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

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "lib/event.h"
#include "lib/io-loop.h"

event_list global_event_list;
event_list global_work_list;

//#ifdef DEBUGGING
#if 0
#define EDL_MAX		16384
enum edl_caller {
  EDL_REMOVE_FROM = 1,
  EDL_POSTPONE = 2,
  EDL_RUN = 3,
  EDL_SEND = 4, 
  EDL_RUN_LIST = 5,
} caller;
static struct event_debug_log {
  event_list *target_list;
  event *event;
  event *receiver;
  uint pos;
  uint prev_edl_pos;
  uint thread;
  enum edl_caller caller;
} edl[EDL_MAX];
static _Atomic uint edl_cnt;
_Thread_local static uint edl_thread;
_Thread_local static uint prev_edl_pos = ~0;
static inline void edlog(event_list *list, event *e, event *receiver, uint pos, enum edl_caller caller)
{
  uint edl_pos = atomic_fetch_add_explicit(&edl_cnt, 1, memory_order_acq_rel);
  if (!edl_thread)
    edl_thread = edl_pos;

  edl[edl_pos % EDL_MAX] = (struct event_debug_log) {
    .target_list = list,
    .event = e,
    .receiver = receiver,
    .pos = pos,
    .prev_edl_pos = prev_edl_pos,
    .thread = edl_thread,
    .caller = caller,
  };

  prev_edl_pos = edl_pos;
}
#else
#define edlog(...)
#endif


void
ev_init_list(event_list *el, struct birdloop *loop, const char *name)
{
  el->name = name;
  el->loop = loop;

  atomic_store_explicit(&el->receiver, NULL, memory_order_release);
  atomic_store_explicit(&el->_executor, NULL, memory_order_release);
}

/*
 * The event list should work as a message passing point. Sending a message
 * must be a fairly fast process with no locks and low waiting times. OTOH,
 * processing messages always involves running the assigned code and the
 * receiver is always a single one thread with no concurrency at all. There is
 * also a postponing requirement to synchronously remove an event from a queue,
 * yet we allow this only when the caller has its receiver event loop locked.
 * It still means that the event may get postponed from other event in the same
 * list, therefore we have to be careful.
 */

static inline int
ev_remove_from(event *e, event * _Atomic * head)
{
  /* The head pointer stores where cur is pointed to from */
  event * _Atomic *prev = head;

  /* The current event in queue to check */
  event *cur = atomic_load_explicit(prev, memory_order_acquire);

  /* This part of queue is empty! */
  if (!cur)
    return 0;

  edlog(NULL, e, cur, 1, EDL_REMOVE_FROM);
  while (cur)
  {
    /* Pre-loaded next pointer */
    event *next = atomic_load_explicit(&cur->next, memory_order_acquire);

    if (e == cur)
    {
      edlog(NULL, e, next, 3, EDL_REMOVE_FROM);

      /* Check whether we have collided with somebody else
       * adding an item to the queue. */
      if (!atomic_compare_exchange_strong_explicit(
	    prev, &cur, next,
	    memory_order_acq_rel, memory_order_acquire))
      {
	/* This may happen only on list head */
	ASSERT_DIE(prev == head);

	/* Restart. The collision should never happen again. */
	return ev_remove_from(e, head);
      }

      /* Successfully removed from the list; inactivate this event. */
      atomic_store_explicit(&cur->next, NULL, memory_order_release);
      return 1;
    }

    edlog(NULL, e, next, 2, EDL_REMOVE_FROM);

    /* Go to the next event. */
    prev = &cur->next;
    cur = next;
  }

  edlog(NULL, e, cur, 4, EDL_REMOVE_FROM);

  return 0;
}

inline void
ev_postpone(event *e)
{
  /* Find the list to remove the event from */
  event_list *sl = ev_get_list(e);
  edlog(sl, e, NULL, 1, EDL_POSTPONE);
  if (!sl)
    return;

  /* Postponing allowed only from the target loop */
  ASSERT_DIE(birdloop_inside(sl->loop));

  /* Remove from one of these lists. */
  ASSERT(ev_remove_from(e, &sl->_executor) || ev_remove_from(e, &sl->receiver));

  /* Mark as inactive */
  ASSERT_DIE(sl == atomic_exchange_explicit(&e->list, NULL, memory_order_acq_rel));
  edlog(sl, e, NULL, 2, EDL_POSTPONE);
}

static void
ev_dump(resource *r, unsigned indent UNUSED)
{
  event *e = (event *) r;

  debug("(code %p, data %p, %s)\n",
	e->hook,
	e->data,
	atomic_load_explicit(&e->next, memory_order_relaxed) ? "scheduled" : "inactive");
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
  edlog(NULL, e, NULL, 1, EDL_RUN);
  ev_postpone(e);
  e->hook(e->data);
  edlog(NULL, e, NULL, 2, EDL_RUN);
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
ev_send(event_list *l, event *e)
{
  edlog(l, e, NULL, 1, EDL_SEND);
  /* Set the target list */
  event_list *ol = NULL;
  if (!atomic_compare_exchange_strong_explicit(
	&e->list, &ol, l,
	memory_order_acq_rel, memory_order_acquire))
    if (ol == l)
      return;
    else
      bug("Queuing an already queued event to another queue is not supported.");

  /* Here should be no concurrent senders */
  event *next = atomic_load_explicit(&l->receiver, memory_order_acquire);
  edlog(l, e, next, 2, EDL_SEND);
  event *old_next = NULL;
  do
    if (!atomic_compare_exchange_strong_explicit(
	  &e->next, &old_next, next,
	  memory_order_acq_rel, memory_order_acquire))
      bug("Event %p in inconsistent state");
    else
    {
      old_next = next;
      edlog(l, old_next, next, 3, EDL_SEND);
    }
  while (!atomic_compare_exchange_strong_explicit(
	&l->receiver, &next, e,
	memory_order_acq_rel, memory_order_acquire));

  edlog(l, e, next, 4, EDL_SEND);
  if (l->loop) birdloop_ping(l->loop);
}

void io_log_event(void *hook, void *data);

/**
 * ev_run_list - run an event list
 * @l: an event list
 *
 * This function calls ev_run() for all events enqueued in the list @l.
 */
int
ev_run_list_limited(event_list *l, uint limit)
{
  event * _Atomic *ep = &l->_executor;
  edlog(l, NULL, NULL, 1, EDL_RUN_LIST);

  /* No pending events, refill the queue. */
  if (!atomic_load_explicit(ep, memory_order_acquire))
  {
    /* Move the current event list aside and create a new one. */
    event *received = atomic_exchange_explicit(&l->receiver, NULL, memory_order_acq_rel);
    edlog(l, NULL, received, 2, EDL_RUN_LIST);

    /* No event to run. */
    if (!received)
      return 0;

    /* Setup the executor queue */
    event *head = NULL;

    /* Flip the order of the events by relinking them one by one (push-pop) */
    while (received)
    {
      event *cur = received;
      received = atomic_exchange_explicit(&cur->next, head, memory_order_acq_rel);
      edlog(l, head, received, 3, EDL_RUN_LIST);
      head = cur;
    }

    /* Store the executor queue to its designated place */
    ASSERT_DIE(atomic_exchange_explicit(ep, head, memory_order_acq_rel) == NULL);
    edlog(l, NULL, head, 4, EDL_RUN_LIST);
  }

  /* Run the events in order. */
  event *e;
  while (e = atomic_load_explicit(ep, memory_order_acquire))
    {
      edlog(l, e, NULL, 5, EDL_RUN_LIST);
      /* Check limit */
      if (!--limit)
	return 1;

      /* This is ugly hack, we want to log just events executed from the main I/O loop */
      if ((l == &global_event_list) || (l == &global_work_list))
	io_log_event(e->hook, e->data);

      edlog(l, e, NULL, 6, EDL_RUN_LIST);
      /* Inactivate the event */
      event *next = atomic_load_explicit(&e->next, memory_order_relaxed);
      ASSERT_DIE(e == atomic_exchange_explicit(ep, next, memory_order_acq_rel));
      ASSERT_DIE(next == atomic_exchange_explicit(&e->next, NULL, memory_order_acq_rel));
      ASSERT_DIE(l == atomic_exchange_explicit(&e->list, NULL, memory_order_acq_rel));
      edlog(l, e, next, 7, EDL_RUN_LIST);

      /* Run the event */
      e->hook(e->data);
      tmp_flush();

      edlog(l, e, next, 8, EDL_RUN_LIST);
    }

  return !!atomic_load_explicit(&l->receiver, memory_order_acquire);
}
