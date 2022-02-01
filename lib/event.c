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
#include "lib/locking.h"
#include "lib/io-loop.h"

extern _Thread_local struct coroutine *this_coro;

event_list global_event_list;
event_list global_work_list;

inline void
ev_postpone(event *e)
{
  event_list *el = e->list;
  if (!el)
    return;

  ASSERT_DIE(birdloop_inside(el->loop));

  LOCK_DOMAIN(event, el->lock);
  if (ev_active(e))
    rem_node(&e->n);
  UNLOCK_DOMAIN(event, el->lock);
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
ev_send(event_list *l, event *e)
{
  DBG("ev_send(%p, %p)\n", l, e);
  ASSERT_DIE(e->hook);
  ASSERT_DIE(!e->list || (e->list == l) || (e->list->loop == l->loop));

  e->list = l;

  struct event_cork *ec = e->cork;

  uint ping = 0;

  if (ec)
  {
    LOCK_DOMAIN(cork, ec->lock);
    LOCK_DOMAIN(event, l->lock);

    if (!enlisted(&e->n))
      if (ec->count)
	add_tail(&ec->events, &e->n);
      else
      {
	add_tail(&l->events, &e->n);
	ping = 1;
      }

    UNLOCK_DOMAIN(event, l->lock);
    UNLOCK_DOMAIN(cork, ec->lock);
  }
  else
  {
    LOCK_DOMAIN(event, l->lock);

    if (!enlisted(&e->n))
    {
      add_tail(&l->events, &e->n);
      ping = 1;
    }

    UNLOCK_DOMAIN(event, l->lock);
  }

  if (ping)
    birdloop_ping(l->loop);
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
  const _Bool legacy = LEGACY_EVENT_LIST(l);

  if (legacy)
    ASSERT_THE_BIRD_LOCKED;

  node *n;

  list tmp_list;
  init_list(&tmp_list);

  /* Move the event list contents to a local list to avoid executing repeatedly added events */
  LOCK_DOMAIN(event, l->lock);
  add_tail_list(&tmp_list, &l->events);
  init_list(&l->events);
  UNLOCK_DOMAIN(event, l->lock);

  WALK_LIST_FIRST(n, tmp_list)
    {
      event *e = SKIP_BACK(event, n, n);
      ASSERT_DIE(n->next->prev == n);

      if (legacy)
      {
	/* The legacy way of event execution */
	io_log_event(e->hook, e->data);
	ev_postpone(e);
	e->hook(e->data);
      }
      else
      {
	// io_log_event(e->hook, e->data); /* TODO: add support for event logging in other io loops */
	ASSERT_DIE(e->list == l);
	LOCK_DOMAIN(event, l->lock);
	rem_node(&e->n);
	UNLOCK_DOMAIN(event, l->lock);
	e->hook(e->data);
      }
    }

  LOCK_DOMAIN(event, l->lock);
  int repeat = ! EMPTY_LIST(l->events);
  UNLOCK_DOMAIN(event, l->lock);
  return repeat;
}

int
ev_run_list_limited(event_list *l, uint limit)
{
  ASSERT_DIE(LEGACY_EVENT_LIST(l));
  ASSERT_THE_BIRD_LOCKED;

  node *n;
  list tmp_list;

  LOCK_DOMAIN(event, l->lock);
  init_list(&tmp_list);
  add_tail_list(&tmp_list, &l->events);
  init_list(&l->events);
  UNLOCK_DOMAIN(event, l->lock);

  WALK_LIST_FIRST(n, tmp_list)
    {
      event *e = SKIP_BACK(event, n, n);

      if (!limit)
	break;

      io_log_event(e->hook, e->data);

      ev_run(e);
      limit--;
    }

  LOCK_DOMAIN(event, l->lock);
  if (!EMPTY_LIST(tmp_list))
  {
    /* Attach new items after the unprocessed old items */
    add_tail_list(&tmp_list, &l->events);
    init_list(&l->events);
    add_tail_list(&l->events, &tmp_list);
  }

  int repeat = ! EMPTY_LIST(l->events);
  UNLOCK_DOMAIN(event, l->lock);

  return repeat;
}

void ev_cork(struct event_cork *ec)
{
  LOCK_DOMAIN(cork, ec->lock);
  ec->count++;
  UNLOCK_DOMAIN(cork, ec->lock);
}

void ev_uncork(struct event_cork *ec)
{
  LOCK_DOMAIN(cork, ec->lock);

  if (--ec->count)
  {
    UNLOCK_DOMAIN(cork, ec->lock);
    return;
  }

  node *n;
  WALK_LIST_FIRST(n, ec->events)
    {
      event *e = SKIP_BACK(event, n, n);
      event_list *el = e->list;

      rem_node(&e->n);

      LOCK_DOMAIN(event, el->lock);
      add_tail(&el->events, &e->n);
      UNLOCK_DOMAIN(event, el->lock);

      birdloop_ping(el->loop);
    }

  struct birdsock *sk;
  WALK_LIST_FIRST2(sk, cork_node, ec->sockets)
    {
//      log(L_TRACE "Socket %p uncorked", sk);
      rem_node(&sk->cork_node);
      sk_ping(sk);
    }

  UNLOCK_DOMAIN(cork, ec->lock);
}
