/*
 *	BIRD -- Deferring calls to the end of the task
 *
 *	(c) 2024       Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * There are cases when we need to just run something multiple times after the
 * current task ends, mostly for cleanup reasons, and it doesn't need the
 * full-blown event list overhead. Therefore, one just can use this tool
 * instead. */

#ifndef _BIRD_LIB_DEFER_H_
#define _BIRD_LIB_DEFER_H_

#include "lib/birdlib.h"
#include "lib/event.h"
#include "lib/resource.h"
#include "lib/io-loop.h"

struct deferred_call {
  struct deferred_call *next;
  void (*hook)(struct deferred_call *);
};

struct deferred {
  event e;
  linpool *lp;
  struct deferred_call *first, **last;
};

extern _Thread_local struct deferred local_deferred;
void defer_init(linpool *lp);

static inline struct deferred_call *
defer_call(struct deferred_call *call, size_t actual_size)
{
  /* Reallocate the call to the appropriate linpool */
  ASSERT_DIE(actual_size < 128);
  struct deferred_call *a = lp_alloc(local_deferred.lp, actual_size);
  memcpy(a, call, actual_size);

  /* If first, send the actual event to the local thread */
  if (local_deferred.last == &local_deferred.first)
    ev_send_defer(&local_deferred.e);
  //else
    //log("nop");

  /* Add to list */
  a->next = NULL;
  *local_deferred.last = a;
  local_deferred.last = &a->next;

  return a;
}

#endif
