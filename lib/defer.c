/*
 *	BIRD -- Deferring calls to the end of the task
 *
 *	(c) 2024       Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/defer.h"

_Thread_local struct deferred local_deferred = {};

static void
defer_execute(void *_ld)
{
  ASSERT_DIE(_ld == &local_deferred);

  /* Run */
  for (struct deferred_call *call = local_deferred.first; call; call = call->next)
    call->hook(call);

  /* Cleanup */
  local_deferred.first = NULL;
  local_deferred.last = &local_deferred.first;

  lp_flush(local_deferred.lp);
}

void
defer_init(linpool *lp)
{
  local_deferred = (struct deferred) {
    .e = {
      .hook = defer_execute,
      .data = &local_deferred,
    },
    .lp = lp,
    .last = &local_deferred.first,
  };
}
