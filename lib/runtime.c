/*
 *	BIRD Internet Routing Daemon -- Global runtime context
 *
 *	(c) 2024       Maria Matejka <mq@jmq.cz>
 *	(c) 2024       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/runtime.h"

struct global_runtime global_runtime_initial = {
  .tf_log = {
    .fmt1 = "%F %T.%3f",
  },
  .tf_base = {
    .fmt1 = "%F %T.%3f",
  },
};

struct global_runtime * _Atomic global_runtime = &global_runtime_initial;

void
switch_runtime(struct global_runtime *new)
{
  new->load_time = current_time();
  atomic_store_explicit(&global_runtime, new, memory_order_release);

  /* We have to wait until every reader surely doesn't read the old values */
  synchronize_rcu();
}

