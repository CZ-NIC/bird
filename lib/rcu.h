/*
 *	BIRD Library -- Read-Copy-Update Basic Operations
 *
 *	(c) 2021 Maria Matejka <mq@jmq.cz>
 *	(c) 2021 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *	Note: all the relevant patents shall be expired.
 */

#ifndef _BIRD_RCU_H_
#define _BIRD_RCU_H_

#include "lib/birdlib.h"
#include "lib/lists.h"
#include <stdatomic.h>

#define RCU_GP_PHASE  0x100
#define RCU_NEST_MASK (RCU_GP_PHASE-1)
#define RCU_NEST_CNT  1

extern _Atomic u64 rcu_global_phase;

struct rcu_thread {
  struct rcu_thread * _Atomic next;
  u64 local_ctl;
  _Atomic u64 ctl;
};

extern _Thread_local struct rcu_thread this_rcu_thread;
extern _Thread_local uint rcu_blocked;

static inline void rcu_read_lock(void)
{
  /* Increment the nesting counter */
  atomic_store_explicit(&this_rcu_thread.ctl, (this_rcu_thread.local_ctl += RCU_NEST_CNT), memory_order_release);

  /* Just nested */
  u64 local_nest = this_rcu_thread.local_ctl & RCU_NEST_MASK;
  if (local_nest > RCU_NEST_CNT)
    return;

  ASSUME(local_nest == RCU_NEST_CNT);

  /* Update the phase */
  u64 new = atomic_load_explicit(&rcu_global_phase, memory_order_acquire) + RCU_NEST_CNT;
  atomic_store_explicit(&this_rcu_thread.ctl, new, memory_order_release);
  this_rcu_thread.local_ctl = new;
}

static inline void rcu_read_unlock(void)
{
  /* Just decrement the nesting counter; when unlocked, nobody cares */
  atomic_fetch_sub_explicit(&this_rcu_thread.ctl, RCU_NEST_CNT, memory_order_acq_rel);
  this_rcu_thread.local_ctl--;
}

static inline bool rcu_read_active(void)
{
  return !!(this_rcu_thread.local_ctl & RCU_NEST_MASK);
}

void synchronize_rcu(void);

/* Registering and unregistering a birdloop. To be called from birdloop implementation */
void rcu_thread_start(void);
void rcu_thread_stop(void);

/* Run this from resource init */
void rcu_init(void);

#endif
