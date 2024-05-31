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
  _Atomic u64 ctl;
};

extern _Thread_local struct rcu_thread this_rcu_thread;
extern _Thread_local uint rcu_blocked;

static inline void rcu_read_lock(void)
{
  /* Increment the nesting counter */
  u64 before = atomic_fetch_add_explicit(
      &this_rcu_thread.ctl,
      RCU_NEST_CNT,
      memory_order_acq_rel
      );

  if (before & RCU_NEST_MASK)
    return;

  /* Update the phase */
  u64 phase = atomic_load_explicit(&rcu_global_phase, memory_order_acquire);
  u64 dif = (before & ~RCU_NEST_MASK) ^ phase;

  if (dif)
    atomic_fetch_xor_explicit(
	&this_rcu_thread.ctl,
	dif,
	memory_order_acq_rel);
}

static inline void rcu_read_unlock(void)
{
  /* Just decrement the nesting counter; when unlocked, nobody cares */
  atomic_fetch_sub(&this_rcu_thread.ctl, RCU_NEST_CNT);
}

static inline _Bool rcu_read_active(void)
{
  return !!(atomic_load_explicit(&this_rcu_thread.ctl, memory_order_acquire) & RCU_NEST_MASK);
}

void synchronize_rcu(void);

/* Registering and unregistering a birdloop. To be called from birdloop implementation */
void rcu_thread_start(void);
void rcu_thread_stop(void);

/* Run this from resource init */
void rcu_init(void);

#endif
