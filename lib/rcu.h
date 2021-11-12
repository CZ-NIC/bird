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

#define RCU_GP_PHASE  0x100000
#define RCU_NEST_MASK 0x0fffff
#define RCU_NEST_CNT  0x000001

extern _Atomic uint rcu_gp_ctl;

struct rcu_coro {
  node n;
  _Atomic uint ctl;
};

extern _Thread_local struct rcu_coro *this_rcu_coro;

static inline void rcu_read_lock(void)
{
  uint cmp = atomic_load_explicit(&this_rcu_coro->ctl, memory_order_acquire);

  if (cmp & RCU_NEST_MASK)
    atomic_store_explicit(&this_rcu_coro->ctl, cmp + RCU_NEST_CNT, memory_order_relaxed);
  else
    atomic_store(&this_rcu_coro->ctl, atomic_load_explicit(&rcu_gp_ctl, memory_order_acquire));
}

static inline void rcu_read_unlock(void)
{
  atomic_fetch_sub(&this_rcu_coro->ctl, RCU_NEST_CNT);
}

void synchronize_rcu(void);

/* Registering and unregistering a coroutine. To be called from coroutine implementation */
void rcu_coro_start(struct rcu_coro *);
void rcu_coro_stop(struct rcu_coro *);

/* Run this from resource init */
void rcu_init(void);

#endif
