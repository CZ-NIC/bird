/*
 *	BIRD Library -- Read-Copy-Update Basic Operations
 *
 *	(c) 2021 Maria Matejka <mq@jmq.cz>
 *	(c) 2021 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *	Note: all the relevant patents shall be expired.
 *
 *	Using the Supplementary Material for User-Level Implementations of Read-Copy-Update
 *	by Matthieu Desnoyers, Paul E. McKenney, Alan S. Stern, Michel R. Dagenais and Jonathan Walpole
 *	obtained from https://www.efficios.com/pub/rcu/urcu-supp-accepted.pdf
 */

#include "lib/rcu.h"
#include "lib/io-loop.h"
#include "lib/locking.h"

_Atomic u64 rcu_global_phase = RCU_GP_PHASE;
_Thread_local struct rcu_thread this_rcu_thread;
_Thread_local uint rcu_blocked;

static struct rcu_thread * _Atomic rcu_thread_list = NULL;

static _Atomic uint rcu_thread_spinlock = 0;

static int
rcu_critical(struct rcu_thread *t, u64 phase)
{
  uint val = atomic_load_explicit(&t->ctl, memory_order_acquire);
  return
    (val & RCU_NEST_MASK) /* Active */
    && ((val & ~RCU_NEST_MASK) <= phase); /* In an older phase */
}

void
synchronize_rcu(void)
{
  if (!rcu_blocked && (last_locked > &locking_stack.meta))
    bug("Forbidden to synchronize RCU unless an appropriate lock is taken");

  /* Increment phase */
  u64 phase = atomic_fetch_add_explicit(&rcu_global_phase, RCU_GP_PHASE, memory_order_acq_rel);

  while (1) {
    /* Spinlock */
    while (atomic_exchange_explicit(&rcu_thread_spinlock, 1, memory_order_acq_rel))
      birdloop_yield();

    /* Check all threads */
    _Bool critical = 0;
    for (struct rcu_thread * _Atomic *tp = &rcu_thread_list, *t;
	t = atomic_load_explicit(tp, memory_order_acquire);
	tp = &t->next)
      /* Found a critical */
      if (critical = rcu_critical(t, phase))
	break;

    /* Unlock */
    ASSERT_DIE(atomic_exchange_explicit(&rcu_thread_spinlock, 0, memory_order_acq_rel));

    /* Done if no critical */
    if (!critical)
      return;

    /* Wait and retry if critical */
    birdloop_yield();
  }
}

void
rcu_thread_start(void)
{
  /* Insert this thread to the thread list, no spinlock is needed */
  struct rcu_thread *next = atomic_load_explicit(&rcu_thread_list, memory_order_acquire);
  do atomic_store_explicit(&this_rcu_thread.next, next, memory_order_relaxed);
  while (!atomic_compare_exchange_strong_explicit(
	&rcu_thread_list, &next, &this_rcu_thread,
	memory_order_acq_rel, memory_order_acquire));
}

void
rcu_thread_stop(void)
{
  /* Spinlock */
  while (atomic_exchange_explicit(&rcu_thread_spinlock, 1, memory_order_acq_rel))
    birdloop_yield();

  /* Find this thread */
  for (struct rcu_thread * _Atomic *tp = &rcu_thread_list, *t;
      t = atomic_load_explicit(tp, memory_order_acquire);
      tp = &t->next)
    if (t == &this_rcu_thread)
    {
      /* Remove this thread */
      atomic_store_explicit(tp, atomic_load_explicit(&t->next, memory_order_acquire), memory_order_release);

      /* Unlock and go */
      ASSERT_DIE(atomic_exchange_explicit(&rcu_thread_spinlock, 0, memory_order_acq_rel));
      return;
    }

  bug("Failed to find a stopped rcu thread");
}

void
rcu_init(void)
{
  rcu_thread_start();
}
