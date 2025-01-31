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

static struct rcu_thread * _Atomic rcu_thread_list = NULL;

bool
rcu_end_sync(struct rcu_stored_phase phase)
{
  _Thread_local static u64 rcu_last_cleared_phase = 0;

  /* First check local cache */
  if ((rcu_last_cleared_phase - phase.phase) < (1ULL << 63))
    return true;

  /* We read the thread list */
  rcu_read_lock();

  /* Check all threads */
  u64 least = atomic_load_explicit(&rcu_global_phase, memory_order_acquire);

  for (struct rcu_thread * _Atomic *tp = &rcu_thread_list, *t;
      t = atomic_load_explicit(tp, memory_order_acquire);
      tp = &t->next)
  {
    /* Load the phase */
    u64 val = atomic_load_explicit(&t->ctl, memory_order_acquire);
    if (val & RCU_NEST_MASK) /* Active */
    {
      /* Too old phase */
      if ((phase.phase - val) < (1ULL << 63))
      {
	rcu_read_unlock();
	return false;
      }

      /* New enough, find oldest */
      if ((least - val) < (1ULL << 63))
	least = val & ~RCU_NEST_MASK;
    }
  }

  rcu_read_unlock();

  /* Store oldest */
  rcu_last_cleared_phase = least - RCU_GP_PHASE;
  return true;
}

static _Atomic int rcu_thread_list_writelock = 0;
void
rcu_thread_start(void)
{
  while (atomic_exchange_explicit(&rcu_thread_list_writelock, 1, memory_order_acq_rel))
    birdloop_yield();

  /* Insert this thread to the beginning of the thread list, no spinlock is needed */
  struct rcu_thread *next = atomic_load_explicit(&rcu_thread_list, memory_order_acquire);
  do atomic_store_explicit(&this_rcu_thread.next, next, memory_order_relaxed);
  while (!atomic_compare_exchange_strong_explicit(
	&rcu_thread_list, &next, &this_rcu_thread,
	memory_order_acq_rel, memory_order_acquire));

  ASSERT_DIE(atomic_exchange_explicit(&rcu_thread_list_writelock, 0, memory_order_acq_rel));
}

void
rcu_thread_stop(void)
{
  /* Assuring only one thread stopper at a time */
  while (atomic_exchange_explicit(&rcu_thread_list_writelock, 1, memory_order_acq_rel))
    birdloop_yield();

  /* Find this thread */
  for (struct rcu_thread * _Atomic *tp = &rcu_thread_list, *t;
      t = atomic_load_explicit(tp, memory_order_acquire);
      tp = &t->next)
    if (t == &this_rcu_thread)
    {
      /* Remove this thread */
      atomic_store_explicit(tp, atomic_load_explicit(&t->next, memory_order_acquire), memory_order_release);

      /* Unlock */
      ASSERT_DIE(atomic_exchange_explicit(&rcu_thread_list_writelock, 0, memory_order_acq_rel));

      /* Wait for readers */
      synchronize_rcu();

      /* Done */
      return;
    }

  bug("Failed to find a stopped rcu thread");
}

void
rcu_init(void)
{
  rcu_thread_start();
}
