/*
 *	BIRD Library -- Generic lock-free structures
 *
 *	(c) 2023       Maria Matejka <mq@jmq.cz>
 *	(c) 2023       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LOCKFREE_H_
#define _BIRD_LOCKFREE_H_

#include "lib/event.h"
#include "lib/rcu.h"

#include <stdatomic.h>

/**
 * Lock-free usecounts.
 */

struct lfuc {
  _Atomic u64 uc;
};

#define LFUC_PU_SHIFT      44
#define LFUC_IN_PROGRESS   (1ULL << LFUC_PU_SHIFT)

/**
 * lfuc_lock - increase an atomic usecount
 * @c: the usecount structure
 */
static inline void lfuc_lock(struct lfuc *c)
{
  /* Locking is trivial; somebody already holds the underlying data structure
   * so we just increase the use count. Nothing can be freed underneath our hands. */
  u64 uc = atomic_fetch_add_explicit(&c->uc, 1, memory_order_acq_rel);
  ASSERT_DIE(uc > 0);
}

/**
 * lfuc_lock_revive - increase an atomic usecount even if it's zero
 * @c: the usecount structure
 *
 * If the caller is sure that they can't collide with the prune routine,
 * they can call this even on structures with already zeroed usecount.
 * Handy for situations with flapping routes. Use only from the same
 * loop as which runs the prune routine.
 */
static inline void lfuc_lock_revive(struct lfuc *c)
{
  UNUSED u64 uc = atomic_fetch_add_explicit(&c->uc, 1, memory_order_acq_rel);
}

/**
 * lfuc_unlock - decrease an atomic usecount
 * @c: the usecount structure
 * @el: prune event list
 * @ev: prune event itself
 *
 * If the usecount reaches zero, a prune event is run to possibly free the object.
 * The prune event MUST use lfuc_finished() to check the object state.
 */
static inline void lfuc_unlock(struct lfuc *c, event_list *el, event *ev)
{
  /* Unlocking is tricky. We do it lockless so at the same time, the prune
   * event may be running, therefore if the unlock gets us to zero, it must be
   * the last thing in this routine, otherwise the prune routine may find the
   * source's usecount zeroed, freeing it prematurely.
   *
   * The usecount is split into two parts:
   * the top 20 bits are an in-progress indicator
   * the bottom 44 bits keep the actual usecount.
   *
   * Therefore at most 1 million of writers can simultaneously unlock the same
   * structure, while at most ~17T different places can reference it. Both limits
   * are insanely high from the 2022 point of view. Let's suppose that when 17T
   * routes or 1M peers/tables get real, we get also 128bit atomic variables in the
   * C norm. */

  /* First, we push the in-progress indicator */
  u64 uc = atomic_fetch_add_explicit(&c->uc, LFUC_IN_PROGRESS, memory_order_acq_rel);

  /* Then we split the indicator to its parts. Remember, we got the value
   * before the operation happened so we're re-doing the operation locally
   * to get a view how the indicator _would_ look if nobody else was interacting.
   */
  u64 pending = (uc >> LFUC_PU_SHIFT) + 1;
  uc &= LFUC_IN_PROGRESS - 1;

  /* We per-use the RCU critical section indicator to make the prune event wait
   * until we finish here in the rare case we get preempted. */
  rcu_read_lock();

  /* Obviously, there can't be more pending unlocks than the usecount itself */
  if (uc == pending)
    /* If we're the last unlocker (every owner is already unlocking), schedule
     * the owner's prune event */
    ev_send(el, ev);
  else
    ASSERT_DIE(uc > pending);

  /* And now, finally, simultaneously pop the in-progress indicator and the
   * usecount, possibly allowing the pruning routine to free this structure */
  atomic_fetch_sub_explicit(&c->uc, LFUC_IN_PROGRESS + 1, memory_order_acq_rel);

  /* ... and to reduce the load a bit, the pruning routine will better wait for
   * RCU synchronization instead of a busy loop. */
  rcu_read_unlock();
}

/**
 * lfuc_finished - auxiliary routine for prune event
 * @c: usecount structure
 *
 * This routine simply waits until all unlockers finish their job and leave
 * the critical section of lfuc_unlock(). Then we decide whether the usecount
 * is indeed zero or not, and therefore whether the structure is free to be freed.
 */
static inline _Bool
lfuc_finished(struct lfuc *c)
{
  u64 uc;
  /* Wait until all unlockers finish */
  while ((uc = atomic_load_explicit(&c->uc, memory_order_acquire)) >> LFUC_PU_SHIFT)
    synchronize_rcu();

  /* All of them are now done and if the usecount is now zero, then we're
   * the last place to reference the object and we can call it finished. */
  return (uc == 0);
}

/**
 * lfuc_init - auxiliary routine for usecount initialization
 * @c: usecount structure
 *
 * Called on object initialization, sets the usecount to an initial one to make
 * sure that the prune routine doesn't free it before somebody else references it.
 */
static inline void
lfuc_init(struct lfuc *c)
{
  atomic_store_explicit(&c->uc, 1, memory_order_release);
}

#endif
