/*
 *	BIRD Library -- Generic lock-free structures
 *
 *	(c) 2023--2024 Maria Matejka <mq@jmq.cz>
 *	(c) 2023--2024 CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LOCKFREE_H_
#define _BIRD_LOCKFREE_H_

#include "lib/defer.h"
#include "lib/event.h"
#include "lib/rcu.h"
#include "lib/settle.h"
#include "lib/tlists.h"
#include "lib/io-loop.h"

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
static inline u64 lfuc_lock(struct lfuc *c)
{
  /* Locking is trivial; somebody already holds the underlying data structure
   * so we just increase the use count. Nothing can be freed underneath our hands. */
  u64 uc = atomic_fetch_add_explicit(&c->uc, 1, memory_order_acq_rel);
  ASSERT_DIE(uc > 0);
  return uc & (LFUC_IN_PROGRESS - 1);
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
static inline u64 lfuc_lock_revive(struct lfuc *c)
{
  u64 uc = atomic_fetch_add_explicit(&c->uc, 1, memory_order_acq_rel);
  return uc & (LFUC_IN_PROGRESS - 1);
}

/**
 * lfuc_unlock_immediately - decrease an atomic usecount
 * @c: the usecount structure
 * @el: prune event list
 * @ev: prune event itself
 *
 * If the usecount reaches zero, a prune event is run to possibly free the object.
 * The prune event MUST use lfuc_finished() to check the object state.
 */
static inline void lfuc_unlock_immediately(struct lfuc *c, event_list *el, event *ev)
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

  /* Obviously, there can't be more pending unlocks than the usecount itself */
  if (uc == pending)
    /* If we're the last unlocker (every owner is already unlocking), schedule
     * the owner's prune event */
    ev_send(el, ev);
  else
    ASSERT_DIE(uc > pending);

  /* And now, finally, simultaneously pop the in-progress indicator and the
   * usecount, possibly allowing the pruning routine to free this structure */
  uc = atomic_fetch_sub_explicit(&c->uc, LFUC_IN_PROGRESS + 1, memory_order_acq_rel);

//  return uc - LFUC_IN_PROGRESS - 1;
}

struct lfuc_unlock_queue_item {
  struct deferred_call dc;
  struct lfuc *c;
  event_list *el;
  event *ev;
};

void lfuc_unlock_deferred(struct deferred_call *dc);

static inline void lfuc_unlock(struct lfuc *c, event_list *el, event *ev)
{
  struct lfuc_unlock_queue_item luqi = {
    .dc.hook = lfuc_unlock_deferred,
    .c = c,
    .el = el,
    .ev = ev,
  };

  defer_call(&luqi.dc, sizeof luqi);
}

/**
 * lfuc_finished - auxiliary routine for prune event
 * @c: usecount structure
 *
 * This routine simply waits until all unlockers finish their job and leave
 * the critical section of lfuc_unlock(). Then we decide whether the usecount
 * is indeed zero or not, and therefore whether the structure is free to be freed.
 */
static inline bool
lfuc_finished(struct lfuc *c)
{
  u64 uc;
  /* Wait until all unlockers finish */
  while ((uc = atomic_load_explicit(&c->uc, memory_order_acquire)) >> LFUC_PU_SHIFT)
    birdloop_yield();

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


/**
 * Lock-free journal.
 */

/* Journal item. Put LFJOUR_ITEM_INHERIT(name) into your structure
 * to inherit lfjour_item */
#define LFJOUR_ITEM	\
  u64 seq;		\

struct lfjour_item {
  LFJOUR_ITEM;
};

#define LFJOUR_ITEM_INHERIT(name) union { \
  struct lfjour_item name; \
  struct { LFJOUR_ITEM; }; \
}

/* Journal item block. Internal structure, no need to check out. */
#define TLIST_PREFIX lfjour_block
#define TLIST_TYPE struct lfjour_block
#define TLIST_ITEM n
#define TLIST_WANT_ADD_TAIL

struct lfjour_block {
  TLIST_DEFAULT_NODE;
  _Atomic u32 end;
  _Atomic bool not_last;

  struct lfjour_item _block[0];
};

/* Defines lfjour_block_list */
#include "lib/tlists.h"

/* Journal recipient. Inherit this in your implementation. */
#define TLIST_PREFIX lfjour_recipient
#define TLIST_TYPE struct lfjour_recipient
#define TLIST_ITEM n
#define TLIST_WANT_ADD_TAIL
#define TLIST_WANT_WALK

struct lfjour_recipient {
  TLIST_DEFAULT_NODE;
  event *event;					/* Event running when something is in the journal */
  event_list *target;				/* Event target */
  const struct lfjour_item * _Atomic last;	/* Last item processed */
  u64 first_holding_seq;			/* First item not released yet */
  struct lfjour_item *cur;			/* Processing this now */
  _Atomic u64 recipient_flags;			/* LFJOUR_R_* */
};

enum lfjour_recipient_flags {
  LFJOUR_R_SEQ_RESET = 1,			/* Signalling of sequence number reset */
  LFJOUR_R_LAST_RUNNER = 2,                     /* Set if this recipient is supposed to ping cleanup hook */
};

/* Defines lfjour_recipient_list */
#include "lib/tlists.h"

/* Journal base structure. Include this. */
struct lfjour {
  struct domain_generic *domain;		/* The journal itself belongs to this domain (if different from the loop) */
  struct birdloop *loop;			/* Cleanup loop */
  u32 item_size, item_count;			/* Allocation parameters */
  struct lfjour_block_list pending;		/* List of packed journal blocks */
  struct lfjour_item * _Atomic first;		/* First journal item to announce */
  struct lfjour_item *open;			/* Journal item in progress */
  u64 next_seq;					/* Next export to push has this ID */
  struct lfjour_recipient_list recipients;	/* Announce updates to these */
  event announce_kick_event;			/* Kicks announce_timer */
  struct settle announce_timer;			/* Announces changes to recipients */
  event cleanup_event;				/* Runs the journal cleanup routine */
  u64 max_tokens;				/* Maximum number of cleanup tokens to issue */
  _Atomic u64 issued_tokens;			/* Current count of issued tokens */

  /* Callback on item removal from journal */
  void (*item_done)(struct lfjour *, struct lfjour_item *);

  /* Callback when the cleanup routine is ending */
  void (*cleanup_done)(struct lfjour *, u64 begin_seq, u64 end_seq);
};

struct lfjour_item *lfjour_push_prepare(struct lfjour *);
void lfjour_push_commit(struct lfjour *);

struct lfjour_item *lfjour_get(struct lfjour_recipient *);
void lfjour_release(struct lfjour_recipient *, const struct lfjour_item *);
static inline bool lfjour_reset_seqno(struct lfjour_recipient *r)
{
  return atomic_fetch_and_explicit(&r->recipient_flags, ~LFJOUR_R_SEQ_RESET, memory_order_acq_rel) & LFJOUR_R_SEQ_RESET;
}

void lfjour_announce_now(struct lfjour *);
u64 lfjour_pending_items(struct lfjour *);

static inline void lfjour_schedule_cleanup(struct lfjour *j)
{ ev_send_loop(j->loop, &j->cleanup_event); }

static inline void lfjour_do_cleanup_now(struct lfjour *j)
{
  /* This requires the caller to own the cleanup event loop */
  ev_postpone(&j->cleanup_event);
  j->cleanup_event.hook(j->cleanup_event.data);
}

void lfjour_register(struct lfjour *, struct lfjour_recipient *);
void lfjour_unregister(struct lfjour_recipient *);
static inline uint lfjour_count_recipients(struct lfjour *j)
{ return TLIST_LENGTH(lfjour_recipient, &j->recipients); }

void lfjour_init(struct lfjour *, struct settle_config *);
void lfjour_dump(struct dump_request *, struct lfjour *);
struct resmem lfjour_memsize(struct lfjour *);

static inline struct lfjour *lfjour_of_recipient(struct lfjour_recipient *r)
{
  struct lfjour_recipient_list *list = lfjour_recipient_enlisted(r);
  return list ? SKIP_BACK(struct lfjour, recipients, list) : NULL;
}
#endif
