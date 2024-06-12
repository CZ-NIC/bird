/*
 *	BIRD Library -- Generic lock-free structures
 *
 *	(c) 2023--2024 Maria Matejka <mq@jmq.cz>
 *	(c) 2023--2024 CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/birdlib.h"
#include "lib/lockfree.h"

#define LOCAL_DEBUG

void lfuc_unlock_deferred(struct deferred_call *dc)
{
  SKIP_BACK_DECLARE(struct lfuc_unlock_queue_item, luqi, dc, dc);
  lfuc_unlock_immediately(luqi->c, luqi->el, luqi->ev);
}

#if 0
#define lfjour_debug(...) log(L_TRACE __VA_ARGS__)
#define lfjour_debug_detailed(...) log(L_TRACE __VA_ARGS__)
#elif 0
#define lfjour_debug(...) log(L_TRACE __VA_ARGS__)
#define lfjour_debug_detailed(...)
#else
#define lfjour_debug(...)
#define lfjour_debug_detailed(...)
#endif

#define LBI(j, b, p)  ((struct lfjour_item *)(((void *) (b)->_block) + ((j)->item_size * (p))))
#define LBP(j, b, i)  ({ \
    off_t off = ((void *) (i)) - ((void *) (b)->_block); \
    u32 s = (j)->item_size; \
    ASSERT_DIE(off < page_size); \
    ASSERT_DIE((off % s) == 0); \
    off / s; \
    })

struct lfjour_item *
lfjour_push_prepare(struct lfjour *j)
{
  ASSERT_DIE(!j->domain || DG_IS_LOCKED(j->domain));
  ASSERT_DIE(!j->open);

  if (EMPTY_TLIST(lfjour_block, &j->pending) &&
      EMPTY_TLIST(lfjour_recipient, &j->recipients))
    return NULL;

  struct lfjour_block *block = NULL;
  u32 end = 0;

  if (!EMPTY_TLIST(lfjour_block, &j->pending))
  {
    block = j->pending.last;
    end = atomic_load_explicit(&block->end, memory_order_relaxed);
    if (end >= j->item_count)
    {
      ASSERT_DIE(end == j->item_count);
      block = NULL;
      end = 0;
    }
  }

  if (!block)
  {
    block = alloc_page();
    lfjour_debug("lfjour(%p)_push_prepare: allocating block %p", j, block);
    *block = (struct lfjour_block) {};
    lfjour_block_add_tail(&j->pending, block);
  }

  struct lfjour_item *i = LBI(j, block, end);
  *i = (struct lfjour_item) {
    .seq = j->next_seq++,
  };

  return j->open = i;
}

void
lfjour_push_commit(struct lfjour *j)
{
  ASSERT_DIE(!j->domain || DG_IS_LOCKED(j->domain));
  ASSERT_DIE(j->open);
  struct lfjour_block *b = PAGE_HEAD(j->open);
  ASSERT_DIE(b == j->pending.last);

  lfjour_debug("lfjour(%p)_push_commit of %p, seq=%lu", j, j->open, j->open->seq);

  u32 end = atomic_fetch_add_explicit(&b->end, 1, memory_order_release);
  ASSERT_DIE(j->open == LBI(j, b, end));

  if (end == 0)
  {
    struct lfjour_block *prev = b->n.prev;
    _Bool f = 0;
    if (prev)
      ASSERT_DIE(atomic_compare_exchange_strong_explicit(&prev->not_last, &f, 1,
	    memory_order_release, memory_order_relaxed));
  }

  /* Store the first item to announce (only if this is actually the first one). */
  struct lfjour_item *null_item = NULL;
  if (atomic_compare_exchange_strong_explicit(
	&j->first, &null_item, j->open,
	memory_order_acq_rel, memory_order_relaxed))
  {
    lfjour_debug("lfjour(%p) first set", j);
  }

  j->open = NULL;

  if (!ev_active(&j->announce_kick_event))
    ev_send_loop(j->loop, &j->announce_kick_event);
}

static struct lfjour_item *
lfjour_get_next(struct lfjour *j, struct lfjour_item *last)
{
  /* This is lockless, no domain checks. */
  if (!last)
  {
    struct lfjour_item *first = atomic_load_explicit(&j->first, memory_order_acquire);
    return first;
  }

  struct lfjour_block *block = PAGE_HEAD(last);
  ASSERT_DIE(block);
  u32 end = atomic_load_explicit(&block->end, memory_order_acquire);
  u32 pos = LBP(j, block, last);
  ASSERT_DIE(pos < end);

  /* Next is in the same block. */
  if (++pos < end)
    return LBI(j, block, pos);

  /* There is another block. */
  if (atomic_load_explicit(&block->not_last, memory_order_acquire))
  {
    /* To avoid rare race conditions, we shall check the current block end once again */
    u32 new_end = atomic_load_explicit(&block->end, memory_order_acquire);
    ASSERT_DIE(new_end >= end);
    if (new_end > end)
      return LBI(j, block, pos);

    /* Nothing in the previous one, let's move to the next block.
     * This is OK to do non-atomically because of the not_last flag. */
    block = block->n.next;
    return LBI(j, block, 0);
  }

  /* There is nothing more. */
  return NULL;
}

struct lfjour_item *
lfjour_get(struct lfjour_recipient *r)
{
  ASSERT_DIE(r->cur == NULL);
  struct lfjour *j = lfjour_of_recipient(r);

  /* The last pointer may get cleaned up under our hands.
   * Indicating that we're using it, by RCU read. */

  rcu_read_lock();
  struct lfjour_item *last = atomic_load_explicit(&r->last, memory_order_acquire);
  r->cur = lfjour_get_next(j, last);
  rcu_read_unlock();

  if (last)
  {
    lfjour_debug_detailed("lfjour(%p)_get(recipient=%p) returns %p, seq=%lu, last %p",
	j, r, r->cur, r->cur ? r->cur->seq : 0ULL, last);
  }
  else
  {
    lfjour_debug("lfjour(%p)_get(recipient=%p) returns %p, seq=%lu, clean",
	j, r, r->cur, r->cur ? r->cur->seq : 0ULL);
  }

  return r->cur;
}

void lfjour_release(struct lfjour_recipient *r)
{
  /* This is lockless, no domain checks. */

  ASSERT_DIE(r->cur);
  struct lfjour_block *block = PAGE_HEAD(r->cur);
  u32 end = atomic_load_explicit(&block->end, memory_order_acquire);

  struct lfjour *j = lfjour_of_recipient(r);
  u32 pos = LBP(j, block, r->cur);
  ASSERT_DIE(pos < end);

  /* Releasing this export for cleanup routine */
  if (pos + 1 == end)
  {
    lfjour_debug("lfjour(%p)_release(recipient=%p) of %p, seq=%lu (end)",
	j, r, r->cur, r->cur->seq);
  }
  else
  {
    lfjour_debug_detailed("lfjour(%p)_release(recipient=%p) of %p, seq=%lu (mid)",
	j, r, r->cur, r->cur->seq);
  }

  atomic_store_explicit(&r->last, r->cur, memory_order_release);

  /* The last block may be available to free */
  if (pos + 1 == end)
    lfjour_schedule_cleanup(j);

  r->cur = NULL;
}

void
lfjour_announce_now(struct lfjour *j)
{
  ASSERT_DIE(birdloop_inside(j->loop));
  settle_cancel(&j->announce_timer);
  ev_postpone(&j->announce_kick_event);

  if (EMPTY_TLIST(lfjour_recipient, &j->recipients))
    return lfjour_schedule_cleanup(j);

  WALK_TLIST(lfjour_recipient, r, &j->recipients)
    if (r->event)
      ev_send(r->target, r->event);
}

static void
lfjour_announce_settle_hook(struct settle *s)
{
  return lfjour_announce_now(SKIP_BACK(struct lfjour, announce_timer, s));
}

static void
lfjour_announce_kick_hook(void *_j)
{
  struct lfjour *j = _j;
  settle_kick(&j->announce_timer, j->loop);
}

u64
lfjour_pending_items(struct lfjour *j)
{
  ASSERT_DIE(!j->domain || DG_IS_LOCKED(j->domain));

  struct lfjour_item *first = atomic_load_explicit(&j->first, memory_order_relaxed);
  if (!first)
    return 0;

  ASSERT_DIE(j->next_seq > first->seq);
  return j->next_seq - first->seq;
}

void
lfjour_register(struct lfjour *j, struct lfjour_recipient *r)
{
  ASSERT_DIE(!j->domain || DG_IS_LOCKED(j->domain));
  ASSERT_DIE(!r->event == !r->target);

  atomic_store_explicit(&r->last, NULL, memory_order_relaxed);
  ASSERT_DIE(!r->cur);

  lfjour_recipient_add_tail(&j->recipients, r);
}

void
lfjour_unregister(struct lfjour_recipient *r)
{
  struct lfjour *j = lfjour_of_recipient(r);
  ASSERT_DIE(!j->domain || DG_IS_LOCKED(j->domain));

  if (r->cur)
    lfjour_release(r);

  lfjour_recipient_rem_node(&j->recipients, r);
  lfjour_schedule_cleanup(j);
}

static inline void lfjour_cleanup_unlock_helper(struct domain_generic **dg)
{
  if (!*dg) return;
  DG_UNLOCK(*dg);
}

static void
lfjour_cleanup_hook(void *_j)
{
  struct lfjour *j = _j;

  CLEANUP(lfjour_cleanup_unlock_helper) struct domain_generic *_locked = j->domain;
  if (_locked) DG_LOCK(_locked);

  u64 min_seq = ~((u64) 0);
  struct lfjour_item *last_item_to_free = NULL;
  struct lfjour_item *first = atomic_load_explicit(&j->first, memory_order_acquire);

  if (!first)
  {
    /* Nothing to cleanup, actually, just call the done callback */
    ASSERT_DIE(EMPTY_TLIST(lfjour_block, &j->pending));
    CALL(j->cleanup_done, j, 0, ~((u64) 0));
    return;
  }

  WALK_TLIST(lfjour_recipient, r, &j->recipients)
  {
    struct lfjour_item *last = atomic_load_explicit(&r->last, memory_order_acquire);

    if (!last)
      /* No last export means that the channel has exported nothing since last cleanup */
      return;

    else if (min_seq > last->seq)
    {
      min_seq = last->seq;
      last_item_to_free = last;
    }
  }

  /* Here we're sure that no receiver is going to use the first pointer soon.
   * It is only used when the receiver's last pointer is NULL, which is avoided by the code above.
   * Thus, we can just move the journal's first pointer forward. */
  struct lfjour_item *next = last_item_to_free ? lfjour_get_next(j, last_item_to_free) : NULL;
  atomic_store_explicit(&j->first, next, memory_order_release);

  lfjour_debug("lfjour(%p) set first=%p (was %p)", j, next, first);

  WALK_TLIST(lfjour_recipient, r, &j->recipients)
  {
    struct lfjour_item *last = last_item_to_free;
    /* This either succeeds if this item is the most-behind-one,
     * or fails and gives us the actual last for debug output. */
    if (atomic_compare_exchange_strong_explicit(
	  &r->last, &last, NULL,
	  memory_order_acq_rel, memory_order_acquire))
    {
      lfjour_debug("lfjour(%p)_cleanup(recipient=%p): store last=NULL", j, r);
    }
    else
    {
      lfjour_debug("lfjour(%p)_cleanup(recipient=%p): keep last=%p", j, r, last);
    }
  }

  /* Now some recipients may have old last-pointers. We have to wait
   * until they finish their routine, before we start cleaning up. */
  synchronize_rcu();

  u64 orig_first_seq = first->seq;

  /* Now we do the actual cleanup */
  while (first && (first->seq <= min_seq))
  {
    j->item_done(j, first);

    /* Find next journal item */
    struct lfjour_item *next = lfjour_get_next(j, first);
    if (PAGE_HEAD(next) != PAGE_HEAD(first))
    {
      /* This was the last one in its block */
      struct lfjour_block *block = PAGE_HEAD(first);
      lfjour_debug("lfjour(%p)_cleanup: freeing block %p", j, block);
      ASSERT_DIE(block == j->pending.first);

      /* Free this block */
      lfjour_block_rem_node(&j->pending, block);

      /* Wait for possible pending readers of the block */
      synchronize_rcu();

      /* Now we can finally drop the block */
#ifdef LOCAL_DEBUG
      memset(block, 0xbe, page_size);
#endif
      free_page(block);

      /* If no more blocks are remaining, we shall reset
       * the sequence numbers */

      if (EMPTY_TLIST(lfjour_block, &j->pending))
      {
	lfjour_debug("lfjour(%p)_cleanup: seq reset", j);
	WALK_TLIST(lfjour_recipient, r, &j->recipients)
	  atomic_fetch_or_explicit(&r->recipient_flags, LFJOUR_R_SEQ_RESET, memory_order_acq_rel);

	j->next_seq = 1;
      }
    }

    /* And now move on to the next item */
    first = next;
  }

  CALL(j->cleanup_done, j, orig_first_seq, first ? first->seq : ~((u64) 0));
}

void
lfjour_init(struct lfjour *j, struct settle_config *scf)
{
  /* Expecting all other fields to be initialized to zeroes by the caller */
  ASSERT_DIE(j->loop);
  ASSERT_DIE(j->item_size >= sizeof(struct lfjour_item));

  j->item_size = BIRD_CPU_ALIGN(j->item_size);
  j->item_count = (page_size - sizeof(struct lfjour_block)) / j->item_size;

  j->next_seq = 1;
  j->announce_kick_event = (event) {
    .hook = lfjour_announce_kick_hook,
    .data = j,
  };
  j->announce_timer = SETTLE_INIT(scf, lfjour_announce_settle_hook, j);
  j->cleanup_event = (event) {
    .hook = lfjour_cleanup_hook,
    .data = j,
  };
}
