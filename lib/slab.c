/*
 *	BIRD Resource Manager -- A SLAB-like Memory Allocator
 *
 *	Heavily inspired by the original SLAB paper by Jeff Bonwick.
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2020       Maria Matejka <mq@jmq.cz>
 *	(c) 2025       Katerina Kubecova <katerina.kubecova@nic.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Slabs
 *
 * Slabs are collections of memory blocks of a fixed size.
 *
 * When the |DEBUGGING| switch is turned on, we automatically fill all
 * newly allocated and freed blocks with special patterns to easier detect
 * uninitialized or already freed memory use.
 *
 * Slabs support very fast allocation and freeing of such blocks, prevent memory
 * fragmentation and optimize L2 cache usage. Slabs have been invented by Jeff Bonwick
 * and published in USENIX proceedings as `The Slab Allocator: An Object-Caching Kernel
 * Memory Allocator'. Our original implementation followed this article except that we
 * didn't use constructors and destructors. Yet now, it's a little bit more complicated.
 *
 * The slab allocates system memory pages and partitions them to allocate the blocks.
 * Every page has its head (struct sl_head) with some basic information,
 * a bitfield for marking allocated blocks, and then the data, aligned to the
 * maximum requred alignment to avoid unaligned access.
 *
 * To allocate a block, every thread has its own page (we call them heads, actually)
 * assigned to allocate from. It finds a free block in the head, marks it and returns it.
 *
 * The thread may be unable to allocate from its own page because it's full. In such cases,
 * the thread pushes that page to the full_heads list. Then, it needs a new one, which it gets
 * primarily from the partial_heads list (see below), and if that list is empty, it requests
 * a new page from the kernel.
 *
 * The threads' own heads are arranged in an array in struct slab.
 *
 * To free a block, we always know that it's allocated from a page which is
 * aligned to its size. (That's an invariant we are enforcing in the page
 * allocation subsystem and we heavily rely on that.) With that, we can calculate
 * the head pointer from the block pointer by zeroing the least significant (usually) 13 bits.
 *
 * With the head pointer in hand, we can unset the appropriate bit in the head.
 * But there are several cases to consider with the head.
 *
 * (1) The head is some thread's head, indicated by slh_thread
 *     -> no need to do anything, the block is going to be reused soon
 * (2) The head is in the partial_heads list and there are some more blocks
 *     in the head still allocated
 *     -> no need to do anything, the block is going to be reused (not so) soon
 *        but it's gonna be taken care of
 * (3) The head is in the full_heads list and its state is slh_pre_partial.
 *     -> no need to do anything, the help is on the way already (see below why)
 * (4) The head is in the partial_heads list and this is the last block to free.
 *     Note that there is no thread which could be allocating from this block
 *     right now. -> Removing the head from the list and freeing it safely
 *     is hard, we need to hire a specialist (schedule an event) to do it.
 * (5) The head is in the full_heads list and its state is slh_full. This means
 *     that it is no longer full and we need to move it to the partial_heads list
 *     for a possible reuse. -> Removing the head from the list is hard. We
 *     need to hire a specialist (schedule an event) to do it. We also change
 *     the head's state to slh_pre_partial to indicate this fact.
 *
 * And that's all. Or is it?
 *
 * The Hired Specialist(TM) is an event doing the cleanup operations on the slab.
 *
 * (1) It walks over the full_heads list and:
 *     (1A) if the head is slh_full, it keeps it there,
 *     (1B) if the head is completely empty, it frees it,
 *     (1C) if the head is slh_pre_partial, it changes its state to slh_partial
 *	    and moves it to another (local) list for further processing.
 * (2) It exchanges the locally gathered partial list and the partial_heads list.
 * (3) It walks over the local list (formerly partial_heads!) and:
 *     (3A) if the head still has some allocated blocks, it pushes it back to partial_heads,
 *     (3B) if the head is completely empty, it frees it.
 *
 * The last part to mention are slab_dump and slab_memsize. But these are simple.
 * They just walk over the full_heads, partial_heads and the thread-array, and
 * dump or calculate the effective / overhead memory usage.
 *
 * And that's all. Or is it?
 *
 * The block allocation and free are lockless.
 * (Are you scared already? We surely are. But we are brave.)
 *
 * Please read the comments in the sl_alloc and sl_free code to see the analysis
 * why this is actually safe.
 *
 * And don't worry. The Hired Specialist, as well as slab_dump and slab_memsize,
 * are locking, therefore these can't collide with themselves. Yet sl_alloc and
 * sl_free may collide and we are catering for that.
 */

#include <stdlib.h>
#include <stdint.h>

#include "nest/bird.h"
#include "lib/resource.h"
#include "lib/io-loop.h"


#ifdef DEBUGGING
#define POISON		/* Poison all regions after they are freed */
#endif

static void slab_free(resource *r);
static void slab_dump(struct dump_request *dreq, resource *r);
//static resource *slab_lookup(resource *r, unsigned long addr);
static struct resmem slab_memsize(resource *r);
static void sl_cleanup(void *sp);
static void sl_thread_end(struct bird_thread_end_callback *);


/*
 * Head state life cycle
 ***********************
 *
 *             (new head)               (all blocks allocated)
 * Alloc page     --->     slh_thread           --->            slh_full
 *                              ^                                  |
 *	                        |                          (some blocks freed)
 *			   (pickup a head)			   |
 *				|				   v
 * Free page	  <---     slh_partial		<---       slh_pre_partial
 *     (cleanup: empty head)		(cleanup: move between lists)
 */

enum sl_head_state {
  slh_new = 0,
  slh_thread = 1,
  slh_full = 2,
  slh_pre_partial = 3,
  slh_partial = 4,
  slh_dummy = 0xd0,
} PACKED;

struct sl_head {
  struct slab *slab;
  struct sl_head *_Atomic next;
  _Atomic u16 num_full;
  _Atomic enum sl_head_state state;
  _Atomic u32 used_bits[0];
};


/* These nodes must be the last nodes of full_heads and partial_heads linked lists, respectively.
 * We need these for sanity checks and for detecting collisions of alloc/free and cleanup. */
static struct sl_head slh_dummy_last_full = {
    .state = slh_dummy,
};
static struct sl_head  slh_dummy_last_partial = {
    .state = slh_dummy,
};

struct slab {
  resource r;
  uint obj_size, head_size, head_bitfield_len;
  uint objs_per_slab, data_size;
  struct sl_head * _Atomic *threads_active_heads;	/* Array of thread-own heads */
  struct sl_head * _Atomic partial_heads;		/* Heads available for grabbing, list ended by &sl_dummy_last_partial */
  struct sl_head * _Atomic full_heads;			/* Full heads, list ended by &sl_dummy_last_full */
  event event_clean;					/* Cleanup event (The Hired Specialist TM) */
  struct event_list *cleanup_ev_list;			/* Schedule event_clean here */
  struct bird_thread_end_callback thread_end;		/* Gets called on thread end */
};

static struct resclass sl_class = {
  .name = "Slab",
  .size = sizeof(struct slab),
  .free = slab_free,
  .dump = slab_dump,
  .memsize = slab_memsize,
};

#define SL_GET_HEAD(x)	PAGE_HEAD(x)
#define SL_GET_STATE(head) atomic_load_explicit(&head->state, memory_order_acquire)
#define SL_SET_STATE(head, expected_state, new_state) \
    ASSERT_DIE(atomic_exchange_explicit(&head->state, new_state, memory_order_acq_rel) == expected_state)
#define SL_MAYBE_SET_STATE(head, expected_state, new_state) \
    ({ enum sl_head_state orig = expected_state; atomic_compare_exchange_strong_explicit(&head->state, &orig, new_state, memory_order_acq_rel, memory_order_acquire); })


#if 0
/* Please do not read this. This is awful and awfully expensive way of debugging. */
static void
slab_asserts(struct slab *s)
{
return;
struct sl_head *c = s->full_heads;
    while (c!= &slh_dummy_last_full)
    {
      ASSERT_DIE(c->slab == s);
      enum sl_head_state state = SL_GET_STATE(c);
      if(!(state == slh_full || state == slh_pre_partial)){
        struct sl_head *cc = s->full_heads;
          while (cc!= &slh_dummy_last_full)
          {
            state = SL_GET_STATE(cc);
            log("cc %x state %i, s %x", cc, state, s);
            if(!(state == slh_full || state == slh_pre_partial)){
              bug("cc wrong full");
            }
            cc = cc->next;
          }
       }
      c = c->next;
    }
  c = s->partial_heads;
  if (c == &slh_dummy_last_partial)
    log("no partial");
  while (c!= &slh_dummy_last_partial)
    {
      ASSERT_DIE(c->slab == s);
      enum sl_head_state state = SL_GET_STATE(c);
      log("cc %x state %i, s %x", c, state, s);
      if(state != slh_partial){
        bug("cc wrong part");
        struct sl_head *cc = s->full_heads;
          while (cc!= &slh_dummy_last_partial)
          {
            state = SL_GET_STATE(cc);
            log("cc %x state %i, s %x", cc, state, s);
            if(state != slh_partial){
              bug("cc wrong part");
            }
            cc = cc->next;
          }
       }
      c = c->next;
    }
}
#endif

/**
 * sl_new - create a new Slab
 * @p: resource pool
 * @size: block size
 *
 * This function creates a new Slab resource from which
 * objects of size @size can be allocated.
 */
slab *
sl_new(pool *p, struct event_list *cleanup_ev_list, uint size)
{
  slab *s = ralloc(p, &sl_class);

  /* We have first to calculate how big the allocates objects actually should
   * be because of alignment constrants, and also the more objects, the bigger
   * the bitfield has to be. */

  /* First, round the size up to the alignment but keep the actual requested
   * size for memory consumption reports. */
  uint align = CPU_STRUCT_ALIGN;
  s->data_size = size;
  size = (size + align - 1) / align * align;
  s->obj_size = size;

  /* Calculate how many objects fit into a head. */
  s->head_size = sizeof(struct sl_head);

  do {
    /* Try just dividing the size by the size of the aligned object
     * and hope that the remainder gives us enough space to actually fit the bitmap.
     */
    s->objs_per_slab = (page_size - s->head_size) / size;
    s->head_bitfield_len = (s->objs_per_slab + 31) / 32;
    s->head_size = (
	sizeof(struct sl_head)
      + sizeof(u32) * s->head_bitfield_len
      + align - 1)
    / align * align;

    /* But if the overall size doesn't fit into the page, we are sure now
     * that s->head_size is larger than at the beginning of the loop, thus
     * s->objs_per_slab is going to decrease. After (at most) several iterations,
     * this will converge. (Maria claims it, please believe her.) */
  } while (s->objs_per_slab * size + s->head_size > (size_t) page_size);

  /* But it may converge to zero which is kinda stupid because we want to
   * allocate some blocks, not just juggle empty pages. But that's definitely
   * the user's fault and we won't bother. */
  if (!s->objs_per_slab)
    bug("Slab: object too large");

  /* We need a block holding the active head pointer for every thread separately */
  ASSERT_DIE(MAX_THREADS * sizeof (struct sl_head * _Atomic) <= (unsigned long) page_size);
  void *page = alloc_page();
  memset(page, 0, page_size);
  s->threads_active_heads = page;
  //atomic_store_explicit(&s->threads_active_heads, (struct sl_head *)page, memory_order_relaxed);

  /* Initialize the partial_heads and full_heads lists by the dummy heads */
  atomic_store_explicit(&s->partial_heads, &slh_dummy_last_partial, memory_order_relaxed);
  atomic_store_explicit(&s->full_heads, &slh_dummy_last_full, memory_order_relaxed);

  /* Initialize the cleanup routine */
  s->event_clean = (event) {
    .hook = sl_cleanup,
    .data = s,
  };

  s->cleanup_ev_list = cleanup_ev_list;

  /* Hook the thread end to get rid of active heads linked to that thread */
  s->thread_end = (struct bird_thread_end_callback) {
    .hook = sl_thread_end,
  };
  bird_thread_end_register(&s->thread_end);

  return s;
}

/**
 * sl_delete - destroy an existing Slab
 * @s: slab
 *
 * This function destroys the given Slab. Just a public wrapper over rfree. This calls slab_free() back internally.
 */
void sl_delete(slab *s)
{
  rfree(&s->r);
}

/**
 * sl_alloc_from_page - allocate a block from the given slab page
 * @s: slab
 * @h: slab head (page)
 *
 * Allocates and returns. May return NULL if the head is actually full, sorry. Deal with it.
 */
static void *
sl_alloc_from_page(slab *s, struct sl_head *h)
{
  ASSERT_DIE(SL_GET_STATE(h) == slh_thread);

  /* This routine must never collide with itself. It's expected to run
   * only on the head assigned to the current thread.
   * The collision may happen though with sl_free().
   *
   * If no object could be allocated, we return NULL. Yet, some block
   * could have been freed inbetween nevertheless. The caller is responsible
   * for checking this and behaving appropriately.
   * */

  /* Looking for a zero bit in a variable-long almost-atomic bitfield */
  for (uint i = 0; i < s->head_bitfield_len; i++)
  {
    u32 used_bits = atomic_load_explicit(&h->used_bits[i], memory_order_acquire);
    if (~used_bits)
    {
      /* There are some zero bits in this part of the bitfield. */
      uint pos = u32_ctz(~used_bits);
      if (i * 32 + pos >= s->objs_per_slab)
	/* But too far, we don't have those objects! */
	return NULL;

      /* Set the one, claim the block */
      u32 check = atomic_fetch_or_explicit(&h->used_bits[i], (1 << pos), memory_order_acq_rel);

      ASSERT_DIE(!(check & (1 << pos))); /* Sanity check: nobody claimed the same block inbetween */
      ASSERT_DIE(!(check & (~used_bits))); /* Sanity check: nobody claimed any other block inbetween */

      /* Update allocation count */
      atomic_fetch_add_explicit(&h->num_full, 1, memory_order_acquire);

      /* Take the pointer and go away */
      void *out = ((void *) h) + s->head_size + (i * 32 + pos) * s->obj_size;
#ifdef POISON
      memset(out, 0xcd, s->data_size);
#endif
      return out;
    }
  }

  /* Everything full */
  return NULL;
}

static struct sl_head *
sl_get_partial_head(struct slab *s)
{
  /* The cleanup must wait until we end */
  rcu_read_lock();

  /* Actual remove the first head */
  struct sl_head *cur_head = atomic_load_explicit(&s->partial_heads, memory_order_acquire),
		 *new_partial;

  /* This runs concurrently with adding heads from partial_heads (sl_cleanup).
   * It is safe, because we only read partial_head (it is always valid or at least dummy),
   * read its next pointer and do atomic exchange.
   *
   * The exchange says -- we try to remove the first head which is cur_head,
   * and we store cur_head->next as the new head. If it happened that somebody
   * else has grabbed the head inbetween, we restart the process.
   *
   * Or the cleanup is running and it pushed a new head there.
   *
   * Well, a hypothetical problem.
   *
   * (1) thread A grabs cur_head, reads cur_head->next,
   *	   and then gets scheduled out for a long long sleep
   * (2) thread B picks cur_head successfully
   * (3) thread B fills the head completely and pushes the head to full_heads
   * (4) anybody frees something from the head
   * (5) cleanup runs and pushes the head back to cur_head ...
   *
   * ... but it does not happen because the cleanup gets stuck, waiting for
   * RCU to synchronize. And sooner or later, thread A finds out
   * that it's screwed, it won't make any mess, and humbly takes another head.
   */
  do {
    if (SL_GET_STATE(cur_head) == slh_dummy)
    {
      /* At the end */
      ASSERT_DIE(cur_head == &slh_dummy_last_partial);
      break;
    }
    else
    {
      /* Another partial found */
      new_partial = atomic_load_explicit(&cur_head->next, memory_order_acquire);
      ASSERT_DIE(new_partial != NULL);
    }
  } while (!atomic_compare_exchange_strong_explicit(
	&s->partial_heads, &cur_head, new_partial,
	memory_order_acq_rel, memory_order_acquire));

  /* Indicate that the head now belongs to a thread */
  if (cur_head != &slh_dummy_last_partial)
    SL_SET_STATE(cur_head, slh_partial, slh_thread);

  /* The next pointer of cur_head is not changed here. We keep it for counting and dumping memory */

  /* Out of critical section, now the cleanup may continue */
  rcu_read_unlock();

  if (cur_head == &slh_dummy_last_partial)
    return NULL;
  else
    return cur_head;
}

/**
 * sl_alloc - allocate an object from Slab
 * @s: slab
 *
 * sl_alloc() allocates space for a single object from the
 * Slab and returns a pointer to the object.
 */
void *
sl_alloc(slab *s)
{
  struct sl_head *h = NULL;

  /* Try to use head owned by this thread */
  if (h = atomic_load_explicit(&s->threads_active_heads[THIS_THREAD_ID], memory_order_relaxed))
  {
    void *ret = sl_alloc_from_page(s, h);

    if (ret)
      return ret;

    /* This thread has a head, but it is already full, put the head to full heads.
     * We did not put the head to full heads right after we used up the last space,
     * because someone might clean some our space. It may have been us, actually,
     * as in many cases these allocations end up being released quite soon. */
    atomic_store_explicit(&s->threads_active_heads[THIS_THREAD_ID], NULL, memory_order_relaxed);

    /* First of all, we mark the head as being full, not belonging to a thread.
     * This creates a window of race conditions with sl_free() where we still think
     * that the head is full but in the meantime the head may become even completely
     * empty.
     *
     * There is no other race condition for now, as the cleanup routine can not see
     * this head yet, and no other thread may pick it from the partial heads. Remember,
     * it's not in full_heads yet, how could it get to partials? */
    SL_SET_STATE(h, slh_thread, slh_full);

    /* We may want to detect the race condition here. In some extremely rare cases,
     * the complete free race may have already happened now, and in such case,
     * nobody would ever run the cleanup. But remember, this is allocation.
     * There is definitely going to be some cleanup in the future anyway.
     *
     * So we don't worry and just go ahead, the cleanup routine will take care.
     *
     * Put the head to full heads linked list.
     *
     * The head->next pointer was intentionally kept set when grabbed from partial heads.
     * It makes it much easier to dump and count memory, yet we can't now
     * assert it to be NULL. */
    struct sl_head *next = atomic_load_explicit(&s->full_heads, memory_order_acquire);
    do atomic_store_explicit(&h->next, next, memory_order_release);
    while (!atomic_compare_exchange_strong_explicit(
	  &s->full_heads, &next, h,
	  memory_order_acq_rel, memory_order_acquire));

    /* After putting the head into full_heads, we can't even expect that it exists anymore.
     * DO NOT TOUCH IT! */
  }

  /* This thread has no page head. Try to get one from partial heads */
  h = sl_get_partial_head(s);
  if (!h)
  {
    /* There are no partial heads, we need to allocate a new page */
    h = alloc_page();
    ASSERT_DIE(SL_GET_HEAD(h) == h);

#ifdef POISON
    memset(h, 0xba, page_size);
#endif

    memset(h, 0, s->head_size);
    h->slab = s;
    atomic_store_explicit(&h->state, slh_thread, memory_order_relaxed);
  }
  ASSERT_DIE(h->slab == s);

  atomic_store_explicit(&s->threads_active_heads[THIS_THREAD_ID], h, memory_order_relaxed);
  void *ret = sl_alloc_from_page(s, h);
  ASSERT_DIE(ret); /* Since the head is new or partial, there must be a space for allocation. */
  return ret;
}

/**
 * sl_allocz - allocate an object from Slab and zero it
 * @s: slab
 *
 * sl_allocz() allocates space for a single object from the
 * Slab and returns a pointer to the object after zeroing out
 * the object memory.
 */
void *
sl_allocz(slab *s)
{
  void *obj = sl_alloc(s);
  memset(obj, 0, s->data_size);
  return obj;
}

static void
sl_free_page(struct sl_head *h)
{
#ifdef POISON
  memset(h, 0xde, page_size);
#endif
  free_page(h);
}

/* Cleaning of a slab consists of two parts. This is the Hired Specialist(TM) mentioned
 * in the algorithm overview.
 *
 * First, we walk over full_heads and find all heads with free blocks.
 * These are put to a new_partials list, or if the head is completely empty,
 * it's freed immediately.
 *
 * This function does this part.
 */
static struct sl_head *
sl_cleanup_full_heads(struct slab *s)
{
  /* Prepare the end of the new partial list */
  struct sl_head *new_partials = &slh_dummy_last_partial;

  /* The topmost full head is ignored to avoid collisions with allocations.
   * This may cause a little bit of inefficiency but we don't care so much. */
  struct sl_head *fh = atomic_load_explicit(&s->full_heads, memory_order_acquire);

  /* The topmost head is never NULL, it is always either valid, or slh_dummy_last_full. */
  ASSERT_DIE(fh);
  struct sl_head *next = atomic_load_explicit(&fh->next, memory_order_relaxed);

  /* Avoid possible problems with very rare race conditions with sl_get_partial_head(),
   * basically wait for everybody who still may have a pointer to any of these heads,
   * to end. */
  synchronize_rcu();

  while (next && (SL_GET_STATE(next) != slh_dummy))
  {
    /* We need to store the next_next pointer now in case we free the page */
    struct sl_head *next_next = atomic_load_explicit(&next->next, memory_order_relaxed);

    /* Find out how many blocks are allocated from this slab head.
     *
     * Transitions between these three variants are covered in sl_free(),
     * so that if we run the wrong variant now, somebody is already scheduling
     * the cleanup routine again.
     * */
    u16 num_full = atomic_load_explicit(&next->num_full, memory_order_acquire);
    if (num_full == 0)
    {
      /* Already completely empty! */

      /* Remove head from the list */
      ASSERT_DIE(atomic_exchange_explicit(&fh->next, next_next, memory_order_acq_rel) == next);

      /* Free the page completely */
      sl_free_page(next);
    }
    else if (num_full < s->objs_per_slab)
    {
      /* Somebody freed some blocks from here. */

      /* Remove head from the list */
      ASSERT_DIE(atomic_exchange_explicit(&fh->next, next_next, memory_order_acq_rel) == next);

      /* We change the head's state to slh_partial to indicate where it is intended to be stored. */
      SL_SET_STATE(next, slh_full, slh_partial);

      /* Put the head into new_partials */
      atomic_store_explicit(&next->next, new_partials, memory_order_relaxed);
      new_partials = next;
    }
    else
    {
      /* This block is kept here. It's still full. */
      ASSERT_DIE(num_full == s->objs_per_slab);
      fh = next;
    }

    /* Next head, let's go! */
    next = next_next;
  }

  return new_partials;
}

/* Slab cleanup, second part. The Hired Specialist(TM) still on the scene.
 *
 * Here partial_heads are cleaned. Since other threads may remove heads from partial_heads,
 * the original partial_heads linked_list is first replaced by "new_partials" linked list
 * and then worked on.
 *
 * Empty heads are freed and the rest is then put back to partial_heads one-by-one
 * to ensure other threads always have as many partial heads as possible for grabs.
 *
 * The swap at the beginning might collide with another thread grabbing a head from partial_heads,
 * hence we employ a simple read-write spinlock to temporarily block allocations.
 *
*/
static void
sl_cleanup_partial_heads(struct slab *s, struct sl_head *new_partials)
{
  /* Exchange the partial heads for the supplied list */
  struct sl_head *ph = atomic_exchange_explicit(&s->partial_heads, new_partials, memory_order_acq_rel);
  ASSERT_DIE(ph);

  /* Wait for readers to realize */
  synchronize_rcu();

  /* Now nobody else sees ph and we can happily free anything we come across. Almost.
   * And we can walk over the list and do the cleanup in peace. */
  while (ph != &slh_dummy_last_partial)
  {
    ASSERT_DIE(SL_GET_STATE(ph) == slh_partial);
    struct sl_head *next_head = atomic_load_explicit(&ph->next, memory_order_relaxed);
    ASSERT_DIE(next_head);

    if (!atomic_load_explicit(&ph->num_full, memory_order_relaxed))
      /* The head is empty, free it. */
      sl_free_page(ph);
    else
    {
      /* Insert the head into the partial heads list.
       * This runs concurrently with removing heads from partial_heads (sl_get_partial_head),
       * but we are the only one pushing heads there, so any pointer we see there is unique
       * and no heads are going to be recycled during the race condition.
       *
       * Thus, we can't run into the ominous race condition of colliding with both
       * addition and removal at the same time. At least by unanimous voting of two people,
       * we consider this safe.
       *
       * No, seriously. The only weird case is that sl_get_partial_head picks a head,
       * then we push another one, then another sl_get_partial_head picks a head,
       * then we push another one ... but in the end, they either find out that this
       * is not the topmost one, or they serialize in the right order and everything works. */
      struct sl_head *head = atomic_load_explicit(&s->partial_heads, memory_order_acquire);
      do atomic_store_explicit(&ph->next, head, memory_order_release);
      while (!atomic_compare_exchange_strong_explicit(
          &s->partial_heads, &head, ph,
	  memory_order_acq_rel, memory_order_acquire));
    }
    ph = next_head;
  }
}

static void
sl_cleanup(void *sp)
{
  struct slab *s = (struct slab*) sp;

  /* Cleanup does weird things and should therefore not collide
   * with memsize and dump calls. We need to lock the pool's domain explicitly. */
  struct domain_generic *dom = resource_parent(&s->r)->domain;
  int locking = !DG_IS_LOCKED(dom);
  if (locking)
    DG_LOCK(dom);

  /* Get the heads transitioning from full to partial */
  struct sl_head *new_partials = sl_cleanup_full_heads(s);

  /* And merge them with partials */
  sl_cleanup_partial_heads(s, new_partials);

  /* If we were locking, we have to unlock! */
  if (locking)
    DG_UNLOCK(dom);
}

static void sl_thread_end(struct bird_thread_end_callback *btec)
{
  SKIP_BACK_DECLARE(slab, s, thread_end, btec);

  /* Getting rid of an active head of a stopping thread.
   * We first pick the head from its place. */
  struct sl_head *h = atomic_load_explicit(&s->threads_active_heads[THIS_THREAD_ID], memory_order_relaxed);
  atomic_store_explicit(&s->threads_active_heads[THIS_THREAD_ID], NULL, memory_order_relaxed);

  /* No such head, yay! */
  if (h == NULL)
    return;

  /* How many items are still allocated from that head? */
  uint num_full = atomic_load_explicit(&h->num_full, memory_order_acquire);
  if (num_full == 0)
    /* The page is empty, just throw it away */
    sl_free_page(h);

  else
  {
    /* There are some, let's put the head into the full heads list */
    SL_SET_STATE(h, slh_thread, slh_full);

    /* Put the head to full heads linked list */
    struct sl_head *next = atomic_load_explicit(&s->full_heads, memory_order_acquire);
    do atomic_store_explicit(&h->next, next, memory_order_release);
    while (!atomic_compare_exchange_strong_explicit(
	  &s->full_heads, &next, h,
	  memory_order_acq_rel, memory_order_acquire));

    /* And if it actually should be partial, the cleanup will take care */
    if (num_full < s->objs_per_slab)
      ev_send(s->cleanup_ev_list, &s->event_clean);
  }
}


/**
 * sl_free - return a free object back to a Slab
 * @s: slab
 * @oo: object returned by sl_alloc()
 *
 * This function frees memory associated with the object @oo
 * and returns it back to the Slab @s.
 */
void
sl_free(void *oo)
{
  struct sl_head *h = SL_GET_HEAD(oo);
  struct slab *s = h->slab;

#ifdef POISON
  memset(oo, 0xdb, s->data_size);
#endif

  /* Find the position of the object in page */
  uint offset = oo - ((void *) h) - s->head_size;
  ASSERT_DIE(offset % s->obj_size == 0);
  uint pos = offset / s->obj_size;
  ASSERT_DIE(pos < s->objs_per_slab);

  /* Remove the corresponding bit from bitfield */
  u32 mask = ~0;
  mask -= 1 << (pos % 32);
  atomic_fetch_and_explicit(&h->used_bits[pos / 32], mask, memory_order_acq_rel);

  u16 num_full_before = atomic_fetch_sub_explicit(&h->num_full, 1, memory_order_acq_rel);

  if ((num_full_before == s->objs_per_slab) || (num_full_before == 1))
    ev_send(s->cleanup_ev_list, &s->event_clean);
}

static void
slab_free(resource *r)
{
  /* At this point, only one thread manipulating the slab is expected */
  slab *s = (slab *) r;

  /* No more thread ends are relevant, we are ending anyway */
  bird_thread_end_unregister(&s->thread_end);

  /* Free partial heads */
  struct sl_head *h = atomic_load_explicit(&s->partial_heads, memory_order_relaxed);
  while (SL_GET_STATE(h) != slh_dummy)
  {
    struct sl_head *nh = atomic_load_explicit(&h->next, memory_order_relaxed);
    sl_free_page(h);
    h = nh;
  }
  atomic_store_explicit(&s->partial_heads, &slh_dummy_last_partial, memory_order_relaxed);

  /* Free full heads */
  h = atomic_load_explicit(&s->full_heads, memory_order_relaxed);
  while (SL_GET_STATE(h) != slh_dummy)
  {
    struct sl_head *nh = atomic_load_explicit(&h->next, memory_order_relaxed);
    sl_free_page(h);
    h = nh;
  }
  atomic_store_explicit(&s->full_heads, &slh_dummy_last_full, memory_order_relaxed);

  /* Free thread heads */
  for (long unsigned int i = 0; i < page_size / (sizeof(struct sl_head *_Atomic)); i++)
  {
    struct sl_head *th = atomic_load_explicit(&s->threads_active_heads[i], memory_order_relaxed);
    if (th)
      sl_free_page(th);
  }
}

static void
slab_dump(struct dump_request *dreq, resource *r)
{
  /* This is expected to run from the same loop as sl_cleanup */
  slab *s = (slab *) r;
  int ec=0, pc=0, fc=0;

  RDUMP("(%d objs per %d bytes in page)\n",
      s->objs_per_slab, s->obj_size);

  /* Dump threads */
  RDUMP("%*sthreads:\n", dreq->indent+3, "");
  for (long unsigned int i = 0; i < (page_size / sizeof(struct sl_head * _Atomic)); i++)
  {
    struct sl_head *th = atomic_load_explicit(&s->threads_active_heads[i], memory_order_relaxed);
    if (th)
    {
      /* There is no guarantee the head remains slh_thread, but it won't be freed. */
      RDUMP("%*s%p (", dreq->indent+6, "", th);
      for (uint i=1; i<=s->head_bitfield_len; i++)
        RDUMP("%08x", atomic_load_explicit(&th->used_bits[s->head_bitfield_len-i], memory_order_relaxed));
      RDUMP(")\n");
      pc++;
    }
  }

  /* Dump full heads */
  RDUMP("%*sfull:\n", dreq->indent+3, "");
  struct sl_head *h = atomic_load_explicit(&s->full_heads, memory_order_relaxed);
  while (h!= &slh_dummy_last_full)
  {
    RDUMP("%*s%p (", dreq->indent+6, "", h);
    for (uint i=1; i<=s->head_bitfield_len; i++)
      RDUMP("%08x", atomic_load_explicit(&h->used_bits[s->head_bitfield_len-i], memory_order_relaxed));
    RDUMP(")\n");
    pc++;
    h = atomic_load_explicit(&h->next, memory_order_relaxed);
  }

  /* Dump partial heads */
  RDUMP("%*spartial:\n", dreq->indent+3, "");
  h = atomic_load_explicit(&s->partial_heads, memory_order_relaxed);
  while (h!= &slh_dummy_last_partial)
  {
    RDUMP("%*s%p (", dreq->indent+6, "", h);
    for (uint i=1; i<=s->head_bitfield_len; i++)
      RDUMP("%08x", atomic_load_explicit(&h->used_bits[s->head_bitfield_len-i], memory_order_relaxed));
    RDUMP(")\n");
    pc++;

    h = atomic_load_explicit(&h->next, memory_order_relaxed);
    enum sl_head_state a = SL_GET_STATE(h);

    if (a != slh_partial && a == slh_dummy)
      /* This is ugly. A head may have changed its state, but could not disappear.
       * The next pointer is never nulled or made invalid. If the head has changed
       * its state, it must be because of it was grabbed from partial_heads linked list.
       * That is why we can be sure in partial_heads linked list are only
       * heads we did not yet see in this loop. */
      h = atomic_load_explicit(&s->partial_heads, memory_order_relaxed);
  }

  RDUMP("%*spartial=%d full=%d total=%d\n", dreq->indent+3, "", ec, pc, fc);
}

static struct resmem
slab_memsize(resource *r)
{
  slab *s = (slab *) r;
  size_t heads = 0;

  size_t items = heads * s->objs_per_slab;

  /* Fullheads memsize */
  struct sl_head *h = atomic_load_explicit(&s->full_heads, memory_order_relaxed);
  while (h!= &slh_dummy_last_full)
  {
    heads++;
    items += atomic_load_explicit(&h->num_full, memory_order_relaxed);
    h = atomic_load_explicit(&h->next, memory_order_relaxed);
  }

  /* Partial heads memsize */
  h = atomic_load_explicit(&s->partial_heads, memory_order_relaxed);
  while (h!= &slh_dummy_last_partial)
  {
    heads++;
    items += atomic_load_explicit(&h->num_full, memory_order_relaxed);

    h = atomic_load_explicit(&h->next, memory_order_relaxed);
    enum sl_head_state a = SL_GET_STATE(h);

    if (a != slh_partial && a == slh_dummy)
      /* This is ugly. A head may have changed its state, but could not disappear.
       * The next pointer is never nulled or made invalid. If the head has changed
       * its state, it must be because of it was grabbed from partial_heads linked list.
       * That is why we can be sure in partial_heads linked list are only
       * heads we did not yet see in this loop. */
      h = atomic_load_explicit(&s->partial_heads, memory_order_relaxed);
  }

  /* Thread heads memsize */
  for (long unsigned int i = 0; i < (page_size / sizeof(struct sl_head * _Atomic)); i++)
  {
    struct sl_head *h = atomic_load_explicit(&s->threads_active_heads[i], memory_order_relaxed);
    if (h)
    {
      items += atomic_load_explicit(&h->num_full, memory_order_relaxed);
      heads++;
    }
  }

  size_t eff = items * s->data_size;

  return (struct resmem) {
    .effective = eff,
    .overhead = ALLOC_OVERHEAD + sizeof(struct slab) + heads * page_size - eff,
  };
}

#if 0
/* The lookup function is almost impossible to write well and actually
 * we should look for different methods of debug, this is too clumsy.
 * Probably an extension for GDB or so. --Maria */
static resource *
slab_lookup(resource *r, unsigned long a)
{
  slab *s = (slab *) r;

  struct sl_head *h = s->full_heads;
  while (h!= &slh_dummy_last_full)
  {
    if ((unsigned long) h < a && (unsigned long) h + page_size < a)
      return r;
    h = h->next;
  }

  h = s->partial_heads;
  while (h!= &slh_dummy_last_partial)
  {
    if ((unsigned long) h < a && (unsigned long) h + page_size < a)
      return r;
    h = h->next;
  }

  for (long unsigned int i = 0; i < (page_size / sizeof(struct sl_head * _Atomic)); i++)
  {
    if (s->threads_active_heads[i])
      if ((unsigned long) h < a && (unsigned long) h + page_size < a)
        return r;
  }
  return NULL;
}
#endif
