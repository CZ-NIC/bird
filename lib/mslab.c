/*
 *	BIRD Resource Manager -- A multithreaded slab-like Memory Allocator
 *
 *	Heavily inspired by the original mslab paper by Jeff Bonwick.
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2020       Maria Matejka <mq@jmq.cz>
 *	(c) 2025--2026 Katerina Kubecova <katerina.kubecova@nic.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

/**
 * DOC: Multithreaded slab (mslab)
 *
 * THIS IS A LOCKLESS MULTITHREADED CONCURRENT PIECE OF CODE, WITH HEAVY USE OF
 * ATOMICS AND IMPLICIT SYNCHRONIZATION. YOU HAVE BEEN WARNED.
 *
 * Slabs are collections of memory blocks of a fixed size.
 * They support very fast allocation and freeing of such blocks, prevent memory
 * fragmentation and optimize L2 cache usage. Slabs have been invented by Jeff Bonwick
 * and published in USENIX proceedings as `The Slab Allocator: An Object-Caching Kernel
 * Memory Allocator'. Our original implementation followed this article except that we
 * didn't use constructors and destructors. Yet now, it's a little bit more complicated.
 *
 * When the |DEBUGGING| switch is turned on, we automatically fill all
 * newly allocated and freed blocks with special patterns to easier detect
 * uninitialized or already freed memory use.
 *
 * The original slab allocator is thread-unsafe. While we could add a local lock
 * and go with that, we actually needed an allocator capable of lockless and
 * almost waitless simultaneous allocations. Therefore, we added several mechanisms
 * to ensure that the allocations don't block each other.
 *
 * The basic mslab operation is still the same. It allocates system memory
 * pages and partitions them to allocate the blocks.
 *
 ******************
 * The Slab Heads *
 ******************
 *
 * Every page has its head (|struct msl_head|) with some basic information,
 * a bitfield for marking allocated blocks, and then the data, aligned to the
 * maximum requred alignment to avoid unaligned access.
 *
 * The mslab main structure keeps track of the heads (and therefore also pages)
 * in several states. They can be:
 *
 * - full, and therefore in the |full_heads| list
 * - partially full, and therefore in the |partial_heads| list
 * - actively being allocated from, assigned to a thread (see below)
 *
 * The page (head) lifecycle follows:
 *
 *             (new head)               (all blocks allocated)
 * Alloc page     --->     slh_thread           --->            slh_full
 *                              ^                                  |
 *	                        |                          (some blocks freed)
 *			   (pickup a head)			   |
 *				|				   v
 * Free page	  <---     slh_partial		<--------------
 *     (cleanup: empty head)
 *
 **************
 * Allocation *
 **************
 *
 * Every thread has its own page assigned to allocate from. It finds a free
 * block in the head, marks it and returns it. The marking happens inside a
 * dedicated thread-local bitmap, so that if a free happens from the same page
 * simultaneously, there is no cache miss. There is no other thread
 * allocating from the same page.
 *
 * The thread may be unable to allocate from its own page because it's full.
 * That may be a false-fullness, as the freed blocks are marked to a different
 * bitmap. Therefore, the thread tries to refresh the local bitmap.
 *
 * If that doesn't work either, the thread pushes that page to the |full_heads|
 * list. Then, it needs a new one, which it gets primarily from the
 * |partial_heads| list (see below), and if that list is empty, it requests
 * a new page from the kernel.
 *
 * After this happens, in the page bitmap, the thread marks all blocks allocated
 * in advance, to avoid bit operations on every allocation. The actually freed
 * block information is kept thread-local.
 *
 ***********
 * Freeing *
 ***********
 *
 * To free a block, we always know that it's allocated from a page which is
 * aligned to its size. (That's an invariant we are enforcing in the page
 * allocation subsystem, and we heavily rely on that.) With that, we can calculate
 * the head pointer from the block pointer by zeroing the least significant (usually) 12 bits.
 *
 * With the head pointer in hand, we can unset the appropriate bit in the head.
 * But there are several cases to consider with the head.
 *
 * (1) The head is some thread's head, indicated by slh_thread
 *     -> no need to do anything, the block is going to be reused soon
 * (2) The head is in the slh_partial state and there are some more blocks
 *     in the head still allocated
 *     -> no need to do anything, probably a thread will pick it up later
 *        when their block gets full
 * (3) The head is in the slh_partial state and this is the last block to free.
 *     Note that there is no thread which could be allocating from this block
 *     right now, but that may be in the process of changing.
 *     We'll do the cleanup asynchronously, schedule an event.
 * (4) The head is in the slh_full state. This means that the head has just become
 *     not full and we need to move it to the partial_heads list for a possible reuse.
 *     Yet, removing the head from the list is hard, we don't want more threads
 *     at once to collide on that, therefore we do it asynchronously later.
 *
 ****************
 * Head Cleanup *
 ****************
 *
 * The Hired Specialist(TM) is an event doing the cleanup operations on the mslab.
 *
 * (1) It walks over the full_heads list and:
 *     (1A) if the head is still full, it keeps it there.
 *     (1B) if the head is completely empty, it frees it,
 *     (1C) otherwise, it changes its state to |slh_partial|
 *	    and moves it to another (local) list for further processing.
 * (2) It exchanges the locally gathered partial list and the |partial_heads| list
 *     to avoid collisions with threads picking new heads.
 * (3) It walks over the local list (formerly |partial_heads|!) and:
 *     (3A) if the head still has some allocated blocks, it pushes it back to |partial_heads|,
 *     (3B) if the head is completely empty, it frees it.
 *
 * The Hired Specialist is locking; it may never run concurrently with itself.
 * The same is true for auxiliary functions |mslab_dump| and |mslab_memsize|.
 *
 *********
 * Notes *
 *********
 *
 * The block allocation and free are lockless. We believe they are correct.
 * (Are you scared already? We surely are. But we are brave.)
 *
 * Please read the comments later in the code to see our analysis
 * why this is actually safe.
 */

#include <stdlib.h>
#include <stdint.h>

#include "nest/bird.h"
#include "lib/resource.h"
#include "lib/io-loop.h"
#include "lib/timer.h"
#include "sysdep/unix/io-loop.h"


#ifdef DEBUGGING
#define POISON		/* Poison all regions after they are freed */
#endif

static void mslab_free(resource *r);
static void mslab_dump(struct dump_request *dreq, resource *r);
//static resource *mslab_lookup(resource *r, unsigned long addr);
static struct resmem mslab_memsize(resource *r);
static void msl_cleanup(void *sp);
static void msl_thread_end(struct bird_thread_end_callback *);

enum msl_head_state {
  slh_new = 0,				/* Just allocated */
  slh_thread = 1,			/* Used for active allocations */
  slh_full = 2,				/* Full of allocated blocks */
  slh_partial = 3,			/* Partially freed blocks, may be reused */
  slh_dummy = 0xd0,			/* A dummy head block for sentinel use */
} PACKED;

typedef struct msl_head {
  struct mslab *mslab;			/* The parent mslab */
  struct msl_head *_Atomic next;	/* Next head in the list */
  _Atomic u16 num_full;			/* Allocated block count */
  _Atomic enum msl_head_state state;	/* Declared head state */
  _Atomic u32 used_bits[0];		/* Bitfield marking allocated blocks */
} msl_head;

/* Auxiliary macros for head manipulation */
#define MSL_GET_HEAD(x)	PAGE_HEAD(x)
#define MSL_GET_STATE(head) atomic_load_explicit(&head->state, memory_order_acquire)
#define MSL_SET_STATE(head, expected_state, new_state) \
    ASSERT_DIE(atomic_exchange_explicit(&head->state, new_state, memory_order_acq_rel) == expected_state)
#define MSL_MAYBE_SET_STATE(head, expected_state, new_state) \
    ({ enum msl_head_state orig = expected_state; atomic_compare_exchange_strong_explicit(&head->state, &orig, new_state, memory_order_acq_rel, memory_order_acquire); })

/* Common Sentinel Nodes for |mslab->full_heads| and |mslab->partial_heads|.
 * We need these for detecting collisions of alloc/free and cleanup.
 * In other words, it's not enough to check whether |next| is |NULL|.
 * We also use them for sanity checks. */
static struct msl_head slh_dummy_last_full    = { .state = slh_dummy, };
static struct msl_head slh_dummy_last_partial = { .state = slh_dummy, };

typedef struct msl_per_thread_info {
  u16 used_bits_index;			/* Current allocator index into used_bits_local */
  u16 still_free;			/* Count of certainly free chunks of memory */
  struct msl_head * _Atomic head;	/* Head from which the thread is allocating right now. */
  _Atomic s64 allocated_heads;		/* Statistics of heads allocated in this thread */
  _Atomic s64 allocated_objs;		/* Statistics of blocks allocated in this thread */
  _Atomic s64 freed_objs;		/* Statistics of blocks freed in this thread */
  u32 used_bits_local[0];		/* Allocated block count. Zero bits mean available memory,
					   one bits are memory which we have recently allocated
					   but may be already freed inbetween. */
} msl_pti;

struct mslab {
  resource r;
  uint data_size;			/* Block size requested when calling msl_new() */
  uint obj_size;			/* Actual block size allocated */
  uint head_size;			/* Total page head size */
  uint head_bitfield_len;		/* Actual size of |msl_head->used_bits| */
  uint objs_per_slab;			/* How many objects fit into one mslab page */
  msl_head * _Atomic partial_heads;	/* Heads available for grabbing, list ended by &msl_dummy_last_partial */
  msl_head * _Atomic full_heads;	/* Full heads, list ended by &msl_dummy_last_full */
  event event_clean;			/* Cleanup event, aka The Hired Specialist (TM) */
  struct event_list *cleanup_ev_list;	/* Schedule |event_clean| here */
  struct bird_thread_end_callback thread_end;	/* Callback for thread end */
  msl_pti * _Atomic *thread_head_info;	/* Per-thread info indexed by thread ID */
  _Atomic s64 freed_heads;		/* Statistics of freed heads */
  _Atomic s64 freed_objs;		/* Consolidated statistics of freed blocks from deceased threads */
  _Atomic s64 allocated_heads;		/* Consolidated statistics of allocated heads from deceased threads */
  _Atomic s64 allocated_objs;		/* Consolidated statistics of allocated blocks from deceased threads */
};

/* The slab is a resource on itself, so that it can be dumped and memsized. */
static struct resclass msl_class = {
  .name = "mslab",
  .size = sizeof(struct mslab),
  .free = mslab_free,
  .dump = mslab_dump,
  .memsize = mslab_memsize,
};

/**
 * msl_new - create a new mslab
 * @p: resource pool
 * @size: block size
 *
 * This function creates a new mslab resource from which
 * objects of size @size can be allocated.
 */
mslab *
msl_new(pool *p, struct event_list *cleanup_ev_list, uint size)
{
  mslab *s = ralloc(p, &msl_class);

  /* We have first to calculate how big the allocated objects actually should
   * be because of alignment constrants, and also the more objects, the bigger
   * the bitfield has to be. */
  s->data_size = size;
  s->obj_size = BIRD_ALIGN(size, CPU_STRUCT_ALIGN);
  s->objs_per_slab = sl_obj_count(page_size, sizeof(struct msl_head), s->obj_size, 1);
  s->head_bitfield_len = (s->objs_per_slab + 31) / 32;
  s->head_size = BIRD_ALIGN(sizeof (struct msl_head) + sizeof(u32) * s->head_bitfield_len, CPU_STRUCT_ALIGN);

  /* But it may converge to zero which is kinda stupid because we want to
   * allocate some blocks, not just juggle empty pages. But that's definitely
   * the user's fault and we won't bother. */
  if (!s->objs_per_slab)
    bug("mslab: object too large");

  /* We need a block holding the thread-local info pointers.
   * We are lazy and we simply expect that these pointers will always fit
   * into one memory page. All in all, nobody is ever gonna need more than 512
   * threads (and 640 kB of memory, as the legend says). */
  ASSERT_DIE(MAX_THREADS * sizeof (struct msl_per_thread_info * _Atomic) <= (unsigned long) page_size);
  void *page = alloc_page();
  memset(page, 0, page_size);
  s->thread_head_info = page;

  /* Initialize the |partial_heads| and |full_heads| lists by the dummy heads */
  atomic_store_explicit(&s->partial_heads, &slh_dummy_last_partial, memory_order_relaxed);
  atomic_store_explicit(&s->full_heads, &slh_dummy_last_full, memory_order_relaxed);

  /* Initialize the cleanup routine */
  s->cleanup_ev_list = cleanup_ev_list;
  s->event_clean = (event) {
    .hook = msl_cleanup,
    .data = s,
  };

  /* Hook the thread end to get rid of active heads linked to that thread */
  s->thread_end = (struct bird_thread_end_callback) {
    .hook = msl_thread_end,
  };
  bird_thread_end_register(&s->thread_end);

  return s;
}

/**
 * msl_delete - destroy an existing mslab
 * @s: mslab
 *
 * This function destroys the given mslab. Just a public wrapper over rfree. This calls mslab_free() back internally.
 */
void msl_delete(mslab *s)
{
  rfree(&s->r);
}

/**
 * msl_pti - get the thread has per thread info
 * @s: mslab
 *
 * If needed, creates, and returns per thread info for the mslab.
 */
static msl_pti *
msl_get_pti(mslab *s)
{
  struct msl_per_thread_info *ti = atomic_load_explicit(&s->thread_head_info[THIS_THREAD_ID], memory_order_relaxed);
  if (ti)
    return ti;

  /* Initialize per-thread-info if this thread has not yet used this mslab */
  ASSERT_DIE(this_thread_pool);
  ti = mb_allocz(this_thread_pool,
      sizeof(struct msl_per_thread_info) + sizeof(u32) * s->head_bitfield_len);

  uint lms = s->objs_per_slab % 32;

  for (uint i = 0; i < s->head_bitfield_len; i++)
    if ((i+1 == s->head_bitfield_len) && lms)
      ti->used_bits_local[i] = (1U << lms) - 1;
    else
      ti->used_bits_local[i] = ~0U;

  atomic_store_explicit(
      &s->thread_head_info[THIS_THREAD_ID],
      ti, memory_order_relaxed);

  return ti;
}

/**
 * msl_alloc_from_page - allocate a block from the given mslab page
 * @s: mslab
 * @h: mslab head (page)
 *
 * Allocates and returns. May return NULL if the head is actually full, sorry. Deal with it.
 */
static void *
msl_alloc_from_page(mslab *s, struct msl_head *h)
{
  ASSERT_DIE(MSL_GET_STATE(h) == slh_thread);
  msl_pti *ti = msl_get_pti(s);

  /* This routine must never collide with itself. It's expected to run
   * only on the head assigned to the current thread.
   *
   * To avoid colisions with msl_free(), actively used heads have two
   * bitfields marking used memory.
   *
   *  - One regular stored in head itself. This bit field is always
   *    present and it is used by msl_free(). If its head belongs to
   *    no thread, this bitfield is accurate, i.e. zero bit always
   *    stands for free memory and one bit for allocated.
   *
   *    If the head does belong to a thread, only zero bits can be trusted.
   *    When the thread gets the head, it sets all available bits
   *    in the bitfield to ones. The memory in the head belongs to that thread
   *    anyway, so the thread simply marks the memory as used in advance.
   *
   *  - The other bitfield is represented by |used_bits_local|. Only the owning
   *    thread should access it (the only exception is freeing the mslab). This field
   *    starts by copying the regular field and then the allocation fills it
   *    with ones from the beginning to the end, where the regular bits have
   *    already been set to one. It has no information about objects freed
   *    later; only zero bits represent free memory for sure.
   *
   * If no object could be allocated, we return NULL. Yet, some block
   * could have been freed inbetween nevertheless. The caller is responsible
   * for checking this and behaving appropriately.
   * */

  /* Looking for a zero bit in a variable-long almost-atomic bitfield */
  for (; ti->used_bits_index < s->head_bitfield_len; ti->used_bits_index++)
  {
    u32 used_bits = ti->used_bits_local[ti->used_bits_index];
    if (~used_bits)
    {
      /* There are some zero bits in this part of the bitfield. */
      uint pos = u32_ctz(~used_bits);

      /* But too far, these objects would overflow the page! */
      if (ti->used_bits_index * 32 + pos >= s->objs_per_slab)
	return NULL;

      /* Set the one, claim the block */
      ti->used_bits_local[ti->used_bits_index] |= (1U << pos);

      /* Bump local counters */
      ti->still_free--;
      atomic_fetch_add_explicit(&ti->allocated_objs, 1, memory_order_relaxed);

      /* Take the pointer and go away */
      void *out = ((void *) h) + s->head_size + (ti->used_bits_index * 32 + pos) * s->obj_size;
#ifdef POISON
      memset(out, 0xcd, s->data_size);
#endif
      return out;
    }
  }

  /* Looks like everything is full, no allocation from here. */
  return NULL;
}

/**
 * msl_refresh_bitfield - update local allocation bitfields
 * @s: mslab
 * @head: mslab head (page)
 *
 * Used memory of a head belonging to a thread is tracked by two bitfields
 * as described in msl_alloc_from_page(). The one stored in head itself tracks
 * freed memory and the other one in msl_per_thread_info() tracks available memory.
 *
 * When there is no more available memory but there is some freed memory,
 * the bitfield in msl_per_thread_info needs to load the unset bits.
 * That is done by this function. The bitfield in msl_per_thread_info is expected
 * to be all set to ones now.
 *
 * This function is used to set up |struct msl_per_thread_info| for thread when it
 * gets new partial head as well.
 *
 * The bitfield in head is atomicaly set to ones. The fetched version of the field
 * is copied to |msl_per_thread_info| field. The number of flipped bits is added to
 * head used bits. It can not be just set to max value, because of race conflicts
 * with msl_free()
 */

static bool
msl_refresh_bitfield(struct mslab *s, struct msl_head *head)
{
  if (atomic_load(&head->num_full) >= s->objs_per_slab)
    return false;

  ASSERT_DIE(MSL_GET_STATE(head) == slh_thread);
  struct msl_per_thread_info *ti = msl_get_pti(s);
  u32 mask = ~0;
  int free_bits = 0;
  uint lms = s->objs_per_slab % 32;

  /* Walk the whole bitfield */
  for (uint i = 0; i < s->head_bitfield_len; i++)
  {
    /* Last bitfield is only partial */
    if ((i+1 == s->head_bitfield_len) && lms)
      mask = (1U << lms) - 1;

    ASSERT_DIE(ti->used_bits_local[i] == mask);

    /* Transfer zeros to local bitfield */
    u32 used = atomic_fetch_or_explicit(&head->used_bits[i], mask, memory_order_acq_rel);
    ti->used_bits_local[i] = used;
    free_bits += u32_popcount((~used & mask));
  }

  /* Reset the allocator bit index */
  ti->used_bits_index = 0;

  /* Update the counters. While the |num_full| is used to determine
   * whether the page is eligible for cleanup, this page won't be considered
   * or touched because it's not a partial page. */
  atomic_fetch_add_explicit(&head->num_full, free_bits, memory_order_relaxed);
  ti->still_free = free_bits;

  return true;
}

static struct msl_head *
msl_get_partial_head(struct mslab *s)
{
  /* This runs concurrently with adding heads from partial_heads (msl_cleanup).
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
   *
   * There is basically one place where we had to put synchronization
   * to avoid this kind of rare circular race condition, and this approach
   * looks the easiest.
   */

  /* The cleanup must wait until we end */
  rcu_read_lock();

  /* Actual remove the first head */
  struct msl_head *cur_head = atomic_load_explicit(&s->partial_heads, memory_order_acquire);
  struct msl_head *new_partial;

  do {
    if (MSL_GET_STATE(cur_head) == slh_dummy)
    {
      /* No partial heads available, bye. */
      ASSERT_DIE(cur_head == &slh_dummy_last_partial);
      rcu_read_unlock();
      return NULL;
    }
    else
    {
      /* Get the next head after that one which we are trying to acquire */
      new_partial = atomic_load_explicit(&cur_head->next, memory_order_acquire);
      ASSERT_DIE(new_partial != NULL);
    }
    /* Try to replace the first head pointer with the next head.
     * On fail, this loads |cur_head| with the actual contents
     * of |partial_heads|, so that we don't have load it explicitly. */
  } while (!atomic_compare_exchange_strong_explicit(
	&s->partial_heads, &cur_head, new_partial,
	memory_order_acq_rel, memory_order_acquire));

  /* Indicate that the head now belongs to a thread */
  MSL_SET_STATE(cur_head, slh_partial, slh_thread);

  /* The next pointer of cur_head is not changed here. That is a trick to allow
   * memory counting and dumping walk through if they happen to collide. */

  /* Out of critical section, now the cleanup may continue */
  rcu_read_unlock();

  /* Localize the bitfield, so that we can start allocating */
  ASSERT_DIE(msl_refresh_bitfield(s, cur_head));
  return cur_head;
}

/**
 * msl_alloc - allocate an object from mslab
 * @s: mslab
 *
 * msl_alloc() allocates space for a single object from the
 * mslab and returns a pointer to the object.
 */
void *
msl_alloc(mslab *s)
{
  struct msl_head *h = NULL;
  msl_pti *ti = msl_get_pti(s);

  /* Try to use the head already owned by this thread */
  if (h = atomic_load_explicit(&ti->head, memory_order_acquire))
  {
    void *ret = msl_alloc_from_page(s, h);
    if (ret)
      /* Hot path. Allocated, return. */
      return ret;

    /* Try to refresh the bitfield before manipulating pages */
    if (msl_refresh_bitfield(s, h))
    {
      ret = msl_alloc_from_page(s, h);
      return ret;
    }

    /* Now the thread-owned head is patently full, it belongs to |full_heads|.
     * We did not put the head to full heads right after we used up the last space,
     * because frees may happen all the time. It may have been us, actually,
     * as in many cases the allocations end up being released quite soon. */
    atomic_store_explicit(&ti->head, NULL, memory_order_relaxed);

    /* First of all, we mark the head as being full, not belonging to a thread.
     * This creates a window of race conditions with msl_free() where we still think
     * that the head is full but in the meantime the head may become even completely
     * empty.
     *
     * There is no other race condition for now, as the cleanup routine can not see
     * this head yet, and no other thread may pick it from the partial heads. Remember,
     * it's not in full_heads yet, how could it get to partials? */
    MSL_SET_STATE(h, slh_thread, slh_full);

    /* We may want to detect the race condition here. In some extremely rare cases,
     * the complete free race may have already happened now, and in such case,
     * nobody would ever run the cleanup. But remember, this is an allocation.
     * There is definitely going to be some cleanup in the future anyway, and
     * that cleanup will take care of this.forgotten page.
     *
     * So we don't worry and just go ahead, the cleanup routine will take care.
     */

    /* Put the head to full heads linked list.
     *
     * The head->next pointer was intentionally kept set when grabbed from partial heads.
     * It makes it much easier to dump and count memory, yet we can't now
     * assert it to be NULL. */
    struct msl_head *next = atomic_load_explicit(&s->full_heads, memory_order_acquire);
    do atomic_store_explicit(&h->next, next, memory_order_release);
    while (!atomic_compare_exchange_strong_explicit(
	  &s->full_heads, &next, h,
	  memory_order_acq_rel, memory_order_acquire));

    /* After putting the head into full_heads, we can't even expect that it exists anymore.
     * DO NOT TOUCH IT! */
  }

  /* This thread has no page head. Try to get one from partial heads */
  h = msl_get_partial_head(s);
  if (!h)
  {
    /* There are no partial heads, we need to allocate a new page */
    h = alloc_page();
    ASSERT_DIE(MSL_GET_HEAD(h) == h);

#ifdef POISON
    memset(h, 0xba, page_size);
#endif

    /* Set the thread head info */
    h->mslab = s;
    h->next = NULL;
    atomic_store_explicit(&h->num_full, 0, memory_order_relaxed);
    memset(&h->used_bits, 0, s->head_bitfield_len * sizeof (u32));

    /* Update state and stats */

    atomic_store_explicit(&h->state, slh_thread, memory_order_relaxed);
    atomic_fetch_add_explicit(&ti->allocated_heads, 1, memory_order_relaxed);

    /* Reserve the memory for future allocations */
    ASSERT_DIE(msl_refresh_bitfield(s, h));
  }
  ASSERT_DIE(h->mslab == s);

  atomic_store_explicit(&ti->head, h, memory_order_relaxed);
  void *ret = msl_alloc_from_page(s, h);
  return ret;
}

/**
 * msl_allocz - allocate an object from mslab and zero it
 * @s: mslab
 *
 * msl_allocz() allocates space for a single object from the
 * mslab and returns a pointer to the object after zeroing out
 * the object memory.
 */
void *
msl_allocz(mslab *s)
{
  void *obj = msl_alloc(s);
  memset(obj, 0, s->data_size);
  return obj;
}

/**
 * msl_free_page - page free helper
 * @h: head to free
 *
 * Also poisons the page just before freeing to help catch use-after-free.
 */
static void
msl_free_page(struct msl_head *h)
{
#ifdef POISON
  memset(h, 0xde, page_size);
#endif
  free_page(h);
}

/**
 * msl_cleanup_full_heads - full heads cleanup helper
 * @s: mslab
 *
 * Cleaning of a mslab consists of two parts. This is the Hired Specialist(TM)
 * mentioned in the algorithm overview.
 *
 * This function walks over |full_heads| and moves all heads with free blocks
 * to the |new_partials| list. If the head is completely empty, it's freed
 * immediately.
 */
static struct msl_head *
msl_cleanup_full_heads(struct mslab *s)
{
  /* Prepare the end of the new partial list */
  struct msl_head *new_partials = &slh_dummy_last_partial;

  /* We may walk the |full_heads| list, apart from the first head, freely.
   * The only other routines doing this walk are dump and memsize,
   * and these run with the owner of this slab locked, as well as this.
   *
   * Freeing only pings cleanup.
   *
   * Allocator pushes to this list, and therefore may collide on the first item.
   * Anyway, no page is going to get there multiple times, and we may just
   * retry when we fail to remove the first head. */

  /* Load the first/current item */
  struct msl_head * _Atomic *this_head_ptr = &s->full_heads;
  struct msl_head *this_head = atomic_load_explicit(this_head_ptr, memory_order_acquire);

  while (this_head != &slh_dummy_last_full)
  {
    /* Find out how many blocks are allocated from this mslab head.
     *
     * Transitions between these three variants are covered in msl_free(),
     * so that if we run the wrong variant now, somebody is already scheduling
     * the cleanup routine again.
     * */
    u16 num_full = atomic_load_explicit(&this_head->num_full, memory_order_acquire);

    /* Full block, keep it. */
    if (num_full == s->objs_per_slab)
    {
      /* Move on to the next head. */
      ASSERT_DIE(MSL_GET_STATE(this_head) == slh_full);
      this_head_ptr = &this_head->next;
      this_head = atomic_load_explicit(this_head_ptr, memory_order_acquire);
      continue;
    }
    ASSERT_DIE(num_full < s->objs_per_slab);

    /* Otherwise, remove the block from the list or retry. */
    struct msl_head *next_head = atomic_load_explicit(&this_head->next, memory_order_acquire);
    if (!atomic_compare_exchange_strong_explicit(
	  this_head_ptr, &this_head, next_head,
	  memory_order_acq_rel, memory_order_acquire))
    {
      /* The collision must never happen anywhere else than in the first head */
      ASSERT_DIE(this_head_ptr == &s->full_heads);
      continue;
    }

    /* Successfully removed */
    if (num_full == 0)
    {
      /* Nobody was seeing this page, we can immediately free the empty page */
      msl_free_page(this_head);
      atomic_fetch_add_explicit(&s->freed_heads, 1, memory_order_relaxed);
    }
    else
    {
      /* We change the head's state to slh_partial to indicate where it is intended to be stored. */
      MSL_SET_STATE(this_head, slh_full, slh_partial);

      /* Move the head into new_partials */
      atomic_store_explicit(&this_head->next, new_partials, memory_order_relaxed);
      new_partials = this_head;
    }

    /* Load next head */
    this_head = atomic_load_explicit(this_head_ptr, memory_order_acquire);
  }

  return new_partials;
}

/**
 * msl_cleanup_partial_heads - partial heads cleanup helper
 * @s: mslab
 * @ph: heads to free or re-stack into |partial_heads|
 *
 * This function walks over |partial_heads| and looks for empty heads available for freeing.
 * mslab cleanup, second part. The Hired Specialist(TM) still on the scene.
 * Since other threads may remove heads from partial_heads, the original
 * |partial_heads| linked list has been replaced by the output of msl_cleanup_full_heads(),
 * and we can now work on the original list without being bothered by msl_get_partial_head().
 *
 * Empty heads are freed and the rest is then put back to |partial_heads| one-by-one
 * to ensure other threads always have as many partial heads as possible for grabs.
 */
static void
msl_cleanup_partial_heads(struct mslab *s, struct msl_head *ph)
{
  /* Walk the whole list and either free the heads or return them back for allocations.
   * Caller ensures that doing that with |ph| is safe. */
  for (struct msl_head *next_head; ph != &slh_dummy_last_partial; ph = next_head)
  {
    ASSERT_DIE(MSL_GET_STATE(ph) == slh_partial);

    /* Pre-load the next pointer */
    next_head = atomic_load_explicit(&ph->next, memory_order_relaxed);
    ASSERT_DIE(next_head);

    if (!atomic_load_explicit(&ph->num_full, memory_order_relaxed))
    {
      /* The head is empty, free it. */
      msl_free_page(ph);
      atomic_fetch_add_explicit(&s->freed_heads, 1, memory_order_relaxed);
    }
    else
    {
      /* Insert the head into the partial heads list.
       * This runs concurrently with removing heads from partial_heads (msl_get_partial_head),
       * but we are the only one pushing heads there, so any pointer we see there is unique
       * and no heads are going to be recycled during the race condition.
       *
       * Thus, we can't run into the ominous race condition of colliding with both
       * addition and removal at the same time. At least by unanimous voting of two people,
       * we consider this safe.
       *
       * No, seriously. The only weird case is that msl_get_partial_head picks a head,
       * then we push another one, then another msl_get_partial_head picks a head,
       * then we push another one ... but in the end, they either find out that this
       * is not the topmost one, or they serialize in the right order and everything works.
       *
       * And the other race condition of a pointer being reused, is out of scope here,
       * as the list being inserted is local, and the readers have been flushed by RCU sync.
       * */
      struct msl_head *head = atomic_load_explicit(&s->partial_heads, memory_order_acquire);
      do atomic_store_explicit(&ph->next, head, memory_order_release);
      while (!atomic_compare_exchange_strong_explicit(
          &s->partial_heads, &head, ph,
	  memory_order_acq_rel, memory_order_acquire));
    }
    ph = next_head;
  }
}

/** msl_cleanup - run mslab maintenance chores
 * @sp: mslab casted to void
 *
 * This function runs as an event hook and performs mslab maintenance by freeing empty heads
 * and requeuing partial heads back for allocations.
 */
static void
msl_cleanup(void *sp)
{
  struct mslab *s = (struct mslab*) sp;

  /* We need to flush all readers stuck inside msl_get_partial_head()
   * so that we can safely exchange the partial_heads pointer. */
  struct rcu_stored_phase phase = rcu_begin_sync();

  /* Get the heads transitioning from full to partial */
  struct msl_head *new_partials = msl_cleanup_full_heads(s);

  /* Wait for stuck readers to end */
  while (!rcu_end_sync(phase))
    birdloop_yield();

  /* Exchange the partial heads for the new list.
   * This may collide with (possibly multiple) msl_get_partial_head().
   * That function does atomic compare-exchange, and all these will
   * ultimately fail and retry.
   *
   * There may be a race condition though, resulting from a thread sleeping for
   * so long after retrieving their new partial head, that the head gets used
   * and goes full circle back into partial_heads.
   *
   * Then the head's next, which may have become completely bogus until now,
   * would get pushed into |partial_heads|, corrupting the data structure.
   *
   * We avoid that by the RCU synchronization just above. */
  struct msl_head *ph = atomic_exchange_explicit(
      &s->partial_heads, new_partials, memory_order_acq_rel);
  ASSERT_DIE(ph);

  /* Now we need to wait again because if a reader has read from partial_heads
   * just before the exhange, they may have a pointer which may return back
   * to partial_heads with a different next pointer value.
   *
   * Or, if we free that page, it could be read after free. Therefore,
   * waiting is necessary.
   */
  synchronize_rcu();

  /* Now we can finally clean up partials */
  msl_cleanup_partial_heads(s, ph);
}

/**
 * msl_thread_end - end-of-thread callback
 * @btec: |mslab->thread_end|
 *
 * As the slab allocates per-thread data structures, this cleanup must run
 * before any thread ends, e.g. consolidating statistics and fixing pointers.
 */
static void msl_thread_end(struct bird_thread_end_callback *btec)
{
  SKIP_BACK_DECLARE(mslab, s, thread_end, btec);

  /* Passing statistic to mslab struct */
  struct msl_per_thread_info *ti = atomic_exchange_explicit(&s->thread_head_info[THIS_THREAD_ID], NULL, memory_order_release);

  /* Never used from that thread, yay! */
  if (!ti)
    return;

  /* Transfer statistics */
#define MSL_CONS(x) \
  atomic_fetch_add_explicit(&s->x, \
      atomic_load_explicit(&ti->x, memory_order_relaxed), \
      memory_order_relaxed), \
  atomic_store_explicit(&ti->x, 0, memory_order_relaxed)

  MSL_CONS(freed_objs);
  MSL_CONS(allocated_objs);
  MSL_CONS(allocated_heads);
#undef MSL_CONS

  /* Getting rid of an active head of a stopping thread.
   * We first pick the head from its place. */
  struct msl_head *h = atomic_load_explicit(&ti->head, memory_order_relaxed);
  atomic_store_explicit(&ti->head, NULL, memory_order_relaxed);

  /* No such head, yay! */
  if (h == NULL)
    return;

  /* How many items are still allocated from that head? */
  uint num_full = atomic_fetch_sub_explicit(&h->num_full, ti->still_free, memory_order_acq_rel);
  if (num_full == ti->still_free)
  {
    /* The page is empty, just throw it away.
     * The |num_full| variable decreases over time but |still_free| is constant
     * at this time because the thread is not allocating anymore. Therefore,
     * if |num_full == still_free|, that's the pre-allocated count,
     * and the page is actually free. */
    msl_free_page(h);
    return;
  }

  uint lms = s->objs_per_slab % 32;

  /* We need to "transfer the zeros" back to the bitmap here. The |num_full| has already been adjusted. */
  for (uint i = 0; i < s->head_bitfield_len; i++)
  {
    u32 loc_used = ti->used_bits_local[i];
    u32 head_used = atomic_fetch_and_explicit(&h->used_bits[i], loc_used, memory_order_acq_rel);
    u32 loc_free = ~loc_used;

    /* Last bitfield is shorter */
    if (lms && (i+1 == s->head_bitfield_len))
      loc_free &= (1 << lms) - 1;

    uint free_bits = u32_popcount(loc_free);
    ASSERT_DIE((loc_free & head_used) == loc_free);
    
    ti->still_free -= free_bits;
  }

  /* Now all the pre-allocated blocks are free again. */
  ASSERT_DIE(ti->still_free == 0);

  /* We can put the head into the full heads list. We don't want to put it into
   * partials, even if it was almost empty. The full_heads list is multi-insert, single-remove.
   * The partial_heads list is single-insert, multi-remove. We don't want to change that. */
  MSL_SET_STATE(h, slh_thread, slh_full);

  /* Put the head to full heads linked list */
  struct msl_head *next = atomic_load_explicit(&s->full_heads, memory_order_acquire);
  do atomic_store_explicit(&h->next, next, memory_order_release);
  while (!atomic_compare_exchange_strong_explicit(
	&s->full_heads, &next, h,
	memory_order_acq_rel, memory_order_acquire));

  /* And if it actually should be partial, the cleanup will take care */
  if (num_full - ti->still_free < s->objs_per_slab)
    ev_send(s->cleanup_ev_list, &s->event_clean);
}


/**
 * msl_free - return a free object back to a mslab
 * @s: mslab
 * @oo: object returned by msl_alloc()
 *
 * This function frees memory associated with the object @oo
 * and returns it back to the mslab @s.
 */
void
msl_free(void *oo)
{
  struct msl_head *h = MSL_GET_HEAD(oo);
  struct mslab *s = h->mslab;
  msl_pti *ti = msl_get_pti(s);

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
  mask -= 1U << (pos % 32);
  u32 check = atomic_fetch_and_explicit(&h->used_bits[pos / 32], mask, memory_order_acq_rel);
  ASSERT_DIE(check & (1U << (pos % 32)));

  u16 num_full_before = atomic_fetch_sub_explicit(&h->num_full, 1, memory_order_acq_rel);

  if ((num_full_before == s->objs_per_slab) || (num_full_before == 1))
    ev_send(s->cleanup_ev_list, &s->event_clean);

  atomic_fetch_add_explicit(&ti->freed_objs, 1, memory_order_relaxed);
}

/**
 * mslab_free - free the mslab
 * @r: resource pointer
 *
 * Drops the mslab. It is expected to be already empty. */
static void
mslab_free(resource *r)
{
  /* At this point, only one thread manipulating the mslab is expected */
  mslab *s = (mslab *) r;
  ev_postpone(&s->event_clean);

  /* Run the cleanup in case it was actually needed
   * Hack: The resource must be inside a  */
  msl_cleanup(s);

  /* No more thread ends are relevant, we are ending anyway */
  bird_thread_end_unregister(&s->thread_end);

  /* Assert there are no full heads */
  ASSERT_DIE(atomic_load_explicit(&s->full_heads, memory_order_relaxed) == &slh_dummy_last_full);

  /* Assert there are no partial heads */
  ASSERT_DIE(atomic_load_explicit(&s->partial_heads, memory_order_relaxed) == &slh_dummy_last_partial);

  /* Free thread heads */
  if (s->thread_head_info)
  {
    for (long unsigned int i = 0; i < page_size / (sizeof(struct msl_head * _Atomic)); i++)
    {
      struct msl_per_thread_info *ti = atomic_load_explicit(&s->thread_head_info[i], memory_order_relaxed);
      if (ti)
      {
        struct msl_head *th = atomic_load_explicit(&ti->head, memory_order_relaxed);
        if (th)
          msl_free_page(th);

#if 0
	/* FIXME: We can't free |ti| as it's allocated from thread-local pools. This is a memory leak.
	 * It doesn't matter though because this structure is going to be used
	 * probably only for the route attribute cache, at least for the
	 * foreseeable future. */
	mb_free(ti);
#endif
      }
    }

    free_page(s->thread_head_info);
  }
}

static void
msl_dump_head(struct dump_request *dreq, const mslab *s, const struct msl_head *h, const u32 *loc)
{
  RDUMP(", PG=%p (%s", h, loc ? "HB=" : "");
  for (uint i=1; i<=s->head_bitfield_len; i++)
    RDUMP("%08x", atomic_load_explicit(&h->used_bits[s->head_bitfield_len-i], memory_order_relaxed));

  if (loc)
  {
    RDUMP("|LB=");
    for (uint i=1; i<=s->head_bitfield_len; i++)
      RDUMP("%08x", loc[s->head_bitfield_len-i]);
  }

  RDUMP(")\n");
}

static void
mslab_dump(struct dump_request *dreq, resource *r)
{
  /* This is expected to run from the same loop as msl_cleanup */
  mslab *s = (mslab *) r;
  int pc=0, fc=0;

  RDUMP("(%d objs per %d bytes in page)\n",
      s->objs_per_slab, s->obj_size);

  /* Dump threads */
  RDUMP("%*sthreads:\n", dreq->indent+3, "");
  for (long unsigned int i = 0; i < (page_size / sizeof(struct msl_head * _Atomic)); i++)
  {
    struct msl_per_thread_info *ti = atomic_load_explicit(&s->thread_head_info[i], memory_order_relaxed);
    if (ti)
    {
      RDUMP("%*s%d: AH=%lu, AO=%lu, FO=$lu",
	  dreq->indent+6, "", i,
	  atomic_load_explicit(&ti->allocated_heads, memory_order_relaxed),
	  atomic_load_explicit(&ti->allocated_objs, memory_order_relaxed),
	  atomic_load_explicit(&ti->freed_objs, memory_order_relaxed)
	  );

      struct msl_head *th = atomic_load_explicit(&ti->head, memory_order_relaxed);
      if (th)
      {
        /* There is no guarantee the head remains slh_thread, but it won't be freed. */
	msl_dump_head(dreq, s, th, ti->used_bits_local);
        pc++;
      }
      else
	RDUMP("\n");
    }
  }

  /* Dump full heads */
  RDUMP("%*sfull:\n", dreq->indent+3, "");
  for (struct msl_head *h = atomic_load_explicit(&s->full_heads, memory_order_relaxed);
      h != &slh_dummy_last_full;
      h = atomic_load_explicit(&h->next, memory_order_relaxed))
  {
    RDUMP("%*s", dreq->indent+6, "");
    msl_dump_head(dreq, s, h, NULL);
    fc++;
  }

  /* Dump partial heads */
  RDUMP("%*spartial:\n", dreq->indent+3, "");
  for (struct msl_head * _Atomic * next = &s->partial_heads,
      *h = atomic_load_explicit(next, memory_order_relaxed);
      (next = &h->next), (h != &slh_dummy_last_partial);
      h = atomic_load_explicit(next, memory_order_relaxed))
  {
    /* A partial head may not disappear. That is done only by The Hired
     * Specialist(TM) which is mutually exclusive to this routine.
     *
     * Yet, it can change its state and become slh_thread, or, if the thread is
     * fast enough, slh_full. It may never become slh_partial back again, that's
     * only done by The Hired Specialist(TM).
     *
     * That also means that we can go back to partial_heads and start over there,
     * as the only routine adding to there is actually The Hired Specialist(TM),
     * again. Therefore during this dump routine, heads are only popped from
     * partial_heads, and we've been just slower dumping than the threads were popping.
     */
    enum msl_head_state a = MSL_GET_STATE(h);
    if (a != slh_partial)
    {
      next = &s->partial_heads;
      continue;
    }

    RDUMP("%*s", dreq->indent+6, "");
    msl_dump_head(dreq, s, h, NULL);
    pc++;
  }

  RDUMP("%*spages partial=%d full=%d\n", dreq->indent+3, "", pc, fc);
}

static struct resmem
mslab_memsize(resource *r)
{
  /* This must be called from main_birdloop. Main_birdloop is the only loop freeing
   * thread pools where msl_per_thread_info structs are allocated. Calling mslab_memsize
   * from anywhere else might result in conflict with msl_thread_end. */
  ASSERT_DIE(birdloop_current == &main_birdloop);
  mslab *s = (mslab *) r;

#define MSL_MSI(x) s64 x = atomic_load_explicit(&s->x, memory_order_relaxed)
  MSL_MSI(allocated_heads);
  MSL_MSI(allocated_objs);
  MSL_MSI(freed_heads);
  MSL_MSI(freed_objs);
#undef MSL_MSI

  uint pti = 0;
  for (int i = 0; i < MAX_THREADS; i++)
  {
    struct msl_per_thread_info *ti = atomic_load_explicit(
	&s->thread_head_info[i], memory_order_relaxed);
    if (!ti)
      continue;

#define MSL_ADD(x) x += atomic_load_explicit(&ti->x, memory_order_relaxed)
    MSL_ADD(allocated_heads);
    MSL_ADD(allocated_objs);
    MSL_ADD(freed_objs);
#undef MSL_ADD
    pti++;
  }

  allocated_heads -= freed_heads;
  allocated_objs -= freed_objs;

  ASSERT_DIE(allocated_heads >= 0);
  ASSERT_DIE(allocated_objs >= 0);

  size_t eff = allocated_objs * s->data_size;

  return (struct resmem) {
    .effective = eff,
    .overhead = ALLOC_OVERHEAD + sizeof(struct mslab)
      + page_size /* per thread info pointers */
      + allocated_heads * page_size - eff,

    /* We should technically count also pti * (ALLOC_OVERHEAD + sizeof (struct msl_per_thread_info))
     * but that is accounted for in thread overhead. Not nice but acceptable. */
  };
}
