/*
 *	BIRD Internet Routing Daemon -- Raw allocation
 *
 *	(c) 2020  Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/resource.h"
#include "lib/lists.h"
#include "lib/event.h"
#include "lib/rcu.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif

#ifdef CONFIG_DISABLE_THP
#include <sys/prctl.h>
#ifndef PR_SET_THP_DISABLE
#define PR_SET_THP_DISABLE 41
#endif
#endif

long page_size = 0;

#ifdef HAVE_MMAP
#define KEEP_PAGES_MAX	512
#define KEEP_PAGES_MIN	32
#define KEEP_PAGES_MAX_LOCAL	16
#define ALLOC_PAGES_AT_ONCE	8

STATIC_ASSERT(KEEP_PAGES_MIN * 4 < KEEP_PAGES_MAX);
STATIC_ASSERT(ALLOC_PAGES_AT_ONCE < KEEP_PAGES_MAX_LOCAL);

static _Bool use_fake = 0;
static _Bool initialized = 0;

#if DEBUGGING
struct free_page {
  node unused[42];
  struct free_page * _Atomic next;
};
#else
struct free_page {
  struct free_page * _Atomic next;
};
#endif

#define EP_POS_MAX	((page_size - OFFSETOF(struct empty_pages, pages)) / sizeof (void *))

struct empty_pages {
  struct empty_pages *next;
  uint pos;
  void *pages[0];
};

DEFINE_DOMAIN(resource);
static DOMAIN(resource) empty_pages_domain;
static struct empty_pages *empty_pages = NULL;

static struct free_page * _Atomic page_stack = NULL;
static _Thread_local struct free_page * local_page_stack = NULL;

static void page_cleanup(void *);
static event page_cleanup_event = { .hook = page_cleanup, };
#define SCHEDULE_CLEANUP  do if (initialized && !shutting_down) ev_send(&global_event_list, &page_cleanup_event); while (0)

_Atomic int pages_kept = 0;
_Atomic int pages_kept_locally = 0;
static _Thread_local int pages_kept_here = 0;

static void *
alloc_sys_page(void)
{
  void *ptr = mmap(NULL, page_size * ALLOC_PAGES_AT_ONCE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (ptr == MAP_FAILED)
    die("mmap(%ld) failed: %m", (s64) page_size);

  return ptr;
}

extern int shutting_down; /* Shutdown requested. */

#else // ! HAVE_MMAP
#define use_fake  1
#endif

void *
alloc_page(void)
{
  /* If the system page allocator is goofy, we use posix_memalign to get aligned blocks of memory. */
  if (use_fake)
  {
    void *ptr = NULL;
    int err = posix_memalign(&ptr, page_size, page_size);

    if (err || !ptr)
      die("posix_memalign(%ld) failed", (s64) page_size);

    return ptr;
  }

#ifdef HAVE_MMAP
  /* If there is any free page kept hot in this thread, we use it. */
  struct free_page *fp = local_page_stack;
  if (fp)
  {
    local_page_stack = atomic_load_explicit(&fp->next, memory_order_acquire);
    atomic_fetch_sub_explicit(&pages_kept_locally, 1, memory_order_relaxed);
    pages_kept_here--;
    return fp;
  }

  ASSERT_DIE(pages_kept_here == 0);

  /* If there is any free page kept hot in global storage, we use it. */
  rcu_read_lock();
  fp = atomic_load_explicit(&page_stack, memory_order_acquire);
  while (fp && !atomic_compare_exchange_strong_explicit(
	&page_stack, &fp, atomic_load_explicit(&fp->next, memory_order_acquire),
	memory_order_acq_rel, memory_order_acquire))
    ;
  rcu_read_unlock();

  if (fp)
  {
    atomic_fetch_sub_explicit(&pages_kept, 1, memory_order_relaxed);
    return fp;
  }

  /* If there is any free page kept cold, we use that. */
  LOCK_DOMAIN(resource, empty_pages_domain);
  if (empty_pages) {
    if (empty_pages->pos)
      /* Either the keeper page contains at least one cold page pointer, return that */
      fp = empty_pages->pages[--empty_pages->pos];
    else
    {
      /* Or the keeper page has no more cold page pointer, return the keeper page */
      fp = (struct free_page *) empty_pages;
      empty_pages = empty_pages->next;
    }
  }
  UNLOCK_DOMAIN(resource, empty_pages_domain);

  if (fp)
    return fp;

  /* And in the worst case, allocate some new pages by mmap() */
  void *ptr = alloc_sys_page();
  for (int i=1; i<ALLOC_PAGES_AT_ONCE; i++)
    free_page(ptr + page_size * i);

  return ptr;
#endif
}

void
free_page(void *ptr)
{
  /* If the system page allocator is goofy, we just free the block and care no more. */
  if (use_fake)
  {
    free(ptr);
    return;
  }

#ifdef HAVE_MMAP
  /* We primarily try to keep the pages locally. */
  struct free_page *fp = ptr;
  if (shutting_down || (pages_kept_here < KEEP_PAGES_MAX_LOCAL))
  {
    atomic_store_explicit(&fp->next, local_page_stack, memory_order_relaxed);
    local_page_stack = fp;

    atomic_fetch_add_explicit(&pages_kept_locally, 1, memory_order_relaxed);
    pages_kept_here++;
    return;
  }

  /* If there are too many local pages, we add the free page to the global hot-free-page list */
  rcu_read_lock();
  struct free_page *next = atomic_load_explicit(&page_stack, memory_order_acquire);

  do atomic_store_explicit(&fp->next, next, memory_order_release);
  while (!atomic_compare_exchange_strong_explicit(
	&page_stack, &next, fp,
	memory_order_acq_rel, memory_order_acquire));
  rcu_read_unlock();

  /* And if there are too many global hot free pages, we ask for page cleanup */
  if (atomic_fetch_add_explicit(&pages_kept, 1, memory_order_relaxed) >= KEEP_PAGES_MAX)
    SCHEDULE_CLEANUP;
#endif
}

/* When the routine is going to sleep for a long time, we flush the local
 * hot page cache to not keep dirty pages for nothing. */
void
flush_local_pages(void)
{
  if (use_fake || !local_page_stack || shutting_down)
    return;

  /* We first count the pages to enable consistency checking.
   * Also, we need to know the last page. */
  struct free_page *last = local_page_stack, *next;
  int check_count = 1;
  while (next = atomic_load_explicit(&last->next, memory_order_acquire))
  {
    check_count++;
    last = next;
  }

  /* The actual number of pages must be equal to the counter value. */
  ASSERT_DIE(check_count == pages_kept_here);

  /* Repeatedly trying to insert the whole page list into global page stack at once. */
  rcu_read_lock();
  next = atomic_load_explicit(&page_stack, memory_order_acquire);

  /* First we set the outwards pointer (from our last),
   * then we try to set the inwards pointer to our first page. */
  do atomic_store_explicit(&last->next, next, memory_order_release);
  while (!atomic_compare_exchange_strong_explicit(
	&page_stack, &next, local_page_stack,
	memory_order_acq_rel, memory_order_acquire));
  rcu_read_unlock();

  /* Finished. Now the local stack is empty. */
  local_page_stack = NULL;
  pages_kept_here = 0;

  /* Check the state of global page cache and maybe schedule its cleanup. */
  atomic_fetch_sub_explicit(&pages_kept_locally, check_count, memory_order_relaxed);
  if (atomic_fetch_add_explicit(&pages_kept, check_count, memory_order_relaxed) >= KEEP_PAGES_MAX)
    SCHEDULE_CLEANUP;
}

#ifdef HAVE_MMAP
static void
page_cleanup(void *_ UNUSED)
{
  /* Cleanup on shutdown is ignored. All pages may be kept hot, OS will take care. */
  if (shutting_down)
    return;

  struct free_page *stack = atomic_exchange_explicit(&page_stack, NULL, memory_order_acq_rel);
  if (!stack)
    return;


  do {
    synchronize_rcu();
    struct free_page *fp = stack;
    stack = atomic_load_explicit(&fp->next, memory_order_acquire);

    LOCK_DOMAIN(resource, empty_pages_domain);
    /* Empty pages are stored as pointers. To store them, we need a pointer block. */
    if (!empty_pages || (empty_pages->pos == EP_POS_MAX))
    {
      /* There is either no pointer block or the last block is full. We use this block as a pointer block. */
      empty_pages = (struct empty_pages *) fp;
      *empty_pages = (struct empty_pages) {};
    }
    else
    {
      /* We store this block as a pointer into the first free place
       * and tell the OS that the underlying memory is trash. */
      empty_pages->pages[empty_pages->pos++] = fp;
      if (madvise(fp, page_size,
#ifdef CONFIG_MADV_DONTNEED_TO_FREE
	    MADV_DONTNEED
#else
	    MADV_FREE
#endif
	    ) < 0)
	bug("madvise(%p) failed: %m", fp);
    }
    UNLOCK_DOMAIN(resource, empty_pages_domain);
  }
  while ((atomic_fetch_sub_explicit(&pages_kept, 1, memory_order_relaxed) >= KEEP_PAGES_MAX / 2) && stack);

  while (stack)
  {
    struct free_page *f = stack;
    stack = atomic_load_explicit(&f->next, memory_order_acquire);
    free_page(f);

    atomic_fetch_sub_explicit(&pages_kept, 1, memory_order_relaxed);
  }
}
#endif

void
resource_sys_init(void)
{
#ifdef CONFIG_DISABLE_THP
  /* Disable transparent huge pages, they do not work properly with madvice(MADV_DONTNEED) */
  if (prctl(PR_SET_THP_DISABLE,  (unsigned long) 1,  (unsigned long) 0,  (unsigned long) 0,  (unsigned long) 0) < 0)
    log(L_WARN "Cannot disable transparent huge pages: prctl(PR_SET_THP_DISABLE) failed: %m");
#endif

#ifdef HAVE_MMAP
  /* Check what page size the system supports */
  if (!(page_size = sysconf(_SC_PAGESIZE)))
    die("System page size must be non-zero");

  if ((u64_popcount(page_size) == 1) && (page_size >= (1 << 10)) && (page_size <= (1 << 18)))
  {
    /* We assume that page size has only one bit and is between 1K and 256K (incl.).
     * Otherwise, the assumptions in lib/slab.c (sl_head's num_full range) aren't met. */

    empty_pages_domain = DOMAIN_NEW(resource, "Empty Pages");
    initialized = 1;
    return;
  }

  /* Too big or strange page, use the aligned allocator instead */
  log(L_WARN "Got strange memory page size (%ld), using the aligned allocator instead", (s64) page_size);
  use_fake = 1;
#endif

  page_size = 4096;
  initialized = 1;
}
