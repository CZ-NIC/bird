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
#define KEEP_PAGES_MAIN_MAX	256
#define KEEP_PAGES_MAIN_MIN	8
#define CLEANUP_PAGES_BULK	256

STATIC_ASSERT(KEEP_PAGES_MAIN_MIN * 4 < KEEP_PAGES_MAIN_MAX);

static _Bool use_fake = 0;

#if DEBUGGING
struct free_page {
  node unused[42];
  node n;
};
#else
struct free_page {
  node n;
};
#endif

#define EP_POS_MAX	((page_size - OFFSETOF(struct empty_pages, pages)) / sizeof (void *))

struct empty_pages {
  node n;
  uint pos;
  void *pages[0];
};

struct free_pages {
  list pages;		/* List of (struct free_page) keeping free pages without releasing them (hot) */
  list empty;		/* List of (struct empty_pages) keeping invalidated pages mapped for us (cold) */
  u16 min, max;		/* Minimal and maximal number of free pages kept */
  uint cnt;		/* Number of free pages in list */
  event cleanup;
};

static void global_free_pages_cleanup_event(void *);
static void *alloc_cold_page(void);

static struct free_pages global_free_pages = {
  .min = KEEP_PAGES_MAIN_MIN,
  .max = KEEP_PAGES_MAIN_MAX,
  .cleanup = { .hook = global_free_pages_cleanup_event },
};

uint *pages_kept = &global_free_pages.cnt;

static void *
alloc_sys_page(void)
{
  void *ptr = mmap(NULL, page_size, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

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
  struct free_pages *fps = &global_free_pages;

  /* If there is any free page kept hot, we use it. */
  if (fps->cnt)
  {
    struct free_page *fp = SKIP_BACK(struct free_page, n, HEAD(fps->pages));
    rem_node(&fp->n);

    /* If the hot-free-page cache is getting short, request the cleanup routine to replenish the cache */
    if ((--fps->cnt < fps->min) && !shutting_down)
      ev_schedule(&fps->cleanup);

    return fp;
  }
  else
    return alloc_cold_page();
}

static void *
alloc_cold_page(void)
{
  struct free_pages *fps = &global_free_pages;

  /* If there is any free page kept cold, we use that. */
  if (!EMPTY_LIST(fps->empty))
  {
    struct empty_pages *ep = HEAD(fps->empty);

    /* Either the keeper page contains at least one cold page pointer, return that */
    if (ep->pos)
      return ep->pages[--ep->pos];

    /* Or the keeper page has no more cold page pointer, return the keeper page */
    rem_node(&ep->n);
    return ep;
  }

  /* And in the worst case, allocate a new page by mmap() */
  return alloc_sys_page();
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
  struct free_pages *fps = &global_free_pages;
  struct free_page *fp = ptr;

  /* Otherwise, we add the free page to the hot-free-page list */
  fp->n = (node) {};
  add_tail(&fps->pages, &fp->n);

  /* And if there are too many hot free pages, we ask for page cleanup */
  if ((++fps->cnt > fps->max) && !shutting_down)
    ev_schedule(&fps->cleanup);
#endif
}

#ifdef HAVE_MMAP
static void
global_free_pages_cleanup_event(void *data UNUSED)
{
  /* Cleanup on shutdown is ignored. All pages may be kept hot, OS will take care. */
  if (shutting_down)
    return;

  struct free_pages *fps = &global_free_pages;

  /* Cleanup may get called when hot free page cache is short of pages. Replenishing. */
  while (fps->cnt / 2 < fps->min)
    free_page(alloc_cold_page());

  /* Or the hot free page cache is too big. Moving some pages to the cold free page cache. */
  for (int limit = CLEANUP_PAGES_BULK; limit && (fps->cnt > fps->max / 2); fps->cnt--, limit--)
  {
    struct free_page *fp = SKIP_BACK(struct free_page, n, TAIL(fps->pages));
    rem_node(&fp->n);

    /* Empty pages are stored as pointers. To store them, we need a pointer block. */
    struct empty_pages *ep;
    if (EMPTY_LIST(fps->empty) || ((ep = HEAD(fps->empty))->pos == EP_POS_MAX))
    {
      /* There is either no pointer block or the last block is full. We use this block as a pointer block. */
      ep = (struct empty_pages *) fp;
      *ep = (struct empty_pages) {};
      add_head(&fps->empty, &ep->n);
    }
    else
    {
      /* We store this block as a pointer into the first free place
       * and tell the OS that the underlying memory is trash. */
      ep->pages[ep->pos++] = fp;
      if (madvise(fp, page_size,
#ifdef CONFIG_MADV_DONTNEED_TO_FREE
	    MADV_DONTNEED
#else
	    MADV_FREE
#endif
	    ) < 0)
	bug("madvise(%p) failed: %m", fp);
    }
  }

  /* If the hot free page cleanup hit the limit, re-schedule this routine
   * to allow for other routines to run. */
  if (fps->cnt > fps->max)
    ev_schedule(&fps->cleanup);
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
  ASSERT_DIE(global_free_pages.cnt == 0);

  /* Check what page size the system supports */
  if (!(page_size = sysconf(_SC_PAGESIZE)))
    die("System page size must be non-zero");

  if ((u64_popcount(page_size) == 1) && (page_size >= (1 << 10)) && (page_size <= (1 << 18)))
  {
    /* We assume that page size has only one bit and is between 1K and 256K (incl.).
     * Otherwise, the assumptions in lib/slab.c (sl_head's num_full range) aren't met. */

    struct free_pages *fps = &global_free_pages;

    init_list(&fps->pages);
    init_list(&fps->empty);
    global_free_pages_cleanup_event(NULL);
    return;
  }

  /* Too big or strange page, use the aligned allocator instead */
  log(L_WARN "Got strange memory page size (%ld), using the aligned allocator instead", (s64) page_size);
  use_fake = 1;
#endif

  page_size = 4096;
}
