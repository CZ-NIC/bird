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
  list pages;
  list empty;
  u16 min, max;		/* Minimal and maximal number of free pages kept */
  uint cnt;		/* Number of empty pages */
  event cleanup;
};

static void global_free_pages_cleanup_event(void *);

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
    bug("mmap(%lu) failed: %m", page_size);

  return ptr;
}

extern int shutting_down; /* Shutdown requested. */

#else // ! HAVE_MMAP
#define use_fake  1
#endif

void *
alloc_page(void)
{
  if (use_fake)
  {
    void *ptr = NULL;
    int err = posix_memalign(&ptr, page_size, page_size);

    if (err || !ptr)
      bug("posix_memalign(%lu) failed", (long unsigned int) page_size);

    return ptr;
  }

#ifdef HAVE_MMAP
  struct free_pages *fps = &global_free_pages;

  if (fps->cnt)
  {
    struct free_page *fp = SKIP_BACK(struct free_page, n, HEAD(fps->pages));
    rem_node(&fp->n);
    if ((--fps->cnt < fps->min) && !shutting_down)
      ev_schedule(&fps->cleanup);

    bzero(fp, page_size);
    return fp;
  }

  if (!EMPTY_LIST(fps->empty))
  {
    struct empty_pages *ep = HEAD(fps->empty);
    if (ep->pos)
      return ep->pages[--ep->pos];

    rem_node(&ep->n);
    return ep;
  }

  return alloc_sys_page();
#endif
}

void
free_page(void *ptr)
{
  if (use_fake)
  {
    free(ptr);
    return;
  }

#ifdef HAVE_MMAP
  struct free_pages *fps = &global_free_pages;
  struct free_page *fp = ptr;

  fp->n = (node) {};
  add_tail(&fps->pages, &fp->n);

  if ((++fps->cnt > fps->max) && !shutting_down)
    ev_schedule(&fps->cleanup);
#endif
}

#ifdef HAVE_MMAP
static void
global_free_pages_cleanup_event(void *data UNUSED)
{
  if (shutting_down)
    return;

  struct free_pages *fps = &global_free_pages;

  while (fps->cnt / 2 < fps->min)
  {
    struct free_page *fp = alloc_sys_page();
    fp->n = (node) {};
    add_tail(&fps->pages, &fp->n);
    fps->cnt++;
  }

  int limit = CLEANUP_PAGES_BULK;
  while (--limit && (fps->cnt > fps->max / 2))
  {
    struct free_page *fp = SKIP_BACK(struct free_page, n, TAIL(fps->pages));
    rem_node(&fp->n);
    fps->cnt--;

    struct empty_pages *ep;
    if (EMPTY_LIST(fps->empty) || ((ep = HEAD(fps->empty))->pos == EP_POS_MAX))
    {
      ep = (struct empty_pages *) fp;
      *ep = (struct empty_pages) {};
      add_head(&fps->empty, &ep->n);
    }
    else
    {
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

  if (!limit)
    ev_schedule(&fps->cleanup);
}
#endif

void
resource_sys_init(void)
{
#ifdef HAVE_MMAP
  ASSERT_DIE(global_free_pages.cnt == 0);

  if (!(page_size = sysconf(_SC_PAGESIZE)))
    die("System page size must be non-zero");

  if (u64_popcount(page_size) == 1)
  {
    struct free_pages *fps = &global_free_pages;

    init_list(&fps->pages);
    init_list(&fps->empty);
    global_free_pages_cleanup_event(NULL);
    return;
  }

  /* Too big or strange page, use the aligned allocator instead */
  log(L_WARN "Got strange memory page size (%lu), using the aligned allocator instead", page_size);
  use_fake = 1;
#endif

  page_size = 4096;
}
