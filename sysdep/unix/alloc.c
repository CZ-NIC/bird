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

struct free_pages {
  list pages;
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

  for (uint seen = 0; (seen < CLEANUP_PAGES_BULK) && (fps->cnt > fps->max / 2); seen++)
  {
    struct free_page *fp = SKIP_BACK(struct free_page, n, TAIL(fps->pages));
    rem_node(&fp->n);

    if (munmap(fp, page_size) == 0)
      fps->cnt--;
    else if (errno == ENOMEM)
      add_head(&fps->pages, &fp->n);
    else
      bug("munmap(%p) failed: %m", fp);
  }
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
    global_free_pages_cleanup_event(NULL);
    return;
  }

  /* Too big or strange page, use the aligned allocator instead */
  log(L_WARN "Got strange memory page size (%lu), using the aligned allocator instead", page_size);
  use_fake = 1;
#endif

  page_size = 4096;
}
