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

#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif

#ifdef HAVE_MMAP
#define KEEP_PAGES  512

static u64 page_size = 0;
static _Bool use_fake = 0;

uint pages_kept = 0;
static list pages_list;

static void cleanup_pages(void *data);
static event page_cleanup_event = { .hook = cleanup_pages };

#else
static const u64 page_size = 4096; /* Fake page size */
#endif

u64 get_page_size(void)
{
  if (page_size)
    return page_size;

#ifdef HAVE_MMAP
  if (page_size = sysconf(_SC_PAGESIZE))
  {
    if ((u64_popcount(page_size) > 1) || (page_size > 16384))
    {
      /* Too big or strange page, use the aligned allocator instead */
      page_size = 4096;
      use_fake = 1;
    }
    return page_size;
  }

  bug("Page size must be non-zero");
#endif
}

void *
alloc_page(void)
{
#ifdef HAVE_MMAP
  if (pages_kept)
  {
    node *page = TAIL(pages_list);
    rem_node(page);
    pages_kept--;
    memset(page, 0, get_page_size());
    return page;
  }

  if (!use_fake)
  {
    void *ret = mmap(NULL, get_page_size(), PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ret == MAP_FAILED)
      bug("mmap(%lu) failed: %m", (long unsigned int) page_size);
    return ret;
  }
  else
#endif
  {
    void *ptr = NULL;
    int err = posix_memalign(&ptr, page_size, page_size);
    if (err || !ptr)
      bug("posix_memalign(%lu) failed", (long unsigned int) page_size);
    return ptr;
  }
}

void
free_page(void *ptr)
{
#ifdef HAVE_MMAP
  if (!use_fake)
  {
    if (!pages_kept)
      init_list(&pages_list);

    memset(ptr, 0, sizeof(node));
    add_tail(&pages_list, ptr);

    if (++pages_kept > KEEP_PAGES)
      ev_schedule(&page_cleanup_event);
  }
  else
#endif
    free(ptr);
}

#ifdef HAVE_MMAP
static void
cleanup_pages(void *data UNUSED)
{
  for (uint seen = 0; (pages_kept > KEEP_PAGES) && (seen < KEEP_PAGES); seen++)
  {
    void *ptr = HEAD(pages_list);
    rem_node(ptr);
    if (munmap(ptr, get_page_size()) == 0)
      pages_kept--;
#ifdef ENOMEM
    else if (errno == ENOMEM)
      add_tail(&pages_list, ptr);
#endif
    else
      bug("munmap(%p) failed: %m", ptr);
  }

  if (pages_kept > KEEP_PAGES)
    ev_schedule(&page_cleanup_event);
}
#endif
