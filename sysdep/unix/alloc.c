/*
 *	BIRD Internet Routing Daemon -- Raw allocation
 *
 *	(c) 2020  Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/resource.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdatomic.h>
#include <errno.h>

#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif

long page_size = 0;
_Bool alloc_multipage = 0;

static _Atomic int global_page_list_not_empty;
static list global_page_list;
static _Atomic int global_page_spinlock;

#define	GLOBAL_PAGE_SPIN_LOCK	for (int v = 0; !atomic_compare_exchange_weak_explicit(&global_page_spinlock, &v, 1, memory_order_acq_rel, memory_order_acquire); v = 0)
#define GLOBAL_PAGE_SPIN_UNLOCK	do { int v = 1; ASSERT_DIE(atomic_compare_exchange_strong_explicit(&global_page_spinlock, &v, 0, memory_order_acq_rel, memory_order_acquire)); } while (0)

#ifdef HAVE_MMAP
static _Bool use_fake = 0;
#else
static _Bool use_fake = 1;
#endif

void resource_sys_init(void)
{
#ifdef HAVE_MMAP
  init_list(&global_page_list);

  if (!(page_size = sysconf(_SC_PAGESIZE)))
    die("System page size must be non-zero");

  if ((u64_popcount(page_size) > 1) || (page_size > 16384))
#endif
  {
    /* Too big or strange page, use the aligned allocator instead */
    page_size = 4096;
    use_fake = 1;
  }
}

void *
alloc_sys_page(void)
{
#ifdef HAVE_MMAP
  if (!use_fake)
  {
    if (atomic_load_explicit(&global_page_list_not_empty, memory_order_relaxed))
    {
      GLOBAL_PAGE_SPIN_LOCK;
      if (!EMPTY_LIST(global_page_list))
      {
	node *ret = HEAD(global_page_list);
	rem_node(ret);
	if (EMPTY_LIST(global_page_list))
	  atomic_store_explicit(&global_page_list_not_empty, 0, memory_order_relaxed);
	GLOBAL_PAGE_SPIN_UNLOCK;
	memset(ret, 0, sizeof(node));
	return (void *) ret;
      }
      GLOBAL_PAGE_SPIN_UNLOCK;
    }

    if (alloc_multipage)
    {
      void *big = mmap(NULL, page_size * 2, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (big == MAP_FAILED)
	bug("mmap(%lu) failed: %m", page_size);

      uintptr_t offset = ((uintptr_t) big) % page_size;
      if (offset)
      {
	void *ret = big + page_size - offset;
	munmap(big, page_size - offset);
	munmap(ret + page_size, offset);
	return ret;
      }
      else
      {
	munmap(big + page_size, page_size);
	return big;
      }
    }

    void *ret = mmap(NULL, page_size, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ret == MAP_FAILED)
      bug("mmap(%lu) failed: %m", page_size);

    return ret;
  }
  else
#endif
  {
    void *ret = aligned_alloc(page_size, page_size);
    if (!ret)
      bug("aligned_alloc(%lu) failed", page_size);
    return ret;
  }
}

void
free_sys_page(void *ptr)
{
#ifdef HAVE_MMAP
  if (!use_fake)
  {
    if (munmap(ptr, page_size) < 0)
#ifdef ENOMEM
      if (errno == ENOMEM)
      {
	memset(ptr, 0, page_size);

	GLOBAL_PAGE_SPIN_LOCK;
	add_tail(&global_page_list, (node *) ptr);
	atomic_store_explicit(&global_page_list_not_empty, 1, memory_order_relaxed);
	GLOBAL_PAGE_SPIN_UNLOCK;
      }
      else
#endif
	bug("munmap(%p) failed: %m", ptr);
  }
  else
#endif
    free(ptr);
}
