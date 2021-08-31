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

#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif

long page_size = 0;

#ifdef HAVE_MMAP
static _Bool use_fake = 0;
#else
static _Bool use_fake = 1;
#endif

void resource_sys_init(void)
{
#ifdef HAVE_MMAP
  if (!(page_size = sysconf(_SC_PAGESIZE)))
    die("System page size must be non-zero");

  if ((u64_popcount(page_size) > 1) || (page_size > 16384))
  {
#endif
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
      bug("munmap(%p) failed: %m", ptr);
  }
  else
#endif
    free(ptr);
}
