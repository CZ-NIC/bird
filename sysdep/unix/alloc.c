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

long page_size = 0;

#ifdef HAVE_MMAP
#define KEEP_PAGES_MAX	256
#define KEEP_PAGES_MIN	8

STATIC_ASSERT(KEEP_PAGES_MIN * 4 < KEEP_PAGES_MAX);

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

static struct free_page * _Atomic page_stack = NULL;

static void page_cleanup(void *);
static event page_cleanup_event = { .hook = page_cleanup, };
#define SCHEDULE_CLEANUP  do if (initialized && !shutting_down) ev_send(&global_event_list, &page_cleanup_event); while (0)

_Atomic int pages_kept = 0;

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
  rcu_read_lock();
  struct free_page *fp = atomic_load_explicit(&page_stack, memory_order_acquire);
  while (fp && !atomic_compare_exchange_strong_explicit(
	&page_stack, &fp, atomic_load_explicit(&fp->next, memory_order_acquire),
	memory_order_acq_rel, memory_order_acquire))
    ;
  rcu_read_unlock();

  if (!fp)
    return alloc_sys_page();

  if (atomic_fetch_sub_explicit(&pages_kept, 1, memory_order_relaxed) <= KEEP_PAGES_MIN)
    SCHEDULE_CLEANUP;

  return fp;
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
  rcu_read_lock();
  struct free_page *fp = ptr;
  struct free_page *next = atomic_load_explicit(&page_stack, memory_order_acquire);

  do atomic_store_explicit(&fp->next, next, memory_order_release);
  while (!atomic_compare_exchange_strong_explicit(
	&page_stack, &next, fp,
	memory_order_acq_rel, memory_order_acquire));
  rcu_read_unlock();

  if (atomic_fetch_add_explicit(&pages_kept, 1, memory_order_relaxed) >= KEEP_PAGES_MAX)
    SCHEDULE_CLEANUP;
#endif
}

#ifdef HAVE_MMAP
static void
page_cleanup(void *_ UNUSED)
{
  struct free_page *stack = atomic_exchange_explicit(&page_stack, NULL, memory_order_acq_rel);
  if (!stack)
    return;

  synchronize_rcu();

  do {
    struct free_page *f = stack;
    stack = atomic_load_explicit(&f->next, memory_order_acquire);

    if (munmap(f, page_size) == 0)
      continue;
    else if (errno != ENOMEM)
      bug("munmap(%p) failed: %m", f);
    else
      free_page(f);
  }
  while (stack && (atomic_fetch_sub_explicit(&pages_kept, 1, memory_order_relaxed) >= KEEP_PAGES_MAX / 2));

  while (stack)
  {
    atomic_fetch_sub_explicit(&pages_kept, 1, memory_order_relaxed);

    struct free_page *f = stack;
    stack = atomic_load_explicit(&f->next, memory_order_acquire);
    free_page(f);
  }
}
#endif

void
resource_sys_init(void)
{
#ifdef HAVE_MMAP
  if (!(page_size = sysconf(_SC_PAGESIZE)))
    die("System page size must be non-zero");

  if (u64_popcount(page_size) == 1)
  {

    for (int i = 0; i < (KEEP_PAGES_MIN * 2); i++)
      free_page(alloc_page());

    page_cleanup(NULL);
    initialized = 1;
    return;
  }

  /* Too big or strange page, use the aligned allocator instead */
  log(L_WARN "Got strange memory page size (%lu), using the aligned allocator instead", page_size);
  use_fake = 1;
#endif

  page_size = 4096;
  initialized = 1;
}
