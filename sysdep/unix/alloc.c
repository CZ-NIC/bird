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

static struct free_page * _Atomic page_stack = NULL;
static _Thread_local struct free_page * local_page_stack = NULL;

static void page_cleanup(void *);
static event page_cleanup_event = { .hook = page_cleanup, };
#define SCHEDULE_CLEANUP  do if (initialized && !shutting_down) ev_send(&global_event_list, &page_cleanup_event); while (0)

_Atomic int pages_kept = 0;
_Atomic int pages_kept_locally = 0;
static int pages_kept_here = 0;

static void *
alloc_sys_page(void)
{
  void *ptr = mmap(NULL, page_size * ALLOC_PAGES_AT_ONCE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

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
  struct free_page *fp = local_page_stack;
  if (fp)
  {
    local_page_stack = atomic_load_explicit(&fp->next, memory_order_acquire);
    atomic_fetch_sub_explicit(&pages_kept_locally, 1, memory_order_relaxed);
    pages_kept_here--;
    return fp;
  }

  rcu_read_lock();
  fp = atomic_load_explicit(&page_stack, memory_order_acquire);
  while (fp && !atomic_compare_exchange_strong_explicit(
	&page_stack, &fp, atomic_load_explicit(&fp->next, memory_order_acquire),
	memory_order_acq_rel, memory_order_acquire))
    ;
  rcu_read_unlock();

  if (!fp)
  {
    void *ptr = alloc_sys_page();
    for (int i=1; i<ALLOC_PAGES_AT_ONCE; i++)
      free_page(ptr + page_size * i);
    return ptr;
  }

  atomic_fetch_sub_explicit(&pages_kept, 1, memory_order_relaxed);
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
  struct free_page *fp = ptr;
  if (shutting_down || (pages_kept_here < KEEP_PAGES_MAX_LOCAL))
  {
    atomic_store_explicit(&fp->next, local_page_stack, memory_order_relaxed);
    atomic_fetch_add_explicit(&pages_kept_locally, 1, memory_order_relaxed);
    pages_kept_here++;
    return;
  }

  rcu_read_lock();
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

void
flush_local_pages(void)
{
  if (use_fake || !local_page_stack || shutting_down)
    return;

  struct free_page *last = local_page_stack, *next;
  int check_count = 1;
  while (next = atomic_load_explicit(&last->next, memory_order_acquire))
  {
    check_count++;
    last = next;
  }

  ASSERT_DIE(check_count == pages_kept_here);

  rcu_read_lock();
  next = atomic_load_explicit(&page_stack, memory_order_acquire);

  do atomic_store_explicit(&last->next, next, memory_order_release);
  while (!atomic_compare_exchange_strong_explicit(
	&page_stack, &next, local_page_stack,
	memory_order_acq_rel, memory_order_acquire));
  rcu_read_unlock();

  local_page_stack = NULL;
  pages_kept_here = 0;

  atomic_fetch_sub_explicit(&pages_kept_locally, check_count, memory_order_relaxed);
  if (atomic_fetch_add_explicit(&pages_kept, check_count, memory_order_relaxed) >= KEEP_PAGES_MAX)
    SCHEDULE_CLEANUP;
}

#ifdef HAVE_MMAP
static void
page_cleanup(void *_ UNUSED)
{
  if (shutting_down)
    return;

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
