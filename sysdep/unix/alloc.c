/*
 *	BIRD Internet Routing Daemon -- Raw allocation
 *
 *	(c) 2020  Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/resource.h"

#include "sysdep/unix/io-loop.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdatomic.h>
#include <errno.h>

#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif

long page_size = 0;

#ifdef HAVE_MMAP
#if DEBUGGING
#define FP_NODE_OFFSET	42
#else
#define FP_NODE_OFFSET   1
#endif
static _Bool use_fake = 0;
#else
static _Bool use_fake = 1;
#endif

static void *
alloc_sys_page(void)
{
  void *ptr = mmap(NULL, page_size, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (ptr == MAP_FAILED)
    bug("mmap(%lu) failed: %m", page_size);

  return ptr;
}

void *
alloc_page(void)
{
#ifdef HAVE_MMAP
  if (!use_fake)
  {
    struct free_pages *fp = &birdloop_current->pages;
    if (!fp->cnt)
      return alloc_sys_page();
    
    node *n = HEAD(fp->list);
    rem_node(n);
    if (--fp->cnt < fp->min)
      ev_send(&global_work_list, fp->cleanup);

    void *ptr = n - FP_NODE_OFFSET;
    memset(ptr, 0, page_size);
    return ptr;
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
free_page(void *ptr)
{
#ifdef HAVE_MMAP
  if (!use_fake)
  {
    struct free_pages *fp = &birdloop_current->pages;
    struct node *n = ptr;
    n += FP_NODE_OFFSET;

    memset(n, 0, sizeof(node));
    add_tail(&fp->list, n);
    if (++fp->cnt > fp->max)
      ev_send(&global_work_list, fp->cleanup);
  }
  else
#endif
    free(ptr);
}

#ifdef HAVE_MMAP

#define GFP (&main_birdloop.pages)

void
flush_pages(struct birdloop *loop)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  add_tail_list(&GFP->list, &loop->pages.list);
  GFP->cnt += loop->pages.cnt;
  
  loop->pages.cnt = 0;
  loop->pages.list = (list) {};
  loop->pages.min = 0;
  loop->pages.max = 0;

  rfree(loop->pages.cleanup);
  loop->pages.cleanup = NULL;
}

static void
cleanup_pages(void *data)
{
  struct birdloop *loop = data;
  birdloop_enter(loop);

  struct free_pages *fp = &birdloop_current->pages;

  while ((fp->cnt < fp->min) && (GFP->cnt > GFP->min))
  {
    node *n = HEAD(GFP->list);
    rem_node(n);
    add_tail(&fp->list, n);
    fp->cnt++;
    GFP->cnt--;
  }
  
  while (fp->cnt < fp->min)
  {
    node *n = alloc_sys_page();
    add_tail(&fp->list, n + FP_NODE_OFFSET);
    fp->cnt++;
  }

  while (fp->cnt > fp->max)
  {
    node *n = HEAD(fp->list);
    rem_node(n);
    add_tail(&GFP->list, n);
    fp->cnt--;
    GFP->cnt++;
  }

  birdloop_leave(loop);

  if (GFP->cnt > GFP->max)
    ev_send(&global_work_list, GFP->cleanup);
}

static void
cleanup_global_pages(void *data UNUSED)
{
  while (GFP->cnt < GFP->max)
  {
    node *n = alloc_sys_page();
    add_tail(&GFP->list, n + FP_NODE_OFFSET);
    GFP->cnt++;
  }

  for (uint limit = GFP->cnt; (limit > 0) && (GFP->cnt > GFP->max); limit--)
  {
    node *n = TAIL(GFP->list);
    rem_node(n);

    if (munmap(n - FP_NODE_OFFSET, page_size) == 0)
      GFP->cnt--;
    else if (errno == ENOMEM)
      add_head(&GFP->list, n);
    else
      bug("munmap(%p) failed: %m", n - FP_NODE_OFFSET);
  }
}

void
init_pages(struct birdloop *loop)
{
  struct free_pages *fp = &loop->pages;

  init_list(&fp->list);
  fp->cleanup = ev_new_init(&root_pool, cleanup_pages, loop);
  fp->min = 4;
  fp->max = 16;

  for (fp->cnt = 0; fp->cnt < fp->min; fp->cnt++)
  {
    node *n = alloc_sys_page();
    add_tail(&fp->list, n + FP_NODE_OFFSET);
  }
}

static event global_free_pages_cleanup_event = { .hook = cleanup_global_pages };

void resource_sys_init(void)
{
  if (!(page_size = sysconf(_SC_PAGESIZE)))
    die("System page size must be non-zero");

  if (u64_popcount(page_size) == 1)
  {
    init_list(&GFP->list);
    GFP->cleanup = &global_free_pages_cleanup_event;
    GFP->min = 0;
    GFP->max = 256;
    return;
  }

  log(L_WARN "Got strange memory page size (%lu), using the aligned allocator instead", page_size);

  /* Too big or strange page, use the aligned allocator instead */
  page_size = 4096;
  use_fake = 1;
}

#else

void
resource_sys_init(void)
{
  page_size = 4096;
  use_fake = 1;
}

#endif
