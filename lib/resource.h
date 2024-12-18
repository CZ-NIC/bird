/*
 *	BIRD Resource Manager
 *
 *	(c) 1998--1999 Martin Mares <mj@ucw.cz>
 *	(c) 2021 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_RESOURCE_H_
#define _BIRD_RESOURCE_H_

#include "lib/locking.h"
#include "lib/tlists.h"

#include <stdarg.h>

struct resmem {
  size_t effective;			/* Memory actually used for data storage */
  size_t overhead;			/* Overhead memory imposed by allocator strategies */
};

/* Resource */

#define TLIST_PREFIX resource
#define TLIST_TYPE struct resource
#define TLIST_ITEM n
#define TLIST_WANT_WALK
#define TLIST_WANT_ADD_TAIL
#define TLIST_WANT_UPDATE_NODE

typedef struct resource {
  TLIST_DEFAULT_NODE;			/* Inside resource pool */
  const struct resclass *class;		/* Resource class */
} resource;

#include "lib/tlists.h"

/* Resource class */

struct resclass {
  char *name;				/* Resource class name */
  unsigned size;			/* Standard size of single resource */
  void (*free)(resource *);		/* Freeing function */
  void (*dump)(struct dump_request *, resource *);	/* Dump to debug output */
  resource *(*lookup)(resource *, unsigned long);	/* Look up address (only for debugging) */
  struct resmem (*memsize)(resource *);	/* Return size of memory used by the resource, may be NULL */
};

/* Estimate of system allocator overhead per item, for memory consumtion stats */
#define ALLOC_OVERHEAD		16

/* Generic resource manipulation */

typedef struct pool {
  resource r;
  TLIST_LIST(resource) inside;
  struct domain_generic *domain;
  const char *name;
} pool;


void resource_init(void);
void rfree(void *);			/* Free single resource */

struct dump_request;
void rdump(struct dump_request *, void *);	/* Dump to debug output */
void resource_dump(struct dump_request *);	/* Dump the root pool */
struct resmem rmemsize(void *res);		/* Return size of memory used by the resource */
void rlookup(unsigned long);		/* Look up address (only for debugging) */
void rmove(void *, pool *);		/* Move to a different pool */

void *ralloc(pool *, struct resclass *);

pool *rp_new(pool *, struct domain_generic *, const char *);		/* Create a new pool */
pool *rp_newf(pool *, struct domain_generic *, const char *, ...);	/* Create a new pool with a formatted string as its name */
pool *rp_vnewf(pool *, struct domain_generic *, const char *, va_list);	/* Create a new pool with a formatted string as its name */
void rp_free(pool *p);							/* Free the whole pool */

extern pool root_pool;

static inline pool *resource_parent(resource *r)
{ return SKIP_BACK(pool, inside, resource_enlisted(r)); }

/* Normal memory blocks */

void *mb_alloc(pool *, unsigned size) ALLOC_SIZE(2);
void *mb_allocz(pool *, unsigned size) ALLOC_SIZE(2);
void *mb_realloc(void *m, unsigned size) ALLOC_SIZE(2);
void mb_free(void *);

/* Memory pools with linear allocation */

typedef struct linpool linpool;

typedef struct lp_state {
  struct linpool *p;
  void *current, *large;
  uint total_large;
} lp_state;

linpool *lp_new(pool *);
void *lp_alloc(linpool *, unsigned size) ALLOC_SIZE(2);		/* Aligned */
void *lp_allocu(linpool *, unsigned size) ALLOC_SIZE(2);	/* Unaligned */
void *lp_allocz(linpool *, unsigned size) ALLOC_SIZE(2);	/* With clear */
void lp_flush(linpool *);			/* Free everything, but leave linpool */
lp_state *lp_save(linpool *m);			/* Save state */
void lp_restore(linpool *m, lp_state *p);	/* Restore state */

static inline void lp_saved_cleanup(struct lp_state **lps)
{
  if (*lps)
    lp_restore((*lps)->p, (*lps));
}

#define LP_SAVED(m)	for (CLEANUP(lp_saved_cleanup) struct lp_state *_lp_state = lp_save(m); _lp_state; lp_restore(m, _lp_state), _lp_state = NULL)

#define lp_new_default	lp_new

/* Thread-local temporary linpools */

extern _Thread_local linpool *tmp_linpool;
#define tmp_alloc(sz)	lp_alloc(tmp_linpool, sz)
#define tmp_allocu(sz)	lp_allocu(tmp_linpool, sz)
#define tmp_allocz(sz)	lp_allocz(tmp_linpool, sz)
#define TMP_SAVED	LP_SAVED(tmp_linpool)

void tmp_init(pool *p);
void tmp_flush(void);


/* Slabs */

typedef struct slab slab;
struct event_list;

struct slab *sl_new(pool *p, struct event_list *cleanup_ev_list, uint size);
void *sl_alloc(slab *);
void *sl_allocz(slab *);
void sl_free(void *);
void sl_delete(slab *);

/*
 * Low-level memory allocation functions, please don't use
 * outside resource manager and possibly sysdep code.
 */

void buffer_realloc(void **buf, unsigned *size, unsigned need, unsigned item_size);

/* Allocator of whole pages; for use in slabs and other high-level allocators. */
#define PAGE_HEAD(x)	((void *) (((uintptr_t) (x)) & ~(page_size-1)))
extern long page_size;
extern _Atomic int pages_kept;
extern _Atomic int pages_kept_locally;
extern _Atomic int pages_kept_cold;
extern _Atomic int pages_kept_cold_index;
extern _Atomic int pages_total;
extern _Atomic int alloc_locking_in_rcu;
void *alloc_page(void);
void free_page(void *);
void flush_local_pages(void);

void resource_sys_init(void);

#ifdef HAVE_LIBDMALLOC
/*
 * The standard dmalloc macros tend to produce lots of namespace
 * conflicts and we use only xmalloc, xrealloc and xfree, so we
 * can define the stubs ourselves.
 */
#define DMALLOC_DISABLE
#include <dmalloc.h>
#define xmalloc(size) \
  dmalloc_malloc(__FILE__, __LINE__, (size), DMALLOC_FUNC_MALLOC, 0, 1)
#define xrealloc(ptr, size) \
  dmalloc_realloc(__FILE__, __LINE__, (ptr), (size), DMALLOC_FUNC_REALLOC, 1)
#define xfree(ptr) \
  dmalloc_free(__FILE__, __LINE__, (ptr), DMALLOC_FUNC_FREE)

#else
/*
 * Unfortunately, several libraries we might want to link to define
 * their own xmalloc and we don't want to interfere with them, hence
 * the renaming.
 */
#define xmalloc bird_xmalloc
#define xrealloc bird_xrealloc
void *xmalloc(unsigned);
void *xrealloc(void *, unsigned);
void xfree(void *);
#endif

#endif

