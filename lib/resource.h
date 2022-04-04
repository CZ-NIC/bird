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

#include "lib/lists.h"

struct resmem {
  size_t effective;			/* Memory actually used for data storage */
  size_t overhead;			/* Overhead memory imposed by allocator strategies */
};

/* Resource */

typedef struct resource {
  node n;				/* Inside resource pool */
  struct resclass *class;		/* Resource class */
} resource;

/* Resource class */

struct resclass {
  char *name;				/* Resource class name */
  unsigned size;			/* Standard size of single resource */
  void (*free)(resource *);		/* Freeing function */
  void (*dump)(resource *);		/* Dump to debug output */
  resource *(*lookup)(resource *, unsigned long);	/* Look up address (only for debugging) */
  struct resmem (*memsize)(resource *);	/* Return size of memory used by the resource, may be NULL */
};

/* Estimate of system allocator overhead per item, for memory consumtion stats */
#define ALLOC_OVERHEAD		16

/* Generic resource manipulation */

typedef struct pool pool;

void resource_init(void);
pool *rp_new(pool *, const char *);	/* Create new pool */
pool *rp_newf(pool *, const char *, ...);	/* Create a new pool with a formatted string as its name */
void rfree(void *);			/* Free single resource */
void rdump(void *);			/* Dump to debug output */
struct resmem rmemsize(void *res);		/* Return size of memory used by the resource */
void rlookup(unsigned long);		/* Look up address (only for debugging) */
void rmove(void *, pool *);		/* Move to a different pool */

void *ralloc(pool *, struct resclass *);

extern pool root_pool;

/* Normal memory blocks */

void *mb_alloc(pool *, unsigned size);
void *mb_allocz(pool *, unsigned size);
void *mb_realloc(void *m, unsigned size);
void mb_free(void *);

/* Memory pools with linear allocation */

typedef struct linpool linpool;

typedef struct lp_state {
  void *current, *large;
  byte *ptr;
  uint total_large;
} lp_state;

linpool *lp_new(pool *);
void *lp_alloc(linpool *, unsigned size);	/* Aligned */
void *lp_allocu(linpool *, unsigned size);	/* Unaligned */
void *lp_allocz(linpool *, unsigned size);	/* With clear */
void lp_flush(linpool *);			/* Free everything, but leave linpool */
void lp_save(linpool *m, lp_state *p);		/* Save state */
void lp_restore(linpool *m, lp_state *p);	/* Restore state */

extern _Thread_local linpool *tmp_linpool;	/* Temporary linpool autoflushed regularily */

#define tmp_alloc(sz)	lp_alloc(tmp_linpool, sz)
#define tmp_allocu(sz)	lp_allocu(tmp_linpool, sz)
#define tmp_allocz(sz)	lp_allocz(tmp_linpool, sz)

#define tmp_init(p)	tmp_linpool = lp_new_default(p)
#define tmp_flush()	lp_flush(tmp_linpool)

#define lp_new_default	lp_new

/* Slabs */

typedef struct slab slab;

slab *sl_new(pool *, unsigned size);
void *sl_alloc(slab *);
void *sl_allocz(slab *);
void sl_free(void *);

/*
 * Low-level memory allocation functions, please don't use
 * outside resource manager and possibly sysdep code.
 */

void buffer_realloc(void **buf, unsigned *size, unsigned need, unsigned item_size);

/* Allocator of whole pages; for use in slabs and other high-level allocators. */
extern long page_size;
void *alloc_page(void);
void free_page(void *);

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
#define xfree(x) free(x)
#endif

#endif

