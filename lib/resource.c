/*
 *	BIRD Resource Manager
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2021 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "nest/bird.h"
#include "lib/resource.h"
#include "lib/string.h"

/**
 * DOC: Resource pools
 *
 * Resource pools (&pool) are just containers holding a list of
 * other resources. Freeing a pool causes all the listed resources
 * to be freed as well. Each existing &resource is linked to some pool
 * except for a root pool which isn't linked anywhere, so all the
 * resources form a tree structure with internal nodes corresponding
 * to pools and leaves being the other resources.
 *
 * Example: Almost all modules of BIRD have their private pool which
 * is freed upon shutdown of the module.
 */

struct pool {
  resource r;
  list inside;
  const char *name;
};

static void pool_dump(struct dump_request *, resource *);
static void pool_free(resource *);
static resource *pool_lookup(resource *, unsigned long);
static struct resmem pool_memsize(resource *P);

static struct resclass pool_class = {
  "Pool",
  sizeof(pool),
  pool_free,
  pool_dump,
  pool_lookup,
  pool_memsize
};

pool root_pool;

/**
 * rp_new - create a resource pool
 * @p: parent pool
 * @name: pool name (to be included in debugging dumps)
 *
 * rp_new() creates a new resource pool inside the specified
 * parent pool.
 */
pool *
rp_new(pool *p, const char *name)
{
  pool *z = ralloc(p, &pool_class);
  z->name = name;
  init_list(&z->inside);
  return z;
}

pool *
rp_newf(pool *p, const char *fmt, ...)
{
  pool *z = rp_new(p, NULL);

  va_list args;
  va_start(args, fmt);
  z->name = mb_vsprintf(p, fmt, args);
  va_end(args);

  return z;
}


static void
pool_free(resource *P)
{
  pool *p = (pool *) P;
  resource *r, *rr;

  r = HEAD(p->inside);
  while (rr = (resource *) r->n.next)
    {
      r->class->free(r);
      xfree(r);
      r = rr;
    }
}

static void
pool_dump(struct dump_request *dreq, resource *P)
{
  pool *p = (pool *) P;
  resource *r;

  RDUMP("%s\n", p->name);
  dreq->indent += 3;
  WALK_LIST(r, p->inside)
    rdump(dreq, r);
  dreq->indent -= 3;
}

static struct resmem
pool_memsize(resource *P)
{
  pool *p = (pool *) P;
  resource *r;
  struct resmem sum = {
    .effective = 0,
    .overhead = sizeof(pool) + ALLOC_OVERHEAD,
  };

  WALK_LIST(r, p->inside)
  {
    struct resmem add = rmemsize(r);
    sum.effective += add.effective;
    sum.overhead += add.overhead;
  }

  return sum;
}

static resource *
pool_lookup(resource *P, unsigned long a)
{
  pool *p = (pool *) P;
  resource *r, *q;

  WALK_LIST(r, p->inside)
    if (r->class->lookup && (q = r->class->lookup(r, a)))
      return q;
  return NULL;
}

/**
 * rmove - move a resource
 * @res: resource
 * @p: pool to move the resource to
 *
 * rmove() moves a resource from one pool to another.
 */

void rmove(void *res, pool *p)
{
  resource *r = res;

  if (r)
    {
      if (r->n.next)
        rem_node(&r->n);
      add_tail(&p->inside, &r->n);
    }
}

/**
 * rfree - free a resource
 * @res: resource
 *
 * rfree() frees the given resource and all information associated
 * with it. In case it's a resource pool, it also frees all the objects
 * living inside the pool.
 *
 * It works by calling a class-specific freeing function.
 */
void
rfree(void *res)
{
  resource *r = res;

  if (!r)
    return;

  if (r->n.next)
    rem_node(&r->n);
  r->class->free(r);
  r->class = NULL;
  xfree(r);
}

/**
 * rdump - dump a resource
 * @res: resource
 *
 * This function prints out all available information about the given
 * resource to the debugging output.
 *
 * It works by calling a class-specific dump function.
 */
void
rdump(struct dump_request *dreq, void *res)
{
  char x[16];
  resource *r = res;

  bsprintf(x, "%%%ds%%p ", dreq->indent);
  RDUMP(x, "", r);
  if (r)
    {
      RDUMP("%s ", r->class->name);
      r->class->dump(dreq, r);
    }
  else
    RDUMP("NULL\n");
}

void page_dump(struct dump_request *req);

void resource_dump(struct dump_request *req)
{
  rdump(req, &root_pool);
  page_dump(req);
}

struct resmem
rmemsize(void *res)
{
  resource *r = res;
  if (!r)
    return (struct resmem) {};
  if (!r->class->memsize)
    return (struct resmem) {
      .effective = r->class->size - sizeof(resource),
      .overhead = ALLOC_OVERHEAD + sizeof(resource),
    };
  return r->class->memsize(r);
}

/**
 * ralloc - create a resource
 * @p: pool to create the resource in
 * @c: class of the new resource
 *
 * This function is called by the resource classes to create a new
 * resource of the specified class and link it to the given pool.
 * Allocated memory is zeroed. Size of the resource structure is taken
 * from the @size field of the &resclass.
 */
void *
ralloc(pool *p, struct resclass *c)
{
  resource *r = xmalloc(c->size);
  bzero(r, c->size);

  r->class = c;
  if (p)
    add_tail(&p->inside, &r->n);
  return r;
}

#if 0
/**
 * rlookup - look up a memory location
 * @a: memory address
 *
 * This function examines all existing resources to see whether
 * the address @a is inside any resource. It's used for debugging
 * purposes only.
 *
 * It works by calling a class-specific lookup function for each
 * resource.
 */
void
rlookup(unsigned long a)
{
  resource *r;

  debug("Looking up %08lx\n", a);
  if (r = pool_lookup(&root_pool.r, a))
    rdump(r);
  else
    debug("Not found.\n");
}
#endif

/**
 * resource_init - initialize the resource manager
 *
 * This function is called during BIRD startup. It initializes
 * all data structures of the resource manager and creates the
 * root pool.
 */
void
resource_init(void)
{
  resource_sys_init();

  root_pool.r.class = &pool_class;
  root_pool.name = "Root";
  init_list(&root_pool.inside);
  tmp_init(&root_pool);
}

/**
 * DOC: Memory blocks
 *
 * Memory blocks are pieces of contiguous allocated memory.
 * They are a bit non-standard since they are represented not by a pointer
 * to &resource, but by a void pointer to the start of data of the
 * memory block. All memory block functions know how to locate the header
 * given the data pointer.
 *
 * Example: All "unique" data structures such as hash tables are allocated
 * as memory blocks.
 */

struct mblock {
  resource r;
  unsigned size;
  max_align_t data_align[0];
  byte data[0];
};

static void mbl_free(resource *r UNUSED)
{
}

static void mbl_debug(struct dump_request *dreq, resource *r)
{
  struct mblock *m = (struct mblock *) r;

  RDUMP("(size=%d)\n", m->size);
}

static resource *
mbl_lookup(resource *r, unsigned long a)
{
  struct mblock *m = (struct mblock *) r;

  if ((unsigned long) m->data <= a && (unsigned long) m->data + m->size > a)
    return r;
  return NULL;
}

static struct resmem
mbl_memsize(resource *r)
{
  struct mblock *m = (struct mblock *) r;
  return (struct resmem) {
    .effective = m->size,
    .overhead = ALLOC_OVERHEAD + sizeof(struct mblock),
  };
}

static struct resclass mb_class = {
  "Memory",
  0,
  mbl_free,
  mbl_debug,
  mbl_lookup,
  mbl_memsize
};

/**
 * mb_alloc - allocate a memory block
 * @p: pool
 * @size: size of the block
 *
 * mb_alloc() allocates memory of a given size and creates
 * a memory block resource representing this memory chunk
 * in the pool @p.
 *
 * Please note that mb_alloc() returns a pointer to the memory
 * chunk, not to the resource, hence you have to free it using
 * mb_free(), not rfree().
 */
void *
mb_alloc(pool *p, unsigned size)
{
  struct mblock *b = xmalloc(sizeof(struct mblock) + size);

  b->r.class = &mb_class;
  b->r.n = (node) {};
  add_tail(&p->inside, &b->r.n);
  b->size = size;
  return b->data;
}

/**
 * mb_allocz - allocate and clear a memory block
 * @p: pool
 * @size: size of the block
 *
 * mb_allocz() allocates memory of a given size, initializes it to
 * zeroes and creates a memory block resource representing this memory
 * chunk in the pool @p.
 *
 * Please note that mb_allocz() returns a pointer to the memory
 * chunk, not to the resource, hence you have to free it using
 * mb_free(), not rfree().
 */
void *
mb_allocz(pool *p, unsigned size)
{
  void *x = mb_alloc(p, size);
  bzero(x, size);
  return x;
}

/**
 * mb_realloc - reallocate a memory block
 * @m: memory block
 * @size: new size of the block
 *
 * mb_realloc() changes the size of the memory block @m to a given size.
 * The contents will be unchanged to the minimum of the old and new sizes;
 * newly allocated memory will be uninitialized. Contrary to realloc()
 * behavior, @m must be non-NULL, because the resource pool is inherited
 * from it.
 *
 * Like mb_alloc(), mb_realloc() also returns a pointer to the memory
 * chunk, not to the resource, hence you have to free it using
 * mb_free(), not rfree().
 */
void *
mb_realloc(void *m, unsigned size)
{
  struct mblock *b = SKIP_BACK(struct mblock, data, m);

  b = xrealloc(b, sizeof(struct mblock) + size);
  update_node(&b->r.n);
  b->size = size;
  return b->data;
}


/**
 * mb_free - free a memory block
 * @m: memory block
 *
 * mb_free() frees all memory associated with the block @m.
 */
void
mb_free(void *m)
{
  if (!m)
    return;

  struct mblock *b = SKIP_BACK(struct mblock, data, m);
  rfree(b);
}



#define STEP_UP(x) ((x) + (x)/2 + 4)

void
buffer_realloc(void **buf, unsigned *size, unsigned need, unsigned item_size)
{
  unsigned nsize = MIN(*size, need);

  while (nsize < need)
    nsize = STEP_UP(nsize);

  *buf = mb_realloc(*buf, nsize * item_size);
  *size = nsize;
}
