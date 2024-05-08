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
#include "lib/rcu.h"

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

static void pool_dump(resource *, unsigned);
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

static void
rp_init(pool *z, struct domain_generic *dom, const char *name)
{
  ASSERT_DIE(DG_IS_LOCKED(dom));

  if (name && !domain_name(dom))
    domain_setup(dom, name, z);

  z->name = name;
  z->domain = dom;
  z->inside = (TLIST_LIST(resource)) {};
}

/**
 * rp_new - create a resource pool
 * @p: parent pool
 * @name: pool name (to be included in debugging dumps)
 *
 * rp_new() creates a new resource pool inside the specified
 * parent pool.
 */
pool *
rp_new(pool *p, struct domain_generic *dom, const char *name)
{
  pool *z = ralloc(p, &pool_class);

  if (dg_order(p->domain) > dg_order(dom))
    bug("Requested reverse order pool creation: %s (%s, order %d) can't be a parent of %s (%s, order %d)",
	p->name, domain_name(p->domain), dg_order(p->domain),
	name, domain_name(dom), dg_order(dom));

  if ((dg_order(p->domain) == dg_order(dom)) && (p->domain != dom))
    bug("Requested incomparable order pool creation: %s (%s, order %d) can't be a parent of %s (%s, order %d)",
	p->name, domain_name(p->domain), dg_order(p->domain),
	name, domain_name(dom), dg_order(dom));

  rp_init(z, dom, name);
  return z;
}

pool *
rp_vnewf(pool *p, struct domain_generic *dom, const char *fmt, va_list args)
{
  pool *z = rp_new(p, dom, NULL);
  z->name = mb_vsprintf(z, fmt, args);
  if (!domain_name(dom))
    domain_setup(dom, z->name, z);
  return z;
}

pool *
rp_newf(pool *p, struct domain_generic *dom, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  pool *z = rp_vnewf(p, dom, fmt, args);
  va_end(args);

  return z;
}

#define POOL_LOCK				\
  struct domain_generic *dom = p->domain;	\
  int locking = !DG_IS_LOCKED(dom);		\
  if (locking)					\
    DG_LOCK(dom);				\

#define POOL_UNLOCK if (locking) DG_UNLOCK(dom);\

void rp_free(pool *p)
{
  ASSERT_DIE(DG_IS_LOCKED(p->domain));
  rfree(p);
}

static void
pool_free(resource *P)
{
  pool *p = (pool *) P;

  POOL_LOCK;
  WALK_TLIST_DELSAFE(resource, r, &p->inside)
    {
      r->class->free(r);
      xfree(r);
    }
  POOL_UNLOCK;
}


static void
pool_dump(resource *P, unsigned indent)
{
  pool *p = (pool *) P;

  POOL_LOCK;

  debug("%s\n", p->name);
  WALK_TLIST_DELSAFE(resource, r, &p->inside)
    rdump(r, indent + 3);

  POOL_UNLOCK;
}

static struct resmem
pool_memsize(resource *P)
{
  pool *p = (pool *) P;
  struct resmem sum = {
    .effective = 0,
    .overhead = sizeof(pool) + ALLOC_OVERHEAD,
  };

  POOL_LOCK;

  WALK_TLIST(resource, r, &p->inside)
  {
    struct resmem add = rmemsize(r);
    sum.effective += add.effective;
    sum.overhead += add.overhead;
  }

  POOL_UNLOCK;

  return sum;
}

static resource *
pool_lookup(resource *P, unsigned long a)
{
  pool *p = (pool *) P;
  resource *q = NULL;

  POOL_LOCK;

  WALK_TLIST(resource, r, &p->inside)
    if (r->class->lookup && (q = r->class->lookup(r, a)))
      break;

  POOL_UNLOCK;
  return q;
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
  pool *orig = resource_parent(r);

  ASSERT_DIE(DG_IS_LOCKED(orig->domain));
  ASSERT_DIE(DG_IS_LOCKED(p->domain));

  resource_rem_node(&orig->inside, r);
  resource_add_tail(&p->inside, r);
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

  pool *orig = resource_parent(r);
  ASSERT_DIE(DG_IS_LOCKED(orig->domain));
  resource_rem_node(&orig->inside, r);

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
rdump(void *res, unsigned indent)
{
  char x[16];
  resource *r = res;

  bsprintf(x, "%%%ds%%p ", indent);
  debug(x, "", r);
  if (r)
    {
      debug("%s ", r->class->name);
      r->class->dump(r, indent);
    }
  else
    debug("NULL\n");
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
  ASSERT_DIE(DG_IS_LOCKED(p->domain));

  resource *r = xmalloc(c->size);
  bzero(r, c->size);

  r->class = c;
  resource_add_tail(&p->inside, r);

  return r;
}

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
    rdump(r, 3);
  else
    debug("Not found.\n");
}

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
  rcu_init();
  resource_sys_init();

  root_pool.r.class = &pool_class;
  rp_init(&root_pool, the_bird_domain.the_bird, "Root");
  tmp_init(&root_pool);
}

_Thread_local linpool *tmp_linpool;

void
tmp_init(pool *p)
{
  ASSERT_DIE(!tmp_linpool);
  tmp_linpool = lp_new_default(p);
}

void
tmp_flush(void)
{
  lp_flush(tmp_linpool);
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
  uintptr_t data_align[0];
  byte data[0];
};

static void mbl_free(resource *r UNUSED)
{
}

static void mbl_debug(resource *r, unsigned indent UNUSED)
{
  struct mblock *m = (struct mblock *) r;

  debug("(size=%d)\n", m->size);
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
  ASSERT_DIE(DG_IS_LOCKED(p->domain));

  struct mblock *b = xmalloc(sizeof(struct mblock) + size);

  b->r.class = &mb_class;
  b->r.n = (struct resource_node) {};
  resource_add_tail(&p->inside, &b->r);
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
  SKIP_BACK_DECLARE(struct mblock, b, data, m);
  struct pool *p = resource_parent(&b->r);

  ASSERT_DIE(DG_IS_LOCKED(p->domain));

  b = xrealloc(b, sizeof(struct mblock) + size);
  b->size = size;

  resource_update_node(&p->inside, &b->r);
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

  SKIP_BACK_DECLARE(struct mblock, b, data, m);
  rfree(&b->r);
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
