/*
 *	BIRD Resource Manager
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
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
#include "lib/io-loop.h"

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

struct pool_pages {
  uint free;
  uint used;
  void *ptr[0];
};

#define POOL_PAGES_MAX	((page_size - sizeof(struct pool_pages)) / sizeof (void *))

static void pool_dump(resource *);
static void pool_free(resource *);
static resource *pool_lookup(resource *, unsigned long);
static size_t pool_memsize(resource *P);

static struct resclass pool_class = {
  "Pool",
  sizeof(pool),
  pool_free,
  pool_dump,
  pool_lookup,
  pool_memsize
};

pool root_pool;

void *alloc_sys_page(void);
int free_sys_page(void *);

static int indent;

/**
 * rp_new - create a resource pool
 * @p: parent pool
 * @l: loop to assign
 * @name: pool name (to be included in debugging dumps)
 *
 * rp_new() creates a new resource pool inside the specified
 * parent pool.
 */
pool *
rp_new(pool *p, struct birdloop *loop, const char *name)
{
  ASSERT_DIE(birdloop_inside(p->loop));
  ASSERT_DIE(birdloop_inside(loop));

  pool *z = ralloc(p, &pool_class);
  z->loop = loop;
  z->name = name;
  init_list(&z->inside);
  return z;
}

_Thread_local static pool *pool_parent = NULL;

static void
pool_free(resource *P)
{
  ASSERT_DIE(pool_parent);

  pool *p = (pool *) P;
  ASSERT_DIE(birdloop_inside(p->loop));

  pool *parent = pool_parent;
  pool_parent = p;

  resource *r, *rr;
  r = HEAD(p->inside);
  while (rr = (resource *) r->n.next)
    {
      r->class->free(r);
      xfree(r);
      r = rr;
    }

  if (p->pages)
    {
      ASSERT_DIE(!p->pages->used);

      for (uint i = 0; i < p->pages->free; i++)
	free_sys_page(p->pages->ptr[i]);

      free_sys_page(p->pages);
    }

  pool_parent = parent;
}

void
rp_free(pool *p, pool *parent)
{
  ASSERT_DIE(pool_parent == NULL);
  pool_parent = parent;
  rfree(p);
  ASSERT_DIE(pool_parent == parent);
  pool_parent = NULL;
}

static void
pool_dump_locked(pool *p)
{
  resource *r;
  
  debug("%s\n", p->name);
  indent += 3;
  WALK_LIST(r, p->inside)
    rdump(r);
  indent -= 3;
}

static void
pool_dump(resource *P)
{
  pool *p = (pool *) P;

  if (p->loop != pool_parent->loop)
    birdloop_enter(p->loop);

  pool *parent = pool_parent;
  pool_parent = p;

  pool_dump_locked(p);

  pool_parent = parent;

  if (p->loop != pool_parent->loop)
    birdloop_leave(p->loop);
}

void
rp_dump(pool *p)
{
  int inside = birdloop_inside(p->loop);
  if (!inside)
    birdloop_enter(p->loop);

  ASSERT_DIE(pool_parent == NULL);
  pool_parent = p;

  pool_dump_locked(p);

  ASSERT_DIE(pool_parent == p);
  pool_parent = NULL;

  if (!inside)
    birdloop_leave(p->loop);
}

static size_t
pool_memsize_locked(pool *p)
{
  resource *r;
  size_t sum = sizeof(pool) + ALLOC_OVERHEAD;

  WALK_LIST(r, p->inside)
    sum += rmemsize(r);

  if (p->pages)
    sum += page_size * (p->pages->used + p->pages->free + 1);

  return sum;
}

static size_t
pool_memsize(resource *P)
{
  pool *p = (pool *) P;

  pool *parent = pool_parent;
  pool_parent = p;

  if (p->loop != parent->loop)
    birdloop_enter(p->loop);

  size_t sum = pool_memsize_locked(p);

  if (p->loop != parent->loop)
    birdloop_leave(p->loop);

  pool_parent = parent;

  return sum;
}

size_t
rp_memsize(pool *p)
{
  int inside = birdloop_inside(p->loop);
  if (!inside)
    birdloop_enter(p->loop);

  ASSERT_DIE(pool_parent == NULL);
  pool_parent = p;
  size_t sum = pool_memsize_locked(p);
  ASSERT_DIE(pool_parent == p);
  pool_parent = NULL;

  if (!inside)
    birdloop_leave(p->loop);

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
rdump(void *res)
{
  char x[16];
  resource *r = res;

  bsprintf(x, "%%%ds%%p ", indent);
  debug(x, "", r);
  if (r)
    {
      debug("%s ", r->class->name);
      r->class->dump(r);
    }
  else
    debug("NULL\n");
}

size_t
rmemsize(void *res)
{
  resource *r = res;
  if (!r)
    return 0;
  if (!r->class->memsize)
    return r->class->size + ALLOC_OVERHEAD;
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
  ASSERT_DIE(p);
  ASSERT_DIE(birdloop_inside(p->loop));

  resource *r = xmalloc(c->size);
  bzero(r, c->size);

  r->class = c;
  add_tail(&p->inside, &r->n);

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
    rdump(r);
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

  root_pool.r.class = &pool_class;
  root_pool.name = "Root";
  init_list(&root_pool.inside);
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

static void mbl_debug(resource *r)
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

static size_t
mbl_memsize(resource *r)
{
  struct mblock *m = (struct mblock *) r;
  return ALLOC_OVERHEAD + sizeof(struct mblock) + m->size;
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
 * mb_move - move a memory block
 * @m: memory block
 * @p: target pool
 *
 * mb_move() moves the given memory block to another pool in the same way
 * as rmove() moves a plain resource.
 */
void
mb_move(void *m, pool *p)
{
  struct mblock *b = SKIP_BACK(struct mblock, data, m);
  rmove(b, p);
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

void *
alloc_page(pool *p)
{
  if (!p->pages)
  {
    p->pages = alloc_sys_page();
    p->pages->free = 0;
    p->pages->used = 1;
  }
  else
    p->pages->used++;

  if (p->pages->free)
  {
    void *ptr = p->pages->ptr[--p->pages->free];
    bzero(ptr, page_size);
    return ptr;
  }
  else
    return alloc_sys_page();
}

void
free_page(pool *p, void *ptr)
{
  ASSERT_DIE(p->pages);
  p->pages->used--;

  ASSERT_DIE(p->pages->free <= POOL_PAGES_MAX);

  if (p->pages->free == POOL_PAGES_MAX)
  {
    const unsigned long keep = POOL_PAGES_MAX / 4;

    for (uint i = keep; i < p->pages->free; i++)
      free_sys_page(p->pages->ptr[i]);

    p->pages->free = keep;
  }

  p->pages->ptr[p->pages->free++] = ptr;
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
