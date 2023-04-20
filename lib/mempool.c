/*
 *	BIRD Resource Manager -- Memory Pools
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Linear memory pools
 *
 * Linear memory pools are collections of memory blocks which
 * support very fast allocation of new blocks, but are able to free only
 * the whole collection at once (or in stack order).
 *
 * Example: Each configuration is described by a complex system of structures,
 * linked lists and function trees which are all allocated from a single linear
 * pool, thus they can be freed at once when the configuration is no longer used.
 */

#include <stdlib.h>
#include <stdint.h>

#include "nest/bird.h"
#include "lib/resource.h"
#include "lib/string.h"

struct lp_chunk {
  struct lp_chunk *next;
  uintptr_t data_align[0];
  byte data[0];
};

#define LP_DATA_SIZE	(page_size - OFFSETOF(struct lp_chunk, data))

struct linpool {
  resource r;
  byte *ptr, *end;
  struct lp_chunk *first, *current;		/* Normal (reusable) chunks */
  struct lp_chunk *first_large;			/* Large chunks */
  uint total, total_large;
};

_Thread_local linpool *tmp_linpool;

static void lp_free(resource *);
static void lp_dump(resource *);
static resource *lp_lookup(resource *, unsigned long);
static struct resmem lp_memsize(resource *r);

static struct resclass lp_class = {
  "LinPool",
  sizeof(struct linpool),
  lp_free,
  lp_dump,
  lp_lookup,
  lp_memsize
};

/**
 * lp_new - create a new linear memory pool
 * @p: pool
 *
 * lp_new() creates a new linear memory pool resource inside the pool @p.
 * The linear pool consists of a list of memory chunks of page size.
 */
linpool
*lp_new(pool *p)
{
  return ralloc(p, &lp_class);
}

/**
 * lp_alloc - allocate memory from a &linpool
 * @m: linear memory pool
 * @size: amount of memory
 *
 * lp_alloc() allocates @size bytes of memory from a &linpool @m
 * and it returns a pointer to the allocated memory.
 *
 * It works by trying to find free space in the last memory chunk
 * associated with the &linpool and creating a new chunk of the standard
 * size (as specified during lp_new()) if the free space is too small
 * to satisfy the allocation. If @size is too large to fit in a standard
 * size chunk, an "overflow" chunk is created for it instead.
 */
void *
lp_alloc(linpool *m, uint size)
{
  byte *a = (byte *) BIRD_ALIGN((unsigned long) m->ptr, CPU_STRUCT_ALIGN);
  byte *e = a + size;

  if (e <= m->end)
    {
      m->ptr = e;
      return a;
    }
  else
    {
      struct lp_chunk *c;
      if (size > LP_DATA_SIZE)
	{
	  /* Too large => allocate large chunk */
	  c = xmalloc(sizeof(struct lp_chunk) + size);
	  m->total_large += size;
	  c->next = m->first_large;
	  m->first_large = c;
	}
      else
	{
	  if (m->current && m->current->next)
	    {
	      /* Still have free chunks from previous incarnation (before lp_flush()) */
	      c = m->current->next;
	    }
	  else
	    {
	      /* Need to allocate a new chunk */
	      c = alloc_page();

	      m->total += LP_DATA_SIZE;
	      c->next = NULL;

	      if (m->current)
		m->current->next = c;
	      else
		m->first = c;
	    }
	  m->current = c;
	  m->ptr = c->data + size;
	  m->end = c->data + LP_DATA_SIZE;
	}
      return c->data;
    }
}

/**
 * lp_allocu - allocate unaligned memory from a &linpool
 * @m: linear memory pool
 * @size: amount of memory
 *
 * lp_allocu() allocates @size bytes of memory from a &linpool @m
 * and it returns a pointer to the allocated memory. It doesn't
 * attempt to align the memory block, giving a very efficient way
 * how to allocate strings without any space overhead.
 */
void *
lp_allocu(linpool *m, uint size)
{
  byte *a = m->ptr;
  byte *e = a + size;

  if (e <= m->end)
    {
      m->ptr = e;
      return a;
    }
  return lp_alloc(m, size);
}

/**
 * lp_allocz - allocate cleared memory from a &linpool
 * @m: linear memory pool
 * @size: amount of memory
 *
 * This function is identical to lp_alloc() except that it
 * clears the allocated memory block.
 */
void *
lp_allocz(linpool *m, uint size)
{
  void *z = lp_alloc(m, size);

  bzero(z, size);
  return z;
}

/**
 * lp_flush - flush a linear memory pool
 * @m: linear memory pool
 *
 * This function frees the whole contents of the given &linpool @m,
 * but leaves the pool itself.
 */
void
lp_flush(linpool *m)
{
  struct lp_chunk *c;

  /* Move ptr to the first chunk and free all other chunks */
  m->current = c = m->first;
  m->ptr = c ? c->data : NULL;
  m->end = c ? c->data + LP_DATA_SIZE : NULL;

  while (c && c->next)
  {
    struct lp_chunk *d = c->next;
    c->next = d->next;
    free_page(d);
  }

  while (c = m->first_large)
    {
      m->first_large = c->next;
      xfree(c);
    }
  m->total_large = 0;
}

/**
 * lp_save - save the state of a linear memory pool
 * @m: linear memory pool
 * @p: state buffer
 *
 * This function saves the state of a linear memory pool. Saved state can be
 * used later to restore the pool (to free memory allocated since).
 */
void
lp_save(linpool *m, lp_state *p)
{
  p->current = m->current;
  p->large = m->first_large;
  p->total_large = m->total_large;
  p->ptr = m->ptr;
}

/**
 * lp_restore - restore the state of a linear memory pool
 * @m: linear memory pool
 * @p: saved state
 *
 * This function restores the state of a linear memory pool, freeing all memory
 * allocated since the state was saved. Note that the function cannot un-free
 * the memory, therefore the function also invalidates other states that were
 * saved between (on the same pool).
 */
void
lp_restore(linpool *m, lp_state *p)
{
  struct lp_chunk *c;

  /* Move ptr to the saved pos and free all newer large chunks */
  m->current = c = p->current ?: m->first;
  m->ptr = p->ptr ?: (c ? c->data : NULL);
  m->end = c ? (c->data + LP_DATA_SIZE) : NULL;
  m->total_large = p->total_large;

  while ((c = m->first_large) && (c != p->large))
    {
      m->first_large = c->next;
      xfree(c);
    }
}

static void
lp_free(resource *r)
{
  linpool *m = (linpool *) r;
  struct lp_chunk *c, *d;

  for(d=m->first; d; d = c)
    {
      c = d->next;
      free_page(d);
    }
  for(d=m->first_large; d; d = c)
    {
      c = d->next;
      xfree(d);
    }
}

static void
lp_dump(resource *r)
{
  linpool *m = (linpool *) r;
  struct lp_chunk *c;
  int cnt, cntl;

  for(cnt=0, c=m->first; c; c=c->next, cnt++)
    ;
  for(cntl=0, c=m->first_large; c; c=c->next, cntl++)
    ;
  debug("(count=%d+%d total=%d+%d)\n",
	cnt,
	cntl,
	m->total,
	m->total_large);
}

static struct resmem
lp_memsize(resource *r)
{
  linpool *m = (linpool *) r;
  struct resmem sz = {
    .overhead = sizeof(struct linpool) + ALLOC_OVERHEAD,
    .effective = m->total_large,
  };

  for (struct lp_chunk *c = m->first_large; c; c = c->next)
    sz.overhead += sizeof(struct lp_chunk) + ALLOC_OVERHEAD;

  uint regular = 0;
  for (struct lp_chunk *c = m->first; c; c = c->next)
    regular++;

  sz.effective += LP_DATA_SIZE * regular;
  sz.overhead += (sizeof(struct lp_chunk) + ALLOC_OVERHEAD) * regular;

  return sz;
}


static resource *
lp_lookup(resource *r, unsigned long a)
{
  linpool *m = (linpool *) r;
  struct lp_chunk *c;

  for(c=m->first; c; c=c->next)
    if ((unsigned long) c->data <= a && (unsigned long) c->data + LP_DATA_SIZE > a)
      return r;
  return NULL;
}
