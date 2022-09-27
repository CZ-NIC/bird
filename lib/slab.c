/*
 *	BIRD Resource Manager -- A SLAB-like Memory Allocator
 *
 *	Heavily inspired by the original SLAB paper by Jeff Bonwick.
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2020       Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Slabs
 *
 * Slabs are collections of memory blocks of a fixed size.
 * They support very fast allocation and freeing of such blocks, prevent memory
 * fragmentation and optimize L2 cache usage. Slabs have been invented by Jeff Bonwick
 * and published in USENIX proceedings as `The Slab Allocator: An Object-Caching Kernel
 * Memory Allocator'. Our implementation follows this article except that we don't use
 * constructors and destructors.
 *
 * When the |DEBUGGING| switch is turned on, we automatically fill all
 * newly allocated and freed blocks with a special pattern to make detection
 * of use of uninitialized or already freed memory easier.
 *
 * Example: Nodes of a FIB are allocated from a per-FIB Slab.
 */

#include <stdlib.h>
#include <stdint.h>

#include "nest/bird.h"
#include "lib/resource.h"
#include "lib/string.h"
#include "lib/tlists.h"

#undef FAKE_SLAB	/* Turn on if you want to debug memory allocations */

#ifdef DEBUGGING
#define POISON		/* Poison all regions after they are freed */
#endif

static void slab_free(resource *r);
static void slab_dump(resource *r);
static resource *slab_lookup(resource *r, unsigned long addr);
static struct resmem slab_memsize(resource *r);

#ifdef FAKE_SLAB

/*
 *  Fake version used for debugging.
 */

struct slab {
  resource r;
  uint size;
  list objs;
};

static struct resclass sl_class = {
  "FakeSlab",
  sizeof(struct slab),
  slab_free,
  slab_dump,
  NULL,
  slab_memsize
};

struct sl_obj {
  node n;
  uintptr_t data_align[0];
  byte data[0];
};

slab *
sl_new(pool *p, uint size)
{
  slab *s = ralloc(p, &sl_class);
  s->size = size;
  init_list(&s->objs);
  return s;
}

void *
sl_alloc(slab *s)
{
  struct sl_obj *o = xmalloc(sizeof(struct sl_obj) + s->size);

  add_tail(&s->objs, &o->n);
  return o->data;
}

void *
sl_allocz(slab *s)
{
  void *obj = sl_alloc(s);
  memset(obj, 0, s->size);
  return obj;
}

void
sl_free(void *oo)
{
  struct sl_obj *o = SKIP_BACK(struct sl_obj, data, oo);

  rem_node(&o->n);
  xfree(o);
}

static void
slab_free(resource *r)
{
  slab *s = (slab *) r;
  struct sl_obj *o, *p;

  for(o = HEAD(s->objs); p = (struct sl_obj *) o->n.next; o = p)
    xfree(o);
}

static void
slab_dump(resource *r)
{
  slab *s = (slab *) r;
  int cnt = 0;
  struct sl_obj *o;

  WALK_LIST(o, s->objs)
    cnt++;
  debug("(%d objects per %d bytes)\n", cnt, s->size);
}

static struct resmem
slab_memsize(resource *r)
{
  slab *s = (slab *) r;
  size_t cnt = 0;
  struct sl_obj *o;

  WALK_LIST(o, s->objs)
    cnt++;

  return (struct resmem) {
    .effective = cnt * s->size,
    .overhead = ALLOC_OVERHEAD + sizeof(struct slab) + cnt * ALLOC_OVERHEAD,
  };
}


#else

/*
 *  Real efficient version.
 */

#define MAX_EMPTY_HEADS 1

enum sl_head_state {
  slh_empty = 2,
  slh_partial = 0,
  slh_full = 1,
} PACKED;

struct sl_head {
  struct slab *slab;
  TLIST_NODE(sl_head, struct sl_head) n;
  u16 num_full;
  enum sl_head_state state;
  u32 used_bits[0];
};

struct sl_alignment {			/* Magic structure for testing of alignment */
  byte data;
  int x[0];
};

#define TLIST_PREFIX sl_head
#define TLIST_TYPE   struct sl_head
#define TLIST_ITEM   n
#define TLIST_WANT_WALK
#define TLIST_WANT_ADD_HEAD

#include "lib/tlists.h"

struct slab {
  resource r;
  uint obj_size, head_size, head_bitfield_len;
  uint objs_per_slab, num_empty_heads, data_size;
  struct sl_head_list empty_heads, partial_heads, full_heads;
};

static struct resclass sl_class = {
  "Slab",
  sizeof(struct slab),
  slab_free,
  slab_dump,
  slab_lookup,
  slab_memsize
};

#define SL_GET_HEAD(x)	((struct sl_head *) (((uintptr_t) (x)) & ~(page_size-1)))

#define SL_HEAD_CHANGE_STATE(_s, _h, _from, _to) ({ \
    ASSERT_DIE(_h->state == slh_##_from); \
    sl_head_rem_node(&_s->_from##_heads, _h); \
    sl_head_add_head(&_s->_to##_heads, _h); \
    _h->state = slh_##_to; \
    })


/**
 * sl_new - create a new Slab
 * @p: resource pool
 * @size: block size
 *
 * This function creates a new Slab resource from which
 * objects of size @size can be allocated.
 */
slab *
sl_new(pool *p, uint size)
{
  slab *s = ralloc(p, &sl_class);
  uint align = sizeof(struct sl_alignment);
  if (align < sizeof(void *))
    align = sizeof(void *);
  s->data_size = size;
  size = (size + align - 1) / align * align;
  s->obj_size = size;

  s->head_size = sizeof(struct sl_head);

  do {
    s->objs_per_slab = (page_size - s->head_size) / size;
    s->head_bitfield_len = (s->objs_per_slab + 31) / 32;
    s->head_size = (
	sizeof(struct sl_head)
      + sizeof(u32) * s->head_bitfield_len
      + align - 1)
    / align * align;
  } while (s->objs_per_slab * size + s->head_size > page_size);

  if (!s->objs_per_slab)
    bug("Slab: object too large");
  s->num_empty_heads = 0;

  return s;
}

/**
 * sl_alloc - allocate an object from Slab
 * @s: slab
 *
 * sl_alloc() allocates space for a single object from the
 * Slab and returns a pointer to the object.
 */
void *
sl_alloc(slab *s)
{
  struct sl_head *h;

redo:
  if (!(h = s->partial_heads.first))
    goto no_partial;
okay:
  for (uint i=0; i<s->head_bitfield_len; i++)
    if (~h->used_bits[i])
    {
      uint pos = u32_ctz(~h->used_bits[i]);
      if (i * 32 + pos >= s->objs_per_slab)
	break;

      h->used_bits[i] |= 1 << pos;
      h->num_full++;

      void *out = ((void *) h) + s->head_size + (i * 32 + pos) * s->obj_size;
#ifdef POISON
      memset(out, 0xcd, s->data_size);
#endif
      return out;
    }

  SL_HEAD_CHANGE_STATE(s, h, partial, full);
  goto redo;

no_partial:
  if (h = s->empty_heads.first)
    {
      SL_HEAD_CHANGE_STATE(s, h, empty, partial);
      s->num_empty_heads--;
      goto okay;
    }

  h = alloc_page();
  ASSERT_DIE(SL_GET_HEAD(h) == h);

#ifdef POISON
  memset(h, 0xba, page_size);
#endif

  memset(h, 0, s->head_size);
  h->slab = s;
  sl_head_add_head(&s->partial_heads, h);
  goto okay;
}

/**
 * sl_allocz - allocate an object from Slab and zero it
 * @s: slab
 *
 * sl_allocz() allocates space for a single object from the
 * Slab and returns a pointer to the object after zeroing out
 * the object memory.
 */
void *
sl_allocz(slab *s)
{
  void *obj = sl_alloc(s);
  memset(obj, 0, s->data_size);
  return obj;
}

/**
 * sl_free - return a free object back to a Slab
 * @s: slab
 * @oo: object returned by sl_alloc()
 *
 * This function frees memory associated with the object @oo
 * and returns it back to the Slab @s.
 */
void
sl_free(void *oo)
{
  struct sl_head *h = SL_GET_HEAD(oo);
  struct slab *s = h->slab;

#ifdef POISON
  memset(oo, 0xdb, s->data_size);
#endif

  uint offset = oo - ((void *) h) - s->head_size;
  ASSERT_DIE(offset % s->obj_size == 0);
  uint pos = offset / s->obj_size;
  ASSERT_DIE(pos < s->objs_per_slab);

  h->used_bits[pos / 32] &= ~(1 << (pos % 32));

  if ((h->num_full-- == s->objs_per_slab) && (h->state == slh_full))
    SL_HEAD_CHANGE_STATE(s, h, full, partial);
  else if (!h->num_full)
    {
      sl_head_rem_node(&s->partial_heads, h);
      if (s->num_empty_heads >= MAX_EMPTY_HEADS)
      {
#ifdef POISON
	memset(h, 0xde, page_size);
#endif
	free_page(h);
      }
      else
	{
	  sl_head_add_head(&s->empty_heads, h);
	  h->state = slh_empty;
	  s->num_empty_heads++;
	}
    }
}

static void
slab_free(resource *r)
{
  slab *s = (slab *) r;

  WALK_TLIST_DELSAFE(sl_head, h, &s->empty_heads)
    free_page(h);
  WALK_TLIST_DELSAFE(sl_head, h, &s->partial_heads)
    free_page(h);
  WALK_TLIST_DELSAFE(sl_head, h, &s->full_heads)
    free_page(h);
}

static void
slab_dump(resource *r)
{
  slab *s = (slab *) r;
  int ec=0, pc=0, fc=0;

  WALK_TLIST(sl_head, h, &s->empty_heads)
    ec++;
  WALK_TLIST(sl_head, h, &s->partial_heads)
    pc++;
  WALK_TLIST(sl_head, h, &s->full_heads)
    fc++;
  debug("(%de+%dp+%df blocks per %d objs per %d bytes)\n", ec, pc, fc, s->objs_per_slab, s->obj_size);
}

static struct resmem
slab_memsize(resource *r)
{
  slab *s = (slab *) r;
  size_t heads = 0;

  WALK_TLIST(sl_head, h, &s->full_heads)
    heads++;

  size_t items = heads * s->objs_per_slab;

  WALK_TLIST(sl_head, h, &s->partial_heads)
  {
    heads++;
    items += h->num_full;
  }

  WALK_TLIST(sl_head, h, &s->empty_heads)
    heads++;

  size_t eff = items * s->data_size;

  return (struct resmem) {
    .effective = eff,
    .overhead = ALLOC_OVERHEAD + sizeof(struct slab) + heads * page_size - eff,
  };
}

static resource *
slab_lookup(resource *r, unsigned long a)
{
  slab *s = (slab *) r;

  WALK_TLIST(sl_head, h, &s->partial_heads)
    if ((unsigned long) h < a && (unsigned long) h + page_size < a)
      return r;
  WALK_TLIST(sl_head, h, &s->full_heads)
    if ((unsigned long) h < a && (unsigned long) h + page_size < a)
      return r;
  return NULL;
}

#endif
