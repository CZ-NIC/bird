/*
 *	BIRD Library -- Bitmaps
 *
 *	(c) 2019 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2019 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>

#include "nest/bird.h"
#include "lib/bitmap.h"
#include "lib/bitops.h"
#include "lib/resource.h"


/*
 *	Basic bitmap
 */

void
bmap_init(struct bmap *b, pool *p, uint size)
{
  b->size = BIRD_ALIGN(size, 4);
  b->data = mb_allocz(p, b->size);
}

void
bmap_reset(struct bmap *b, uint size)
{
  b->size = BIRD_ALIGN(size, 4);
  memset(b->data, 0, b->size);
}

void
bmap_grow(struct bmap *b, uint need)
{
  uint size = b->size * 2;
  while (size < need)
    size *= 2;

  uint old_size = b->size;
  b->size = size;
  b->data = mb_realloc(b->data, b->size);

  ASSERT(size >= old_size);
  memset(b->data + (old_size / 4), 0, size - old_size);
}

void
bmap_free(struct bmap *b)
{
  mb_free(b->data);
  b->size = 0;
  b->data = NULL;
}



/*
 *	Hierarchical bitmap
 */

#define B256_SIZE(b)  BIRD_ALIGN(b, 32)
#define B256_STEP(b) (BIRD_ALIGN(b, 8192) >> 8)

void
hmap_init(struct hmap *b, pool *p, uint size)
{
  b->size[0] = B256_SIZE(size);
  b->size[1] = B256_STEP(b->size[0]);
  b->size[2] = B256_STEP(b->size[1]);
  b->size[3] = sizeof(b->root);

  b->data[0] = mb_allocz(p, b->size[0]);
  b->data[1] = mb_allocz(p, b->size[1]);
  b->data[2] = mb_allocz(p, b->size[2]);
  b->data[3] = b->root;

  memset(b->root, 0, sizeof(b->root));
}

static void
hmap_grow(struct hmap *b, uint need)
{
  uint size = b->size[0] * 2;
  while (size < need)
    size *= 2;

  for (uint i = 0; i < 3; i++)
  {
    uint old_size = b->size[i];
    b->size[i] = size;
    b->data[i] = mb_realloc(b->data[i], b->size[i]);

    ASSERT(size >= old_size);
    memset(b->data[i] + (old_size / 4), 0, size - old_size);

    size = B256_STEP(size);
  }
}

void
hmap_free(struct hmap *b)
{
  mb_free(b->data[0]);
  mb_free(b->data[1]);
  mb_free(b->data[2]);

  memset(b, 0, sizeof(struct hmap));
}

static inline int
b256_and(u32 *p)
{
  for (int i = 0; i < 8; i++)
    if (~p[i])
      return 0;

  return 1;
}

void
hmap_set(struct hmap *b, uint n)
{
  if (n >= hmap_max(b))
    hmap_grow(b, n/8 + 1);

  for (int i = 0; i < 4; i++)
  {
    BIT32_SET(b->data[i], n);
    n = n >> 8;

    /* Continue if all bits in 256-bit block are set */
    if (! b256_and(b->data[i] + 8*n))
      break;
  }
}

void
hmap_clear(struct hmap *b, uint n)
{
  if (n >= hmap_max(b))
    return;

  for (int i = 0; i < 4; i++)
  {
    BIT32_CLR(b->data[i], n);
    n = n >> 8;
  }
}

static inline int
b256_first_zero(u32 *p)
{
  for (int i = 0; i < 8; i++)
    if (~p[i])
      return 32*i + u32_ctz(~p[i]);

  return 256;
}

u32
hmap_first_zero(struct hmap *b)
{
  u32 n = 0;

  for (int i = 3; i >= 0; i--)
  {
    if (32*n >= b->size[i])
      return hmap_max(b);

    u32 *p = b->data[i] + 8*n;

    n = (n << 8) + b256_first_zero(p);
  }

  return n;
}

void
hmap_check(struct hmap *b)
{
  for (int i = 0; i < 2; i++)
  {
    int max = b->size[i] / 32;

    for (int j = 0; j < max; j++)
    {
      int x = b256_and(b->data[i] + 8*j);
      int y = !!BIT32_TEST(b->data[i+1], j);
      if (x != y)
	bug("Inconsistent data on %d:%d (%d vs %d)", i, j, x, y);
    }
  }
}


/*
 *	Indirect bitmap for MPLS labels (20 bit range)
 */

void
lmap_init(struct lmap *b, pool *p)
{
  b->slab = sl_new(p, 128);
  b->size = 8;
  b->data = mb_allocz(p, b->size * sizeof(u32 *));
  b->root = sl_allocz(b->slab);
}

static void
lmap_grow(struct lmap *b, uint need)
{
  uint old_size = b->size;

  while (b->size < need)
    b->size *= 2;

  b->data = mb_realloc(b->data, b->size * sizeof(u32 *));

  memset(b->data + old_size, 0, (b->size - old_size) * sizeof(u32 *));
}

void
lmap_free(struct lmap *b)
{
  rfree(b->slab);
  mb_free(b->data);
  memset(b, 0, sizeof(struct lmap));
}

static inline int
b1024_and(u32 *p)
{
  for (int i = 0; i < 32; i++)
    if (~p[i])
      return 0;

  return 1;
}

static inline int
b1024_or(u32 *p)
{
  for (int i = 0; i < 32; i++)
    if (p[i])
      return 1;

  return 0;
}

int
lmap_test(struct lmap *b, uint n)
{
  uint n0 = n >> 10;
  uint n1 = n & 0x3ff;

  return (n0 < b->size) && b->data[n0] && BIT32_TEST(b->data[n0], n1);
}

void
lmap_set(struct lmap *b, uint n)
{
  uint n0 = n >> 10;
  uint n1 = n & 0x3ff;

  if (n0 >= b->size)
    lmap_grow(b, n0 + 1);

  if (! b->data[n0])
    b->data[n0] = sl_allocz(b->slab);

  BIT32_SET(b->data[n0], n1);

  if (b1024_and(b->data[n0]))
    BIT32_SET(b->root, n0);
}

void
lmap_clear(struct lmap *b, uint n)
{
  uint n0 = n >> 10;
  uint n1 = n & 0x3ff;

  if (n0 >= b->size)
    return;

  if (! b->data[n0])
    return;

  BIT32_CLR(b->data[n0], n1);
  BIT32_CLR(b->root, n0);

  if (!b1024_or(b->data[n0]))
  {
    sl_free(b->data[n0]);
    b->data[n0] = NULL;
  }
}

static inline int
b1024_first_zero(u32 *p)
{
  for (int i = 0; i < 32; i++)
    if (~p[i])
      return 32*i + u32_ctz(~p[i]);

  return 1024;
}

uint
lmap_first_zero(struct lmap *b)
{
  uint n0 = b1024_first_zero(b->root);
  uint n1 = ((n0 < b->size) && b->data[n0]) ?
    b1024_first_zero(b->data[n0]) : 0;

  return (n0 << 10) + n1;
}

static uint
b1024_first_zero_in_range(u32 *p, uint lo, uint hi)
{
  uint lo0 = lo >> 5;
  uint lo1 = lo & 0x1f;
  uint hi0 = hi >> 5;
  uint hi1 = hi & 0x1f;
  u32 mask = (1 << lo1) - 1;
  u32 val;

  for (uint i = lo0; i < hi0; i++)
  {
    val = p[i] | mask;
    mask = 0;

    if (~val)
      return 32*i + u32_ctz(~val);
  }

  if (hi1)
  {
    mask |= ~((1u << hi1) - 1);
    val = p[hi0] | mask;

    if (~val)
      return 32*hi0 + u32_ctz(~val);
  }

  return hi;
}

uint
lmap_first_zero_in_range(struct lmap *b, uint lo, uint hi)
{
  uint lo0 = lo >> 10;
  uint lo1 = lo & 0x3ff;
  uint hi0 = hi >> 10;
  uint hi1 = hi & 0x3ff;

  if (lo1)
  {
    uint max = (lo0 == hi0) ? hi1 : 1024;
    uint n0 = lo0;
    uint n1 = ((n0 < b->size) && b->data[n0]) ?
      b1024_first_zero_in_range(b->data[n0], lo1, max) : lo1;

    if (n1 < 1024)
      return (n0 << 10) + n1;

    lo0++;
    lo1 = 0;
  }

  if (lo0 < hi0)
  {
    uint n0 = b1024_first_zero_in_range(b->root, lo0, hi0);

    if (n0 < hi0)
    {
      uint n1 = ((n0 < b->size) && b->data[n0]) ?
	b1024_first_zero(b->data[n0]) : 0;

      return (n0 << 10) + n1;
    }
  }

  if (hi1)
  {
    uint n0 = hi0;
    uint n1 = ((n0 < b->size) && b->data[n0]) ?
      b1024_first_zero_in_range(b->data[n0], 0, hi1) : 0;

    return (n0 << 10) + n1;
  }

  return hi;
}

static inline int
b1024_last_one(u32 *p)
{
  for (int i = 31; i >= 0; i--)
    if (p[i])
      return 32*i + (31 - u32_clz(p[i]));

  return 1024;
}

static uint
b1024_last_one_in_range(u32 *p, uint lo, uint hi)
{
  uint lo0 = lo >> 5;
  uint lo1 = lo & 0x1f;
  uint hi0 = hi >> 5;
  uint hi1 = hi & 0x1f;
  u32 mask = (1u << hi1) - 1;
  u32 val;

  for (int i = hi0; i > (int) lo0; i--)
  {
    val = p[i] & mask;
    mask = ~0;

    if (val)
      return 32*i + (31 - u32_clz(val));
  }

  {
    mask &= ~((1u << lo1) - 1);
    val = p[lo0] & mask;

    if (val)
      return 32*lo0 + (31 - u32_clz(val));
  }

  return hi;
}

uint
lmap_last_one_in_range(struct lmap *b, uint lo, uint hi)
{
  uint lo0 = lo >> 10;
  uint lo1 = lo & 0x3ff;
  uint hi0 = hi >> 10;
  uint hi1 = hi & 0x3ff;

  if (hi1 && (hi0 < b->size) && b->data[hi0])
  {
    uint min = (lo0 == hi0) ? lo1 : 0;
    uint n0 = hi0;
    uint n1 = b1024_last_one_in_range(b->data[n0], min, hi1);

    if (n1 < hi1)
      return (n0 << 10) + n1;
  }

  for (int i = (int)MIN(hi0, b->size) - 1; i >= (int) lo0; i--)
  {
    if (! b->data[i])
      continue;

    uint n0 = i;
    uint n1 = b1024_last_one(b->data[n0]);

    if ((n0 == lo0) && (n1 < lo1))
      return hi;

    return (n0 << 10) + n1;
  }

  return hi;
}

void
lmap_check(struct lmap *b)
{
  for (int i = 0; i < (int) b->size; i++)
  {
    int x = b->data[i] && b1024_and(b->data[i]);
    int y = !!BIT32_TEST(b->root, i);
    if (x != y)
      bug("Inconsistent data on %d (%d vs %d)", i, x, y);
  }
}
