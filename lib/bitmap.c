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
