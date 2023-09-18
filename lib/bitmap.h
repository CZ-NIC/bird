/*
 *	BIRD Library -- Bitmaps
 *
 *	(c) 2019 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2019 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_BITMAP_H_
#define _BIRD_BITMAP_H_

struct bmap
{
  u32 size;
  u32 *data;
};

void bmap_init(struct bmap *b, pool *p, uint size);
void bmap_reset(struct bmap *b, uint size);
void bmap_grow(struct bmap *b, uint need);
void bmap_free(struct bmap *b);

static inline uint bmap_max(struct bmap *b)
{ return 8 * b->size; }

static inline int bmap_test(struct bmap *b, uint n)
{ return (n < bmap_max(b)) && BIT32_TEST(b->data, n); }

static inline void bmap_set(struct bmap *b, uint n)
{
  if (n >= bmap_max(b)) bmap_grow(b, n/8 + 1);
  BIT32_SET(b->data, n);
}

static inline void bmap_clear(struct bmap *b, uint n)
{
  if (n >= bmap_max(b)) return;
  BIT32_CLR(b->data, n);
}


struct hmap
{
  u32 size[4];
  u32 *data[4];
  u32 root[8];
};

static inline uint hmap_max(struct hmap *b)
{ return 8 * b->size[0]; }

static inline int hmap_test(struct hmap *b, uint n)
{ return (n < hmap_max(b)) && BIT32_TEST(b->data[0], n); }

void hmap_init(struct hmap *b, pool *p, uint size);
void hmap_free(struct hmap *b);
void hmap_set(struct hmap *b, uint n);
void hmap_clear(struct hmap *b, uint n);
u32 hmap_first_zero(struct hmap *b);
void hmap_check(struct hmap *b);


struct lmap
{
  slab *slab;
  uint size;
  u32 **data;
  u32 *root;
};

static inline uint lmap_max(struct lmap *b)
{ return b->size << 10; }

void lmap_init(struct lmap *b, pool *p);
void lmap_free(struct lmap *b);
int lmap_test(struct lmap *b, uint n);
void lmap_set(struct lmap *b, uint n);
void lmap_clear(struct lmap *b, uint n);
uint lmap_first_zero(struct lmap *b);
uint lmap_first_zero_in_range(struct lmap *b, uint lo, uint hi);
uint lmap_last_one_in_range(struct lmap *b, uint lo, uint hi);
void lmap_check(struct lmap *b);

#endif
