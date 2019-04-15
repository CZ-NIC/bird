/*
 *	Trie index for efficient trie storage
 *
 *	(c) 2019 Maria Matejka <mq@jmq.cz>
 *	(c) 2019 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"

/**
 * Allocate a new trie index from the given pool
 * @p: pool to allocate from
 *
 * Returns the allocated tindex structure.
 */
struct tindex* tindex_new(pool *p);

#define TINDEX_CREATE	(~(0ULL))
#define TINDEX_FIND	0

/**
 * Find an index
 * @ti: the tindex to look into
 * @bits_in: data
 * @blen: number of bits to extract from bits_in.
 *	  If @blen is not multiple of 64, the LSB's of the last u64 are ignored.
 * @create: TINDEX_FIND to find existing, TINDEX_CREATE to create new records,
 *	    every other value is for internal use
 *
 * Return value: 0 for not found; nonzero = the index
 */

u64 tindex_find(struct tindex *ti, const u32 *bits_in, const uint blen, const u64 create);

/**
 * Delete an index.
 * @ti: the tindex to use
 * @idx: the index to delete
 **/

u64 tindex_delete(struct tindex *ti, const u64 idx);

struct tindex_walk_params {
  u64 begin;
  uint blen;
  uint maxlen;
  uint internal:1;
};

/**
 * Walk the trie (prefix order): Get first node, return the walk context.
 * @ti: the index to use
 * @twp: walk parameters
 *
 * Returns the tindex walk context. Run tindex_walk_next() repeatedly to get single items.
 **/

struct tindex_walk *tindex_walk_init(const struct tindex *ti, const struct tindex_walk_params *twp);

/**
 * Finish the trie walk. This must be called to return the allocated structures.
 * @ctx: walk context to free
 **/

void tindex_walk_done(struct tindex_walk *ctx);

/**
 * Get next node.
 */
u64 tindex_walk_next(const struct tindex *ti, struct tindex_walk *ctx);

#define TINDEX_WALK_BEGIN(ti) do { \
  struct tindex_walk *_ti_ctx = tindex_walk_init(ti); \
  for (u64 idx; idx = tindex_walk_next(ti, _ti_ctx); )
#define TINDEX_WALK_END tindex_walk_done(_ti_ctx); } while (0)

/**
 * Dump the index. Useful for debugging.
 */

void tindex_dump(const struct tindex *ti);
