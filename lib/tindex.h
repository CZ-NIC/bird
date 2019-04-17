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
 * Get the whole path to the indexed node at once
 * @ti: the index to look into
 * @sidx: index where to start
 * @bits_in: data
 * @blen: number of bits to extract from @bits_in.
 *	  If @blen is not multiple of 64, the LSB's of the last u64 are ignored.
 * @bpos: number of bits to ignore from @bits_in.
 * @path: preallocated array of @blen of u64's to store the path.
 * @create: TINDEX_FIND to find existing, TINDEX_CREATE to create new records,
 *	    every other value is for internal use
 *
 * Return value: 0 for not found; nonzero = the index
 */

u64 tindex_find_rel_path(struct tindex *ti, const u64 sidx, const u32 *bits_in, const uint blen, const uint bpos, u64 *path, const u64 create);


/**
 * Find an index beginning somewhere else
 * @ti: the index to look into
 * @sidx: index where to start
 * @bits_in: data
 * @blen: number of bits to extract from @bits_in.
 *	  If @blen is not multiple of 64, the LSB's of the last u64 are ignored.
 * @bpos: number of bits to ignore from @bits_in.
 * @create: TINDEX_FIND to find existing, TINDEX_CREATE to create new records,
 *	    every other value is for internal use
 *
 * Return value: 0 for not found; nonzero = the index
 */

static inline u64 tindex_find_rel(struct tindex *ti, const u64 sidx, const u32 *bits_in, const uint blen, uint bpos, const u64 create)
{ return tindex_find_rel_path(ti, sidx, bits_in, blen, bpos, NULL, create); }

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

static inline u64 tindex_find(struct tindex *ti, const u32 *bits_in, const uint blen, const u64 create)
{ return tindex_find_rel(ti, 1, bits_in, blen, 0, create); }

/**
 * Delete an index.
 * @ti: the tindex to use
 * @idx: the index to delete
 **/

u64 tindex_delete(struct tindex *ti, const u64 idx);

#define TINDEX_WALK_NOMAXLEN	(((uint) 0) - 1)

struct tindex_walk_params {
  u64 begin;		/* Index to begin at. Root is 1. */
  uint maxlen;		/* Maximal data length; skip longer branches. */
  uint internal:1;	/* Return internal nodes with no data. */
  u32 *data;		/* Where to store the current bits. */
  uint *dlen;		/* Where to store the current bit length. */
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
 * Get next node.
 * @ctx: walk context
 *
 * Returns next eligible index in trie. Returns 0 and frees the context if no more nodes are available.
 **/
u64 tindex_walk_next(struct tindex_walk *ctx);

/**
 * Finish the trie walk. This must be called to return the allocated structures
 * if you break the walk prematurely by other means than the break clause.
 *
 * Breaking the walk by break is sane and safe.
 *
 * @ctx: walk context to free
 **/

void tindex_walk_free(struct tindex_walk *ctx);

#define TINDEX_WALK(ti, twp) \
  for (struct tindex_walk *_ti_ctx = tindex_walk_init(ti, twp); _ti_ctx; _ti_ctx = NULL) \
    for (u64 idx; idx = tindex_walk_next(_ti_ctx); )

/**
 * Dump the index. Useful for debugging.
 */

void tindex_dump(const struct tindex *ti);
