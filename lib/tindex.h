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

/**
 * Find an index
 * @ti: the tindex to look into
 * @bits_in: data
 * @blen: number of bits to extract from bits_in.
 *	  If @blen is not multiple of 64, the LSB's of the last u64 are ignored.
 * @create: 0 to find existing, 1 to create new records
 *
 * Return value: 0 for not found; nonzero = the index
 */

u64 tindex_find(struct tindex *ti, const u64 *bits_in, const uint blen, const int create);

/**
 * Delete an index.
 * @ti: the tindex to use
 * @idx: the index to delete
 **/

u64 tindex_delete(struct tindex *ti, const u64 idx);

/**
 * Dump the index. Useful for debugging.
 */

void tindex_dump(const struct tindex *ti);
