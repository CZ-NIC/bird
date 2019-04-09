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
 * Find an index by the auxiliary funcction @tib.
 * @t: the index to look into
 * @tib: the auxiliary function; see before
 * @create: 0 to find only existing records, 1 to create new
 * Return value: 0 for not found (create == 0) or retry (create == 1); nonzero = the index
 */

u64 tindex_find(struct tindex *ti, const u64 *bits_in, const uint blen, const int create);

/**
 * Dump the index. Useful for debugging.
 */

void tindex_dump(const struct tindex *ti);
