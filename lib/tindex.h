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
 * tindex_bitcheck() callback is called by tindex_find() repeatedly
 * to get input bits as needed. Maximal number of bits is
 * given in @len; it shall be replaced the actual number of bits
 * returned. The bits shall be returned in LSB of the return value.
 * If (and only if) no bits are remaining, @len shall be changed,
 * otherwise the callee must always return full bit string.
 *
 * This is intended to be implemented as a nested function in
 * a library call using this tree index.
 **/

typedef u64 (*tindex_bitcheck)(u8 *len);

/**
 * Allocate a new tr[ei]e index from the given pool
 * @p: pool to allocate from
 *
 * Returns the allocated tindex structure 
 */
struct tindex* tindex_new(pool *p);

/**
 * Find an index by the auxiliary funcction @tib.
 * @t: the index to look into
 * @tib: the auxiliary function; see before
 * @create: 0 to find only existing records, 1 to create new
 * Return value: 0 for not found (create == 0) or retry (create == 1); nonzero = the index
 */

u64 tindex_find(struct tindex *t, tindex_bitcheck tib, int create);
