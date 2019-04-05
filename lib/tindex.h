/*
 *	Trie index for efficient trie storage
 *
 *	(c) 2019 Maria Matejka <mq@jmq.cz>
 *	(c) 2019 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"

typedef int (*tindex_bitcheck)(u32 needle, uint len);

#define TBR_DONE	0xff	/* The bits are matching the end of the needle */
#define TBR_PROCEED	0xfe	/* There is still some data to check */

struct tindex* tindex_new(pool *p);

u64 tindex_find(struct tindex *t, tindex_bitcheck tib, int create);
