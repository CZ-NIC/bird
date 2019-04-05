/*
 *	Trie index for efficient trie storage
 *
 *	(c) 2019 Maria Matejka <mq@jmq.cz>
 *	(c) 2019 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/idm.h"
#include "lib/tindex.h"

#define TI_MIN_UNIT_SIZE	4
#define TI_MIN_ADDRESS_SIZE	6

union tindex_data {
  u32 data4[0];
  u16 data6[0];
  u64 data8[0];
  u32 data12[0];
};

struct tindex {
  union tindex_data *index_data;
  pool *p;
  struct idm idm;
  u8 unit_size;
  u8 address_size;
};

struct tindex *
tindex_new(pool *p)
{
  struct tindex *ti = mb_allocz(p, sizeof(struct tindex *));
  ti->p = p;
  ti->unit_size = TI_MIN_UNIT_SIZE;
  ti->address_size = TI_MIN_ADDRESS_SIZE;
  ti->index_data = mb_allocz(p, ti->unit_size * (1 << ti->address_size));
  idm_init(&(ti->idm), p, (1 << ti->address_size));
  return ti;
}

u64
tindex_find(struct tindex *ti, tindex_bitcheck tib, int create)
{
  const u64 asize = ti->address_size;
  const u64 usize = ti->unit_size;

  const u64 d3shift = 8 * (usize / 3) - asize; /* (d3shift * 3 + asize * 3 == usize * 8) if usize % 3 == 0 */

  const u64 addrmask = (1ULL << ti->address_size) - 1;
  u64 idx = 1;	/* The root node is always 1 */
  
  switch (usize) {
    case 6:
      do {
	const u64 data =
	  ((ti->index_data->data6[idx * 3] >> asize) << (d3shift * 2)) |
	  ((ti->index_data->data6[idx * 3 + 1] >> asize) << (d3shift)) |
	  (ti->index_data->data6[idx * 3 + 2] >> asize);

	u8 len = d3shift * 3;
	u64 bits = tib(&len);
  /* TODO */

	const u64 left = ti->index_data->data6[idx * 3] & addrmask;
	const u64 right = ti->index_data->data6[idx * 3 + 1] & addrmask;
	const u64 parent = ti->index_data->data6[idx * 3 + 2] & addrmask;

	u8 len = 1;
	u64 bits = tib(&len);
	if (!len)
	  return idx;
	if (bits)
	  idx = right;
	else
	  idx = left;
      } while (1);
  }

}
