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
  struct tindex *ti = mb_allocz(p, sizeof(struct tindex *ti));
  ti->p = p;
  idm_init(&(ti->idm), p);
  ti->unit_size = TI_MIN_UNIT_SIZE;
  ti->address_size = TI_MIN_ADDRESS_SIZE;
  ti->index_data = mb_allocz(p, ti->unit_size * (1 << ti->address_size));
  return ti;
}

u64
tindex_find(struct tindex *ti, tindex_bitcheck tib, int create)
{
  switch (ti->unit_size) {
    case 4:
      switch (ti->address_size) {
	case 6:
	  return tindex_find_4_6(ti, tib, create);
	case 7:
	  return tindex_find_4_7(ti, tib, create);
	case 8:
	  return tindex_find_4_8(ti, tib, create);
	case 9:
	  return tindex_find_4_9(ti, tib, create);
	case 10:
	  return tindex_find_4_10(ti, tib, create);
	default:
	  bug("This shall never happen");
      }
    case 6:
      switch (ti->address_size) {
	case 9:
	  return tindex_find_6_9(ti, tib, create);
	case 10:
	  return tindex_find_6_10(ti, tib, create);
	case 11:
	  return tindex_find_6_11(ti, tib, create);
	case 12:
	  return tindex_find_6_12(ti, tib, create);
	case 13:
	  return tindex_find_6_13(ti, tib, create);
	case 14:
	  return tindex_find_6_14(ti, tib, create);
	default:
	  bug("This shall never happen");
      }
    default:
      bug("This shall never happen");
  }
}
