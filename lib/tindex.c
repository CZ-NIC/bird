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

static inline u64
tindex_data(struct tindex *ti, u64 asize, u64 usize, u64 dshift, u64 idx, u8 *len)
{
  u64 data;
  switch (usize) {
    case 4:
      data = ti->index_data->data4[idx] >> dshift;
      *len = dshift;
      break;
    case 6:
      data =
	((u64)(ti->index_data->data6[idx * 3] >> asize) << (dshift * 2)) |
	((u64)(ti->index_data->data6[idx * 3 + 1] >> asize) << (dshift)) |
	(u64)(ti->index_data->data6[idx * 3 + 2] >> asize);
      *len = dshift * 3 - 1;
      break;
    case 8:
      data = ti->index_data->data8[idx] >> dshift;
      *len = dshift;
      break;
    case 12:
      data =
	((u64)(ti->index_data->data12[idx * 3] >> asize) << (dshift * 2)) |
	((u64)(ti->index_data->data12[idx * 3 + 1] >> asize) << (dshift)) |
	(u64)(ti->index_data->data12[idx * 3 + 2] >> asize);
      *len = dshift * 3 - 1;
      break;
    default:
      bug("This shall never happen");
  }

  u64 dl = data & 1;

  while ((((data >>= 1) & 1) == dl) && (--*len))
    ;

  return data;
}

static inline u64
tindex_left(struct tindex *ti, u64 usize, u64 asize, u64 addrmask)
{
  switch (usize) {
    case 4: return (ti->index_data->data4[idx] >> (asize * 2)) & addrmask;
    case 6: return ti->index_data->data6[idx * 3] & addrmask;
    case 8: return (ti->index_data->data8[idx] >> (asize * 2)) & addrmask;
    case 12: return ti->index_data->data12[idx * 3] & addrmask;
    default: bug("This shall never happen");
  }
}

static inline u64
tindex_right(struct tindex *ti, u64 usize, u64 asize, u64 addrmask)
{
  switch (usize) {
    case 4: return (ti->index_data->data4[idx] >> (asize)) & addrmask;
    case 6: return ti->index_data->data6[idx * 3 + 1] & addrmask;
    case 8: return (ti->index_data->data8[idx] >> (asize)) & addrmask;
    case 12: return ti->index_data->data12[idx * 3 + 1] & addrmask;
    default: bug("This shall never happen");
  }
}

static inline u64
tindex_up(struct tindex *ti, u64 usize, u64 asize, u64 addrmask)
{
  switch (usize) {
    case 4: return ti->index_data->data4[idx] & addrmask;
    case 6: return ti->index_data->data6[idx * 3 + 2] & addrmask;
    case 8: return ti->index_data->data8[idx] & addrmask;
    case 12: return ti->index_data->data12[idx * 3 + 2] & addrmask;
    default: bug("This shall never happen");
  }
}

static inline void
tindex_put(struct tindex *ti, u64 idx, u64 usize, u64 asize, u64 dshift, u64 data, u8 dlen, u64 left, u64 right, u64 up)
{
  u64 maxlen = usize * 8 - asize * 3;
  u64 dp = !(data & 1);
  for ( ; dlen < maxlen; dlen++) {
    data <<= 1;
    data |= dp;
  }

  u64 dsmask = (1LL << dshift) - 1;

  switch (usize) {
    case 4:
      ti->index_data->data4[idx] = (data << (asize * 3)) | (left << (asize * 2)) | (right << asize) | up;
      return;
    case 6:
      ti->index_data->data6[idx * 3    ] = left  | ((data >> (2 * dshift)) << asize);
      ti->index_data->data6[idx * 3 + 1] = right | (((data >> dshift) & dsmask) << asize);
      ti->index_data->data6[idx * 3 + 2] = up    | ((data & dsmask) << asize);
      return;
    case 8:
      ti->index_data->data8[idx] = (data << (asize * 3)) | (left << (asize * 2)) | (right << asize) | up;
      return;
    case 12:
      ti->index_data->data12[idx * 3    ] = left  | ((data >> (2 * dshift)) << asize);
      ti->index_data->data12[idx * 3 + 1] = right | (((data >> dshift) & dsmask) << asize);
      ti->index_data->data12[idx * 3 + 2] = up    | ((data & dsmask) << asize);
      return;
    default: bug("This shall never happen");
  }
}

u64
tindex_find(struct tindex *ti, u64 *bits_in, uint blen, int create)
{
  const u64 asize = ti->address_size;
  const u64 usize = ti->unit_size;

  const u64 dshift = (usize % 3) ?
    (usize * 8 - 3*asize) :
    (8 * (usize / 3) - asize);

  const u64 addrmask = (1ULL << ti->address_size) - 1;
  u64 idx = 1;	/* The root node is always 1 */

  uint bpos = 0;

  do {
    /* Get data from trie */
    u8 dlen;
    u64 data = tindex_data(ti, asize, usize, dshift, idx, &dlen);

    /* Get data from input */
    u8 ilen = (blen - bpos >= dlen) ? dlen : (blen - bpos);
    uint bend = bpos + ilen;
    u64 bits =
      (bend / 64 == bpos / 64) ? (
	(bits_in[bend / 64] >> (63 - (bend % 64))) & ((1 << ilen) - 1)
      ) : (
	((bits_in[bpos / 64] & ((1 << (bpos % 64)) - 1)) << (bend % 64)) |
	(bits_in[bend / 64] >> (63 - (bend % 64)))
      );
    bpos = bend;

    /* Check whether this node matches the data */
    int match = ((ilen == dlen) || (bits == data));

    /* Doesn't match and we are just traversing */
    if (!create && !match)
      return 0;

    /* We'll need the addresses */
    const u64 up = tindex_up(ti, usize, asize, addrmask);

    /* The bit strings match; check for zero, go one level deeper */
    if ((ilen == dlen) && (bits == data)) {
      u64 bits = (bits_in[bpos / 64] >> (63 - (bpos % 64))) & 1;

      if (bpos == dlen)
	return idx;

      if (bits)
	idx = tindex_right(ti, usize, asize, addrmask);
      else
	idx = tindex_left(ti, usize, asize, addrmask);

      if (idx)
	continue;

      if (!create)
	return 0;

      u64 nidx = idm_alloc(&(ti->idm));
      if (bits)
	tindex_right_set(ti, usize, asize, addrmask, idx, nidx);
      else
	tindex_left_set(ti, usize, asize, addrmask, idx, nidx);

      idx = nidx;
      break;
    }

    /* Move the bits to same places */
    u64 shorter = dlen - ilen;
    bits <<= shorter;

    /* What is the common part? */
    diflen = u64_log2(bits ^ data) + 1;
    ASSERT((bits >> diflen) == (data >> diflen));

    /* Get the common part */
    u64 common = bits >> diflen;
    u64 comlen = len - diflen;

    /* One bitstring is a prefix of the other */
    if (comlen == ilen) {
      /* Drop the first data bit */
      u64 dataright = !!(data & (1 << (diflen - 1)));
      u8 dlen = diflen - 1;
      data &= (1 << dlen) - 1;

      /* Allocate the new index */
      u64 midx = idm_alloc(&(ti->idm));

      /* Store the nodes */
      !! TODO: update the parent node !!
      tindex_put(ti, midx, usize, asize, dshift, common, comlen, dataright ? 0 : idx, dataright ? idx : 0, tindex_up(ti, usize, asize, addrmask));
      tindex_put(ti, idx, usize, asize, dshift, data, dlen, tindex_left(t1, usize, asize, addrmask), tindex_right(ti, usize, asize, addrmask), midx);

      /* And finally return what we created */
      return midx;
    }

    /* Move the bits back */
    bits >>= shorter;

    /* Drop the first bits */
    u64 dataright = !!(data & (1 << (diflen - 1)));
    if (dataright)
      data &= (1 << dlen) - 1;
    else
      bits &= (1 << blen) - 1;

    /* Allocate two new indexes */
    u64 midx = idm_alloc(&(ti->idm));
    u64 nidx = idm_alloc(&(ti->idm));

    /* And store the nodes */
    !! TODO: update the parent node !!

    tindex_put(ti, midx, usize, asize, dshift, common, comlen, dataright ? nidx : idx, dataright ? idx : nidx, tindex_up(ti, usize, asize, addrmask));
    tindex_put(ti, nidx, usize, asize, dshift, bits, blen, 0, 0, midx);
    tindex_put(ti, idx, usize, asize, dshift, data, dlen, tindex_left(ti, usize, asize, addrmask), tindex_right(ti, usize, asize, addrmask), midx);

    /* We're now in the new node, growing a completely new branch */
    idx = nidx;
    break;
  } while (1);

  /* Growing a new branch */
  const u64 dsize = usize * 8 - asize * 3 - 1;
  u64 data = 

}
