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

#undef LOCAL_DEBUG
#define LOCAL_DEBUG

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
  u64 *exists;
  pool *p;
  struct idm idm;
  u8 unit_size;
  u8 address_size;
};

struct tindex *
tindex_new(pool *p)
{
  struct tindex *ti = mb_allocz(p, sizeof(struct tindex));
  ti->p = p;
  ti->unit_size = TI_MIN_UNIT_SIZE;
  ti->address_size = TI_MIN_ADDRESS_SIZE;
  ti->index_data = mb_allocz(p, ti->unit_size * (1 << ti->address_size));
  ti->exists = mb_allocz(p, (1 << (ti->address_size - 3)));
  idm_init(&(ti->idm), p, (1 << (ti->address_size - 5)), (1 << ti->address_size));
  u32 rootnode = idm_alloc(&(ti->idm));
  ASSERT(rootnode == 1);
  return ti;
}

static inline u64
tindex_data(const struct tindex *ti, u64 asize, u64 usize, u64 dsize, u64 dshift, u64 idx, uint *len)
{
  u64 data;
  switch (usize) {
    case 4:
      data = ti->index_data->data4[idx] >> dshift;
      break;
    case 6:
      data =
	((u64)(ti->index_data->data6[idx * 3] >> asize) << (dshift * 2)) |
	((u64)(ti->index_data->data6[idx * 3 + 1] >> asize) << (dshift)) |
	(u64)(ti->index_data->data6[idx * 3 + 2] >> asize);
      break;
    case 8:
      data = ti->index_data->data8[idx] >> dshift;
      break;
    case 12:
      data =
	((u64)(ti->index_data->data12[idx * 3] >> asize) << (dshift * 2)) |
	((u64)(ti->index_data->data12[idx * 3 + 1] >> asize) << (dshift)) |
	(u64)(ti->index_data->data12[idx * 3 + 2] >> asize);
      break;
    default:
      bug("This shall never happen");
  }

  u64 out = u64_var_decode(data, len);

  if (*len == 64)
    *len = 0;
  else
    *len = dsize - *len;

  return out;
}

static inline u64
tindex_left(const struct tindex *ti, u64 idx, u64 usize, u64 asize, u64 addrmask)
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
tindex_right(const struct tindex *ti, u64 idx, u64 usize, u64 asize, u64 addrmask)
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
tindex_up(const struct tindex *ti, u64 idx, u64 usize, u64 addrmask)
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
tindex_put(struct tindex *ti, u64 idx, u64 usize, u64 asize, u64 dsize, u64 dshift, u64 data, uint dlen, u64 left, u64 right, u64 up)
{
  const u64 dsmask = (1LL << dshift) - 1;
  data = u64_var_encode(data, dsize - dlen);

  switch (usize) {
    case 4:
      ti->index_data->data4[idx] = (data << dshift) | (left << (asize * 2)) | (right << asize) | up;
      return;
    case 6:
      ti->index_data->data6[idx * 3    ] = left  | ((data >> (2 * dshift)) << asize);
      ti->index_data->data6[idx * 3 + 1] = right | (((data >> dshift) & dsmask) << asize);
      ti->index_data->data6[idx * 3 + 2] = up    | ((data & dsmask) << asize);
      return;
    case 8:
      ti->index_data->data8[idx] = (data << dshift) | (left << (asize * 2)) | (right << asize) | up;
      return;
    case 12:
      ti->index_data->data12[idx * 3    ] = left  | ((data >> (2 * dshift)) << asize);
      ti->index_data->data12[idx * 3 + 1] = right | (((data >> dshift) & dsmask) << asize);
      ti->index_data->data12[idx * 3 + 2] = up    | ((data & dsmask) << asize);
      return;
    default: bug("This shall never happen");
  }
}

static inline void
tindex_left_clear(struct tindex *ti, u64 idx, u64 usize, u64 asize, u64 addrmask)
{
  switch (usize) {
    case 4: ti->index_data->data4[idx] &= ~(addrmask << (asize * 2)); break;
    case 6: ti->index_data->data6[idx * 3] &= ~addrmask; break;
    case 8: ti->index_data->data8[idx] &= ~(addrmask << (asize * 2)); break;
    case 12: ti->index_data->data6[idx * 3] &= ~addrmask; break;
  }
}

static inline void
tindex_right_clear(struct tindex *ti, u64 idx, u64 usize, u64 asize, u64 addrmask)
{
  switch (usize) {
    case 4: ti->index_data->data4[idx] &= ~(addrmask << asize); break;
    case 6: ti->index_data->data6[idx * 3 + 1] &= ~addrmask; break;
    case 8: ti->index_data->data8[idx] &= ~(addrmask << asize); break;
    case 12: ti->index_data->data6[idx * 3 + 1] &= ~addrmask; break;
  }
}

static inline void
tindex_left_set(struct tindex *ti, u64 idx, u64 usize, u64 asize, u64 nidx)
{
  /* The left child must have been zero before */
  switch (usize) {
    case 4: ti->index_data->data4[idx] |= nidx << (asize * 2); break;
    case 6: ti->index_data->data6[idx * 3] |= nidx; break;
    case 8: ti->index_data->data8[idx] |= nidx << (asize * 2); break;
    case 12: ti->index_data->data6[idx * 3] |= nidx; break;
  }
}

static inline void
tindex_right_set(struct tindex *ti, u64 idx, u64 usize, u64 asize, u64 nidx)
{
  /* The right child must have been zero before */
  switch (usize) {
    case 4: ti->index_data->data4[idx] |= nidx << asize; break;
    case 6: ti->index_data->data6[idx * 3 + 1] |= nidx; break;
    case 8: ti->index_data->data8[idx] |= nidx << asize; break;
    case 12: ti->index_data->data6[idx * 3 + 1] |= nidx; break;
  }
}

static inline void
tindex_child_update(struct tindex *ti, u64 idx, u64 usize, u64 asize, u64 addrmask, u64 oidx, u64 nidx)
{
  if (oidx == tindex_left(ti, idx, usize, asize, addrmask)) {
    tindex_left_clear(ti, idx, usize, asize, addrmask);
    tindex_left_set(ti, idx, usize, asize, nidx);
  } else {
    ASSERT(oidx == tindex_right(ti, idx, usize, asize, addrmask));
    tindex_right_clear(ti, idx, usize, asize, addrmask);
    tindex_right_set(ti, idx, usize, asize, nidx);
  }
}

static inline uint tindex_input_bits(const u64 *bits_in, const uint blen, uint *bpos, const uint dlen, u64 *bits) {
  uint bmax = blen - *bpos;	/* How much remains in the input */
  uint ilen = MIN(bmax, dlen);	/* How much we really take */

  if (ilen == 0) {		/* End of input */
    *bits = 0;
    return 0;
  }

  ASSERT(ilen <= 64);		/* The limit of output bit count is 64 */
  uint bend = *bpos + ilen - 1;	/* The last bit, inclusive (!) */

  /* Crop the bits at the end */
  *bits = (bits_in[bend / 64] >> (63 - (bend % 64)));

  /* Prepend bits from the previous item if the range goes over */
  if (bend / 64 > *bpos / 64)
    *bits |= bits_in[*bpos / 64] << (1 + bend % 64);
  else
    ASSERT(bend / 64 == *bpos / 64);

  /* Advance the bit pointer */
  *bpos += ilen;

  /* Return the wanted bits */
  *bits &= ((1 << ilen) - 1);
  return ilen;
}

static inline void
tindex_exists_set(const struct tindex *ti, const u64 idx)
{
  ti->exists[idx / 64] |= (1ULL << (idx % 64));
}

static inline u64
tindex_exists(const struct tindex *ti, const u64 idx)
{
  return (ti->exists[idx / 64] & (1ULL << (idx % 64)));
}

static inline void
tindex_exists_clear(const struct tindex *ti, const u64 idx)
{
  ti->exists[idx / 64] &= ~(1ULL << (idx % 64));
}

const char dump_indent[] = "                                                                ";
#define INDENT (dump_indent + sizeof(dump_indent) - depth - 1)

static void
_tindex_dump(const struct tindex *ti, u64 idx, uint depth, uint bit)
{
  const uint asize = ti->address_size;
  const uint usize = ti->unit_size;
  const uint dsize = usize * 8 - asize * 3;

  const uint dshift = (usize % 3) ? (asize * 3) : (dsize / 3);
  const u64 addrmask = (1ULL << ti->address_size) - 1;

  /* Validate unit size */
  switch (usize) {
    case 4:
    case 6:
    case 8:
    case 12: break;
    default: bug("This shall never happen");
  }

  uint dlen;
  u64 data = tindex_data(ti, asize, usize, dsize, dshift, idx, &dlen);
  if (depth && bit)
    data |= 1ULL << dlen;
  if (depth)
    dlen++;

  debug("%s0x%x/%u (%lu %c)\n", INDENT, data, dlen, idx, tindex_exists(ti, idx) ? '*' : ' ');
  u64 left = tindex_left(ti, idx, usize, asize, addrmask);
  if (left)
    _tindex_dump(ti, left, depth+1, 0);

  u64 right = tindex_right(ti, idx, usize, asize, addrmask);
  if (right)
    _tindex_dump(ti, right, depth+1, 1);
}

void
tindex_dump(const struct tindex *ti)
{
  _tindex_dump(ti, 1, 0, 0);
}

u64
tindex_find(struct tindex *ti, const u64 *bits_in, const uint blen, const int create)
{
  const uint asize = ti->address_size;
  const uint usize = ti->unit_size;
  const uint dsize = usize * 8 - asize * 3;

  const uint dshift = (usize % 3) ? (asize * 3) : (dsize / 3);
  const u64 addrmask = (1ULL << ti->address_size) - 1;

  /* Validate unit size */
  switch (usize) {
    case 4:
    case 6:
    case 8:
    case 12: break;
    default: bug("This shall never happen");
  }

  u64 idx = 1;	/* The root node is always 1 */
  u64 uidx = 0;	/* Parent node is 0 on beginning */

  uint bpos = 0;

  while (1) {
    /* Get data from trie */
    uint dlen;
    u64 data = tindex_data(ti, asize, usize, dsize, dshift, idx, &dlen);

    /* Get data from input */
    u64 bits;
    uint ilen = tindex_input_bits(bits_in, blen, &bpos, dlen, &bits);

    /* Check whether this node matches the data */
    int match = ((ilen == dlen) && (bits == data));

    /* Doesn't match and we are just traversing */
    if (!create && !match)
      return 0;

    /* The bit strings match */
    if (match) {
      /* Get one more bit */
      ilen = tindex_input_bits(bits_in, blen, &bpos, 1, &bits);

      /* No more bits, we're done */
      if (!ilen) {
	/* Existence bits fiddling */
	if (create)
	  tindex_exists_set(ti, idx);
	else if (!tindex_exists(ti, idx))
	  return 0;

	return idx;
      }

      /* Just one bit, to be sure */
      ASSERT(bits < 2);
      ASSERT(ilen == 1);

      /* Go left or right? */
      u64 nidx = bits ? tindex_right(ti, idx, usize, asize, addrmask) : tindex_left(ti, idx, usize, asize, addrmask);

      /* There is a path, we'll follow it. */
      if (nidx) {
	uidx = idx;
	idx = nidx;
	continue;
      }

      /* There is no path and we shan't create it. */
      if (!create)
	return 0;

      /* So there will be a new node on path. */
      nidx = idm_alloc(&(ti->idm));

      /* Left or right? */
      if (bits)
	tindex_right_set(ti, idx, usize, asize, nidx);
      else
	tindex_left_set(ti, idx, usize, asize, nidx);

      /* Go there. */
      uidx = idx;
      idx = nidx;

      /* And now we shall continue by the brand new node. */
      break;
    }

    /* Move the bits to same places */
    u64 shorter = dlen - ilen;
    bits <<= shorter;

    /* What is the common part? */
    u64 diflen = u64_log2(bits ^ data) + 1;

    /* To be sure that the split is right. */
    ASSERT((bits >> diflen) == (data >> diflen));
    ASSERT(((bits >> (diflen - 1)) ^ (data >> (diflen - 1))) == 1);

    /* Get the common part */
    u64 common = data >> diflen;
    u64 comlen = dlen - diflen;

    /* Return the differing part to the input buffer (if there is some) */
    int split = (ilen - comlen > 0);
    if (split)
      bpos -= ilen - comlen - 1;

    /* Split out the first different bit */
    u64 dataright = !!(data & (1 << (diflen - 1)));
    dlen = diflen - 1;
    data &= (1 << dlen) - 1;

    /* Allocate the splitting index */
    u64 midx = idm_alloc(&(ti->idm));

    /* Allocate the new node if it shall exist */
    u64 nidx = split ? idm_alloc(&(ti->idm)) : 0;

    /* Relink idx -> midx in the parent node */
    if (uidx)
      tindex_child_update(ti, uidx, usize, asize, addrmask, idx, midx);

    /* Setup the splitting index (midx) */
    tindex_put(ti, midx, usize, asize, dsize, dshift, common, comlen, dataright ? nidx : idx, dataright ? idx : nidx, uidx);

    /* Update the existing index (idx) */
    tindex_put(ti, idx, usize, asize, dsize, dshift, data, dlen, tindex_left(ti, idx, usize, asize, addrmask), tindex_right(ti, idx, usize, asize, addrmask), midx);

    /* Go down to the child */
    uidx = idx;
    idx = nidx;

    /* Grow there a branch if it has to be grown, otherwise return */
    if (split)
      break;
    else {
      tindex_exists_set(ti, midx);
      return midx;
    }
  }

  /* Growing a new branch */
  while (1) {
    /* Get more data from input */
    u64 data;
    uint ilen = tindex_input_bits(bits_in, blen, &bpos, dsize - 1, &data);

    /* For the single bit */
    u64 dataright = ~0;

    /* End of input data */
    if ((ilen < dsize - 1) || !tindex_input_bits(bits_in, blen, &bpos, 1, &dataright)) {
      tindex_put(ti, idx, usize, asize, dsize, dshift, data, ilen, 0, 0, uidx);
      tindex_exists_set(ti, idx);
      return idx;
    }

    /* Just one bit. */
    ASSERT(dataright < 2);

    /* Create a new node */
    uint nidx = idm_alloc(&(ti->idm));

    /* Link it into the trie */
    tindex_put(ti, idx, usize, asize, dsize, dshift, data, ilen, dataright ? 0 : nidx, dataright ? nidx : 0, uidx);

    /* And continue there */
    uidx = idx;
    idx = nidx;
  }
}
