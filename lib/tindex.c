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

#define TDB	32
#define uTDB	u32

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
  u16 depth;
  u8 unit_size;
  u8 address_size;
};

struct tindex_info {
  uint usize;
  uint asize;
  uint dsize;
  uint dshift;
  u64 addrmask;
};

static inline void
tindex_fill_info(const struct tindex *ti, struct tindex_info *tinfo)
{
  tinfo->asize = ti->address_size;
  tinfo->usize = ti->unit_size;
  tinfo->dsize = tinfo->usize * 8 - tinfo->asize * 3;

  tinfo->dshift = (tinfo->usize % 3) ? (tinfo->asize * 3) : (tinfo->dsize / 3);
  tinfo->addrmask = (1ULL << ti->address_size) - 1;
}

#define usize tinfo->usize
#define asize tinfo->asize
#define dsize tinfo->dsize
#define dshift tinfo->dshift
#define addrmask tinfo->addrmask

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
  u64 rootnode = idm_alloc(&(ti->idm));
  ASSERT(rootnode == 1);
  return ti;
}

static inline u64
tindex_data(const union tindex_data *id, const struct tindex_info *tinfo, u64 idx, uint *len)
{
  ASSERT(dsize <= TDB);
  u64 data;
  switch (usize) {
    case 4:
      data = id->data4[idx] >> dshift;
      break;
    case 6:
      data =
	((u64)(id->data6[idx * 3] >> asize) << (dshift * 2)) |
	((u64)(id->data6[idx * 3 + 1] >> asize) << (dshift)) |
	(u64)(id->data6[idx * 3 + 2] >> asize);
      break;
    case 8:
      data = id->data8[idx] >> dshift;
      break;
    case 12:
      data =
	((u64)(id->data12[idx * 3] >> asize) << (dshift * 2)) |
	((u64)(id->data12[idx * 3 + 1] >> asize) << (dshift)) |
	(u64)(id->data12[idx * 3 + 2] >> asize);
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
tindex_left(const union tindex_data *id, const struct tindex_info *tinfo, u64 idx)
{
  switch (usize) {
    case 4: return (id->data4[idx] >> (asize * 2)) & addrmask;
    case 6: return id->data6[idx * 3] & addrmask;
    case 8: return (id->data8[idx] >> (asize * 2)) & addrmask;
    case 12: return id->data12[idx * 3] & addrmask;
    default: bug("This shall never happen");
  }
}

static inline u64
tindex_right(const union tindex_data *id, const struct tindex_info *tinfo, u64 idx)
{
  switch (usize) {
    case 4: return (id->data4[idx] >> (asize)) & addrmask;
    case 6: return id->data6[idx * 3 + 1] & addrmask;
    case 8: return (id->data8[idx] >> (asize)) & addrmask;
    case 12: return id->data12[idx * 3 + 1] & addrmask;
    default: bug("This shall never happen");
  }
}

static inline u64
tindex_up(const union tindex_data *id, const struct tindex_info *tinfo, u64 idx)
{
  switch (usize) {
    case 4: return id->data4[idx] & addrmask;
    case 6: return id->data6[idx * 3 + 2] & addrmask;
    case 8: return id->data8[idx] & addrmask;
    case 12: return id->data12[idx * 3 + 2] & addrmask;
    default: bug("This shall never happen");
  }
}

static inline void
tindex_put(union tindex_data *id, const struct tindex_info *tinfo, u64 idx, u64 data, uint dlen, u64 left, u64 right, u64 up)
{
  const u64 dsmask = (1LL << dshift) - 1;
  data = u64_var_encode(data, dsize - dlen);

  switch (usize) {
    case 4:
      id->data4[idx] = (data << dshift) | (left << (asize * 2)) | (right << asize) | up;
      return;
    case 6:
      id->data6[idx * 3    ] = left  | ((data >> (2 * dshift)) << asize);
      id->data6[idx * 3 + 1] = right | (((data >> dshift) & dsmask) << asize);
      id->data6[idx * 3 + 2] = up    | ((data & dsmask) << asize);
      return;
    case 8:
      id->data8[idx] = (data << dshift) | (left << (asize * 2)) | (right << asize) | up;
      return;
    case 12:
      id->data12[idx * 3    ] = left  | ((data >> (2 * dshift)) << asize);
      id->data12[idx * 3 + 1] = right | (((data >> dshift) & dsmask) << asize);
      id->data12[idx * 3 + 2] = up    | ((data & dsmask) << asize);
      return;
    default: bug("This shall never happen");
  }
}

static inline void
tindex_left_clear(union tindex_data *id, const struct tindex_info *tinfo, u64 idx)
{
  switch (usize) {
    case 4: id->data4[idx] &= ~(addrmask << (asize * 2)); break;
    case 6: id->data6[idx * 3] &= ~addrmask; break;
    case 8: id->data8[idx] &= ~(addrmask << (asize * 2)); break;
    case 12: id->data12[idx * 3] &= ~addrmask; break;
  }
}

static inline void
tindex_right_clear(union tindex_data *id, const struct tindex_info *tinfo, u64 idx)
{
  switch (usize) {
    case 4: id->data4[idx] &= ~(addrmask << asize); break;
    case 6: id->data6[idx * 3 + 1] &= ~addrmask; break;
    case 8: id->data8[idx] &= ~(addrmask << asize); break;
    case 12: id->data12[idx * 3 + 1] &= ~addrmask; break;
  }
}

static inline void
tindex_up_clear(union tindex_data *id, const struct tindex_info *tinfo, u64 idx)
{
  switch (usize) {
    case 4: id->data4[idx] &= ~addrmask; break;
    case 6: id->data6[idx * 3 + 2] &= ~addrmask; break;
    case 8: id->data8[idx] &= ~addrmask; break;
    case 12: id->data12[idx * 3 + 2] &= ~addrmask; break;
  }
}

static inline void
tindex_left_set(union tindex_data *id, const struct tindex_info *tinfo, u64 idx, u64 nidx)
{
  /* The left child must have been zero before */
  switch (usize) {
    case 4: id->data4[idx] |= nidx << (asize * 2); break;
    case 6: id->data6[idx * 3] |= nidx; break;
    case 8: id->data8[idx] |= nidx << (asize * 2); break;
    case 12: id->data12[idx * 3] |= nidx; break;
  }
}

static inline void
tindex_right_set(union tindex_data *id, const struct tindex_info *tinfo, u64 idx, u64 nidx)
{
  /* The right child must have been zero before */
  switch (usize) {
    case 4: id->data4[idx] |= nidx << asize; break;
    case 6: id->data6[idx * 3 + 1] |= nidx; break;
    case 8: id->data8[idx] |= nidx << asize; break;
    case 12: id->data12[idx * 3 + 1] |= nidx; break;
  }
}

static inline void
tindex_up_set(union tindex_data *id, const struct tindex_info *tinfo, u64 idx, u64 nidx)
{
  /* The parent must have been zero before */
  switch (usize) {
    case 4: id->data4[idx] |= nidx; break;
    case 6: id->data6[idx * 3 + 2] |= nidx; break;
    case 8: id->data8[idx] |= nidx; break;
    case 12: id->data12[idx * 3 + 2] |= nidx; break;
  }
}

static inline void
tindex_child_update(union tindex_data *id, const struct tindex_info *tinfo, u64 idx, u64 oidx, u64 nidx)
{
  if (oidx == tindex_left(id, tinfo, idx)) {
    tindex_left_clear(id, tinfo, idx);
    tindex_left_set(id, tinfo, idx, nidx);
  } else {
    ASSERT(oidx == tindex_right(id, tinfo, idx));
    tindex_right_clear(id, tinfo, idx);
    tindex_right_set(id, tinfo, idx, nidx);
  }
}

static inline uint tindex_input_bits(const uTDB *bits_in, const uint blen, uint *bpos, const uint dlen, u64 *bits) {
  uint bmax = blen - *bpos;	/* How much remains in the input */
  uint ilen = MIN(bmax, dlen);	/* How much we really take */

  if (ilen == 0) {		/* End of input */
    *bits = 0;
    return 0;
  }

  ASSERT(ilen <= TDB);		/* The limit of output bit count is TDB */
  uint bend = *bpos + ilen - 1;	/* The last bit, inclusive (!) */

  /* Crop the bits at the end */
  *bits = (bits_in[bend / TDB] >> (TDB - 1 - (bend % TDB)));

  /* Prepend bits from the previous item if the range goes over */
  if (bend / TDB > *bpos / TDB)
    *bits |= bits_in[*bpos / TDB] << (1 + bend % TDB);
  else
    ASSERT(bend / TDB == *bpos / TDB);

  /* Advance the bit pointer */
  *bpos += ilen;

  /* Return the wanted bits */
  *bits &= ((1ULL << ilen) - 1);
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

struct tindex_parsed_node {
  u64 left;
  u64 right;
  u64 up;
  u64 data;
  uint dlen;
  uint seen:1;
};

struct tindex_walk {
  const struct tindex_walk_params twp;
  const struct tindex_info tinfo;
  uint pos;
  struct tindex_parsed_node tpn[0];
};

struct tindex_walk *
tindex_walk_init(const struct tindex *ti, const struct tindex_walk_params *twp)
{
  struct tindex_walk *tw = mb_allocz(ti->p, sizeof(struct tindex_walk) + ti->ndepth * sizeof(struct tindex_parsed_node));
  memcpy(tw, twp, sizeof(*twp));
  tw->tpn[0] = tindex_walk_parse(ti
  return tw;
}

const char dump_indent[] = "                                                                ";
#define INDENT (dump_indent + sizeof(dump_indent) - depth - 1)

static void
_tindex_dump(const struct tindex *ti, u64 idx, uint depth, uint bit)
{
  struct tindex_info stinfo, *tinfo = &stinfo;
  tindex_fill_info(ti, tinfo);

  union tindex_data *idata = ti->index_data;

  /* Validate unit size */
  switch (usize) {
    case 4:
    case 6:
    case 8:
    case 12: break;
    default: bug("This shall never happen");
  }

  uint dlen;
  u64 data = tindex_data(idata, usize, asize, dsize, dshift, idx, &dlen);
  if (depth && bit)
    data |= 1ULL << dlen;
  if (depth)
    dlen++;

  debug("%s0x%x/%u (%lu %c)\n", INDENT, data, dlen, idx, tindex_exists(ti, idx) ? '*' : ' ');
  u64 left = tindex_left(idata, idx, usize, asize, addrmask);
  if (left)
    _tindex_dump(ti, left, depth+1, 0);

  u64 right = tindex_right(idata, idx, usize, asize, addrmask);
  if (right)
    _tindex_dump(ti, right, depth+1, 1);
}

void
tindex_dump(const struct tindex *ti)
{
  debug("Trie index; usize = %u, asize = %u, dsize = %u, depth = %u\n",
      ti->unit_size, ti->address_size, ti->unit_size * 8 - ti->address_size * 3,
      ti->depth);
  _tindex_dump(ti, 1, 0, 0);
}

void tindex_migrate(struct tindex * restrict ti, const union tindex_data * restrict odata, const u64 idx, const uint usize, const uint asize, const uint dsize, const uint dshift, const u64 addrmask, uTDB *bits, uint bpos) {
  uint dlen;
  u64 data = tindex_data(odata, usize, asize, dsize, dshift, idx, &dlen);
  u64 mask = (1 << dlen) - 1;
  if (dlen) {
    uint bend = bpos + dlen - 1;

    if (bend / TDB > bpos / TDB) {
      bits[bpos / TDB] &= ~(mask >> (1 + bend % TDB));
      bits[bpos / TDB] |= data >> (1 + bend % TDB);
    }

    bits[bend / TDB] &= ~(mask << (TDB - 1 - (bend % TDB)));
    bits[bend / TDB] |= data << (TDB - 1 - (bend % TDB));

    bpos = bend + 1;
  }

  /* Migration of non-root nodes */
  if (idx > 1)
    if (tindex_exists(ti, idx))
      tindex_find(ti, bits, bpos, idx);
    else
      idm_free(&(ti->idm), idx);

  u64 left = tindex_left(odata, idx, usize, asize, addrmask);
  if (left) {
    bits[bpos / TDB] &= ~(1ULL << (TDB - 1 - (bpos % TDB)));
    tindex_migrate(ti, odata, left, usize, asize, dsize, dshift, addrmask, bits, bpos + 1);
  }

  u64 right = tindex_right(odata, idx, usize, asize, addrmask);
  if (right) {
    bits[bpos / TDB] |= 1ULL << (TDB - 1 - (bpos % TDB));
    tindex_migrate(ti, odata, right, usize, asize, dsize, dshift, addrmask, bits, bpos + 1);
  }
}

void
tindex_do_grow(struct tindex *ti, const uint nasize, const uint nusize)
{
  const uint asize = ti->address_size;
  const uint usize = ti->unit_size;
  const uint dsize = usize * 8 - asize * 3;

  const uint dshift = (usize % 3) ? (asize * 3) : (dsize / 3);
  const u64 addrmask = (1ULL << ti->address_size) - 1;

  ti->unit_size = nusize;
  ti->address_size = nasize;

  union tindex_data *odata = ti->index_data;
  ti->index_data = mb_allocz(ti->p, nusize * (1 << nasize));

  u64 *oexists = ti->exists;
  ti->exists = mb_allocz(ti->p, (1 << (nasize - 3)));
  memcpy(ti->exists, oexists, 1 << (asize - 3));
  mb_free(oexists);

  ti->idm.max = 1 << nasize;

  uTDB *bits = alloca(((ti->depth / TDB) + 1)*sizeof(uTDB));
  memset(bits, 0, ((ti->depth / TDB) + 1)*sizeof(uTDB));

  tindex_migrate(ti, odata, 1, usize, asize, dsize, dshift, addrmask, bits, 0);
  mb_free(odata);
}

void tindex_lencnt(u64 idx) {
  uint dlen;
  tindex_data(idata, usize, asize, dsize, dshift, idx, &dlen);
  ASSERT(dlen < dsize);
  if (dlen >= dsize - 3)
    needsplit++;
  total++;

  u64 left = tindex_left(idata, idx, usize, asize, addrmask);
  if (left)
    tindex_lencnt(left);

  u64 right = tindex_right(idata, idx, usize, asize, addrmask);
  if (right)
    tindex_lencnt(right);
}

void
tindex_grow(struct tindex *ti)
{
  /* We want bigger index space so we have to change parameters
   * of the tindex and completely rebuild it. Then we'll free the
   * old index_data.
   *
   * Assigned indices are kept, internal nodes may be rearranged
   * and renumbered.
   */

  const uint asize = ti->address_size;
  const uint usize = ti->unit_size;
  const uint dsize = usize * 8 - asize * 3;
  const union tindex_data *idata = ti->index_data;

  const uint dshift = (usize % 3) ? (asize * 3) : (dsize / 3);
  const u64 addrmask = (1ULL << ti->address_size) - 1;

  if (dsize > 3) {
    /* First we'll try to estimate whether it is feasible to shorten
     * the data part while getting more space for the indices */

    u64 needsplit = 0;
    u64 total = 0;

    tindex_lencnt(idata, 1, usize, asize, dsize, dshift, addrmask);

    /* After shortening the data part, needsplit/total nodes will duplicate (or triplicate!).
     * If the overall index usage goes up by at most 20% by doing this change,
     * we consider it feasible. By math:
     *
     * ((float)(needsplit / total)) * ((int)(dsize / (dsize - 3)) + 1) < 0.2
     * needsplit * ((dsize / (dsize - 3)) + 1) < 0.2 * total
     * 5 * needsplit * ((dsize / (dsize - 3)) + 1) < total
     */

    if (5 * needsplit * ((dsize / (dsize - 3)) + 1) < total)
      return tindex_do_grow(ti, asize + 1, usize);
  }

  switch (usize) {
#define UP_ASIZE(usize) (1+MAX((((usize-4)*8)/3),asize))
    case 4: return tindex_do_grow(ti, UP_ASIZE(6), 6);
    case 6: return tindex_do_grow(ti, UP_ASIZE(8), 8);
    case 8: return tindex_do_grow(ti, UP_ASIZE(12), 12);
    case 12: bug("Not implemented yet.");
    default: bug("This shall not happen.");
  }
}

static inline void
tindex_renumber(union tindex_data *idata, u64 usize, u64 asize, u64 dsize, u64 dshift, u64 addrmask, u64 oidx, u64 nidx)
{
  u64 up = tindex_up(idata, oidx, usize, addrmask);
  u64 left = tindex_left(idata, oidx, usize, asize, addrmask);
  u64 right = tindex_right(idata, oidx, usize, asize, addrmask);

  if (up)
    tindex_child_update(idata, up, usize, asize, addrmask, oidx, nidx);

  if (left) {
    tindex_up_clear(idata, left, usize, asize, addrmask);
    tindex_up_set(idata, left, usize, asize, nidx);
  }

  if (right) {
    tindex_up_clear(idata, right, usize, asize, addrmask);
    tindex_up_set(idata, right, usize, asize, nidx);
  }

  switch (usize) {
    case 4: idata->data4[nidx] = idata->data4[oidx];
	    break;
    case 6: memcpy(&(idata->data6[nidx * 3]), &(idata->data6[oidx * 3]), 3*sizeof(idata->data6[0]));
	    break;
    case 8: idata->data8[nidx] = idata->data8[oidx];
	    break;
    case 12: memcpy(&(idata->data12[nidx * 3]), &(idata->data12[oidx * 3]), 3*sizeof(idata->data12[0]));
	    break;
    default: bug("This shall never happen");
  }
}

#define TINDEX_ALLOC_IDX ({ u64 out = idm_alloc(&(ti->idm)); if (!out) goto noidx; out; })

u64
tindex_find(struct tindex *ti, const uTDB *bits_in, const uint blen, const u64 create)
{
  if (blen > ti->depth)
    if (create)
      ti->depth = blen;
    else
      return 0;

  union tindex_data *idata = ti->index_data;


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
    u64 data = tindex_data(idata, usize, asize, dsize, dshift, idx, &dlen);

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
	if (create == TINDEX_CREATE) {
	  /* Creating at any index -> do it */
	  tindex_exists_set(ti, idx);
	  return idx;
	} else if (create) {
	  /* Migration from old version -> renumber */
	  tindex_renumber(idata, usize, asize, dsize, dshift, addrmask, idx, create);
	  idm_free(&(ti->idm), idx);
	  return create;
	} else if (tindex_exists(ti, idx))
	  /* Shan't create but it already exists */
	  return idx;
	else
	  return 0;
      }

      /* Just one bit, to be sure */
      ASSERT(bits < 2);
      ASSERT(ilen == 1);

      /* Go left or right? */
      u64 nidx = bits ? tindex_right(idata, idx, usize, asize, addrmask) : tindex_left(idata, idx, usize, asize, addrmask);

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
      nidx = TINDEX_ALLOC_IDX;

      /* Left or right? */
      if (bits)
	tindex_right_set(idata, idx, usize, asize, nidx);
      else
	tindex_left_set(idata, idx, usize, asize, nidx);

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
    u64 midx = TINDEX_ALLOC_IDX;

    /* Allocate the new node if it shall exist */
    u64 nidx = split ? TINDEX_ALLOC_IDX : 0;

    /* Relink idx -> midx in the parent node */
    if (uidx)
      tindex_child_update(idata, uidx, usize, asize, addrmask, idx, midx);

    /* Setup the splitting index (midx) */
    tindex_put(idata, midx, usize, asize, dsize, dshift, common, comlen, dataright ? nidx : idx, dataright ? idx : nidx, uidx);

    /* Update the existing index (idx) */
    tindex_put(idata, idx, usize, asize, dsize, dshift, data, dlen, tindex_left(idata, idx, usize, asize, addrmask), tindex_right(idata, idx, usize, asize, addrmask), midx);

    if (split) {
      /* The new parent is the splitting node */
      uidx = midx;

      /* The current node is the newly allocated */
      idx = nidx;

      /* Grow there a branch */
      break;

    } else if (create == TINDEX_CREATE) {
      /* This internal node exists */
      tindex_exists_set(ti, midx);
      return midx;

    } else {
      /* This internal node must be renumbered to the right one */
      tindex_renumber(idata, usize, asize, dsize, dshift, addrmask, midx, create);
      idm_free(&(ti->idm), midx);
      return create;
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
      tindex_put(idata, idx, usize, asize, dsize, dshift, data, ilen, 0, 0, uidx);
      if (create == TINDEX_CREATE) {
	tindex_exists_set(ti, idx);
	return idx;
      } else {
	tindex_renumber(idata, usize, asize, dsize, dshift, addrmask, idx, create);
	return create;
      }
    }

    /* Just one bit. */
    ASSERT(dataright < 2);

    /* Create a new node */
    uint nidx = TINDEX_ALLOC_IDX;

    /* Link it into the trie */
    tindex_put(idata, idx, usize, asize, dsize, dshift, data, ilen, dataright ? 0 : nidx, dataright ? nidx : 0, uidx);

    /* And continue there */
    uidx = idx;
    idx = nidx;
  }

  /* This statement should be unreachable */
  ASSERT(0);

  /* No index available for alloc */
noidx:
  /* This may happen only directly while adding.
   * It should never hapṕen when growing.
   * */
  ASSERT(create == TINDEX_CREATE);

  /* Grow the tindex */
  tindex_grow(ti);

  /* And retry */
  return tindex_find(ti, bits_in, blen, create);
}
