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
  uint bdepth;
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

static inline struct tindex_info
tindex_get_info(const struct tindex *ti)
{
  struct tindex_info stinfo;
  stinfo.asize = ti->address_size;
  stinfo.usize = ti->unit_size;
  stinfo.dsize = stinfo.usize * 8 - stinfo.asize * 3;

  stinfo.dshift = (stinfo.usize % 3) ? (stinfo.asize * 3) : (stinfo.dsize / 3);
  stinfo.addrmask = (1ULL << ti->address_size) - 1;

  return stinfo;
}

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
  ASSERT(tinfo->dsize <= TDB);
  u64 data;
  switch (tinfo->usize) {
    case 4:
      data = id->data4[idx] >> tinfo->dshift;
      break;
    case 6:
      data =
	((u64)(id->data6[idx * 3] >> tinfo->asize) << (tinfo->dshift * 2)) |
	((u64)(id->data6[idx * 3 + 1] >> tinfo->asize) << (tinfo->dshift)) |
	(u64)(id->data6[idx * 3 + 2] >> tinfo->asize);
      break;
    case 8:
      data = id->data8[idx] >> tinfo->dshift;
      break;
    case 12:
      data =
	((u64)(id->data12[idx * 3] >> tinfo->asize) << (tinfo->dshift * 2)) |
	((u64)(id->data12[idx * 3 + 1] >> tinfo->asize) << (tinfo->dshift)) |
	(u64)(id->data12[idx * 3 + 2] >> tinfo->asize);
      break;
    default:
      bug("This shall never happen");
  }

  u64 out = u64_var_decode(data, len);

  if (*len == 64)
    *len = 0;
  else
    *len = tinfo->dsize - *len;

  return out;
}

static inline u64
tindex_left(const union tindex_data *id, const struct tindex_info *tinfo, u64 idx)
{
  switch (tinfo->usize) {
    case 4: return (id->data4[idx] >> (tinfo->asize * 2)) & tinfo->addrmask;
    case 6: return id->data6[idx * 3] & tinfo->addrmask;
    case 8: return (id->data8[idx] >> (tinfo->asize * 2)) & tinfo->addrmask;
    case 12: return id->data12[idx * 3] & tinfo->addrmask;
    default: bug("This shall never happen");
  }
}

static inline u64
tindex_right(const union tindex_data *id, const struct tindex_info *tinfo, u64 idx)
{
  switch (tinfo->usize) {
    case 4: return (id->data4[idx] >> (tinfo->asize)) & tinfo->addrmask;
    case 6: return id->data6[idx * 3 + 1] & tinfo->addrmask;
    case 8: return (id->data8[idx] >> (tinfo->asize)) & tinfo->addrmask;
    case 12: return id->data12[idx * 3 + 1] & tinfo->addrmask;
    default: bug("This shall never happen");
  }
}

static inline u64
tindex_up(const union tindex_data *id, const struct tindex_info *tinfo, u64 idx)
{
  switch (tinfo->usize) {
    case 4: return id->data4[idx] & tinfo->addrmask;
    case 6: return id->data6[idx * 3 + 2] & tinfo->addrmask;
    case 8: return id->data8[idx] & tinfo->addrmask;
    case 12: return id->data12[idx * 3 + 2] & tinfo->addrmask;
    default: bug("This shall never happen");
  }
}

static inline void
tindex_put(union tindex_data *id, const struct tindex_info *tinfo, u64 idx, u64 data, uint dlen, u64 left, u64 right, u64 up)
{
  const u64 dsmask = (1LL << tinfo->dshift) - 1;
  data = u64_var_encode(data, tinfo->dsize - dlen);

  switch (tinfo->usize) {
    case 4:
      id->data4[idx] = (data << tinfo->dshift) | (left << (tinfo->asize * 2)) | (right << tinfo->asize) | up;
      return;
    case 6:
      id->data6[idx * 3    ] = left  | ((data >> (2 * tinfo->dshift)) << tinfo->asize);
      id->data6[idx * 3 + 1] = right | (((data >> tinfo->dshift) & dsmask) << tinfo->asize);
      id->data6[idx * 3 + 2] = up    | ((data & dsmask) << tinfo->asize);
      return;
    case 8:
      id->data8[idx] = (data << tinfo->dshift) | (left << (tinfo->asize * 2)) | (right << tinfo->asize) | up;
      return;
    case 12:
      id->data12[idx * 3    ] = left  | ((data >> (2 * tinfo->dshift)) << tinfo->asize);
      id->data12[idx * 3 + 1] = right | (((data >> tinfo->dshift) & dsmask) << tinfo->asize);
      id->data12[idx * 3 + 2] = up    | ((data & dsmask) << tinfo->asize);
      return;
    default: bug("This shall never happen");
  }
}

static inline void
tindex_left_clear(union tindex_data *id, const struct tindex_info *tinfo, u64 idx)
{
  switch (tinfo->usize) {
    case 4: id->data4[idx] &= ~(tinfo->addrmask << (tinfo->asize * 2)); break;
    case 6: id->data6[idx * 3] &= ~tinfo->addrmask; break;
    case 8: id->data8[idx] &= ~(tinfo->addrmask << (tinfo->asize * 2)); break;
    case 12: id->data12[idx * 3] &= ~tinfo->addrmask; break;
  }
}

static inline void
tindex_right_clear(union tindex_data *id, const struct tindex_info *tinfo, u64 idx)
{
  switch (tinfo->usize) {
    case 4: id->data4[idx] &= ~(tinfo->addrmask << tinfo->asize); break;
    case 6: id->data6[idx * 3 + 1] &= ~tinfo->addrmask; break;
    case 8: id->data8[idx] &= ~(tinfo->addrmask << tinfo->asize); break;
    case 12: id->data12[idx * 3 + 1] &= ~tinfo->addrmask; break;
  }
}

static inline void
tindex_up_clear(union tindex_data *id, const struct tindex_info *tinfo, u64 idx)
{
  switch (tinfo->usize) {
    case 4: id->data4[idx] &= ~tinfo->addrmask; break;
    case 6: id->data6[idx * 3 + 2] &= ~tinfo->addrmask; break;
    case 8: id->data8[idx] &= ~tinfo->addrmask; break;
    case 12: id->data12[idx * 3 + 2] &= ~tinfo->addrmask; break;
  }
}

static inline void
tindex_left_set(union tindex_data *id, const struct tindex_info *tinfo, u64 idx, u64 nidx)
{
  /* The left child must have been zero before */
  switch (tinfo->usize) {
    case 4: id->data4[idx] |= nidx << (tinfo->asize * 2); break;
    case 6: id->data6[idx * 3] |= nidx; break;
    case 8: id->data8[idx] |= nidx << (tinfo->asize * 2); break;
    case 12: id->data12[idx * 3] |= nidx; break;
  }
}

static inline void
tindex_right_set(union tindex_data *id, const struct tindex_info *tinfo, u64 idx, u64 nidx)
{
  /* The right child must have been zero before */
  switch (tinfo->usize) {
    case 4: id->data4[idx] |= nidx << tinfo->asize; break;
    case 6: id->data6[idx * 3 + 1] |= nidx; break;
    case 8: id->data8[idx] |= nidx << tinfo->asize; break;
    case 12: id->data12[idx * 3 + 1] |= nidx; break;
  }
}

static inline void
tindex_up_set(union tindex_data *id, const struct tindex_info *tinfo, u64 idx, u64 nidx)
{
  /* The parent must have been zero before */
  switch (tinfo->usize) {
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
tindex_exists_set(u64 *exists, const u64 idx)
{
  exists[idx / 64] |= (1ULL << (idx % 64));
}

static inline u64
tindex_exists(const u64 *exists, const u64 idx)
{
  return (exists[idx / 64] & (1ULL << (idx % 64)));
}

static inline void
tindex_exists_clear(u64 *exists, const u64 idx)
{
  exists[idx / 64] &= ~(1ULL << (idx % 64));
}

/* Expanded node to an easily accessible structure */
struct tindex_parsed_node {
  u64 idx;
  u64 left;
  u64 right;
  u64 up;
  u64 data;
  uint dlen;
  uint plen;
  uint ndepth;
};

static struct tindex_parsed_node
tindex_parse_node(const union tindex_data *tdata, const struct tindex_info *tinfo, const u64 idx)
{
  struct tindex_parsed_node tpn = {
    .idx = idx,
    .left = tindex_left(tdata, tinfo, idx),
    .right = tindex_right(tdata, tinfo, idx),
    .up = tindex_up(tdata, tinfo, idx),
  };

  tpn.data = tindex_data(tdata, tinfo, idx, &tpn.dlen);
  return tpn;
}

struct tindex_walk {
  const struct tindex_walk_params twp;
  const struct tindex_info tinfo;
  const union tindex_data *tdata;
  const u64 *exists;
  uint pos;
  uint dlen;
  uint tpnlen;
  struct tindex_parsed_node *tpn;
};

struct tindex_walk *
tindex_walk_init(const struct tindex *ti, const struct tindex_walk_params *twp)
{
  struct tindex_walk tmpw = {
    .twp = *twp,
    .tinfo = tindex_get_info(ti),
    .tdata = ti->index_data,
    .exists = ti->exists,
    .tpnlen = 64,
    .tpn = mb_alloc(ti->p, 64 * sizeof(struct tindex_parsed_node)),
  }, *tw = mb_alloc(ti->p, sizeof(struct tindex_walk));

  memcpy(tw, &tmpw, sizeof(struct tindex_walk));

  /* Checking whether begin is in bounds */
  ASSERT(twp->begin);
  ASSERT(twp->begin <= tw->tinfo.addrmask);

  /* Checking that data and dlen are set both or none */
  ASSERT((!twp->data) + (!twp->dlen) != 1);

  /* Load the root node */
  tw->tpn[0] = tindex_parse_node(tw->tdata, &(tw->tinfo), twp->begin);

  /* Find real length of the given begin index */
  for (u64 begin = twp->begin; begin = tindex_up(tw->tdata, &(tw->tinfo), begin); ) {
    uint dtmp;
    tindex_data(tw->tdata, &(tw->tinfo), begin, &dtmp);
    tw->tpn[0].plen += dtmp + 1;
  }

  return tw;
}

void
tindex_walk_free(struct tindex_walk *tw)
{
  /* Free the allocated data structures */
  mb_free(tw->tpn);
  mb_free(tw);
}

u64
tindex_walk_next(struct tindex_walk *tw)
{
  /* While there is something to check ... */
  while (tw->pos + 1) {
    /* Overall prefix length */
    uint plen = tw->tpn[tw->pos].plen + tw->tpn[tw->pos].dlen;

    /* In-trie node depth */
    uint ndepth = tw->tpn[tw->pos].ndepth;

    /* Too long prefix, skip this branch */
    if (plen > tw->twp.maxlen) {
      tw->pos--;
      continue;
    }

    /* Is this node eligible to be returned? */
    u64 idx = 0;
    if (tw->twp.internal || tindex_exists(tw->exists, tw->tpn[tw->pos].idx))
      idx = tw->tpn[tw->pos].idx;

    /* Does the caller want full data? */
    if (tw->twp.data && !plen) {
      /* Zero-length prefix */
      tw->twp.data[0] = 0;
      *tw->twp.dlen = 0;
    } else if (tw->twp.data) {
      /* Non-zero length */
      uint bpos = tw->tpn[tw->pos].plen;
      uint bend = plen - 1;

      /* Mask out the remaining data in the partial uTDB */
      if (bpos % TDB)
	tw->twp.data[bpos / TDB] &= ~((1 << (TDB - (bpos % TDB))) - 1);
      else
	tw->twp.data[bpos / TDB] = 0;

      if (bend / TDB == 1 + bpos / TDB) {
	/* The data must be split between two uTDBs */
	tw->twp.data[bpos / TDB] |= tw->tpn[tw->pos].data >> (1 + bend % TDB);
	tw->twp.data[bend / TDB] = tw->tpn[tw->pos].data << (TDB - 1 - (bend % TDB));
      } else {
	/* Or it fits into one uTDB */
	ASSERT(bend / TDB == bpos / TDB);
	tw->twp.data[bpos / TDB] |= tw->tpn[tw->pos].data << (TDB - 1 - (bend % TDB));
      }

      /* Output also the data length */
      *tw->twp.dlen = plen;
    }

    if (plen == tw->twp.maxlen)
      /* We have exactly the maxlen, no children examined */
      tw->pos--;
    else if (tw->tpn[tw->pos].left && tw->tpn[tw->pos].right) {
      /* Both children exist, expand both */
      if (tw->pos + 1 >= tw->tpnlen)
	tw->tpn = mb_realloc(tw->tpn, (tw->tpnlen *= 2) * sizeof(struct tindex_parsed_node));
	
      tw->tpn[tw->pos + 1] = tindex_parse_node(tw->tdata, &(tw->tinfo), tw->tpn[tw->pos].left);
      tw->tpn[tw->pos + 1].dlen++;
      tw->tpn[tw->pos + 1].plen = plen;
      tw->tpn[tw->pos + 1].ndepth = ndepth + 1;
      tw->tpn[tw->pos] = tindex_parse_node(tw->tdata, &(tw->tinfo), tw->tpn[tw->pos].right);
      tw->tpn[tw->pos].data |= 1 << tw->tpn[tw->pos].dlen++;
      tw->tpn[tw->pos].plen = plen;
      tw->tpn[tw->pos].ndepth = ndepth + 1;
      tw->pos++;
    } else if (tw->tpn[tw->pos].left) {
      /* Only left child exists */
      tw->tpn[tw->pos] = tindex_parse_node(tw->tdata, &(tw->tinfo), tw->tpn[tw->pos].left);
      tw->tpn[tw->pos].dlen++;
      tw->tpn[tw->pos].plen = plen;
      tw->tpn[tw->pos].ndepth = ndepth + 1;
    } else if (tw->tpn[tw->pos].right) {
      /* Only right child exists */
      tw->tpn[tw->pos] = tindex_parse_node(tw->tdata, &(tw->tinfo), tw->tpn[tw->pos].right);
      tw->tpn[tw->pos].data |= 1 << tw->tpn[tw->pos].dlen++;
      tw->tpn[tw->pos].plen = plen;
      tw->tpn[tw->pos].ndepth = ndepth + 1;
    } else
      /* No child at all */
      tw->pos--;

    /* Return the node if it is eligible. */
    if (idx)
      return idx;
  }

  /* Not found any other eligible node. We're done. */
  tindex_walk_free(tw);

  /* And indicate that we're done */
  return 0;
}

const char dump_indent[] = "                                                                ";
#define INDENT(x) (dump_indent + sizeof(dump_indent) - (x) - 1)

void
tindex_dump(const struct tindex *ti)
{
  debug("Trie index; tinfo->usize = %u, tinfo->asize = %u, tinfo->dsize = %u, bdepth = %u\n",
      ti->unit_size, ti->address_size, ti->unit_size * 8 - ti->address_size * 3, ti->bdepth);

  const struct tindex_walk_params twp = {
    .begin = 1,
    .maxlen = TINDEX_WALK_NOMAXLEN,
    .internal = 1,
  };

  struct tindex_walk *tw = tindex_walk_init(ti, &twp);
  while (tw->pos + 1) {
    struct tindex_parsed_node tpn = tw->tpn[tw->pos];
    debug("%s0x%x/%u (%lu %c)\n", INDENT(tpn.ndepth), tpn.data, tpn.dlen, tpn.idx, tindex_exists(ti->exists, tpn.idx) ? '*' : ' ');
    tindex_walk_next(tw);
  }
}

void
tindex_do_grow(struct tindex *ti, const struct tindex_info *tinfo, const uint nusize, const uint nasize)
{
  /* Where to store trie data */
  uTDB *bits = alloca(((ti->bdepth / TDB) + 1)*sizeof(uTDB));
  memset(bits, 0, ((ti->bdepth / TDB) + 1)*sizeof(uTDB));
  uint blen = 0;

  /* Initialize tindex_walk before realloc */
  const struct tindex_walk_params twp = {
    .begin = 1,
    .maxlen = TINDEX_WALK_NOMAXLEN,
    .internal = 1,
    .data = bits,
    .dlen = &blen,
  };
  struct tindex_walk *tw = tindex_walk_init(ti, &twp);
  
  /* Update the size values */
  ti->unit_size = nusize;
  ti->address_size = nasize;

  /* Allocate new index data */
  union tindex_data *odata = ti->index_data;
  ti->index_data = mb_allocz(ti->p, nusize * (1 << nasize));

  /* Grow the bitmask of existing indices */
  u64 *oexists = ti->exists;
  ti->exists = mb_allocz(ti->p, (1 << (nasize - 3)));
  memcpy(ti->exists, oexists, 1 << (tinfo->asize - 3));
  mb_free(oexists);

  /* Update IDM maximum */
  ti->idm.max = 1 << nasize;

  /* Do the migration */
  for (u64 idx; idx = tindex_walk_next(tw); )
    if (idx > 1)
      if (tindex_exists(ti->exists, idx))
	tindex_find(ti, bits, blen, idx);
      else
	idm_free(&(ti->idm), idx);

  /* Free the old index data */
  mb_free(odata);
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

  const struct tindex_info stinfo = tindex_get_info(ti), *tinfo = &stinfo;

  if (tinfo->dsize > 3) {
    /* First we'll try to estimate whether it is feasible to shorten
     * the data part while getting more space for the indices */

    const struct tindex_walk_params twp = {
      .begin = 1,
      .maxlen = TINDEX_WALK_NOMAXLEN,
      .internal = 1,
    };

    u64 needsplit = 0;
    u64 total = 0;

    struct tindex_walk *tw = tindex_walk_init(ti, &twp);
    while (tw->pos + 1) {
      ASSERT(tw->tpn[tw->pos].dlen <= tinfo->dsize);
      if (tw->tpn[tw->pos].dlen > tinfo->dsize - 3)
	needsplit++;
      total++;
      tindex_walk_next(tw);
    }

    /* After shortening the data part, needsplit/total nodes will duplicate (or triplicate!).
     * If the overall index usage goes up by at most 20% by doing this change,
     * we consider it feasible. By math:
     *
     * ((float)(needsplit / total)) * ((int)(tinfo->dsize / (tinfo->dsize - 3)) + 1) < 0.2
     * needsplit * ((tinfo->dsize / (tinfo->dsize - 3)) + 1) < 0.2 * total
     * 5 * needsplit * ((tinfo->dsize / (tinfo->dsize - 3)) + 1) < total
     */

    const uint dsmul = ((tinfo->dsize / (tinfo->dsize - 3)) + 1) * 5;

    if (needsplit * dsmul < total)
      return tindex_do_grow(ti, tinfo, ti->unit_size, ti->address_size + 1);
  }

  /* It is not feasible to shorten the data part. Increasting the unit size. */
  switch (tinfo->usize) {
#define GROW(usize) tindex_do_grow(ti, tinfo, usize, (1+MAX((((usize-4)*8)/3),ti->address_size)))
    case 4: return GROW(6);
    case 6: return GROW(8);
    case 8: return GROW(12);
    case 12: bug("Not implemented yet.");
    default: bug("This shall not happen.");
#undef GROW
  }
}

static inline void
tindex_renumber(union tindex_data *idata, const struct tindex_info *tinfo, u64 oidx, u64 nidx)
{
  u64 up = tindex_up(idata, tinfo, oidx);
  u64 left = tindex_left(idata, tinfo, oidx);
  u64 right = tindex_right(idata, tinfo, oidx);

  if (up)
    tindex_child_update(idata, tinfo, up, oidx, nidx);

  if (left) {
    tindex_up_clear(idata, tinfo, left);
    tindex_up_set(idata, tinfo, left, nidx);
  }

  if (right) {
    tindex_up_clear(idata, tinfo, right);
    tindex_up_set(idata, tinfo, right, nidx);
  }

  switch (tinfo->usize) {
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
tindex_find_rel_path(struct tindex *ti, const u64 sidx, const uTDB *bits_in, const uint blen, uint bpos, u64 *path, const u64 create)
{
  if (blen > ti->bdepth)
    if (create)
      ti->bdepth = blen;
    else
      return 0;

  union tindex_data *idata = ti->index_data;
  const struct tindex_info stinfo = tindex_get_info(ti), *tinfo = &stinfo;

  ASSERT(sidx > 0);
  ASSERT(sidx <= tinfo->addrmask);

  /* Validate unit size */
  switch (tinfo->usize) {
    case 4:
    case 6:
    case 8:
    case 12: break;
    default: bug("This shall never happen");
  }

  /* Here we begin */
  u64 idx = sidx;
  u64 uidx = tindex_up(idata, tinfo, idx);

  if (path)
    memset(&(path[bpos]), 0, (blen - bpos) * sizeof(u64));

  /* Shortcut for zero-length query */
  if (blen == bpos)
    return tindex_exists(ti->exists, idx) ? idx : 0;

  while (1) {
    /* Get data from trie */
    uint dlen;
    u64 data = tindex_data(idata, tinfo, idx, &dlen);

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
	  tindex_exists_set(ti->exists, idx);
	  return idx;
	} else if (create) {
	  /* Migration from old version -> renumber */
	  tindex_renumber(idata, tinfo, idx, create);
	  idm_free(&(ti->idm), idx);
	  return create;
	} else if (tindex_exists(ti->exists, idx))
	  /* Shan't create but it already exists */
	  return idx;
	else
	  return 0;
      }

      /* This is not final for sure, store the path node */
      if (path && tindex_exists(ti->exists, idx))
	path[bpos] = idx;

      /* Just one bit, to be sure */
      ASSERT(bits < 2);
      ASSERT(ilen == 1);

      /* Go left or right? */
      u64 nidx = bits ? tindex_right(idata, tinfo, idx) : tindex_left(idata, tinfo, idx);

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
	tindex_right_set(idata, tinfo, idx, nidx);
      else
	tindex_left_set(idata, tinfo, idx, nidx);

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
      tindex_child_update(idata, tinfo, uidx, idx, midx);

    /* Setup the splitting index (midx) */
    tindex_put(idata, tinfo, midx, common, comlen, dataright ? nidx : idx, dataright ? idx : nidx, uidx);

    /* Update the existing index (idx) */
    tindex_put(idata, tinfo, idx, data, dlen, tindex_left(idata, tinfo, idx), tindex_right(idata, tinfo, idx), midx);

    if (split) {
      /* The new parent is the splitting node */
      uidx = midx;

      /* The current node is the newly allocated */
      idx = nidx;

      /* Grow there a branch */
      break;

    } else if (create == TINDEX_CREATE) {
      /* This internal node exists */
      tindex_exists_set(ti->exists, midx);
      return midx;

    } else {
      /* This internal node must be renumbered to the right one */
      tindex_renumber(idata, tinfo, midx, create);
      idm_free(&(ti->idm), midx);
      return create;
    }
  }

  /* Growing a new branch */
  while (1) {
    /* Get more data from input */
    u64 data;
    uint ilen = tindex_input_bits(bits_in, blen, &bpos, tinfo->dsize - 1, &data);

    /* For the single bit */
    u64 dataright = ~0;

    /* End of input data */
    if ((ilen < tinfo->dsize - 1) || !tindex_input_bits(bits_in, blen, &bpos, 1, &dataright)) {
      tindex_put(idata, tinfo, idx, data, ilen, 0, 0, uidx);
      if (create == TINDEX_CREATE) {
	tindex_exists_set(ti->exists, idx);
	return idx;
      } else {
	tindex_renumber(idata, tinfo, idx, create);
	return create;
      }
    }

    /* Just one bit. */
    ASSERT(dataright < 2);

    /* Create a new node */
    uint nidx = TINDEX_ALLOC_IDX;

    /* Link it into the trie */
    tindex_put(idata, tinfo, idx, data, ilen, dataright ? 0 : nidx, dataright ? nidx : 0, uidx);

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
