/*
 *	BIRD -- Path Operations
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *	(c) 2000 Pavel Machek <pavel@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/attrs.h"
#include "lib/resource.h"
#include "lib/unaligned.h"
#include "lib/string.h"
#include "filter/data.h"

// static inline void put_as(byte *data, u32 as) { put_u32(data, as); }
// static inline u32 get_as(byte *data) { return get_u32(data); }

#define put_as put_u32
#define get_as get_u32
#define BS  4	/* Default block size of ASN (autonomous system number) */

#define BAD(DSC, VAL) ({ err_dsc = DSC; err_val = VAL; goto bad; })

int
as_path_valid(byte *data, uint len, int bs, int confed, char *err, uint elen)
{
  byte *pos = data;
  char *err_dsc = NULL;
  uint err_val = 0;

  while (len)
  {
    if (len < 2)
      BAD("segment framing error", 0);

    /* Process one AS path segment */
    uint type = pos[0];
    uint slen = 2 + bs * pos[1];

    if (len < slen)
      BAD("segment framing error", len);

    switch (type)
    {
    case AS_PATH_SET:
    case AS_PATH_SEQUENCE:
      break;

    case AS_PATH_CONFED_SEQUENCE:
    case AS_PATH_CONFED_SET:
      if (!confed)
	BAD("AS_CONFED* segment", type);
      break;

    default:
      BAD("unknown segment", type);
    }

    if (pos[1] == 0)
      BAD("zero-length segment", type);

    pos += slen;
    len -= slen;
  }

  return 1;

bad:
  if (err)
    if (bsnprintf(err, elen, "%s (%u) at %d", err_dsc, err_val, (int) (pos - data)) < 0)
      err[0] = 0;

  return 0;
}

int
as_path_16to32(byte *dst, const byte *src, uint len)
{
  byte *dst0 = dst;
  const byte *end = src + len;
  uint i, n;

  while (src < end)
  {
    n = src[1];
    *dst++ = *src++;
    *dst++ = *src++;

    for (i = 0; i < n; i++)
    {
      put_u32(dst, get_u16(src));
      src += 2;
      dst += 4;
    }
  }

  return dst - dst0;
}

int
as_path_32to16(byte *dst, const byte *src, uint len)
{
  byte *dst0 = dst;
  const byte *end = src + len;
  uint i, n;

  while (src < end)
  {
    n = src[1];
    *dst++ = *src++;
    *dst++ = *src++;

    for (i = 0; i < n; i++)
    {
      put_u16(dst, get_u32(src));
      src += 4;
      dst += 2;
    }
  }

  return dst - dst0;
}

int
as_path_contains_as4(const struct adata *path)
{
  const byte *pos = path->data;
  const byte *end = pos + path->length;
  uint i, n;

  while (pos < end)
  {
    n = pos[1];
    pos += 2;

    for (i = 0; i < n; i++)
    {
      if (get_as(pos) > 0xFFFF)
	return 1;

      pos += BS;
    }
  }

  return 0;
}

int
as_path_contains_confed(const struct adata *path)
{
  const byte *pos = path->data;
  const byte *end = pos + path->length;

  while (pos < end)
  {
    uint type = pos[0];
    uint slen = 2 + BS * pos[1];

    if ((type == AS_PATH_CONFED_SEQUENCE) ||
	(type == AS_PATH_CONFED_SET))
      return 1;

    pos += slen;
  }

  return 0;
}

struct adata *
as_path_strip_confed(struct linpool *pool, const struct adata *path)
{
  struct adata *res = lp_alloc_adata(pool, path->length);
  const byte *src = path->data;
  const byte *end = src + path->length;
  byte *dst = res->data;

  while (src < end)
  {
    uint type = src[0];
    uint slen = 2 + BS * src[1];

    /* Copy regular segments */
    if ((type == AS_PATH_SET) || (type == AS_PATH_SEQUENCE))
    {
      memcpy(dst, src, slen);
      dst += slen;
    }

    src += slen;
  }

  /* Fix the result length */
  res->length = dst - res->data;

  return res;
}

struct adata *
as_path_prepend2(struct linpool *pool, const struct adata *op, int seq, u32 as)
{
  struct adata *np;
  const byte *pos = op->data;
  uint len = op->length;

  if (len && (pos[0] == seq) && (pos[1] < 255))
  {
    /* Starting with matching segment => just prepend the AS number */
    np = lp_alloc_adata(pool, len + BS);
    np->data[0] = seq;
    np->data[1] = pos[1] + 1;
    put_as(np->data + 2, as);

    uint dlen = BS * pos[1];
    memcpy(np->data + 2 + BS, pos + 2, dlen);
    ADVANCE(pos, len, 2 + dlen);
  }
  else
  {
    /* Create a new path segment */
    np = lp_alloc_adata(pool, len + 2 + BS);
    np->data[0] = seq;
    np->data[1] = 1;
    put_as(np->data + 2, as);
  }

  if (len)
  {
    byte *dst = np->data + 2 + BS * np->data[1];

    memcpy(dst, pos, len);
  }

  return np;
}


struct adata *
as_path_to_old(struct linpool *pool, const struct adata *path)
{
  struct adata *res = lp_alloc_adata(pool, path->length);
  byte *pos = res->data;
  byte *end = pos + res->length;
  uint i, n;
  u32 as;

  /* Copy the whole path */
  memcpy(res->data, path->data, path->length);

  /* Replace 32-bit AS numbers with AS_TRANS */
  while (pos < end)
  {
    n = pos[1];
    pos += 2;

    for (i = 0; i < n; i++)
    {
      as = get_as(pos);
      if (as > 0xFFFF)
	put_as(pos, AS_TRANS);

      pos += BS;
    }
  }

  return res;
}

/*
 * Cut the path to the length @num, measured to the usual path metric. Note that
 * AS_CONFED_* segments have zero length and must be added if they are on edge.
 */
struct adata *
as_path_cut(struct linpool *pool, const struct adata *path, uint num)
{
  const byte *pos = path->data;
  const byte *end = pos + path->length;

  while (pos < end)
  {
    uint t = pos[0];
    uint l = pos[1];
    uint n = 0;

    switch (t)
    {
    case AS_PATH_SET:			n = 1; break;
    case AS_PATH_SEQUENCE:		n = l; break;
    case AS_PATH_CONFED_SEQUENCE:	n = 0; break;
    case AS_PATH_CONFED_SET:		n = 0; break;
    default: bug("as_path_cut: Invalid path segment");
    }

    /* Cannot add whole segment, so try partial one and finish */
    if (num < n)
    {
      const byte *nend = pos;
      if (num)
	nend += 2 + BS * num;

      struct adata *res = lp_alloc_adata(pool, path->length);
      res->length = nend - (const byte *) path->data;
      memcpy(res->data, path->data, res->length);

      if (num)
      {
	byte *dpos = ((byte *) res->data) + (pos - (const byte *) path->data);
	dpos[1] = num;
      }

      return res;
    }

    num -= n;
    pos += 2 + BS * l;
  }

  struct adata *res = lp_alloc_adata(pool, path->length);
  res->length = path->length;
  memcpy(res->data, path->data, res->length);
  return res;
}

/*
 * Merge (concatenate) paths @p1 and @p2 and return the result.
 * In contrast to other as_path_* functions, @p1 and @p2 may be reused.
 */
const struct adata *
as_path_merge(struct linpool *pool, const struct adata *p1, const struct adata *p2)
{
  if (p1->length == 0)
    return p2;

  if (p2->length == 0)
    return p1;

  struct adata *res = lp_alloc_adata(pool, p1->length + p2->length);
  memcpy(res->data, p1->data, p1->length);
  memcpy(res->data + p1->length, p2->data, p2->length);

  return res;
}

void
as_path_format(const struct adata *path, byte *bb, uint size)
{
  buffer buf = { .start = bb, .pos = bb, .end = bb + size }, *b = &buf;
  const byte *pos = path->data;
  const byte *end = pos + path->length;
  const char *ops, *cls;

  b->pos[0] = 0;

  while (pos < end)
  {
    uint type = pos[0];
    uint len  = pos[1];
    pos += 2;

    switch (type)
    {
    case AS_PATH_SET:			ops = "{";	cls = "}";	break;
    case AS_PATH_SEQUENCE:		ops = NULL;	cls = NULL;	break;
    case AS_PATH_CONFED_SEQUENCE:	ops = "(";	cls = ")";	break;
    case AS_PATH_CONFED_SET:		ops = "({";	cls = "})";	break;
    default: bug("Invalid path segment");
    }

    if (ops)
      buffer_puts(b, ops);

    while (len--)
    {
      buffer_print(b, len ? "%u " : "%u", get_as(pos));
      pos += BS;
    }

    if (cls)
      buffer_puts(b, cls);

    if (pos < end)
      buffer_puts(b, " ");
  }

  /* Handle overflow */
  if (b->pos == b->end)
    strcpy(b->end - 12, "...");
}

int
as_path_getlen(const struct adata *path)
{
  const byte *pos = path->data;
  const byte *end = pos + path->length;
  uint res = 0;

  while (pos < end)
  {
    uint t = pos[0];
    uint l = pos[1];
    uint n = 0;

    switch (t)
    {
    case AS_PATH_SET:			n = 1; break;
    case AS_PATH_SEQUENCE:		n = l; break;
    case AS_PATH_CONFED_SEQUENCE:	n = 0; break;
    case AS_PATH_CONFED_SET:		n = 0; break;
    default: bug("as_path_getlen: Invalid path segment");
    }

    res += n;
    pos += 2 + BS * l;
  }

  return res;
}

int
as_path_get_last(const struct adata *path, u32 *orig_as)
{
  const byte *pos = path->data;
  const byte *end = pos + path->length;
  int found = 0;
  u32 val = 0;

  while (pos < end)
  {
    uint type = pos[0];
    uint len  = pos[1];
    pos += 2;

    if (!len)
      continue;

    switch (type)
    {
    case AS_PATH_SET:
    case AS_PATH_CONFED_SET:
      found = 0;
      break;

    case AS_PATH_SEQUENCE:
    case AS_PATH_CONFED_SEQUENCE:
      val = get_as(pos + BS * (len - 1));
      found = 1;
      break;

    default:
      bug("Invalid path segment");
    }

    pos += BS * len;
  }

  if (found)
    *orig_as = val;
  return found;
}

u32
as_path_get_last_nonaggregated(const struct adata *path)
{
  const byte *pos = path->data;
  const byte *end = pos + path->length;
  u32 val = 0;

  while (pos < end)
  {
    uint type = pos[0];
    uint len  = pos[1];
    pos += 2;

    if (!len)
      continue;

    switch (type)
    {
    case AS_PATH_SET:
    case AS_PATH_CONFED_SET:
      return val;

    case AS_PATH_SEQUENCE:
    case AS_PATH_CONFED_SEQUENCE:
      val = get_as(pos + BS * (len - 1));
      break;

    default:
      bug("Invalid path segment");
    }

    pos += BS * len;
  }

  return val;
}

int
as_path_get_first(const struct adata *path, u32 *last_as)
{
  const u8 *p = path->data;

  if ((path->length == 0) || (p[0] != AS_PATH_SEQUENCE) || (p[1] == 0))
    return 0;

  *last_as = get_as(p+2);
  return 1;
}

int
as_path_get_first_regular(const struct adata *path, u32 *last_as)
{
  const byte *pos = path->data;
  const byte *end = pos + path->length;

  while (pos < end)
  {
    uint type = pos[0];
    uint len  = pos[1];
    pos += 2;

    switch (type)
    {
    case AS_PATH_SET:
      return 0;

    case AS_PATH_SEQUENCE:
      if (len == 0)
	return 0;

      *last_as = get_as(pos);
      return 1;

    case AS_PATH_CONFED_SEQUENCE:
    case AS_PATH_CONFED_SET:
      break;

    default:
      bug("Invalid path segment");
    }

    pos += BS * len;
  }

  return 0;
}

int
as_path_contains(const struct adata *path, u32 as, int min)
{
  const u8 *p = path->data;
  const u8 *q = p+path->length;
  int num = 0;
  int i, n;

  while (p<q)
    {
      n = p[1];
      p += 2;
      for(i=0; i<n; i++)
	{
	  if (get_as(p) == as)
	    if (++num == min)
	      return 1;
	  p += BS;
	}
    }
  return 0;
}

int
as_path_match_set(const struct adata *path, const struct f_tree *set)
{
  const u8 *p = path->data;
  const u8 *q = p+path->length;
  int i, n;

  while (p<q)
    {
      n = p[1];
      p += 2;
      for (i=0; i<n; i++)
	{
	  struct f_val v = {T_INT, .val.i = get_as(p)};
	  if (find_tree(set, &v))
	    return 1;
	  p += BS;
	}
    }

  return 0;
}

const struct adata *
as_path_filter(struct linpool *pool, const struct adata *path, const struct f_tree *set, u32 key, int pos)
{
  if (!path)
    return NULL;

  int len = path->length;
  const u8 *p = path->data;
  const u8 *q = path->data + len;
  u8 *d, *d2;
  int i, bt, sn, dn;
  u8 buf[len];

  d = buf;
  while (p<q)
    {
      /* Read block header (type and length) */
      bt = p[0];
      sn = p[1];
      dn = 0;
      p += 2;
      d2 = d + 2;

      for (i = 0; i < sn; i++)
	{
	  u32 as = get_as(p);
	  int match;

	  if (set)
	    {
	      struct f_val v = {T_INT, .val.i = as};
	      match = !!find_tree(set, &v);
	    }
	  else
	    match = (as == key);

	  if (match == pos)
	    {
	      put_as(d2, as);
	      d2 += BS;
	      dn++;
	    }

	  p += BS;
	}

      if (dn > 0)
	{
	  /* Nonempty block, set block header and advance */
	  d[0] = bt;
	  d[1] = dn;
	  d = d2;
	}
  }

  uint nl = d - buf;
  if (nl == path->length)
    return path;

  struct adata *res = lp_alloc(pool, sizeof(struct adata) + nl);
  res->length = nl;
  memcpy(res->data, buf, nl);

  return res;
}


struct pm_pos
{
  u8 set;
  u8 mark;
  union
  {
    const char *sp;
    u32 asn;
  } val;
};

static int
parse_path(const struct adata *path, struct pm_pos *pp)
{
  const byte *pos = path->data;
  const byte *end = pos + path->length;
  struct pm_pos *op = pp;
  uint i;

  while (pos < end)
  {
    uint type = pos[0];
    uint len  = pos[1];
    pos += 2;

    switch (type)
    {
    case AS_PATH_SET:
    case AS_PATH_CONFED_SET:
      pp->set = 1;
      pp->mark = 0;
      pp->val.sp = pos - 1;
      pp++;

      pos += BS * len;
      break;

    case AS_PATH_SEQUENCE:
    case AS_PATH_CONFED_SEQUENCE:
      for (i = 0; i < len; i++)
      {
	pp->set = 0;
	pp->mark = 0;
	pp->val.asn = get_as(pos);
	pp++;

	pos += BS;
      }
      break;

    default:
      bug("Invalid path segment");
    }
  }

  return pp - op;
}

static int
pm_match(struct pm_pos *pos, u32 asn, u32 asn2)
{
  u32 gas;
  if (! pos->set)
    return ((pos->val.asn >= asn) && (pos->val.asn <= asn2));

  const u8 *p = pos->val.sp;
  int len = *p++;
  int i;

  for (i = 0; i < len; i++)
  {
    gas = get_as(p + i * BS);

    if ((gas >= asn) && (gas <= asn2))
      return 1;
  }

  return 0;
}

static int
pm_match_set(struct pm_pos *pos, const struct f_tree *set)
{
  struct f_val asn = { .type = T_INT };

  if (! pos->set)
  {
    asn.val.i = pos->val.asn;
    return !!find_tree(set, &asn);
  }

  const u8 *p = pos->val.sp;
  int len = *p++;
  int i;

  for (i = 0; i < len; i++)
  {
    asn.val.i = get_as(p + i * BS);
    if (find_tree(set, &asn))
      return 1;
  }

  return 0;
}

static void
pm_mark(struct pm_pos *pos, int i, int plen, int *nl, int *nh)
{
  int j;

  if (pos[i].set)
    pos[i].mark = 1;

  for (j = i + 1; (j < plen) && pos[j].set && (! pos[j].mark); j++)
    pos[j].mark = 1;
  pos[j].mark = 1;

  /* We are going downwards, therefore every mark is
     new low and just the first mark is new high */

  *nl = i + (pos[i].set ? 0 : 1);

  if (*nh < 0)
    *nh = j;
}

/* AS path matching is nontrivial. Because AS path can
 * contain sets, it is not a plain wildcard matching. A set
 * in an AS path is interpreted as it might represent any
 * sequence of AS numbers from that set (possibly with
 * repetitions). So it is also a kind of a pattern,
 * more complicated than a path mask.
 *
 * The algorithm for AS path matching is a variant
 * of nondeterministic finite state machine, where
 * positions in AS path are states, and items in
 * path mask are input for that finite state machine.
 * During execution of the algorithm we maintain a set
 * of marked states - a state is marked if it can be
 * reached by any walk through NFSM with regard to
 * currently processed part of input. When we process
 * next part of mask, we advance each marked state.
 * We start with marked first position, when we
 * run out of marked positions, we reject. When
 * we process the whole mask, we accept if final position
 * (auxiliary position after last real position in AS path)
 * is marked.
 */
int
as_path_match(const struct adata *path, const struct f_path_mask *mask)
{
  struct pm_pos pos[2048 + 1];
  int plen = parse_path(path, pos);
  int l, h, i, nh, nl;
  u32 val = 0;
  u32 val2 = 0;

  /* l and h are bound of interval of positions where
     are marked states */

  pos[plen].set = 0;
  pos[plen].mark = 0;

  l = h = 0;
  pos[0].mark = 1;

  for (uint m=0; m < mask->len; m++)
    {
      /* We remove this mark to not step after pos[plen] */
      pos[plen].mark = 0;

      switch (mask->item[m].kind)
	{
	case PM_ASTERISK:
	  for (i = l; i <= plen; i++)
	    pos[i].mark = 1;
	  h = plen;
	  break;

	case PM_ASN:	/* Define single ASN as ASN..ASN - very narrow interval */
	  val2 = val = mask->item[m].asn;
	  goto step;
	case PM_ASN_EXPR:
	  bug("Expressions should be evaluated on AS path mask construction.");
	case PM_ASN_RANGE:
	  val = mask->item[m].from;
	  val2 = mask->item[m].to;
	  goto step;
	case PM_QUESTION:
	case PM_ASN_SET:
	step:
	  nh = nl = -1;
	  for (i = h; i >= l; i--)
	    if (pos[i].mark)
	      {
		pos[i].mark = 0;
		if ((mask->item[m].kind == PM_QUESTION) ||
		    ((mask->item[m].kind != PM_ASN_SET) ?
		     pm_match(pos + i, val, val2) :
		     pm_match_set(pos + i, mask->item[m].set)))
		  pm_mark(pos, i, plen, &nl, &nh);
	      }

	  if (nh < 0)
	    return 0;

	  h = nh;
	  l = nl;
	  break;
	}
    }

  return pos[plen].mark;
}
