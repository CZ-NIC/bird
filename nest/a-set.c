/*
 *	BIRD -- Set/Community-list Operations
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *	(c) 2000 Pavel Machek <pavel@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/attrs.h"
#include "lib/resource.h"
#include "lib/string.h"

/**
 * int_set_format - format an &set for printing
 * @set: set attribute to be formatted
 * @way: style of format (0 for router ID list, 1 for community list)
 * @from: starting position in set
 * @buf: destination buffer
 * @size: size of buffer
 *
 * This function takes a set attribute and formats it. @way specifies
 * the style of format (router ID / community). @from argument can be
 * used to specify the first printed value for the purpose of printing
 * untruncated sets even with smaller buffers. If the output fits in
 * the buffer, 0 is returned, otherwise the position of the first not
 * printed item is returned. This value can be used as @from argument
 * in subsequent calls. If truncated output suffices, -1 can be
 * instead used as @from, in that case " ..." is eventually added at
 * the buffer to indicate truncation.
 */
int
int_set_format(const struct adata *set, int way, int from, byte *buf, uint size)
{
  u32 *z = (u32 *) set->data;
  byte *end = buf + size - 24;
  int from2 = MAX(from, 0);
  int to = set->length / 4;
  int i;

  for (i = from2; i < to; i++)
    {
      if (buf > end)
	{
	  if (from < 0)
	    strcpy(buf, " ...");
	  else
	    *buf = 0;
	  return i;
	}

      if (i > from2)
	*buf++ = ' ';

      if (way)
	buf += bsprintf(buf, "(%d,%d)", z[i] >> 16, z[i] & 0xffff);
      else
	buf += bsprintf(buf, "%R", z[i]);
    }
  *buf = 0;
  return 0;
}

int
ec_format(byte *buf, u64 ec)
{
  u32 type, key, val;
  char tbuf[16];
  const char *kind;

  type = ec >> 48;
  kind = ec_subtype_str(type & 0xf0ff);

  if (!kind) {
    bsprintf(tbuf, "unknown 0x%x", type);
    kind = tbuf;
  }

  switch (ec >> 56)
    {
      /* RFC 4360 3.1.  Two-Octet AS Specific Extended Community */
    case 0x00:
    case 0x40:
      key = (ec >> 32) & 0xFFFF;
      val = ec;
      return bsprintf(buf, "(%s, %u, %u)", kind, key, val);

      /* RFC 4360 3.2.  IPv4 Address Specific Extended Community */
    case 0x01:
    case 0x41:
      key = ec >> 16;
      val = ec & 0xFFFF;
      return bsprintf(buf, "(%s, %R, %u)", kind, key, val);

      /* RFC 5668  4-Octet AS Specific BGP Extended Community */
    case 0x02:
    case 0x42:
      key = ec >> 16;
      val = ec & 0xFFFF;
      return bsprintf(buf, "(%s, %u, %u)", kind, key, val);

      /* Generic format for unknown kinds of extended communities */
    default:
      key = ec >> 32;
      val = ec;
      return bsprintf(buf, "(generic, 0x%x, 0x%x)", key, val);
    }

}

int
ec_set_format(const struct adata *set, int from, byte *buf, uint size)
{
  u32 *z = int_set_get_data(set);
  byte *end = buf + size - 64;
  int from2 = MAX(from, 0);
  int to = int_set_get_size(set);
  int i;

  for (i = from2; i < to; i += 2)
    {
      if (buf > end)
	{
	  if (from < 0)
	    strcpy(buf, " ...");
	  else
	    *buf = 0;
	  return i;
	}

      if (i > from2)
	*buf++ = ' ';

      buf += ec_format(buf, ec_get(z, i));
    }
  *buf = 0;
  return 0;
}

int
lc_format(byte *buf, lcomm lc)
{
  return bsprintf(buf, "(%u, %u, %u)", lc.asn, lc.ldp1, lc.ldp2);
}

int
lc_set_format(const struct adata *set, int from, byte *buf, uint bufsize)
{
  u32 *d = (u32 *) set->data;
  byte *end = buf + bufsize - 64;
  int from2 = MAX(from, 0);
  int to = set->length / 4;
  int i;

  for (i = from2; i < to; i += 3)
    {
      if (buf > end)
	{
	  if (from < 0)
	    strcpy(buf, "...");
	  else
	    buf[-1] = 0;
	  return i;
	}

      buf += bsprintf(buf, "(%u, %u, %u)", d[i], d[i+1], d[i+2]);
      *buf++ = ' ';
    }

  if (i != from2)
    buf--;

  *buf = 0;
  return 0;
}

int
int_set_contains(const struct adata *list, u32 val)
{
  if (!list)
    return 0;

  u32 *l = (u32 *) list->data;
  int len = int_set_get_size(list);
  int i;

  for (i = 0; i < len; i++)
    if (*l++ == val)
      return 1;

  return 0;
}

int
ec_set_contains(const struct adata *list, u64 val)
{
  if (!list)
    return 0;

  u32 *l = int_set_get_data(list);
  int len = int_set_get_size(list);
  u32 eh = ec_hi(val);
  u32 el = ec_lo(val);
  int i;

  for (i=0; i < len; i += 2)
    if (l[i] == eh && l[i+1] == el)
      return 1;

  return 0;
}

int
lc_set_contains(const struct adata *list, lcomm val)
{
  if (!list)
    return 0;

  u32 *l = int_set_get_data(list);
  int len = int_set_get_size(list);
  int i;

  for (i = 0; i < len; i += 3)
    if (lc_match(l, i, val))
      return 1;

  return 0;
}

const struct adata *
int_set_prepend(struct linpool *pool, const struct adata *list, u32 val)
{
  struct adata *res;
  int len;

  if (int_set_contains(list, val))
    return list;

  len = list ? list->length : 0;
  res = lp_alloc(pool, sizeof(struct adata) + len + 4);
  res->length = len + 4;

  if (list)
    memcpy(res->data + 4, list->data, list->length);

  * (u32 *) res->data = val;

  return res;
}

const struct adata *
int_set_add(struct linpool *pool, const struct adata *list, u32 val)
{
  struct adata *res;
  int len;

  if (int_set_contains(list, val))
    return list;

  len = list ? list->length : 0;
  res = lp_alloc(pool, sizeof(struct adata) + len + 4);
  res->length = len + 4;

  if (list)
    memcpy(res->data, list->data, list->length);

  * (u32 *) (res->data + len) = val;

  return res;
}

const struct adata *
ec_set_add(struct linpool *pool, const struct adata *list, u64 val)
{
  if (ec_set_contains(list, val))
    return list;

  int olen = list ? list->length : 0;
  struct adata *res = lp_alloc(pool, sizeof(struct adata) + olen + 8);
  res->length = olen + 8;

  if (list)
    memcpy(res->data, list->data, list->length);

  u32 *l = (u32 *) (res->data + olen);
  l[0] = ec_hi(val);
  l[1] = ec_lo(val);

  return res;
}

const struct adata *
lc_set_add(struct linpool *pool, const struct adata *list, lcomm val)
{
  if (lc_set_contains(list, val))
    return list;

  int olen = list ? list->length : 0;
  struct adata *res = lp_alloc(pool, sizeof(struct adata) + olen + LCOMM_LENGTH);
  res->length = olen + LCOMM_LENGTH;

  if (list)
    memcpy(res->data, list->data, list->length);

  lc_put((u32 *) (res->data + olen), val);

  return res;
}

const struct adata *
int_set_del(struct linpool *pool, const struct adata *list, u32 val)
{
  if (!int_set_contains(list, val))
    return list;

  struct adata *res;
  res = lp_alloc(pool, sizeof(struct adata) + list->length - 4);
  res->length = list->length - 4;

  u32 *l = int_set_get_data(list);
  u32 *k = int_set_get_data(res);
  int len = int_set_get_size(list);
  int i;

  for (i = 0; i < len; i++)
    if (l[i] != val)
      *k++ = l[i];

  return res;
}

const struct adata *
ec_set_del(struct linpool *pool, const struct adata *list, u64 val)
{
  if (!ec_set_contains(list, val))
    return list;

  struct adata *res;
  res = lp_alloc(pool, sizeof(struct adata) + list->length - 8);
  res->length = list->length - 8;

  u32 *l = int_set_get_data(list);
  u32 *k = int_set_get_data(res);
  int len = int_set_get_size(list);
  u32 eh = ec_hi(val);
  u32 el = ec_lo(val);
  int i;

  for (i=0; i < len; i += 2)
    if (! (l[i] == eh && l[i+1] == el))
      {
	*k++ = l[i];
	*k++ = l[i+1];
      }

  return res;
}

const struct adata *
lc_set_del(struct linpool *pool, const struct adata *list, lcomm val)
{
  if (!lc_set_contains(list, val))
    return list;

  struct adata *res;
  res = lp_alloc(pool, sizeof(struct adata) + list->length - LCOMM_LENGTH);
  res->length = list->length - LCOMM_LENGTH;

  u32 *l = int_set_get_data(list);
  u32 *k = int_set_get_data(res);
  int len = int_set_get_size(list);
  int i;

  for (i=0; i < len; i += 3)
    if (! lc_match(l, i, val))
      k = lc_copy(k, l+i);

  return res;
}

const struct adata *
int_set_union(struct linpool *pool, const struct adata *l1, const struct adata *l2)
{
  if (!l1)
    return l2;
  if (!l2)
    return l1;

  struct adata *res;
  int len = int_set_get_size(l2);
  u32 *l = int_set_get_data(l2);
  u32 tmp[len];
  u32 *k = tmp;
  int i;

  for (i = 0; i < len; i++)
    if (!int_set_contains(l1, l[i]))
      *k++ = l[i];

  if (k == tmp)
    return l1;

  len = (k - tmp) * 4;
  res = lp_alloc(pool, sizeof(struct adata) + l1->length + len);
  res->length = l1->length + len;
  memcpy(res->data, l1->data, l1->length);
  memcpy(res->data + l1->length, tmp, len);
  return res;
}

const struct adata *
ec_set_union(struct linpool *pool, const struct adata *l1, const struct adata *l2)
{
  if (!l1)
    return l2;
  if (!l2)
    return l1;

  struct adata *res;
  int len = int_set_get_size(l2);
  u32 *l = int_set_get_data(l2);
  u32 tmp[len];
  u32 *k = tmp;
  int i;

  for (i = 0; i < len; i += 2)
    if (!ec_set_contains(l1, ec_get(l, i)))
      {
	*k++ = l[i];
	*k++ = l[i+1];
      }

  if (k == tmp)
    return l1;

  len = (k - tmp) * 4;
  res = lp_alloc(pool, sizeof(struct adata) + l1->length + len);
  res->length = l1->length + len;
  memcpy(res->data, l1->data, l1->length);
  memcpy(res->data + l1->length, tmp, len);
  return res;
}

const struct adata *
lc_set_union(struct linpool *pool, const struct adata *l1, const struct adata *l2)
{
  if (!l1)
    return l2;
  if (!l2)
    return l1;

  struct adata *res;
  int len = int_set_get_size(l2);
  u32 *l = int_set_get_data(l2);
  u32 tmp[len];
  u32 *k = tmp;
  int i;

  for (i = 0; i < len; i += 3)
    if (!lc_set_contains(l1, lc_get(l, i)))
      k = lc_copy(k, l+i);

  if (k == tmp)
    return l1;

  len = (k - tmp) * 4;
  res = lp_alloc(pool, sizeof(struct adata) + l1->length + len);
  res->length = l1->length + len;
  memcpy(res->data, l1->data, l1->length);
  memcpy(res->data + l1->length, tmp, len);
  return res;
}


struct adata *
ec_set_del_nontrans(struct linpool *pool, const struct adata *set)
{
  adata *res = lp_alloc_adata(pool, set->length);
  u32 *src = int_set_get_data(set);
  u32 *dst = int_set_get_data(res);
  int len = int_set_get_size(set);
  int i;

  /* Remove non-transitive communities (EC_TBIT set) */
  for (i = 0; i < len; i += 2)
  {
    if (src[i] & EC_TBIT)
      continue;

    *dst++ = src[i];
    *dst++ = src[i+1];
  }

  res->length = ((byte *) dst) - res->data;

  return res;
}

static int
int_set_cmp(const void *X, const void *Y)
{
  const u32 *x = X, *y = Y;
  return (*x < *y) ? -1 : (*x > *y) ? 1 : 0;
}

struct adata *
int_set_sort(struct linpool *pool, const struct adata *src)
{
  struct adata *dst = lp_alloc_adata(pool, src->length);
  memcpy(dst->data, src->data, src->length);
  qsort(dst->data, dst->length / 4, 4, int_set_cmp);
  return dst;
}


static int
ec_set_cmp(const void *X, const void *Y)
{
  u64 x = ec_get(X, 0);
  u64 y = ec_get(Y, 0);
  return (x < y) ? -1 : (x > y) ? 1 : 0;
}

struct adata *
ec_set_sort(struct linpool *pool, const struct adata *src)
{
  struct adata *dst = lp_alloc_adata(pool, src->length);
  memcpy(dst->data, src->data, src->length);
  qsort(dst->data, dst->length / 8, 8, ec_set_cmp);
  return dst;
}

void
ec_set_sort_x(struct adata *set)
{
  /* Sort in place */
  qsort(set->data, set->length / 8, 8, ec_set_cmp);
}


static int
lc_set_cmp(const void *X, const void *Y)
{
  const u32 *x = X, *y = Y;
  if (x[0] != y[0])
    return (x[0] > y[0]) ? 1 : -1;
  if (x[1] != y[1])
    return (x[1] > y[1]) ? 1 : -1;
  if (x[2] != y[2])
    return (x[2] > y[2]) ? 1 : -1;
  return 0;
}

struct adata *
lc_set_sort(struct linpool *pool, const struct adata *src)
{
  struct adata *dst = lp_alloc_adata(pool, src->length);
  memcpy(dst->data, src->data, src->length);
  qsort(dst->data, dst->length / LCOMM_LENGTH, LCOMM_LENGTH, lc_set_cmp);
  return dst;
}
