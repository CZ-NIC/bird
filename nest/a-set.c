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
int_set_format(struct adata *set, int way, int from, byte *buf, uint size)
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
  char tbuf[16], *kind;

  type = ec >> 48;
  switch (type & 0xf0ff)
    {
    case EC_RT: kind = "rt"; break;
    case EC_RO: kind = "ro"; break;

    default:
      kind = tbuf;
      bsprintf(kind, "unknown 0x%x", type);
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
ec_set_format(struct adata *set, int from, byte *buf, uint size)
{
  u32 *z = (u32 *) set->data;
  byte *end = buf + size - 64;
  int from2 = MAX(from, 0);
  int to = set->length / 4;
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

      u64 ec;
      memcpy(&ec, &(z[i]), sizeof(u64));
      buf += ec_format(buf, ec);
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
lc_set_format(struct adata *set, int from, byte *buf, uint bufsize)
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
set_position(struct adata *list, void *val, int size)
{
  if (!list)
    return -1;

  int len = list->length / size;
  void *l = list->data;

  for (int i = 0; i < len; i++)
    if (!memcmp(l + i * size, val, size))
      return i;

  return -1;
}

struct adata *
int_set_prepend(struct linpool *pool, struct adata *list, u32 val)
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

struct adata *
set_add(struct linpool *pool, struct adata *list, void *val, int size)
{
  struct adata *res;
  int len;

  if (set_contains(list, val, size))
    return list;

  len = list ? list->length : 0;
  res = lp_alloc(pool, sizeof(struct adata) + len + size);
  res->length = len + size;

  if (list)
    memcpy(res->data, list->data, len);

  memcpy(res->data + len, val, size);

  return res;
}

struct adata *
set_del(struct linpool *pool, struct adata *list, void *val, int size)
{
  int pos = set_position(list, val, size);
  if (pos == -1)
    return list;

  int len = list->length - size;
  struct adata *res = lp_alloc(pool, sizeof(struct adata) + len);
  res->length = len;

  void *dest = res->data;
  void *src = list->data;
  memcpy(dest, src, size * pos);
  memcpy(dest + size * pos, src + size * (pos + 1), size * (len - pos));

  return res;
}

struct adata *
set_union(struct linpool *pool, struct adata *l1, struct adata *l2, int size)
{
  if (!l1)
    return l2;
  if (!l2)
    return l1;

  /* Filter out duplicit data from l2 */
  struct adata *res;
  int len = l2->length / size;
  void *l = l2->data;
  u32 tmp[len*size/sizeof(u32)];
  void *k = tmp;

  for (int i = 0; i < len; i++)
    if (!set_contains(l1, l + i*size, size))
    {
      memcpy(k, l + i*size, size);
      k += size;
    }

  /* Nothing to add */
  if (k == tmp)
    return l1;

  len = (k - (void*)tmp);
  res = lp_alloc(pool, sizeof(struct adata) + l1->length + len);
  res->length = l1->length + len;
  memcpy(res->data, l1->data, l1->length);
  memcpy(res->data + l1->length, tmp, len);
  return res;
}


struct adata *
ec_set_del_nontrans(struct linpool *pool, struct adata *set)
{
  adata *res = lp_alloc_adata(pool, set->length);
  u32 *src = (u32 *) set->data;
  u32 *dst = (u32 *) res->data;
  int len = set->length / 4;
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
int_set_sort(struct linpool *pool, struct adata *src)
{
  struct adata *dst = lp_alloc_adata(pool, src->length);
  memcpy(dst->data, src->data, src->length);
  qsort(dst->data, dst->length / 4, 4, int_set_cmp);
  return dst;
}


static int
ec_set_cmp(const void *X, const void *Y)
{
  u64 x = *((u64 *) X);
  u64 y = *((u64 *) Y);
  return (x < y) ? -1 : (x > y) ? 1 : 0;
}

struct adata *
ec_set_sort(struct linpool *pool, struct adata *src)
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
lc_set_sort(struct linpool *pool, struct adata *src)
{
  struct adata *dst = lp_alloc_adata(pool, src->length);
  memcpy(dst->data, src->data, src->length);
  qsort(dst->data, dst->length / sizeof(lcomm), sizeof(lcomm), lc_set_cmp);
  return dst;
}
