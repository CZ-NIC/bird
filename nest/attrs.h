/*
 *	BIRD Internet Routing Daemon -- Attribute Operations
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_ATTRS_H_
#define _BIRD_ATTRS_H_

#include <stdint.h>
#include "lib/unaligned.h"
#include "nest/route.h"


/* a-path.c */

#define AS_PATH_SET		1	/* Types of path segments */
#define AS_PATH_SEQUENCE	2
#define AS_PATH_CONFED_SEQUENCE	3
#define AS_PATH_CONFED_SET	4

#define AS_PATH_MAXLEN		10000

#define AS_TRANS		23456
/* AS_TRANS is used when we need to store 32bit ASN larger than 0xFFFF
 * to 16bit slot (like in 16bit AS_PATH). See RFC 4893 for details
 */

struct f_tree;

int as_path_valid(byte *data, uint len, int bs, int confed, char *err, uint elen);
int as_path_16to32(byte *dst, const byte *src, uint len);
int as_path_32to16(byte *dst, const byte *src, uint len);
int as_path_contains_as4(const struct adata *path);
int as_path_contains_confed(const struct adata *path);
struct adata *as_path_strip_confed(struct linpool *pool, const struct adata *op);
struct adata *as_path_prepend2(struct linpool *pool, const struct adata *op, int seq, u32 as);
struct adata *as_path_to_old(struct linpool *pool, const struct adata *path);
struct adata *as_path_cut(struct linpool *pool, const struct adata *path, uint num);
const struct adata *as_path_merge(struct linpool *pool, const struct adata *p1, const struct adata *p2);
void as_path_format(const struct adata *path, byte *buf, uint size);
int as_path_getlen(const struct adata *path);
int as_path_getlen_int(const struct adata *path, int bs);
int as_path_get_first(const struct adata *path, u32 *orig_as);
int as_path_get_first_regular(const struct adata *path, u32 *last_as);
int as_path_get_last(const struct adata *path, u32 *last_as);
u32 as_path_get_last_nonaggregated(const struct adata *path);
int as_path_contains(const struct adata *path, u32 as, int min);
int as_path_match_set(const struct adata *path, const struct f_tree *set);
const struct adata *as_path_filter(struct linpool *pool, const struct adata *path, const struct f_tree *set, u32 key, int pos);

static inline struct adata *as_path_prepend(struct linpool *pool, const struct adata *path, u32 as)
{ return as_path_prepend2(pool, path, AS_PATH_SEQUENCE, as); }


#define PM_ASN		0
#define PM_QUESTION	1
#define PM_ASTERISK	2
#define PM_ASN_EXPR	3
#define PM_ASN_RANGE	4
#define PM_ASN_SET	5

struct f_path_mask_item {
  union {
    u32 asn; /* PM_ASN */
    const struct f_line *expr; /* PM_ASN_EXPR */
    const struct f_tree *set; /* PM_ASN_SET */
    struct { /* PM_ASN_RANGE */
      u32 from;
      u32 to;
    };
  };
  int kind;
};

struct f_path_mask {
  uint len;
  struct f_path_mask_item item[0];
};

int as_path_match(const struct adata *path, const struct f_path_mask *mask);


/* Counterparts to appropriate as_path_* functions */

static inline int
aggregator_16to32(byte *dst, const byte *src)
{
  put_u32(dst, get_u16(src));
  memcpy(dst+4, src+2, 4);
  return 8;
}

static inline int
aggregator_32to16(byte *dst, const byte *src)
{
  put_u16(dst, get_u32(src));
  memcpy(dst+2, src+4, 4);
  return 6;
}

static inline int
aggregator_contains_as4(const struct adata *a)
{
  return get_u32(a->data) > 0xFFFF;
}

static inline struct adata *
aggregator_to_old(struct linpool *pool, const struct adata *a)
{
  struct adata *d = lp_alloc_adata(pool, 8);
  put_u32(d->data, 0xFFFF);
  memcpy(d->data + 4, a->data + 4, 4);
  return d;
}


/* a-set.c */


/* Extended Community subtypes (kinds) */
enum ec_subtype {
  EC_RT = 0x0002,
  EC_RO = 0x0003,
  EC_GENERIC = 0xFFFF,
};

static inline const char *ec_subtype_str(const enum ec_subtype ecs) {
  switch (ecs) {
    case EC_RT: return "rt";
    case EC_RO: return "ro";
    default: return NULL;
  }
}

/* Transitive bit (for first u32 half of EC) */
#define EC_TBIT 0x40000000

#define ECOMM_LENGTH 8

static inline int int_set_get_size(const struct adata *list)
{ return list->length / 4; }

static inline int ec_set_get_size(const struct adata *list)
{ return list->length / 8; }

static inline int lc_set_get_size(const struct adata *list)
{ return list->length / 12; }

static inline u32 *int_set_get_data(const struct adata *list)
{ return (u32 *) list->data; }

static inline u32 ec_hi(u64 ec) { return ec >> 32; }
static inline u32 ec_lo(u64 ec) { return ec; }
static inline u64 ec_get(const u32 *l, int i)
{ return (((u64) l[i]) << 32) | l[i+1]; }

/* RFC 4360 3.1.  Two-Octet AS Specific Extended Community */
static inline u64 ec_as2(enum ec_subtype kind, u64 key, u64 val)
{ return (((u64) kind | 0x0000) << 48) | (key << 32) | val; }

/* RFC 5668  4-Octet AS Specific BGP Extended Community */
static inline u64 ec_as4(enum ec_subtype kind, u64 key, u64 val)
{ return (((u64) kind | 0x0200) << 48) | (key << 16) | val; }

/* RFC 4360 3.2.  IPv4 Address Specific Extended Community */
static inline u64 ec_ip4(enum ec_subtype kind, u64 key, u64 val)
{ return (((u64) kind | 0x0100) << 48) | (key << 16) | val; }

static inline u64 ec_generic(u64 key, u64 val)
{ return (key << 32) | val; }

/* Large community value */
typedef struct lcomm {
  u32 asn;
  u32 ldp1;
  u32 ldp2;
} lcomm;

#define LCOMM_LENGTH 12

static inline lcomm lc_get(const u32 *l, int i)
{ return (lcomm) { l[i], l[i+1], l[i+2] }; }

static inline void lc_put(u32 *l, lcomm v)
{ l[0] = v.asn; l[1] = v.ldp1; l[2] = v.ldp2; }

static inline int lc_match(const u32 *l, int i, lcomm v)
{ return (l[i] == v.asn && l[i+1] == v.ldp1 && l[i+2] == v.ldp2); }

static inline u32 *lc_copy(u32 *dst, const u32 *src)
{ memcpy(dst, src, LCOMM_LENGTH); return dst + 3; }


int int_set_format(const struct adata *set, int way, int from, byte *buf, uint size);
int ec_format(byte *buf, u64 ec);
int ec_set_format(const struct adata *set, int from, byte *buf, uint size);
int lc_format(byte *buf, lcomm lc);
int lc_set_format(const struct adata *set, int from, byte *buf, uint size);
int int_set_contains(const struct adata *list, u32 val);
int ec_set_contains(const struct adata *list, u64 val);
int lc_set_contains(const struct adata *list, lcomm val);
const struct adata *int_set_prepend(struct linpool *pool, const struct adata *list, u32 val);
const struct adata *int_set_add(struct linpool *pool, const struct adata *list, u32 val);
const struct adata *ec_set_add(struct linpool *pool, const struct adata *list, u64 val);
const struct adata *lc_set_add(struct linpool *pool, const struct adata *list, lcomm val);
const struct adata *int_set_del(struct linpool *pool, const struct adata *list, u32 val);
const struct adata *ec_set_del(struct linpool *pool, const struct adata *list, u64 val);
const struct adata *lc_set_del(struct linpool *pool, const struct adata *list, lcomm val);
const struct adata *int_set_union(struct linpool *pool, const struct adata *l1, const struct adata *l2);
const struct adata *ec_set_union(struct linpool *pool, const struct adata *l1, const struct adata *l2);
const struct adata *lc_set_union(struct linpool *pool, const struct adata *l1, const struct adata *l2);

struct adata *ec_set_del_nontrans(struct linpool *pool, const struct adata *set);
struct adata *int_set_sort(struct linpool *pool, const struct adata *src);
struct adata *ec_set_sort(struct linpool *pool, const struct adata *src);
struct adata *lc_set_sort(struct linpool *pool, const struct adata *src);

void ec_set_sort_x(struct adata *set); /* Sort in place */

#endif
