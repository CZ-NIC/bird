/*
 *	Filters: utility functions
 *
 *	(c) 1998 Pavel Machek <pavel@ucw.cz>
 *	(c) 2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 */

#include "nest/bird.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/string.h"
#include "lib/unaligned.h"
#include "lib/net.h"
#include "lib/ip.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/attrs.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/f-inst.h"
#include "filter/data.h"

const struct f_val f_const_empty_path = {
  .type = T_PATH,
  .val.ad = &null_adata,
}, f_const_empty_clist = {
  .type = T_CLIST,
  .val.ad = &null_adata,
}, f_const_empty_eclist = {
  .type = T_ECLIST,
  .val.ad = &null_adata,
}, f_const_empty_lclist = {
  .type = T_LCLIST,
  .val.ad = &null_adata,
};

static struct adata *
adata_empty(struct linpool *pool, int l)
{
  struct adata *res = lp_alloc(pool, sizeof(struct adata) + l);
  res->length = l;
  return res;
}

static void
pm_format(const struct f_path_mask *p, buffer *buf)
{
  buffer_puts(buf, "[= ");

  for (uint i=0; i<p->len; i++)
  {
    switch(p->item[i].kind)
    {
    case PM_ASN:
      buffer_print(buf, "%u ", p->item[i].asn);
      break;

    case PM_QUESTION:
      buffer_puts(buf, "? ");
      break;

    case PM_ASTERISK:
      buffer_puts(buf, "* ");
      break;

    case PM_ASN_RANGE:
      buffer_print(buf, "%u..%u ", p->item[i].from, p->item[i].to);
      break;

    case PM_ASN_EXPR:
      ASSERT(0);
    }

  }

  buffer_puts(buf, "=]");
}

static inline int
lcomm_cmp(lcomm v1, lcomm v2)
{
  if (v1.asn != v2.asn)
    return (v1.asn > v2.asn) ? 1 : -1;
  if (v1.ldp1 != v2.ldp1)
    return (v1.ldp1 > v2.ldp1) ? 1 : -1;
  if (v1.ldp2 != v2.ldp2)
    return (v1.ldp2 > v2.ldp2) ? 1 : -1;
  return 0;
}

/**
 * val_compare - compare two values
 * @v1: first value
 * @v2: second value
 *
 * Compares two values and returns -1, 0, 1 on <, =, > or F_CMP_ERROR on
 * error. Tree module relies on this giving consistent results so
 * that it can be used for building balanced trees.
 */
int
val_compare(const struct f_val *v1, const struct f_val *v2)
{
  if (v1->type != v2->type) {
    if (v1->type == T_VOID)	/* Hack for else */
      return -1;
    if (v2->type == T_VOID)
      return 1;

    /* IP->Quad implicit conversion */
    if ((v1->type == T_QUAD) && val_is_ip4(v2))
      return uint_cmp(v1->val.i, ipa_to_u32(v2->val.ip));
    if (val_is_ip4(v1) && (v2->type == T_QUAD))
      return uint_cmp(ipa_to_u32(v1->val.ip), v2->val.i);

    debug( "Types do not match in val_compare\n" );
    return F_CMP_ERROR;
  }

  switch (v1->type) {
  case T_VOID:
    return 0;
  case T_ENUM:
  case T_INT:
  case T_BOOL:
  case T_PAIR:
  case T_QUAD:
    return uint_cmp(v1->val.i, v2->val.i);
  case T_EC:
  case T_RD:
    return u64_cmp(v1->val.ec, v2->val.ec);
  case T_LC:
    return lcomm_cmp(v1->val.lc, v2->val.lc);
  case T_IP:
    return ipa_compare(v1->val.ip, v2->val.ip);
  case T_NET:
    return net_compare(v1->val.net, v2->val.net);
  case T_STRING:
    return strcmp(v1->val.s, v2->val.s);
  default:
    return F_CMP_ERROR;
  }
}

static inline int
pmi_same(const struct f_path_mask_item *mi1, const struct f_path_mask_item *mi2)
{
  if (mi1->kind != mi2->kind)
    return 0;

  switch (mi1->kind) {
    case PM_ASN:
      if (mi1->asn != mi2->asn)
	return 0;
      break;
    case PM_ASN_EXPR:
      if (!f_same(mi1->expr, mi2->expr))
	return 0;
      break;
    case PM_ASN_RANGE:
      if (mi1->from != mi2->from)
	return 0;
      if (mi1->to != mi2->to)
	return 0;
      break;
  }

  return 1;
}

static int
pm_same(const struct f_path_mask *m1, const struct f_path_mask *m2)
{
  if (m1->len != m2->len)

  for (uint i=0; i<m1->len; i++)
    if (!pmi_same(&(m1->item[i]), &(m2->item[i])))
      return 0;

  return 1;
}

/**
 * val_same - compare two values
 * @v1: first value
 * @v2: second value
 *
 * Compares two values and returns 1 if they are same and 0 if not.
 * Comparison of values of different types is valid and returns 0.
 */
int
val_same(const struct f_val *v1, const struct f_val *v2)
{
  int rc;

  rc = val_compare(v1, v2);
  if (rc != F_CMP_ERROR)
    return !rc;

  if (v1->type != v2->type)
    return 0;

  switch (v1->type) {
  case T_PATH_MASK:
    return pm_same(v1->val.path_mask, v2->val.path_mask);
  case T_PATH_MASK_ITEM:
    return pmi_same(&(v1->val.pmi), &(v2->val.pmi));
  case T_PATH:
  case T_CLIST:
  case T_ECLIST:
  case T_LCLIST:
    return adata_same(v1->val.ad, v2->val.ad);
  case T_SET:
    return same_tree(v1->val.t, v2->val.t);
  case T_PREFIX_SET:
    return trie_same(v1->val.ti, v2->val.ti);
  default:
    bug("Invalid type in val_same(): %x", v1->type);
  }
}

int
clist_set_type(const struct f_tree *set, struct f_val *v)
{
  switch (set->from.type)
  {
  case T_PAIR:
    v->type = T_PAIR;
    return 1;

  case T_QUAD:
    v->type = T_QUAD;
    return 1;

  case T_IP:
    if (val_is_ip4(&(set->from)) && val_is_ip4(&(set->to)))
    {
      v->type = T_QUAD;
      return 1;
    }
    /* Fall through */
  default:
    v->type = T_VOID;
    return 0;
  }
}

static int
clist_match_set(const struct adata *clist, const struct f_tree *set)
{
  if (!clist)
    return 0;

  struct f_val v;
  if (!clist_set_type(set, &v))
    return F_CMP_ERROR;

  u32 *l = (u32 *) clist->data;
  u32 *end = l + clist->length/4;

  while (l < end) {
    v.val.i = *l++;
    if (find_tree(set, &v))
      return 1;
  }
  return 0;
}

static int
eclist_match_set(const struct adata *list, const struct f_tree *set)
{
  if (!list)
    return 0;

  if (!eclist_set_type(set))
    return F_CMP_ERROR;

  struct f_val v;
  u32 *l = int_set_get_data(list);
  int len = int_set_get_size(list);
  int i;

  v.type = T_EC;
  for (i = 0; i < len; i += 2) {
    v.val.ec = ec_get(l, i);
    if (find_tree(set, &v))
      return 1;
  }

  return 0;
}

static int
lclist_match_set(const struct adata *list, const struct f_tree *set)
{
  if (!list)
    return 0;

  if (!lclist_set_type(set))
    return F_CMP_ERROR;

  struct f_val v;
  u32 *l = int_set_get_data(list);
  int len = int_set_get_size(list);
  int i;

  v.type = T_LC;
  for (i = 0; i < len; i += 3) {
    v.val.lc = lc_get(l, i);
    if (find_tree(set, &v))
      return 1;
  }

  return 0;
}

const struct adata *
clist_filter(struct linpool *pool, const struct adata *list, const struct f_val *set, int pos)
{
  if (!list)
    return NULL;

  int tree = (set->type == T_SET);	/* 1 -> set is T_SET, 0 -> set is T_CLIST */
  struct f_val v;
  if (tree)
    clist_set_type(set->val.t, &v);
  else
    v.type = T_PAIR;

  int len = int_set_get_size(list);
  u32 *l = int_set_get_data(list);
  u32 tmp[len];
  u32 *k = tmp;
  u32 *end = l + len;

  while (l < end) {
    v.val.i = *l++;
    /* pos && member(val, set) || !pos && !member(val, set),  member() depends on tree */
    if ((tree ? !!find_tree(set->val.t, &v) : int_set_contains(set->val.ad, v.val.i)) == pos)
      *k++ = v.val.i;
  }

  uint nl = (k - tmp) * sizeof(u32);
  if (nl == list->length)
    return list;

  struct adata *res = adata_empty(pool, nl);
  memcpy(res->data, tmp, nl);
  return res;
}

const struct adata *
eclist_filter(struct linpool *pool, const struct adata *list, const struct f_val *set, int pos)
{
  if (!list)
    return NULL;

  int tree = (set->type == T_SET);	/* 1 -> set is T_SET, 0 -> set is T_CLIST */
  struct f_val v;

  int len = int_set_get_size(list);
  u32 *l = int_set_get_data(list);
  u32 tmp[len];
  u32 *k = tmp;
  int i;

  v.type = T_EC;
  for (i = 0; i < len; i += 2) {
    v.val.ec = ec_get(l, i);
    /* pos && member(val, set) || !pos && !member(val, set),  member() depends on tree */
    if ((tree ? !!find_tree(set->val.t, &v) : ec_set_contains(set->val.ad, v.val.ec)) == pos) {
      *k++ = l[i];
      *k++ = l[i+1];
    }
  }

  uint nl = (k - tmp) * sizeof(u32);
  if (nl == list->length)
    return list;

  struct adata *res = adata_empty(pool, nl);
  memcpy(res->data, tmp, nl);
  return res;
}

const struct adata *
lclist_filter(struct linpool *pool, const struct adata *list, const struct f_val *set, int pos)
{
  if (!list)
    return NULL;

  int tree = (set->type == T_SET);	/* 1 -> set is T_SET, 0 -> set is T_CLIST */
  struct f_val v;

  int len = int_set_get_size(list);
  u32 *l = int_set_get_data(list);
  u32 tmp[len];
  u32 *k = tmp;
  int i;

  v.type = T_LC;
  for (i = 0; i < len; i += 3) {
    v.val.lc = lc_get(l, i);
    /* pos && member(val, set) || !pos && !member(val, set),  member() depends on tree */
    if ((tree ? !!find_tree(set->val.t, &v) : lc_set_contains(set->val.ad, v.val.lc)) == pos)
      k = lc_copy(k, l+i);
  }

  uint nl = (k - tmp) * sizeof(u32);
  if (nl == list->length)
    return list;

  struct adata *res = adata_empty(pool, nl);
  memcpy(res->data, tmp, nl);
  return res;
}

/**
 * val_in_range - implement |~| operator
 * @v1: element
 * @v2: set
 *
 * Checks if @v1 is element (|~| operator) of @v2.
 */
int
val_in_range(const struct f_val *v1, const struct f_val *v2)
{
  if ((v1->type == T_PATH) && (v2->type == T_PATH_MASK))
    return as_path_match(v1->val.ad, v2->val.path_mask);

  if ((v1->type == T_INT) && (v2->type == T_PATH))
    return as_path_contains(v2->val.ad, v1->val.i, 1);

  if (((v1->type == T_PAIR) || (v1->type == T_QUAD)) && (v2->type == T_CLIST))
    return int_set_contains(v2->val.ad, v1->val.i);
  /* IP->Quad implicit conversion */
  if (val_is_ip4(v1) && (v2->type == T_CLIST))
    return int_set_contains(v2->val.ad, ipa_to_u32(v1->val.ip));

  if ((v1->type == T_EC) && (v2->type == T_ECLIST))
    return ec_set_contains(v2->val.ad, v1->val.ec);

  if ((v1->type == T_LC) && (v2->type == T_LCLIST))
    return lc_set_contains(v2->val.ad, v1->val.lc);

  if ((v1->type == T_STRING) && (v2->type == T_STRING))
    return patmatch(v2->val.s, v1->val.s);

  if ((v1->type == T_IP) && (v2->type == T_NET))
    return ipa_in_netX(v1->val.ip, v2->val.net);

  if ((v1->type == T_NET) && (v2->type == T_NET))
    return net_in_netX(v1->val.net, v2->val.net);

  if ((v1->type == T_NET) && (v2->type == T_PREFIX_SET))
    return trie_match_net(v2->val.ti, v1->val.net);

  if (v2->type != T_SET)
    return F_CMP_ERROR;

  /* With integrated Quad<->IP implicit conversion */
  if ((v1->type == v2->val.t->from.type) ||
      ((v1->type == T_QUAD) && val_is_ip4(&(v2->val.t->from)) && val_is_ip4(&(v2->val.t->to))))
    return !!find_tree(v2->val.t, v1);

  if (v1->type == T_CLIST)
    return clist_match_set(v1->val.ad, v2->val.t);

  if (v1->type == T_ECLIST)
    return eclist_match_set(v1->val.ad, v2->val.t);

  if (v1->type == T_LCLIST)
    return lclist_match_set(v1->val.ad, v2->val.t);

  if (v1->type == T_PATH)
    return as_path_match_set(v1->val.ad, v2->val.t);

  return F_CMP_ERROR;
}

/*
 * val_format - format filter value
 */
void
val_format(const struct f_val *v, buffer *buf)
{
  char buf2[1024];
  switch (v->type)
  {
  case T_VOID:	buffer_puts(buf, "(void)"); return;
  case T_BOOL:	buffer_puts(buf, v->val.i ? "TRUE" : "FALSE"); return;
  case T_INT:	buffer_print(buf, "%u", v->val.i); return;
  case T_STRING: buffer_print(buf, "%s", v->val.s); return;
  case T_IP:	buffer_print(buf, "%I", v->val.ip); return;
  case T_NET:   buffer_print(buf, "%N", v->val.net); return;
  case T_PAIR:	buffer_print(buf, "(%u,%u)", v->val.i >> 16, v->val.i & 0xffff); return;
  case T_QUAD:	buffer_print(buf, "%R", v->val.i); return;
  case T_EC:	ec_format(buf2, v->val.ec); buffer_print(buf, "%s", buf2); return;
  case T_LC:	lc_format(buf2, v->val.lc); buffer_print(buf, "%s", buf2); return;
  case T_RD:	rd_format(v->val.ec, buf2, 1024); buffer_print(buf, "%s", buf2); return;
  case T_PREFIX_SET: trie_format(v->val.ti, buf); return;
  case T_SET:	tree_format(v->val.t, buf); return;
  case T_ENUM:	buffer_print(buf, "(enum %x)%u", v->type, v->val.i); return;
  case T_PATH:	as_path_format(v->val.ad, buf2, 1000); buffer_print(buf, "(path %s)", buf2); return;
  case T_CLIST:	int_set_format(v->val.ad, 1, -1, buf2, 1000); buffer_print(buf, "(clist %s)", buf2); return;
  case T_ECLIST: ec_set_format(v->val.ad, -1, buf2, 1000); buffer_print(buf, "(eclist %s)", buf2); return;
  case T_LCLIST: lc_set_format(v->val.ad, -1, buf2, 1000); buffer_print(buf, "(lclist %s)", buf2); return;
  case T_PATH_MASK: pm_format(v->val.path_mask, buf); return;
  default:	buffer_print(buf, "[unknown type %x]", v->type); return;
  }
}

char *
val_format_str(struct linpool *lp, const struct f_val *v) {
  buffer b;
  LOG_BUFFER_INIT(b);
  val_format(v, &b);
  return lp_strdup(lp, b.start);
}


static char val_dump_buffer[1024];
const char *
val_dump(const struct f_val *v) {
  static buffer b = {
    .start = val_dump_buffer,
    .end = val_dump_buffer + 1024,
  };
  b.pos = b.start;
  val_format(v, &b);
  return val_dump_buffer;
}

