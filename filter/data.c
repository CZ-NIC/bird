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

enum f_type
f_type_element_type(enum f_type t)
{
  switch(t) {
    case T_PATH:   return T_INT;
    case T_CLIST:  return T_PAIR;
    case T_ECLIST: return T_EC;
    case T_LCLIST: return T_LC;
    case T_ROUTES_BLOCK: return T_ROUTE;
    default: return T_VOID;
  };
}

const struct f_trie f_const_empty_trie = { .ipv4 = -1, };
const struct f_val f_const_empty_prefix_set = {
  .type = T_PREFIX_SET,
  .val.ti = &f_const_empty_trie,
};

static struct adata *
adata_empty(struct linpool *pool, int l)
{
  struct adata *res = lp_alloc(pool, sizeof(struct adata) + l);
  res->length = l;
  return res;
}

int
clist_set_type(const struct f_tree *set, struct f_val *v)
{
  if (!set)
  {
    v->type = T_VOID;
    return 1;
  }

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

int
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

int
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

int
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
    lcomm lc = lc_get(l, i);
    v.val.lc = &lc;
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
    lcomm lc = lc_get(l, i);
    v.val.lc = &lc;
    /* pos && member(val, set) || !pos && !member(val, set),  member() depends on tree */
    if ((tree ? !!find_tree(set->val.t, &v) : lc_set_contains(set->val.ad, lc)) == pos)
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
    return lc_set_contains(v2->val.ad, *v1->val.lc);

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

  if (!v2->val.t)
    return 0;

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

const struct adata *
bytestring_append(struct linpool *pool, const struct adata *v1, const struct adata *v2)
{
  if (!v1 || !v2)
    return v1 ?: v2;

  struct adata *res = lp_alloc_adata(pool, v1->length + v2->length);
  memcpy(res->data, v1->data, v1->length);
  memcpy(res->data + v1->length, v2->data, v2->length);
  return res;
}
