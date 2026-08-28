
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

const char *
f_type_name(enum f_type t)
{
  const struct f_class *cls = f_type_get_class(t);

  return
    cls ? cls->name :
    ((t == T_SET) || (t == T_PREFIX_SET)) ? "set" :
    tmp_sprintf("unknown_type_0x%x", t);
}

const char *
f_type_pretty_name(enum f_type t)
{
  const struct f_class *cls = f_type_get_class(t);

  if (cls)
    if (cls->pretty_name)
      return cls->pretty_name;
    else if (cls->name)
      return tmp_sprintf("Type %s", cls->name);

  if ((t == T_SET) || (t == T_PREFIX_SET))
    return "Set";

  return tmp_sprintf("Unknown type 0x%x", t);
}

struct f_val
val_empty(enum f_type t)
{
  const struct f_class *cls = (t < ARRAY_SIZE(f_base_types)) ? f_base_types[t] : NULL;
  return cls ? cls->empty : (struct f_val) {};
}

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

    DBG( "Types do not match in val_compare\n" );
    return F_CMP_ERROR;
  }

  if (v1->type == T_VOID)
    return 0;

  const struct f_class *cls = f_type_get_class(v1->type);

  if (!cls || !cls->compare)
    return F_CMP_ERROR;

  return cls->compare(v1, v2);
}

/**
 * val_hash - hash a value
 * @v: value
 * @seed: seed
 *
 * Mixes a hash of the given value into the given seed, returns updated seed.
 */
u64
val_hash(u64 seed, const struct f_val *v)
{
  const struct f_class *cls = f_type_get_class(v->type);
  if (!cls || !cls->hash)
    bug("Tried to hash a value of type %u (%s) which was never expected to be hashed", v->type, cls ? cls->name ?: "no name" : "unknown");

  return cls->hash(seed, v);
}


static inline int
bs_same(const struct adata *bs1, const struct adata *bs2)
{
  return (bs1->length == bs2->length) && !memcmp(bs1->data, bs2->data, bs1->length);
}

/**
 * val_same - compare two values
 * @v1: first value
 * @v2: second value
 *
 * Compares two values and returns 1 if they are same and 0 if not.
 * Comparison of values of different types is valid and returns 0.
 */
bool
val_same(const struct f_val *v1, const struct f_val *v2)
{
  int rc = val_compare(v1, v2);
  if (rc != F_CMP_ERROR)
    return !rc;

  if (v1->type != v2->type)
    return false;

  const struct f_class *cls = f_type_get_class(v1->type);
  if (cls && cls->same)
    return cls->same(v1, v2);

  if (v1->type == T_SET)
    return same_tree(v1->val.t, v2->val.t);

  if (v1->type == T_PREFIX_SET)
    return trie_same(v1->val.ti, v2->val.ti);

  bug("Can't compute sameness of values of type %u (%s)", v1->type, cls ? cls->name ?: "no name" : "no class");
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
  case T_INT:
    v->type = T_INT;
    return 1;

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

  if (((v1->type == T_INT) || (v1->type == T_PAIR) || (v1->type == T_QUAD)) && (v2->type == T_CLIST))
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

/*
 * val_format - format filter value
 */
void
val_format(const struct f_val *v, buffer *buf)
{
  switch (v->type)
  {
  case T_PREFIX_SET: trie_format(v->val.ti, buf); return;
  case T_SET:	tree_format(v->val.t, buf); return;
  default: break;
  }

  const struct f_class *cls = f_type_get_class(v->type);
  if (!cls)
    return (void) buffer_print(buf, "[unknown type %x]", v->type);

  if (!cls->name)
    return (void) buffer_print(buf, "[unnamed type %x]", v->type);

  if (!cls->format)
    return (void) buffer_print(buf, "[missing format for %x/%s]", v->type, cls->name);

  return cls->format(v, buf);
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

int
bytestring_compare(const struct adata *bs1, const struct adata *bs2)
{
  uint len = MIN(bs1->length, bs2->length);
  int i = memcmp(bs1->data, bs2->data, len);
  if (i)
    return (i > 0) - (i < 0);
  else
    return (bs1->length > len) - (bs2->length > len);
}
