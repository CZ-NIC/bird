/*
 *	Filters: utility functions
 *
 *	Copyright 1998 Pavel Machek <pavel@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 */

/**
 * DOC: Filters
 *
 * You can find sources of the filter language in |filter/|
 * directory. File |filter/config.Y| contains filter grammar and basically translates
 * the source from user into a tree of &f_inst structures. These trees are
 * later interpreted using code in |filter/filter.c|.
 *
 * A filter is represented by a tree of &f_inst structures, one structure per
 * "instruction". Each &f_inst contains @code, @aux value which is
 * usually the data type this instruction operates on and two generic
 * arguments (@a[0], @a[1]). Some instructions contain pointer(s) to other
 * instructions in their (@a[0], @a[1]) fields.
 *
 * Filters use a &f_val structure for their data. Each &f_val
 * contains type and value (types are constants prefixed with %T_). Few
 * of the types are special; %T_RETURN can be or-ed with a type to indicate
 * that return from a function or from the whole filter should be
 * forced. Important thing about &f_val's is that they may be copied
 * with a simple |=|. That's fine for all currently defined types: strings
 * are read-only (and therefore okay), paths are copied for each
 * operation (okay too).
 */

#undef LOCAL_DEBUG

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

#define CMP_ERROR 999

#define FILTER_STACK_DEPTH 16384

/* Filter interpreter stack. Make this thread local after going parallel. */
struct filter_stack {
  struct f_val val;
};

static struct filter_stack filter_stack[FILTER_STACK_DEPTH];

/* Internal filter state, to be allocated on stack when executing filters */
struct filter_state {
  struct rte **rte;
  struct rta *old_rta;
  struct ea_list **eattrs;
  struct linpool *pool;
  struct buffer buf;
  int flags;
};

void (*bt_assert_hook)(int result, struct f_inst *assert);

static struct adata undef_adata;	/* adata of length 0 used for undefined */

/* Special undef value for paths and clists */
static inline int
undef_value(struct f_val v)
{
  return ((v.type == T_PATH) || (v.type == T_CLIST) ||
	  (v.type == T_ECLIST) || (v.type == T_LCLIST)) &&
    (v.val.ad == &undef_adata);
}

static struct adata *
adata_empty(struct linpool *pool, int l)
{
  struct adata *res = lp_alloc(pool, sizeof(struct adata) + l);
  res->length = l;
  return res;
}

static void
pm_format(struct f_path_mask *p, buffer *buf)
{
  buffer_puts(buf, "[= ");

  while (p)
  {
    switch(p->kind)
    {
    case PM_ASN:
      buffer_print(buf, "%u ", p->val);
      break;

    case PM_QUESTION:
      buffer_puts(buf, "? ");
      break;

    case PM_ASTERISK:
      buffer_puts(buf, "* ");
      break;

    case PM_ASN_RANGE:
      buffer_print(buf, "%u..%u ", p->val, p->val2);
      break;

    case PM_ASN_EXPR:
      ASSERT(0);
    }

    p = p->next;
  }

  buffer_puts(buf, "=]");
}

static inline int val_is_ip4(const struct f_val v)
{ return (v.type == T_IP) && ipa_is_ip4(v.val.ip); }

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
 * Compares two values and returns -1, 0, 1 on <, =, > or CMP_ERROR on
 * error. Tree module relies on this giving consistent results so
 * that it can be used for building balanced trees.
 */
int
val_compare(struct f_val v1, struct f_val v2)
{
  if (v1.type != v2.type) {
    if (v1.type == T_VOID)	/* Hack for else */
      return -1;
    if (v2.type == T_VOID)
      return 1;

    /* IP->Quad implicit conversion */
    if ((v1.type == T_QUAD) && val_is_ip4(v2))
      return uint_cmp(v1.val.i, ipa_to_u32(v2.val.ip));
    if (val_is_ip4(v1) && (v2.type == T_QUAD))
      return uint_cmp(ipa_to_u32(v1.val.ip), v2.val.i);

    debug( "Types do not match in val_compare\n" );
    return CMP_ERROR;
  }

  switch (v1.type) {
  case T_VOID:
    return 0;
  case T_ENUM:
  case T_INT:
  case T_BOOL:
  case T_PAIR:
  case T_QUAD:
    return uint_cmp(v1.val.i, v2.val.i);
  case T_EC:
  case T_RD:
    return u64_cmp(v1.val.ec, v2.val.ec);
  case T_LC:
    return lcomm_cmp(v1.val.lc, v2.val.lc);
  case T_IP:
    return ipa_compare(v1.val.ip, v2.val.ip);
  case T_NET:
    return net_compare(v1.val.net, v2.val.net);
  case T_STRING:
    return strcmp(v1.val.s, v2.val.s);
  default:
    return CMP_ERROR;
  }
}

static int
pm_same(struct f_path_mask *m1, struct f_path_mask *m2)
{
  while (m1 && m2)
  {
    if (m1->kind != m2->kind)
      return 0;

    if (m1->kind == PM_ASN_EXPR)
    {
      if (!i_same((struct f_inst *) m1->val, (struct f_inst *) m2->val))
	return 0;
    }
    else
    {
      if ((m1->val != m2->val) || (m1->val2 != m2->val2))
	return 0;
    }

    m1 = m1->next;
    m2 = m2->next;
  }

  return !m1 && !m2;
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
val_same(struct f_val v1, struct f_val v2)
{
  int rc;

  rc = val_compare(v1, v2);
  if (rc != CMP_ERROR)
    return !rc;

  if (v1.type != v2.type)
    return 0;

  switch (v1.type) {
  case T_PATH_MASK:
    return pm_same(v1.val.path_mask, v2.val.path_mask);
  case T_PATH:
  case T_CLIST:
  case T_ECLIST:
  case T_LCLIST:
    return adata_same(v1.val.ad, v2.val.ad);
  case T_SET:
    return same_tree(v1.val.t, v2.val.t);
  case T_PREFIX_SET:
    return trie_same(v1.val.ti, v2.val.ti);
  default:
    bug("Invalid type in val_same(): %x", v1.type);
  }
}

static int
clist_set_type(struct f_tree *set, struct f_val *v)
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
    if (val_is_ip4(set->from) && val_is_ip4(set->to))
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

static inline int
eclist_set_type(struct f_tree *set)
{ return set->from.type == T_EC; }

static inline int
lclist_set_type(struct f_tree *set)
{ return set->from.type == T_LC; }

static int
clist_match_set(struct adata *clist, struct f_tree *set)
{
  if (!clist)
    return 0;

  struct f_val v;
  if (!clist_set_type(set, &v))
    return CMP_ERROR;

  u32 *l = (u32 *) clist->data;
  u32 *end = l + clist->length/4;

  while (l < end) {
    v.val.i = *l++;
    if (find_tree(set, v))
      return 1;
  }
  return 0;
}

static int
eclist_match_set(struct adata *list, struct f_tree *set)
{
  if (!list)
    return 0;

  if (!eclist_set_type(set))
    return CMP_ERROR;

  struct f_val v;
  u32 *l = int_set_get_data(list);
  int len = int_set_get_size(list);
  int i;

  v.type = T_EC;
  for (i = 0; i < len; i += 2) {
    v.val.ec = ec_get(l, i);
    if (find_tree(set, v))
      return 1;
  }

  return 0;
}

static int
lclist_match_set(struct adata *list, struct f_tree *set)
{
  if (!list)
    return 0;

  if (!lclist_set_type(set))
    return CMP_ERROR;

  struct f_val v;
  u32 *l = int_set_get_data(list);
  int len = int_set_get_size(list);
  int i;

  v.type = T_LC;
  for (i = 0; i < len; i += 3) {
    v.val.lc = lc_get(l, i);
    if (find_tree(set, v))
      return 1;
  }

  return 0;
}

static struct adata *
clist_filter(struct linpool *pool, struct adata *list, struct f_val set, int pos)
{
  if (!list)
    return NULL;

  int tree = (set.type == T_SET);	/* 1 -> set is T_SET, 0 -> set is T_CLIST */
  struct f_val v;
  if (tree)
    clist_set_type(set.val.t, &v);
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
    if ((tree ? !!find_tree(set.val.t, v) : int_set_contains(set.val.ad, v.val.i)) == pos)
      *k++ = v.val.i;
  }

  uint nl = (k - tmp) * sizeof(u32);
  if (nl == list->length)
    return list;

  struct adata *res = adata_empty(pool, nl);
  memcpy(res->data, tmp, nl);
  return res;
}

static struct adata *
eclist_filter(struct linpool *pool, struct adata *list, struct f_val set, int pos)
{
  if (!list)
    return NULL;

  int tree = (set.type == T_SET);	/* 1 -> set is T_SET, 0 -> set is T_CLIST */
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
    if ((tree ? !!find_tree(set.val.t, v) : ec_set_contains(set.val.ad, v.val.ec)) == pos) {
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

static struct adata *
lclist_filter(struct linpool *pool, struct adata *list, struct f_val set, int pos)
{
  if (!list)
    return NULL;

  int tree = (set.type == T_SET);	/* 1 -> set is T_SET, 0 -> set is T_CLIST */
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
    if ((tree ? !!find_tree(set.val.t, v) : lc_set_contains(set.val.ad, v.val.lc)) == pos)
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
static int
val_in_range(struct f_val v1, struct f_val v2)
{
  if ((v1.type == T_PATH) && (v2.type == T_PATH_MASK))
    return as_path_match(v1.val.ad, v2.val.path_mask);

  if ((v1.type == T_INT) && (v2.type == T_PATH))
    return as_path_contains(v2.val.ad, v1.val.i, 1);

  if (((v1.type == T_PAIR) || (v1.type == T_QUAD)) && (v2.type == T_CLIST))
    return int_set_contains(v2.val.ad, v1.val.i);
  /* IP->Quad implicit conversion */
  if (val_is_ip4(v1) && (v2.type == T_CLIST))
    return int_set_contains(v2.val.ad, ipa_to_u32(v1.val.ip));

  if ((v1.type == T_EC) && (v2.type == T_ECLIST))
    return ec_set_contains(v2.val.ad, v1.val.ec);

  if ((v1.type == T_LC) && (v2.type == T_LCLIST))
    return lc_set_contains(v2.val.ad, v1.val.lc);

  if ((v1.type == T_STRING) && (v2.type == T_STRING))
    return patmatch(v2.val.s, v1.val.s);

  if ((v1.type == T_IP) && (v2.type == T_NET))
    return ipa_in_netX(v1.val.ip, v2.val.net);

  if ((v1.type == T_NET) && (v2.type == T_NET))
    return net_in_netX(v1.val.net, v2.val.net);

  if ((v1.type == T_NET) && (v2.type == T_PREFIX_SET))
    return trie_match_net(v2.val.ti, v1.val.net);

  if (v2.type != T_SET)
    return CMP_ERROR;

  /* With integrated Quad<->IP implicit conversion */
  if ((v1.type == v2.val.t->from.type) ||
      ((v1.type == T_QUAD) && val_is_ip4(v2.val.t->from) && val_is_ip4(v2.val.t->to)))
    return !!find_tree(v2.val.t, v1);

  if (v1.type == T_CLIST)
    return clist_match_set(v1.val.ad, v2.val.t);

  if (v1.type == T_ECLIST)
    return eclist_match_set(v1.val.ad, v2.val.t);

  if (v1.type == T_LCLIST)
    return lclist_match_set(v1.val.ad, v2.val.t);

  if (v1.type == T_PATH)
    return as_path_match_set(v1.val.ad, v2.val.t);

  return CMP_ERROR;
}

/*
 * val_format - format filter value
 */
void
val_format(struct f_val v, buffer *buf)
{
  char buf2[1024];
  switch (v.type)
  {
  case T_VOID:	buffer_puts(buf, "(void)"); return;
  case T_BOOL:	buffer_puts(buf, v.val.i ? "TRUE" : "FALSE"); return;
  case T_INT:	buffer_print(buf, "%u", v.val.i); return;
  case T_STRING: buffer_print(buf, "%s", v.val.s); return;
  case T_IP:	buffer_print(buf, "%I", v.val.ip); return;
  case T_NET:   buffer_print(buf, "%N", v.val.net); return;
  case T_PAIR:	buffer_print(buf, "(%u,%u)", v.val.i >> 16, v.val.i & 0xffff); return;
  case T_QUAD:	buffer_print(buf, "%R", v.val.i); return;
  case T_EC:	ec_format(buf2, v.val.ec); buffer_print(buf, "%s", buf2); return;
  case T_LC:	lc_format(buf2, v.val.lc); buffer_print(buf, "%s", buf2); return;
  case T_RD:	rd_format(v.val.ec, buf2, 1024); buffer_print(buf, "%s", buf2); return;
  case T_PREFIX_SET: trie_format(v.val.ti, buf); return;
  case T_SET:	tree_format(v.val.t, buf); return;
  case T_ENUM:	buffer_print(buf, "(enum %x)%u", v.type, v.val.i); return;
  case T_PATH:	as_path_format(v.val.ad, buf2, 1000); buffer_print(buf, "(path %s)", buf2); return;
  case T_CLIST:	int_set_format(v.val.ad, 1, -1, buf2, 1000); buffer_print(buf, "(clist %s)", buf2); return;
  case T_ECLIST: ec_set_format(v.val.ad, -1, buf2, 1000); buffer_print(buf, "(eclist %s)", buf2); return;
  case T_LCLIST: lc_set_format(v.val.ad, -1, buf2, 1000); buffer_print(buf, "(lclist %s)", buf2); return;
  case T_PATH_MASK: pm_format(v.val.path_mask, buf); return;
  default:	buffer_print(buf, "[unknown type %x]", v.type); return;
  }
}


static inline void f_cache_eattrs(struct filter_state *fs)
{
  fs->eattrs = &((*fs->rte)->attrs->eattrs);
}

static inline void f_rte_cow(struct filter_state *fs)
{
  if (!((*fs->rte)->flags & REF_COW))
    return;

  *fs->rte = rte_cow(*fs->rte);
}

/*
 * rta_cow - prepare rta for modification by filter
 */
static void
f_rta_cow(struct filter_state *fs)
{
  if (!rta_is_cached((*fs->rte)->attrs))
    return;

  /* Prepare to modify rte */
  f_rte_cow(fs);

  /* Store old rta to free it later, it stores reference from rte_cow() */
  fs->old_rta = (*fs->rte)->attrs;

  /*
   * Get shallow copy of rta. Fields eattrs and nexthops of rta are shared
   * with fs->old_rta (they will be copied when the cached rta will be obtained
   * at the end of f_run()), also the lock of hostentry is inherited (we
   * suppose hostentry is not changed by filters).
   */
  (*fs->rte)->attrs = rta_do_cow((*fs->rte)->attrs, fs->pool);

  /* Re-cache the ea_list */
  f_cache_eattrs(fs);
}

static char *
val_format_str(struct filter_state *fs, struct f_val v) {
  buffer b;
  LOG_BUFFER_INIT(b);
  val_format(v, &b);
  return lp_strdup(fs->pool, b.start);
}

static struct tbf rl_runtime_err = TBF_DEFAULT_LOG_LIMITS;

static uint
inst_line_size(const struct f_inst *what)
{
  uint cnt = 0;
  for ( ; what; what = what->next) {
    switch (what->fi_code) {
#include "filter/f-inst-line-size.c"
    }
  }
  return cnt;
}

static uint
postfixify(struct f_line *dest, const struct f_inst *what, uint pos)
{
  for ( ; what; what = what->next) {
    switch (what->fi_code) {
#include "filter/f-inst-postfixify.c"
    }
    pos++;
  }
  return pos;
}

struct f_line *
f_postfixify(struct f_inst *root)
{
  uint len = inst_line_size(root);
  struct f_line *out = cfg_allocz(sizeof(struct f_line) + sizeof(struct f_line_item)*len);
  out->len = postfixify(out, root, 0);
  return out;
}

/**
 * interpret
 * @fs: filter state
 * @what: filter to interpret
 *
 * Interpret given tree of filter instructions. This is core function
 * of filter system and does all the hard work.
 *
 * Each instruction has 4 fields: code (which is instruction code),
 * aux (which is extension to instruction code, typically type),
 * arg1 and arg2 - arguments. Depending on instruction, arguments
 * are either integers, or pointers to instruction trees. Common
 * instructions like +, that have two expressions as arguments use
 * TWOARGS macro to get both of them evaluated.
 */
static enum filter_return
interpret(struct filter_state *fs, struct f_line *line, struct f_val *val)
{
  struct f_val_stack vstk;
  struct f_exec_stack estk = {
    .cnt = 1,
    .item[0] = {
      .line = line,
      .pos = 0,
    },
  };

#define curline estk.item[estk.cnt-1]

  while (estk.cnt > 0) {
    while (curline.pos < curline.line->len) {
      struct f_line_item *what = &(curline.line->items[curline.pos++]);


      switch (what->fi_code) {
#define res vstk.val[vstk.cnt]
#define v1 vstk.val[vstk.cnt]
#define v2 vstk.val[vstk.cnt + 1]
#define v3 vstk.val[vstk.cnt + 2]

#define runtime(fmt, ...) do { \
  if (!(fs->flags & FF_SILENT)) \
    log_rl(&rl_runtime_err, L_ERR "filters, line %d: " fmt, what->lineno, ##__VA_ARGS__); \
  return F_ERROR; \
} while(0)

#define ACCESS_RTE do { if (!fs->rte) runtime("No route to access"); } while (0)
#define ACCESS_EATTRS do { if (!fs->eattrs) f_cache_eattrs(fs); } while (0)
#define BITFIELD_MASK(what_) (1u << EA_BIT_GET(what_->a[1].i))

#include "filter/f-inst-interpret.c"
#undef res
#undef v1
#undef v2
#undef v3
#undef runtime
#undef ACCESS_RTE
#undef ACCESS_EATTRS
      }
    }
    estk.cnt--;
  }

  switch (vstk.cnt) {
    case 0:
      if (val)
	log_rl(&rl_runtime_err, L_ERR "filters: No value left on stack");
      return F_NOP;
    case 1:
      if (val) {
	*val = vstk.val[0];
	return F_NOP;
      }
      /* fallthrough */
    default:
      log_rl(&rl_runtime_err, L_ERR "Too many items left on stack: %u", vstk.cnt);
  }
}


#define ARG(n) \
	if (!i_same(f1->a[n-1].p, f2->a[n-1].p)) \
		return 0;

#define ONEARG		ARG(1);
#define TWOARGS		ONEARG; ARG(2);
#define THREEARGS	TWOARGS; ARG(3);

#define A2_SAME if (f1->a[1].i != f2->a[1].i) return 0;

/*
 * i_same - function that does real comparing of instruction trees, you should call filter_same from outside
 */
int
i_same(struct f_line *f1, struct f_line *f2)
{
  if ((!!f1) != (!!f2))
    return 0;
  if (!f1)
    return 1;
  if (f1->aux != f2->aux)
    return 0;
  if (f1->fi_code != f2->fi_code)
    return 0;
  if (f1 == f2)		/* It looks strange, but it is possible with call rewriting trickery */
    return 1;

  switch(f1->fi_code) {
  case FI_ADD: /* fall through */
  case FI_SUBTRACT:
  case FI_MULTIPLY:
  case FI_DIVIDE:
  case FI_OR:
  case FI_AND:
  case FI_PAIR_CONSTRUCT:
  case FI_EC_CONSTRUCT:
  case FI_NEQ:
  case FI_EQ:
  case FI_LT:
  case FI_LTE: TWOARGS; break;

  case FI_PATHMASK_CONSTRUCT: if (!pm_same(f1->a[0].p, f2->a[0].p)) return 0; break;

  case FI_NOT: ONEARG; break;
  case FI_NOT_MATCH:
  case FI_MATCH: TWOARGS; break;
  case FI_DEFINED: ONEARG; break;
  case FI_TYPE: ONEARG; break;

  case FI_LC_CONSTRUCT:
    THREEARGS;
    break;

  case FI_SET:
    ARG(2);
    {
      struct symbol *s1, *s2;
      s1 = f1->a[0].p;
      s2 = f2->a[0].p;
      if (strcmp(s1->name, s2->name))
	return 0;
      if (s1->class != s2->class)
	return 0;
    }
    break;

  case FI_CONSTANT:
    switch (f1->aux) {

    case T_PREFIX_SET:
      if (!trie_same(f1->a[1].p, f2->a[1].p))
	return 0;
      break;

    case T_SET:
      if (!same_tree(f1->a[1].p, f2->a[1].p))
	return 0;
      break;

    case T_STRING:
      if (strcmp(f1->a[1].p, f2->a[1].p))
	return 0;
      break;

    default:
      A2_SAME;
    }
    break;

  case FI_CONSTANT_INDIRECT:
    if (!val_same(* (struct f_val *) f1->a[0].p, * (struct f_val *) f2->a[0].p))
      return 0;
    break;

  case FI_VARIABLE:
    if (strcmp((char *) f1->a[1].p, (char *) f2->a[1].p))
      return 0;
    break;
  case FI_PRINT: case FI_LENGTH: ONEARG; break;
  case FI_CONDITION: THREEARGS; break;
  case FI_NOP: case FI_EMPTY: break;
  case FI_PRINT_AND_DIE: ONEARG; A2_SAME; break;
  case FI_PREF_GET:
  case FI_RTA_GET: A2_SAME; break;
  case FI_EA_GET: A2_SAME; break;
  case FI_PREF_SET:
  case FI_RTA_SET:
  case FI_EA_SET: ONEARG; A2_SAME; break;

  case FI_RETURN: ONEARG; break;
  case FI_ROA_MAXLEN: ONEARG; break;
  case FI_ROA_ASN: ONEARG; break;
  case FI_SADR_SRC: ONEARG; break;
  case FI_IP: ONEARG; break;
  case FI_IS_V4: ONEARG; break;
  case FI_ROUTE_DISTINGUISHER: ONEARG; break;
  case FI_CALL: /* Call rewriting trickery to avoid exponential behaviour */
             ONEARG;
	     if (!i_same(f1->a[1].p, f2->a[1].p))
	       return 0;
	     f2->a[1].p = f1->a[1].p;
	     break;
  case FI_CLEAR_LOCAL_VARS: break; /* internal instruction */
  case FI_SWITCH: ONEARG; if (!same_tree(f1->a[1].p, f2->a[1].p)) return 0; break;
  case FI_IP_MASK: TWOARGS; break;
  case FI_PATH_PREPEND: TWOARGS; break;
  case FI_CLIST_ADD_DEL: TWOARGS; break;
  case FI_AS_PATH_FIRST:
  case FI_AS_PATH_LAST:
  case FI_AS_PATH_LAST_NAG: ONEARG; break;
  case FI_ROA_CHECK:
    TWOARGS;
    /* FIXME: ROA check results may change anyway */
    if (strcmp(f1->a[2].rtc->name,
	       f2->a[2].rtc->name))
      return 0;
    break;
  case FI_FORMAT: ONEARG; break;
  case FI_ASSERT: ONEARG; break;
  default:
    bug( "Unknown instruction %d in same (%c)", f1->fi_code, f1->fi_code & 0xff);
  }
  return i_same(f1->next, f2->next);
}

/**
 * f_run - run a filter for a route
 * @filter: filter to run
 * @rte: route being filtered, may be modified
 * @tmp_pool: all filter allocations go from this pool
 * @flags: flags
 *
 * If filter needs to modify the route, there are several
 * posibilities. @rte might be read-only (with REF_COW flag), in that
 * case rw copy is obtained by rte_cow() and @rte is replaced. If
 * @rte is originally rw, it may be directly modified (and it is never
 * copied).
 *
 * The returned rte may reuse the (possibly cached, cloned) rta, or
 * (if rta was modificied) contains a modified uncached rta, which
 * uses parts allocated from @tmp_pool and parts shared from original
 * rta. There is one exception - if @rte is rw but contains a cached
 * rta and that is modified, rta in returned rte is also cached.
 *
 * Ownership of cached rtas is consistent with rte, i.e.
 * if a new rte is returned, it has its own clone of cached rta
 * (and cached rta of read-only source rte is intact), if rte is
 * modified in place, old cached rta is possibly freed.
 */
enum filter_return
f_run(struct filter *filter, struct rte **rte, struct linpool *tmp_pool, int flags)
{
  if (filter == FILTER_ACCEPT)
    return F_ACCEPT;

  if (filter == FILTER_REJECT)
    return F_REJECT;

  int rte_cow = ((*rte)->flags & REF_COW);
  DBG( "Running filter `%s'...", filter->name );

  struct filter_state fs = {
    .rte = rte,
    .pool = tmp_pool,
    .flags = flags,
  };

  LOG_BUFFER_INIT(fs.buf);

  enum filter_return fret = interpret(&fs, filter->root, NULL);

  if (fs.old_rta) {
    /*
     * Cached rta was modified and fs->rte contains now an uncached one,
     * sharing some part with the cached one. The cached rta should
     * be freed (if rte was originally COW, fs->old_rta is a clone
     * obtained during rte_cow()).
     *
     * This also implements the exception mentioned in f_run()
     * description. The reason for this is that rta reuses parts of
     * fs->old_rta, and these may be freed during rta_free(fs->old_rta).
     * This is not the problem if rte was COW, because original rte
     * also holds the same rta.
     */
    if (!rte_cow)
      (*fs.rte)->attrs = rta_lookup((*fs.rte)->attrs);

    rta_free(fs.old_rta);
  }


  if (fret < F_ACCEPT) {
    if (!(fs.flags & FF_SILENT))
      log_rl(&rl_runtime_err, L_ERR "Filter %s did not return accept nor reject. Make up your mind", filter->name);
    return F_ERROR;
  }
  DBG( "done (%u)\n", res.val.i );
  return fret;
}

/* TODO: perhaps we could integrate f_eval(), f_eval_rte() and f_run() */

enum filter_return
f_eval_rte(struct f_line *expr, struct rte **rte, struct linpool *tmp_pool)
{

  struct filter_state fs = {
    .rte = rte,
    .pool = tmp_pool,
  };

  LOG_BUFFER_INIT(fs.buf);

  /* Note that in this function we assume that rte->attrs is private / uncached */
  return interpret(&fs, expr, NULL);
}

enum filter_return
f_eval(struct f_line *expr, struct linpool *tmp_pool, struct f_val *pres)
{
  struct filter_state fs = {
    .pool = tmp_pool,
  };

  LOG_BUFFER_INIT(fs.buf);

  enum filter_return fret = interpret(&fs, expr, pres);
  return fret;
}

uint
f_eval_int(struct f_line *expr)
{
  /* Called independently in parse-time to eval expressions */
  struct filter_state fs = {
    .pool = cfg_mem,
  };

  struct f_val val;

  LOG_BUFFER_INIT(fs.buf);

  if (interpret(&fs, expr, &val) > F_RETURN)
    cf_error("Runtime error while evaluating expression");

  if (val.type != T_INT)
    cf_error("Integer expression expected");

  return val.val.i;
}

/**
 * filter_same - compare two filters
 * @new: first filter to be compared
 * @old: second filter to be compared, notice that this filter is
 * damaged while comparing.
 *
 * Returns 1 in case filters are same, otherwise 0. If there are
 * underlying bugs, it will rather say 0 on same filters than say
 * 1 on different.
 */
int
filter_same(struct filter *new, struct filter *old)
{
  if (old == new)	/* Handle FILTER_ACCEPT and FILTER_REJECT */
    return 1;
  if (old == FILTER_ACCEPT || old == FILTER_REJECT ||
      new == FILTER_ACCEPT || new == FILTER_REJECT)
    return 0;
  return i_same(new->root, old->root);
}
