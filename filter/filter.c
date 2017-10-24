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
 * arguments (@a1, @a2). Some instructions contain pointer(s) to other
 * instructions in their (@a1, @a2) fields.
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
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/attrs.h"
#include "conf/conf.h"
#include "filter/filter.h"

#define CMP_ERROR 999

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
      buffer_print(buf, "%u ", f_eval_asn((struct f_inst *) p->val));
      break;
    }

    p = p->next;
  }

  buffer_puts(buf, "=]");
}

static inline int
uint_cmp(uint i1, uint i2)
{
  return (int)(i1 > i2) - (int)(i1 < i2);
}

static inline int
u64_cmp(u64 i1, u64 i2)
{
  return (int)(i1 > i2) - (int)(i1 < i2);
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
 * Compares two values and returns -1, 0, 1 on <, =, > or CMP_ERROR on
 * error. Tree module relies on this giving consistent results so
 * that it can be used for building balanced trees.
 */
int
val_compare(struct f_val v1, struct f_val v2)
{
  int rc;

  if (v1.type != v2.type) {
    if (v1.type == T_VOID)	/* Hack for else */
      return -1;
    if (v2.type == T_VOID)
      return 1;

#ifndef IPV6
    /* IP->Quad implicit conversion */
    if ((v1.type == T_QUAD) && (v2.type == T_IP))
      return uint_cmp(v1.val.i, ipa_to_u32(v2.val.px.ip));
    if ((v1.type == T_IP) && (v2.type == T_QUAD))
      return uint_cmp(ipa_to_u32(v1.val.px.ip), v2.val.i);
#endif

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
    return u64_cmp(v1.val.ec, v2.val.ec);
  case T_LC:
    return lcomm_cmp(v1.val.lc, v2.val.lc);
  case T_IP:
    return ipa_compare(v1.val.px.ip, v2.val.px.ip);
  case T_PREFIX:
    if (rc = ipa_compare(v1.val.px.ip, v2.val.px.ip))
      return rc;
    return uint_cmp(v1.val.px.len, v2.val.px.len);
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

void
fprefix_get_bounds(struct f_prefix *px, int *l, int *h)
{
  *l = *h = px->len & LEN_MASK;

  if (px->len & LEN_MINUS)
    *l = 0;

  else if (px->len & LEN_PLUS)
    *h = MAX_PREFIX_LENGTH;

  else if (px->len & LEN_RANGE)
    {
      *l = 0xff & (px->len >> 16);
      *h = 0xff & (px->len >> 8);
    }
}

static int
clist_set_type(struct f_tree *set, struct f_val *v)
{
 switch (set->from.type) {
  case T_PAIR:
    v->type = T_PAIR;
    return 1;
  case T_QUAD:
#ifndef IPV6
  case T_IP:
#endif
    v->type = T_QUAD;
    return 1;
    break;
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
#ifndef IPV6
  /* IP->Quad implicit conversion */
  if ((v1.type == T_IP) && (v2.type == T_CLIST))
    return int_set_contains(v2.val.ad, ipa_to_u32(v1.val.px.ip));
#endif

  if ((v1.type == T_EC) && (v2.type == T_ECLIST))
    return ec_set_contains(v2.val.ad, v1.val.ec);

  if ((v1.type == T_LC) && (v2.type == T_LCLIST))
    return lc_set_contains(v2.val.ad, v1.val.lc);

  if ((v1.type == T_STRING) && (v2.type == T_STRING))
    return patmatch(v2.val.s, v1.val.s);

  if ((v1.type == T_IP) && (v2.type == T_PREFIX))
    return ipa_in_net(v1.val.px.ip, v2.val.px.ip, v2.val.px.len);

  if ((v1.type == T_PREFIX) && (v2.type == T_PREFIX))
    return net_in_net(v1.val.px.ip, v1.val.px.len, v2.val.px.ip, v2.val.px.len);

  if ((v1.type == T_PREFIX) && (v2.type == T_PREFIX_SET))
    return trie_match_fprefix(v2.val.ti, &v1.val.px);

  if (v2.type != T_SET)
    return CMP_ERROR;

  /* With integrated Quad<->IP implicit conversion */
  if ((v1.type == v2.val.t->from.type) ||
      ((IP_VERSION == 4) && (v1.type == T_QUAD) && (v2.val.t->from.type == T_IP)))
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
  case T_IP:	buffer_print(buf, "%I", v.val.px.ip); return;
  case T_PREFIX: buffer_print(buf, "%I/%d", v.val.px.ip, v.val.px.len); return;
  case T_PAIR:	buffer_print(buf, "(%u,%u)", v.val.i >> 16, v.val.i & 0xffff); return;
  case T_QUAD:	buffer_print(buf, "%R", v.val.i); return;
  case T_EC:	ec_format(buf2, v.val.ec); buffer_print(buf, "%s", buf2); return;
  case T_LC:	lc_format(buf2, v.val.lc); buffer_print(buf, "%s", buf2); return;
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

static struct rte **f_rte;
static struct rta *f_old_rta;
static struct ea_list **f_tmp_attrs;
static struct linpool *f_pool;
static struct buffer f_buf;
static int f_flags;

static inline void f_rte_cow(void)
{
  *f_rte = rte_cow(*f_rte);
}

/*
 * rta_cow - prepare rta for modification by filter
 */
static void
f_rta_cow(void)
{
  if (!rta_is_cached((*f_rte)->attrs))
    return;

  /* Prepare to modify rte */
  f_rte_cow();

  /* Store old rta to free it later, it stores reference from rte_cow() */
  f_old_rta = (*f_rte)->attrs;

  /*
   * Get shallow copy of rta. Fields eattrs and nexthops of rta are shared
   * with f_old_rta (they will be copied when the cached rta will be obtained
   * at the end of f_run()), also the lock of hostentry is inherited (we
   * suppose hostentry is not changed by filters).
   */
  (*f_rte)->attrs = rta_do_cow((*f_rte)->attrs, f_pool);
}

static struct tbf rl_runtime_err = TBF_DEFAULT_LOG_LIMITS;

#define runtime(x) do { \
    log_rl(&rl_runtime_err, L_ERR "filters, line %d: %s", what->lineno, x); \
    return (struct f_val) { .type = T_RETURN; .val.i = F_ERROR; }; \
  } while(0)

struct filter_instruction {
  struct f_val *(*interpret)(struct f_inst *what);
  int (*same)(struct f_inst *f1, struct f_inst *f2);
};

#define FI__DEF(code,interpret,same) \
  static struct f_val * _filter_interpret_##code(struct f_inst *what) interpret \
  static struct f_val * _filter_same_##code(struct f_inst *what) same

static struct filter_instruction filter_instruction[] = {
#define FI__DO(code) \
  [FI_NUMERIC_CODE(code)] = { _filter_interpret_##code, _filter_same_##code },
FI__LIST
};

#include "filter/interpret.h"

/**
 * interpret
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
 *
 * &f_val structures are copied around, so there are no problems with
 * memory managment.
 */
static struct f_val
interpret(struct f_inst *what)
{
  struct symbol *sym;
  struct f_val v1, v2, res, *vp;
  unsigned u1, u2;
  int i;
  u32 as;

  res.type = T_VOID;
  if (!what)
    return res;

  switch(what->fi_code) {
#define F(c,a,b) \
    case fi_##c: res = fi_interpret_##c(what); \
		 break;
    FI_LIST
#undef F
  default:
    bug( "Unknown instruction %d (%c)", what->code, what->code & 0xff);
  }
  if (what->next)
    return interpret(what->next);
  return res;
}

#undef ARG
#define ARG(x,y) \
	if (!i_same(f1->y, f2->y)) \
		return 0;

#define ONEARG ARG(v1, a1.p)
#define TWOARGS ARG(v1, a1.p) \
		ARG(v2, a2.p)

#define A2_SAME if (f1->a2.i != f2->a2.i) return 0;

/*
 * i_same - function that does real comparing of instruction trees, you should call filter_same from outside
 */
int
i_same(struct f_inst *f1, struct f_inst *f2)
{
  if ((!!f1) != (!!f2))
    return 0;
  if (!f1)
    return 1;
  if (f1->aux != f2->aux)
    return 0;
  if (f1->code != f2->code)
    return 0;
  if (f1 == f2)		/* It looks strange, but it is possible with call rewriting trickery */
    return 1;

  switch(f1->code) {
  case ',': /* fall through */
  case '+':
  case '-':
  case '*':
  case '/':
  case '|':
  case '&':
  case P('m','p'):
  case P('m','c'):
  case P('!','='):
  case P('=','='):
  case '<':
  case P('<','='): TWOARGS; break;

  case '!': ONEARG; break;
  case P('!', '~'):
  case '~': TWOARGS; break;
  case P('d','e'): ONEARG; break;

  case P('m','l'):
    TWOARGS;
    if (!i_same(INST3(f1).p, INST3(f2).p))
      return 0;
    break;

  case 's':
    ARG(v2, a2.p);
    {
      struct symbol *s1, *s2;
      s1 = f1->a1.p;
      s2 = f2->a1.p;
      if (strcmp(s1->name, s2->name))
	return 0;
      if (s1->class != s2->class)
	return 0;
    }
    break;

  case 'c':
    switch (f1->aux) {

    case T_PREFIX_SET:
      if (!trie_same(f1->a2.p, f2->a2.p))
	return 0;
      break;

    case T_SET:
      if (!same_tree(f1->a2.p, f2->a2.p))
	return 0;
      break;

    case T_STRING:
      if (strcmp(f1->a2.p, f2->a2.p))
	return 0;
      break;

    default:
      A2_SAME;
    }
    break;

  case 'C':
    if (!val_same(* (struct f_val *) f1->a1.p, * (struct f_val *) f2->a1.p))
      return 0;
    break;

  case 'V':
    if (strcmp((char *) f1->a2.p, (char *) f2->a2.p))
      return 0;
    break;
  case 'p': case 'L': ONEARG; break;
  case '?': TWOARGS; break;
  case '0': case 'E': break;
  case P('p',','): ONEARG; A2_SAME; break;
  case 'P':
  case 'a': A2_SAME; break;
  case P('e','a'): A2_SAME; break;
  case P('P','S'):
  case P('a','S'):
  case P('e','S'): ONEARG; A2_SAME; break;

  case 'r': ONEARG; break;
  case P('c','p'): ONEARG; break;
  case P('c','a'): /* Call rewriting trickery to avoid exponential behaviour */
             ONEARG;
	     if (!i_same(f1->a2.p, f2->a2.p))
	       return 0;
	     f2->a2.p = f1->a2.p;
	     break;
  case P('c','v'): break; /* internal instruction */
  case P('S','W'): ONEARG; if (!same_tree(f1->a2.p, f2->a2.p)) return 0; break;
  case P('i','M'): TWOARGS; break;
  case P('A','p'): TWOARGS; break;
  case P('C','a'): TWOARGS; break;
  case P('a','f'):
  case P('a','l'):
  case P('a','L'): ONEARG; break;
  case P('R','C'):
    TWOARGS;
    /* Does not really make sense - ROA check resuls may change anyway */
    if (strcmp(((struct f_inst_roa_check *) f1)->rtc->name,
	       ((struct f_inst_roa_check *) f2)->rtc->name))
      return 0;
    break;
  default:
    bug( "Unknown instruction %d in same (%c)", f1->code, f1->code & 0xff);
  }
  return i_same(f1->next, f2->next);
}

/**
 * f_run - run a filter for a route
 * @filter: filter to run
 * @rte: route being filtered, may be modified
 * @tmp_attrs: temporary attributes, prepared by caller or generated by f_run()
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
int
f_run(struct filter *filter, struct rte **rte, struct ea_list **tmp_attrs, struct linpool *tmp_pool, int flags)
{
  if (filter == FILTER_ACCEPT)
    return F_ACCEPT;

  if (filter == FILTER_REJECT)
    return F_REJECT;

  int rte_cow = ((*rte)->flags & REF_COW);
  DBG( "Running filter `%s'...", filter->name );

  f_rte = rte;
  f_old_rta = NULL;
  f_tmp_attrs = tmp_attrs;
  f_pool = tmp_pool;
  f_flags = flags;

  LOG_BUFFER_INIT(f_buf);

  struct f_val res = interpret(filter->root);

  if (f_old_rta) {
    /*
     * Cached rta was modified and f_rte contains now an uncached one,
     * sharing some part with the cached one. The cached rta should
     * be freed (if rte was originally COW, f_old_rta is a clone
     * obtained during rte_cow()).
     *
     * This also implements the exception mentioned in f_run()
     * description. The reason for this is that rta reuses parts of
     * f_old_rta, and these may be freed during rta_free(f_old_rta).
     * This is not the problem if rte was COW, because original rte
     * also holds the same rta.
     */
    if (!rte_cow)
      (*f_rte)->attrs = rta_lookup((*f_rte)->attrs);

    rta_free(f_old_rta);
  }


  if (res.type != T_RETURN) {
    log_rl(&rl_runtime_err, L_ERR "Filter %s did not return accept nor reject. Make up your mind", filter->name);
    return F_ERROR;
  }
  DBG( "done (%u)\n", res.val.i );
  return res.val.i;
}

/* TODO: perhaps we could integrate f_eval(), f_eval_rte() and f_run() */

struct f_val
f_eval_rte(struct f_inst *expr, struct rte **rte, struct linpool *tmp_pool)
{
  struct ea_list *tmp_attrs = NULL;

  f_rte = rte;
  f_old_rta = NULL;
  f_tmp_attrs = &tmp_attrs;
  f_pool = tmp_pool;
  f_flags = 0;

  LOG_BUFFER_INIT(f_buf);

  /* Note that in this function we assume that rte->attrs is private / uncached */
  struct f_val res = interpret(expr);

  /* Hack to include EAF_TEMP attributes to the main list */
  (*rte)->attrs->eattrs = ea_append(tmp_attrs, (*rte)->attrs->eattrs);

  return res;
}

struct f_val
f_eval(struct f_inst *expr, struct linpool *tmp_pool)
{
  f_flags = 0;
  f_tmp_attrs = NULL;
  f_rte = NULL;
  f_pool = tmp_pool;

  LOG_BUFFER_INIT(f_buf);

  return interpret(expr);
}

uint
f_eval_int(struct f_inst *expr)
{
  /* Called independently in parse-time to eval expressions */
  struct f_val res = f_eval(expr, cfg_mem);

  if (res.type != T_INT)
    cf_error("Integer expression expected");

  return res.val.i;
}

u32
f_eval_asn(struct f_inst *expr)
{
  /* Called as a part of another interpret call, therefore no log_reset() */
  struct f_val res = interpret(expr);
  return (res.type == T_INT) ? res.val.i : 0;
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
