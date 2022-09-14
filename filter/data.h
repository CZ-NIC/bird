/*
 *	BIRD Internet Routing Daemon -- Dynamic data structures
 *
 *	(c) 1999 Pavel Machek <pavel@ucw.cz>
 *	(c) 2018--2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_FILTER_DATA_H_
#define _BIRD_FILTER_DATA_H_

#include "nest/bird.h"
#include "nest/route.h"

/* Type numbers must be in 0..0xff range */
#define T_MASK 0xff

/* Internal types */
enum f_type {
/* Nothing. Simply nothing. */
  T_VOID = 0,

  T_NONE = 1,		/* Special hack to represent missing arguments */

/* User visible types, which fit in int */
  T_INT = 0x10,
  T_BOOL = 0x11,
  T_PAIR = 0x12,  /*	Notice that pair is stored as integer: first << 16 | second */
  T_QUAD = 0x13,

/* Put enumerational types in 0x30..0x3f range */
  T_ENUM_LO = 0x30,
  T_ENUM_HI = 0x3f,

  T_ENUM_RTS = 0x30,
  T_ENUM_BGP_ORIGIN = 0x31,
  T_ENUM_SCOPE = 0x32,
  T_ENUM_RTC = 0x33,
  T_ENUM_RTD = 0x34,
  T_ENUM_ROA = 0x35,
  T_ENUM_NETTYPE = 0x36,
  T_ENUM_RA_PREFERENCE = 0x37,
  T_ENUM_AF = 0x38,
  T_ENUM_MPLS_POLICY = 0x39,

/* new enums go here */
  T_ENUM_EMPTY = 0x3f,	/* Special hack for atomic_aggr */

#define T_ENUM T_ENUM_LO ... T_ENUM_HI

/* Bigger ones */
  T_IP = 0x20,
  T_NET = 0x21,
  T_STRING = 0x22,
  T_PATH_MASK = 0x23,	/* mask for BGP path */
  T_PATH = 0x24,		/* BGP path */
  T_CLIST = 0x25,		/* Community list */
  T_EC = 0x26,		/* Extended community value, u64 */
  T_ECLIST = 0x27,		/* Extended community list */
  T_LC = 0x28,		/* Large community value, lcomm */
  T_LCLIST = 0x29,		/* Large community list */
  T_RD = 0x2a,		/* Route distinguisher for VPN addresses */
  T_PATH_MASK_ITEM = 0x2b,	/* Path mask item for path mask constructors */
  T_BYTESTRING = 0x2c,

  T_ROUTE = 0x78,
  T_ROUTES_BLOCK = 0x79,
  T_SET = 0x80,
  T_PREFIX_SET = 0x81,
} PACKED;

struct f_method {
  struct symbol *sym;
  struct f_inst *(*new_inst)(struct f_inst *obj, struct f_inst *args);
  const struct f_method *next;
  uint arg_num;
  enum f_type args_type[];
};

/* Filter value; size of this affects filter memory consumption */
struct f_val {
  enum f_type type;	/* T_*  */
  union {
    uint i;
    u64 ec;
    lcomm lc;
    ip_addr ip;
    const net_addr *net;
    const char *s;
    const struct adata *bs;
    const struct f_tree *t;
    const struct f_trie *ti;
    const struct adata *ad;
    const struct f_path_mask *path_mask;
    struct f_path_mask_item pmi;
    struct rte *rte;
  } val;
};

/* Dynamic attribute definition (eattrs) */
struct f_dynamic_attr {
  u8 type;		/* EA type (EAF_*) */
  u8 bit;		/* For bitfield accessors */
  enum f_type f_type;	/* Filter type */
  uint ea_code;		/* EA code */
  uint flags;
};

enum f_sa_code {
  SA_FROM = 1,
  SA_GW,
  SA_NET,
  SA_PROTO,
  SA_SOURCE,
  SA_SCOPE,
  SA_DEST,
  SA_IFNAME,
  SA_IFINDEX,
  SA_WEIGHT,
  SA_PREF,
  SA_GW_MPLS,
  SA_ONLINK,
} PACKED;

/* Static attribute definition (members of struct rta) */
struct f_static_attr {
  enum f_type f_type;		/* Filter type */
  enum f_sa_code sa_code;	/* Static attribute id */
  int readonly:1;			/* Don't allow writing */
};

/* Filter l-value type */
enum f_lval_type {
  F_LVAL_VARIABLE,
  F_LVAL_PREFERENCE,
  F_LVAL_SA,
  F_LVAL_EA,
};

/* Filter l-value */
struct f_lval {
  enum f_lval_type type;
  struct f_inst *rte;
  union {
    struct symbol *sym;
    struct f_dynamic_attr da;
    struct f_static_attr sa;
  };
};

/* IP prefix range structure */
struct f_prefix {
  net_addr net;		/* The matching prefix must match this net */
  u8 lo, hi;		/* And its length must fit between lo and hi */
};

struct f_tree {
  struct f_tree *left, *right;
  struct f_val from, to;
  void *data;
};

#ifdef ENABLE_COMPACT_TRIES
/* Compact 4-way tries */
#define TRIE_STEP		2
#define TRIE_STACK_LENGTH	65
#else
/* Faster 16-way tries */
#define TRIE_STEP		4
#define TRIE_STACK_LENGTH	33
#endif

struct f_trie_node4
{
  ip4_addr addr, mask, accept;
  u16 plen;
  u16 local;
  struct f_trie_node4 *c[1 << TRIE_STEP];
};

struct f_trie_node6
{
  ip6_addr addr, mask, accept;
  u16 plen;
  u16 local;
  struct f_trie_node6 *c[1 << TRIE_STEP];
};

struct f_trie_node
{
  union {
    struct f_trie_node4 v4;
    struct f_trie_node6 v6;
  };
};

struct f_trie
{
  linpool *lp;
  u8 zero;
  s8 ipv4;				/* -1 for undefined / empty */
  u16 data_size;			/* Additional data for each trie node */
  u32 prefix_count;			/* Works only for restricted tries (pxlen == l == h) */
  struct f_trie_node root;		/* Root trie node */
};

struct f_trie_walk_state
{
  u8 ipv4;
  u8 accept_length;			/* Current inter-node prefix position */
  u8 start_pos;				/* Initial prefix position in stack[0] */
  u8 local_pos;				/* Current intra-node prefix position */
  u8 stack_pos;				/* Current node in stack below */
  const struct f_trie_node *stack[TRIE_STACK_LENGTH];
};

struct f_tree *f_new_tree(void);
struct f_tree *build_tree(struct f_tree *);
const struct f_tree *find_tree(const struct f_tree *t, const struct f_val *val);
const struct f_tree *find_tree_linear(const struct f_tree *t, const struct f_val *val);
int same_tree(const struct f_tree *t0, const struct f_tree *t2);
int tree_node_count(const struct f_tree *t);
void tree_format(const struct f_tree *t, buffer *buf);
void tree_walk(const struct f_tree *t, void (*hook)(const struct f_tree *, void *), void *data);

struct f_trie *f_new_trie(linpool *lp, uint data_size);
void *trie_add_prefix(struct f_trie *t, const net_addr *n, uint l, uint h);
int trie_match_net(const struct f_trie *t, const net_addr *n);
int trie_match_longest_ip4(const struct f_trie *t, const net_addr_ip4 *net, net_addr_ip4 *dst, ip4_addr *found0);
int trie_match_longest_ip6(const struct f_trie *t, const net_addr_ip6 *net, net_addr_ip6 *dst, ip6_addr *found0);
void trie_walk_init(struct f_trie_walk_state *s, const struct f_trie *t, const net_addr *from);
int trie_walk_next(struct f_trie_walk_state *s, net_addr *net);
int trie_same(const struct f_trie *t1, const struct f_trie *t2);
void trie_format(const struct f_trie *t, buffer *buf);

static inline int
trie_match_next_longest_ip4(net_addr_ip4 *n, ip4_addr *found)
{
  while (n->pxlen)
  {
    n->pxlen--;
    ip4_clrbit(&n->prefix, n->pxlen);

    if (ip4_getbit(*found, n->pxlen))
      return 1;
  }

  return 0;
}

static inline int
trie_match_next_longest_ip6(net_addr_ip6 *n, ip6_addr *found)
{
  while (n->pxlen)
  {
    n->pxlen--;
    ip6_clrbit(&n->prefix, n->pxlen);

    if (ip6_getbit(*found, n->pxlen))
      return 1;
  }

  return 0;
}


#define TRIE_WALK_TO_ROOT_IP4(trie, net, dst) ({		\
  net_addr_ip4 dst;						\
  ip4_addr _found;						\
  for (int _n = trie_match_longest_ip4(trie, net, &dst, &_found); \
       _n;							\
       _n = trie_match_next_longest_ip4(&dst, &_found))

#define TRIE_WALK_TO_ROOT_IP6(trie, net, dst) ({		\
  net_addr_ip6 dst;						\
  ip6_addr _found;						\
  for (int _n = trie_match_longest_ip6(trie, net, &dst, &_found); \
       _n;							\
       _n = trie_match_next_longest_ip6(&dst, &_found))

#define TRIE_WALK_TO_ROOT_END })


#define TRIE_WALK(trie, net, from) ({				\
  net_addr net;							\
  struct f_trie_walk_state tws_;				\
  trie_walk_init(&tws_, trie, from);				\
  while (trie_walk_next(&tws_, &net))

#define TRIE_WALK_END })


#define F_CMP_ERROR 999

const char *f_type_name(enum f_type t);
enum f_type f_type_element_type(enum f_type t);
struct sym_scope *f_type_method_scope(enum f_type t);

int val_same(const struct f_val *v1, const struct f_val *v2);
int val_compare(const struct f_val *v1, const struct f_val *v2);
void val_format(const struct f_val *v, buffer *buf);
char *val_format_str(struct linpool *lp, const struct f_val *v);
const char *val_dump(const struct f_val *v);

static inline int val_is_ip4(const struct f_val *v)
{ return (v->type == T_IP) && ipa_is_ip4(v->val.ip); }
int val_in_range(const struct f_val *v1, const struct f_val *v2);

int clist_set_type(const struct f_tree *set, struct f_val *v);
static inline int eclist_set_type(const struct f_tree *set)
{ return !set || set->from.type == T_EC; }
static inline int lclist_set_type(const struct f_tree *set)
{ return !set || set->from.type == T_LC; }
static inline int path_set_type(const struct f_tree *set)
{ return !set || set->from.type == T_INT; }

int clist_match_set(const struct adata *clist, const struct f_tree *set);
int eclist_match_set(const struct adata *list, const struct f_tree *set);
int lclist_match_set(const struct adata *list, const struct f_tree *set);

const struct adata *clist_filter(struct linpool *pool, const struct adata *list, const struct f_val *set, int pos);
const struct adata *eclist_filter(struct linpool *pool, const struct adata *list, const struct f_val *set, int pos);
const struct adata *lclist_filter(struct linpool *pool, const struct adata *list, const struct f_val *set, int pos);


/* Special undef value for paths and clists */

static inline int
val_is_undefined(struct f_val v)
{
  return ((v.type == T_PATH) || (v.type == T_CLIST) ||
	  (v.type == T_ECLIST) || (v.type == T_LCLIST)) &&
    (v.val.ad == &null_adata);
}

static inline struct f_val
val_empty(enum f_type t)
{
  switch (t)
  {
  case T_PATH:
  case T_CLIST:
  case T_ECLIST:
  case T_LCLIST:
    return (struct f_val) { .type = t, .val.ad = &null_adata };

  default:
    return (struct f_val) { };
  }
}


extern const struct f_val f_const_empty_prefix_set;

enum filter_return f_eval(const struct f_line *expr, struct linpool *tmp_pool, struct f_val *pres);

#endif
