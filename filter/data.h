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

/* Type numbers must be in 0..0xff range */
#define T_MASK 0xff

/* Internal types */
enum f_type {
/* Nothing. Simply nothing. */
  T_VOID = 0,

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

  T_SET = 0x80,
  T_PREFIX_SET = 0x81,
} PACKED;

/* Filter value; size of this affects filter memory consumption */
struct f_val {
  enum f_type type;	/* T_*  */
  union {
    uint i;
    u64 ec;
    lcomm lc;
    ip_addr ip;
    const net_addr *net;
    char *s;
    const struct f_tree *t;
    const struct f_trie *ti;
    const struct adata *ad;
    const struct f_path_mask *path_mask;
    struct f_path_mask_item pmi;
  } val;
};

/* Dynamic attribute definition (eattrs) */
struct f_dynamic_attr {
  u8 type;		/* EA type (EAF_*) */
  u8 bit;		/* For bitfield accessors */
  enum f_type f_type;	/* Filter type */
  uint ea_code;		/* EA code */
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

struct f_trie_node
{
  ip_addr addr, mask, accept;
  uint plen;
  struct f_trie_node *c[2];
};

struct f_trie
{
  linpool *lp;
  int zero;
  uint node_size;
  struct f_trie_node root[0];		/* Root trie node follows */
};

struct f_tree *f_new_tree(void);
struct f_tree *build_tree(struct f_tree *);
const struct f_tree *find_tree(const struct f_tree *t, const struct f_val *val);
int same_tree(const struct f_tree *t0, const struct f_tree *t2);
void tree_format(const struct f_tree *t, buffer *buf);

struct f_trie *f_new_trie(linpool *lp, uint node_size);
void *trie_add_prefix(struct f_trie *t, const net_addr *n, uint l, uint h);
int trie_match_net(const struct f_trie *t, const net_addr *n);
int trie_same(const struct f_trie *t1, const struct f_trie *t2);
void trie_format(const struct f_trie *t, buffer *buf);

#define F_CMP_ERROR 999

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
{ return set->from.type == T_EC; }
static inline int lclist_set_type(const struct f_tree *set)
{ return set->from.type == T_LC; }

const struct adata *clist_filter(struct linpool *pool, const struct adata *list, const struct f_val *set, int pos);
const struct adata *eclist_filter(struct linpool *pool, const struct adata *list, const struct f_val *set, int pos);
const struct adata *lclist_filter(struct linpool *pool, const struct adata *list, const struct f_val *set, int pos);


/* Special undef value for paths and clists */
static inline int
undef_value(struct f_val v)
{
  return ((v.type == T_PATH) || (v.type == T_CLIST) ||
	  (v.type == T_ECLIST) || (v.type == T_LCLIST)) &&
    (v.val.ad == &null_adata);
}

extern const struct f_val f_const_empty_path, f_const_empty_clist, f_const_empty_eclist, f_const_empty_lclist;

enum filter_return f_eval(const struct f_line *expr, struct linpool *tmp_pool, struct f_val *pres);

#endif
