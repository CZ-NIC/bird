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
#include "lib/types-enums.h"
#include "lib/types-union.h"
#include "nest/route.h"

#include "filter/tree.h"
#include "filter/trie.h"

#define T_ENUM T_ENUM_RTS ... T_ENUM_EMPTY

struct f_method {
  struct symbol *sym;
  struct f_inst *(*new_inst)(struct f_inst *obj, struct f_inst *args);
  const struct f_method *next;
  uint arg_num;
  enum f_type args_type[];
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
  SA_GW_MPLS_STACK,
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


#define F_CMP_ERROR 999

const char *f_type_name(enum f_type t);
enum f_type f_type_element_type(enum f_type t);
struct sym_scope *f_type_method_scope(enum f_type t);

int val_same(const struct f_val *v1, const struct f_val *v2);
int val_compare(const struct f_val *v1, const struct f_val *v2);
#define val_format(val, buf)  f_val_str(val, buf)
char *val_format_str(struct linpool *lp, const struct f_val *v);
const char *val_dump(const struct f_val *v);

static inline int val_is_ip4(const struct f_val *v)
{ return (v->type == T_IP) && ipa_is_ip4(v->val.ip); }
int val_in_range(const struct f_val *v1, const struct f_val *v2);

const struct adata *clist_filter(struct linpool *pool, const struct adata *list, const struct f_val *set, int pos);
const struct adata *eclist_filter(struct linpool *pool, const struct adata *list, const struct f_val *set, int pos);
const struct adata *lclist_filter(struct linpool *pool, const struct adata *list, const struct f_val *set, int pos);

const struct adata *bytestring_append(struct linpool *pool, const struct adata *v1, const struct adata *v2);


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
