/*
 *	BIRD Internet Routing Daemon -- Filters
 *
 *	(c) 1999 Pavel Machek <pavel@ucw.cz>
 *	(c) 2018--2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_FILT_H_
#define _BIRD_FILT_H_

#include "lib/resource.h"
#include "lib/ip.h"
#include "lib/macro.h"
#include "nest/route.h"
#include "nest/attrs.h"

/* IP prefix range structure */
struct f_prefix {
  net_addr net;		/* The matching prefix must match this net */
  u8 lo, hi;		/* And its length must fit between lo and hi */
};

/* Type numbers must be in 0..0xff range */
#define T_MASK 0xff

/* Internal types */
enum f_type {
/* Do not use type of zero, that way we'll see errors easier. */
  T_VOID = 1,

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

/* Possible return values of filter execution */
enum filter_return {
  F_NOP = 0,
  F_NONL,
  F_RETURN,
  F_ACCEPT,   /* Need to preserve ordering: accepts < rejects! */
  F_REJECT,
  F_ERROR,
  F_QUITBIRD,
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
    const struct symbol *sym;
    struct f_dynamic_attr da;
    struct f_static_attr sa;
  };
};

/* Filter instruction declarations */
#define FI__LIST \
  F(FI_NOP) \
  F(FI_ADD, ARG, ARG) \
  F(FI_SUBTRACT, ARG, ARG) \
  F(FI_MULTIPLY, ARG, ARG) \
  F(FI_DIVIDE, ARG, ARG) \
  F(FI_AND, ARG, LINE) \
  F(FI_OR, ARG, LINE) \
  F(FI_PAIR_CONSTRUCT, ARG, ARG) \
  F(FI_EC_CONSTRUCT, ARG, ARG, ECS) \
  F(FI_LC_CONSTRUCT, ARG, ARG, ARG) \
  F(FI_PATHMASK_CONSTRUCT, ARG, COUNT) \
  F(FI_NEQ, ARG, ARG) \
  F(FI_EQ, ARG, ARG) \
  F(FI_LT, ARG, ARG) \
  F(FI_LTE, ARG, ARG) \
  F(FI_NOT, ARG) \
  F(FI_MATCH, ARG, ARG) \
  F(FI_NOT_MATCH, ARG, ARG) \
  F(FI_DEFINED, ARG) \
  F(FI_TYPE, ARG) \
  F(FI_IS_V4, ARG) \
  F(FI_SET, ARG, SYMBOL) \
  F(FI_CONSTANT, VALI) \
  F(FI_VARIABLE, SYMBOL) \
  F(FI_CONSTANT_INDIRECT, VALP) \
  F(FI_PRINT, ARG) \
  F(FI_CONDITION, ARG, LINE, LINE) \
  F(FI_PRINT_AND_DIE, ARG, FRET) \
  F(FI_RTA_GET, SA) \
  F(FI_RTA_SET, ARG, SA) \
  F(FI_EA_GET, EA) \
  F(FI_EA_SET, ARG, EA) \
  F(FI_EA_UNSET, EA) \
  F(FI_PREF_GET) \
  F(FI_PREF_SET, ARG) \
  F(FI_LENGTH, ARG) \
  F(FI_ROA_MAXLEN, ARG) \
  F(FI_ROA_ASN, ARG) \
  F(FI_SADR_SRC, ARG) \
  F(FI_IP, ARG) \
  F(FI_ROUTE_DISTINGUISHER, ARG) \
  F(FI_AS_PATH_FIRST, ARG) \
  F(FI_AS_PATH_LAST, ARG) \
  F(FI_AS_PATH_LAST_NAG, ARG) \
  F(FI_RETURN, ARG) \
  F(FI_CALL, SYMBOL, LINE) \
  F(FI_DROP_RESULT, ARG) \
  F(FI_SWITCH, ARG, TREE) \
  F(FI_IP_MASK, ARG, ARG) \
  F(FI_PATH_PREPEND, ARG, ARG) \
  F(FI_CLIST_ADD, ARG, ARG) \
  F(FI_CLIST_DEL, ARG, ARG) \
  F(FI_CLIST_FILTER, ARG, ARG) \
  F(FI_ROA_CHECK_IMPLICIT, RTC) \
  F(FI_ROA_CHECK_EXPLICIT, ARG, ARG, RTC) \
  F(FI_FORMAT, ARG) \
  F(FI_ASSERT, ARG, STRING)

/* The enum itself */
enum f_instruction_code {
#define F(c, ...) c,
FI__LIST
#undef F
  FI__MAX,
} PACKED;

/* Convert the instruction back to the enum name */
const char *f_instruction_name(enum f_instruction_code fi);

struct f_inst;
void f_inst_next(struct f_inst *first, const struct f_inst *append);
struct f_inst *f_clear_local_vars(struct f_inst *decls);

#define FIA(x)	, FIA_##x
#define FIA_ARG	const struct f_inst *
#define FIA_LINE const struct f_inst *
#define FIA_COUNT uint
#define FIA_SYMBOL const struct symbol *
#define FIA_VALI struct f_val
#define FIA_VALP const struct f_val *
#define FIA_FRET enum filter_return
#define FIA_ECS enum ec_subtype
#define FIA_SA struct f_static_attr
#define FIA_EA struct f_dynamic_attr
#define FIA_RTC const struct rtable_config *
#define FIA_TREE const struct f_tree *
#define FIA_STRING const char *
#define F(c, ...) \
  struct f_inst *f_new_inst_##c(enum f_instruction_code MACRO_IFELSE(MACRO_ISLAST(__VA_ARGS__))()(MACRO_FOREACH(FIA, __VA_ARGS__)));
FI__LIST
#undef F
#undef FIA_ARG
#undef FIA_LINE
#undef FIA_LINEP
#undef FIA_COUNT
#undef FIA_SYMBOL
#undef FIA_VALI
#undef FIA_VALP
#undef FIA_FRET
#undef FIA_ECS
#undef FIA_SA
#undef FIA_EA
#undef FIA_RTC
#undef FIA_STRING
#undef FIA

#define f_new_inst(...) MACRO_CONCAT_AFTER(f_new_inst_, MACRO_FIRST(__VA_ARGS__))(__VA_ARGS__)

/* Flags for instructions */
enum f_instruction_flags {
  FIF_PRINTED = 1,		/* FI_PRINT_AND_DIE: message put in buffer */
};

/* Filter structures for execution */
struct f_line;

/* The single instruction item */
struct f_line_item {
  enum f_instruction_code fi_code;	/* What to do */
  enum f_instruction_flags flags;	/* Flags, instruction-specific */
  uint lineno;				/* Where */
  union {
    struct {
      const struct f_val *vp;
      const struct symbol *sym;
    };
    struct f_val val;
    const struct f_line *lines[2];
    enum filter_return fret;
    struct f_static_attr sa;
    struct f_dynamic_attr da;
    enum ec_subtype ecs;
    const char *s;
    const struct f_tree *tree;
    const struct rtable_config *rtc;
    uint count;
  };					/* Additional instruction data */
};

/* Line of instructions to be unconditionally executed one after another */
struct f_line {
  uint len;				/* Line length */
  struct f_line_item items[0];		/* The items themselves */
};

/* The filter encapsulating structure to be pointed-to from outside */
struct filter {
  char *name;
  struct f_line *root;
};

/* Convert the f_inst infix tree to the f_line structures */
struct f_line *f_postfixify_concat(const struct f_inst * const inst[], uint count);
static inline struct f_line *f_postfixify(const struct f_inst *root)
{ return f_postfixify_concat(&root, 1); }

#define F_VAL_STACK_MAX	4096

/* Value stack for execution */
struct f_val_stack {
  uint cnt;				/* Current stack size; 0 for empty */
  struct f_val val[F_VAL_STACK_MAX];	/* The stack itself */
};

#define F_EXEC_STACK_MAX 4096

/* Exception bits */
enum f_exception {
  FE_RETURN = 0x1,
};

/* Instruction stack for execution */
struct f_exec_stack {
  struct {
    const struct f_line *line;		/* The line that is being executed */
    uint pos;				/* Instruction index in the line */
    uint ventry;			/* Value stack depth on entry */
    enum f_exception emask;		/* Exception mask */
  } item[F_EXEC_STACK_MAX];
  uint cnt;				/* Current stack size; 0 for empty */
};

struct filter *f_new_where(const struct f_inst *);
static inline struct f_dynamic_attr f_new_dynamic_attr(u8 type, u8 bit, enum f_type f_type, uint code) /* Type as core knows it, type as filters know it, and code of dynamic attribute */
{ return (struct f_dynamic_attr) { .type = type, .bit = bit, .f_type = f_type, .ea_code = code }; }   /* f_type currently unused; will be handy for static type checking */
static inline struct f_static_attr f_new_static_attr(int f_type, int code, int readonly)
{ return (struct f_static_attr) { .f_type = f_type, .sa_code = code, .readonly = readonly }; }
struct f_tree *f_new_tree(void);
struct f_inst *f_generate_complex(enum f_instruction_code fi_code, struct f_dynamic_attr da, struct f_inst *argument);
struct f_inst *f_generate_roa_check(struct rtable_config *table, struct f_inst *prefix, struct f_inst *asn);


struct f_tree *build_tree(struct f_tree *);
const struct f_tree *find_tree(const struct f_tree *t, const struct f_val *val);
int same_tree(const struct f_tree *t1, const struct f_tree *t2);
void tree_format(const struct f_tree *t, buffer *buf);

struct f_trie *f_new_trie(linpool *lp, uint node_size);
void *trie_add_prefix(struct f_trie *t, const net_addr *n, uint l, uint h);
int trie_match_net(const struct f_trie *t, const net_addr *n);
int trie_same(const struct f_trie *t1, const struct f_trie *t2);
void trie_format(const struct f_trie *t, buffer *buf);

struct ea_list;
struct rte;

enum filter_return f_run(const struct filter *filter, struct rte **rte, struct linpool *tmp_pool, int flags);
enum filter_return f_eval_rte(const struct f_line *expr, struct rte **rte, struct linpool *tmp_pool);
enum filter_return f_eval(const struct f_line *expr, struct linpool *tmp_pool, struct f_val *pres);
uint f_eval_int(const struct f_line *expr);

char *filter_name(struct filter *filter);
int filter_same(struct filter *new, struct filter *old);

int f_same(const struct f_line *f1, const struct f_line *f2);

int val_compare(const struct f_val *v1, const struct f_val *v2);

void val_format(const struct f_val *v, buffer *buf);

extern const struct f_val f_const_empty_path, f_const_empty_clist, f_const_empty_eclist, f_const_empty_lclist;

#define FILTER_ACCEPT NULL
#define FILTER_REJECT ((void *) 1)
#define FILTER_UNDEF  ((void *) 2)	/* Used in BGP */


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

#define NEW_F_VAL struct f_val * val; val = cfg_alloc(sizeof(struct f_val));

#define FF_SILENT 2			/* Silent filter execution */

/* Custom route attributes */
struct custom_attribute {
  resource r;
  struct f_dynamic_attr *fda;
  const char *name;
};

struct custom_attribute *ca_lookup(pool *p, const char *name, int ea_type);

/* Bird Tests */
struct f_bt_test_suite {
  node n;			/* Node in config->tests */
  struct f_line *fn;		/* Root of function */
  const char *fn_name;		/* Name of test */
  const char *dsc;		/* Description */
};

/* Hook for call bt_assert() function in configuration */
extern void (*bt_assert_hook)(int result, const struct f_line_item *assert);

#endif
