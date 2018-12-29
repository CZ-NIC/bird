/*
 *	BIRD Internet Routing Daemon -- Filters
 *
 *	(c) 1999 Pavel Machek <pavel@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_FILT_H_
#define _BIRD_FILT_H_

#include "lib/resource.h"
#include "lib/ip.h"
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
    struct f_tree *t;
    struct f_trie *ti;
    struct adata *ad;
    struct f_path_mask *path_mask;
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

/* Filter instruction words */
#define FI__TWOCHAR(a,b)	((a<<8) | b)
#define FI__LIST \
  F(FI_NOP,			  0, '0') \
  F(FI_ADD,			  0, '+') \
  F(FI_SUBTRACT,		  0, '-') \
  F(FI_MULTIPLY,		  0, '*') \
  F(FI_DIVIDE,			  0, '/') \
  F(FI_AND,			  0, '&') \
  F(FI_OR,			  0, '|') \
  F(FI_PAIR_CONSTRUCT,		'm', 'p') \
  F(FI_EC_CONSTRUCT,		'm', 'c') \
  F(FI_LC_CONSTRUCT,		'm', 'l') \
  F(FI_PATHMASK_CONSTRUCT,	'm', 'P') \
  F(FI_NEQ,			'!', '=') \
  F(FI_EQ,			'=', '=') \
  F(FI_LT,			  0, '<') \
  F(FI_LTE,			'<', '=') \
  F(FI_NOT,			  0, '!') \
  F(FI_MATCH,			  0, '~') \
  F(FI_NOT_MATCH,		'!', '~') \
  F(FI_DEFINED,			'd', 'e') \
  F(FI_TYPE,			  0, 'T') \
  F(FI_IS_V4,			'I', 'i') \
  F(FI_SET,			  0, 's') \
  F(FI_CONSTANT,		  0, 'c') \
  F(FI_VARIABLE,		  0, 'V') \
  F(FI_CONSTANT_INDIRECT,	  0, 'C') \
  F(FI_PRINT,			  0, 'p') \
  F(FI_CONDITION,		  0, '?') \
  F(FI_PRINT_AND_DIE,		'p', ',') \
  F(FI_RTA_GET,			  0, 'a') \
  F(FI_RTA_SET,			'a', 'S') \
  F(FI_EA_GET,			'e', 'a') \
  F(FI_EA_SET,			'e', 'S') \
  F(FI_PREF_GET,		  0, 'P') \
  F(FI_PREF_SET,		'P', 'S') \
  F(FI_LENGTH,			  0, 'L') \
  F(FI_ROA_MAXLEN,		'R', 'M') \
  F(FI_ROA_ASN,			'R', 'A') \
  F(FI_SADR_SRC,		'n', 's') \
  F(FI_IP,			'c', 'p') \
  F(FI_ROUTE_DISTINGUISHER,	'R', 'D') \
  F(FI_AS_PATH_FIRST,		'a', 'f') \
  F(FI_AS_PATH_LAST,		'a', 'l') \
  F(FI_AS_PATH_LAST_NAG,	'a', 'L') \
  F(FI_RETURN,			  0, 'r') \
  F(FI_CALL,			'c', 'a') \
  F(FI_CLEAR_LOCAL_VARS,	'c', 'V') \
  F(FI_SWITCH,			'S', 'W') \
  F(FI_IP_MASK,			'i', 'M') \
  F(FI_EMPTY,			  0, 'E') \
  F(FI_PATH_PREPEND,		'A', 'p') \
  F(FI_CLIST_ADD_DEL,		'C', 'a') \
  F(FI_ROA_CHECK,		'R', 'C') \
  F(FI_FORMAT,			  0, 'F') \
  F(FI_ASSERT,			'a', 's')

/* The enum itself */
enum f_instruction_code {
#define F(c,a,b) \
  c,
FI__LIST
#undef F
  FI__MAX,
} PACKED;

/* Convert the instruction back to the enum name */
const char *f_instruction_name(enum f_instruction_code fi);

enum f_instruction_flags {
  FIF_PRINTED = 1,		/* FI_PRINT_AND_DIE: message put in buffer */
};

union f_inst_attr {
  uint i;
  void *p;
  struct rtable_config *rtc;
};

/* Instruction structure for config */
struct f_inst {
  struct f_inst *next;	/* Next instruction to be executed */
  enum f_instruction_code fi_code;	/* The instruction itself */
  u16 aux;		/* Extension to instruction code, T_*, EA_*, EAF_*  */
  union {
    union f_inst_attr a[3];		/* The three arguments */
    struct f_val val;	/* The value if FI_CONSTANT */
    struct {
      union f_inst_attr sa_a[1];
      struct f_static_attr sa;	/* Static attribute def for FI_RTA_* */
    };
    struct {
      union f_inst_attr da_a[1];
      struct f_dynamic_attr da; /* Dynamic attribute def for FI_EA_* */
    };
  };
  int lineno;
};

#define arg1 a[0].p
#define arg2 a[1].p
#define arg3 a[2].p

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
    const struct f_line *lines[2];
    enum filter_return fret;
    struct f_static_attr sa;
    struct f_dynamic_attr da;
    enum ec_subtype ecs;
    const struct f_path_mask *pm;
    const char *s;
    const struct f_tree *tree;
  };					/* Additional instruction data */
};

/* Line of instructions to be unconditionally executed one after another */
struct f_line {
  uint len;				/* Line length */
  int stack_balance;			/* How does the stack pointer move */
  struct f_line_item items[0];		/* The items themselves */
};

/* The filter encapsulating structure to be pointed-to from outside */
struct filter {
  char *name;
  struct f_line *root;
};

/* Convert the f_inst infix tree to the f_line structures */
struct f_line *f_postfixify(struct f_inst *root);

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

struct f_inst *f_new_inst(enum f_instruction_code fi_code);
struct f_inst *f_new_inst_da(enum f_instruction_code fi_code, struct f_dynamic_attr da);
struct f_inst *f_new_inst_sa(enum f_instruction_code fi_code, struct f_static_attr sa);
static inline struct f_dynamic_attr f_new_dynamic_attr(u8 type, u8 bit, enum f_type f_type, uint code) /* Type as core knows it, type as filters know it, and code of dynamic attribute */
{ return (struct f_dynamic_attr) { .type = type, .bit = bit, .f_type = f_type, .ea_code = code }; }   /* f_type currently unused; will be handy for static type checking */
static inline struct f_static_attr f_new_static_attr(int f_type, int code, int readonly)
{ return (struct f_static_attr) { .f_type = f_type, .sa_code = code, .readonly = readonly }; }
struct f_tree *f_new_tree(void);
struct f_inst *f_generate_complex(int operation, int operation_aux, struct f_dynamic_attr da, struct f_inst *argument);
struct f_inst *f_generate_roa_check(struct rtable_config *table, struct f_inst *prefix, struct f_inst *asn);


struct f_tree *build_tree(struct f_tree *);
const struct f_tree *find_tree(const struct f_tree *t, const struct f_val *val);
int same_tree(const struct f_tree *t1, const struct f_tree *t2);
void tree_format(struct f_tree *t, buffer *buf);

struct f_trie *f_new_trie(linpool *lp, uint node_size);
void *trie_add_prefix(struct f_trie *t, const net_addr *n, uint l, uint h);
int trie_match_net(struct f_trie *t, const net_addr *n);
int trie_same(struct f_trie *t1, struct f_trie *t2);
void trie_format(struct f_trie *t, buffer *buf);

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
