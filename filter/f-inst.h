/*
 *	BIRD Internet Routing Daemon -- Filter instructions
 *
 *	(c) 1999 Pavel Machek <pavel@ucw.cz>
 *	(c) 2018--2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_F_INST_H_
#define _BIRD_F_INST_H_

#include "nest/bird.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/f-util.h"

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

#include "filter/f-inst-decl.h"

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

/* Convert the f_inst infix tree to the f_line structures */
struct f_line *f_postfixify_concat(const struct f_inst * const inst[], uint count);
static inline struct f_line *f_postfixify(const struct f_inst *root)
{ return f_postfixify_concat(&root, 1); }

struct filter *f_new_where(const struct f_inst *);
static inline struct f_dynamic_attr f_new_dynamic_attr(u8 type, u8 bit, enum f_type f_type, uint code) /* Type as core knows it, type as filters know it, and code of dynamic attribute */
{ return (struct f_dynamic_attr) { .type = type, .bit = bit, .f_type = f_type, .ea_code = code }; }   /* f_type currently unused; will be handy for static type checking */
static inline struct f_static_attr f_new_static_attr(int f_type, int code, int readonly)
{ return (struct f_static_attr) { .f_type = f_type, .sa_code = code, .readonly = readonly }; }
struct f_inst *f_generate_complex(enum f_instruction_code fi_code, struct f_dynamic_attr da, struct f_inst *argument);
struct f_inst *f_generate_roa_check(struct rtable_config *table, struct f_inst *prefix, struct f_inst *asn);

/* Hook for call bt_assert() function in configuration */
extern void (*bt_assert_hook)(int result, const struct f_line_item *assert);

/* Bird Tests */
struct f_bt_test_suite {
  node n;			/* Node in config->tests */
  struct f_line *fn;		/* Root of function */
  const char *fn_name;		/* Name of test */
  const char *dsc;		/* Description */
};

/* Include the auto-generated structures */
#include "filter/f-inst-struct.h"

#endif
