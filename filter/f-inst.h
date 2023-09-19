/*
 *	BIRD Internet Routing Daemon -- Filter instructions
 *
 *	(c) 1999 Pavel Machek <pavel@ucw.cz>
 *	(c) 2018--2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	Filter interpreter data structures and internal API.
 *	See filter/f-inst.c for documentation.
 */

#ifndef _BIRD_F_INST_H_
#define _BIRD_F_INST_H_

#include "nest/bird.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/data.h"
#include "lib/buffer.h"
#include "lib/flowspec.h"
#include "lib/string.h"

/* Flags for instructions */
enum f_instruction_flags {
  FIF_RECURSIVE = 1,		/* FI_CALL: function is directly recursive */
} PACKED;

/* Include generated filter instruction declarations */
#include "filter/inst-gen.h"

#define f_new_inst(...) MACRO_CONCAT_AFTER(f_new_inst_, MACRO_FIRST(__VA_ARGS__))(__VA_ARGS__)

/* Convert the instruction back to the enum name */
const char *f_instruction_name_(enum f_instruction_code fi);
static inline const char *f_instruction_name(enum f_instruction_code fi)
{ return f_instruction_name_(fi) + 3; }


int f_const_promotion_(struct f_inst *arg, enum f_type want, int update);

static inline int f_const_promotion(struct f_inst *arg, enum f_type want)
{ return f_const_promotion_(arg, want, 1); }

static inline int f_try_const_promotion(struct f_inst *arg, enum f_type want)
{ return f_const_promotion_(arg, want, 0); }


struct f_arg {
  struct symbol *arg;
  struct f_arg *next;
};

/* Filter structures for execution */
/* Line of instructions to be unconditionally executed one after another */
struct f_line {
  uint len;				/* Line length */
  u8 args;				/* Function: Args required */
  u8 vars;
  u8 results;				/* Results left on stack: cmd -> 0, term -> 1 */
  u8 return_type;			/* Type which the function returns */
  struct f_arg *arg_list;
  struct f_line_item items[0];		/* The items themselves */
};

/* Convert the f_inst infix tree to the f_line structures */
struct f_line *f_linearize_concat(const struct f_inst * const inst[], uint count, uint results);
static inline struct f_line *f_linearize(const struct f_inst *root, uint results)
{ return f_linearize_concat(&root, 1, results); }

void f_dump_line(const struct f_line *, uint indent);


/* Recursive iteration over filter instructions */

struct filter_iterator {
  BUFFER_(const struct f_line *) lines;
};

void f_add_lines(const struct f_line_item *what, struct filter_iterator *fit);

#define FILTER_ITERATE_INIT(fit, filter, pool)			\
  ({								\
    BUFFER_INIT((fit)->lines, (pool), 32);			\
    BUFFER_PUSH((fit)->lines) = (filter)->root;			\
  })

#define FILTER_ITERATE(fit, fi) ({				\
  const struct f_line *fl_;					\
  while (!BUFFER_EMPTY((fit)->lines))				\
  {								\
    BUFFER_POP((fit)->lines);					\
    fl_ = (fit)->lines.data[(fit)->lines.used];			\
    for (uint i_ = 0; i_ < fl_->len; i_++)			\
    {								\
      const struct f_line_item *fi = &fl_->items[i_];		\
      f_add_lines(fi, (fit));

#define FILTER_ITERATE_END } } })

#define FILTER_ITERATE_CLEANUP(fit)				\
  ({								\
    mb_free((fit)->lines.data);					\
    memset((fit), 0, sizeof(struct filter_iterator));		\
  })


struct filter *f_new_where(struct f_inst *);
struct f_inst *f_dispatch_method(struct symbol *sym, struct f_inst *obj, struct f_inst *args, int skip);
struct f_inst *f_dispatch_method_x(const char *name, enum f_type t, struct f_inst *obj, struct f_inst *args);
struct f_inst *f_for_cycle(struct symbol *var, struct f_inst *term, struct f_inst *block);
struct f_inst *f_print(struct f_inst *vars, int flush, enum filter_return fret);

static inline struct f_dynamic_attr f_new_dynamic_attr(u8 type, enum f_type f_type, uint code) /* Type as core knows it, type as filters know it, and code of dynamic attribute */
{ return (struct f_dynamic_attr) { .type = type, .f_type = f_type, .ea_code = code }; }   /* f_type currently unused; will be handy for static type checking */
static inline struct f_dynamic_attr f_new_dynamic_attr_bit(u8 bit, enum f_type f_type, uint code) /* Type as core knows it, type as filters know it, and code of dynamic attribute */
{ return (struct f_dynamic_attr) { .type = EAF_TYPE_BITFIELD, .bit = bit, .f_type = f_type, .ea_code = code }; }   /* f_type currently unused; will be handy for static type checking */
static inline struct f_static_attr f_new_static_attr(int f_type, int code, int readonly)
{ return (struct f_static_attr) { .f_type = f_type, .sa_code = code, .readonly = readonly }; }

static inline int f_type_attr(int f_type) {
  switch (f_type) {
    case T_INT:		return EAF_TYPE_INT;
    case T_IP:		return EAF_TYPE_IP_ADDRESS;
    case T_QUAD:	return EAF_TYPE_ROUTER_ID;
    case T_PATH:	return EAF_TYPE_AS_PATH;
    case T_CLIST:	return EAF_TYPE_INT_SET;
    case T_ECLIST:	return EAF_TYPE_EC_SET;
    case T_LCLIST:	return EAF_TYPE_LC_SET;
    case T_BYTESTRING:	return EAF_TYPE_OPAQUE;
    default:
      cf_error("Custom route attribute of unsupported type");
  }
}

/* Hook for call bt_assert() function in configuration */
extern void (*bt_assert_hook)(int result, const struct f_line_item *assert);

/* Bird Tests */
struct f_bt_test_suite {
  node n;			/* Node in config->tests */
  const struct f_line *fn;	/* Root of function */
  const struct f_line *cmp;	/* Compare to this function */
  const char *fn_name;		/* Name of test */
  const char *dsc;		/* Description */
  int result;			/* Desired result */
};

#endif
