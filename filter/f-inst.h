/*
 *	BIRD Internet Routing Daemon -- Filter instructions
 *
 *	(c) 1999 Pavel Machek <pavel@ucw.cz>
 *	(c) 2018--2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	Filter interpreter data structures and internal API.
 *	The filter code goes through several phases:
 *
 *	1  Parsing
 *	Flex- and Bison-generated parser decodes the human-readable data into
 *	a struct f_inst tree. This is an infix tree that was interpreted by
 *	depth-first search execution in previous versions of the interpreter.
 *	All instructions have their constructor: f_new_inst(FI_code, ...)
 *	translates into f_new_inst_FI_code(...) and the types are checked in
 *	compile time.
 *
 *	2  Linearize before interpreting
 *	The infix tree is always interpreted in the same order. Therefore we
 *	sort the instructions one after another into struct f_line. Results
 *	and arguments of these instructions are implicitly put on a value
 *	stack; e.g. the + operation just takes two arguments from the value
 *	stack and puts the result on there.
 *
 *	3  Interpret
 *	The given line is put on a custom execution stack. If needed (FI_CALL,
 *	FI_SWITCH, FI_AND, FI_OR, FI_CONDITION, ...), another line is put on top
 *	of the stack; when that line finishes, the execution continues on the
 *	older lines on the stack where it stopped before.
 *
 *	4  Same
 *	On config reload, the filters have to be compared whether channel
 *	reload is needed or not. The comparison is done by comparing the
 *	struct f_line's recursively.
 *
 *	The main purpose of this rework was to improve filter performance
 *	by making the interpreter non-recursive.
 *
 *	The other outcome is concentration of instruction definitions to
 *	one place -- filter/f-inst.c
 */

#ifndef _BIRD_F_INST_H_
#define _BIRD_F_INST_H_

#include "nest/bird.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/data.h"

/* Flags for instructions */
enum f_instruction_flags {
  FIF_PRINTED = 1,		/* FI_PRINT_AND_DIE: message put in buffer */
} PACKED;

/* Include generated filter instruction declarations */
#include "filter/inst-gen.h"

#define f_new_inst(...) MACRO_CONCAT_AFTER(f_new_inst_, MACRO_FIRST(__VA_ARGS__))(__VA_ARGS__)

/* Convert the instruction back to the enum name */
const char *f_instruction_name(enum f_instruction_code fi);

/* Filter structures for execution */
/* Line of instructions to be unconditionally executed one after another */
struct f_line {
  uint len;				/* Line length */
  u8 args;				/* Function: Args required */
  u8 vars;
  struct f_line_item items[0];		/* The items themselves */
};

/* Convert the f_inst infix tree to the f_line structures */
struct f_line *f_linearize_concat(const struct f_inst * const inst[], uint count);
static inline struct f_line *f_linearize(const struct f_inst *root)
{ return f_linearize_concat(&root, 1); }

void f_dump_line(const struct f_line *, uint indent);

struct filter *f_new_where(struct f_inst *);
static inline struct f_dynamic_attr f_new_dynamic_attr(u8 type, enum f_type f_type, uint code) /* Type as core knows it, type as filters know it, and code of dynamic attribute */
{ return (struct f_dynamic_attr) { .type = type, .f_type = f_type, .ea_code = code }; }   /* f_type currently unused; will be handy for static type checking */
static inline struct f_dynamic_attr f_new_dynamic_attr_bit(u8 bit, enum f_type f_type, uint code) /* Type as core knows it, type as filters know it, and code of dynamic attribute */
{ return (struct f_dynamic_attr) { .type = EAF_TYPE_BITFIELD, .bit = bit, .f_type = f_type, .ea_code = code }; }   /* f_type currently unused; will be handy for static type checking */
static inline struct f_static_attr f_new_static_attr(int f_type, int code, int readonly)
{ return (struct f_static_attr) { .f_type = f_type, .sa_code = code, .readonly = readonly }; }
struct f_inst *f_generate_complex(enum f_instruction_code fi_code, struct f_dynamic_attr da, struct f_inst *argument);
struct f_inst *f_generate_roa_check(struct rtable_config *table, struct f_inst *prefix, struct f_inst *asn);

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
