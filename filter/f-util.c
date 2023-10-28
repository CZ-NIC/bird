/*
 *	Filters: utility functions
 *
 *	Copyright 1998 Pavel Machek <pavel@ucw.cz>
 *		  2017 Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/f-inst.h"
#include "lib/idm.h"
#include "nest/protocol.h"
#include "nest/rt.h"

#define P(a,b) ((a<<8) | b)

const char *
filter_name(const struct filter *filter)
{
  if (!filter)
    return "ACCEPT";
  else if (filter == FILTER_REJECT)
    return "REJECT";
  else if (!filter->sym)
    return "(unnamed)";
  else
    return filter->sym->name;
}

struct filter *f_new_where(struct f_inst *where)
{
  struct f_inst *cond = f_new_inst(FI_CONDITION, where,
				   f_new_inst(FI_DIE, F_ACCEPT),
				   f_new_inst(FI_DIE, F_REJECT));

  struct filter *f = cfg_allocz(sizeof(struct filter));
  f->root = f_linearize(cond, 0);
  return f;
}

struct f_inst *
f_for_cycle(struct symbol *var, struct f_inst *term, struct f_inst *block)
{
  ASSERT((var->class & ~0xff) == SYM_VARIABLE);
  ASSERT(term->next == NULL);

  /* Static type check */
  if (term->type == T_VOID)
    cf_error("Couldn't infer the type of FOR expression, please assign it to a variable.");

  enum btype el_type = f_type_element_type(term->type);
  struct sym_scope *scope = el_type ? f_type_method_scope(term->type) : NULL;
  struct symbol *ms = scope ? cf_find_symbol_scope(scope, "!for_next") : NULL;

  if (!ms)
    cf_error("Type %s is not iterable, can't be used in FOR", f_type_name(term->type));

  if (var->class != (SYM_VARIABLE | el_type))
    cf_error("Loop variable '%s' in FOR must be of type %s, got %s",
	var->name, f_type_name(el_type), f_type_name(var->class & 0xff));

  /* Push the iterator auxiliary value onto stack */
  struct f_inst *iter = term->next = f_new_inst(FI_CONSTANT, (struct f_val) {});

  /* Initialize the iterator variable */
  iter->next = f_new_inst(FI_CONSTANT, (struct f_val) { .type = el_type });

  /* Prepend the loop block with loop beginning instruction */
  struct f_inst *loop_start = f_new_inst(FI_FOR_LOOP_START, var);
  loop_start->next = block;

  return ms->method->new_inst(term, loop_start);
}

struct f_inst *
f_print(struct f_inst *vars, int flush, enum filter_return fret)
{
#define AX(...)  do { struct f_inst *_tmp = f_new_inst(__VA_ARGS__); _tmp->next = output; output = _tmp; } while (0)
  struct f_inst *output = NULL;
  if (fret != F_NOP)
    AX(FI_DIE, fret);

  if (flush)
    AX(FI_FLUSH);

  while (vars)
  {
    struct f_inst *tmp = vars;
    vars = vars->next;
    tmp->next = NULL;

    AX(FI_PRINT, tmp);
  }

  return output;
#undef AX
}
