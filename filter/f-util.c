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
#include "nest/route.h"

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

struct filter *
f_new_where(struct f_inst *where)
{
  struct f_inst *cond = f_new_inst(FI_CONDITION, where,
				   f_new_inst(FI_DIE, F_ACCEPT),
				   f_new_inst(FI_DIE, F_REJECT));

  struct filter *f = cfg_allocz(sizeof(struct filter));
  f->root = f_linearize(cond, 0);
  return f;
}

static inline int
f_match_signature(const struct f_method *dsc, struct f_inst *args)
{
  int i, arg_num = (int) dsc->arg_num;

  for (i = 1; args && (i < arg_num); args = args->next, i++)
    if (dsc->args_type[i] && (args->type != dsc->args_type[i]) &&
	!f_try_const_promotion(args, dsc->args_type[i]))
      return 0;

  return !args && !(i < arg_num);
}

/* Variant of f_match_signature(), optimized for error reporting */
static inline void
f_match_signature_err(const struct f_method *dsc, struct f_inst *args, int *pos, int *want, int *got)
{
  int i, arg_num = (int) dsc->arg_num;

  for (i = 1; args && (i < arg_num); args = args->next, i++)
    if (dsc->args_type[i] && (args->type != dsc->args_type[i]) &&
	!f_try_const_promotion(args, dsc->args_type[i]))
      break;

  *pos = i;
  *want = (i < arg_num) ? dsc->args_type[i] : T_NONE;
  *got = args ? args->type : T_NONE;
}

struct f_inst *
f_dispatch_method(struct symbol *sym, struct f_inst *obj, struct f_inst *args, int skip)
{
  /* Find match */
  for (const struct f_method *dsc = sym->method; dsc; dsc = dsc->next)
    if (f_match_signature(dsc, args))
      return dsc->new_inst(obj, args);


  /* No valid match - format error message */

  int best_pos = -1;	/* Longest argument position with partial match */
  int best_got = 0;	/* Received type at best partial match position */
  int best_count = 0;	/* Number of partial matches at best position */
  const int best_max = 8;	/* Max number of reported types */
  int best_want[best_max];	/* Expected types at best position */

  for (const struct f_method *dsc = sym->method; dsc; dsc = dsc->next)
  {
    int pos, want, got;
    f_match_signature_err(dsc, args, &pos, &want, &got);

    /* Ignore shorter match */
    if (pos < best_pos)
      continue;

    /* Found longer match, reset existing results */
    if (pos > best_pos)
    {
      best_pos = pos;
      best_got = got;
      best_count = 0;
    }

    /* Skip duplicates */
    for (int i = 0; i < best_count; i++)
      if (best_want[i] == want)
	goto next;

    /* Skip if we have enough types */
    if (best_count >= best_max)
      continue;

    /* Add new expected type */
    best_want[best_count] = want;
    best_count++;
  next:;
  }

  /* There is at least one method */
  ASSERT(best_pos >= 0 && best_count > 0);

  /* Update best_pos for printing */
  best_pos = best_pos - skip + 1;

  if (!best_got)
    cf_error("Cannot infer type of argument %d of '%s', please assign it to a variable", best_pos, sym->name);

  /* Format list of expected types */
  buffer tbuf;
  STACK_BUFFER_INIT(tbuf, 128);
  for (int i = 0; i < best_count; i++)
    buffer_print(&tbuf, " / %s", best_want[i] ? f_type_name(best_want[i]) : "any");
  char *types = tbuf.start + 3;
  char *dots = (best_count >= best_max) || (tbuf.pos == tbuf.end) ? " / ..." : "";

  cf_error("Argument %d of '%s' expected %s%s, got %s",
	   best_pos, sym->name, types, dots, f_type_name(best_got));
}

struct f_inst *
f_dispatch_method_x(const char *name, enum btype t, struct f_inst *obj, struct f_inst *args)
{
  struct sym_scope *scope = f_type_method_scope(t);
  struct symbol *sym = cf_find_symbol_scope(scope, name);

  if (!sym)
    cf_error("Cannot dispatch method '%s'", name);

  return f_dispatch_method(sym, obj, args, 0);
}


struct f_inst *
f_for_cycle(struct symbol *var, struct f_inst *term, struct f_inst *block)
{
  ASSERT((var->class & ~0xff) == SYM_VARIABLE);
  ASSERT(term->next == NULL);

  /* Static type check */
  if (term->type == T_VOID)
    cf_error("Cannot infer type of FOR expression, please assign it to a variable");

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
f_implicit_roa_check(struct rtable_config *tab)
{
  const struct ea_class *def = ea_class_find("bgp_path");
  if (!def)
    bug("Couldn't find BGP AS Path attribute definition.");

  struct f_inst *path_getter = f_new_inst(FI_EA_GET, def);
  struct sym_scope *scope = f_type_method_scope(path_getter->type);
  struct symbol *ms = scope ? cf_find_symbol_scope(scope, "last") : NULL;

  if (!ms)
    bug("Couldn't find the \"last\" method for AS Path.");

  struct f_static_attr fsa = f_new_static_attr(T_NET, SA_NET, 1);

  return f_new_inst(FI_ROA_CHECK,
	    f_new_inst(FI_RTA_GET, fsa),
	    ms->method->new_inst(path_getter, NULL),
	    tab);
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
