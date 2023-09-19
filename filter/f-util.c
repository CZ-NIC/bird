/*
 *	Filters: utility functions
 *
 *	Copyright 1998 Pavel Machek <pavel@ucw.cz>
 *		  2017 Jan Maria Matejka <mq@ucw.cz>
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
f_dispatch_method_x(const char *name, enum f_type t, struct f_inst *obj, struct f_inst *args)
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

  enum f_type el_type = f_type_element_type(term->type);
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


#define CA_KEY(n)	n->name, n->fda.type
#define CA_NEXT(n)	n->next
#define CA_EQ(na,ta,nb,tb)	(!strcmp(na,nb) && (ta == tb))
#define CA_FN(n,t)	(mem_hash(n, strlen(n)) ^ (t*0xaae99453U))
#define CA_ORDER	8 /* Fixed */

struct ca_storage {
  struct ca_storage *next;
  struct f_dynamic_attr fda;
  u32 uc;
  char name[0];
};

HASH(struct ca_storage) ca_hash;

static struct idm ca_idm;
static struct ca_storage **ca_storage;
static uint ca_storage_max;

static void
ca_free(resource *r)
{
  struct custom_attribute *ca = (void *) r;
  struct ca_storage *cas = HASH_FIND(ca_hash, CA, ca->name, ca->fda->type);
  ASSERT(cas);

  ca->name = NULL;
  ca->fda = NULL;
  if (!--cas->uc) {
    uint id = EA_CUSTOM_ID(cas->fda.ea_code);
    idm_free(&ca_idm, id);
    HASH_REMOVE(ca_hash, CA, cas);
    ca_storage[id] = NULL;
    mb_free(cas);
  }
}

static void
ca_dump(resource *r)
{
  struct custom_attribute *ca = (void *) r;
  debug("name \"%s\" id 0x%04x ea_type 0x%02x f_type 0x%02x\n",
      ca->name, ca->fda->ea_code, ca->fda->type, ca->fda->f_type);
}

static struct resclass ca_class = {
  .name = "Custom attribute",
  .size = sizeof(struct custom_attribute),
  .free = ca_free,
  .dump = ca_dump,
  .lookup = NULL,
  .memsize = NULL,
};

struct custom_attribute *
ca_lookup(pool *p, const char *name, int f_type)
{
  int ea_type;

  switch (f_type) {
    case T_INT:
      ea_type = EAF_TYPE_INT;
      break;
    case T_IP:
      ea_type = EAF_TYPE_IP_ADDRESS;
      break;
    case T_QUAD:
      ea_type = EAF_TYPE_ROUTER_ID;
      break;
    case T_PATH:
      ea_type = EAF_TYPE_AS_PATH;
      break;
    case T_CLIST:
      ea_type = EAF_TYPE_INT_SET;
      break;
    case T_ECLIST:
      ea_type = EAF_TYPE_EC_SET;
      break;
    case T_LCLIST:
      ea_type = EAF_TYPE_LC_SET;
      break;
    case T_BYTESTRING:
      ea_type = EAF_TYPE_OPAQUE;
      break;
    default:
      cf_error("Custom route attribute of unsupported type");
  }

  static int inited = 0;
  if (!inited) {
    idm_init(&ca_idm, config_pool, 8);
    HASH_INIT(ca_hash, config_pool, CA_ORDER);

    ca_storage_max = 256;
    ca_storage = mb_allocz(config_pool, sizeof(struct ca_storage *) * ca_storage_max);

    inited++;
  }

  struct ca_storage *cas = HASH_FIND(ca_hash, CA, name, ea_type);
  if (cas) {
    cas->uc++;
  } else {

    uint id = idm_alloc(&ca_idm);

    if (id >= EA_CUSTOM_BIT)
      cf_error("Too many custom attributes.");

    if (id >= ca_storage_max) {
      ca_storage_max *= 2;
      ca_storage = mb_realloc(ca_storage, sizeof(struct ca_storage *) * ca_storage_max * 2);
    }

    cas = mb_allocz(config_pool, sizeof(struct ca_storage) + strlen(name) + 1);
    cas->fda = f_new_dynamic_attr(ea_type, f_type, EA_CUSTOM(id));
    cas->uc = 1;

    strcpy(cas->name, name);
    ca_storage[id] = cas;

    HASH_INSERT(ca_hash, CA, cas);
  }

  struct custom_attribute *ca = ralloc(p, &ca_class);
  ca->fda = &(cas->fda);
  ca->name = cas->name;
  return ca;
}

const char *
ea_custom_name(uint ea)
{
  uint id = EA_CUSTOM_ID(ea);
  if (id >= ca_storage_max)
    return NULL;

  if (!ca_storage[id])
    return NULL;

  return ca_storage[id]->name;
}

