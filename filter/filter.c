/*
 *	Filters: utility functions
 *
 *	Copyright 1998 Pavel Machek <pavel@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 */

/**
 * DOC: Filters
 *
 * You can find sources of the filter language in |filter/|
 * directory. File |filter/config.Y| contains filter grammar and basically translates
 * the source from user into a tree of &f_inst structures. These trees are
 * later interpreted using code in |filter/filter.c|.
 *
 * A filter is represented by a tree of &f_inst structures, later translated
 * into lists called &f_line. All the instructions are defined and documented
 * in |filter/f-inst.c| definition file.
 *
 * Filters use a &f_val structure for their data. Each &f_val
 * contains type and value (types are constants prefixed with %T_).
 * Look into |filter/data.h| for more information and appropriate calls.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/string.h"
#include "lib/unaligned.h"
#include "lib/ip.h"
#include "lib/net.h"
#include "lib/flowspec.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/attrs.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/f-inst.h"
#include "filter/data.h"


/* Exception bits */
enum f_exception {
  FE_RETURN = 0x1,
};

/* Global filter runtime */
static struct {
  _Atomic u16 filter_vstk;
  _Atomic u16 filter_estk;
} global_filter_runtime = {
  .filter_vstk = 128,
  .filter_estk = 128,
};

struct filter_exec_stack {
  const struct f_line *line;		/* The line that is being executed */
  uint pos;				/* Instruction index in the line */
  uint ventry;				/* Value stack depth on entry */
  uint vbase;				/* Where to index variable positions from */
  enum f_exception emask;		/* Exception mask */
};

/* Internal filter state, to be allocated on stack when executing filters */
struct filter_state {
  /* Stacks needed for execution */
  struct filter_stack {
    /* Current filter stack depth */

    /* Value stack */
    uint vcnt, vlen;
    struct f_val *vstk;

    /* Instruction stack for execution */
    uint ecnt, elen;
    struct filter_exec_stack *estk;
  } stack;

  /* The route we are processing. This may be NULL to indicate no route available. */
  struct rte *rte;

  /* Additional external values provided to the filter */
  const struct f_val *val;

  /* Buffer for log output */
  log_buffer buf;

  /* Filter execution flags */
  int flags;
};

_Thread_local static struct filter_state filter_state;

void (*bt_assert_hook)(int result, const struct f_line_item *assert);

#define _f_stack_init(fs, px) ((fs).stack.px##stk = alloca(sizeof(*(fs).stack.px##stk) * ((fs).stack.px##len = atomic_load_explicit(&global_filter_runtime.filter_##px##stk, memory_order_relaxed))))

#define f_stack_init(fs) ( _f_stack_init(fs, v), _f_stack_init(fs, e) )

static struct tbf rl_runtime_err = TBF_DEFAULT_LOG_LIMITS;

/**
 * interpret
 * @fs: filter state
 * @what: filter to interpret
 *
 * Interpret given tree of filter instructions. This is core function
 * of filter system and does all the hard work.
 *
 * Each instruction has 4 fields: code (which is instruction code),
 * aux (which is extension to instruction code, typically type),
 * arg1 and arg2 - arguments. Depending on instruction, arguments
 * are either integers, or pointers to instruction trees. Common
 * instructions like +, that have two expressions as arguments use
 * TWOARGS macro to get both of them evaluated.
 */
static enum filter_return
interpret(struct filter_state *fs, const struct f_line *line, uint argc, const struct f_val *argv, uint resc, struct f_val *resv)
{
  /* Check of appropriate number of arguments */
  ASSERT(line->args == argc);

  /* Initialize the filter stack */
  struct filter_stack *fstk = &fs->stack;

  /* Set the arguments and top-level variables */
  fstk->vcnt = line->vars + line->args;
  memcpy(fstk->vstk, argv, sizeof(struct f_val) * line->args);
  memset(fstk->vstk + argc, 0, sizeof(struct f_val) * line->vars);

  /* The same as with the value stack. Not resetting the stack completely for performance reasons. */
  fstk->ecnt = 1;
  fstk->estk[0] = (struct filter_exec_stack) {
    .line = line,
    .pos = 0,
  };

#define curline fstk->estk[fstk->ecnt-1]
#define prevline fstk->estk[fstk->ecnt-2]

#ifdef LOCAL_DEBUG
  debug("Interpreting line.");
  f_dump_line(line, 1);
#endif

  while (fstk->ecnt > 0) {
    while (curline.pos < curline.line->len) {
      const struct f_line_item *what = &(curline.line->items[curline.pos++]);

      switch (what->fi_code) {
#define res fstk->vstk[fstk->vcnt]
#define vv(i) fstk->vstk[fstk->vcnt + (i)]
#define v1 vv(0)
#define v2 vv(1)
#define v3 vv(2)

#define f_vcnt_check_overflow(n) do { if (fstk->vcnt + n >= fstk->vlen) runtime("Filter execution stack overflow"); } while (0)

#define runtime(fmt, ...) do { \
  if (!(fs->flags & FF_SILENT)) \
    log_rl(&rl_runtime_err, L_ERR "filters, line %d: " fmt, what->lineno, ##__VA_ARGS__); \
  return F_ERROR; \
} while(0)

#define falloc(size)	tmp_alloc(size)
#define fpool		tmp_linpool

#include "filter/inst-interpret.c"
#undef res
#undef v1
#undef v2
#undef v3
#undef runtime
#undef falloc
#undef fpool
      }
    }

    /* End of current line. Drop local variables before exiting. */
    fstk->vcnt = curline.ventry + curline.line->results;
    fstk->ecnt--;
  }

  if (fstk->vcnt != resc)
  {
    log_rl(&rl_runtime_err, L_ERR "Filter expected to leave %d values on stack but %d left instead", resc, fstk->vcnt);
    return F_ERROR;
  }

  memcpy(resv, fstk->vstk, sizeof(struct f_val) * resc);
  return F_NOP;
}


/**
 * f_run - run a filter for a route
 * @filter: filter to run
 * @rte: route being filtered, must be write-able
 * @tmp_pool: all filter allocations go from this pool
 * @flags: flags
 *
 * If @rte->attrs is cached, the returned rte allocates a new rta on
 * tmp_pool, otherwise the filters may modify it.
 */
enum filter_return
f_run(const struct filter *filter, struct rte *rte, int flags)
{
  if (filter == FILTER_ACCEPT)
    return F_ACCEPT;

  if (filter == FILTER_REJECT)
    return F_REJECT;

  return f_run_args(filter, rte, 0, NULL, flags);
}

enum filter_return
f_run_args(const struct filter *filter, struct rte *rte, uint argc, const struct f_val *argv, int flags)
{
  DBG( "Running filter `%s'...", filter->name );

  /* Initialize the filter state */
  filter_state = (struct filter_state) {
    .rte = rte,
    .flags = flags,
  };

  f_stack_init(filter_state);

  /* Run the interpreter itself */
  enum filter_return fret = interpret(&filter_state, filter->root, argc, argv, 0, NULL);

  /* Process the filter output, log it and return */
  if (fret < F_ACCEPT) {
    if (!(filter_state.flags & FF_SILENT))
      log_rl(&rl_runtime_err, L_ERR "Filter %s did not return accept nor reject. Make up your mind", filter_name(filter));
    return F_ERROR;
  }
  DBG( "done (%u)\n", res.val.i );
  return fret;
}

/**
 * f_eval_rte - run a filter line for an uncached route
 * @expr: filter line to run
 * @rte: route being filtered, may be modified
 * @tmp_pool: all filter allocations go from this pool
 *
 * This specific filter entry point runs the given filter line
 * (which must not have any arguments) on the given route.
 *
 * The route MUST NOT have REF_COW set and its attributes MUST NOT
 * be cached by rta_lookup().
 */

enum filter_return
f_eval_rte(const struct f_line *expr, struct rte *rte, uint argc, const struct f_val *argv, uint resc, struct f_val *resv)
{
  filter_state = (struct filter_state) {
    .rte = rte,
  };

  f_stack_init(filter_state);

  return interpret(&filter_state, expr, argc, argv, resc, resv);
}

/*
 * f_eval - get a value of a term
 * @expr: filter line containing the term
 * @tmp_pool: long data may get allocated from this pool
 * @pres: here the output will be stored if requested
 */
enum filter_return
f_eval(const struct f_line *expr, struct f_val *pres)
{
  filter_state = (struct filter_state) {};

  f_stack_init(filter_state);

  enum filter_return fret = interpret(&filter_state, expr, 0, NULL, !!pres, pres);
  return fret;
}

/*
 * cf_eval_tmp - evaluate a value of a term and check its type
 */
struct f_val
cf_eval_tmp(const struct f_inst *inst, int type)
{
  struct f_val val;

  if (f_eval(f_linearize(inst, 1), &val) > F_RETURN)
    cf_error("Runtime error while evaluating expression; see log for details");

  if (type != T_VOID && val.type != type)
    cf_error("Expression of type %s expected", f_type_name(type));

  return val;
}


/*
 * f_eval_buf - get a value of a term and print it to the supplied buffer
 */
enum filter_return
f_eval_buf(const struct f_line *expr, buffer *buf)
{
  struct f_val val;
  enum filter_return fret = f_eval(expr, &val);
  if (fret <= F_RETURN)
    val_format(&val, buf);
  return fret;
}

/**
 * filter_same - compare two filters
 * @new: first filter to be compared
 * @old: second filter to be compared
 *
 * Returns 1 in case filters are same, otherwise 0. If there are
 * underlying bugs, it will rather say 0 on same filters than say
 * 1 on different.
 */
int
filter_same(const struct filter *new, const struct filter *old)
{
  if (old == new)	/* Handle FILTER_ACCEPT and FILTER_REJECT */
    return 1;
  if (old == FILTER_ACCEPT || old == FILTER_REJECT ||
      new == FILTER_ACCEPT || new == FILTER_REJECT)
    return 0;

  if ((!old->sym) && (!new->sym))
    return f_same(new->root, old->root);

  if ((!old->sym) || (!new->sym))
    return 0;

  if (strcmp(old->sym->name, new->sym->name))
    return 0;

  return new->sym->flags & SYM_FLAG_SAME;
}

/* Initialize filter knobs */
void
filter_preconfig(struct config *new)
{
  new->filter_vstk = 128;
  new->filter_estk = 128;
}

/**
 * filter_commit - do filter comparisons on all the named functions and filters
 */
void
filter_commit(struct config *new, struct config *old)
{
  /* Update filter stack size variables */
  atomic_store_explicit(&global_filter_runtime.filter_vstk, new->filter_vstk, memory_order_relaxed);
  atomic_store_explicit(&global_filter_runtime.filter_estk, new->filter_estk, memory_order_relaxed);

  if (!old)
    return;

  struct symbol *sym, *osym;
  WALK_LIST(sym, new->symbols)
    switch (sym->class) {
      case SYM_FUNCTION:
	if ((osym = cf_find_symbol(old, sym->name)) &&
	    (osym->class == SYM_FUNCTION) &&
	    f_same(sym->function, osym->function))
	  sym->flags |= SYM_FLAG_SAME;
	else
	  sym->flags &= ~SYM_FLAG_SAME;
	break;

      case SYM_FILTER:
	if ((osym = cf_find_symbol(old, sym->name)) &&
	    (osym->class == SYM_FILTER) &&
	    f_same(sym->filter->root, osym->filter->root))
	  sym->flags |= SYM_FLAG_SAME;
	else
	  sym->flags &= ~SYM_FLAG_SAME;
	break;
    }
}

void channel_filter_dump(const struct filter *f)
{
  if (f == FILTER_ACCEPT)
    debug(" ALL");
  else if (f == FILTER_REJECT)
    debug(" NONE");
  else if (f == FILTER_UNDEF)
    debug(" UNDEF");
  else if (f->sym) {
    ASSERT(f->sym->filter == f);
    debug(" named filter %s", f->sym->name);
  } else {
    debug("\n");
    f_dump_line(f->root, 2);
  }
}

void filters_dump_all(void)
{
  struct symbol *sym;
  WALK_LIST(sym, config->symbols) {
    switch (sym->class) {
      case SYM_FILTER:
	debug("Named filter %s:\n", sym->name);
	f_dump_line(sym->filter->root, 1);
	break;
      case SYM_FUNCTION:
	debug("Function %s:\n", sym->name);
	f_dump_line(sym->function, 1);
	break;
      case SYM_PROTO:
	{
	  debug("Protocol %s:\n", sym->name);
	  struct channel *c;
	  WALK_LIST(c, sym->proto->proto->channels) {
	    debug(" Channel %s (%s) IMPORT", c->name, net_label[c->net_type]);
	    channel_filter_dump(c->in_filter);
	    debug(" EXPORT", c->name, net_label[c->net_type]);
	    channel_filter_dump(c->out_filter);
	    debug("\n");
	  }
	}
    }
  }
}
