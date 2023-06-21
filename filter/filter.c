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
#include "nest/attrs.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/f-inst.h"
#include "filter/data.h"


/* Exception bits */
enum f_exception {
  FE_RETURN = 0x1,
};


struct filter_stack {
  /* Value stack for execution */
#define F_VAL_STACK_MAX	4096
  uint vcnt;				/* Current value stack size; 0 for empty */
  uint ecnt;				/* Current execute stack size; 0 for empty */

  struct f_val vstk[F_VAL_STACK_MAX];	/* The stack itself */

  /* Instruction stack for execution */
#define F_EXEC_STACK_MAX 4096
  struct {
    const struct f_line *line;		/* The line that is being executed */
    uint pos;				/* Instruction index in the line */
    uint ventry;			/* Value stack depth on entry */
    uint vbase;				/* Where to index variable positions from */
    enum f_exception emask;		/* Exception mask */
  } estk[F_EXEC_STACK_MAX];
};

/* Internal filter state, to be allocated on stack when executing filters */
struct filter_state {
  /* Stacks needed for execution */
  struct filter_stack *stack;

  /* The route we are processing. This may be NULL to indicate no route available. */
  struct rte **rte;

  /* The old rta to be freed after filters are done. */
  struct rta *old_rta;

  /* Cached pointer to ea_list */
  struct ea_list **eattrs;

  /* Linpool for adata allocation */
  struct linpool *pool;

  /* Buffer for log output */
  struct buffer buf;

  /* Pointers to routes we are aggregating */
  const struct f_val *val;

  /* Filter execution flags */
  int flags;
};

_Thread_local static struct filter_state filter_state;
_Thread_local static struct filter_stack filter_stack;

void (*bt_assert_hook)(int result, const struct f_line_item *assert);

static inline void f_cache_eattrs(struct filter_state *fs)
{
  fs->eattrs = &((*fs->rte)->attrs->eattrs);
}

static inline void f_rte_cow(struct filter_state *fs)
{
  if (!((*fs->rte)->flags & REF_COW))
    return;

  *fs->rte = rte_cow(*fs->rte);
}

/*
 * rta_cow - prepare rta for modification by filter
 */
static void
f_rta_cow(struct filter_state *fs)
{
  if (!rta_is_cached((*fs->rte)->attrs))
    return;

  /* Prepare to modify rte */
  f_rte_cow(fs);

  /* Store old rta to free it later, it stores reference from rte_cow() */
  fs->old_rta = (*fs->rte)->attrs;

  /*
   * Get shallow copy of rta. Fields eattrs and nexthops of rta are shared
   * with fs->old_rta (they will be copied when the cached rta will be obtained
   * at the end of f_run()), also the lock of hostentry is inherited (we
   * suppose hostentry is not changed by filters).
   */
  (*fs->rte)->attrs = rta_do_cow((*fs->rte)->attrs, fs->pool);

  /* Re-cache the ea_list */
  f_cache_eattrs(fs);
}

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
interpret(struct filter_state *fs, const struct f_line *line, uint argc, const struct f_val *argv, struct f_val *val)
{
  /* No arguments allowed */
  ASSERT_DIE(line->args == argc);

  /* Initialize the filter stack */
  struct filter_stack *fstk = fs->stack;

  /* Set the arguments and top-level variables */
  fstk->vcnt = line->vars + line->args;
  memcpy(fstk->vstk, argv, sizeof(struct f_val) * line->args);
  memset(fstk->vstk + line->args, 0, sizeof(struct f_val) * line->vars);

  /* The same as with the value stack. Not resetting the stack completely for performance reasons. */
  fstk->ecnt = 1;
  fstk->estk[0].line = line;
  fstk->estk[0].pos = 0;

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

#define runtime(fmt, ...) do { \
  if (!(fs->flags & FF_SILENT)) \
    log_rl(&rl_runtime_err, L_ERR "filters, line %d: " fmt, what->lineno, ##__VA_ARGS__); \
  return F_ERROR; \
} while(0)

#define falloc(size)  lp_alloc(fs->pool, size)
#define fpool fs->pool

#define ACCESS_EATTRS do { if (!fs->eattrs) f_cache_eattrs(fs); } while (0)

#include "filter/inst-interpret.c"
#undef res
#undef v1
#undef v2
#undef v3
#undef runtime
#undef falloc
#undef fpool
#undef ACCESS_EATTRS
      }
    }

    /* End of current line. Drop local variables before exiting. */
    fstk->vcnt = curline.ventry + curline.line->results;
    fstk->ecnt--;
  }

  if (fstk->vcnt == 0) {
    if (val) {
      log_rl(&rl_runtime_err, L_ERR "filters: No value left on stack");
      return F_ERROR;
    }
    return F_NOP;
  }

  if (val && (fstk->vcnt == 1)) {
    *val = fstk->vstk[0];
    return F_NOP;
  }

  log_rl(&rl_runtime_err, L_ERR "Too many items left on stack: %u", fstk->vcnt);
  return F_ERROR;
}

/**
 * f_run - run a filter for a route
 * @filter: filter to run
 * @rte: route being filtered, may be modified
 * @tmp_pool: all filter allocations go from this pool
 * @flags: flags
 *
 * If filter needs to modify the route, there are several
 * posibilities. @rte might be read-only (with REF_COW flag), in that
 * case rw copy is obtained by rte_cow() and @rte is replaced. If
 * @rte is originally rw, it may be directly modified (and it is never
 * copied).
 *
 * The returned rte may reuse the (possibly cached, cloned) rta, or
 * (if rta was modified) contains a modified uncached rta, which
 * uses parts allocated from @tmp_pool and parts shared from original
 * rta. There is one exception - if @rte is rw but contains a cached
 * rta and that is modified, rta in returned rte is also cached.
 *
 * Ownership of cached rtas is consistent with rte, i.e.
 * if a new rte is returned, it has its own clone of cached rta
 * (and cached rta of read-only source rte is intact), if rte is
 * modified in place, old cached rta is possibly freed.
 */
enum filter_return
f_run(const struct filter *filter, struct rte **rte, struct linpool *tmp_pool, int flags)
{
  if (filter == FILTER_ACCEPT)
    return F_ACCEPT;

  if (filter == FILTER_REJECT)
    return F_REJECT;

  return f_run_args(filter, rte, tmp_pool, 0, NULL, flags);
}

enum filter_return
f_run_args(const struct filter *filter, struct rte **rte, struct linpool *tmp_pool, uint argc, const struct f_val *argv, int flags)
{
  int rte_cow = ((*rte)->flags & REF_COW);
  DBG( "Running filter `%s'...", filter->name );

  /* Initialize the filter state */
  filter_state = (struct filter_state) {
    .stack = &filter_stack,
    .rte = rte,
    .pool = tmp_pool,
    .flags = flags,
  };

  LOG_BUFFER_INIT(filter_state.buf);

  /* Run the interpreter itself */
  enum filter_return fret = interpret(&filter_state, filter->root, argc, argv, NULL);

  if (filter_state.old_rta) {
    /*
     * Cached rta was modified and filter_state->rte contains now an uncached one,
     * sharing some part with the cached one. The cached rta should
     * be freed (if rte was originally COW, filter_state->old_rta is a clone
     * obtained during rte_cow()).
     *
     * This also implements the exception mentioned in f_run()
     * description. The reason for this is that rta reuses parts of
     * filter_state->old_rta, and these may be freed during rta_free(filter_state->old_rta).
     * This is not the problem if rte was COW, because original rte
     * also holds the same rta.
     */
    if (!rte_cow) {
      /* Cache the new attrs */
      (*filter_state.rte)->attrs = rta_lookup((*filter_state.rte)->attrs);

      /* Drop cached ea_list pointer */
      filter_state.eattrs = NULL;
    }

    /* Uncache the old attrs and drop the pointer as it is invalid now. */
    rta_free(filter_state.old_rta);
    filter_state.old_rta = NULL;
  }

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
f_eval_rte(const struct f_line *expr, struct rte **rte, struct linpool *tmp_pool, uint argc, const struct f_val *argv, struct f_val *pres)
{
  filter_state = (struct filter_state) {
    .stack = &filter_stack,
    .rte = rte,
    .pool = tmp_pool,
  };

  LOG_BUFFER_INIT(filter_state.buf);

  return interpret(&filter_state, expr, argc, argv, pres);
}

/*
 * f_eval - get a value of a term
 * @expr: filter line containing the term
 * @tmp_pool: long data may get allocated from this pool
 * @pres: here the output will be stored
 */
enum filter_return
f_eval(const struct f_line *expr, struct linpool *tmp_pool, struct f_val *pres)
{
  filter_state = (struct filter_state) {
    .stack = &filter_stack,
    .pool = tmp_pool,
  };

  LOG_BUFFER_INIT(filter_state.buf);

  enum filter_return fret = interpret(&filter_state, expr, 0, NULL, pres);
  return fret;
}

/*
 * cf_eval - evaluate a value of a term and check its type
 * Called internally from the config parser, uses its internal memory pool
 * for allocations. Do not call in other cases.
 */
struct f_val
cf_eval(const struct f_inst *inst, int type)
{
  struct f_val val;

  if (f_eval(f_linearize(inst, 1), cfg_mem, &val) > F_RETURN)
    cf_error("Runtime error while evaluating expression; see log for details");

  if (type != T_VOID && val.type != type)
    cf_error("Expression of type %s expected", f_type_name(type));

  return val;
}

/*
 * f_eval_buf - get a value of a term and print it to the supplied buffer
 */
enum filter_return
f_eval_buf(const struct f_line *expr, struct linpool *tmp_pool, buffer *buf)
{
  struct f_val val;
  enum filter_return fret = f_eval(expr, tmp_pool, &val);
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

/**
 * filter_commit - do filter comparisons on all the named functions and filters
 */
void
filter_commit(struct config *new, struct config *old)
{
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
	    if (c->in_filter == FILTER_ACCEPT)
	      debug(" ALL\n");
	    else if (c->in_filter == FILTER_REJECT)
	      debug(" NONE\n");
	    else if (c->in_filter == FILTER_UNDEF)
	      debug(" UNDEF\n");
	    else if (c->in_filter->sym) {
	      ASSERT(c->in_filter->sym->filter == c->in_filter);
	      debug(" named filter %s\n", c->in_filter->sym->name);
	    } else {
	      debug("\n");
	      f_dump_line(c->in_filter->root, 2);
	    }
	  }
	}
    }
  }
}
