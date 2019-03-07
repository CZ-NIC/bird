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
 * A filter is represented by a tree of &f_inst structures, one structure per
 * "instruction". Each &f_inst contains @code, @aux value which is
 * usually the data type this instruction operates on and two generic
 * arguments (@a[0], @a[1]). Some instructions contain pointer(s) to other
 * instructions in their (@a[0], @a[1]) fields.
 *
 * Filters use a &f_val structure for their data. Each &f_val
 * contains type and value (types are constants prefixed with %T_). Few
 * of the types are special; %T_RETURN can be or-ed with a type to indicate
 * that return from a function or from the whole filter should be
 * forced. Important thing about &f_val's is that they may be copied
 * with a simple |=|. That's fine for all currently defined types: strings
 * are read-only (and therefore okay), paths are copied for each
 * operation (okay too).
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/string.h"
#include "lib/unaligned.h"
#include "lib/net.h"
#include "lib/ip.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/attrs.h"
#include "nest/notify.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/f-inst.h"
#include "filter/data.h"

/* Internal filter state, to be allocated on stack when executing filters */
struct filter_state {
  struct rte **rte;
  struct rta *old_rta;
  struct ea_list **eattrs;
  struct linpool *pool;
  struct filter_slot *slot;
  struct buffer buf;
  int flags;
};

void (*bt_assert_hook)(int result, const struct f_line_item *assert);

struct filter_roa_notifier {
  resource r;
  struct listener L;
  struct rtable *roa_table;
  struct filter_slot *slot;
};

static void filter_roa_notifier_hook(struct listener *L, void *data UNUSED) {
  struct filter_roa_notifier *frn = SKIP_BACK(struct filter_roa_notifier, L, L);
  frn->slot->reloader(frn->slot);
}

static void filter_roa_notifier_unsubscribe(struct listener *L) {
  struct filter_roa_notifier *frn = SKIP_BACK(struct filter_roa_notifier, L, L);
  rfree(frn);
}

static void filter_roa_notifier_free(resource *r) {
  struct filter_roa_notifier *frn = (void *) r;
  unsubscribe(&(frn->L));
}

static struct resclass filter_roa_notifier_class = {
  .name = "Filter ROA Notifier",
  .size = sizeof(struct filter_roa_notifier),
  .free = filter_roa_notifier_free,
  .dump = NULL,
  .lookup = NULL,
  .memsize = NULL,
};

static void filter_roa_notifier_subscribe(struct rtable *roa_table, struct filter_slot *slot, const net_addr *n UNUSED, u32 as UNUSED) {
  struct listener *oldL;
  node *x;
  WALK_LIST2(oldL, x, slot->notifiers, receiver_node)
    if (oldL->hook == filter_roa_notifier_hook)
    {
      struct filter_roa_notifier *old = SKIP_BACK(struct filter_roa_notifier, L, oldL);
      if ((old->roa_table == roa_table) && (old->slot == slot))
       return; /* Old notifier found for the same event. */
    }

  struct filter_roa_notifier *frn = ralloc(slot->p, &filter_roa_notifier_class);
  frn->L = (struct listener) {
    .hook = filter_roa_notifier_hook,
    .unsub = filter_roa_notifier_unsubscribe,
  };
  frn->roa_table = roa_table;
  frn->slot = slot;

  subscribe(&(frn->L), &(roa_table->listeners), &(slot->notifiers));
}

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

static char *
val_format_str(struct filter_state *fs, struct f_val *v) {
  buffer b;
  LOG_BUFFER_INIT(b);
  val_format(v, &b);
  return lp_strdup(fs->pool, b.start);
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
interpret(struct filter_state *fs, const struct f_line *line, struct f_val *val)
{

#define F_VAL_STACK_MAX	4096
  /* Value stack for execution */
  struct f_val_stack {
    uint cnt;				/* Current stack size; 0 for empty */
    struct f_val val[F_VAL_STACK_MAX];	/* The stack itself */
  } vstk;

  /* The stack itself is intentionally kept as-is for performance reasons.
   * Do NOT rewrite this to initialization by struct literal. It's slow.
   */
  vstk.cnt = 0;
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
  } estk;

  /* The same as with the value stack. Not resetting the stack for performance reasons. */
  estk.cnt = 1;
  estk.item[0].line = line;		
  estk.item[0].pos = 0;

#define curline estk.item[estk.cnt-1]

#if DEBUGGING
  debug("Interpreting line.");
  f_dump_line(line, 1);
#endif

  while (estk.cnt > 0) {
    while (curline.pos < curline.line->len) {
      const struct f_line_item *what = &(curline.line->items[curline.pos++]);


      switch (what->fi_code) {
#define res vstk.val[vstk.cnt]
#define v1 vstk.val[vstk.cnt]
#define v2 vstk.val[vstk.cnt + 1]
#define v3 vstk.val[vstk.cnt + 2]

#define runtime(fmt, ...) do { \
  if (!(fs->flags & FF_SILENT)) \
    log_rl(&rl_runtime_err, L_ERR "filters, line %d: " fmt, what->lineno, ##__VA_ARGS__); \
  return F_ERROR; \
} while(0)

#define ACCESS_RTE do { if (!fs->rte) runtime("No route to access"); } while (0)
#define ACCESS_EATTRS do { if (!fs->eattrs) f_cache_eattrs(fs); } while (0)

#include "filter/inst-interpret.c"
#undef res
#undef v1
#undef v2
#undef v3
#undef runtime
#undef ACCESS_RTE
#undef ACCESS_EATTRS
      }
    }
    estk.cnt--;
  }

  switch (vstk.cnt) {
    case 0:
      if (val) {
	log_rl(&rl_runtime_err, L_ERR "filters: No value left on stack");
	return F_ERROR;
      }
      return F_NOP;
    case 1:
      if (val) {
	*val = vstk.val[0];
	return F_NOP;
      }
      /* fallthrough */
    default:
      log_rl(&rl_runtime_err, L_ERR "Too many items left on stack: %u", vstk.cnt);
      return F_ERROR;
  }
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
 * (if rta was modificied) contains a modified uncached rta, which
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
f_run(struct filter_slot *filter_slot, struct rte **rte, struct linpool *tmp_pool, int flags)
{
  const struct filter *filter = filter_slot->filter;
  if (filter == FILTER_ACCEPT)
    return F_ACCEPT;

  if (filter == FILTER_REJECT)
    return F_REJECT;

  int rte_cow = ((*rte)->flags & REF_COW);
  DBG( "Running filter `%s'...", filter->name );

  struct filter_state fs = {
    .rte = rte,
    .pool = tmp_pool,
    .flags = flags,
    .slot = filter_slot,
  };

  LOG_BUFFER_INIT(fs.buf);

  enum filter_return fret = interpret(&fs, filter->root, NULL);

  if (fs.old_rta) {
    /*
     * Cached rta was modified and fs->rte contains now an uncached one,
     * sharing some part with the cached one. The cached rta should
     * be freed (if rte was originally COW, fs->old_rta is a clone
     * obtained during rte_cow()).
     *
     * This also implements the exception mentioned in f_run()
     * description. The reason for this is that rta reuses parts of
     * fs->old_rta, and these may be freed during rta_free(fs->old_rta).
     * This is not the problem if rte was COW, because original rte
     * also holds the same rta.
     */
    if (!rte_cow)
      (*fs.rte)->attrs = rta_lookup((*fs.rte)->attrs);

    rta_free(fs.old_rta);
  }


  if (fret < F_ACCEPT) {
    if (!(fs.flags & FF_SILENT))
      log_rl(&rl_runtime_err, L_ERR "Filter %s did not return accept nor reject. Make up your mind", filter_name(filter));
    return F_ERROR;
  }
  DBG( "done (%u)\n", res.val.i );
  return fret;
}

/* TODO: perhaps we could integrate f_eval(), f_eval_rte() and f_run() */

enum filter_return
f_eval_rte(const struct f_line *expr, struct rte **rte, struct linpool *tmp_pool)
{

  struct filter_state fs = {
    .rte = rte,
    .pool = tmp_pool,
  };

  LOG_BUFFER_INIT(fs.buf);

  /* Note that in this function we assume that rte->attrs is private / uncached */
  return interpret(&fs, expr, NULL);
}

enum filter_return
f_eval(const struct f_line *expr, struct linpool *tmp_pool, struct f_val *pres)
{
  struct filter_state fs = {
    .pool = tmp_pool,
  };

  LOG_BUFFER_INIT(fs.buf);

  enum filter_return fret = interpret(&fs, expr, pres);
  return fret;
}

uint
f_eval_int(const struct f_line *expr)
{
  /* Called independently in parse-time to eval expressions */
  struct filter_state fs = {
    .pool = cfg_mem,
  };

  struct f_val val;

  LOG_BUFFER_INIT(fs.buf);

  if (interpret(&fs, expr, &val) > F_RETURN)
    cf_error("Runtime error while evaluating expression");

  if (val.type != T_INT)
    cf_error("Integer expression expected");

  return val.val.i;
}

enum filter_return
f_eval_buf(const struct f_line *expr, struct linpool *tmp_pool, buffer *buf)
{
  struct f_val val;
  enum filter_return fret = f_eval(expr, tmp_pool, &val);
  if (fret > F_RETURN)
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
filter_commit(const struct config *new, const struct config *old)
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
