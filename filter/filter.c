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
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/f-inst.h"
#include "filter/data.h"


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

  /* Filter execution flags */
  int flags;
};

#if HAVE_THREAD_LOCAL
_Thread_local static struct filter_state filter_state;
_Thread_local static struct filter_stack filter_stack;
#define FS_INIT(...)	filter_state = (struct filter_state) { .stack = &filter_stack, __VA_ARGS__ }
#else
#define FS_INIT(...)	struct filter_state filter_state = { .stack = alloca(sizeof(struct filter_stack)), __VA_ARGS__ };
#endif

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

static char *
val_format_str(struct filter_state *fs, const struct f_val *v) {
  buffer b;
  LOG_BUFFER_INIT(b);
  val_format(v, &b);
  return lp_strdup(fs->pool, b.start);
}

static struct tbf rl_runtime_err = TBF_DEFAULT_LOG_LIMITS;

#define runtime(fmt, ...) do { \
  if (!(fs->flags & FF_SILENT)) \
    log_rl(&rl_runtime_err, L_ERR "filters, line %d: " fmt, \
	(fs->stack->estk[fs->stack->ecnt-1].line->items[fs->stack->estk[fs->stack->ecnt-1].pos-1]).lineno, \
	##__VA_ARGS__); \
  return F_ERROR; \
} while(0)

#define ACCESS_RTE do { if (!fs->rte) runtime("No route to access"); } while (0)
#define ACCESS_EATTRS do { if (!fs->eattrs) f_cache_eattrs(fs); } while (0)

static inline enum filter_return
f_rta_set(struct filter_state *fs, struct f_static_attr sa, const struct f_val *val)
{
    ACCESS_RTE;
    if (sa.f_type != val->type)
      runtime( "Attempt to set static attribute to incompatible type" );

    f_rta_cow(fs);
    {
      struct rta *rta = (*fs->rte)->attrs;

      switch (sa.sa_code)
      {
      case SA_FROM:
	rta->from = val->val.ip;
	return F_NOP;

      case SA_GW:
	{
	  ip_addr ip = val->val.ip;
	  neighbor *n = neigh_find(rta->src->proto, ip, NULL, 0);
	  if (!n || (n->scope == SCOPE_HOST))
	    runtime( "Invalid gw address" );

	  rta->dest = RTD_UNICAST;
	  rta->nh.gw = ip;
	  rta->nh.iface = n->iface;
	  rta->nh.next = NULL;
	  rta->hostentry = NULL;
	}
	return F_NOP;

      case SA_SCOPE:
	rta->scope = val->val.i;
	return F_NOP;

      case SA_DEST:
	{
	  int i = val->val.i;
	  if ((i != RTD_BLACKHOLE) && (i != RTD_UNREACHABLE) && (i != RTD_PROHIBIT))
	    runtime( "Destination can be changed only to blackhole, unreachable or prohibit" );

	  rta->dest = i;
	  rta->nh.gw = IPA_NONE;
	  rta->nh.iface = NULL;
	  rta->nh.next = NULL;
	  rta->hostentry = NULL;
	}
	return F_NOP;

      case SA_IFNAME:
	{
	  struct iface *ifa = if_find_by_name(val->val.s);
	  if (!ifa)
	    runtime( "Invalid iface name" );

	  rta->dest = RTD_UNICAST;
	  rta->nh.gw = IPA_NONE;
	  rta->nh.iface = ifa;
	  rta->nh.next = NULL;
	  rta->hostentry = NULL;
	}
	return F_NOP;

      default:
	bug("Invalid static attribute access (%u/%u)", sa.f_type, sa.sa_code);
      }
    }
}

static inline enum filter_return
f_ea_set(struct filter_state *fs, struct f_dynamic_attr da, const struct f_val *val)
{
    ACCESS_RTE;
    ACCESS_EATTRS;
    {
      struct ea_list *l = lp_alloc(fs->pool, sizeof(struct ea_list) + sizeof(eattr));

      l->next = NULL;
      l->flags = EALF_SORTED;
      l->count = 1;
      l->attrs[0].id = da.ea_code;
      l->attrs[0].flags = 0;
      l->attrs[0].type = da.type | EAF_ORIGINATED | EAF_FRESH;

      switch (da.type) {
      case EAF_TYPE_INT:
	if (val->type != da.f_type)
	  runtime( "Setting int attribute to non-int value" );
	l->attrs[0].u.data = val->val.i;
	break;

      case EAF_TYPE_ROUTER_ID:
	/* IP->Quad implicit conversion */
	if (val_is_ip4(val)) {
	  l->attrs[0].u.data = ipa_to_u32(val->val.ip);
	  break;
	}
	/* T_INT for backward compatibility */
	if ((val->type != T_QUAD) && (val->type != T_INT))
	  runtime( "Setting quad attribute to non-quad value" );
	l->attrs[0].u.data = val->val.i;
	break;

      case EAF_TYPE_OPAQUE:
	runtime( "Setting opaque attribute is not allowed" );
	break;
      case EAF_TYPE_IP_ADDRESS:
	if (val->type != T_IP)
	  runtime( "Setting ip attribute to non-ip value" );
	int len = sizeof(ip_addr);
	struct adata *ad = lp_alloc(fs->pool, sizeof(struct adata) + len);
	ad->length = len;
	(* (ip_addr *) ad->data) = val->val.ip;
	l->attrs[0].u.ptr = ad;
	break;
      case EAF_TYPE_AS_PATH:
	if (val->type != T_PATH)
	  runtime( "Setting path attribute to non-path value" );
	l->attrs[0].u.ptr = val->val.ad;
	break;
      case EAF_TYPE_BITFIELD:
	if (val->type != T_BOOL)
	  runtime( "Setting bit in bitfield attribute to non-bool value" );
	{
	  /* First, we have to find the old value */
	  eattr *e = ea_find(*fs->eattrs, da.ea_code);
	  u32 data = e ? e->u.data : 0;

	  if (val->val.i)
	    l->attrs[0].u.data = data | (1u << da.bit);
	  else
	    l->attrs[0].u.data = data & ~(1u << da.bit);
	}
	break;
      case EAF_TYPE_INT_SET:
	if (val->type != T_CLIST)
	  runtime( "Setting clist attribute to non-clist value" );
	l->attrs[0].u.ptr = val->val.ad;
	break;
      case EAF_TYPE_EC_SET:
	if (val->type != T_ECLIST)
	  runtime( "Setting eclist attribute to non-eclist value" );
	l->attrs[0].u.ptr = val->val.ad;
	break;
      case EAF_TYPE_LC_SET:
	if (val->type != T_LCLIST)
	  runtime( "Setting lclist attribute to non-lclist value" );
	l->attrs[0].u.ptr = val->val.ad;
	break;
      default: bug("Unknown type in e,S");
      }

      f_rta_cow(fs);
      l->next = *fs->eattrs;
      *fs->eattrs = l;

      return F_NOP;
    }
}

static inline enum filter_return
f_lval_set(struct filter_state *fs, const struct f_lval *lv, const struct f_val *val)
{
  switch (lv->type) {
    case F_LVAL_STACK:
      fs->stack->vstk[fs->stack->vcnt] = *val;
      fs->stack->vcnt++;
      return F_NOP;
    case F_LVAL_EXCEPTION:
      {
	/* Drop every sub-block including ourselves */
	while ((fs->stack->ecnt-- > 0) && !(fs->stack->estk[fs->stack->ecnt].emask & lv->exception))
	  ;

	/* Now we are at the catch frame; if no such, try to convert to accept/reject. */
	if (!fs->stack->ecnt)
	  if (lv->exception == FE_RETURN)
	    if (val->type == T_BOOL)
	      if (val->val.i)
		return F_ACCEPT;
	      else
		return F_REJECT;
	    else
	      runtime("Can't return non-bool from non-function");
	  else
	    runtime("Unhandled exception 0x%x: %s", lv->exception, val_format_str(fs, val));

	/* Set the value stack position, overwriting the former implicit void */
	fs->stack->vcnt = fs->stack->estk[fs->stack->ecnt].ventry;

	/* Copy the return value */
	fs->stack->vstk[fs->stack->vcnt - 1] = *val;
	return F_NOP;
      }
    case F_LVAL_VARIABLE:
      fs->stack->vstk[fs->stack->estk[fs->stack->ecnt-1].vbase + lv->sym->offset] = *val;
      return F_NOP;
    case F_LVAL_PREFERENCE:
      ACCESS_RTE;
      if (val->type != T_INT)
	runtime("Preference must be integer, got 0x%02x", val->type);
      if (val->val.i > 0xFFFF)
	runtime("Preference is at most 65536");
      f_rte_cow(fs);
      (*fs->rte)->pref = val->val.i;
      return F_NOP;
    case F_LVAL_SA:
      return f_rta_set(fs, lv->sa, val);
    case F_LVAL_EA:
      return f_ea_set(fs, lv->da, val);
    default:
      bug("This shall never happen");
  }    
}

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
  /* No arguments allowed */
  ASSERT(line->args == 0);

  /* Initialize the filter stack */
  struct filter_stack *fstk = fs->stack;

  fstk->vcnt = line->vars;
  memset(fstk->vstk, 0, sizeof(struct f_val) * line->vars);

  /* The same as with the value stack. Not resetting the stack for performance reasons. */
  fstk->ecnt = 1;
  fstk->estk[0].line = line;		
  fstk->estk[0].pos = 0;

#define curline fstk->estk[fstk->ecnt-1]

#if DEBUGGING
  debug("Interpreting line.");
  f_dump_line(line, 1);
#endif

  while (fstk->ecnt > 0) {
    while (curline.pos < curline.line->len) {
      const struct f_line_item *what = &(curline.line->items[curline.pos++]);

      switch (what->fi_code) {
#define res fstk->vstk[fstk->vcnt]
#define v1 fstk->vstk[fstk->vcnt]
#define v2 fstk->vstk[fstk->vcnt + 1]
#define v3 fstk->vstk[fstk->vcnt + 2]

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
    
    /* End of current line. Drop local variables before exiting. */
    fstk->vcnt -= curline.line->vars;
    fstk->vcnt -= curline.line->args;
    fstk->ecnt--;

    /* If the caller wants to store the result somewhere, do it. */
    if (fstk->ecnt) {
      const struct f_line_item *caller = &(curline.line->items[curline.pos-1]);
      if (caller->result.type != F_LVAL_STACK) {
	enum filter_return fret = f_lval_set(fs, &(caller->result), &fstk->vstk[--fstk->vcnt]);
	if (fret != F_NOP)
	  return fret;
      }
    }
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

  int rte_cow = ((*rte)->flags & REF_COW);
  DBG( "Running filter `%s'...", filter->name );

  /* Initialize the filter state */
  FS_INIT(
      .rte = rte,
      .pool = tmp_pool,
      .flags = flags,
      );

  LOG_BUFFER_INIT(filter_state.buf);

  /* Run the interpreter itself */
  enum filter_return fret = interpret(&filter_state, filter->root, NULL);

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
 * f_eval_rte – run a filter line for an uncached route
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
f_eval_rte(const struct f_line *expr, struct rte **rte, struct linpool *tmp_pool)
{
  FS_INIT(
      .rte = rte,
      .pool = tmp_pool,
      );

  LOG_BUFFER_INIT(filter_state.buf);

  ASSERT(!((*rte)->flags & REF_COW));
  ASSERT(!rta_is_cached((*rte)->attrs));

  return interpret(&filter_state, expr, NULL);
}

/*
 * f_eval – get a value of a term
 * @expr: filter line containing the term
 * @tmp_pool: long data may get allocated from this pool
 * @pres: here the output will be stored
 */
enum filter_return
f_eval(const struct f_line *expr, struct linpool *tmp_pool, struct f_val *pres)
{
  FS_INIT(
      .pool = tmp_pool,
      );

  LOG_BUFFER_INIT(filter_state.buf);

  enum filter_return fret = interpret(&filter_state, expr, pres);
  return fret;
}

/*
 * f_eval_int – get an integer value of a term 
 * Called internally from the config parser, uses its internal memory pool
 * for allocations. Do not call in other cases.
 */
uint
f_eval_int(const struct f_line *expr)
{
  /* Called independently in parse-time to eval expressions */
  FS_INIT(
      .pool = cfg_mem,
      );

  struct f_val val;

  LOG_BUFFER_INIT(filter_state.buf);

  if (interpret(&filter_state, expr, &val) > F_RETURN)
    cf_error("Runtime error while evaluating expression");

  if (val.type != T_INT)
    cf_error("Integer expression expected");

  return val.val.i;
}

/*
 * f_eval_buf – get a value of a term and print it to the supplied buffer
 */
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
