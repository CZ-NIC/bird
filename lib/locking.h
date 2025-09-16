/*
 *	BIRD Library -- Locking
 *
 *	(c) 2020--2021 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LOCKING_H_
#define _BIRD_LOCKING_H_

#include "lib/birdlib.h"
#include "lib/macro.h"
#include "lib/rcu.h"

struct domain_generic;
struct pool;

#define LOCK_ORDER \
  the_bird, \
  meta, \
  control, \
  proto, \
  subproto, \
  service, \
  rtable, \
  attrs, \
  logging, \
  resource, \

/* Here define the global lock order; first to last. */
struct lock_order {
#define LOCK_ORDER_EXPAND(p)	struct domain_generic *p;
  MACRO_FOREACH(LOCK_ORDER_EXPAND, LOCK_ORDER)
#undef LOCK_ORDER_EXPAND
};

#define LOCK_ORDER_EXPAND(p)	struct domain__##p { struct domain_generic *p; };
  MACRO_FOREACH(LOCK_ORDER_EXPAND, LOCK_ORDER)
#undef LOCK_ORDER_EXPAND

extern _Thread_local struct lock_order locking_stack;
extern _Thread_local struct domain_generic **last_locked;

#define DOMAIN(type) struct domain__##type
#define DOMAIN_ORDER(type)  OFFSETOF(struct lock_order, type)

#define DOMAIN_NEW(type)  (DOMAIN(type)) { .type = domain_new(DOMAIN_ORDER(type)) }
struct domain_generic *domain_new(uint order);

#define DOMAIN_FREE(type, d)	domain_free((d).type)
void domain_free(struct domain_generic *);

#define DOMAIN_NAME(type, d)	domain_name((d).type)
const char *domain_name(struct domain_generic *);

#define DOMAIN_SETUP(type, d, n, p)	domain_setup((d).type, n, p)
void domain_setup(struct domain_generic *, const char *name, struct pool *);

#define DOMAIN_NULL(type)   (DOMAIN(type)) {}

#define LOCK_DOMAIN(type, d)	do_lock(((d).type), &(locking_stack.type))
#define UNLOCK_DOMAIN(type, d)  do_unlock(((d).type), &(locking_stack.type))

#define DOMAIN_IS_LOCKED(type, d) (((d).type) == (locking_stack.type))
#define DG_IS_LOCKED(d)	((d) == *(DG_LSP(d)))

/* Internal for locking */
void do_lock(struct domain_generic *dg, struct domain_generic **lsp);
void do_unlock(struct domain_generic *dg, struct domain_generic **lsp);

uint dg_order(struct domain_generic *dg);

#define DG_LSP(d)	((struct domain_generic **) (((void *) &locking_stack) + dg_order(d)))
#define DG_LOCK(d)	do_lock(d, DG_LSP(d))
#define DG_UNLOCK(d)	do_unlock(d, DG_LSP(d))

/* Use with care. To be removed in near future. */
extern DOMAIN(the_bird) the_bird_domain;

#define the_bird_lock()		LOCK_DOMAIN(the_bird, the_bird_domain)
#define the_bird_unlock()	UNLOCK_DOMAIN(the_bird, the_bird_domain)
#define the_bird_locked()	DOMAIN_IS_LOCKED(the_bird, the_bird_domain)

#define ASSERT_THE_BIRD_LOCKED	({ if (!the_bird_locked()) bug("The BIRD lock must be locked here: %s:%d", __FILE__, __LINE__); })

/*
 * RW spinlocks
 */

#define RWS_READ_PENDING_POS	0
#define RWS_READ_ACTIVE_POS	20
#define RWS_WRITE_PENDING_POS	40
#define RWS_WRITE_ACTIVE_POS	56

#define RWS_READ_PENDING	(1ULL << RWS_READ_PENDING_POS)
#define RWS_READ_ACTIVE		(1ULL << RWS_READ_ACTIVE_POS)
#define RWS_WRITE_PENDING	(1ULL << RWS_WRITE_PENDING_POS)
#define RWS_WRITE_ACTIVE	(1ULL << RWS_WRITE_ACTIVE_POS)

#define RWS_READ_PENDING_MASK	(RWS_READ_ACTIVE - 1)
#define RWS_READ_ACTIVE_MASK	((RWS_WRITE_PENDING - 1) & ~(RWS_READ_ACTIVE - 1))
#define RWS_WRITE_PENDING_MASK	((RWS_WRITE_ACTIVE - 1) & ~(RWS_WRITE_PENDING - 1))
#define RWS_WRITE_ACTIVE_MASK	(~(RWS_WRITE_ACTIVE - 1))

typedef struct {
  u64 _Atomic spin;
} rw_spinlock;

#ifdef DEBUGGING
#define MAX_RWS_AT_ONCE		32
extern _Thread_local rw_spinlock *rw_spinlocks_taken[MAX_RWS_AT_ONCE];
extern _Thread_local btime rw_spinlocks_time[MAX_RWS_AT_ONCE];
extern _Thread_local u32 rw_spinlocks_taken_cnt;
extern _Thread_local u32 rw_spinlocks_taken_write;

/* Borrowed from lib/timer.h */
btime current_time_now(void);

static inline void rws_mark(rw_spinlock *p, bool write, bool lock)
{
  if (lock) {
    ASSERT_DIE(rw_spinlocks_taken_cnt < MAX_RWS_AT_ONCE);
    if (write)
      rw_spinlocks_taken_write |= (1 << rw_spinlocks_taken_cnt);
    else
      rw_spinlocks_taken_write &= ~(1 << rw_spinlocks_taken_cnt);
    rw_spinlocks_time[rw_spinlocks_taken_cnt] = current_time_now();
    rw_spinlocks_taken[rw_spinlocks_taken_cnt++] = p;

  }
  else {
    ASSERT_DIE(rw_spinlocks_taken_cnt > 0);
    ASSERT_DIE(rw_spinlocks_taken[--rw_spinlocks_taken_cnt] == p);
    ASSERT_DIE(!(rw_spinlocks_taken_write & (1 << rw_spinlocks_taken_cnt)) == !write);
    btime tdif = current_time_now() - rw_spinlocks_time[rw_spinlocks_taken_cnt];
    if (tdif > 1 S_)
      log(L_WARN "Spent an alarming time %t s in spinlock %p (%s); "
	 "if this happens often to you, please contact the developers.",
	 tdif, p, write ? "write" : "read");
  }
}
#else
#define rws_mark(...)
#endif

static inline void rws_init(rw_spinlock *p)
{
  atomic_store_explicit(&p->spin, 0, memory_order_relaxed);
}

static inline void rws_read_lock(rw_spinlock *p)
{
  u64 old = atomic_fetch_add_explicit(&p->spin, RWS_READ_PENDING, memory_order_acquire);

  while (1)
  {
    /* Wait until all writers end */
    while (old & (RWS_WRITE_PENDING_MASK | RWS_WRITE_ACTIVE_MASK))
    {
      birdloop_yield();
      old = atomic_load_explicit(&p->spin, memory_order_acquire);
    }

    /* Convert to active */
    old = atomic_fetch_add_explicit(&p->spin, RWS_READ_ACTIVE - RWS_READ_PENDING, memory_order_acq_rel);

    if (old & RWS_WRITE_ACTIVE_MASK)
      /* Oh but some writer was faster */
      old = atomic_fetch_sub_explicit(&p->spin, RWS_READ_ACTIVE - RWS_READ_PENDING, memory_order_acq_rel);
    else
      /* No writers, approved */
      break;
  }

  rws_mark(p, 0, 1);
}

static inline void rws_read_unlock(rw_spinlock *p)
{
  rws_mark(p, 0, 0);
  u64 old = atomic_fetch_sub_explicit(&p->spin, RWS_READ_ACTIVE, memory_order_release);
  ASSERT_DIE(old & RWS_READ_ACTIVE_MASK);
}

static inline void rws_write_lock(rw_spinlock *p)
{
  u64 old = atomic_fetch_add_explicit(&p->spin, RWS_WRITE_PENDING, memory_order_acquire);

  /* Wait until all active readers end */
  while (1)
  {
    while (old & (RWS_READ_ACTIVE_MASK | RWS_WRITE_ACTIVE_MASK))
    {
      birdloop_yield();
      old = atomic_load_explicit(&p->spin, memory_order_acquire);
    }

    /* Mark self as active */
    u64 updated = atomic_fetch_or_explicit(&p->spin, RWS_WRITE_ACTIVE, memory_order_acquire);

    /* And it's us */
    if (!(updated & RWS_WRITE_ACTIVE))
    {
      if (updated & RWS_READ_ACTIVE_MASK)
	/* But some reader was faster */
	atomic_fetch_and_explicit(&p->spin, ~RWS_WRITE_ACTIVE, memory_order_release);
      else
	/* No readers, approved */
	break;
    }
  }

  /* It's us, then we aren't actually pending */
  u64 updated = atomic_fetch_sub_explicit(&p->spin, RWS_WRITE_PENDING, memory_order_acquire);
  ASSERT_DIE(updated & RWS_WRITE_PENDING_MASK);
  rws_mark(p, 1, 1);
}

static inline void rws_write_unlock(rw_spinlock *p)
{
  rws_mark(p, 1, 0);
  u64 old = atomic_fetch_and_explicit(&p->spin, ~RWS_WRITE_ACTIVE, memory_order_release);
  ASSERT_DIE(old & RWS_WRITE_ACTIVE);
}


/*
 * Unwind stored lock state helpers
 */
struct locking_unwind_status {
  struct lock_order *desired;
  enum {
    LOCKING_UNWIND_SAME,
    LOCKING_UNWIND_UNLOCK,
  } state;
};

static inline struct locking_unwind_status locking_unwind_helper(struct locking_unwind_status status, uint order)
{
  struct domain_generic **lsp = ((void *) &locking_stack) + order;
  struct domain_generic **dp = ((void *) status.desired) + order;

  if (!status.state)
  {
    /* Just checking that the rest of the stack is consistent */
    if (*lsp != *dp)
      bug("Mangled lock unwind state at order %d", order);
  }
  else if (*dp)
    /* Stored state expects locked */
    if (*lsp == *dp)
      /* Indeed is locked, switch to check mode */
      status.state = 0;
    else
      /* Not locked or locked elsewhere */
      bug("Mangled lock unwind state at order %d", order);
  else if (*lsp)
    /* Stored state expects unlocked but we're locked */
    DG_UNLOCK(*lsp);

  return status;
}

static inline void locking_unwind(struct lock_order *desired)
{
  struct locking_unwind_status status = {
    .desired = desired,
    .state = LOCKING_UNWIND_UNLOCK,
  };

#define LOCK_ORDER_POS_HELPER(x)	DOMAIN_ORDER(x),
#define LOCK_ORDER_POS			MACRO_FOREACH(LOCK_ORDER_POS_HELPER, LOCK_ORDER)
  MACRO_RPACK(locking_unwind_helper, status, LOCK_ORDER_POS);
#undef LOCK_ORDER_POS_HELPER
}

/**
 *  Objects bound with domains
 *
 *  First, we need some object to have its locked and unlocked part.
 *  This is accomplished typically by the following pattern:
 *
 *    struct foo_public {
 *      ...			// Public fields
 *      DOMAIN(bar) lock;	// The assigned domain
 *    };
 *
 *    struct foo_private {
 *      struct foo_public;	// Importing public fields
 *      struct foo_private **locked_at;	// Auxiliary field for locking routines
 *      ...			// Private fields
 *    };
 *
 *    typedef union foo {
 *      struct foo_public;
 *      struct foo_private priv;
 *    } foo;
 *
 *  All persistently stored object pointers MUST point to the public parts.
 *  If accessing the locked object from embedded objects, great care must
 *  be applied to always SKIP_BACK to the public object version, not the
 *  private one.
 *
 *  To access the private object parts, either the private object pointer
 *  is explicitly given to us, therefore assuming somewhere else the domain
 *  has been locked, or we have to lock the domain ourselves. To do that,
 *  there are some handy macros.
 */

#define LOBJ_LOCK_SIMPLE(_obj, _level) \
  ({ LOCK_DOMAIN(_level, (_obj)->lock); &(_obj)->priv; })

#define LOBJ_UNLOCK_SIMPLE(_obj, _level) \
  UNLOCK_DOMAIN(_level, (_obj)->lock)

/*
 *  These macros can be used to define specific macros for given class.
 *
 *  #define FOO_LOCK_SIMPLE(foo)	LOBJ_LOCK_SIMPLE(foo, bar)
 *  #define FOO_UNLOCK_SIMPLE(foo)	LOBJ_UNLOCK_SIMPLE(foo, bar)
 *
 *  Then these can be used like this:
 *
 *  void foo_frobnicate(foo *f)
 *  {
 *    // Unlocked context
 *    ...
 *    struct foo_private *fp = FOO_LOCK_SIMPLE(f);
 *    // Locked context
 *    ...
 *    FOO_UNLOCK_SIMPLE(f);
 *    // Unlocked context
 *    ...
 *  }
 *
 *  These simple calls have two major drawbacks. First, if you return
 *  from locked context, you don't unlock, which may lock you dead.
 *  And second, the foo_private pointer is still syntactically valid
 *  even after unlocking.
 *
 *  To fight this, we need more magic and the switch should stay in that
 *  position.
 *
 *  First, we need an auxiliary _function_ for unlocking. This function
 *  is intended to be called in a local variable cleanup context.
 */

#define LOBJ_UNLOCK_CLEANUP_NAME(_stem) _lobj__##_stem##_unlock_cleanup

#define LOBJ_UNLOCK_CLEANUP(_stem, _level) \
  static inline void LOBJ_UNLOCK_CLEANUP_NAME(_stem)(struct _stem##_private **obj) { \
    if (!*obj) return; \
    ASSERT_DIE(LOBJ_IS_LOCKED((*obj), _level)); \
    ASSERT_DIE((*obj)->locked_at == obj); \
    (*obj)->locked_at = NULL; \
    UNLOCK_DOMAIN(_level, (*obj)->lock); \
  }

#define LOBJ_LOCK(_obj, _pobj, _stem, _level) \
  CLEANUP(LOBJ_UNLOCK_CLEANUP_NAME(_stem)) struct _stem##_private *_pobj = LOBJ_LOCK_SIMPLE(_obj, _level); _pobj->locked_at = &_pobj;

/*
 *  And now the usage of these macros. You first need to declare the auxiliary
 *  cleanup function.
 *
 *  LOBJ_UNLOCK_CLEANUP(foo, bar);
 *
 *  And then declare the lock-local macro:
 *
 *  #define FOO_LOCK(foo, fpp)	LOBJ_LOCK(foo, fpp, foo, bar)
 *
 *  This construction then allows you to lock much more safely:
 *
 *  void foo_frobnicate_safer(foo *f)
 *  {
 *    // Unlocked context
 *    ...
 *    do {
 *      FOO_LOCK(foo, fpp);
 *	// Locked context, fpp is valid here
 *
 *	if (something) return;	// This implicitly unlocks
 *	if (whatever) break;	// This unlocks too
 *
 *      // Finishing context with no unlock at all
 *    } while (0);
 *
 *    // Here is fpp invalid and the object is back unlocked.
 *    ...
 *  }
 *
 *  There is no explicit unlock statement. To unlock, simply leave the block
 *  with locked context.
 *
 *  This may be made even nicer to use by employing a for-cycle.
 */

#define LOBJ_LOCKED(_obj, _pobj, _stem, _level) \
  for (CLEANUP(LOBJ_UNLOCK_CLEANUP_NAME(_stem)) struct _stem##_private *_pobj = LOBJ_LOCK_SIMPLE(_obj, _level); \
      _pobj ? (_pobj->locked_at = &_pobj) : NULL; \
      LOBJ_UNLOCK_CLEANUP_NAME(_stem)(&_pobj), _pobj = NULL)

/*
 *  This for-cycle employs heavy magic to hide as much of the boilerplate
 *  from the user as possibly needed. Here is how it works.
 *
 *  First, the for-1 clause is executed, setting up _pobj, to the private
 *  object pointer. It has a cleanup hook set.
 *
 *  Then, the for-2 clause is checked. As _pobj is non-NULL, _pobj->locked_at
 *  is initialized to the _pobj address to ensure that the cleanup hook unlocks
 *  the right object.
 *
 *  Now the user block is executed. If it ends by break or return, the cleanup
 *  hook fires for _pobj, triggering object unlock.
 *
 *  If the user block executed completely, the for-3 clause is run, executing
 *  the cleanup hook directly and then deactivating it by setting _pobj to NULL.
 *
 *  Finally, the for-2 clause is checked again but now with _pobj being NULL,
 *  causing the loop to end. As the object has already been unlocked, nothing
 *  happens after leaving the context.
 *
 *  #define FOO_LOCKED(foo, fpp)	LOBJ_LOCKED(foo, fpp, foo, bar)
 *
 *  Then the previous code can be modified like this:
 *
 *  void foo_frobnicate_safer(foo *f)
 *  {
 *    // Unlocked context
 *    ...
 *    FOO_LOCKED(foo, fpp)
 *    {
 *	// Locked context, fpp is valid here
 *
 *	if (something) return;	// This implicitly unlocks
 *	if (whatever) break;	// This unlocks too
 *
 *      // Finishing context with no unlock at all
 *    }
 *
 *    // Unlocked context
 *    ...
 *
 *    // Locking once again without an explicit block
 *    FOO_LOCKED(foo, fpp)
 *	do_something(fpp);
 *
 *    // Here is fpp invalid and the object is back unlocked.
 *    ...
 *  }
 *
 *
 *  For many reasons, a lock-check macro is handy.
 *
 *  #define FOO_IS_LOCKED(foo)	LOBJ_IS_LOCKED(foo, bar)
 */

#define LOBJ_IS_LOCKED(_obj, _level)	DOMAIN_IS_LOCKED(_level, (_obj)->lock)

/*
 *  An example implementation is available in lib/locking_test.c
 */


/*
 *  Please don't use this macro unless you at least try to prove that
 *  it's completely safe. It's a can of worms.
 *
 *  NEVER RETURN OR BREAK FROM THIS MACRO, it will crash.
 */

#define LOBJ_UNLOCKED_TEMPORARILY(_obj, _pobj, _stem, _level) \
  for (union _stem *_obj = SKIP_BACK(union _stem, priv, _pobj), **_lataux = (union _stem **) _pobj->locked_at; \
      _obj ? (_pobj->locked_at = NULL, LOBJ_UNLOCK_SIMPLE(_obj, _level), _obj) : NULL; \
      LOBJ_LOCK_SIMPLE(_obj, _level), _pobj->locked_at = (struct _stem##_private **) _lataux, _obj = NULL)

/*
 *  Get the locked object when the lock is already taken
 */

#define LOBJ_PRIV(_obj, _level) \
  ({ ASSERT_DIE(DOMAIN_IS_LOCKED(_level, (_obj)->lock)); &(_obj)->priv; })

/*
 * RCU retry unwinder
 *
 * Start a retriable operation with RCU_ANCHOR() and pass the _i object along
 * with the code which may then call RCU_RETRY() to return back to RCU_ANCHOR
 * and try again.
 */

struct rcu_unwinder {
  struct lock_order locking_stack;
  const char *file;
  u32 line;
  u32 retry;
  u8 fast;
  jmp_buf buf;
};

static inline void _rcu_unwinder_unlock_(struct rcu_unwinder *o UNUSED)
{
  rcu_read_unlock();
}

#define RCU_UNWIND_WARN	4096

#define RCU_ANCHOR(_i)	\
  CLEANUP(_rcu_unwinder_unlock_) struct rcu_unwinder _s##_i = {};	\
  struct rcu_unwinder *_i = &_s##_i;					\
  if (setjmp(_i->buf)) {						\
    rcu_read_unlock();							\
    locking_unwind(&_i->locking_stack);					\
    if (_i->fast) _i->fast = 0;						\
    else {								\
      birdloop_yield();							\
      if (!(++_i->retry % RCU_UNWIND_WARN))				\
	log(L_WARN "Suspiciously many RCU_ANCHORs retried (%lu)"	\
	   " at %s:%d", _i->retry, __FILE__, __LINE__);			\
    }									\
  }									\
  _i->locking_stack = locking_stack;					\
  rcu_read_lock();							\

#define RCU_RETRY(_i) do { if (_i) { _i->file = __FILE__; _i->line = __LINE__; longjmp(_i->buf, 1); } else bug("No rcu retry allowed here"); } while (0)

#define RCU_RETRY_FAST(_i) do { (_i)->fast++; RCU_RETRY(_i); } while (0)

#define RCU_WONT_RETRY	((struct rcu_unwinder *) NULL)
#endif
