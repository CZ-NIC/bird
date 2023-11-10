/*
 *	BIRD Library -- Locking
 *
 *	(c) 2020--2021 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LOCKING_H_
#define _BIRD_LOCKING_H_

struct domain_generic;
struct pool;

/* Here define the global lock order; first to last. */
struct lock_order {
  struct domain_generic *the_bird;
  struct domain_generic *meta;
  struct domain_generic *control;
  struct domain_generic *proto;
  struct domain_generic *service;
  struct domain_generic *rtable;
  struct domain_generic *attrs;
  struct domain_generic *logging;
  struct domain_generic *resource;
};

extern _Thread_local struct lock_order locking_stack;
extern _Thread_local struct domain_generic **last_locked;

#define DOMAIN(type) struct domain__##type
#define DEFINE_DOMAIN(type) DOMAIN(type) { struct domain_generic *type; }
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
DEFINE_DOMAIN(the_bird);
extern DOMAIN(the_bird) the_bird_domain;

#define the_bird_lock()		LOCK_DOMAIN(the_bird, the_bird_domain)
#define the_bird_unlock()	UNLOCK_DOMAIN(the_bird, the_bird_domain)
#define the_bird_locked()	DOMAIN_IS_LOCKED(the_bird, the_bird_domain)

#define ASSERT_THE_BIRD_LOCKED	({ if (!the_bird_locked()) bug("The BIRD lock must be locked here: %s:%d", __FILE__, __LINE__); })

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

#define LOBJ_UNLOCK(_obj, _level) \
  UNLOCK_DOMAIN(_level, (_obj)->lock)

/*
 *  These macros can be used to define specific macros for given class.
 *
 *  #define FOO_LOCK_SIMPLE(foo)	LOBJ_LOCK_SIMPLE(foo, bar)
 *  #define FOO_UNLOCK(foo)		LOBJ_UNLOCK(foo, bar)
 *
 *  Then these can be used like this:
 *
 *  void foo_frobnicate(foo *f)
 *  {
 *    // Unlocked context
 *    ...
 *    struct foo_private *fp = FOO_LOCK(f);
 *    // Locked context
 *    ...
 *    FOO_UNLOCK(f);
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
    if (!*obj || ((*obj)->locked_at != obj)) return; \
    (*obj)->locked_at = NULL; \
    UNLOCK_DOMAIN(_level, (*obj)->lock); \
  }

#define LOBJ_LOCK(_obj, _pobj, _stem, _level) \
  CLEANUP(LOBJ_UNLOCK_CLEANUP_NAME(_stem)) struct _stem##_private *_pobj = LOBJ_LOCK_SIMPLE(_obj, _level)

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
 */





#endif
