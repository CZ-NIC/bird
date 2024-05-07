/*
 *	BIRD Library -- Locking
 *
 *	(c) 2020--2021 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LOCKING_H_
#define _BIRD_LOCKING_H_

#include "lib/macro.h"

struct domain_generic;
struct pool;

#define LOCK_ORDER \
  the_bird, \
  meta, \
  control, \
  proto, \
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

#endif
