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

/* Here define the global lock order; first to last. */
struct lock_order {
  struct domain_generic *meta;
  struct domain_generic *the_bird;
  struct domain_generic *control;
  struct domain_generic *proto;
  struct domain_generic *service;
  struct domain_generic *rtable;
  struct domain_generic *attrs;
  struct domain_generic *resource;
};

extern _Thread_local struct lock_order locking_stack;
extern _Thread_local struct domain_generic **last_locked;

#define DOMAIN(type) struct domain__##type
#define DEFINE_DOMAIN(type) DOMAIN(type) { struct domain_generic *type; }
#define DOMAIN_ORDER(type)  OFFSETOF(struct lock_order, type)

#define DOMAIN_NEW(type, name)  (DOMAIN(type)) { .type = domain_new(name, DOMAIN_ORDER(type)) }
struct domain_generic *domain_new(const char *name, uint order);

#define DOMAIN_FREE(type, d)	domain_free((d).type)
void domain_free(struct domain_generic *);

#define DOMAIN_NAME(type, d)	domain_name((d).type)
const char *domain_name(struct domain_generic *);

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

#endif
