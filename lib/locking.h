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
  struct domain_generic *the_bird;
};

#define LOCK_ORDER_DEPTH  (sizeof(struct lock_order) / sizeof(struct domain_generic *))

extern _Thread_local struct lock_order locking_stack;
extern _Thread_local struct domain_generic **last_locked;

#define DOMAIN(type) struct domain__##type
#define DEFINE_DOMAIN(type) DOMAIN(type) { struct domain_generic *type; }

#define DOMAIN_NEW(type, name)  (DOMAIN(type)) { .type = domain_new(name) }
struct domain_generic *domain_new(const char *name);

#define DOMAIN_NULL(type)   (DOMAIN(type)) {}

#define LOCK_DOMAIN(type, d)	do_lock(((d).type), &(locking_stack.type))
#define UNLOCK_DOMAIN(type, d)  do_unlock(((d).type), &(locking_stack.type))

/* Internal for locking */
void do_lock(struct domain_generic *dg, struct domain_generic **lsp);
void do_unlock(struct domain_generic *dg, struct domain_generic **lsp);

/* Use with care. To be removed in near future. */
DEFINE_DOMAIN(the_bird);
extern DOMAIN(the_bird) the_bird_domain;

#define the_bird_lock()		LOCK_DOMAIN(the_bird, the_bird_domain)
#define the_bird_unlock()	UNLOCK_DOMAIN(the_bird, the_bird_domain)

#endif
