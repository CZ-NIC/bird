/*
 *	BIRD Object Locks
 *
 *	(c) 1999 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Object locks
 *
 * The lock module provides a simple mechanism for avoiding conflicts between
 * various protocols which would like to use a single physical resource (for
 * example a network port). It would be easy to say that such collisions can
 * occur only when the user specifies an invalid configuration and therefore
 * he deserves to get what he has asked for, but unfortunately they can also
 * arise legitimately when the daemon is reconfigured and there exists (although
 * for a short time period only) an old protocol instance being shut down and a new one
 * willing to start up on the same interface.
 *
 * The solution is very simple: when any protocol wishes to use a network port
 * or some other non-shareable resource, it asks the core to lock it and it doesn't
 * use the resource until it's notified that it has acquired the lock.
 *
 * Object locks are represented by &object_lock structures which are in turn a
 * kind of resource. Lockable resources are uniquely determined by resource type
 * (%OBJLOCK_UDP for a UDP port etc.), IP address (usually a broadcast or
 * multicast address the port is bound to), port number, interface and optional
 * instance ID.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "lib/resource.h"
#include "nest/locks.h"
#include "nest/iface.h"

static list olock_list;

DEFINE_DOMAIN(attrs);
static DOMAIN(attrs) olock_domain;
#define OBJ_LOCK	LOCK_DOMAIN(attrs, olock_domain)
#define OBJ_UNLOCK	UNLOCK_DOMAIN(attrs, olock_domain)

static inline int
olock_same(struct object_lock *x, struct object_lock *y)
{
  return
    x->type == y->type &&
    x->iface == y->iface &&
    x->vrf == y->vrf &&
    x->port == y->port &&
    x->inst == y->inst &&
    ipa_equal(x->addr, y->addr);
}

static void
olock_free(resource *r)
{
  /* Called externally from rfree() */
  struct object_lock *l = SKIP_BACK(struct object_lock, r, r);
  node *n;

  OBJ_LOCK;
  DBG("olock: Freeing %p\n", l);
  switch (l->state)
    {
    case OLOCK_STATE_FREE:
      break;
    case OLOCK_STATE_LOCKED:
      /* Remove myself from the olock_list */
      rem_node(&l->n);

      /* Maybe the notification is still pending. */
      ev_postpone(&l->event);

      /* Get new lock candidate */
      n = HEAD(l->waiters);
      if (NODE_VALID(n))
	{
	  struct object_lock *q = SKIP_BACK(struct object_lock, n, n);

	  /* Remove this candidate from waiters list */
	  rem_node(n);

	  /* Move waiter lists */
	  DBG("olock: -> %p becomes locked\n", n);
	  add_tail_list(&q->waiters, &l->waiters);

	  /* Add the new olock to olock_list */
	  add_head(&olock_list, n);

	  /* Inform */
	  q->state = OLOCK_STATE_LOCKED;
	  ev_send(q->target, &q->event);
	}
      break;
    case OLOCK_STATE_WAITING:
      /* Remove from the waiters list */
      rem_node(&l->n);
      break;
    default:
      ASSERT(0);
    }
  OBJ_UNLOCK;
}

static void
olock_dump(resource *r, unsigned indent UNUSED)
{
  struct object_lock *l = (struct object_lock *) r;
  static char *olock_states[] = { "free", "locked", "waiting", "event" };

  debug("(%d:%s:%I:%d:%d) [%s]\n", l->type, (l->iface ? l->iface->name : "?"), l->addr, l->port, l->inst, olock_states[l->state]);
  if (!EMPTY_LIST(l->waiters))
    debug(" [wanted]\n");
}

static struct resclass olock_class = {
  "ObjLock",
  sizeof(struct object_lock),
  olock_free,
  olock_dump,
  NULL,
  NULL,
};

/**
 * olock_new - create an object lock
 * @p: resource pool to create the lock in.
 *
 * The olock_new() function creates a new resource of type &object_lock
 * and returns a pointer to it. After filling in the structure, the caller
 * should call olock_acquire() to do the real locking.
 */
struct object_lock *
olock_new(pool *p)
{
  struct object_lock *l = ralloc(p, &olock_class);

  l->state = OLOCK_STATE_FREE;
  init_list(&l->waiters);
  return l;
}

/**
 * olock_acquire - acquire a lock
 * @l: the lock to acquire
 *
 * This function attempts to acquire exclusive access to the non-shareable
 * resource described by the lock @l. It returns immediately, but as soon
 * as the resource becomes available, it calls the hook() function set up
 * by the caller.
 *
 * When you want to release the resource, just rfree() the lock.
 */
void
olock_acquire(struct object_lock *l)
{
  node *n;
  struct object_lock *q;

  OBJ_LOCK;

  WALK_LIST(n, olock_list)
    {
      q = SKIP_BACK(struct object_lock, n, n);
      if (olock_same(q, l))
	{
	  l->state = OLOCK_STATE_WAITING;
	  add_tail(&q->waiters, &l->n);
	  DBG("olock: %p waits\n", l);

	  OBJ_UNLOCK;
	  return;
	}
    }

  DBG("olock: %p acquired immediately\n", l);
  add_head(&olock_list, &l->n);

  l->state = OLOCK_STATE_LOCKED;
  ev_send(l->target, &l->event);

  OBJ_UNLOCK;
}

/**
 * olock_init - initialize the object lock mechanism
 *
 * This function is called during BIRD startup. It initializes
 * all the internal data structures of the lock module.
 */
void
olock_init(void)
{
  DBG("olock: init\n");
  init_list(&olock_list);
  olock_domain = DOMAIN_NEW(attrs, "Object lock");
}
