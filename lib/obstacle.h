/*
 *	BIRD Library -- Obstacle Keeper
 *
 *	(c) 2024	CZ.NIC, z.s.p.o.
 *	(c) 2024	Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_OBSTACLE_H_
#define _BIRD_OBSTACLE_H_

#include "lib/event.h"
#include "lib/locking.h"
#include "lib/string.h"
#include "lib/tlists.h"

#define TLIST_PREFIX obstacle
#define TLIST_TYPE struct obstacle
#define TLIST_ITEM n

struct obstacle {
  TLIST_DEFAULT_NODE;
};

#define TLIST_WANT_ADD_TAIL

#include "lib/tlists.h"

struct obstacle_target {
  DOMAIN(resource) dom;
  TLIST_LIST(obstacle) obstacles;
  struct callback *done;
};

static inline void
obstacle_put(struct obstacle_target *t, struct obstacle *o)
{
  LOCK_DOMAIN(resource, t->dom);
  obstacle_add_tail(&t->obstacles, o);
  UNLOCK_DOMAIN(resource, t->dom);
}

static inline void
obstacle_remove(struct obstacle *o)
{
  SKIP_BACK_DECLARE(struct obstacle_target, t, obstacles, obstacle_enlisted(o));
  LOCK_DOMAIN(resource, t->dom);
  obstacle_rem_node(&t->obstacles, o);
  if (EMPTY_TLIST(obstacle, &t->obstacles))
    callback_activate(t->done);
  UNLOCK_DOMAIN(resource, t->dom);
}

static inline void
obstacle_target_init(struct obstacle_target *t, struct callback *done, pool *p, const char *fmt, ...)
{
  t->dom = DOMAIN_NEW(resource);
  va_list args;
  va_start(args, fmt);
  DOMAIN_SETUP(resource, t->dom, mb_vsprintf(p, fmt, args), p);
  va_end(args);

  t->obstacles = (struct obstacle_list) {};
  t->done = done;
}

static inline uint
obstacle_target_count(struct obstacle_target *t)
{
  LOCK_DOMAIN(resource, t->dom);
  uint len = TLIST_LENGTH(obstacle, &t->obstacles);
  UNLOCK_DOMAIN(resource, t->dom);
  return len;
}

#define OBSREF(_type)	struct { _type *ref; struct obstacle o; }

#define OBSREF_SET(_ref, _val)	({	\
  typeof (_ref) *_r = &(_ref);		\
  typeof (_val) _v = (_val);		\
  ASSERT_DIE(_r->ref == NULL);		\
  obstacle_put(&_v->obstacles, &_r->o);	\
  _r->ref = _v;				\
  })

#define OBSREF_CLEAR(_ref)  ({		\
  typeof (_ref) *_r = &(_ref);		\
  if (_r->ref) {			\
    obstacle_remove(&_r->o);		\
    _r->ref = NULL;			\
  }})

#define OBSREF_GET(_ref) ((_ref).ref)

#endif
