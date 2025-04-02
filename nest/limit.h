/*
 *	BIRD Internet Routing Daemon -- Limits
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2021 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LIMIT_H_
#define _BIRD_LIMIT_H_


#define LIMIT_PUBLIC                                                                    \
  DOMAIN(attrs) lock;		/* Lock to take to access the private parts */		\
  int (*action)(struct limit_private *, void *data);                                    \

struct limit_private {
  /* Once more the public part */
  struct { LIMIT_PUBLIC; };
  struct limit_private **locked_at;
  u32 max;
  u32 count;
};

typedef union limit {
  struct { LIMIT_PUBLIC; };
  struct limit_private priv;
} limit;


LOBJ_UNLOCK_CLEANUP(limit, attrs);
#define LIMIT_LOCK_SIMPLE(lim)	LOBJ_LOCK_SIMPLE(lim, attrs)
#define LIMIT_UNLOCK_SIMPLE(lim)	LOBJ_UNLOCK_SIMPLE(lim, attrs)

#define LIMIT_LOCKED(lim, lm)	LOBJ_LOCKED(lim, lm, limit, attrs)
#define LIMIT_LOCK(lim, tp)	LOBJ_LOCK(lim, lm, limit, attrs)

static inline int limit_do_action(struct limit_private *l, void *data)
{
  return l->action ? l->action(l, data) : 1;
}

static inline int limit_push(struct limit_private *l, void *data)
{
  if ((l->count >= l->max) && limit_do_action(l, data))
    return 1;

  l->count++;
  return 0;
}

static inline int limit_lock_push(limit *lim, void *data)
{
  int ret;
  LIMIT_LOCKED(lim, l)
  {
    ret = limit_push(l, data);
  }
  return ret;
}

static inline void limit_pop(struct limit_private *l)
{
  ASSERT_DIE(l->count > 0);
  --l->count;
}


static inline void limit_reset(struct limit_private *l)
{
  l->count = 0;
}

static inline void limit_update(struct limit_private *l, void *data, u32 max)
{
  if (l->count > (l->max = max))
    limit_do_action(l, data);
}

#endif
