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

struct limit {
  u32 max;
  u32 count;
  int (*action)(struct limit *, void *data);
};

static inline int limit_do_action(struct limit *l, void *data)
{
  return l->action ? l->action(l, data) : 1;
}

static inline int limit_push(struct limit *l, void *data)
{
  if ((l->count >= l->max) && limit_do_action(l, data))
    return 1;

  l->count++;
  return 0;
}

static inline void limit_pop(struct limit *l)
{
  ASSERT_DIE(l->count > 0);
  --l->count;
}

static inline void limit_reset(struct limit *l)
{
  l->count = 0;
}

static inline void limit_update(struct limit *l, void *data, u32 max)
{
  if (l->count > (l->max = max))
    limit_do_action(l, data);
}

#endif
