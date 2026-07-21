/*
 *	BIRD -- Settle timer
 *
 *	(c) 2022 Maria Matejka <mq@jmq.cz>
 *	(c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SETTLE_H_
#define _BIRD_SETTLE_H_

#include "lib/birdlib.h"
#include "lib/timer.h"

struct settle_config {
  btime min, max;
};

struct settle {
  union {
    /* Timer hook polymorphism. */
    struct {
      resource _r;
      void (*hook)(struct settle *);
    };
    timer tm;
  };
  struct settle_config cf;
  btime started;
};

STATIC_ASSERT(OFFSETOF(struct settle, hook) == OFFSETOF(struct settle, tm) + OFFSETOF(timer, hook));

#define SETTLE_INIT(_cfp, _hook, _data) (struct settle) { .tm = { .data = (_data), .hook = TYPE_CAST(void (*)(struct settle *), void (*)(struct timer *), (_hook)), }, .cf = ({ASSERT_DIE((_cfp)->min <= (_cfp)->max); *(_cfp); }), }


static inline void settle_init(struct settle *s, struct settle_config *cf, void (*hook)(struct settle *), void *data)
{
  *s = SETTLE_INIT(cf, hook, data);
}

#define settle_active(s) tm_active(&(s)->tm)

static inline void settle_kick(struct settle *s)
{
  if (!tm_active(&s->tm))
  {
    s->started = current_time();
    tm_set(&s->tm, s->started + s->cf.min);
  }
  else
  {
    btime now = current_time();
    tm_set(&s->tm, MIN_(now + s->cf.min, s->started + s->cf.max));
  }
}

static inline void settle_cancel(struct settle *s)
{
  tm_stop(&s->tm);
}

#endif
