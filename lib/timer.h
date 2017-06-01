/*
 *	BIRD -- Timers
 *
 *	(c) 2013--2017 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2013--2017 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_TIMER2_H_
#define _BIRD_TIMER2_H_

#include "nest/bird.h"
#include "lib/buffer.h"
#include "lib/resource.h"


typedef struct timer2
{
  resource r;
  void (*hook)(struct timer2 *);
  void *data;

  btime expires;			/* 0=inactive */
  uint randomize;			/* Amount of randomization */
  uint recurrent;			/* Timer recurrence */

  int index;
} timer2;

struct timeloop
{
  BUFFER(timer2 *) timers;
  btime last_time;
  btime real_time;
};

static inline uint timers_count(struct timeloop *loop)
{ return loop->timers.used - 1; }

static inline timer2 *timers_first(struct timeloop *loop)
{ return (loop->timers.used > 1) ? loop->timers.data[1] : NULL; }

extern struct timeloop main_timeloop;

btime current_time(void);
btime current_real_time(void);

#define now (current_time() TO_S)
#define now_real (current_real_time() TO_S)
extern btime boot_time;

timer2 *tm2_new(pool *p);
void tm2_set(timer2 *t, btime when);
void tm2_start(timer2 *t, btime after);
void tm2_stop(timer2 *t);

static inline int
tm2_active(timer2 *t)
{
  return t->expires != 0;
}

static inline btime
tm2_remains(timer2 *t)
{
  btime now_ = current_time();
  return (t->expires > now_) ? (t->expires - now_) : 0;
}

static inline timer2 *
tm2_new_init(pool *p, void (*hook)(struct timer2 *), void *data, uint rec, uint rand)
{
  timer2 *t = tm2_new(p);
  t->hook = hook;
  t->data = data;
  t->recurrent = rec;
  t->randomize = rand;
  return t;
}

static inline void
tm2_set_max(timer2 *t, btime when)
{
  if (when > t->expires)
    tm2_set(t, when);
}

static inline void
tm2_start_max(timer2 *t, btime after)
{
  btime rem = tm2_remains(t);
  tm2_start(t, MAX_(rem, after));
}

/* In sysdep code */
void times_init(struct timeloop *loop);
void times_update(struct timeloop *loop);
void times_update_real_time(struct timeloop *loop);

/* For I/O loop */
void timers_init(struct timeloop *loop, pool *p);
void timers_fire(struct timeloop *loop);

void timer_init(void);


#endif
