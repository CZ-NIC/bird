/*
 *	BIRD -- Timers
 *
 *	(c) 2013--2017 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2013--2017 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_TIMER_H_
#define _BIRD_TIMER_H_

#include "nest/bird.h"
#include "lib/buffer.h"
#include "lib/resource.h"


typedef struct timer
{
  resource r;
  void (*hook)(struct timer *);
  void *data;

  btime expires;			/* 0=inactive */
  uint randomize;			/* Amount of randomization */
  uint recurrent;			/* Timer recurrence */

  int index;
} timer;

struct timeloop
{
  BUFFER_(timer *) timers;
  btime last_time;
  btime real_time;
};

static inline uint timers_count(struct timeloop *loop)
{ return loop->timers.used - 1; }

static inline timer *timers_first(struct timeloop *loop)
{ return (loop->timers.used > 1) ? loop->timers.data[1] : NULL; }

extern struct timeloop main_timeloop;

btime current_time(void);
btime current_real_time(void);

/* In sysdep code */
btime current_time_now(void);

//#define now (current_time() TO_S)
//#define now_real (current_real_time() TO_S)
extern btime boot_time;

timer *tm_new(pool *p);
void tm_set(timer *t, btime when);
void tm_start(timer *t, btime after);
void tm_stop(timer *t);

static inline int
tm_active(timer *t)
{
  return t->expires != 0;
}

static inline btime
tm_remains(timer *t)
{
  btime now_ = current_time();
  return (t->expires > now_) ? (t->expires - now_) : 0;
}

static inline timer *
tm_new_init(pool *p, void (*hook)(struct timer *), void *data, uint rec, uint rand)
{
  timer *t = tm_new(p);
  t->hook = hook;
  t->data = data;
  t->recurrent = rec;
  t->randomize = rand;
  return t;
}

static inline void
tm_set_max(timer *t, btime when)
{
  if (when > t->expires)
    tm_set(t, when);
}

static inline void
tm_start_max(timer *t, btime after)
{
  btime rem = tm_remains(t);
  tm_start(t, MAX_(rem, after));
}

/* In sysdep code */
void times_init(struct timeloop *loop);
void times_update(struct timeloop *loop);
void times_update_real_time(struct timeloop *loop);

/* For I/O loop */
void timers_init(struct timeloop *loop, pool *p);
void timers_fire(struct timeloop *loop);

void timer_init(void);


struct timeformat {
  const char *fmt1, *fmt2;
  btime limit;
};

#define TM_ISO_SHORT_S	(struct timeformat){"%T",     "%F", (s64) (20*3600) S_}
#define TM_ISO_SHORT_MS	(struct timeformat){"%T.%3f", "%F", (s64) (20*3600) S_}
#define TM_ISO_SHORT_US	(struct timeformat){"%T.%6f", "%F", (s64) (20*3600) S_}

#define TM_ISO_LONG_S	(struct timeformat){"%F %T",     NULL, 0}
#define TM_ISO_LONG_MS	(struct timeformat){"%F %T.%3f", NULL, 0}
#define TM_ISO_LONG_US	(struct timeformat){"%F %T.%6f", NULL, 0}

#define TM_DATETIME_BUFFER_SIZE 32	/* Buffer size required by tm_format_time() */

btime tm_parse_time(const char *x);
void tm_format_time(char *x, struct timeformat *fmt, btime t);
int tm_format_real_time(char *x, size_t max, const char *fmt, btime t);

#endif
