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
#include "lib/io-loop.h"
#include "lib/locking.h"
#include "lib/resource.h"

#include <stdatomic.h>

extern _Atomic btime last_time;
extern _Atomic btime real_time;

typedef struct timer
{
  resource r;
  void (*hook)(struct timer *);
  void *data;

  btime expires;			/* 0=inactive */
  btime recurrent;			/* Timer recurrence */
  uint randomize;			/* Amount of randomization */

  struct timeloop *loop;		/* Loop where the timer is active */

  int index;
} timer;

struct timeloop
{
  BUFFER_(timer *) timers;
  struct domain_generic *domain;
  struct birdloop *loop;
};

#define TLOCK_TIMER_ASSERT(loop) ASSERT_DIE((loop)->domain && DG_IS_LOCKED((loop)->domain))
#define TLOCK_LOCAL_ASSERT(loop) ASSERT_DIE(!(loop)->domain || DG_IS_LOCKED((loop)->domain))

static inline uint timers_count(struct timeloop *loop)
{ TLOCK_TIMER_ASSERT(loop); return loop->timers.used - 1; }

static inline timer *timers_first(struct timeloop *loop)
{ TLOCK_TIMER_ASSERT(loop); return (loop->timers.used > 1) ? loop->timers.data[1] : NULL; }

#define current_time()		atomic_load_explicit(&last_time, memory_order_acquire)
#define current_real_time()	atomic_load_explicit(&real_time, memory_order_acquire)

/* In sysdep code */
btime current_time_now(void);

//#define now (current_time() TO_S)
//#define now_real (current_real_time() TO_S)
extern btime boot_time;

timer *tm_new(pool *p);
#define tm_set(t, when) tm_set_in((t), (when), &main_birdloop)
#define tm_start(t, after) tm_start_in((t), (after), &main_birdloop)
void tm_stop(timer *t);

void tm_set_in(timer *t, btime when, struct birdloop *loop);
#define tm_start_in(t, after, loop) tm_set_in((t), (current_time() + MAX_((after), 0)), loop)

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
tm_new_init(pool *p, void (*hook)(struct timer *), void *data, btime rec, uint rand)
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
tm_start_max_in(timer *t, btime after, struct birdloop *loop)
{
  btime rem = tm_remains(t);
  tm_start_in(t, MAX_(rem, after), loop);
}

#define tm_start_max(t, after)	tm_start_max_in(t, after, &main_birdloop)

/* In sysdep code */
void times_update(void);

/* For I/O loop */
void timers_init(struct timeloop *loop, pool *p);
void timers_fire(struct timeloop *loop);

/* For extra fine precision */
u64 ns_now(void);

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
