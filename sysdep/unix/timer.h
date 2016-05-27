/*
 *	BIRD -- Unix Timers
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_TIMER_H_
#define _BIRD_TIMER_H_

#include <time.h>

#include "lib/resource.h"

/* Microsecond time */

typedef s64 btime;

#define S_	*1000000
#define MS_	*1000
#define US_	*1
#define NS_	/1000

#define TO_S	/1000000
#define TO_MS	/1000
#define TO_US	/1
#define TO_NS	*1000

#ifndef PARSER
#define S	S_
#define MS	MS_
#define US	US_
#define NS	NS_
#endif

typedef time_t bird_clock_t;		/* Use instead of time_t */

typedef struct timer {
  resource r;
  void (*hook)(struct timer *);
  void *data;
  unsigned randomize;			/* Amount of randomization */
  unsigned recurrent;			/* Timer recurrence */
  node n;				/* Internal link */
  btime expires_btime;			/* 0=inactive */
  bird_clock_t expires;			/* == expires_btime TO_S */
} timer;

timer *tm_new(pool *);
void tm_start(timer *, unsigned after);
void tm_start_btime(timer *, btime after);
void tm_stop(timer *);
void tm_dump_all(void);

extern bird_clock_t now; 		/* Relative, monotonic time in seconds */
extern btime now_btime;			/* dtto in microseconds */
extern bird_clock_t now_real;		/* Time in seconds since fixed known epoch */
extern bird_clock_t boot_time;


static inline int
tm_active(timer *t)
{
  return t->expires_btime != 0;
}

static inline btime
tm_remains_btime(timer *t)
{
  return t->expires_btime ? t->expires_btime - now_btime : 0;
}

static inline bird_clock_t
tm_remains(timer *t)
{
  return tm_remains_btime(t) TO_S;
}

static inline void
tm_start_max_btime(timer *t, btime after)
{
  btime rem = tm_remains_btime(t);
  tm_start(t, (rem > after) ? rem : after);
}

static inline void
tm_start_min_btime(timer *t, btime after)
{
  btime rem = tm_remains_btime(t);
  if (!rem || after < rem)
    tm_start(t, after);
}

static inline void
tm_start_max(timer *t, unsigned after)
{
  tm_start_max_btime(t, after S_);
}

static inline timer *
tm_new_set(pool *p, void (*hook)(struct timer *), void *data, unsigned rand, unsigned rec)
{
  timer *t = tm_new(p);
  t->hook = hook;
  t->data = data;
  t->randomize = rand;
  t->recurrent = rec;
  return t;
}


struct timeformat {
  char *fmt1, *fmt2;
  bird_clock_t limit;
};

bird_clock_t tm_parse_date(char *);	/* Convert date to bird_clock_t */
bird_clock_t tm_parse_datetime(char *);	/* Convert date to bird_clock_t */

#define TM_DATETIME_BUFFER_SIZE 32	/* Buffer size required by tm_format_datetime */
void
tm_format_datetime(char *x, struct timeformat *fmt_spec, bird_clock_t t);

#ifdef TIME_T_IS_64BIT
#define TIME_INFINITY 0x7fffffffffffffff
#else
#ifdef TIME_T_IS_SIGNED
#define TIME_INFINITY 0x7fffffff
#else
#define TIME_INFINITY 0xffffffff
#endif
#endif

#define BTIME_INFINITY 0x7fffffffffffffff

#endif
