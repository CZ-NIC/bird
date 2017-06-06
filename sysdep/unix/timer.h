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

#include "lib/birdlib.h"
#include "lib/timer.h"


typedef struct timer2 timer;

static inline timer *tm_new(pool *p)
{ return (void *) tm2_new(p); }

static inline void tm_start(timer *t, bird_clock_t after)
{ tm2_start(t, after S_); }

static inline void tm_stop(timer *t)
{ tm2_stop(t); }

// void tm_dump_all(void);

//extern bird_clock_t now; 		/* Relative, monotonic time in seconds */
//extern bird_clock_t now_real;		/* Time in seconds since fixed known epoch */
//extern bird_clock_t boot_time;

static inline int tm_active(timer *t)
{ return tm2_active(t); }

static inline bird_clock_t tm_remains(timer *t)
{ return tm2_remains(t) TO_S; }

static inline void tm_start_max(timer *t, bird_clock_t after)
{ tm2_start_max(t, after S_); }

static inline timer * tm_new_set(pool *p, void (*hook)(timer *), void *data, uint rand, uint rec)
{ return tm2_new_init(p, hook, data, rec S_, rand S_); }


#define TIME_INFINITY ((s64) 0x7fffffffffffffff)


#endif
