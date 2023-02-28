/*
 *	BIRD -- Timers
 *
 *	(c) 2013--2017 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2013--2017 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Timers
 *
 * Timers are resources which represent a wish of a module to call a function at
 * the specified time. The timer code does not guarantee exact timing, only that
 * a timer function will not be called before the requested time.
 *
 * In BIRD, time is represented by values of the &btime type which is signed
 * 64-bit integer interpreted as a relative number of microseconds since some
 * fixed time point in past. The current time can be obtained by current_time()
 * function with reasonable accuracy and is monotonic. There is also a current
 * 'wall-clock' real time obtainable by current_real_time() reported by OS.
 *
 * Each timer is described by a &timer structure containing a pointer to the
 * handler function (@hook), data private to this function (@data), time the
 * function should be called at (@expires, 0 for inactive timers), for the other
 * fields see |timer.h|.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "nest/bird.h"

#include "lib/heap.h"
#include "lib/resource.h"
#include "lib/timer.h"

#include <pthread.h>

_Atomic btime last_time;
_Atomic btime real_time;

void wakeup_kick_current(void);


#define TIMER_LESS(a,b)		((a)->expires < (b)->expires)
#define TIMER_SWAP(heap,a,b,t)	(t = heap[a], heap[a] = heap[b], heap[b] = t, \
				   heap[a]->index = (a), heap[b]->index = (b))


static void
tm_free(resource *r)
{
  timer *t = (void *) r;

  tm_stop(t);
}

static void
tm_dump(resource *r, unsigned indent UNUSED)
{
  timer *t = (void *) r;

  debug("(code %p, data %p, ", t->hook, t->data);
  if (t->randomize)
    debug("rand %d, ", t->randomize);
  if (t->recurrent)
    debug("recur %d, ", t->recurrent);
  if (t->expires)
    debug("in loop %p expires in %d ms)\n", t->loop, (t->expires - current_time()) TO_MS);
  else
    debug("inactive)\n");
}


static struct resclass tm_class = {
  "Timer",
  sizeof(timer),
  tm_free,
  tm_dump,
  NULL,
  NULL
};

timer *
tm_new(pool *p)
{
  timer *t = ralloc(p, &tm_class);
  t->index = -1;
  return t;
}

static void
tm_set_in_tl(timer *t, btime when, struct timeloop *local_timeloop)
{
  uint tc = timers_count(local_timeloop);

  if (!t->expires)
  {
    t->index = ++tc;
    t->expires = when;
    BUFFER_PUSH(local_timeloop->timers) = t;
    HEAP_INSERT(local_timeloop->timers.data, tc, timer *, TIMER_LESS, TIMER_SWAP);
  }
  else if (t->expires < when)
  {
    t->expires = when;
    HEAP_INCREASE(local_timeloop->timers.data, tc, timer *, TIMER_LESS, TIMER_SWAP, t->index);
  }
  else if (t->expires > when)
  {
    t->expires = when;
    HEAP_DECREASE(local_timeloop->timers.data, tc, timer *, TIMER_LESS, TIMER_SWAP, t->index);
  }

  t->loop = local_timeloop;

  if (t->index == 1)
    birdloop_ping(local_timeloop->loop);
}

void
tm_set_in(timer *t, btime when, struct birdloop *loop)
{
  ASSERT_DIE(birdloop_inside(loop));
  tm_set_in_tl(t, when, birdloop_time_loop(loop));
}

void
tm_stop(timer *t)
{
  if (!t->expires)
    return;

  TLOCK_TIMER_ASSERT(t->loop);

  uint tc = timers_count(t->loop);

  HEAP_DELETE(t->loop->timers.data, tc, timer *, TIMER_LESS, TIMER_SWAP, t->index);
  BUFFER_POP(t->loop->timers);

  t->index = -1;
  t->expires = 0;
  t->loop = NULL;
}

void
timers_init(struct timeloop *loop, pool *p)
{
  TLOCK_TIMER_ASSERT(loop);

  BUFFER_INIT(loop->timers, p, 4);
  BUFFER_PUSH(loop->timers) = NULL;
}

void io_log_event(void *hook, void *data);

void
timers_fire(struct timeloop *loop, int io_log)
{
  TLOCK_TIMER_ASSERT(loop);

  btime base_time;
  timer *t;

  times_update();
  base_time = current_time();

  while (t = timers_first(loop))
  {
    if (t->expires > base_time)
      return;

    if (t->recurrent)
    {
      btime when = t->expires + t->recurrent;

      if (when <= base_time)
	when = base_time + t->recurrent;

      if (t->randomize)
	when += random() % (t->randomize + 1);

      tm_set_in_tl(t, when, loop);
    }
    else
      tm_stop(t);

    /* This is ugly hack, we want to log just timers executed from the main I/O loop */
    if (io_log)
      io_log_event(t->hook, t->data);

    t->hook(t);
    tmp_flush();
  }
}


/**
 * tm_parse_time - parse a date and time
 * @x: time string
 *
 * tm_parse_time() takes a textual representation of a date and time
 * (yyyy-mm-dd[ hh:mm:ss[.sss]]) and converts it to the corresponding value of
 * type &btime.
 */
btime
tm_parse_time(const char *x)
{
  struct tm tm = {};
  int usec, n1, n2, n3, r;

  r = sscanf(x, "%d-%d-%d%n %d:%d:%d%n.%d%n",
	     &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &n1,
	     &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &n2,
	     &usec, &n3);

  if ((r == 3) && !x[n1])
    tm.tm_hour = tm.tm_min = tm.tm_sec = usec = 0;
  else if ((r == 6) && !x[n2])
    usec = 0;
  else if ((r == 7) && !x[n3])
  {
    /* Convert subsecond digits to proper precision */
    int digits = n3 - n2 - 1;
    if ((usec < 0) || (usec > 999999) || (digits < 1) || (digits > 6))
      return 0;

    while (digits++ < 6)
      usec *= 10;
  }
  else
    return 0;

  tm.tm_mon--;
  tm.tm_year -= 1900;
  s64 ts = mktime(&tm);
  if ((ts == (s64) (time_t) -1) || (ts < 0) || (ts > ((s64) 1 << 40)))
    return 0;

  return ts S + usec;
}

/**
 * tm_format_time - convert date and time to textual representation
 * @x: destination buffer of size %TM_DATETIME_BUFFER_SIZE
 * @fmt: specification of resulting textual representation of the time
 * @t: time
 *
 * This function formats the given relative time value @t to a textual
 * date/time representation (dd-mm-yyyy hh:mm:ss) in real time.
 */
void
tm_format_time(char *x, struct timeformat *fmt, btime t)
{
  btime dt = current_time() - t;
  btime rt = current_real_time() - dt;
  int v1 = !fmt->limit || (dt < fmt->limit);

  if (!tm_format_real_time(x, TM_DATETIME_BUFFER_SIZE, v1 ? fmt->fmt1 : fmt->fmt2, rt))
    strcpy(x, "<error>");
}

/* Replace %f in format string with usec scaled to requested precision */
static int
strfusec(char *buf, int size, const char *fmt, uint usec)
{
  char *str = buf;
  int parity = 0;

  while (*fmt)
  {
    if (!size)
      return 0;

    if ((fmt[0] == '%') && (!parity) &&
	((fmt[1] == 'f') || (fmt[1] >= '1') && (fmt[1] <= '6') && (fmt[2] == 'f')))
    {
      int digits = (fmt[1] == 'f') ? 6 : (fmt[1] - '0');
      uint d = digits, u = usec;

      /* Convert microseconds to requested precision */
      while (d++ < 6)
	u /= 10;

      int num = bsnprintf(str, size, "%0*u", digits, u);
      if (num < 0)
	return 0;

      fmt += (fmt[1] == 'f') ? 2 : 3;
      ADVANCE(str, size, num);
    }
    else
    {
      /* Handle '%%' expression */
      parity = (*fmt == '%') ? !parity : 0;
      *str++ = *fmt++;
      size--;
    }
  }

  if (!size)
    return 0;

  *str = 0;
  return str - buf;
}

int
tm_format_real_time(char *x, size_t max, const char *fmt, btime t)
{
  s64 t1 = t TO_S;
  s64 t2 = t - t1 S;

  time_t ts = t1;
  struct tm tm;
  if (!localtime_r(&ts, &tm))
    return 0;

  size_t tbuf_size = MIN(max, 4096);
  byte *tbuf = alloca(tbuf_size);
  if (!strfusec(tbuf, tbuf_size, fmt, t2))
    return 0;

  if (!strftime(x, max, tbuf, &tm))
    return 0;

  return 1;
}
