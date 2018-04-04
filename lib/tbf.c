/*
 *	BIRD Library -- Token Bucket Filter
 *
 *	(c) 2014 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2014 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/timer.h"

int
tbf_limit(struct tbf *f)
{
  btime delta = current_time() - f->timestamp;

  if (delta > 0)
  {
    u64 next = f->count + delta * f->rate;
    u64 burst = (u64) f->burst << 20;
    f->count = MIN(next, burst);
    f->timestamp += delta;
  }

  if (f->count < 1000000)
  {
    f->drop++;
    return 1;
  }
  else
  {
    f->count -= 1000000;
    f->drop = 0;
    return 0;
  }
}
