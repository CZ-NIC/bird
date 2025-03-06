/*
 *	BIRD Library -- malloc() With Checking
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>

#include "nest/bird.h"
#include "lib/resource.h"
#include "lib/timer.h"

#ifndef HAVE_LIBDMALLOC

#if DEBUG_ALLOCATOR
struct minfo {
  void *ptr;
  uint size;
  uint action;
  uint thread_id;
  btime time;
} minfo_block[65536];
_Atomic uint minfo_pos;

#define MINFO(p, s, a)	minfo_block[atomic_fetch_add_explicit(&minfo_pos, 1, memory_order_acq_rel) % 65536] = (struct minfo) { .ptr = p, .size = s, .action = a, .thread_id = THIS_THREAD_ID, .time = current_time_now(), }
#else
#define MINFO(...)
#endif

/**
 * xmalloc - malloc with checking
 * @size: block size
 *
 * This function is equivalent to malloc() except that in case of
 * failure it calls die() to quit the program instead of returning
 * a %NULL pointer.
 *
 * Wherever possible, please use the memory resources instead.
 */
void *
xmalloc(uint size)
{

  void *p = malloc(size);
  MINFO(p, size, 1);

  if (p)
    return p;
  die("Unable to allocate %d bytes of memory", size);
}

/**
 * xrealloc - realloc with checking
 * @ptr: original memory block
 * @size: block size
 *
 * This function is equivalent to realloc() except that in case of
 * failure it calls die() to quit the program instead of returning
 * a %NULL pointer.
 *
 * Wherever possible, please use the memory resources instead.
 */
void *
xrealloc(void *ptr, uint size)
{
  MINFO(ptr, 0, 2);
  void *p = realloc(ptr, size);
  MINFO(p, size, 3);

  if (p)
    return p;
  die("Unable to allocate %d bytes of memory", size);
}


void xfree(void *p)
{
  MINFO(p, 0, 4);
  free(p);
}
#endif
