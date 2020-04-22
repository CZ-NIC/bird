/*
 *	BIRD Library -- Garbage Collector
 *
 *	(c) 2020 Maria Matejka <mq@jmq.cz>
 *	(c) 2020 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/gc.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t gc_mutex = PTHREAD_MUTEX_INITIALIZER;
static u64 gc_last_round = 0, gc_oldest_round = 1;
_Thread_local u64 gc_current_round = 0;

#define DEFAULT_CONCURRENT_GC_ROUNDS  32

static u32 *gc_uc = NULL;
static u64 gc_uc_size = 0;

static u64 gc_offset = 0;
#define RTOI(round) ((round) - gc_offset)
#define ITOR(index) ((index) + gc_offset)

void gc_enter(void)
{
  ASSERT(gc_current_round == 0);

  /* Everything is done locked. */
  pthread_mutex_lock(&gc_mutex);

  /* No usecount keeper? Just create some. */
  if (!gc_uc)
  {
    gc_uc = malloc(sizeof(u32) * DEFAULT_CONCURRENT_GC_ROUNDS);
    gc_uc_size = DEFAULT_CONCURRENT_GC_ROUNDS;
  }

  /* Update current round ID */
  gc_current_round = ++gc_last_round;

  /* We're at the end of the array */
  if (RTOI(gc_current_round) >= gc_uc_size)
  {
    /* How much space is in the beginning? */
    u64 skip = RTOI(gc_oldest_round);

    if (skip >= gc_uc_size/2)
    {
      /* Enough. Move to the beginning. */
      memcpy(gc_uc, gc_uc + skip, (gc_current_round - gc_oldest_round) * sizeof(u32));
      gc_offset += skip;
    }
    else
      /* Not enough. Realloc. */
      gc_uc = realloc(gc_uc, (gc_uc_size *= 2) * sizeof(u32));
  }

  u64 index = RTOI(gc_current_round);

  /* Current usecount is sum of all threads already accessing shared data
   * plus one for this thread. */
  gc_uc[index] = 1 + (index ? gc_uc[index - 1] : 0);

  /* We're done now. Unlock. */
  pthread_mutex_unlock(&gc_mutex);
}

void gc_exit(void)
{
  ASSERT(gc_current_round <= gc_last_round);
  ASSERT(gc_current_round >= gc_oldest_round);

  /* Everything is done locked. */
  pthread_mutex_lock(&gc_mutex);

  for (
      u64 index = RTOI(gc_current_round),
	  max = RTOI(gc_last_round);
	  index <= max;
	  index++
      )
  {
    ASSERT(gc_uc[index] > 0);
    gc_uc[index]--;
  }

  gc_current_round = 0;

  /* Done. Unlock. */
  pthread_mutex_unlock(&gc_mutex);

  /* Do some cleanup */
  uint max = 4;
  while (max-- && gc_cleanup())
    ;
}

_Bool gc_cleanup(void)
{
  ASSERT(gc_last_round >= gc_oldest_round);

  /* Check for zero in the oldest round */
  pthread_mutex_lock(&gc_mutex);
  u32 oldest_round_uc = gc_uc[RTOI(gc_oldest_round)];
  pthread_mutex_unlock(&gc_mutex);

  /* The oldest round is still in use */
  if (oldest_round_uc > 0)
    return 0;

  /* TODO: Do the real cleanup here */

  /* This round is done */
  pthread_mutex_lock(&gc_mutex);
  gc_oldest_round++;
  pthread_mutex_unlock(&gc_mutex);

  return 1;
}
