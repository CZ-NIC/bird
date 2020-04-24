/*
 *	BIRD Library -- Garbage Collector
 *
 *	(c) 2020 Maria Matejka <mq@jmq.cz>
 *	(c) 2020 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/gc.h"
#include "lib/resource.h"
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

#define DEFAULT_GC_CALLBACKS  4

struct gc_callback_set **gc_callbacks = NULL;
static uint gc_callbacks_cnt = 0, gc_callbacks_size = 0;

void gc_enter(void)
{
  /* Everything is done locked. */
  pthread_mutex_lock(&gc_mutex);

  ASSERT(gc_current_round == 0);

  /* No usecount keeper? Just create some. */
  if (!gc_uc)
  {
    gc_uc = xmalloc(sizeof(u32) * DEFAULT_CONCURRENT_GC_ROUNDS);
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
      gc_uc = xrealloc(gc_uc, (gc_uc_size *= 2) * sizeof(u32));
  }

  u64 index = RTOI(gc_current_round);

  /* Current usecount is sum of all threads already accessing shared data
   * plus one for this thread. */
  gc_uc[index] = 1 + (index ? gc_uc[index - 1] : 0);

  /* Run hooks */
  for (uint i=0; i<gc_callbacks_cnt; i++)
    if (gc_callbacks[i])
      CALL(gc_callbacks[i]->enter, gc_current_round, gc_callbacks[i]);

  /* We're done now. Unlock. */
  pthread_mutex_unlock(&gc_mutex);
}

void gc_exit(void)
{
  /* Everything is done locked. */
  pthread_mutex_lock(&gc_mutex);

  ASSERT(gc_current_round <= gc_last_round);
  ASSERT(gc_current_round >= gc_oldest_round);

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

  /* Run hooks */
  for (uint i=0; i<gc_callbacks_cnt; i++)
    if (gc_callbacks[i])
      CALL(gc_callbacks[i]->exit, gc_current_round, gc_callbacks[i]);


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

  /* Run hooks */
  for (uint i=0; i<gc_callbacks_cnt; i++)
    if (gc_callbacks[i])
      CALL(gc_callbacks[i]->cleanup, gc_current_round, gc_callbacks[i]);

  /* This round is done */
  pthread_mutex_lock(&gc_mutex);
  gc_oldest_round++;
  pthread_mutex_unlock(&gc_mutex);

  return 1;
}

void gc_register(struct gc_callback_set *gcs)
{
  pthread_mutex_lock(&gc_mutex);

  if (!gc_callbacks)
    gc_callbacks = xmalloc(sizeof(struct gc_callback_set *) * (gc_callbacks_size = DEFAULT_GC_CALLBACKS));

  if (gc_callbacks_cnt == gc_callbacks_size)
    gc_callbacks = xrealloc(gc_callbacks, sizeof(struct gc_callback_set *) * (gc_callbacks_size *= 2));

  gc_callbacks[gc_callbacks_cnt++] = gcs;

  pthread_mutex_unlock(&gc_mutex);
}

void gc_unregister(struct gc_callback_set *gcs)
{
  pthread_mutex_lock(&gc_mutex);

  for (uint i=0; i<gc_callbacks_cnt; i++)
    if (gc_callbacks[i] == gcs)
    {
      gc_callbacks[i] = NULL;
      break;
    }

  pthread_mutex_unlock(&gc_mutex);
}
