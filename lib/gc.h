/*
 *	BIRD Library -- Garbage Collector
 *
 *	(c) 2020 Maria Matejka <mq@jmq.cz>
 *	(c) 2020 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_GC_H_
#define _BIRD_GC_H_

#include "lib/birdlib.h"

/* Current gc round */
extern _Thread_local u64 gc_current_round_id;

/* Call gc_enter() before any code where a shared structure may be accessed.
 * Mostly this should be called immediately after a poll() returns.
 * This call sets gc_current_round to the appropriate value. */
void gc_enter(void);

/* Call gc_exit() when no shared structure is being held.
 * Mostly this means calling this before calling poll() which may wait for a long time.
 * This call nulls gc_current_round. */
void gc_exit(void);

/* Clean up all the data which has been freed in the oldest gc round that has been already exited.
 * Returns 1 on success (there was something to clean), 0 when there is no gc round available to cleanup.
 * It is recommended to run this outside any gc round. */
_Bool gc_cleanup(void);

#endif
