/*
 *	BIRD Library -- Garbage Collector for Threads
 *
 *	(c) 2020 Maria Matejka <mq@jmq.cz>
 *	(c) 2020 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_GC_H_
#define _BIRD_GC_H_

#include "lib/birdlib.h"

/* Call gc_enter() before any code where a shared structure
 * may be accessed by this thread. Mostly this should be called
 * immediately after a poll() returns.  */
void gc_enter(void);

/* Call gc_exit() when no shared structure is being held
 * by the current thread. Mostly this means calling this
 * before calling poll() which may wait for a long time. */
void gc_exit(void);

/* Clean up all the data which has been freed in the oldest gc round that has been already exited.
 * Returns 1 on success (there was something to clean), 0 when there is no gc round available to cleanup.
 * It is recommended to run this outside any gc round. */
_Bool gc_cleanup(void);

/* GC callback type */
struct gc_callback_set {
  void (*enter)(u64, struct gc_callback_set *);
  void (*exit)(u64, struct gc_callback_set *);
  void (*cleanup)(u64, struct gc_callback_set *);
};

/* Register callbacks. These are called for each entered, exited and cleaned-up round.
 * The caller must keep the structure. */
void gc_register(struct gc_callback_set *);
void gc_unregister(struct gc_callback_set *);

#endif
