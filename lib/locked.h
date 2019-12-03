/*
 *	BIRD Library -- Locked data structures
 *
 *	(c) 2019 Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LOCKED_H_
#define _BIRD_LOCKED_H_

/* Worker / Thread ID */
#define NOWORKER (~((u64) 0))
extern _Thread_local u64 worker_id;

#endif

