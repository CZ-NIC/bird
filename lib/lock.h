/*
 *	BIRD Locking
 *
 *	(c) 2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	This is the simplest way to get shared resource locking.
 *	It should be replaced by per-structure lock or lockless structures.
 *
 *	For now, it is enough.
 *
 *	Implemented in sysdep
 */

#ifndef _BIRD_LOCKING_H_
#define _BIRD_LOCKING_H_

/* Lock and unlock the BIG BIRD LOCK */
void general_lock(void);
void general_unlock(void);

#define LOCKED MACRO_PACK_BEFORE_AFTER(general_lock(), general_unlock())

#endif
