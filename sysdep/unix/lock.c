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
 */

#include "lib/lock.h"

#include <pthread.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void general_lock(void) {
  pthread_mutex_lock(&lock);
}

void general_unlock(void) {
  pthread_mutex_unlock(&lock);
}
