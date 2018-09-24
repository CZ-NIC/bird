/*
 *	BIRD Locking Subsystem
 *
 *	(c) 2018 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SYSDEP_MUTEX_H_
#define _BIRD_SYSDEP_MUTEX_H_

#define MUTEX_DEBUG 1

#if MUTEX_DEBUG
#define MUTEX_TYPE PTHREAD_MUTEX_ERRORCHECK
#else
#define MUTEX_TYPE PTHREAD_MUTEX_NORMAL
#endif

#include <pthread.h>
typedef pthread_mutex_t mutex;

static inline void mutex_init(mutex *m)
{
  pthread_mutexattr_t mat;
  if (pthread_mutexattr_init(&mat) < 0)
    bug("pthread_mutexattr_init() failed: %m");
  if (pthread_mutexattr_settype(&mat, MUTEX_TYPE) < 0)
    bug("pthread_mutexattr_settype() failed: %m");
  if (pthread_mutex_init(m, &mat) < 0)
    bug("pthread_mutex_init() failed: %m");
}

#if MUTEX_DEBUG
#define mutex_lock(m) do { \
    if (pthread_mutex_lock(m)) \
      bug("pthread_mutex_lock() failed: %m"); \
  } while (0)

#define mutex_unlock(m) do { \
    if (pthread_mutex_unlock(m)) \
      bug("pthread_mutex_unlock() failed: %m"); \
  } while (0)
#else
#define mutex_lock(m) pthread_mutex_lock(m)
#define mutex_unlock(m) pthread_mutex_unlock(m)
#endif

#endif
