/*
 *	BIRD Library -- Atomic calls
 *
 *	(c) 2019 Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_ATOMIC_H_
#define _BIRD_ATOMIC_H_

/* If we have stdatomic.h, we simply use C11 atomic calls */

#if HAVE_ATOMIC
#include <stdatomic.h>
#else

/* Otherwise, we try to approximate the atomic calls by GCC __sync calls */

#define _Atomic

#define atomic_load(ptr) __sync_val_compare_and_swap(ptr, 0, 0)
#define atomic_load_explicit(ptr, mem) atomic_load(ptr)
#define atomic_store(ptr, val) __sync_lock_test_and_set(ptr, val)

#define atomic_fetch_add(ptr, val) __sync_fetch_and_add((ptr), (val))
#define atomic_fetch_add_explicit(ptr, val, memory) __sync_fetch_and_add((ptr), (val))
#define atomic_fetch_sub(ptr, val) __sync_fetch_and_sub((ptr), (val))
#define atomic_fetch_sub_explicit(ptr, val, memory) __sync_fetch_and_sub((ptr), (val))

#define atomic_exchange(ptr, val) __sync_lock_test_and_set((ptr), (val))
#define atomic_exchange_explicit(ptr, val, memory) atomic_exchange((ptr), (val))

#define atomic_compare_exchange_weak(ptr, desired, wanted) ({ \
    typeof(desired) _desptr = desired; /* save the pointer */ \
    typeof(*_desptr) _old = __sync_val_compare_and_swap(ptr, *_desptr, wanted); /* do the exchange */ \
    int result = _old == *_desptr; /* get the return value */ \
    *_desptr = _old; /* store the old value */ \
    result; /* and return */ })

#define atomic_compare_exchange_strong(ptr, desired, wanted) \
  atomic_compare_exchange_weak(ptr, desired, wanted)

#define atomic_compare_exchange_weak_explicit(ptr, desired, wanted, success, failure) \
  atomic_compare_exchange_weak(ptr, desired, wanted)

#define atomic_compare_exchange_strong_explicit(ptr, desired, wanted, success, failure) \
  atomic_compare_exchange_weak(ptr, desired, wanted)

#define ATOMIC_FLAG_INIT  0
typedef u8 atomic_flag;

#define atomic_flag_test_and_set_explicit(ptr, memory) \
  __sync_lock_test_and_set(ptr, 1)

#define atomic_flag_clear_explicit(ptr, memory) \
  __sync_lock_release(ptr)

#endif
#endif
