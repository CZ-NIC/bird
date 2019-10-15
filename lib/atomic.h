#ifndef _BIRD_ATOMIC_H_
#define _BIRD_ATOMIC_H_

//#if HAVE_ATOMIC
#if 0
#include <stdatomic.h>
#else

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

#endif
#endif
