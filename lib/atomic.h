#ifndef _BIRD_ATOMIC_H_
#define _BIRD_ATOMIC_H_

#if HAVE_ATOMIC
#include <stdatomic.h>
#else

#define _Atomic volatile

#define atomic_load(ptr) (*(ptr))
#define atomic_load_explicit(ptr, mem) (*(ptr))
#define atomic_store(ptr, val) (*(ptr) = (val))

#define atomic_fetch_add(ptr, val) __sync_fetch_and_add((ptr), (val))
#define atomic_fetch_add_explicit(ptr, val, memory) __sync_fetch_and_add((ptr), (val))
#define atomic_fetch_sub_explicit(ptr, val, memory) __sync_fetch_and_sub((ptr), (val))

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
