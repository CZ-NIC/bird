/*
 *	BIRD Library -- Atomic pointer-based circular buffer
 *
 *	(c) 2019 Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_CQ_H_
#define _BIRD_CQ_H_

#include "lib/atomic.h"
#include "lib/worker.h"

#define CQ_PTR(size_) struct { \
  _Atomic u64 acquire, release; \
  _Atomic u64 mask[(size_ + 63) / 64]; \
}

#define CQ_N(type_, size_, ptrs_) struct { \
  type_ buffer[size_]; \
  CQ_PTR(size_) ptr[ptrs_]; \
}

#define CQ(type_, size_) CQ_N(type_, size_, 2)

#define CQ_PTR_COUNT(buf_) sizeof((buf_)->ptr) / sizeof((buf_)->ptr[0])

#define CQ_INIT(buf_, pool_) do { \
  memset((buf_)->buffer, 0, sizeof((buf_)->buffer)); \
  for (uint i_=0; i_<CQ_PTR_COUNT((buf_)); i_++) \
    (buf_)->ptr[i_].acquire = (buf_)->ptr[i_].release = ATOMIC_VAR_INIT(0); \
} while (0)

#define CQ_CLEANUP(buf_) do { \
  u64 val = atomic_load(&((buf_)->ptr[0].acquire)); \
  for (uint i_=0; i_<CQ_PTR_COUNT((buf_)); i_++) { \
    ASSERT(val == atomic_load(&((buf_)->ptr[i_].acquire))); \
    ASSERT(val == atomic_load(&((buf_)->ptr[i_].release))); \
  } \
} while (0)

#define CQ_ACQUIRE_TRY(buf_,

#endif
