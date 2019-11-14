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

#define CQ_PTR_COUNT(buf_) (sizeof((buf_)->ptr) / sizeof((buf_)->ptr[0]))
#define CQ_PTRN(buf_, ptrn_) (&(buf_)->ptr[ptrn_])

#define CQ_BUF_SIZE(buf_) (sizeof((buf_)->buffer) / sizeof((buf_)->buffer[0]))

#define CQ_INIT(buf_, pool_) do { \
  memset((buf_)->buffer, 0, sizeof((buf_)->buffer)); \
  for (uint i_=0; i_<CQ_PTR_COUNT((buf_)); i_++) \
    CQ_PTRN((buf_), i_)->acquire = CQ_PTRN((buf_), i_)->release = ATOMIC_VAR_INIT(0); \
} while (0)

#define CQ_CLEANUP(buf_) do { \
  u64 val = atomic_load(&((buf_)->ptr[0].acquire)); \
  for (uint i_=0; i_<CQ_PTR_COUNT((buf_)); i_++) { \
    ASSERT(val == atomic_load(&(CQ_PTRN((buf_), i_)->acquire))); \
    ASSERT(val == atomic_load(&(CQ_PTRN((buf_), i_)->release))); \
  } \
} while (0)

#define CQ_RELEASE(buf_, ptrn_, id_, released_) do { \
  released_ = 0; \
  /* Indicate that we're done */ \
  atomic_fetch_or_explicit(&(CQ_PTRN((buf_), (ptrn_))->mask[((id_) % CQ_BUF_SIZE((buf_))) / 64]), (((u64) 1) << ((id_) % 64)), memory_order_acq_rel); \
  /* First, check the release index */ \
  for (u64 release_; (release_ = atomic_load_explicit(&(CQ_PTRN((buf_), (ptrn_))->release), memory_order_acq_rel)) <= (id_); ) { \
    /* Get the first bits from mask */ \
    u64 mask_ = atomic_load_explicit(&(CQ_PTRN((buf_), (ptrn_))->mask[(release_ % CQ_BUF_SIZE((buf_))) / 64]), memory_order_acquire) >> (release_ % 64); \
    /* How many consecutive bits from release index up */ \
    u64 consec = (~mask_) ? u64_log2(mask_ ^ (mask_ + 1)) : 64; \
    if (!consec) \
      break; \
    /* Release what is to be released */ \
    u64 unmask_ = (~mask_) ? : ~(((mask_ ^ (mask_ + 1)) >> 1) << (release_ % 64)); \
    if (!atomic_compare_exchange_strong_explicit( \
	  &(CQ_PTRN((buf_), (ptrn_))->mask[(release_ % CQ_BUF_SIZE((buf_))) / 64]), \
	  &mask_, mask_ & unmask_, \
	  memory_order_acquire, memory_order_acq_rel)) \
      continue; \
    if (!atomic_compare_exchange_strong_explicit( \
	  &(CQ_PTRN((buf_), (ptrn_))->release), &release_, release_ + consec, \
	  memory_order_acquire, memory_order_acq_rel)) \
      bug("Invalid release value"); \
    released_ += consec; \
  } \
} while (0)


#endif
