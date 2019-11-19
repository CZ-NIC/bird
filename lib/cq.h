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
#define CQ_PTRN_PREV(buf_, ptrn_) CQ_PTRN((buf_), ((ptrn_) + CQ_PTR_COUNT((buf_)) - 1) % CQ_PTR_COUNT((buf_)))

#define CQ_BUF_SIZE(buf_) (sizeof((buf_)->buffer) / sizeof((buf_)->buffer[0]))

#define CQ_ITEM(buf_, id_) (&(buf_)->buffer[(id_) % CQ_BUF_SIZE(buf_)])

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

#define CQ_PENDING_RELEASE_BIT	(((u64) 1) << 63)

#define CQ_ACQUIRE_TRY(buf_, ptrn_) ({ \
  /* Get local acquire index and adjacent release index */ \
  u64 acquire_ = atomic_load_explicit(&(CQ_PTRN((buf_), (ptrn_))->acquire), memory_order_acquire); \
  u64 adj_rel_ = 0; \
  u64 out_ = ~((u64) 0); \
  while (1) { \
    /* Outdated? */ \
    if (acquire_ > (adj_rel_ & ~CQ_PENDING_RELEASE_BIT)) \
      adj_rel_ = atomic_load_explicit(&(CQ_PTRN_PREV((buf_), (ptrn_))->release), memory_order_acquire); \
    /* Congested? */ \
    if ((acquire_ == (adj_rel_ & ~CQ_PENDING_RELEASE_BIT)) && \
	atomic_compare_exchange_strong_explicit( \
	  &(CQ_PTRN_PREV((buf_), (ptrn_))->release), &adj_rel_, adj_rel_ | CQ_PENDING_RELEASE_BIT, \
	  memory_order_acquire, memory_order_acq_rel)) \
	  break; \
    /* Try to acquire */ \
    if (atomic_compare_exchange_strong_explicit( \
	  &(CQ_PTRN((buf_), (ptrn_))->acquire), &acquire_, acquire_ + 1, \
	  memory_order_acquire, memory_order_acq_rel)) { \
	  out_ = acquire_; \
	  break; \
	  } \
  } \
  out_; \
})

#define CQ_RELEASE(buf_, ptrn_, id_) do { \
  /* Indicate that we're done */ \
  atomic_fetch_or_explicit(&(CQ_PTRN((buf_), (ptrn_))->mask[((id_) % CQ_BUF_SIZE((buf_))) / 64]), (((u64) 1) << ((id_) % 64)), memory_order_acq_rel); \
  while (1) { \
    /* First, get the release index */ \
    u64 release_ = atomic_load_explicit(&(CQ_PTRN((buf_), (ptrn_))->release), memory_order_acquire); \
    /* Get the first bits from mask */ \
    u64 mask_ = atomic_load_explicit(&(CQ_PTRN((buf_), (ptrn_))->mask[(release_ % CQ_BUF_SIZE((buf_))) / 64]), memory_order_acquire); \
    /* How many consecutive bits from release index up */ \
    u64 consec_ = mask_ >> (release_ % 64); \
    consec_ = (~consec_) ? u64_log2(consec_ ^ (consec_ + 1)) : 64; \
    /* No bits to release */ \
    if (!consec_) break; \
    /* Unmask these indices or retry */ \
    u64 unmask_ = (consec_ == 64) ? ~((u64) 0) : (((((u64) 1) << consec_) - 1) << (release_ % 64)); \
    if (!atomic_compare_exchange_strong_explicit( \
	  &(CQ_PTRN((buf_), (ptrn_))->mask[(release_ % CQ_BUF_SIZE((buf_))) / 64]), \
	  &mask_, mask_ & ~unmask_, \
	  memory_order_acquire, memory_order_acq_rel)) \
      continue; \
    u64 rel_tmp_ = release_; \
    if (!atomic_compare_exchange_strong_explicit( \
	  &(CQ_PTRN((buf_), (ptrn_))->release), &rel_tmp_, release_ + consec_, \
	  memory_order_acquire, memory_order_acq_rel) && \
	((rel_tmp_ != (release_ | CQ_PENDING_RELEASE_BIT)) || \
	  !atomic_compare_exchange_strong_explicit( \
	    &(CQ_PTRN((buf_), (ptrn_))->release), &rel_tmp_, release_ + consec_, \
	    memory_order_acquire, memory_order_acq_rel))) \
	bug("Invalid release value"); \
    if (!(rel_tmp_ & CQ_PENDING_RELEASE_BIT)) continue; \
    do

#define CQ_RELEASE_DONE() while (0); } } while (0)

#endif
