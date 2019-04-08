/*
 *	BIRD Library -- Generic Bit Operations
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_BITOPTS_H_
#define _BIRD_BITOPTS_H_

#include "sysdep/config.h"

/*
 *	Bit mask operations:
 *
 *	u32_mkmask	Make bit mask consisting of <n> consecutive ones
 *			from the left and the rest filled with zeroes.
 *			E.g., u32_mkmask(5) = 0xf8000000.
 *	u32_masklen	Inverse operation to u32_mkmask, -1 if not a bitmask.
 *
 *	u32_log2
 *	u64_log2	Find the first 1 in the number
 *
 *	u32_hash	Compute a common hash
 *
 *	u64_var_encode	Encode a variable-length bitstring into fixed-length u64
 *	u64_var_decode	Decode the bitstring
 */

u32 u32_mkmask(uint n);
uint u32_masklen(u32 x);

u32 u32_log2(u32 v);
u64 u64_log2(u64 v);

static inline u32 u32_hash(u32 v) { return v * 2902958171u; }

static inline u8 u32_popcount(u32 v) { return __builtin_popcount(v); }

static inline u64 u64_var_encode(u64 data, uint padlen)
{
  ASSERT(padlen > 0);

  /* Append the other bit than the last */
  if (data & 1)
    return data << padlen;
  else
    return (data << padlen) | ((1ULL << padlen) - 1);
}

static inline u64 u64_var_decode(u64 enc, uint *padlen)
{
  /* If enc is ....|100..00, then cpl is ....|011..11
   * If enc is ....|011..11, then cpl is ....|100..00
   *
   * In both cases, enc ^ cpl is then 0...0|111..11
   * so u64_log2((enc ^ cpl) + 1) is the number of bits to shift right.
   * */
  u64 cpl = (enc & 1) ? (enc + 1) : (enc - 1);
  if ((~enc == 0) || (~cpl == 0)) {
    *padlen = 64;
    return 0;
  } else {
    *padlen = u64_log2(enc ^ cpl);
    return enc >> *padlen;
  }
}

#endif
