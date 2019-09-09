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
 */

u32 u32_mkmask(uint n);
uint u32_masklen(u32 x);

u32 u32_log2(u32 v);

static inline u32 u32_hash(u32 v) { return v * 2902958171u; }

static inline u8 u32_popcount(u32 v) { return __builtin_popcount(v); }

static inline int u32_clz(u32 v) { return __builtin_clz(v); }
static inline int u32_ctz(u32 v) { return __builtin_ctz(v); }

static inline int uint_is_pow2(uint n) { return n && !(n & (n-1)); }

#endif
