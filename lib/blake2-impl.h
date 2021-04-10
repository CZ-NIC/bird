/*
 *	BIRD Library -- BLAKE2 Support Code
 *
 *	Based on the code from BLAKE2 reference source code package
 *
 *	Copyright 2012, Samuel Neves <sneves@dei.uc.pt>
 *
 *	You may use this under the terms of the CC0, the OpenSSL Licence, or the
 *	Apache Public License 2.0, at your option.  The terms of these licenses
 *	can be found at:
 *
 *	- CC0 1.0 Universal : https://creativecommons.org/publicdomain/zero/1.0
 *	- OpenSSL license   : https://www.openssl.org/source/license.html
 *	- Apache 2.0        : https://www.apache.org/licenses/LICENSE-2.0
 *
 *  	More information about the BLAKE2 hash function can be found at
 *	https://blake2.net/ web.
 */

#ifndef _BIRD_BLAKE2_IMPL_H_
#define _BIRD_BLAKE2_IMPL_H_

#include "nest/bird.h"


static inline u32 load32(const void *src)
{
#if !defined(CPU_BIG_ENDIAN)
  u32 w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const u8 *p = (const u8 *) src;
  return ((u32) (p[0]) <<  0) |
         ((u32) (p[1]) <<  8) |
         ((u32) (p[2]) << 16) |
         ((u32) (p[3]) << 24) ;
#endif
}

static inline u64 load64(const void *src)
{
#if !defined(CPU_BIG_ENDIAN)
  u64 w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const u8 *p = (const u8 *) src;
  return ((u64) (p[0]) <<  0) |
         ((u64) (p[1]) <<  8) |
         ((u64) (p[2]) << 16) |
         ((u64) (p[3]) << 24) |
         ((u64) (p[4]) << 32) |
         ((u64) (p[5]) << 40) |
         ((u64) (p[6]) << 48) |
         ((u64) (p[7]) << 56) ;
#endif
}

static inline u16 load16(const void *src)
{
#if !defined(CPU_BIG_ENDIAN)
  u16 w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const u8 *p = (const u8 *) src;
  return (u16) (((u32) (p[0]) <<  0) |
                      ((u32) (p[1]) <<  8));
#endif
}

static inline void store16(void *dst, u16 w)
{
#if !defined(CPU_BIG_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  u8 *p = (u8 *) dst;
  *p++ = (u8)w; w >>= 8;
  *p++ = (u8)w;
#endif
}

static inline void store32(void *dst, u32 w)
{
#if !defined(CPU_BIG_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  u8 *p = (u8 *)dst;
  p[0] = (u8) (w >>  0);
  p[1] = (u8) (w >>  8);
  p[2] = (u8) (w >> 16);
  p[3] = (u8) (w >> 24);
#endif
}

static inline void store64(void *dst, u64 w)
{
#if !defined(CPU_BIG_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  u8 *p = (u8 *) dst;
  p[0] = (u8) (w >>  0);
  p[1] = (u8) (w >>  8);
  p[2] = (u8) (w >> 16);
  p[3] = (u8) (w >> 24);
  p[4] = (u8) (w >> 32);
  p[5] = (u8) (w >> 40);
  p[6] = (u8) (w >> 48);
  p[7] = (u8) (w >> 56);
#endif
}

static inline u64 load48(const void *src)
{
  const u8 *p = (const u8 *) src;
  return ((u64) (p[0]) <<  0) |
         ((u64) (p[1]) <<  8) |
         ((u64) (p[2]) << 16) |
         ((u64) (p[3]) << 24) |
         ((u64) (p[4]) << 32) |
         ((u64) (p[5]) << 40) ;
}

static inline void store48(void *dst, u64 w)
{
  u8 *p = (u8 *) dst;
  p[0] = (u8) (w >>  0);
  p[1] = (u8) (w >>  8);
  p[2] = (u8) (w >> 16);
  p[3] = (u8) (w >> 24);
  p[4] = (u8) (w >> 32);
  p[5] = (u8) (w >> 40);
}

static inline u32 rotr32(const u32 w, const uint c)
{
  return (w >> c) | (w << (32 - c));
}

static inline u64 rotr64(const u64 w, const uint c)
{
  return (w >> c) | (w << (64 - c));
}

/* prevents compiler optimizing out memset() */
static inline void secure_zero_memory(void *v, size_t n)
{
  static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
  memset_v(v, 0, n);
}

#endif
