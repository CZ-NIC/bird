/*
 *	Unaligned Data Accesses -- Generic Version, Network Order
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_UNALIGNED_H_
#define _BIRD_UNALIGNED_H_

/*
 *  We don't do any clever tricks with unaligned accesses since it's
 *  virtually impossible to figure out what alignment does the CPU want
 *  (unaligned accesses can be emulated by the OS which makes them work,
 *  but unusably slow). We use memcpy and hope GCC will optimize it out
 *  if possible.
 */

#include "lib/string.h"
#include <netinet/in.h>

static inline u16
get_u16(void *p)
{
  u16 x;
  memcpy(&x, p, 2);
  return ntohs(x);
}

static inline u32
get_u32(void *p)
{
  u32 x;
  memcpy(&x, p, 4);
  return ntohl(x);
}

static inline void
put_u16(void *p, u16 x)
{
  x = htons(x);
  memcpy(p, &x, 2);
}

static inline void
put_u32(void *p, u32 x)
{
  x = htonl(x);
  memcpy(p, &x, 4);
}

/* Big endian format */

#if defined(CPU_BIG_ENDIAN)
static inline uint get_u16_be(const void *p) { return *(u16 *)p; }	/** Read 16-bit integer value from an unaligned sequence of 2 bytes (big-endian version). **/
static inline u32 get_u32_be(const void *p) { return *(u32 *)p; }	/** Read 32-bit integer value from an unaligned sequence of 4 bytes (big-endian version). **/
static inline u64 get_u64_be(const void *p) { return *(u64 *)p; }	/** Read 64-bit integer value from an unaligned sequence of 8 bytes (big-endian version). **/
static inline void put_u16_be(void *p, uint x) { *(u16 *)p = x; }	/** Write 16-bit integer value to an unaligned sequence of 2 bytes (big-endian version). **/
static inline void put_u32_be(void *p, u32 x) { *(u32 *)p = x; }	/** Write 32-bit integer value to an unaligned sequence of 4 bytes (big-endian version). **/
static inline void put_u64_be(void *p, u64 x) { *(u64 *)p = x; }	/** Write 64-bit integer value to an unaligned sequence of 8 bytes (big-endian version). **/
#else
static inline uint get_u16_be(const void *p)
{
  const byte *c = (const byte *)p;
  return (c[0] << 8) | c[1];
}
static inline u32 get_u32_be(const void *p)
{
  const byte *c = (const byte *)p;
  return (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}
static inline u64 get_u64_be(const void *p)
{
  return ((u64) get_u32_be(p) << 32) | get_u32_be((const byte *)p+4);
}
static inline void put_u16_be(void *p, uint x)
{
  byte *c = (byte *)p;
  c[0] = x >> 8;
  c[1] = x;
}
static inline void put_u32_be(void *p, u32 x)
{
  byte *c = (byte *)p;
  c[0] = x >> 24;
  c[1] = x >> 16;
  c[2] = x >> 8;
  c[3] = x;
}
static inline void put_u64_be(void *p, u64 x)
{
  put_u32_be(p, x >> 32);
  put_u32_be((byte *)p+4, x);
}
#endif

#endif
