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

#include "sysdep/unix/endian.h"
#include "lib/string.h"

static inline u8
get_u8(const void *p)
{
  return * (u8 *) p;
}

static inline u16
get_u16(const void *p)
{
  u16 x;
  memcpy(&x, p, 2);
  return ntohs(x);
}

static inline u32
get_u24(const void *P)
{
  const byte *p = P;
  return (p[0] << 16) + (p[1] << 8) + p[2];
}

static inline u32
get_u32(const void *p)
{
  u32 x;
  memcpy(&x, p, 4);
  return ntohl(x);
}

static inline u64
get_u64(const void *p)
{
  u32 xh, xl;
  memcpy(&xh, p, 4);
  memcpy(&xl, p+4, 4);
  return (((u64) ntohl(xh)) << 32) | ntohl(xl);
}

static inline void
put_u8(void *p, u8 x)
{
  memcpy(p, &x, 1);
}

static inline void
put_u16(void *p, u16 x)
{
  x = htons(x);
  memcpy(p, &x, 2);
}

static inline void
put_u24(void *p, u32 x)
{
  x = htonl(x);
  memcpy(p, ((char *) &x) + 1, 3);
}

static inline void
put_u32(void *p, u32 x)
{
  x = htonl(x);
  memcpy(p, &x, 4);
}

static inline void
put_u64(void *p, u64 x)
{
  u32 xh, xl;
  xh = htonl(x >> 32);
  xl = htonl((u32) x);
  memcpy(p, &xh, 4);
  memcpy(p+4, &xl, 4);
}

static inline void
get_u32s(const void *p, u32 *x, int n)
{
  int i;
  memcpy(x, p, 4*n);
  for (i = 0; i < n; i++)
    x[i] = ntohl(x[i]);
}

static inline void
put_u32s(void *p, const u32 *x, int n)
{
  int i;
  for (i = 0; i < n; i++)
    put_u32((byte *) p + 4*i, x[i]);
}


#endif
