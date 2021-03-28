/*
 *	BIRD -- The BGP Monitoring Protocol (BMP)
 *
 *	(c) 2020 Akamai Technologies, Inc. (Pawel Maslanka, pmaslank@akamai.com)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_BMP_BUFFER_H_
#define _BIRD_BMP_BUFFER_H_

#include "proto/bmp/bmp.h"

#include <stdlib.h>

#include "lib/resource.h"

buffer
bmp_buffer_alloc(pool *ppool, const size_t n);

void
bmp_buffer_free(buffer *buf);

static inline void
bmp_buffer_flush(buffer *buf)
{
  buf->pos = buf->start;
}

static inline size_t
bmp_buffer_size(const buffer *buf)
{
  return buf->end - buf->start;
}

static inline size_t
bmp_buffer_avail(const buffer *buf)
{
  return buf->end - buf->pos;
}

static inline size_t
bmp_buffer_pos(const buffer *buf)
{
  return buf->pos - buf->start;
}

static inline byte *
bmp_buffer_data(const buffer *buf)
{
  return buf->start;
}

void
bmp_buffer_need(buffer *buf, const size_t n);

// Idea for following macros has been taken from |proto/mrt/mrt.c|
#define BMP_DEFINE_PUT_FUNC(S, T)                               \
  static inline void                                            \
  bmp_put_##S(buffer *b, const T x)                             \
  {                                                             \
    bmp_buffer_need(b, sizeof(T));                              \
    put_##S(b->pos, x);                                    \
    b->pos += sizeof(T);                                   \
  }

BMP_DEFINE_PUT_FUNC(u8, u8)
BMP_DEFINE_PUT_FUNC(u16, u16)
BMP_DEFINE_PUT_FUNC(u32, u32)
BMP_DEFINE_PUT_FUNC(u64, u64)
BMP_DEFINE_PUT_FUNC(ip4, ip4_addr)
BMP_DEFINE_PUT_FUNC(ip6, ip6_addr)

void
bmp_put_data(buffer *buf, const void *src, const size_t n);

#endif /* _BIRD_BMP_BUFFER_H_ */
