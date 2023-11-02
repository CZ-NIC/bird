/*
 *	BIRD -- The BGP Monitoring Protocol (BMP)
 *
 *	(c) 2020 Akamai Technologies, Inc. (Pawel Maslanka, pmaslank@akamai.com)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "proto/bmp/buffer.h"

buffer
bmp_buffer_alloc(pool *ppool, const size_t n)
{
  buffer buf;
  buf.start = mb_alloc(ppool, n);
  buf.pos = buf.start;
  buf.end = buf.start + n;
  return buf;
}

void
bmp_buffer_free(buffer *buf)
{
  mb_free(buf->start);
  buf->start = buf->pos = buf->end = NULL;
}

/**
 * @brief bmp_buffer_grow
 * @param buf - buffer to grow
 * @param n   - required amount of available space
 * Resize buffer in a way that there is at least @n bytes of available space.
 */
static void
bmp_buffer_grow(buffer *buf, const size_t n)
{
  size_t pos = bmp_buffer_pos(buf);
  size_t size = bmp_buffer_size(buf);
  size_t req = pos + n;

  while (size < req)
    size = size * 3 / 2;

  buf->start = mb_realloc(buf->start, size);
  buf->pos = buf->start + pos;
  buf->end = buf->start + size;
}

void
bmp_buffer_need(buffer *buf, const size_t n)
{
  if (bmp_buffer_avail(buf) < n)
    bmp_buffer_grow(buf, n);
}

void
bmp_put_data(buffer *buf, const void *src, const size_t n)
{
  if (!n)
    return;

  bmp_buffer_need(buf, n);
  memcpy(buf->pos, src, n);
  buf->pos += n;
}
