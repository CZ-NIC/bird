/*
 *	BIRD -- SHA256 and SHA224 Hash Functions
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Based on the code from libgcrypt-1.6.0, which is
 *	(c) 2003, 2006, 2008, 2009 Free Software Foundation, Inc.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SHA256_H
#define _BIRD_SHA256_H

#define SHA256_SIZE 		32
#define SHA256_HEX_SIZE		65

#define SHA224_SIZE 		28
#define SHA224_HEX_SIZE		57

typedef struct {
  u32  h0,h1,h2,h3,h4,h5,h6,h7;
  byte buf[64];
  u32 nblocks;
  u32 nblocks_high;
  int count;
} sha256_context;
typedef sha256_context sha224_context;

void sha256_init(sha256_context *ctx);
void sha256_init(sha224_context *ctx);

void sha256_update(sha256_context *ctx, const byte *in_buf, size_t in_len);
void sha224_update(sha224_context *ctx, const byte *in_buf, size_t in_len)
{
  sha256_update(ctx, in_buf, in_len);
}

byte* sha256_final(sha256_context *ctx);
byte* sha224_final(sha224_context *ctx)
{
  return sha256_final(ctx);
}

#endif
