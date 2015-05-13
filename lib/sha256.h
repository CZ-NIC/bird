/*
 *	BIRD -- SHA-256 and SHA-224 Hash Functions,
 *		HMAC-SHA-256 and HMAC-SHA-224 Functions
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Based on the code from libgcrypt-1.6.0, which is
 *	(c) 2003, 2006, 2008, 2009 Free Software Foundation, Inc.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SHA256_H_
#define _BIRD_SHA256_H_

#include "sysdep/config.h"

#define SHA224_SIZE 		28
#define SHA224_HEX_SIZE		57
#define SHA224_BLOCK_SIZE 	64

#define SHA256_SIZE 		32
#define SHA256_HEX_SIZE		65
#define SHA256_BLOCK_SIZE 	64

typedef unsigned int sha_transform_fn (void *c, const unsigned char *blks, size_t nblks);

typedef struct {
  u32  h0,h1,h2,h3,h4,h5,h6,h7;
  byte buf[128];			/* 128 is for SHA384 and SHA512 support, otherwise for SHA224 and SHA256 is 64 enough */
  u32 nblocks;
  u32 nblocks_high;
  int count;
  u32 blocksize;
  sha_transform_fn *transform;
} sha256_context;
typedef sha256_context sha224_context;

void sha256_init(sha256_context *ctx);
void sha224_init(sha224_context *ctx);

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

static unsigned int sha256_transform(void *ctx, const unsigned char *data, size_t nblks);

/**
 *	HMAC-SHA256, HMAC-SHA224
 */
typedef struct
{
  sha256_context ictx;
  sha256_context octx;
} sha256_hmac_context;
typedef sha256_hmac_context sha224_hmac_context;

void sha256_hmac_init(sha256_hmac_context *ctx, const byte *key, size_t keylen);
void sha224_hmac_init(sha224_hmac_context *ctx, const byte *key,  size_t keylen);

void sha256_hmac_update(sha256_hmac_context *ctx, const byte *buf, size_t buflen);
void sha224_hmac_update(sha224_hmac_context *ctx, const byte *buf, size_t buflen);

byte *sha256_hmac_final(sha256_hmac_context *ctx);
byte *sha224_hmac_final(sha224_hmac_context *ctx);

#endif /* _BIRD_SHA256_H_ */
