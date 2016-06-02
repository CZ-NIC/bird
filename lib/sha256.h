/*
 *	BIRD Library -- SHA-256 and SHA-224 Hash Functions,
 *			HMAC-SHA-256 and HMAC-SHA-224 Functions
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

#include "nest/bird.h"


#define SHA224_SIZE 		28
#define SHA224_HEX_SIZE		57
#define SHA224_BLOCK_SIZE 	64

#define SHA256_SIZE 		32
#define SHA256_HEX_SIZE		65
#define SHA256_BLOCK_SIZE 	64


struct sha256_context {
  u32  h0, h1, h2, h3, h4, h5, h6, h7;
  byte buf[SHA256_BLOCK_SIZE];
  uint nblocks;
  uint count;
};

#define sha224_context sha256_context


void sha256_init(struct sha256_context *ctx);
void sha224_init(struct sha224_context *ctx);

void sha256_update(struct sha256_context *ctx, const byte *buf, size_t len);
static inline void sha224_update(struct sha224_context *ctx, const byte *buf, size_t len)
{ sha256_update(ctx, buf, len); }

byte *sha256_final(struct sha256_context *ctx);
static inline byte *sha224_final(struct sha224_context *ctx)
{ return sha256_final(ctx); }


/*
 *	HMAC-SHA256, HMAC-SHA224
 */

struct sha256_hmac_context
{
  struct sha256_context ictx;
  struct sha256_context octx;
};

#define sha224_hmac_context sha256_hmac_context


void sha256_hmac_init(struct sha256_hmac_context *ctx, const byte *key, size_t keylen);
void sha224_hmac_init(struct sha224_hmac_context *ctx, const byte *key, size_t keylen);

void sha256_hmac_update(struct sha256_hmac_context *ctx, const byte *buf, size_t buflen);
void sha224_hmac_update(struct sha224_hmac_context *ctx, const byte *buf, size_t buflen);

byte *sha256_hmac_final(struct sha256_hmac_context *ctx);
byte *sha224_hmac_final(struct sha224_hmac_context *ctx);


#endif /* _BIRD_SHA256_H_ */
