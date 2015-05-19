/*
 *	BIRD -- SHA-512 and SHA-384 Hash Functions,
 *		HMAC-SHA-512 and HMAC-SHA-384 Functions
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Based on the code from libgcrypt-1.6.0, which is
 *	(c) 2003, 2006, 2008, 2009 Free Software Foundation, Inc.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SHA512_H_
#define _BIRD_SHA512_H_

#include "sysdep/config.h"
#include "lib/sha256.h"

#define SHA384_SIZE 		48
#define SHA384_HEX_SIZE		97
#define SHA384_BLOCK_SIZE	128

#define SHA512_SIZE 		64
#define SHA512_HEX_SIZE		129
#define SHA512_BLOCK_SIZE	128

typedef struct
{
  u64 h0, h1, h2, h3, h4, h5, h6, h7;
} sha512_state;

typedef struct
{
  sha256_context bctx;
  sha512_state state;
} sha512_context;
typedef sha512_context sha384_context;


void sha512_init(sha512_context *ctx);
void sha384_init(sha384_context *ctx);

void sha512_update(sha512_context *ctx, const byte *in_buf, size_t in_len);
void sha384_update(sha384_context *ctx, const byte *in_buf, size_t in_len)
{
  sha512_update(ctx, in_buf, in_len);
}

byte* sha512_final(sha512_context *ctx);
byte* sha384_final(sha384_context *ctx)
{
  return sha512_final(ctx);
}

static unsigned int sha512_transform(void *context, const byte *data, size_t nblks);

/**
 *	HMAC-SHA512, HMAC-SHA384
 */
typedef struct
{
  sha512_context ictx;
  sha512_context octx;
} sha512_hmac_context;
typedef sha512_hmac_context sha384_hmac_context;

void sha512_hmac_init(sha512_hmac_context *ctx, const byte *key, size_t keylen);
void sha384_hmac_init(sha384_hmac_context *ctx, const byte *key, size_t keylen);

void sha512_hmac_update(sha512_hmac_context *ctx, const byte *buf, size_t buflen);
void sha384_hmac_update(sha384_hmac_context *ctx, const byte *buf, size_t buflen);

byte *sha512_hmac_final(sha512_hmac_context *ctx);
byte *sha384_hmac_final(sha384_hmac_context *ctx);

#endif /* _BIRD_SHA512_H_ */
