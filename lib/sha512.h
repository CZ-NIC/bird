/*
 *	BIRD Library -- SHA-512 and SHA-384 Hash Functions,
 *			HMAC-SHA-512 and HMAC-SHA-384 Functions
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

#include "nest/bird.h"


#define SHA384_SIZE 		48
#define SHA384_HEX_SIZE		97
#define SHA384_BLOCK_SIZE	128

#define SHA512_SIZE 		64
#define SHA512_HEX_SIZE		129
#define SHA512_BLOCK_SIZE	128


struct sha512_context {
  u64 h0, h1, h2, h3, h4, h5, h6, h7;
  byte buf[SHA512_BLOCK_SIZE];
  uint nblocks;
  uint count;
};

#define sha384_context sha512_context


void sha512_init(struct sha512_context *ctx);
void sha384_init(struct sha384_context *ctx);

void sha512_update(struct sha512_context *ctx, const byte *buf, size_t len);
static inline void sha384_update(struct sha384_context *ctx, const byte *buf, size_t len)
{ sha512_update(ctx, buf, len); }

byte *sha512_final(struct sha512_context *ctx);
static inline byte *sha384_final(struct sha384_context *ctx)
{ return sha512_final(ctx); }


/*
 *	HMAC-SHA512, HMAC-SHA384
 */

struct sha512_hmac_context
{
  struct sha512_context ictx;
  struct sha512_context octx;
};

#define sha384_hmac_context sha512_hmac_context


void sha512_hmac_init(struct sha512_hmac_context *ctx, const byte *key, size_t keylen);
void sha384_hmac_init(struct sha384_hmac_context *ctx, const byte *key, size_t keylen);

void sha512_hmac_update(struct sha512_hmac_context *ctx, const byte *buf, size_t buflen);
void sha384_hmac_update(struct sha384_hmac_context *ctx, const byte *buf, size_t buflen);

byte *sha512_hmac_final(struct sha512_hmac_context *ctx);
byte *sha384_hmac_final(struct sha384_hmac_context *ctx);


#endif /* _BIRD_SHA512_H_ */
