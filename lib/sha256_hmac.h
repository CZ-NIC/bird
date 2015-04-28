/*
 *	BIRD -- HMAC-SHA256 Message Authentication
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Based on the code from libgcrypt-1.6.0, which is
 *	(c) 2003, 2006, 2008, 2009 Free Software Foundation, Inc.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SHA256_HMAC_H_
#define _BIRD_SHA256_HMAC_H_

#define SHA256_SIZE 		32
#define SHA256_HEX_SIZE		65

#define SHA224_SIZE 		28
#define SHA224_HEX_SIZE		57

/* The context used by this module.  */
typedef struct
{
  u32  h0, h1, h2, h3, h4, h5, h6, h7;
  u32  nblocks;
  int  count;
  int  finalized:1;
  int  use_hmac:1;
  byte buf[64];
  byte opad[64];
} sha256_hmac_context;

void sha256_hmac_init(sha256_hmac_context *ctx, const void *key, size_t keylen);
void sha256_hmac_update(sha256_hmac_context *ctx, const void *buf, size_t buflen);
const byte *sha256_hmac_final(sha256_hmac_context *ctx);

#endif /* _BIRD_SHA256_HMAC_H_ */
