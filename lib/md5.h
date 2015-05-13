/*
 *	BIRD -- MD5 Hash Function and HMAC-MD5 Function
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Adapted for BIRD by Martin Mares <mj@atrey.karlin.mff.cuni.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_MD5_H_
#define _BIRD_MD5_H_

#define MD5_SIZE	16
#define MD5_HEX_SIZE	33
#define MD5_BLOCK_SIZE	64

typedef struct
{
  u32 buf[4];
  u32 bits[2];
  unsigned char in[64];
} md5_context;

void md5_init(md5_context *context);
void md5_update(md5_context *context, unsigned char const *buf, unsigned len);
byte *md5_final(md5_context *context);

void md5_transform(u32 buf[4], u32 const in[16]);

/**
 *	HMAC-MD5
 */
typedef struct
{
  md5_context ictx;
  md5_context octx;
} md5_hmac_context;

void md5_hmac_init(md5_hmac_context *ctx, const byte *key, size_t keylen);
void md5_hmac_update(md5_hmac_context *ctx, const byte *buf, size_t buflen);
byte *md5_hmac_final(md5_hmac_context *ctx);

#endif /* _BIRD_MD5_H_ */
