/*
 *	BIRD Library -- MD5 Hash Function and HMAC-MD5 Function
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

struct md5_context
{
  u32 buf[4];
  u32 bits[2];
  byte in[64];
};

void md5_init(struct md5_context *context);
void md5_update(struct md5_context *context, byte const *buf, uint len);
byte *md5_final(struct md5_context *context);

/*
 *	HMAC-MD5
 */
struct md5_hmac_context
{
  struct md5_context ictx;
  struct md5_context octx;
};

void md5_hmac_init(struct md5_hmac_context *ctx, const byte *key, size_t keylen);
void md5_hmac_update(struct md5_hmac_context *ctx, const byte *buf, size_t buflen);
byte *md5_hmac_final(struct md5_hmac_context *ctx);

#endif /* _BIRD_MD5_H_ */
