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

#include "sysdep/config.h"
#include "lib/null.h"
#include "lib/unaligned.h"
#include "lib/sha256_hmac.h"

/* Bitwise rotation of an unsigned int to the right */
static inline u32 ror(u32 x, int n)
{
  return ( (x >> (n&(32-1))) | (x << ((32-n)&(32-1))) );
}

#define my_wipememory2(_ptr,_set,_len) do { \
    volatile char *_vptr=(volatile char *)(_ptr); \
    size_t _vlen=(_len); \
    while(_vlen) { *_vptr=(_set); _vptr++; _vlen--; } \
} while(0)
#define my_wipememory(_ptr,_len) my_wipememory2(_ptr,0,_len)

/*
    The SHA-256 core: Transform the message X which consists of 16
    32-bit-words. See FIPS 180-2 for details.
 */
static void
transform(sha256_hmac_context *hd, const void *data_arg)
{
  const unsigned char *data = data_arg;

#define Cho(x,y,z) (z ^ (x & (y ^ z)))      /* (4.2) same as SHA-1's F1 */
#define Maj(x,y,z) ((x & y) | (z & (x|y)))  /* (4.3) same as SHA-1's F3 */
#define Sum0(x) (ror((x), 2) ^ ror((x), 13) ^ ror((x), 22))  /* (4.4) */
#define Sum1(x) (ror((x), 6) ^ ror((x), 11) ^ ror((x), 25))  /* (4.5) */
#define S0(x) (ror((x), 7) ^ ror((x), 18) ^ ((x) >> 3))       /* (4.6) */
#define S1(x) (ror((x), 17) ^ ror((x), 19) ^ ((x) >> 10))     /* (4.7) */
#define R(a,b,c,d,e,f,g,h,k,w) do                       \
    {                                                   \
  t1 = (h) + Sum1((e)) + Cho((e),(f),(g)) + (k) + (w);  \
  t2 = Sum0((a)) + Maj((a),(b),(c));                    \
  h = g;                                                \
  g = f;                                                \
  f = e;                                                \
  e = d + t1;                                           \
  d = c;                                                \
  c = b;                                                \
  b = a;                                                \
  a = t1 + t2;                                          \
    } while(0)

  static const u32 K[64] =
  {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };

  u32 a, b, c, d, e, f, g, h, t1, t2;
  u32 x[16];
  u32 w[64];
  int i;

  a = hd->h0;
  b = hd->h1;
  c = hd->h2;
  d = hd->h3;
  e = hd->h4;
  f = hd->h5;
  g = hd->h6;
  h = hd->h7;

#ifdef WORDS_BIGENDIAN
  memcpy(x, data, 64);
#else /*!WORDS_BIGENDIAN*/
  {
    unsigned char *p2;

    for(i=0, p2=(unsigned char*)x; i < 16; i++, p2 += 4 )
    {
      p2[3] = *data++;
      p2[2] = *data++;
      p2[1] = *data++;
      p2[0] = *data++;
    }
  }
#endif /*!WORDS_BIGENDIAN*/

  for(i=0; i < 16; i++)
    w[i] = x[i];
  for(; i < 64; i++)
    w[i] = S1(w[i-2]) + w[i-7] + S0(w[i-15]) + w[i-16];

  for(i=0; i < 64; i++)
    R(a,b,c,d,e,f,g,h,K[i],w[i]);

  hd->h0 += a;
  hd->h1 += b;
  hd->h2 += c;
  hd->h3 += d;
  hd->h4 += e;
  hd->h5 += f;
  hd->h6 += g;
  hd->h7 += h;
}
#undef Cho
#undef Maj
#undef Sum0
#undef Sum1
#undef S0
#undef S1
#undef R

/*  Finalize the current SHA256 calculation.  */
static void
finalize(sha256_hmac_context *hd)
{
  u32 t, msb, lsb;
  unsigned char *p;

  if (hd->finalized)
    return; /* Silently ignore a finalized context.  */

  sha256_hmac_update(hd, NULL, 0); /* Flush.  */

  t = hd->nblocks;
  /* Multiply by 64 to make a byte count. */
  lsb = t << 6;
  msb = t >> 26;
  /* Add the count. */
  t = lsb;
  if ((lsb += hd->count) < t)
    msb++;
  /* Multiply by 8 to make a bit count. */
  t = lsb;
  lsb <<= 3;
  msb <<= 3;
  msb |= t >> 29;

  if (hd->count < 56)
  { /* Enough room.  */
    hd->buf[hd->count++] = 0x80; /* pad */
    while(hd->count < 56)
      hd->buf[hd->count++] = 0;  /* pad */
  }
  else
  { /* Need one extra block. */
    hd->buf[hd->count++] = 0x80; /* pad character */
    while(hd->count < 64)
      hd->buf[hd->count++] = 0;
    sha256_hmac_update(hd, NULL, 0);  /* Flush.  */;
    memset(hd->buf, 0, 56 ); /* Zero out next next block.  */
  }
  /* Append the 64 bit count. */
  hd->buf[56] = msb >> 24;
  hd->buf[57] = msb >> 16;
  hd->buf[58] = msb >>  8;
  hd->buf[59] = msb;
  hd->buf[60] = lsb >> 24;
  hd->buf[61] = lsb >> 16;
  hd->buf[62] = lsb >>  8;
  hd->buf[63] = lsb;
  transform(hd, hd->buf);

  /* Store the digest into hd->buf.  */
  p = hd->buf;
#define X(a) do { *p++ = hd->h##a >> 24; *p++ = hd->h##a >> 16;	 \
    *p++ = hd->h##a >> 8; *p++ = hd->h##a; } while(0)
  X(0);
  X(1);
  X(2);
  X(3);
  X(4);
  X(5);
  X(6);
  X(7);
#undef X
  hd->finalized = 1;
}

/* Create a new context.  On error NULL is returned and errno is set
   appropriately.  If KEY is given the function computes HMAC using
   this key; with KEY given as NULL, a plain SHA-256 digest is
   computed.  */
void
sha256_hmac_init(sha256_hmac_context *ctx, const void *key, size_t keylen)
{
  ctx->h0 = 0x6a09e667;
  ctx->h1 = 0xbb67ae85;
  ctx->h2 = 0x3c6ef372;
  ctx->h3 = 0xa54ff53a;
  ctx->h4 = 0x510e527f;
  ctx->h5 = 0x9b05688c;
  ctx->h6 = 0x1f83d9ab;
  ctx->h7 = 0x5be0cd19;
  ctx->nblocks = 0;
  ctx->count = 0;
  ctx->finalized = 0;
  ctx->use_hmac = 0;

  if (key)
  {
    int i;
    unsigned char ipad[64];

    memset(ipad, 0, 64);
    memset(ctx->opad, 0, 64);
    if (keylen <= 64)
    {
      memcpy(ipad, key, keylen);
      memcpy(ctx->opad, key, keylen);
    }
    else
    {
      sha256_hmac_context tmp_ctx;

      sha256_hmac_init(&tmp_ctx, NULL, 0);
      sha256_hmac_update(&tmp_ctx, key, keylen);
      finalize(&tmp_ctx);
      memcpy(ipad, tmp_ctx.buf, 32);
      memcpy(ctx->opad, tmp_ctx.buf, 32);
    }
    for(i=0; i < 64; i++)
    {
      ipad[i] ^= 0x36;
      ctx->opad[i] ^= 0x5c;
    }
    ctx->use_hmac = 1;
    sha256_hmac_update(ctx, ipad, 64);
    my_wipememory(ipad, 64);
  }
}

/* Update the message digest with the contents of BUFFER containing
   LENGTH bytes.  */
void
sha256_hmac_update(sha256_hmac_context *ctx, const void *buffer, size_t length)
{
  const unsigned char *inbuf = buffer;

  if (ctx->finalized)
    return; /* Silently ignore a finalized context.  */

  if (ctx->count == 64)
  {
    /* Flush the buffer. */
    transform(ctx, ctx->buf);
    ctx->count = 0;
    ctx->nblocks++;
  }
  if (!inbuf)
    return;  /* Only flushing was requested. */
  if (ctx->count)
  {
    for(; length && ctx->count < 64; length--)
      ctx->buf[ctx->count++] = *inbuf++;
    sha256_hmac_update(ctx, NULL, 0); /* Flush.  */
    if (!length)
      return;
  }

  while(length >= 64)
  {
    transform(ctx, inbuf);
    ctx->count = 0;
    ctx->nblocks++;
    length -= 64;
    inbuf += 64;
  }
  for(; length && ctx->count < 64; length--)
    ctx->buf[ctx->count++] = *inbuf++;
}

/* Finalize an operation and return the digest.  If R_DLEN is not NULL
   the length of the digest will be stored at that address.  The
   returned value is valid as long as the context exists.  On error
   NULL is returned. */
const byte *
sha256_hmac_final(sha256_hmac_context *ctx)
{
  finalize(ctx);
  if (ctx->use_hmac)
  {
    sha256_hmac_context tmp_ctx;

    sha256_hmac_init(&tmp_ctx, NULL, 0);
    sha256_hmac_update(&tmp_ctx, ctx->opad, 64);
    sha256_hmac_update(&tmp_ctx, ctx->buf, 32);
    finalize(&tmp_ctx);
    memcpy(ctx->buf, tmp_ctx.buf, 32);
  }
  return ctx->buf;
}
