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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "lib/sha256.h"
#include "lib/sha256.c"	/* REMOVE ME */
#include "lib/sha512.h"
#include "lib/unaligned.h"

#define U64_C(c) (c ## UL) /* Maybe is system dependent */

void
sha512_init(sha512_context *ctx)
{
  sha512_state *hd = &ctx->state;

  hd->h0 = U64_C(0x6a09e667f3bcc908);
  hd->h1 = U64_C(0xbb67ae8584caa73b);
  hd->h2 = U64_C(0x3c6ef372fe94f82b);
  hd->h3 = U64_C(0xa54ff53a5f1d36f1);
  hd->h4 = U64_C(0x510e527fade682d1);
  hd->h5 = U64_C(0x9b05688c2b3e6c1f);
  hd->h6 = U64_C(0x1f83d9abfb41bd6b);
  hd->h7 = U64_C(0x5be0cd19137e2179);

  ctx->bctx.nblocks = 0;
  ctx->bctx.nblocks_high = 0;
  ctx->bctx.count = 0;
  ctx->bctx.blocksize = 128;
  ctx->bctx.transform = sha512_transform;
}

void
sha384_init(sha384_context *ctx)
{
  sha512_state *hd = &ctx->state;

  hd->h0 = U64_C(0xcbbb9d5dc1059ed8);
  hd->h1 = U64_C(0x629a292a367cd507);
  hd->h2 = U64_C(0x9159015a3070dd17);
  hd->h3 = U64_C(0x152fecd8f70e5939);
  hd->h4 = U64_C(0x67332667ffc00b31);
  hd->h5 = U64_C(0x8eb44a8768581511);
  hd->h6 = U64_C(0xdb0c2e0d64f98fa7);
  hd->h7 = U64_C(0x47b5481dbefa4fa4);

  ctx->bctx.nblocks = 0;
  ctx->bctx.nblocks_high = 0;
  ctx->bctx.count = 0;
  ctx->bctx.blocksize = 128;
  ctx->bctx.transform = sha512_transform;
}

void sha512_update(sha512_context *ctx, const byte *in_buf, size_t in_len)
{
  sha256_update(&ctx->bctx, in_buf, in_len);
}

static inline u64
ROTR(u64 x, u64 n)
{
  return ((x >> n) | (x << (64 - n)));
}

static inline u64
Ch(u64 x, u64 y, u64 z)
{
  return ((x & y) ^ ( ~x & z));
}

static inline u64
Maj(u64 x, u64 y, u64 z)
{
  return ((x & y) ^ (x & z) ^ (y & z));
}

static inline u64
Sum0(u64 x)
{
  return (ROTR (x, 28) ^ ROTR (x, 34) ^ ROTR (x, 39));
}

static inline u64
Sum1 (u64 x)
{
  return (ROTR (x, 14) ^ ROTR (x, 18) ^ ROTR (x, 41));
}

static const u64 k[] =
{
    U64_C(0x428a2f98d728ae22), U64_C(0x7137449123ef65cd),
    U64_C(0xb5c0fbcfec4d3b2f), U64_C(0xe9b5dba58189dbbc),
    U64_C(0x3956c25bf348b538), U64_C(0x59f111f1b605d019),
    U64_C(0x923f82a4af194f9b), U64_C(0xab1c5ed5da6d8118),
    U64_C(0xd807aa98a3030242), U64_C(0x12835b0145706fbe),
    U64_C(0x243185be4ee4b28c), U64_C(0x550c7dc3d5ffb4e2),
    U64_C(0x72be5d74f27b896f), U64_C(0x80deb1fe3b1696b1),
    U64_C(0x9bdc06a725c71235), U64_C(0xc19bf174cf692694),
    U64_C(0xe49b69c19ef14ad2), U64_C(0xefbe4786384f25e3),
    U64_C(0x0fc19dc68b8cd5b5), U64_C(0x240ca1cc77ac9c65),
    U64_C(0x2de92c6f592b0275), U64_C(0x4a7484aa6ea6e483),
    U64_C(0x5cb0a9dcbd41fbd4), U64_C(0x76f988da831153b5),
    U64_C(0x983e5152ee66dfab), U64_C(0xa831c66d2db43210),
    U64_C(0xb00327c898fb213f), U64_C(0xbf597fc7beef0ee4),
    U64_C(0xc6e00bf33da88fc2), U64_C(0xd5a79147930aa725),
    U64_C(0x06ca6351e003826f), U64_C(0x142929670a0e6e70),
    U64_C(0x27b70a8546d22ffc), U64_C(0x2e1b21385c26c926),
    U64_C(0x4d2c6dfc5ac42aed), U64_C(0x53380d139d95b3df),
    U64_C(0x650a73548baf63de), U64_C(0x766a0abb3c77b2a8),
    U64_C(0x81c2c92e47edaee6), U64_C(0x92722c851482353b),
    U64_C(0xa2bfe8a14cf10364), U64_C(0xa81a664bbc423001),
    U64_C(0xc24b8b70d0f89791), U64_C(0xc76c51a30654be30),
    U64_C(0xd192e819d6ef5218), U64_C(0xd69906245565a910),
    U64_C(0xf40e35855771202a), U64_C(0x106aa07032bbd1b8),
    U64_C(0x19a4c116b8d2d0c8), U64_C(0x1e376c085141ab53),
    U64_C(0x2748774cdf8eeb99), U64_C(0x34b0bcb5e19b48a8),
    U64_C(0x391c0cb3c5c95a63), U64_C(0x4ed8aa4ae3418acb),
    U64_C(0x5b9cca4f7763e373), U64_C(0x682e6ff3d6b2b8a3),
    U64_C(0x748f82ee5defb2fc), U64_C(0x78a5636f43172f60),
    U64_C(0x84c87814a1f0ab72), U64_C(0x8cc702081a6439ec),
    U64_C(0x90befffa23631e28), U64_C(0xa4506cebde82bde9),
    U64_C(0xbef9a3f7b2c67915), U64_C(0xc67178f2e372532b),
    U64_C(0xca273eceea26619c), U64_C(0xd186b8c721c0c207),
    U64_C(0xeada7dd6cde0eb1e), U64_C(0xf57d4f7fee6ed178),
    U64_C(0x06f067aa72176fba), U64_C(0x0a637dc5a2c898a6),
    U64_C(0x113f9804bef90dae), U64_C(0x1b710b35131c471b),
    U64_C(0x28db77f523047d84), U64_C(0x32caab7b40c72493),
    U64_C(0x3c9ebe0a15c9bebc), U64_C(0x431d67c49c100d4c),
    U64_C(0x4cc5d4becb3e42b6), U64_C(0x597f299cfc657e2a),
    U64_C(0x5fcb6fab3ad6faec), U64_C(0x6c44198c4a475817)
};

/*
 * Transform the message W which consists of 16 64-bit-words
 */
static unsigned int
sha512_transform_block(sha512_state *hd, const byte *data)
{
  u64 a, b, c, d, e, f, g, h;
  u64 w[16];
  int t;

  /* get values from the chaining vars */
  a = hd->h0;
  b = hd->h1;
  c = hd->h2;
  d = hd->h3;
  e = hd->h4;
  f = hd->h5;
  g = hd->h6;
  h = hd->h7;

  for ( t = 0; t < 16; t++ )
    w[t] = get_u64(data + t * 8);

#define S0(x) (ROTR((x),1) ^ ROTR((x),8) ^ ((x)>>7))
#define S1(x) (ROTR((x),19) ^ ROTR((x),61) ^ ((x)>>6))

  for (t = 0; t < 80 - 16; )
  {
    u64 t1, t2;

    /* Performance on a AMD Athlon(tm) Dual Core Processor 4050e
         with gcc 4.3.3 using gcry_md_hash_buffer of each 10000 bytes
         initialized to 0,1,2,3...255,0,... and 1000 iterations:

         Not unrolled with macros:  440ms
         Unrolled with macros:      350ms
         Unrolled with inline:      330ms
     */
#if 0 /* Not unrolled.  */
    t1 = h + Sum1 (e) + Ch(e, f, g) + k[t] + w[t%16];
    w[t%16] += S1 (w[(t - 2)%16]) + w[(t - 7)%16] + S0 (w[(t - 15)%16]);
    t2 = Sum0 (a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
    t++;
#else /* Unrolled to interweave the chain variables.  */
    t1 = h + Sum1 (e) + Ch(e, f, g) + k[t] + w[0];
    w[0] += S1 (w[14]) + w[9] + S0 (w[1]);
    t2 = Sum0 (a) + Maj(a, b, c);
    d += t1;
    h = t1 + t2;

    t1 = g + Sum1 (d) + Ch(d, e, f) + k[t+1] + w[1];
    w[1] += S1 (w[15]) + w[10] + S0 (w[2]);
    t2 = Sum0 (h) + Maj(h, a, b);
    c += t1;
    g  = t1 + t2;

    t1 = f + Sum1 (c) + Ch(c, d, e) + k[t+2] + w[2];
    w[2] += S1 (w[0]) + w[11] + S0 (w[3]);
    t2 = Sum0 (g) + Maj(g, h, a);
    b += t1;
    f  = t1 + t2;

    t1 = e + Sum1 (b) + Ch(b, c, d) + k[t+3] + w[3];
    w[3] += S1 (w[1]) + w[12] + S0 (w[4]);
    t2 = Sum0 (f) + Maj(f, g, h);
    a += t1;
    e  = t1 + t2;

    t1 = d + Sum1 (a) + Ch(a, b, c) + k[t+4] + w[4];
    w[4] += S1 (w[2]) + w[13] + S0 (w[5]);
    t2 = Sum0 (e) + Maj(e, f, g);
    h += t1;
    d  = t1 + t2;

    t1 = c + Sum1 (h) + Ch(h, a, b) + k[t+5] + w[5];
    w[5] += S1 (w[3]) + w[14] + S0 (w[6]);
    t2 = Sum0 (d) + Maj(d, e, f);
    g += t1;
    c  = t1 + t2;

    t1 = b + Sum1 (g) + Ch(g, h, a) + k[t+6] + w[6];
    w[6] += S1 (w[4]) + w[15] + S0 (w[7]);
    t2 = Sum0 (c) + Maj(c, d, e);
    f += t1;
    b  = t1 + t2;

    t1 = a + Sum1 (f) + Ch(f, g, h) + k[t+7] + w[7];
    w[7] += S1 (w[5]) + w[0] + S0 (w[8]);
    t2 = Sum0 (b) + Maj(b, c, d);
    e += t1;
    a  = t1 + t2;

    t1 = h + Sum1 (e) + Ch(e, f, g) + k[t+8] + w[8];
    w[8] += S1 (w[6]) + w[1] + S0 (w[9]);
    t2 = Sum0 (a) + Maj(a, b, c);
    d += t1;
    h  = t1 + t2;

    t1 = g + Sum1 (d) + Ch(d, e, f) + k[t+9] + w[9];
    w[9] += S1 (w[7]) + w[2] + S0 (w[10]);
    t2 = Sum0 (h) + Maj(h, a, b);
    c += t1;
    g  = t1 + t2;

    t1 = f + Sum1 (c) + Ch(c, d, e) + k[t+10] + w[10];
    w[10] += S1 (w[8]) + w[3] + S0 (w[11]);
    t2 = Sum0 (g) + Maj(g, h, a);
    b += t1;
    f  = t1 + t2;

    t1 = e + Sum1 (b) + Ch(b, c, d) + k[t+11] + w[11];
    w[11] += S1 (w[9]) + w[4] + S0 (w[12]);
    t2 = Sum0 (f) + Maj(f, g, h);
    a += t1;
    e  = t1 + t2;

    t1 = d + Sum1 (a) + Ch(a, b, c) + k[t+12] + w[12];
    w[12] += S1 (w[10]) + w[5] + S0 (w[13]);
    t2 = Sum0 (e) + Maj(e, f, g);
    h += t1;
    d  = t1 + t2;

    t1 = c + Sum1 (h) + Ch(h, a, b) + k[t+13] + w[13];
    w[13] += S1 (w[11]) + w[6] + S0 (w[14]);
    t2 = Sum0 (d) + Maj(d, e, f);
    g += t1;
    c  = t1 + t2;

    t1 = b + Sum1 (g) + Ch(g, h, a) + k[t+14] + w[14];
    w[14] += S1 (w[12]) + w[7] + S0 (w[15]);
    t2 = Sum0 (c) + Maj(c, d, e);
    f += t1;
    b  = t1 + t2;

    t1 = a + Sum1 (f) + Ch(f, g, h) + k[t+15] + w[15];
    w[15] += S1 (w[13]) + w[8] + S0 (w[0]);
    t2 = Sum0 (b) + Maj(b, c, d);
    e += t1;
    a  = t1 + t2;

    t += 16;
#endif
  }

  for (; t < 80; )
  {
    u64 t1, t2;

#if 0 /* Not unrolled.  */
    t1 = h + Sum1 (e) + Ch(e, f, g) + k[t] + w[t%16];
    t2 = Sum0 (a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
    t++;
#else /* Unrolled to interweave the chain variables.  */
    t1 = h + Sum1 (e) + Ch(e, f, g) + k[t] + w[0];
    t2 = Sum0 (a) + Maj(a, b, c);
    d += t1;
    h  = t1 + t2;

    t1 = g + Sum1 (d) + Ch(d, e, f) + k[t+1] + w[1];
    t2 = Sum0 (h) + Maj(h, a, b);
    c += t1;
    g  = t1 + t2;

    t1 = f + Sum1 (c) + Ch(c, d, e) + k[t+2] + w[2];
    t2 = Sum0 (g) + Maj(g, h, a);
    b += t1;
    f  = t1 + t2;

    t1 = e + Sum1 (b) + Ch(b, c, d) + k[t+3] + w[3];
    t2 = Sum0 (f) + Maj(f, g, h);
    a += t1;
    e  = t1 + t2;

    t1 = d + Sum1 (a) + Ch(a, b, c) + k[t+4] + w[4];
    t2 = Sum0 (e) + Maj(e, f, g);
    h += t1;
    d  = t1 + t2;

    t1 = c + Sum1 (h) + Ch(h, a, b) + k[t+5] + w[5];
    t2 = Sum0 (d) + Maj(d, e, f);
    g += t1;
    c  = t1 + t2;

    t1 = b + Sum1 (g) + Ch(g, h, a) + k[t+6] + w[6];
    t2 = Sum0 (c) + Maj(c, d, e);
    f += t1;
    b  = t1 + t2;

    t1 = a + Sum1 (f) + Ch(f, g, h) + k[t+7] + w[7];
    t2 = Sum0 (b) + Maj(b, c, d);
    e += t1;
    a  = t1 + t2;

    t1 = h + Sum1 (e) + Ch(e, f, g) + k[t+8] + w[8];
    t2 = Sum0 (a) + Maj(a, b, c);
    d += t1;
    h  = t1 + t2;

    t1 = g + Sum1 (d) + Ch(d, e, f) + k[t+9] + w[9];
    t2 = Sum0 (h) + Maj(h, a, b);
    c += t1;
    g  = t1 + t2;

    t1 = f + Sum1 (c) + Ch(c, d, e) + k[t+10] + w[10];
    t2 = Sum0 (g) + Maj(g, h, a);
    b += t1;
    f  = t1 + t2;

    t1 = e + Sum1 (b) + Ch(b, c, d) + k[t+11] + w[11];
    t2 = Sum0 (f) + Maj(f, g, h);
    a += t1;
    e  = t1 + t2;

    t1 = d + Sum1 (a) + Ch(a, b, c) + k[t+12] + w[12];
    t2 = Sum0 (e) + Maj(e, f, g);
    h += t1;
    d  = t1 + t2;

    t1 = c + Sum1 (h) + Ch(h, a, b) + k[t+13] + w[13];
    t2 = Sum0 (d) + Maj(d, e, f);
    g += t1;
    c  = t1 + t2;

    t1 = b + Sum1 (g) + Ch(g, h, a) + k[t+14] + w[14];
    t2 = Sum0 (c) + Maj(c, d, e);
    f += t1;
    b  = t1 + t2;

    t1 = a + Sum1 (f) + Ch(f, g, h) + k[t+15] + w[15];
    t2 = Sum0 (b) + Maj(b, c, d);
    e += t1;
    a  = t1 + t2;

    t += 16;
#endif
  }

  /* Update chaining vars.  */
  hd->h0 += a;
  hd->h1 += b;
  hd->h2 += c;
  hd->h3 += d;
  hd->h4 += e;
  hd->h5 += f;
  hd->h6 += g;
  hd->h7 += h;

  return /* burn_stack */ (8 + 16) * sizeof(u64) + sizeof(u32) + 3 * sizeof(void*);
}

static unsigned int
sha512_transform(void *context, const byte *data, size_t nblks)
{
  sha512_context *ctx = context;
  unsigned int burn;

  do
  {
    burn = sha512_transform_block(&ctx->state, data) + 3 * sizeof(void*);
    data += 128;
  }
  while(--nblks);

  return burn;
}

/* The routine final terminates the computation and
 * returns the digest.
 * The handle is prepared for a new cycle, but adding bytes to the
 * handle will the destroy the returned buffer.
 * Returns: 64 bytes representing the digest.  When used for sha384,
 * we take the leftmost 48 of those bytes.
 */
byte *
sha512_final(sha512_context *ctx)
{
  u64 t, th, msb, lsb;
  byte *p;

  sha256_update(&ctx->bctx, NULL, 0); /* flush */ ;

  t = ctx->bctx.nblocks;
  /* if (sizeof t == sizeof ctx->bctx.nblocks) */
  th = ctx->bctx.nblocks_high;
  /* else */
  /*   th = ctx->bctx.nblocks >> 64; In case we ever use u128  */

  /* multiply by 128 to make a byte count */
  lsb = t << 7;
  msb = (th << 7) | (t >> 57);
  /* add the count */
  t = lsb;
  if ((lsb += ctx->bctx.count) < t)
    msb++;
  /* multiply by 8 to make a bit count */
  t = lsb;
  lsb <<= 3;
  msb <<= 3;
  msb |= t >> 61;

  if (ctx->bctx.count < 112)
  {						/* enough room */
    ctx->bctx.buf[ctx->bctx.count++] = 0x80;	/* pad */
    while(ctx->bctx.count < 112)
      ctx->bctx.buf[ctx->bctx.count++] = 0;	/* pad */
  }
  else
  {						/* need one extra block */
    ctx->bctx.buf[ctx->bctx.count++] = 0x80;	/* pad character */
    while(ctx->bctx.count < 128)
      ctx->bctx.buf[ctx->bctx.count++] = 0;
    sha256_update(&ctx->bctx, NULL, 0); 	/* flush */ ;
    memset(ctx->bctx.buf, 0, 112);		/* fill next block with zeroes */
  }
  /* append the 128 bit count */
  put_u64(ctx->bctx.buf + 112, msb);
  put_u64(ctx->bctx.buf + 120, lsb);
  sha512_transform(ctx, ctx->bctx.buf, 1);

  p = ctx->bctx.buf;
#define X(a) do { put_u64(p, ctx->state.h##a); p += 8; } while(0)
  X (0);
  X (1);
  X (2);
  X (3);
  X (4);
  X (5);
  /* Note that these last two chunks are included even for SHA384.
     We just ignore them. */
  X (6);
  X (7);
#undef X

  return ctx->bctx.buf;
}

/**
 * 	SHA512-HMAC
 */

static void
sha512_hash_buffer(byte *outbuf, const byte *buffer, size_t length)
{
  sha512_context hd_tmp;

  sha512_init(&hd_tmp);
  sha512_update(&hd_tmp, buffer, length);
  memcpy(outbuf, sha512_final(&hd_tmp), SHA512_SIZE);
}

void
sha512_hmac_init(sha512_hmac_context *ctx, const byte *key, size_t keylen)
{
  byte keybuf[SHA512_BLOCK_SIZE], buf[SHA512_BLOCK_SIZE];

  // Hash the key if necessary
  if (keylen <= SHA512_BLOCK_SIZE)
  {
    memcpy(keybuf, key, keylen);
    bzero(keybuf + keylen, SHA512_BLOCK_SIZE - keylen);
  }
  else
  {
    sha512_hash_buffer(keybuf, key, keylen);
    bzero(keybuf + SHA512_SIZE, SHA512_BLOCK_SIZE - SHA512_SIZE);
  }

  // Initialize the inner digest
  sha512_init(&ctx->ictx);
  int i;
  for (i = 0; i < SHA512_BLOCK_SIZE; i++)
    buf[i] = keybuf[i] ^ 0x36;
  sha512_update(&ctx->ictx, buf, SHA512_BLOCK_SIZE);

  // Initialize the outer digest
  sha512_init(&ctx->octx);
  for (i = 0; i < SHA512_BLOCK_SIZE; i++)
    buf[i] = keybuf[i] ^ 0x5c;
  sha512_update(&ctx->octx, buf, SHA512_BLOCK_SIZE);
}

void sha512_hmac_update(sha512_hmac_context *ctx, const byte *buf, size_t buflen)
{
  // Just update the inner digest
  sha512_update(&ctx->ictx, buf, buflen);
}

byte *sha512_hmac_final(sha512_hmac_context *ctx)
{
  // Finish the inner digest
  byte *isha = sha512_final(&ctx->ictx);

  // Finish the outer digest
  sha512_update(&ctx->octx, isha, SHA512_SIZE);
  return sha512_final(&ctx->octx);
}

/**
 * 	SHA384-HMAC
 */

static void
sha384_hash_buffer(byte *outbuf, const byte *buffer, size_t length)
{
  sha384_context hd_tmp;

  sha384_init(&hd_tmp);
  sha384_update(&hd_tmp, buffer, length);
  memcpy(outbuf, sha384_final(&hd_tmp), SHA384_SIZE);
}

void
sha384_hmac_init(sha384_hmac_context *ctx, const byte *key, size_t keylen)
{
  byte keybuf[SHA384_BLOCK_SIZE], buf[SHA384_BLOCK_SIZE];

  // Hash the key if necessary
  if (keylen <= SHA384_BLOCK_SIZE)
  {
    memcpy(keybuf, key, keylen);
    bzero(keybuf + keylen, SHA384_BLOCK_SIZE - keylen);
  }
  else
  {
    sha384_hash_buffer(keybuf, key, keylen);
    bzero(keybuf + SHA384_SIZE, SHA384_BLOCK_SIZE - SHA384_SIZE);
  }

  // Initialize the inner digest
  sha384_init(&ctx->ictx);
  int i;
  for (i = 0; i < SHA384_BLOCK_SIZE; i++)
    buf[i] = keybuf[i] ^ 0x36;
  sha384_update(&ctx->ictx, buf, SHA384_BLOCK_SIZE);

  // Initialize the outer digest
  sha384_init(&ctx->octx);
  for (i = 0; i < SHA384_BLOCK_SIZE; i++)
    buf[i] = keybuf[i] ^ 0x5c;
  sha384_update(&ctx->octx, buf, SHA384_BLOCK_SIZE);
}

void sha384_hmac_update(sha384_hmac_context *ctx, const byte *buf, size_t buflen)
{
  // Just update the inner digest
  sha384_update(&ctx->ictx, buf, buflen);
}

byte *sha384_hmac_final(sha384_hmac_context *ctx)
{
  // Finish the inner digest
  byte *isha = sha384_final(&ctx->ictx);

  // Finish the outer digest
  sha384_update(&ctx->octx, isha, SHA384_SIZE);
  return sha384_final(&ctx->octx);
}
