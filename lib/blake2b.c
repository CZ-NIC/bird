/*
 *	BIRD Library -- BLAKE2b Hash Function
 *
 *	Based on the code from BLAKE2 reference source code package
 *
 *	Copyright 2012, Samuel Neves <sneves@dei.uc.pt>
 *
 *	You may use this under the terms of the CC0, the OpenSSL Licence, or the
 *	Apache Public License 2.0, at your option.  The terms of these licenses
 *	can be found at:
 *
 *	- CC0 1.0 Universal : https://creativecommons.org/publicdomain/zero/1.0
 *	- OpenSSL license   : https://www.openssl.org/source/license.html
 *	- Apache 2.0        : https://www.apache.org/licenses/LICENSE-2.0
 *
 *  	More information about the BLAKE2 hash function can be found at
 *	https://blake2.net/ web.
 */

#include "lib/mac.h"
#include "lib/blake2.h"
#include "lib/blake2-impl.h"


static const u64 blake2b_IV[8] =
{
  U64(0x6a09e667f3bcc908),
  U64(0xbb67ae8584caa73b),
  U64(0x3c6ef372fe94f82b),
  U64(0xa54ff53a5f1d36f1),
  U64(0x510e527fade682d1),
  U64(0x9b05688c2b3e6c1f),
  U64(0x1f83d9abfb41bd6b),
  U64(0x5be0cd19137e2179)
};

static const u8 blake2b_sigma[12][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
};

STATIC_ASSERT(sizeof(struct blake2b_param) == BLAKE2B_OUTBYTES);


static inline void
blake2b_set_lastnode(struct blake2b_state *s)
{
  s->f[1] = (u64) -1;
}

/* Some helper functions, not necessarily useful */
static inline int
blake2b_is_lastblock(const struct blake2b_state *s)
{
  return s->f[0] != 0;
}

static inline void
blake2b_set_lastblock(struct blake2b_state *s)
{
  if (s->last_node)
    blake2b_set_lastnode(s);

  s->f[0] = (u64) -1;
}

static inline void
blake2b_increment_counter(struct blake2b_state *s, const u64 inc)
{
  s->t[0] += inc;
  s->t[1] += (s->t[0] < inc);
}

static void
blake2b_init0(struct blake2b_state *s)
{
  memset(s, 0, sizeof(struct blake2b_state));

  for (uint i = 0; i < 8; ++i)
    s->h[i] = blake2b_IV[i];
}

/* init xors IV with input parameter block */
int
blake2b_init_param(struct blake2b_state *s, const struct blake2b_param *p)
{
  const byte *pb = (const void *) p;

  blake2b_init0(s);

  /* IV XOR ParamBlock */
  for (uint i = 0; i < 8; ++i)
    s->h[i] ^= load64(pb + sizeof(s->h[i]) * i);

  s->outlen = p->digest_length;

  return 0;
}


int
blake2b_init(struct blake2b_state *s, size_t outlen)
{
  struct blake2b_param p[1];

  if (!outlen || (outlen > BLAKE2B_OUTBYTES))
    return -1;

  p->digest_length = (uint8_t) outlen;
  p->key_length    = 0;
  p->fanout        = 1;
  p->depth         = 1;
  store32(&p->leaf_length, 0);
  store32(&p->node_offset, 0);
  store32(&p->xof_length, 0);
  p->node_depth    = 0;
  p->inner_length  = 0;
  memset(p->reserved, 0, sizeof(p->reserved));
  memset(p->salt,     0, sizeof(p->salt));
  memset(p->personal, 0, sizeof(p->personal));

  return blake2b_init_param(s, p);
}


int
blake2b_init_key(struct blake2b_state *s, size_t outlen, const void *key, size_t keylen)
{
  struct blake2b_param p[1];

  if (!outlen || (outlen > BLAKE2B_OUTBYTES))
    return -1;

  if (!key || !keylen || (keylen > BLAKE2B_KEYBYTES))
    return -1;

  p->digest_length = (uint8_t) outlen;
  p->key_length    = (uint8_t) keylen;
  p->fanout        = 1;
  p->depth         = 1;
  store32(&p->leaf_length, 0);
  store32(&p->node_offset, 0);
  store32(&p->xof_length, 0);
  p->node_depth    = 0;
  p->inner_length  = 0;
  memset(p->reserved, 0, sizeof(p->reserved));
  memset(p->salt,     0, sizeof(p->salt));
  memset(p->personal, 0, sizeof(p->personal));

  if (blake2b_init_param(s, p) < 0)
    return -1;

  {
    byte block[BLAKE2B_BLOCKBYTES];
    memset(block, 0, BLAKE2B_BLOCKBYTES);
    memcpy(block, key, keylen);
    blake2b_update(s, block, BLAKE2B_BLOCKBYTES);
    secure_zero_memory(block, BLAKE2B_BLOCKBYTES); /* Burn the key from stack */
  }

  return 0;
}

#define G(r,i,a,b,c,d)                      \
  do {                                      \
    a = a + b + m[blake2b_sigma[r][2*i+0]]; \
    d = rotr64(d ^ a, 32);                  \
    c = c + d;                              \
    b = rotr64(b ^ c, 24);                  \
    a = a + b + m[blake2b_sigma[r][2*i+1]]; \
    d = rotr64(d ^ a, 16);                  \
    c = c + d;                              \
    b = rotr64(b ^ c, 63);                  \
  } while(0)

#define ROUND(r)                    \
  do {                              \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
  } while(0)

static void
blake2b_compress(struct blake2b_state *s, const byte block[BLAKE2B_BLOCKBYTES])
{
  u64 m[16];
  u64 v[16];
  uint i;

  for (i = 0; i < 16; ++i)
    m[i] = load64(block + i * sizeof(m[i]));

  for (i = 0; i < 8; ++i)
    v[i] = s->h[i];

  v[ 8] = blake2b_IV[0];
  v[ 9] = blake2b_IV[1];
  v[10] = blake2b_IV[2];
  v[11] = blake2b_IV[3];
  v[12] = blake2b_IV[4] ^ s->t[0];
  v[13] = blake2b_IV[5] ^ s->t[1];
  v[14] = blake2b_IV[6] ^ s->f[0];
  v[15] = blake2b_IV[7] ^ s->f[1];

  ROUND(0);
  ROUND(1);
  ROUND(2);
  ROUND(3);
  ROUND(4);
  ROUND(5);
  ROUND(6);
  ROUND(7);
  ROUND(8);
  ROUND(9);
  ROUND(10);
  ROUND(11);

  for (i = 0; i < 8; ++i)
    s->h[i] = s->h[i] ^ v[i] ^ v[i + 8];
}

#undef G
#undef ROUND

int
blake2b_update(struct blake2b_state *s, const void *pin, size_t inlen)
{
  const byte *in = pin;

  if (inlen > 0)
  {
    size_t left = s->buflen;
    size_t fill = BLAKE2B_BLOCKBYTES - left;

    if (inlen > fill)
    {
      s->buflen = 0;
      memcpy(s->buf + left, in, fill); /* Fill buffer */
      blake2b_increment_counter(s, BLAKE2B_BLOCKBYTES);
      blake2b_compress(s, s->buf); /* Compress */
      in += fill; inlen -= fill;

      while (inlen > BLAKE2B_BLOCKBYTES)
      {
        blake2b_increment_counter(s, BLAKE2B_BLOCKBYTES);
        blake2b_compress(s, in);
        in += BLAKE2B_BLOCKBYTES;
        inlen -= BLAKE2B_BLOCKBYTES;
      }
    }

    memcpy(s->buf + s->buflen, in, inlen);
    s->buflen += inlen;
  }

  return 0;
}

int
blake2b_final(struct blake2b_state *s, void *out, size_t outlen)
{
  byte buffer[BLAKE2B_OUTBYTES] = {0};

  if (!out || (outlen < s->outlen))
    return -1;

  if (blake2b_is_lastblock(s))
    return -1;

  blake2b_increment_counter(s, s->buflen);
  blake2b_set_lastblock(s);
  memset(s->buf + s->buflen, 0, BLAKE2B_BLOCKBYTES - s->buflen); /* Padding */
  blake2b_compress(s, s->buf);

  /* Output full hash to temp buffer */
  for (uint i = 0; i < 8; ++i)
    store64(buffer + sizeof(s->h[i]) * i, s->h[i]);

  memcpy(out, buffer, s->outlen);
  secure_zero_memory(buffer, sizeof(buffer));

  return 0;
}


void
blake2b_mac_init(struct mac_context *mac, const byte *key, uint keylen)
{
  struct blake2b_context *ctx = (void *) mac;
  blake2b_init_key(&ctx->state, mac_get_length(mac), key, keylen);
}

void
blake2b_mac_update(struct mac_context *mac, const byte *buf, uint len)
{
  struct blake2b_context *ctx = (void *) mac;
  blake2b_update(&ctx->state, buf, len);
}

byte *
blake2b_mac_final(struct mac_context *mac)
{
  struct blake2b_context *ctx = (void *) mac;
  blake2b_final(&ctx->state, ctx->buf, mac_get_length(mac));
  return ctx->buf;
}
