/*
 *	BIRD Library -- BLAKE2 Hash Functions
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

#ifndef _BIRD_BLAKE2_H_
#define _BIRD_BLAKE2_H_

#include "nest/bird.h"


enum blake2s_constant
{
  BLAKE2S_BLOCKBYTES		= 64,
  BLAKE2S_OUTBYTES		= 32,
  BLAKE2S_KEYBYTES		= 32,
  BLAKE2S_SALTBYTES		=  8,
  BLAKE2S_PERSONALBYTES		=  8,
};

enum blake2b_constant
{
  BLAKE2B_BLOCKBYTES		= 128,
  BLAKE2B_OUTBYTES		=  64,
  BLAKE2B_KEYBYTES		=  64,
  BLAKE2B_SALTBYTES		=  16,
  BLAKE2B_PERSONALBYTES		=  16,
};

#define BLAKE2S_SIZE		32  // BLAKE2S_OUTBYTES
#define BLAKE2S_BLOCK_SIZE	64  // BLAKE2S_BLOCKBYTES
#define BLAKE2S_256_SIZE	32

#define BLAKE2B_SIZE		64  // BLAKE2B_OUTBYTES
#define BLAKE2B_BLOCK_SIZE	128 // BLAKE2B_BLOCKBYTES
#define BLAKE2B_512_SIZE	64


struct blake2s_state
{
  u32 h[8];
  u32 t[2];
  u32 f[2];
  byte buf[BLAKE2S_BLOCK_SIZE];
  uint buflen;
  uint outlen;
  u8 last_node;
};

struct blake2b_state
{
  u64 h[8];
  u64 t[2];
  u64 f[2];
  byte buf[BLAKE2B_BLOCK_SIZE];
  uint buflen;
  uint outlen;
  u8 last_node;
};

struct blake2s_param
{
  u8  digest_length;	/* 1 */
  u8  key_length;	/* 2 */
  u8  fanout;		/* 3 */
  u8  depth;		/* 4 */
  u32 leaf_length;	/* 8 */
  u32 node_offset;	/* 12 */
  u16 xof_length;	/* 14 */
  u8  node_depth;	/* 15 */
  u8  inner_length;	/* 16 */
  /* byte  reserved[0]; */
  byte salt[BLAKE2S_SALTBYTES];		/* 24 */
  byte personal[BLAKE2S_PERSONALBYTES];	/* 32 */
} PACKED;

struct blake2b_param
{
  u8  digest_length;	/* 1 */
  u8  key_length;	/* 2 */
  u8  fanout;		/* 3 */
  u8  depth;		/* 4 */
  u32 leaf_length;	/* 8 */
  u32 node_offset;	/* 12 */
  u32 xof_length;	/* 16 */
  u8  node_depth;	/* 17 */
  u8  inner_length;	/* 18 */
  byte reserved[14];	/* 32 */
  byte salt[BLAKE2B_SALTBYTES];		/* 48 */
  byte personal[BLAKE2B_PERSONALBYTES];	/* 64 */
} PACKED;


/* Streaming API */
int blake2s_init(struct blake2s_state *s, size_t outlen);
int blake2s_init_key(struct blake2s_state *s, size_t outlen, const void *key, size_t keylen);
int blake2s_init_param(struct blake2s_state *s, const struct blake2s_param *p);
int blake2s_update(struct blake2s_state *s, const void *in, size_t inlen);
int blake2s_final(struct blake2s_state *s, void *out, size_t outlen);

int blake2b_init(struct blake2b_state *s, size_t outlen);
int blake2b_init_key(struct blake2b_state *s, size_t outlen, const void *key, size_t keylen);
int blake2b_init_param(struct blake2b_state *s, const struct blake2b_param *p);
int blake2b_update(struct blake2b_state *s, const void *in, size_t inlen);
int blake2b_final(struct blake2b_state *s, void *out, size_t outlen);


/* Wrapper functions for MAC class */

struct mac_desc;
struct mac_context;

struct blake2s_context {
  const struct mac_desc *type;
  struct blake2s_state state;
  byte buf[BLAKE2S_SIZE];
};

struct blake2b_context {
  const struct mac_desc *type;
  struct blake2b_state state;
  byte buf[BLAKE2B_SIZE];
};


void blake2s_mac_init(struct mac_context *ctx, const byte *key, uint keylen);
void blake2s_mac_update(struct mac_context *ctx, const byte *data, uint datalen);
byte *blake2s_mac_final(struct mac_context *ctx);

void blake2b_mac_init(struct mac_context *ctx, const byte *key, uint keylen);
void blake2b_mac_update(struct mac_context *ctx, const byte *data, uint datalen);
byte *blake2b_mac_final(struct mac_context *ctx);

#endif /* _BIRD_BLAKE2_H_ */
