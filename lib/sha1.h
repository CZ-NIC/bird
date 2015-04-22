/*
 *	BIRD -- SHA-1 Hash Function (FIPS 180-1, RFC 3174)
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Based on the code from libucw-6.4
 *	(c) 2008--2009 Martin Mares <mj@ucw.cz>
 *
 *	Based on the code from libgcrypt-1.2.3, which is
 *	(c) 1998, 2001, 2002, 2003 Free Software Foundation, Inc.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SHA1_H
#define _BIRD_SHA1_H

#include "sysdep/config.h"

/**
 * Internal SHA1 state.
 * You should use it just as an opaque handle only.
 */
typedef struct {
  u32 h0,h1,h2,h3,h4;
  u32 nblocks;
  byte buf[64];
  int count;
} sha1_context;

void sha1_init(sha1_context *hd); /** Initialize new algorithm run in the @hd context. **/
/**
 * Push another @inlen bytes of data pointed to by @inbuf onto the
 * SHA1 hash currently in @hd. You can call this any times you want on
 * the same hash (and you do not need to reinitialize it by
 * @sha1_init()). It has the same effect as concatenating all the data
 * together and passing them at once.
 */
void sha1_update(sha1_context *hd, const byte *inbuf, uint inlen);
/**
 * No more @sha1_update() calls will be done. This terminates the hash
 * and returns a pointer to it.
 *
 * Note that the pointer points into data in the @hd context. If it ceases
 * to exist, the pointer becomes invalid.
 *
 * To convert the hash to its usual hexadecimal representation, see
 * <<string:mem_to_hex()>>.
 */
byte *sha1_final(sha1_context *hd);

/**
 * A convenience one-shot function for SHA1 hash.
 * It is equivalent to this snippet of code:
 *
 *  sha1_context hd;
 *  sha1_init(&hd);
 *  sha1_update(&hd, buffer, length);
 *  memcpy(outbuf, sha1_final(&hd), SHA1_SIZE);
 */
void sha1_hash_buffer(byte *outbuf, const byte *buffer, uint length);

/**
 * SHA1 HMAC message authentication. If you provide @key and @data,
 * the result will be stored in @outbuf.
 */
void sha1_hmac(byte *outbuf, const byte *key, uint keylen, const byte *data, uint datalen);

/**
 * The HMAC also exists in a stream version in a way analogous to the
 * plain SHA1. Pass this as a context.
 */
typedef struct {
  sha1_context ictx;
  sha1_context octx;
} sha1_hmac_context;

void sha1_hmac_init(sha1_hmac_context *hd, const byte *key, uint keylen);	/** Initialize HMAC with context @hd and the given key. See sha1_init(). */
void sha1_hmac_update(sha1_hmac_context *hd, const byte *data, uint datalen);	/** Hash another @datalen bytes of data. See sha1_update(). */
byte *sha1_hmac_final(sha1_hmac_context *hd);					/** Terminate the HMAC and return a pointer to the allocated hash. See sha1_final(). */

#define SHA1_SIZE 20 /** Size of the SHA1 hash in its binary representation **/
#define SHA1_HEX_SIZE 41 /** Buffer length for a string containing SHA1 in hexadecimal format. **/
#define SHA1_BLOCK_SIZE 64 /** SHA1 splits input to blocks of this size. **/

#endif
