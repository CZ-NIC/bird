/*
 *	BIRD -- HMAC-SHA1 Message Authentication (RFC 2202)
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

#include "lib/sha1.h"
#include "lib/unaligned.h"

#include <string.h>

void
sha1_hmac_init(sha1_hmac_context *hd, const byte *key, uint keylen)
{
  byte keybuf[SHA1_BLOCK_SIZE], buf[SHA1_BLOCK_SIZE];

  // Hash the key if necessary
  if (keylen <= SHA1_BLOCK_SIZE)
  {
    memcpy(keybuf, key, keylen);
    bzero(keybuf + keylen, SHA1_BLOCK_SIZE - keylen);
  }
  else
  {
    sha1_hash_buffer(keybuf, key, keylen);
    bzero(keybuf + SHA1_SIZE, SHA1_BLOCK_SIZE - SHA1_SIZE);
  }

  // Initialize the inner digest
  sha1_init(&hd->ictx);
  int i;
  for (i = 0; i < SHA1_BLOCK_SIZE; i++)
    buf[i] = keybuf[i] ^ 0x36;
  sha1_update(&hd->ictx, buf, SHA1_BLOCK_SIZE);

  // Initialize the outer digest
  sha1_init(&hd->octx);
  for (i = 0; i < SHA1_BLOCK_SIZE; i++)
    buf[i] = keybuf[i] ^ 0x5c;
  sha1_update(&hd->octx, buf, SHA1_BLOCK_SIZE);
}

void
sha1_hmac_update(sha1_hmac_context *hd, const byte *data, uint datalen)
{
  // Just update the inner digest
  sha1_update(&hd->ictx, data, datalen);
}

byte *sha1_hmac_final(sha1_hmac_context *hd)
{
  // Finish the inner digest
  byte *isha = sha1_final(&hd->ictx);

  // Finish the outer digest
  sha1_update(&hd->octx, isha, SHA1_SIZE);
  return sha1_final(&hd->octx);
}

void
sha1_hmac(byte *outbuf, const byte *key, uint keylen, const byte *data, uint datalen)
{
  sha1_hmac_context hd;
  sha1_hmac_init(&hd, key, keylen);
  sha1_hmac_update(&hd, data, datalen);
  byte *osha = sha1_hmac_final(&hd);
  memcpy(outbuf, osha, SHA1_SIZE);
}
