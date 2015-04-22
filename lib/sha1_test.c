/*
 *	BIRD Library -- SHA-1 Hash Function Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>

#include "test/birdtest.h"
#include "sysdep/config.h"
#include "lib/sha1.h"
#include "lib/sha1.c" /* REMOVE ME */

static void
get_sha1(const char *str, char (*out_hash)[SHA1_HEX_SIZE])
{
  sha1_context ctx;
  sha1_init(&ctx);
  sha1_update(&ctx, str, strlen(str));
  byte *hash = sha1_final(&ctx);

  int i;
  for(i = 0; i < SHA1_SIZE; i++)
    sprintf(*out_hash + i*2, "%02x", hash[i]);
}

static int
t_sha1(void)
{
  struct in_out {
    char *in;
    char out[SHA1_HEX_SIZE];
  } in_out[] = {
      {
	  .in  = "",
	  .out = "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      },
      {
	  .in  = "a",
	  .out = "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
      },
      {
	  .in  = "abc",
	  .out = "a9993e364706816aba3e25717850c26c9cd0d89d",
      },
      {
	  .in  = "message digest",
	  .out = "c12252ceda8be8994d5fa0290a47231c1d16aae3",
      },
      {
	  .in  = "abcdefghijklmnopqrstuvwxyz",
	  .out = "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
      },
      {
	  .in  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	  .out = "761c457bf73b14d27e9e9265c46f4b4dda11f940",
      },
      {
	  .in  = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	  .out = "50abf5706a150990a08b2c5ea40fa0e585554732",
      },
  };

  bt_assert_fn_in_out(get_sha1, in_out, "'%s'", "'%s'");

  return BT_SUCCESS;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_sha1, "Test Suite by RFC 1321 (it is for MD5)");

  return bt_end();
}
