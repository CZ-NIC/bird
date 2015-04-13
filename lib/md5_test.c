/*
 *	BIRD Library -- MD5 message-digest algorithm Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>

#include "test/birdtest.h"
#include "sysdep/config.h"
#include "lib/md5.h"
#include "lib/md5.c" /* REMOVE ME */

#define MD5_BYTES 16
#define MD5_CHARS 32

static void
get_md5(unsigned char hash[MD5_BYTES], unsigned char const *str)
{
  struct MD5Context ctxt;

  MD5Init(&ctxt);
  MD5Update(&ctxt, str, strlen(str));
  MD5Final(hash, &ctxt);
}

static void
compute_md5(const char *str, char (*out_hash)[MD5_CHARS+1])
{
  unsigned char hash[MD5_BYTES];
  get_md5(hash, str);

  int i;
  for(i = 0; i < MD5_BYTES; i++)
    sprintf(*out_hash + i*2, "%02x", hash[i]);
}

static int
t_md5(void)
{
  struct in_out_data_ {
    char *in;
    char out[MD5_CHARS+1];
    char fn_out[MD5_CHARS+1];
  } in_out_data[] = {
      {
	  .in  = "",
	  .out = "d41d8cd98f00b204e9800998ecf8427e",
      },
      {
	  .in  = "",
	  .out = "d41d8cd98f00b204e9800998ecf8427e",
      },
      {
	  .in  = "a",
	  .out = "0cc175b9c0f1b6a831c399e269772661",
      },
      {
	  .in  = "abc",
	  .out = "900150983cd24fb0d6963f7d28e17f72",
      },
      {
	  .in  = "message digest",
	  .out = "f96b697d7cb7938d525a2f31aaf161d0",
      },
      {
	  .in  = "abcdefghijklmnopqrstuvwxyz",
	  .out = "c3fcd3d76192e4007dfb496cca67e13b",
      },
      {
	  .in  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	  .out = "d174ab98d277d9f5a5611c2c9f419d9f",
      },
      {
	  .in  = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	  .out = "57edf4a22be3c955ac49da2e2107b67a",
      },
  };

  bt_assert_fn_in_out(compute_md5, in_out_data, "\"%s\"", "\"%s\"");

  return BT_SUCCESS;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_md5, "Test Suite from RFC1321");

  return bt_end();
}
