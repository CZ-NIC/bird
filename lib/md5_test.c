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
#define HEX_BASE 16

static void
get_md5(unsigned char hash[MD5_BYTES], unsigned char const *str)
{
  struct MD5Context ctxt;

  MD5Init(&ctxt);
  MD5Update(&ctxt, str, strlen(str));
  MD5Final(hash, &ctxt);
}

static void
show_hash(unsigned char hash[MD5_BYTES])
{
  int i;
  for(i = 0; i < 16; i++)
    bt_debug("%02X", hash[i]);
}

static int
check_md5_hash(unsigned char const *str, unsigned char const *expected)
{
  unsigned char computed_hash[MD5_BYTES];
  unsigned char expected_hash[MD5_BYTES];
  int i;

  for(i = 0; i < 16; i++)
  {
    char * pEnd;
    unsigned char c[3] = {expected[i*2], expected[i*2 + 1], '\0'};
    expected_hash[i] = strtoul(c, &pEnd, HEX_BASE);
  }

  get_md5(computed_hash, str);

  bt_debug("MD5('%s') \n", str);
  bt_debug("  computed: ");
  show_hash(computed_hash);
  bt_debug("\n");
  bt_debug("  expected: ");
  show_hash(expected_hash);

  for(i = 0; i < 16; i++)
  {
    if(computed_hash[i] != expected_hash[i])
    {
      bt_debug("  FAIL! \n");
      bt_abort_msg("MD5('%s') should get '%s'", str, expected);
    }
  }
  bt_debug("  OK \n");
}

static int
t_md5(void)
{
  check_md5_hash("", "d41d8cd98f00b204e9800998ecf8427e");
  check_md5_hash("a", "0cc175b9c0f1b6a831c399e269772661");
  check_md5_hash("abc", "900150983cd24fb0d6963f7d28e17f72");
  check_md5_hash("message digest", "f96b697d7cb7938d525a2f31aaf161d0");
  check_md5_hash("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b");
  check_md5_hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f");
  check_md5_hash("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a");

  return BT_SUCCESS;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_case(t_md5, "Test Suite from RFC1321");

  return 0;
}
