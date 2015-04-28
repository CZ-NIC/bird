/*
 *	BIRD Library -- SHA512 and SHA384 Hash Functions Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>

#include "test/birdtest.h"
#include "test/birdtest_support.h"
#include "sysdep/config.h"
#include "lib/sha512.h"
#include "lib/sha512.c" /* REMOVE ME */

static void
byte_to_hex(char *out, const byte *in, uint len)
{
  int i;
  for (i = 0; i < len; i++)
    sprintf(out + i*2, "%02x", in[i]);
}

static void
get_sha512(const char *str, char (*out_hash)[SHA512_HEX_SIZE])
{
  sha512_context ctx;
  sha512_init(&ctx);
  sha512_update(&ctx, str, strlen(str));
  byte *hash = sha512_final(&ctx);
  byte_to_hex((char*)out_hash, hash, SHA512_SIZE);
}

static void
get_sha384(const char *str, char (*out_hash)[SHA384_HEX_SIZE])
{
  sha384_context ctx;
  sha384_init(&ctx);
  sha384_update(&ctx, str, strlen(str));
  byte *hash = sha384_final(&ctx);
  byte_to_hex((char*)out_hash, hash, SHA384_SIZE);
}

static int
t_sha512(void)
{
  struct in_out {
    char *in;
    char out[SHA512_HEX_SIZE];
  } in_out[] = {
      {
	  .in  = "",
	  .out = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
      },
      {
	  .in  = "a",
	  .out = "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
      },
      {
	  .in  = "abc",
	  .out = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
      },
      {
	  .in  = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  .out = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
      },
      {
	  .in  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  .out = "86497b815f64702e2ac6aca1f1d16f7159b4f0b34f6e92a41e632982a7291465957e0ef171042b9630bb66c6e35051613f99bdc95c371eeb46bff8c897eba6e9",
      },
  };

  bt_assert_fn_in_out(get_sha512, in_out, "'%s'", "'%s'");

  return BT_SUCCESS;
}

static int
t_sha384(void)
{

  struct in_out {
    char *in;
    char out[SHA384_HEX_SIZE];
  } in_out[] = {
      {
	  .in  = "",
	  .out = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
      },
      {
	  .in  = "a",
	  .out = "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
      },
      {
	  .in  = "abc",
	  .out = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
      },
      {
	  .in  = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  .out = "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
      },
      {
	  .in  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  .out = "7b2cc66b0f621c1cb45c8dec93becf425d08f48d0e652154f8fffdde3ac7b1d2c6b19e9e507867301a3b604a8dafd3ba",
      },
  };

  bt_assert_fn_in_out(get_sha384, in_out, "'%s'", "'%s'");

  return BT_SUCCESS;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_sha512, "Testing SHA512");
  bt_test_suite(t_sha384, "Testing SHA384");

  return bt_end();
}
