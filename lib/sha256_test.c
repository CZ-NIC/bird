/*
 *	BIRD Library -- SHA256 and SHA224 Hash Functions Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>

#include "test/birdtest.h"
#include "test/birdtest_support.h"
#include "sysdep/config.h"
#include "lib/sha256.h"
#include "lib/sha256.c" /* REMOVE ME */


static void
byte_to_hex(char *out, const byte *in, uint len)
{
  int i;
  for(i = 0; i < len; i++)
    sprintf(out + i*2, "%02x", in[i]);
}

static void
get_sha256(const char *str, char (*out_hash)[SHA256_HEX_SIZE])
{
  sha256_context ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, str, strlen(str));
  byte *hash = sha256_final(&ctx);
  byte_to_hex((char*)out_hash, hash, SHA256_SIZE);
}

static void
get_sha224(const char *str, char (*out_hash)[SHA256_HEX_SIZE])
{
  sha224_context ctx;
  sha224_init(&ctx);
  sha224_update(&ctx, str, strlen(str));
  byte *hash = sha224_final(&ctx);
  byte_to_hex((char*)out_hash, hash, SHA224_SIZE);
}

static int
t_sha256(void)
{
  struct in_out {
    char *in;
    char out[SHA256_HEX_SIZE];
  } in_out[] = {
      {
	  .in  = "",
	  .out = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      {
	  .in  = "a",
	  .out = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
      },
      {
	  .in  = "abc",
	  .out = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      },
      {
	  .in  = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  .out = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
      },
      {
	  .in  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  .out = "970d31b428de8fea74b16484d8a8adb2c9e1bd974d7c621fd04332bc3499f117",
      },
  };

  bt_assert_fn_in_out(get_sha256, in_out, "'%s'", "'%s'");

  return BT_SUCCESS;
}

static int
t_sha224(void)
{
  struct in_out {
    char *in;
    char out[SHA256_HEX_SIZE];
  } in_out[] = {
      {
	  .in  = "",
	  .out = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
      },
      {
	  .in  = "a",
	  .out = "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
      },
      {
	  .in  = "abc",
	  .out = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
      },
      {
	  .in  = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  .out = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
      },
      {
	  .in  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  .out = "8a75b49f36c174693ee51a3f47c845d327dea06eab343cc15e975adf",
      },

  };

  bt_assert_fn_in_out(get_sha224, in_out, "'%s'", "'%s'");

  return BT_SUCCESS;
}

static int
t_sha256_concating(void)
{
  char hash_a[SHA256_HEX_SIZE];
  char hash_b[SHA256_HEX_SIZE];

  char *str_a  = "a" "bb" "ccc" "dddd" "eeeee" "ffffff";
  char *str_b1 = "a"                                   ;
  char *str_b2 =     "bb"                              ;
  char *str_b3 =          "ccc"                        ;
  char *str_b4 =                "dddd"                 ;
  char *str_b5 =                       "eeeee"         ;
  char *str_b6 =                               "ffffff";

  sha256_context ctx_a;
  sha256_init(&ctx_a);
  sha256_update(&ctx_a, str_a, strlen(str_a));
  byte *hash_a_ = sha256_final(&ctx_a);
  byte_to_hex(hash_a, hash_a_, SHA256_SIZE);

  sha256_context ctx_b;
  sha256_init(&ctx_b);
  sha256_update(&ctx_b, str_b1, strlen(str_b1));
  sha256_update(&ctx_b, str_b2, strlen(str_b2));
  sha256_update(&ctx_b, str_b3, strlen(str_b3));
  sha256_update(&ctx_b, str_b4, strlen(str_b4));
  sha256_update(&ctx_b, str_b5, strlen(str_b5));
  sha256_update(&ctx_b, str_b6, strlen(str_b6));
  byte *hash_b_ = sha256_final(&ctx_b);
  byte_to_hex(hash_b, hash_b_, SHA256_SIZE);

  int are_hash_a_b_equal = (strncmp(hash_a, hash_b, sizeof(hash_a)) == 0);
  bt_assert_msg(are_hash_a_b_equal, "Hashes are different: \n A: %s \n B: %s ", hash_a, hash_b);

  return BT_SUCCESS;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_sha256, "Testing SHA256");
  bt_test_suite(t_sha224, "Testing SHA224");
  bt_test_suite(t_sha256_concating, "Testing concating input string to hash process via sha256_update");

  return bt_end();
}
