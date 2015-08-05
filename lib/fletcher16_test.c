/*
 *	BIRD Library -- Fletcher-16 checksum Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/fletcher16.h"

struct in {
  u8 *data;
  int count;
};

static u16
straightforward_fletcher16_compute(const char *data)
{
  int count = strlen(data);

  u16 sum1 = 0;
  u16 sum2 = 0;
  int index;

  for(index = 0; index < count; ++index)
  {
    sum1 = (sum1 + data[index]) % 255;
    sum2 = (sum2 + sum1) % 255;
  }

  return (sum2 << 8) | sum1;
}

static u16
straightforward_fletcher16_checksum(const char *data)
{
  u16 csum;
  u8 c0,c1,f0,f1;

  csum = straightforward_fletcher16_compute(data);
  f0 = csum & 0xff;
  f1 = (csum >> 8) & 0xff;
  c0 = 0xff - ((f0 + f1) % 0xff);
  c1 = 0xff - ((f0 + c0) % 0xff);

  return (c1 << 8) | c0;
}

static u16
get_fletcher16_compute(const char *str)
{
  struct fletcher16_context ctxt;

  fletcher16_init(&ctxt);
  fletcher16_update(&ctxt, str, strlen(str));
  u16 f;
  put_u16(&f, fletcher16_compute(&ctxt));
  return f;
}

static u16
get_fletcher16_checksum(const char *str)
{
  struct fletcher16_context ctxt;

  int len = strlen(str);

  fletcher16_init(&ctxt);
  fletcher16_update(&ctxt, str, len);
  u16 f;
  put_u16(&f, fletcher16_final(&ctxt, len, len));
  return f;
}

static int
t_fletcher16_compute(void)
{
  struct in_out {
    char *in;
    u16 out;
  } in_out[] = {
      {
	  .in  = "\001\002",
	  .out = 0x0403,
      },
      {
	  .in  = "",
	  .out = straightforward_fletcher16_compute(""),
      },
      {
	  .in  = "a",
	  .out = straightforward_fletcher16_compute("a"),
      },
      {
	  .in  = "abcd",
	  .out = straightforward_fletcher16_compute("abcd"),
      },
      {
	  .in  = "message digest",
	  .out = straightforward_fletcher16_compute("message digest"),
      },
      {
	  .in  = "abcdefghijklmnopqrstuvwxyz",
	  .out = straightforward_fletcher16_compute("abcdefghijklmnopqrstuvwxyz"),
      },
      {
	  .in  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	  .out = straightforward_fletcher16_compute("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
      },
      {
	  .in  = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	  .out = straightforward_fletcher16_compute("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
      },
  };

  bt_assert_out_fn_in(get_fletcher16_compute, in_out, "'%s'", "0x%04X");

  return BT_SUCCESS;
}

static int
t_fletcher16_checksum(void)
{
  struct in_out {
    char *in;
    u16 out;
  } in_out[] = {
      {
	  .in  = "\001\002",
	  .out = straightforward_fletcher16_checksum("\001\002"),
      },
      {
	  .in  = "",
	  .out = straightforward_fletcher16_checksum(""),
      },
      {
	  .in  = "a",
	  .out = straightforward_fletcher16_checksum("a"),
      },
      {
	  .in  = "abcd",
	  .out = straightforward_fletcher16_checksum("abcd"),
      },
      {
	  .in  = "message digest",
	  .out = straightforward_fletcher16_checksum("message digest"),
      },
      {
	  .in  = "abcdefghijklmnopqrstuvwxyz",
	  .out = straightforward_fletcher16_checksum("abcdefghijklmnopqrstuvwxyz"),
      },
      {
	  .in  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	  .out = straightforward_fletcher16_checksum("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
      },
      {
	  .in  = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	  .out = straightforward_fletcher16_checksum("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
      },
  };

  bt_assert_out_fn_in(get_fletcher16_checksum, in_out, "'%s'", "0x%04X");

  return BT_SUCCESS;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_fletcher16_compute, "Fletcher-16 Compute Tests");
  bt_test_suite(t_fletcher16_checksum, "Fletcher-16 Checksum Tests");

  return bt_end();
}
