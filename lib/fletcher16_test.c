/*
 *	BIRD Library -- Fletcher-16 Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/fletcher16.h"

static u16
straightforward_fletcher16_compute(const char *data)
{
  int count = strlen(data);

  u16 sum1 = 0;
  u16 sum2 = 0;
  int index;

  for (index = 0; index < count; ++index)
  {
    sum1 = (sum1 + data[index]) % 255;
    sum2 = (sum2 + sum1) % 255;
  }

  sum2 = (sum2 + sum1) % 255;
  sum2 = (sum2 + sum1) % 255;

  return (sum1 << 8) | sum2;
}

static u16
straightforward_fletcher16_checksum(const char *data)
{
  u16 csum;
  u16 c0,c1,x,y;

  csum = straightforward_fletcher16_compute(data);
  c0 = (csum >> 8) & 0xff;
  c1 = csum & 0xff;

  x = (255 +   c0 - c1) % 255;
  y = (510 - 2*c0 + c1) % 255;

  if (!x) x = 255;
  if (!y) y = 255;

  return (x << 8) | y;
}

const u8 zero16[2] = {};

static int
test_fletcher16(void *out_, const void *in_, const void *expected_out_)
{
  u16 *out = out_;
  const char *in = in_;
  const u16 *expected_out = expected_out_;

  struct fletcher16_context ctxt;

  fletcher16_init(&ctxt);
  fletcher16_update(&ctxt, in, strlen(in));
  fletcher16_update(&ctxt, zero16, 2);
  *out = fletcher16_compute(&ctxt);

  return *out == *expected_out;
}

static int
test_fletcher16_checksum(void *out_, const void *in_, const void *expected_out_)
{
  u16 *out = out_;
  const char *in = in_;
  const u16 *expected_out = expected_out_;

  struct fletcher16_context ctxt;
  int len = strlen(in);

  fletcher16_init(&ctxt);
  fletcher16_update(&ctxt, in, len);
  fletcher16_update(&ctxt, zero16, 2);
  *out = fletcher16_final(&ctxt, len+2, len);

  return *out == *expected_out;
}

static int
t_fletcher16_compute(void)
{
  struct bt_pair test_vectors[] = {
    {
      .in  = "\001\002",
      .out = & ((const u16) { straightforward_fletcher16_compute("\001\002") }),
    },
    {
      .in  = "",
      .out = & ((const u16) { straightforward_fletcher16_compute("") }),
    },
    {
      .in  = "a",
      .out = & ((const u16) { straightforward_fletcher16_compute("a") }),
    },
    {
      .in  = "abcd",
      .out = & ((const u16) { straightforward_fletcher16_compute("abcd") }),
    },
    {
      .in  = "message digest",
      .out = & ((const u16) { straightforward_fletcher16_compute("message digest") }),
    },
    {
      .in  = "abcdefghijklmnopqrstuvwxyz",
      .out = & ((const u16) { straightforward_fletcher16_compute("abcdefghijklmnopqrstuvwxyz") }),
    },
    {
      .in  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      .out = & ((const u16) { straightforward_fletcher16_compute("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") }),
    },
    {
      .in  = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      .out = & ((const u16) { straightforward_fletcher16_compute("12345678901234567890123456789012345678901234567890123456789012345678901234567890") }),
    },
  };

  return bt_assert_batch(test_vectors, test_fletcher16, bt_fmt_str, bt_fmt_unsigned);
}

static int
t_fletcher16_checksum(void)
{
  struct bt_pair test_vectors[] = {
    {
      .in  = "\001\002",
      .out =  & ((const u16) { straightforward_fletcher16_checksum("\001\002") }),
    },
    {
      .in  = "",
      .out =  & ((const u16) { straightforward_fletcher16_checksum("") }),
    },
    {
      .in  = "a",
      .out =  & ((const u16) { straightforward_fletcher16_checksum("a") }),
    },
    {
      .in  = "abcd",
      .out =  & ((const u16) { straightforward_fletcher16_checksum("abcd") }),
    },
    {
      .in  = "message digest",
      .out =  & ((const u16) { straightforward_fletcher16_checksum("message digest") }),
    },
    {
      .in  = "abcdefghijklmnopqrstuvwxyz",
      .out =  & ((const u16) { straightforward_fletcher16_checksum("abcdefghijklmnopqrstuvwxyz") }),
    },
    {
      .in  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      .out =  & ((const u16) { straightforward_fletcher16_checksum("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") }),
    },
    {
      .in  = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      .out =  & ((const u16) { straightforward_fletcher16_checksum("12345678901234567890123456789012345678901234567890123456789012345678901234567890") }),
    },
  };

  return bt_assert_batch(test_vectors, test_fletcher16_checksum, bt_fmt_str, bt_fmt_unsigned);
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_fletcher16_compute, "Fletcher-16 Compute Tests");
  bt_test_suite(t_fletcher16_checksum, "Fletcher-16 Checksum Tests");

  return bt_exit_value();
}
