/*
 *	BIRD Library -- Generic Bit Operations Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"
#include "bitops.h"

#define MAX_NUM 1000
#define CHECK_BIT(var,pos) ((var) & (u32)(1<<(pos)))

static int
t_mkmask(void)
{
  int i;
  u32 compute, expect;

  bt_assert(u32_mkmask(0) == 0x00000000);
  for (i = 1; i <= 32; i++)
  {
    compute = u32_mkmask(i);
    expect  = (u32) (0xffffffff << (32-i));
    bt_assert_msg(compute == expect, "u32_mkmask(%d) = 0x%08X, expected 0x%08X \n", i, compute, expect);
  }

  return BT_SUCCESS;
}

static int
u32_masklen_expected(u32 mask)
{
  int j, expect = 0;

  int valid = 0;
  for (j = 0; j <= 32; j++)
    if (mask == (j ? (0xffffffff << (32-j)) : 0)) /* Shifting 32-bit value by 32 bits is undefined behaviour */
	valid = 1;

  if (!valid && mask != 0)
    expect = -1;
  else
    for (j = 0; j <= 31; j++)
      if (CHECK_BIT(mask, (31-j)))
	expect = j+1;
      else
	break;
  return expect;
}

void static
check_mask(u32 mask)
{
  int compute, expect;

  compute = u32_masklen_expected(mask);
  expect = u32_masklen(mask);
  int ok = compute == expect;
  bt_debug("u32_masklen(Ox%08x) = %d, expected %d  %s\n", mask, u32_masklen(mask), u32_masklen_expected(mask), ok ? "OK" : "FAIL!");
  bt_assert(compute == expect);
}

static int
t_masklen(void)
{
  u32 i;

  check_mask(0x82828282);
  check_mask(0x00000000);

  for (i = 0; i <= 32; i++)
    check_mask(((u32) (i ? (0xffffffff << (32-i)) : 0)) & 0xffffffff); /* Shifting 32-bit value by 32 bits is undefined behaviour */

  for (i = 0; i <= MAX_NUM; i++)
    check_mask(bt_random());

  return BT_SUCCESS;
}

static void
check_log2(u32 n)
{
  u32 log  = u32_log2(n);
  u32 low  = naive_pow(2, log);
  u32 high = naive_pow(2, log+1);

  bt_debug("Test u32_log2(%u) = %u, %u should be in the range <%u, %u) \n", n, log, n, low, high);
  bt_assert(n >= low && n < high);
}

static int
t_log2(void)
{
  u32 i;

  struct in_out_data_ {
    u32 in;
    u32 out;
  } in_out_data[31];

  for (i = 0; i < 31; i++)
  {
    in_out_data[i].in  = naive_pow(2, i+1);
    in_out_data[i].out = i+1;
  }
  bt_assert_out_fn_in(u32_log2, in_out_data, "%u", "%u");

  u32_log2(0);

  for (i = 1; i < MAX_NUM; i++)
    check_log2(i);

  for (i = 1; i < MAX_NUM; i++)
    check_log2(bt_random() % 0xffff);

  return BT_SUCCESS;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_mkmask, "u32_mkmask()");
  bt_test_suite(t_masklen, "u32_masklen()");
  bt_test_suite(t_log2, "u32_log2()");

  return bt_end();
}
