/*
 *	BIRD Library -- Generic Bit Operations Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h" /* naive_pow() */

#include "lib/bitops.h"

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
    bt_assert_msg(compute == expect, "u32_mkmask(%d) = 0x%08X, expected 0x%08X", i, compute, expect);
  }

  return 1;
}

static int
u32_masklen_expected(u32 mask)
{
  int j, expect = 0;

  int valid = 0;
  for (j = 0; j <= 32; j++)
    if (mask == (j ? (0xffffffff << (32-j)) : 0)) /* Shifting 32-bit value by 32 bits is undefined behavior */
	valid = 1;

  if (!valid && mask != 0)
    expect = 255;
  else
    for (j = 0; j <= 31; j++)
      if (CHECK_BIT(mask, (31-j)))
	expect = j+1;
      else
	break;
  return expect;
}

static void
check_mask(u32 mask)
{
  int expected, masklen;

  expected = u32_masklen_expected(mask);
  masklen = u32_masklen(mask);
  int ok = (expected == masklen);
  bt_debug("u32_masklen(Ox%08x) = %d, expected %d  %s\n", mask, masklen, expected, ok ? "OK" : "FAIL!");
  bt_assert(ok);
}

static int
t_masklen(void)
{
  u32 i;

  check_mask(0x82828282);
  check_mask(0x00000000);

  for (i = 0; i <= 32; i++)
    check_mask(((u32) (i ? (0xffffffff << (32-i)) : 0)) & 0xffffffff); /* Shifting 32-bit value by 32 bits is undefined behavior */

  for (i = 0; i <= MAX_NUM; i++)
    check_mask(bt_random());

  return 1;
}

static void
check_log2(u64 n)
{
  u64 log  = u64_log2(n);
  u64 low  = bt_naive_pow(2, log);
  u64 high = bt_naive_pow(2, log+1);

  if (n <= 0xffffffff)
    bt_assert(u32_log2(n) == log);

  bt_assert_msg(n >= low && n < high,
		"u32_log2(%u) = %u, %u should be in the range <%u, %u)",
		n, log, n, low, high);
}

static int
t_log2(void)
{
  u32 i;

  for (i = 0; i < 31; i++)
    bt_assert(u32_log2(bt_naive_pow(2, i+1)) == i+1);

  for (i = 0; i < 63; i++)
    bt_assert(u64_log2(bt_naive_pow(2, i+1)) == i+1);

  for (i = 1; i < MAX_NUM; i++)
    check_log2(i);

  for (i = 1; i < MAX_NUM; i++)
    check_log2((unsigned long int) bt_random());

  return 1;
}

static void
var_enc_dec(u64 data, uint padlen)
{
  uint olen = ~0;
  u64 enc = u64_var_encode(data, padlen);
  u64 odata = u64_var_decode(enc, &olen);
  bt_assert_msg(
      (odata == data) && (olen == padlen),
      "u64_var_encode(0x%llx, %u) == 0x%llx; u64_var_decode(0x%llx, %u) == 0x%llx",
      data, padlen, enc, enc, olen, odata
      );
}

static int
t_var(void)
{
  for (uint i = 0; i < 63; i++)
    for (uint j = 1; j+i < 64; j++) {
      var_enc_dec(1ULL << i, j);
      var_enc_dec((1ULL << i) - 1, j);
      var_enc_dec(((unsigned long int) bt_random()) & ((1ULL << (64-j)) - 1), j);
    }

  return 1;
}




int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_mkmask, "u32_mkmask()");
  bt_test_suite(t_masklen, "u32_masklen()");
  bt_test_suite(t_log2, "u32_log2()");
  bt_test_suite(t_var, "u64_var_(en|de)code()");

  return bt_exit_value();
}
