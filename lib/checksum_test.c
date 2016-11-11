/*
 *	BIRD Library -- IP One-Complement Checksum Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>

#include "test/birdtest.h"

#include "lib/checksum.h"

#define MAX_NUM 10000

static u16
ipsum_calculate_expected(u32 *a)
{
  int i;
  u32 sum = 0;

  for(i = 0; i < MAX_NUM; i++)
  {
    sum += a[i] & 0xffff;
    bt_debug("low) \t0x%08X \n", sum);

    sum += a[i] >> 16;
    bt_debug("high) \t0x%08X \n", sum);

    u16 carry = sum >> 16;
    sum = (sum & 0xffff) + carry;
    bt_debug("carry) \t0x%08X \n\n", sum);
  }
  bt_debug("sum) \t0x%08X \n", sum);

  sum = sum ^ 0xffff;
  bt_debug("~sum) \t0x%08X \n", sum);

  return sum;
}

static int
t_calculate(void)
{
  u32 a[MAX_NUM];
  int i;

  for (i = 0; i < MAX_NUM; i++)
    a[i] = bt_random();

  u16 sum_calculated   = ipsum_calculate(a, sizeof(a), NULL);
  u16 sum_calculated_2 = ipsum_calculate(&a[0], sizeof(u32)*(MAX_NUM/2), &a[MAX_NUM/2], sizeof(u32)*(MAX_NUM - MAX_NUM/2), NULL);
  bt_assert(sum_calculated == sum_calculated_2);

  u16 sum_expected = ipsum_calculate_expected(a);

  bt_debug("sum_calculated: %08X \n", sum_calculated);
  bt_debug("sum_expected:   %08X \n", sum_expected);

  bt_assert(sum_calculated == sum_expected);

  return 1;
}

static int
t_verify(void)
{
  u32 a[MAX_NUM+1];
  int i;

  for (i = 0; i < MAX_NUM; i++)
    a[i] = bt_random();

  u16 sum = ipsum_calculate_expected(a);

  a[MAX_NUM] = sum;

  bt_assert(ipsum_verify(a, sizeof(a), NULL));

  return 1;
}


int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_calculate, "Checksum of pseudo-random data");
  bt_test_suite(t_verify, "Verification of pseudo-random data.");

  return bt_exit_value();
}
