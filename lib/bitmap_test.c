/*
 *	BIRD Library -- Bitmap Tests
 *
 *	(c) 2019 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2019 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "sysdep/config.h"
#include "lib/bitmap.h"

#define MAX_NUM (1 << 20)
#define MAX_SET (1 << 19)
#define MAX_CLR (1 << 17)

#define STEP_NUM 1000
#define STEP_SET 1000
#define STEP_CLR 500

static int
t_bmap_set_clear_random(void)
{
  struct bmap b;

  bmap_init(&b, &root_pool, 1024);

  char expected[MAX_NUM] = {};
  uint i, n;

  for (i = 0; i < MAX_SET; i++)
  {
    do n = bt_random() % MAX_NUM;
    while (expected[n]);

    bmap_set(&b, n);
    expected[n] = 1;
  }

  for (i = 0; i < MAX_CLR; i++)
  {
    do n = bt_random() % MAX_NUM;
    while (!expected[n]);

    bmap_clear(&b, n);
    expected[n] = 0;
  }

  for (i = 0; i < MAX_NUM; i++)
    if (bmap_test(&b, i) != expected[i])
      bt_abort_msg("Bitmap mismatch on %d (should be %d %d)", i, bmap_test(&b, i), expected[i]);

  return 1;
}

static int
t_hmap_set_clear_random(void)
{
  struct hmap b;

  hmap_init(&b, &root_pool, 1024);

  char expected[MAX_NUM] = {};
  uint i, n;

  for (i = 0; i < MAX_SET; i++)
  {
    do n = bt_random() % MAX_NUM;
    while (expected[n]);

    hmap_set(&b, n);
    expected[n] = 1;
  }

  hmap_check(&b);

  for (i = 0; i < MAX_CLR; i++)
  {
    do n = bt_random() % MAX_NUM;
    while (!expected[n]);

    hmap_clear(&b, n);
    expected[n] = 0;
  }

  hmap_check(&b);

  for (i = 0; i < MAX_NUM; i++)
    if (hmap_test(&b, i) != expected[i])
      bt_abort_msg("Bitmap mismatch on %d (should be %d %d)", i, hmap_test(&b, i), expected[i]);

  for (i = 0; 1; i++)
  {
    n = hmap_first_zero(&b);
    bt_assert(n >= i);
    bt_assert(n <= MAX_NUM);

    for (; i < n; i++)
      bt_assert(expected[i]);

    if (n == MAX_NUM)
      break;

    bt_assert(!expected[i]);

    hmap_set(&b, n);
  }

  hmap_check(&b);

  return 1;
}

static int
t_hmap_set_clear_fill(void)
{
  struct hmap b;

  hmap_init(&b, &root_pool, 1024);

  char expected[MAX_NUM] = {};
  uint i, j, n, max = 0;

  for (i = 0; i < STEP_NUM; i++)
  {
    uint last = 0;
    uint step_set = bt_random() % STEP_SET;
    uint step_clr = bt_random() % STEP_CLR;

    for (j = 0; j < step_set; j++)
    {
      n = hmap_first_zero(&b);
      bt_assert(n > last || !last);
      bt_assert(n < MAX_NUM);

      if (!last)
	last = n;

      for (; last < n; last++)
	bt_assert(expected[last]);

      bt_assert(!expected[n]);

      hmap_set(&b, n);
      expected[n] = 1;
      max = MAX(max, n);
    }

    for (j = 0; j < step_clr; j++)
    {
      uint k = 0;
      do n = bt_random() % max;
      while (!expected[n] && (k++ < 8));

      if (!expected[n])
	continue;

      hmap_clear(&b, n);
      expected[n] = 0;
    }
  }

  for (i = 0; i < MAX_NUM; i++)
    if (hmap_test(&b, i) != expected[i])
      bt_abort_msg("Bitmap mismatch on %d (should be %d %d)", i, hmap_test(&b, i), expected[i]);

  hmap_check(&b);

  return 1;
}

static int
t_lmap_set_clear_fill(void)
{
  struct lmap b;

  lmap_init(&b, &root_pool);

  char expected[MAX_NUM] = {};
  uint i, j, n;

  for (i = 0; i < STEP_NUM; i++)
  {
    uint last = 0;
    uint lo = bt_random() % (1 << 19);
    uint hi = lo + 2 * STEP_SET;
    uint step_set = bt_random() % STEP_SET;
    uint step_clr = bt_random() % STEP_CLR;

    for (j = 0; j < step_set; j++)
    {
      n = lmap_first_zero_in_range(&b, lo, hi);
      bt_assert(n >= lo);
      bt_assert(n <= hi);

      for (last = lo; last < n; last++)
	bt_assert(expected[last]);

      if (n >= hi)
	break;

      bt_assert(!expected[n]);

      lmap_set(&b, n);
      expected[n] = 1;
    }

    for (j = 0; j < step_clr; j++)
    {
      n = lo + bt_random() % (step_set + 1);

      if (!expected[n])
	continue;

      lmap_clear(&b, n);
      expected[n] = 0;
    }

    {
      n = lmap_last_one_in_range(&b, lo, hi);
      bt_assert(n >= lo);
      bt_assert(n <= hi);

      for (last = n + 1; last < hi; last++)
	bt_assert(!expected[last]);

      if (n < hi)
	bt_assert(expected[n]);
    }
  }

  uint cnt = 0;
  for (i = 0; i < MAX_NUM; i++)
  {
    if (lmap_test(&b, i) != expected[i])
      bt_abort_msg("Bitmap mismatch on %d (should be %d %d)", i, lmap_test(&b, i), expected[i]);

    if (expected[i])
      cnt++;
  }
  // bt_log("Total %u", cnt);

  lmap_check(&b);

  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_bmap_set_clear_random, "BMap - random sequence of sets / clears");
  bt_test_suite(t_hmap_set_clear_random, "HMap - random sequence of sets / clears");
  bt_test_suite(t_hmap_set_clear_fill, "HMap - linear sets and random clears");
  bt_test_suite(t_lmap_set_clear_fill, "LMap - linear sets and random clears");

  return bt_exit_value();
}
