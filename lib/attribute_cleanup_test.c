/*
 *	BIRD Library -- Auto storage attribute cleanup test
 *
 *	(c) 2023 Maria Matejka <mq@jmq.cz>
 *	(c) 2023 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"

static int order_pos;
#define CHECK(n) bt_assert(order_pos++ == (n))

static void
tacd_cleanup(int *val)
{
  CHECK(*val);
}

static void
tacd_aux(int pos)
{
  CHECK(pos + 0);

  UNUSED CLEANUP(tacd_cleanup) int upmost = pos + 18;

  if (order_pos > 0)
  {
    CHECK(pos + 1);
    UNUSED CLEANUP(tacd_cleanup) int inner_if = pos + 3;
    CHECK(pos + 2);
  }

  for (int i=0; i<3; i++)
  {
    CHECK(pos + 4 + 3*i);
    UNUSED CLEANUP(tacd_cleanup) int inner_for = pos + 6 + 3*i;
    CHECK(pos + 5 + 3*i);
  }

  for (
      CLEANUP(tacd_cleanup) int i = pos + 15;
      i < pos + 16; i++)
  {
    CHECK(pos + 13);
    UNUSED CLEANUP(tacd_cleanup) int inner_for = pos + 15;
    CHECK(pos + 14);
  }

  CHECK(pos + 17);
}

#define CHECKCNT 19

static int
t_attribute_cleanup(void)
{
  order_pos = 0;
  CHECK(0);

  for (int i=0; i<3; i++)
  {
    CHECK(i*(CHECKCNT+3) + 1);
    UNUSED CLEANUP(tacd_cleanup) int inner_for = (i+1) * (CHECKCNT+3);
    tacd_aux(i*(CHECKCNT+3) + 2);
    CHECK((i+1) * (CHECKCNT+3) - 1);
  }

  CHECK(3 * (CHECKCNT+3) + 1);

  return 1;
}

int main(int argc, char **argv)
{
  bt_init(argc, argv);

  bt_test_suite(t_attribute_cleanup, "Basic usability of the cleanup attribute");

  return bt_exit_value();
}
