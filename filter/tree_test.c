/*
 *	Filters: Utility Functions Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/utils.h"

#include "filter/filter.h"

static void
show_buffer(buffer *b)
{
  byte *p;
  for (p=b->start; p != b->pos; p++)
    bt_debug("%c", *p);
  bt_debug("\n");
}

static int
t_tree(void)
{
  bt_bird_init();

  struct f_tree *a = f_new_tree();
  struct f_tree *b = f_new_tree();
  bt_assert(same_tree(a, b));

  buffer buffer1;
  LOG_BUFFER_INIT(buffer1);
  tree_format(a, &buffer1);

  show_buffer(&buffer1);

  return BT_SUCCESS;
}
int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_tree, "Tree Test");

  return bt_end();
}
