/*
 *	BIRD -- Set/Community-list Operations Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "lib/net.h"
#include "nest/route.h"
#include "nest/attrs.h"
#include "lib/resource.h"

#define SET_SIZE 10
static const struct adata *set_sequence;		/* <0; SET_SIZE) */
static const struct adata *set_sequence_same;		/* <0; SET_SIZE) */
static const struct adata *set_sequence_higher;	/* <SET_SIZE; 2*SET_SIZE) */
static const struct adata *set_random;

#define BUFFER_SIZE 1000
static byte buf[BUFFER_SIZE] = {};

#define SET_SIZE_FOR_FORMAT_OUTPUT 10

struct linpool *lp;

enum set_type
{
  SET_TYPE_INT,
  SET_TYPE_EC
};

static void
generate_set_sequence(enum set_type type, int len)
{
  struct adata empty_as_path = {};
  set_sequence = set_sequence_same = set_sequence_higher = set_random = &empty_as_path;
  lp = lp_new_default(&root_pool);

  int i;
  for (i = 0; i < len; i++)
  {
    if (type == SET_TYPE_INT)
    {
      set_sequence 	  = int_set_add(lp, set_sequence, i);
      set_sequence_same   = int_set_add(lp, set_sequence_same, i);
      set_sequence_higher = int_set_add(lp, set_sequence_higher, i + SET_SIZE);
      set_random   	  = int_set_add(lp, set_random, bt_random());
    }
    else if (type == SET_TYPE_EC)
    {
      set_sequence 	  = ec_set_add(lp, set_sequence, i);
      set_sequence_same   = ec_set_add(lp, set_sequence_same, i);
      set_sequence_higher = ec_set_add(lp, set_sequence_higher, i + SET_SIZE);
      set_random   	  = ec_set_add(lp, set_random, (bt_random() << 32 | bt_random()));
    }
    else
      bt_abort_msg("This should be unreachable");
  }
}

/*
 * SET INT TESTS
 */

static int
t_set_int_contains(void)
{
  int i;

  resource_init();
  generate_set_sequence(SET_TYPE_INT, SET_SIZE);

  bt_assert(int_set_get_size(set_sequence) == SET_SIZE);

  for (i = 0; i < SET_SIZE; i++)
    bt_assert(int_set_contains(set_sequence, i));
  bt_assert(int_set_contains(set_sequence, -1) == 0);
  bt_assert(int_set_contains(set_sequence, SET_SIZE) == 0);

  int *data = int_set_get_data(set_sequence);
  for (i = 0; i < SET_SIZE; i++)
    bt_assert_msg(data[i] == i, "(data[i] = %d) == i = %d)", data[i], i);

  rfree(lp);
  return 1;
}

static int
t_set_int_union(void)
{
  resource_init();
  generate_set_sequence(SET_TYPE_INT, SET_SIZE);

  const struct adata *set_union;
  set_union = int_set_union(lp, set_sequence, set_sequence_same);
  bt_assert(int_set_get_size(set_union) == SET_SIZE);
  bt_assert(int_set_format(set_union, 0, 2, buf, BUFFER_SIZE) == 0);

  set_union = int_set_union(lp, set_sequence, set_sequence_higher);
  bt_assert_msg(int_set_get_size(set_union) == SET_SIZE*2, "int_set_get_size(set_union) %d, SET_SIZE*2 %d", int_set_get_size(set_union), SET_SIZE*2);
  bt_assert(int_set_format(set_union, 0, 2, buf, BUFFER_SIZE) == 0);

  rfree(lp);
  return 1;
}

static int
t_set_int_format(void)
{
  resource_init();
  generate_set_sequence(SET_TYPE_INT, SET_SIZE_FOR_FORMAT_OUTPUT);

  bt_assert(int_set_format(set_sequence, 0, 0, buf, BUFFER_SIZE) == 0);
  bt_assert(strcmp(buf, "0.0.0.0 0.0.0.1 0.0.0.2 0.0.0.3 0.0.0.4 0.0.0.5 0.0.0.6 0.0.0.7 0.0.0.8 0.0.0.9") == 0);

  bzero(buf, BUFFER_SIZE);
  bt_assert(int_set_format(set_sequence, 0, 2, buf, BUFFER_SIZE) == 0);
  bt_assert(strcmp(buf, "0.0.0.2 0.0.0.3 0.0.0.4 0.0.0.5 0.0.0.6 0.0.0.7 0.0.0.8 0.0.0.9") == 0);

  bzero(buf, BUFFER_SIZE);
  bt_assert(int_set_format(set_sequence, 1, 0, buf, BUFFER_SIZE) == 0);
  bt_assert(strcmp(buf, "(0,0) (0,1) (0,2) (0,3) (0,4) (0,5) (0,6) (0,7) (0,8) (0,9)") == 0);

  rfree(lp);
  return 1;
}

static int
t_set_int_delete(void)
{
  resource_init();
  generate_set_sequence(SET_TYPE_INT, SET_SIZE);

  const struct adata *deleting_sequence = set_sequence;
  u32 i;
  for (i = 0; i < SET_SIZE; i++)
  {
    deleting_sequence = int_set_del(lp, deleting_sequence, i);
    bt_assert_msg(int_set_get_size(deleting_sequence) == (int) (SET_SIZE-1-i),
		  "int_set_get_size(deleting_sequence) %d == SET_SIZE-1-i %d",
		  int_set_get_size(deleting_sequence),
		  SET_SIZE-1-i);
  }

  bt_assert(int_set_get_size(set_sequence) == SET_SIZE);

  return 1;
}

/*
 * SET EC TESTS
 */

static int
t_set_ec_contains(void)
{
  u32 i;

  resource_init();
  generate_set_sequence(SET_TYPE_EC, SET_SIZE);

  bt_assert(ec_set_get_size(set_sequence) == SET_SIZE);

  for (i = 0; i < SET_SIZE; i++)
    bt_assert(ec_set_contains(set_sequence, i));
  bt_assert(ec_set_contains(set_sequence, -1) == 0);
  bt_assert(ec_set_contains(set_sequence, SET_SIZE) == 0);

//  int *data = ec_set_get_data(set_sequence);
//  for (i = 0; i < SET_SIZE; i++)
//    bt_assert_msg(data[i] == (SET_SIZE-1-i), "(data[i] = %d) == ((SET_SIZE-1-i) = %d)", data[i], SET_SIZE-1-i);

  rfree(lp);
  return 1;
}

static int
t_set_ec_union(void)
{
  resource_init();
  generate_set_sequence(SET_TYPE_EC, SET_SIZE);

  const struct adata *set_union;
  set_union = ec_set_union(lp, set_sequence, set_sequence_same);
  bt_assert(ec_set_get_size(set_union) == SET_SIZE);
  bt_assert(ec_set_format(set_union, 0, buf, BUFFER_SIZE) == 0);

  set_union = ec_set_union(lp, set_sequence, set_sequence_higher);
  bt_assert_msg(ec_set_get_size(set_union) == SET_SIZE*2, "ec_set_get_size(set_union) %d, SET_SIZE*2 %d", ec_set_get_size(set_union), SET_SIZE*2);
  bt_assert(ec_set_format(set_union, 0, buf, BUFFER_SIZE) == 0);

  rfree(lp);
  return 1;
}

static int
t_set_ec_format(void)
{
  resource_init();

  const struct adata empty_as_path = {};
  set_sequence = set_sequence_same = set_sequence_higher = set_random = &empty_as_path;
  lp = lp_new_default(&root_pool);

  u64 i = 0;
  set_sequence = ec_set_add(lp, set_sequence, i);
  for (i = 1; i < SET_SIZE_FOR_FORMAT_OUTPUT; i++)
    set_sequence = ec_set_add(lp, set_sequence, i + ((i%2) ? ((u64)EC_RO << 48) : ((u64)EC_RT << 48)));

  bt_assert(ec_set_format(set_sequence, 0, buf, BUFFER_SIZE) == 0);
  bt_assert_msg(strcmp(buf, "(unknown 0x0, 0, 0) (ro, 0, 1) (rt, 0, 2) (ro, 0, 3) (rt, 0, 4) (ro, 0, 5) (rt, 0, 6) (ro, 0, 7) (rt, 0, 8) (ro, 0, 9)") == 0,
		"ec_set_format() returns '%s'", buf);

  rfree(lp);
  return 1;
}

static int
t_set_ec_delete(void)
{
  resource_init();
  generate_set_sequence(SET_TYPE_EC, SET_SIZE);

  const struct adata *deleting_sequence = set_sequence;
  u32 i;
  for (i = 0; i < SET_SIZE; i++)
  {
    deleting_sequence = ec_set_del(lp, deleting_sequence, i);
    bt_assert_msg(ec_set_get_size(deleting_sequence) == (int) (SET_SIZE-1-i),
		  "ec_set_get_size(deleting_sequence) %d  == SET_SIZE-1-i %d",
		  ec_set_get_size(deleting_sequence), SET_SIZE-1-i);
  }

  bt_assert(ec_set_get_size(set_sequence) == SET_SIZE);

  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_set_int_contains, "Testing sets of integers: contains, get_data");
  bt_test_suite(t_set_int_format,   "Testing sets of integers: format");
  bt_test_suite(t_set_int_union,    "Testing sets of integers: union");
  bt_test_suite(t_set_int_delete,   "Testing sets of integers: delete");

  bt_test_suite(t_set_ec_contains, "Testing sets of Extended Community values: contains, get_data");
  bt_test_suite(t_set_ec_format,   "Testing sets of Extended Community values: format");
  bt_test_suite(t_set_ec_union,    "Testing sets of Extended Community values: union");
  bt_test_suite(t_set_ec_delete,   "Testing sets of Extended Community values: delete");

  return bt_exit_value();
}
