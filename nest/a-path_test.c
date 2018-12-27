/*
 *	BIRD -- Path Operations Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "nest/route.h"
#include "nest/attrs.h"
#include "lib/resource.h"

#define TESTS_NUM 30
#define AS_PATH_LENGTH 1000

#if AS_PATH_LENGTH > AS_PATH_MAXLEN
#warning "AS_PATH_LENGTH should be <= AS_PATH_MAXLEN"
#endif

static int
t_as_path_match(void)
{
  resource_init();

  int round;
  for (round = 0; round < TESTS_NUM; round++)
  {
    struct adata empty_as_path = {};
    struct adata *as_path = &empty_as_path;
    u32 first_prepended, last_prepended;
    first_prepended = last_prepended = 0;
    struct linpool *lp = lp_new_default(&root_pool);

    struct f_path_mask *mask = alloca(sizeof(struct f_path_mask) + AS_PATH_LENGTH * sizeof(struct f_path_mask_item));
    mask->len = AS_PATH_LENGTH;
    for (int i = AS_PATH_LENGTH - 1; i >= 0; i--)
    {
      u32 val = bt_random();
      as_path = as_path_prepend(lp, as_path, val);
      bt_debug("Prepending ASN: %10u \n", val);

      if (i == 0)
	last_prepended = val;
      if (i == AS_PATH_LENGTH-1)
	first_prepended = val;

      mask->item[i].kind = PM_ASN;
      mask->item[i].asn  = val;
    }

    bt_assert_msg(as_path_match(as_path, mask), "Mask should match with AS path");

    u32 asn;

    bt_assert(as_path_get_first(as_path, &asn));
    bt_assert_msg(asn == last_prepended, "as_path_get_first() should return the last prepended ASN");

    bt_assert(as_path_get_last(as_path, &asn));
    bt_assert_msg(asn == first_prepended, "as_path_get_last() should return the first prepended ASN");

    rfree(lp);
  }

  return 1;
}

static int
t_path_format(void)
{
  resource_init();

  struct adata empty_as_path = {};
  struct adata *as_path = &empty_as_path;
  struct linpool *lp = lp_new_default(&root_pool);

  uint i;
  for (i = 4294967285; i <= 4294967294; i++)
  {
    as_path = as_path_prepend(lp, as_path, i);
    bt_debug("Prepending ASN: %10u \n", i);
  }

#define BUFFER_SIZE 120
  byte buf[BUFFER_SIZE] = {};

  as_path_format(&empty_as_path, buf, BUFFER_SIZE);
  bt_assert_msg(strcmp(buf, "") == 0, "Buffer(%zu): '%s'", strlen(buf), buf);

  as_path_format(as_path, buf, BUFFER_SIZE);
  bt_assert_msg(strcmp(buf, "4294967294 4294967293 4294967292 4294967291 4294967290 4294967289 4294967288 4294967287 4294967286 4294967285") == 0, "Buffer(%zu): '%s'", strlen(buf), buf);

#define SMALL_BUFFER_SIZE 25
  byte buf2[SMALL_BUFFER_SIZE] = {};
  as_path_format(as_path, buf2, SMALL_BUFFER_SIZE);
  bt_assert_msg(strcmp(buf2, "4294967294 42...") == 0, "Small Buffer(%zu): '%s'", strlen(buf2), buf2);

  rfree(lp);

  return 1;
}

static int
count_asn_in_array(const u32 *array, u32 asn)
{
  int counts_of_contains = 0;
  int u;
  for (u = 0; u < AS_PATH_LENGTH; u++)
    if (array[u] == asn)
	counts_of_contains++;
  return counts_of_contains;
}

static int
t_path_include(void)
{
  resource_init();

  struct adata empty_as_path = {};
  struct adata *as_path = &empty_as_path;
  struct linpool *lp = lp_new_default(&root_pool);

  u32 as_nums[AS_PATH_LENGTH] = {};
  int i;
  for (i = 0; i < AS_PATH_LENGTH; i++)
  {
    u32 val = bt_random();
    as_nums[i] = val;
    as_path = as_path_prepend(lp, as_path, val);
  }

  for (i = 0; i < AS_PATH_LENGTH; i++)
  {
    int counts_of_contains = count_asn_in_array(as_nums, as_nums[i]);
    bt_assert_msg(as_path_contains(as_path, as_nums[i], counts_of_contains), "AS Path should contains %d-times number %d", counts_of_contains, as_nums[i]);

    bt_assert(as_path_filter(lp, as_path, NULL, as_nums[i], 0) != NULL);
    bt_assert(as_path_filter(lp, as_path, NULL, as_nums[i], 1) != NULL);
  }

  for (i = 0; i < 10000; i++)
  {
    u32 test_val = bt_random();
    int counts_of_contains = count_asn_in_array(as_nums, test_val);
    int result = as_path_contains(as_path, test_val, (counts_of_contains == 0 ? 1 : counts_of_contains));

    if (counts_of_contains)
      bt_assert_msg(result, "As path should contain %d-times the number %u", counts_of_contains, test_val);
    else
      bt_assert_msg(result == 0, "As path should not contain the number %u", test_val);
  }

  rfree(lp);

  return 1;
}

#if 0
static int
t_as_path_converting(void)
{
  resource_init();

  struct adata empty_as_path = {};
  struct adata *as_path = &empty_as_path;
  struct linpool *lp = lp_new_default(&root_pool);
#define AS_PATH_LENGTH_FOR_CONVERTING_TEST 10

  int i;
  for (i = 0; i < AS_PATH_LENGTH_FOR_CONVERTING_TEST; i++)
    as_path = as_path_prepend(lp, as_path, i);

  bt_debug("data length: %u \n", as_path->length);

  byte buffer[100] = {};
  int used_size = as_path_convert_to_new(as_path, buffer, AS_PATH_LENGTH_FOR_CONVERTING_TEST-1);
  bt_debug("as_path_convert_to_new: len %d \n%s\n", used_size, buffer);
  for (i = 0; i < used_size; i++)
  {
    bt_debug("\\03%d", buffer[i]);
  }
  bt_debug("\n");
  bt_assert(memcmp(buffer,
		   "\032\039\030\030\030\030\030\030\030\039\030\030\030\030\030\030\030\038\030\030\030\030\030\030"
		   "\030\037\030\030\030\030\030\030\030\036\030\030\030\030",
		   38));

  bzero(buffer, sizeof(buffer));
  int new_used;
  used_size = as_path_convert_to_old(as_path, buffer, &new_used);
  bt_debug("as_path_convert_to_old: len %d, new_used: %d \n", used_size, new_used);
  for (i = 0; i < used_size; i++)
  {
    bt_debug("\\03%d", buffer[i]);
  }
  bt_debug("\n");
  bt_assert(memcmp(buffer,
		   "\032\0310\030\039\030\038\030\037\030\036\030\035\030\034\030\033\030\032\030\031\030\030",
		   22));

  return 1;
}
#endif

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_as_path_match, "Testing AS path matching and some a-path utilities.");
  bt_test_suite(t_path_format, "Testing formating as path into byte buffer");
  bt_test_suite(t_path_include, "Testing including a AS number in AS path");
  // bt_test_suite(t_as_path_converting, "Testing as_path_convert_to_*() output constancy");

  return bt_exit_value();
}
