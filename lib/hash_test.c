/*
 *	BIRD Library -- Hash Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

#include "test/birdtest.h"

#include "lib/hash.h"

struct test_node {
  struct test_node *next;	/* Hash chain */
  u32 key;
};

#define TEST_KEY(n)		n->key
#define TEST_NEXT(n)		n->next
#define TEST_EQ(n1,n2)		n1 == n2
#define TEST_FN(n)		(n) ^ u32_hash((n))
#define TEST_ORDER		13
#define TEST_PARAMS		/TEST_ORDER, *2, 2, 2, TEST_ORDER, 20
#define TEST_REHASH		test_rehash

HASH_DEFINE_REHASH_FN(TEST, struct test_node);

HASH(struct test_node) hash;
struct pool *my_pool;

#define MAX_NUM			(1 << TEST_ORDER)

struct test_node nodes[MAX_NUM];

static void
print_rate_of_fulfilment(void)
{
  int i;
  int num_stacked_items = 0;

  for (i = 0; i < MAX_NUM; i++)
    if (!hash.data[i])
      num_stacked_items++;

  double percent_stacked_items = ((double)num_stacked_items/(double)MAX_NUM)*100.;
  bt_debug("%d (%.2f %%) chained of %d hashes \n", num_stacked_items, percent_stacked_items, MAX_NUM);
}

#ifdef LOCAL_DEBUG
static void
dump_nodes(void)
{
  int i;
  for (i = 0; i < MAX_NUM; i++)
    bt_debug("nodes[%3d] is at address %14p has .key %3d, .next %14p \n", i, &nodes[i], nodes[i].key, nodes[i].next);
}
#endif

static void
init_hash_(uint order)
{
  my_pool = rp_new(&root_pool, "Test pool");

  HASH_INIT(hash, my_pool, order);

  int i;
  for (i = 0; i < MAX_NUM; i++)
  {
    nodes[i].key  = i;
    nodes[i].next = NULL;
  }

  bt_debug("MAX_NUM %d \n", MAX_NUM);
}

static void
init_hash(void)
{
  init_hash_(TEST_ORDER);
}

static void
validate_filled_hash(void)
{
  int i;
  struct test_node *node;
  for (i = 0; i < MAX_NUM; i++)
  {
    node = HASH_FIND(hash, TEST, nodes[i].key);
    bt_assert_msg(node->key == nodes[i].key, "Hash should be filled, to find (%p) the node[%d] (%p) with .key = %u, .next %p", node, i, &nodes[i], nodes[i].key, nodes[i].next);
  }

  print_rate_of_fulfilment();
}

static void
validate_empty_hash(void)
{
  int i;
  struct test_node *node;
  for (i = 0; i < MAX_NUM; i++)
  {
    node = HASH_FIND(hash, TEST, nodes[i].key);
    bt_assert_msg(node == NULL, "Hash should be empty, to find (%p) the node[%d] (%p) with .key %u, .next %p", node, i, &nodes[i], nodes[i].key, nodes[i].next);
  }
}

static void
fill_hash(void)
{
  int i;
  struct test_node *node;

  for (i = 0; i < MAX_NUM; i++)
  {
    nodes[i].key = i;
    node = &nodes[i];
    HASH_INSERT(hash, TEST, node);
  }
}

static int
t_insert_find(void)
{
  init_hash();
  fill_hash();
  validate_filled_hash();

  return 1;
}

static int
t_insert_find_random(void)
{
  init_hash();

  int i;
  struct test_node *node;
  for (i = 0; i < MAX_NUM; i++)
  {
    nodes[i].key = bt_random();
    node = &nodes[i];
    HASH_INSERT(hash, TEST, node);
  }

  validate_filled_hash();

  return 1;
}

static int
t_insert2_find(void)
{
  init_hash_(1);

  int i;
  struct test_node *node;
  for (i = 0; i < MAX_NUM; i++)
  {
    nodes[i].key = i;
    node = &nodes[i];
    HASH_INSERT2(hash, TEST, my_pool, node);
  }
  bt_assert_msg(hash.order != 1, "The hash should auto-resize from order 2^1. The order of the hash is 2^%u.", hash.order);

  validate_filled_hash();

  return 1;
}

static int
t_walk(void)
{
  init_hash();
  fill_hash();

  uint i;
  uint check[MAX_NUM];
  for (i = 0; i < MAX_NUM; i++)
    check[i] = 0;

  HASH_WALK(hash, next, n)
  {
    check[n->key]++;
  }
  HASH_WALK_END;

  for (i = 0; i < MAX_NUM; i++)
    bt_assert(check[i] == 1);

  return 1;
}

static int
t_walk_delsafe_delete(void)
{
  init_hash();
  fill_hash();

  HASH_WALK_DELSAFE(hash, next, n)
  {
    HASH_DELETE(hash, TEST, n->key);
  }
  HASH_WALK_DELSAFE_END;

  validate_empty_hash();

  return 1;
}

static int
t_walk_delsafe_remove(void)
{
  init_hash();
  fill_hash();

  HASH_WALK_DELSAFE(hash, next, n)
  {
    HASH_REMOVE(hash, TEST, n);
  }
  HASH_WALK_DELSAFE_END;

  validate_empty_hash();

  return 1;
}

static int
t_walk_delsafe_delete2(void)
{
  init_hash();
  fill_hash();

  HASH_WALK_DELSAFE(hash, next, n)
  {
    HASH_DELETE2(hash, TEST, my_pool, n->key);
  }
  HASH_WALK_DELSAFE_END;

  validate_empty_hash();

  return 1;
}

static int
t_walk_delsafe_remove2(void)
{
  init_hash();
  fill_hash();

  HASH_WALK_DELSAFE(hash, next, n)
  {
    HASH_REMOVE2(hash, TEST, my_pool, n);
  }
  HASH_WALK_DELSAFE_END;

  validate_empty_hash();

  return 1;
}

static int
t_walk_filter(void)
{
  init_hash();
  fill_hash();

  uint i;
  uint check[MAX_NUM];
  for (i = 0; i < MAX_NUM; i++)
    check[i] = 0;

  HASH_WALK_FILTER(hash, next, n, m)
  {
    bt_assert(n == *m);
    check[n->key]++;
  }
  HASH_WALK_FILTER_END;

  for (i = 0; i < MAX_NUM; i++)
    bt_assert(check[i] == 1);

  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_insert_find, 		"HASH_INSERT and HASH_FIND");
  bt_test_suite(t_insert_find_random, 	"HASH_INSERT pseudo-random keys and HASH_FIND");
  bt_test_suite(t_insert2_find, 	"HASH_INSERT2 and HASH_FIND. HASH_INSERT2 is HASH_INSERT and a smart auto-resize function");
  bt_test_suite(t_walk, 		"HASH_WALK");
  bt_test_suite(t_walk_delsafe_delete, 	"HASH_WALK_DELSAFE and HASH_DELETE");
  bt_test_suite(t_walk_delsafe_delete2,	"HASH_WALK_DELSAFE and HASH_DELETE2. HASH_DELETE2 is HASH_DELETE and smart auto-resize function");
  bt_test_suite(t_walk_delsafe_remove, 	"HASH_WALK_DELSAFE and HASH_REMOVE");
  bt_test_suite(t_walk_delsafe_remove2,	"HASH_WALK_DELSAFE and HASH_REMOVE2. HASH_REMOVE2 is HASH_REMOVE and smart auto-resize function");
  bt_test_suite(t_walk_filter,		"HASH_WALK_FILTER");

  return bt_exit_value();
}
