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
#include "lib/event.h"

#include <pthread.h>

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
  my_pool = rp_new(&root_pool, the_bird_domain.the_bird, "Test pool");

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


/*
 * Spinlocked hashes
 */

struct st_node {
  struct st_node *next;	/* Hash chain */
  u32 key;
};

#define ST_KEY(n)		n->key
#define ST_NEXT(n)		n->next
#define ST_EQ(n1,n2)		n1 == n2
#define ST_FN(n)		(n) ^ u32_hash((n))
#define ST_ORDER		4

#define ST_PARAMS		*1, *8, 3, 2, 3, 9

#define ST_MAX			16384
#define ST_READERS		1

#if 0
#define ST_DEBUG(...)		printf(__VA_ARGS__)
#else
#define ST_DEBUG(...)
#endif

static uint const st_skip[] = { 3, 7, 13, 17, 23, 37 };

typedef SPINHASH(struct st_node) shtest;

static _Atomic uint st_end = 0;
static _Atomic uint st_skip_pos = 0;

static void *
st_rehash_thread(void *_v)
{
  shtest *v = _v;
  rcu_thread_start();
  int step;

  the_bird_lock();
  while (!atomic_load_explicit(&st_end, memory_order_relaxed))
  {
    birdloop_yield();
    ST_DEBUG("rehash prepare\n");
    SPINHASH_REHASH_PREPARE(v, ST, struct st_node, step);
    ST_DEBUG("rehash prepared step=%d\n", step);

    if (!step)		continue;
    if (step < 0)	SPINHASH_REHASH_DOWN(v, ST, struct st_node, -step);
    if (step > 0)	SPINHASH_REHASH_UP  (v, ST, struct st_node,  step);

    ST_DEBUG("rehash finish\n");
    SPINHASH_REHASH_FINISH(v, ST);
    ST_DEBUG("rehash finished\n");
  }
  the_bird_unlock();

  rcu_thread_stop();
  return NULL;
}

static void *
st_find_thread(void *_v)
{
  shtest *v = _v;
  rcu_thread_start();

  uint skip = st_skip[atomic_fetch_add_explicit(&st_skip_pos, 1, memory_order_acq_rel)];

  for (u64 i = 0; !atomic_load_explicit(&st_end, memory_order_acquire); i += skip)
  {
    struct st_node *n = SPINHASH_FIND(*v, ST, i % ST_MAX);
    ASSERT_DIE(!n || (n->key == i % ST_MAX));
  }

  atomic_fetch_add_explicit(&st_end, 1, memory_order_release);

  rcu_thread_stop();
  return NULL;
}

static void *
st_update_thread(void *_v)
{
  shtest *v = _v;
  rcu_thread_start();

  struct st_node block[ST_MAX];
  for (uint i = 0; i < ST_MAX; i++)
    block[i] = (struct st_node) { .key = i, };

  for (uint r = 0; r < 32; r++)
  {
    for (uint i = 0; i < ST_MAX; i++)
    {
      ST_DEBUG("insert start %d\n", i);
      SPINHASH_INSERT(*v, ST, (&block[i]));
      ST_DEBUG("insert finish %d\n", i);
    }

    for (uint i = 0; i < ST_MAX; i++)
    {
      ST_DEBUG("remove start %d\n", i);
      SPINHASH_REMOVE(*v, ST, (&block[i]));
      ST_DEBUG("remove finish %d\n", i);
    }
  }

  atomic_store_explicit(&st_end, 1, memory_order_release);

  /* Wait for readers to properly end before releasing the memory,
   * as the hash nodes may be accessed even after removed from hash */
  while (atomic_load_explicit(&st_end, memory_order_acquire) < ST_READERS + 1)
    birdloop_yield();

  rcu_thread_stop();
  return NULL;
}

int
t_spinhash_basic(void)
{
  pthread_t reader[6], updater, rehasher;

  shtest v = {};
  void *ST_REHASH = NULL;
  SPINHASH_INIT(v, ST, rp_new(&root_pool, the_bird_domain.the_bird, "Test pool"), NULL);
  the_bird_unlock();

  for (int i=0; i<ST_READERS; i++)
    pthread_create(&reader[i], NULL, st_find_thread, &v);

  pthread_create(&rehasher, NULL, st_rehash_thread, &v);
  pthread_create(&updater, NULL, st_update_thread, &v);

  pthread_join(updater, NULL);
  pthread_join(rehasher, NULL);

  for (int i=0; i<ST_READERS; i++)
    pthread_join(reader[i], NULL);

  the_bird_lock();
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

  bt_test_suite(t_spinhash_basic,	"SPINHASH insert, remove, find and rehash");

  return bt_exit_value();
}
