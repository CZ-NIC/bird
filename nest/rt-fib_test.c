/*
 *	BIRD -- Forwarding Information Base -- Tests
 *
 *	(c) 2023 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "nest/route.h"


#define TESTS_NUM		10
#define PREFIXES_NUM 		400000
#define PREFIX_TESTS_NUM 	200000
#define PREFIX_BENCH_MAX 	1000000
#define PREFIX_BENCH_NUM 	10000000

struct test_node
{
  int pos;
  struct fib_node n;
};

static inline int net_match(struct test_node *tn, net_addr *query, net_addr *data)
{ return (tn->pos < PREFIXES_NUM) && net_equal(query, &data[tn->pos]); }

static int
t_match_random_net(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  for (int round = 0; round < TESTS_NUM; round++)
  {
    int type = !(round & 1) ? NET_IP4 : NET_IP6;

    pool *p = rp_new(&root_pool, "FIB pool");
    net_addr *nets = bt_random_nets(type, PREFIXES_NUM);

    /* Make FIB structure */
    struct fib f;
    fib_init(&f, &root_pool, type, sizeof(struct test_node), OFFSETOF(struct test_node, n), 4, NULL);

    for (int i = 0; i < PREFIXES_NUM; i++)
    {
      struct test_node *tn = fib_get(&f, &nets[i]);
      bt_assert(!tn->pos || net_match(tn, &nets[i], nets));
      tn->pos = i;
    }

    /* Test (mostly) negative matches */
    for (int i = 0; i < PREFIX_TESTS_NUM; i++)
    {
      net_addr net;
      bt_random_net(&net, type);

      struct test_node *tn = fib_find(&f, &net);
      bt_assert(!tn || net_match(tn, &net, nets));
    }

    /* Test positive matches */
    for (int i = 0; i < PREFIX_TESTS_NUM; i++)
    {
      int j = bt_random_n(PREFIXES_NUM);

      struct test_node *tn = fib_find(&f, &nets[j]);
      bt_assert(tn && net_match(tn, &nets[j], nets));
    }

    rfree(p);
    tmp_flush();
  }

  bt_bird_cleanup();
  return 1;
}

static int
t_fib_walk(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  for (int round = 0; round < TESTS_NUM; round++)
  {
    int type = !(round & 1) ? NET_IP4 : NET_IP6;

    pool *p = rp_new(&root_pool, "FIB pool");
    net_addr *nets = bt_random_nets(type, PREFIXES_NUM);
    byte *marks = tmp_allocz(PREFIXES_NUM);

    /* Make FIB structure */
    struct fib f;
    fib_init(&f, p, type, sizeof(struct test_node), OFFSETOF(struct test_node, n), 4, NULL);

    for (int i = 1; i < PREFIXES_NUM; i++)
    {
      struct test_node *tn = fib_get(&f, &nets[i]);
      bt_assert(!tn->pos || net_match(tn, &nets[i], nets));
      if (tn->pos)
      {
	/* Mark dupicate nets */
	bt_assert(!marks[tn->pos]);
	marks[tn->pos] = 1;
      }
      tn->pos = i;
    }

    /* Walk FIB and mark nets */
    FIB_WALK(&f, struct test_node, tn)
    {
      bt_assert(!marks[tn->pos]);
      marks[tn->pos] = 1;
    }
    FIB_WALK_END;

    /* Check in all nets are marked */
    for (int i = 1; i < PREFIXES_NUM; i++)
      bt_assert(marks[i]);

    rfree(p);
    tmp_flush();
  }

  bt_bird_cleanup();
  return 1;
}

static int
benchmark_fib_dataset(const char *filename, int type)
{
  net_addr *nets, *test_r, *test_s;
  uint n = PREFIX_BENCH_MAX;
  int tn = PREFIX_BENCH_NUM;
  int match;

  bt_reset_suite_case_timer();
  bt_log_suite_case_result(1, "Reading %s", filename, n);
  nets = bt_read_net_file(filename, type, &n);
  bt_log_suite_case_result(1, "Read net data, %u nets", n);
  bt_reset_suite_case_timer();

  pool *p = rp_new(&root_pool, "FIB pool");

  /* Make FIB structure */
  struct fib f;
  fib_init(&f, p, type, sizeof(struct test_node), OFFSETOF(struct test_node, n), 0, NULL);

  for (int i = 0; i < (int) n; i++)
  {
    struct test_node *tn = fib_get(&f, &nets[i]);
    tn->pos = i;
  }

  bt_log_suite_case_result(1, "Fill FIB structure, %u nets, order %u", n, f.hash_order);
  bt_reset_suite_case_timer();

  /* Compute FIB size */
  size_t fib_size = rmemsize(p).effective * 1000 / (1024*1024);
  bt_log_suite_case_result(1, "FIB size: %u.%03u MB", (uint) (fib_size / 1000), (uint) (fib_size % 1000));

  /* Compute FIB histogram */
  uint hist[16] = {};
  uint sum = 0;
  for (uint i = 0; i < f.hash_size; i++)
  {
    int len = 0;
    for (struct fib_node *fn = f.hash_table[i]; fn; fn = fn->next)
      len++;

    sum += len;
    len = MIN(len, 15);
    hist[len]++;
  }
  bt_log_suite_case_result(1, "FIB histogram:");
  for (uint i = 0; i < 16; i++)
    if (hist[i])
      bt_log_suite_case_result(1, "%02u: %8u", i, hist[i]);

  uint avg = (sum * 1000) / (f.hash_size - hist[0]);
  bt_log_suite_case_result(1, "FIB chain length: %u.%03u", (uint) (avg / 1000), (uint) (avg % 1000));
  bt_reset_suite_case_timer();

  /* Make test data */
  test_r = bt_random_nets(type, tn);
  test_s = bt_random_net_subset(nets, n, tn);

  bt_log_suite_case_result(1, "Make test data, 2x %u nets", tn);
  bt_reset_suite_case_timer();

  /* Test (mostly negative) random matches */
  match = 0;
  for (int i = 0; i < tn; i++)
    if (fib_find(&f, &test_r[i]))
      match++;

  bt_log_suite_case_result(1, "Random match, %d / %d matches", match, tn);
  bt_reset_suite_case_timer();

  /* Test (positive) subset matches */
  match = 0;
  for (int i = 0; i < tn; i++)
    if (fib_find(&f, &test_s[i]))
      match++;

  bt_log_suite_case_result(1, "Subset match, %d / %d matches", match, tn);
  bt_log_suite_case_result(1, "");
  bt_reset_suite_case_timer();

  rfree(p);
  tmp_flush();
  return 1;
}

static int UNUSED
t_bench_fib_datasets(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  /* Specific datasets, not included */
  benchmark_fib_dataset("fib-data-bgp-v4-1",  NET_IP4);
  benchmark_fib_dataset("fib-data-bgp-v4-10", NET_IP4);
  benchmark_fib_dataset("fib-data-bgp-v6-1",  NET_IP6);
  benchmark_fib_dataset("fib-data-bgp-v6-10", NET_IP6);

  bt_bird_cleanup();

  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_match_random_net, "Testing random prefix matching");
  bt_test_suite(t_fib_walk, "Testing FIB_WALK() on random FIB");

  // bt_test_suite(t_bench_fib_datasets, "Benchmark FIB from datasets by random subset of nets");

  return bt_exit_value();
}
