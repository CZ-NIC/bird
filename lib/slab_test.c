/*
 *	BIRD Library -- Slab Alloc / Dealloc Tests
 *
 *	(c) 2022 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/resource.h"
#include "lib/bitops.h"

static const int sizes[] = {
  8, 12, 18, 27, 41, 75, 131, 269,
};

#define TEST_SIZE	1024 * 128
#define ITEMS(sz)	TEST_SIZE / ( (sz) >> u32_log2((sz))/2 )

struct test_request {
  int size;
  enum strategy {
    TEST_NONE,
    TEST_FORWARDS,
    TEST_BACKWARDS,
    TEST_RANDOM,
    TEST_MIXED,
    TEST__MAX,
  } strategy;
};

const char * const strategy_name[TEST__MAX] = {
  [TEST_FORWARDS] = "forwards",
  [TEST_BACKWARDS] = "backwards",
  [TEST_RANDOM] = "random",
  [TEST_MIXED] = "mixed",
};

static inline byte *test_alloc(slab *s, int sz, struct resmem *sliz)
{
  byte *out = sl_alloc(s);

  for (int p=0; p < sz; p++)
    out[p] = p & 0xff;

  struct resmem ns = rmemsize((resource *) s);

  bt_assert(sliz->effective + sz == ns.effective);
  bt_assert((sliz->overhead - sz - ns.overhead) % page_size == 0);

  *sliz = ns;

  return out;
}

static inline void test_free(slab *s, byte *block, int sz, struct resmem *sliz)
{
  for (int p=0; p < sz; p++)
  {
    bt_assert(block[p] == (p & 0xff));
    block[p]++;
  }

  sl_free(block);

  struct resmem ns = rmemsize((resource *) s);

  bt_assert(sliz->effective - sz == ns.effective);
  bt_assert((sliz->overhead + sz - ns.overhead) % page_size == 0);

  *sliz = ns;
}

static inline struct resmem get_memsize(slab *s)
{
  struct resmem sz = rmemsize((resource *) s);
  bt_assert(sz.effective == 0);
  return sz;
}

static int
t_slab(const void *data)
{
  const struct test_request *tr = data;
  int sz = tr->size;

  slab *s = sl_new(&root_pool, sz);
  struct resmem sliz = get_memsize(s);

  int n = ITEMS(sz);
  byte **block = mb_alloc(&root_pool, n * sizeof(*block));

  switch (tr->strategy) {
    case TEST_FORWARDS:
      for (int i = 0; i < n; i++)
	block[i] = test_alloc(s, sz, &sliz);

      for (int i = 0; i < n; i++)
	test_free(s, block[i], sz, &sliz);

      break;

    case TEST_BACKWARDS:
      for (int i = 0; i < n; i++)
	block[i] = test_alloc(s, sz, &sliz);

      for (int i = n - 1; i >= 0; i--)
	test_free(s, block[i], sz, &sliz);

      break;

    case TEST_RANDOM:
      for (int i = 0; i < n; i++)
	block[i] = test_alloc(s, sz, &sliz);

      for (int i = 0; i < n; i++)
      {
	int pos = bt_random() % (n - i);
	test_free(s, block[pos], sz, &sliz);
	if (pos != n - i - 1)
	  block[pos] = block[n - i - 1];
      }

      break;

    case TEST_MIXED:
      {
	int cur = 0;
	int pending = n;

	while (cur + pending > 0) {
	  int action = bt_random() % (cur + pending);

	  if (action < cur) {
	    test_free(s, block[action], sz, &sliz);
	    if (action != --cur)
	      block[action] = block[cur];
	  } else {
	    block[cur++] = test_alloc(s, sz, &sliz);
	    pending--;
	  }
	}

	break;
      }

    default: bug("This shouldn't happen");
  }

  mb_free(block);
  return 1;
}
int main(int argc, char *argv[])
{
  bt_init(argc, argv);

  struct test_request tr;

  for (uint i = 0; i < sizeof(sizes) / sizeof(*sizes); i++)
      for (uint strategy = TEST_FORWARDS; strategy < TEST__MAX; strategy++)
      {
	tr = (struct test_request) {
	  .size = sizes[i],
	  .strategy = strategy,
	};
	bt_test_suite_arg(t_slab, &tr, "Slab allocator test, size=%d, strategy=%s",
	    tr.size, strategy_name[strategy]);
      }

  return bt_exit_value();
}
