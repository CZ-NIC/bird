/*
 *	BIRD Resource Manager -- Indexed Slab Alloc / Dealloc Tests
 *
 *	(c) 2026       Katerina Kubecova <katerina.kubecova@nic.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/resource.h"
#include "lib/bitops.h"

static const int sizes[] = {
  8, 12, 18, 27, 41, 75, 131, 269,
};

#define TEST_SIZE	1024 * 128 * (bt_is_extended ? 1024 : 1)
#define ITEMS(sz)	TEST_SIZE / ( (sz) >> u32_log2((sz))/2 )

#define REPS		(bt_is_extended ? 32 : 1)

struct test_request {
  int size;
  bool ptr;
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

static inline byte *test_alloc(islab *s, int sz, struct resmem *sliz, u32 *id)
{
  struct isl_block b = isl_alloc(s);
  byte *out = b.ptr;
  *id = b.id;

  for (int p=0; p < sz; p++)
    out[p] = p & 0xff;

  struct resmem ns = rmemsize((resource *) s);

  bt_assert(sliz->effective + sz == ns.effective);
  bt_assert((sliz->overhead - sz - ns.overhead) % page_size == 0);

  *sliz = ns;

  return out;
}

static inline void test_free_id(islab *s, u32 id, int sz, struct resmem *sliz)
{
  byte *block = isl_find_id(s, id);

  for (int p=0; p < sz; p++)
  {
    bt_assert(block[p] == (p & 0xff));
    block[p]++;
  }

  isl_free_id(s, id);

  struct resmem ns = rmemsize((resource *) s);

  bt_assert(sliz->effective - sz == ns.effective);
  bt_assert((sliz->overhead + sz - ns.overhead) % page_size == 0);

  *sliz = ns;
}

static inline void test_free_ptr(islab *s, byte *block, int sz, struct resmem *sliz)
{
  for (int p=0; p < sz; p++)
  {
    bt_assert(block[p] == (p & 0xff));
    block[p]++;
  }

  isl_free_ptr(s, block);

  struct resmem ns = rmemsize((resource *) s);

  bt_assert(sliz->effective - sz == ns.effective);
  bt_assert((sliz->overhead + sz - ns.overhead) % page_size == 0);

  *sliz = ns;
}

static inline struct resmem get_memsize(islab *s)
{
  struct resmem sz = rmemsize((resource *) s);
  bt_assert(sz.effective == 0);
  return sz;
}

static int
t_islab(const void *data)
{
  const struct test_request *tr = data;
  int sz = tr->size;

  islab *s = isl_new(&root_pool, sz);
  struct resmem sliz = get_memsize(s);

  int n = ITEMS(sz);
  byte **block = mb_alloc(&root_pool, n * sizeof(*block));
  u32 *id = mb_alloc(&root_pool, n * sizeof(*id));

  switch (tr->strategy) {
    case TEST_FORWARDS:
      for (int rep = 0; rep < REPS; rep++)
      {
      for (int i = 0; i < n; i++)
	block[i] = test_alloc(s, sz, &sliz, &id[i]);

      for (int i = 0; i < n; i++)
	if (tr->ptr)
	  test_free_ptr(s, block[i], sz, &sliz);
	else
	  test_free_id(s, id[i], sz, &sliz);
      }
      break;

    case TEST_BACKWARDS:
      for (int rep = 0; rep < REPS; rep++)
      {
      for (int i = 0; i < n; i++)
	block[i] = test_alloc(s, sz, &sliz, &id[i]);

      for (int i = n - 1; i >= 0; i--)
	if (tr->ptr)
	  test_free_ptr(s, block[i], sz, &sliz);
	else
	  test_free_id(s, id[i], sz, &sliz);
      }
      break;

    case TEST_RANDOM:
      for (int rep = 0; rep < REPS; rep++)
      {
      for (int i = 0; i < n; i++)
	block[i] = test_alloc(s, sz, &sliz, &id[i]);

      for (int i = 0; i < n; i++)
      {
	int pos = bt_random() % (n - i);

	if (tr->ptr)
	  test_free_ptr(s, block[pos], sz, &sliz);
	else
	  test_free_id(s, id[pos], sz, &sliz);

	if (pos != n - i - 1)
	{
	  block[pos] = block[n - i - 1];
	  id[pos] = id[n - i - 1];
	}
      }
      }

      break;

    case TEST_MIXED:
      {
	int cur = 0;
	int pending = n;
	int recycle = n * (REPS-1);

	while (cur + pending > 0) {
	  int action = bt_random() % ((cur + pending) * 2);
	  int ptr = action & 1;
	  action >>= 1;

	  if (action < cur) {
	    if (ptr)
	      test_free_ptr(s, block[action], sz, &sliz);
	    else
	      test_free_id(s, id[action], sz, &sliz);

	    if (action != --cur)
	    {
	      block[action] = block[cur];
	      id[action] = id[cur];
	    }

	    if (recycle-- > 0)
	      pending++;
	  } else {
	    block[cur] = test_alloc(s, sz, &sliz, &id[cur]);
	    cur++;
	    pending--;
	  }
	}

	break;
      }

    default: bug("This shouldn't happen");
  }

  mb_free(block);
  mb_free(id);
  rfree(s);
  return 1;
}

int main(int argc, char *argv[])
{
  bt_init(argc, argv);

  struct test_request tr;

  for (uint i = 0; i < sizeof(sizes) / sizeof(*sizes); i++)
    for (uint strategy = TEST_FORWARDS; strategy < TEST__MAX; strategy++)
      for (uint ptr = 0; ptr < 2; ptr++)
      {
	tr = (struct test_request) {
	  .size = sizes[i],
	  .strategy = strategy,
	  .ptr = ptr,
	};
	bt_test_suite_arg(t_islab, &tr, "Basic Indexed Slab allocator test, size=%d, strategy=%s",
	    tr.size, strategy_name[strategy]);
      }

  return bt_exit_value();
}
