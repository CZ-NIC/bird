/*
 *	BIRD Library -- Red Black Tree Tests
 *
 *	(c) 2018 Maria Matejka <mq@jmq.cz>
 *	(c) 2018 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/redblack.h"

struct rb_test {
  REDBLACK_NODE(struct rb_test, rb_);
  uint value;
};

#define RBT_KEY(a) ((a)->value)
#define RBT_COMPARE(a, b) ((int)(a) - (int)(b))

#define RBTDS64 "                                                                "
const char *spaces = RBTDS64;

#define RBT_DUMPER(node, color, depth) printf("%s%c %d\n", spaces + 64 - (depth*2), color ? '-' : '*', node->value); fflush(stdout)

static void rb_dump(struct rb_test *root) {
  printf("Redblack dump.\n");
  REDBLACK_DUMP(struct rb_test, rb_, root, RBT_DUMPER);
  printf("Redblack dump done.\n");
  fflush(stdout);
}

#define RB_CHECK(root, bits, total) do { \
  REDBLACK_CHECK(struct rb_test, rb_, RBT_KEY, RBT_COMPARE, root); \
  uint tot = 0; \
  for ( \
      struct rb_test *last = NULL, *node = REDBLACK_FIRST(struct rb_test, rb_, root); \
      node; \
      last = node, node = REDBLACK_NEXT(struct rb_test, rb_, node) \
      ) { \
    ASSERT(BIT(RBT_KEY(node))); \
    tot++; \
    if (last) \
      ASSERT(RBT_COMPARE(RBT_KEY(last), RBT_KEY(node)) < 0); \
  } \
  ASSERT(tot == total); \
  uint begin = (uint) bt_random() % N, end = (uint) bt_random() % N; \
  if (begin > end) { uint t = begin; begin = end; end = t; } \
  bt_debug("Nodes from %d to %d:\n", begin, end); \
  for ( \
      struct rb_test *node = REDBLACK_FIND_UP(struct rb_test, rb_, RBT_KEY, RBT_COMPARE, root, begin); \
      node && (RBT_COMPARE(RBT_KEY(node), end) < 0); \
      node = REDBLACK_NEXT(struct rb_test, rb_, node) \
      ) \
    bt_debug("%d\n", RBT_KEY(node)); \
  bt_debug("Nodes done.\n"); \
} while (0)

#define RB_FIND(root, val, exists) do { \
  struct rb_test *found = REDBLACK_FIND(struct rb_test, rb_, RBT_KEY, RBT_COMPARE, root, val); \
  if (exists) { \
    bt_assert(found); \
    bt_assert(found->value == val); \
  } else \
    bt_assert(!found); \
} while (0)

#define RB_INSERT(root, val) do { \
  struct rb_test *new = xmalloc(sizeof(struct rb_test)); \
  memset(new, 42, sizeof(struct rb_test)); \
  new->value = val; \
  REDBLACK_INSERT(struct rb_test, rb_, RBT_KEY, RBT_COMPARE, root, new); \
} while (0)

#define RB_DELETE(root, val) do { \
  struct rb_test *old = REDBLACK_FIND(struct rb_test, rb_, RBT_KEY, RBT_COMPARE, root, val); \
  REDBLACK_DELETE(struct rb_test, rb_, root, old); \
} while (0)

struct rb_test_args {
  uint N, MUL;
};

#define RB_INSERT_SIMPLE(root, val) do { \
  RB_CHECK(root, bits, total); \
  if (bt_verbose >= BT_VERBOSE_ABSOLUTELY_ALL) \
    rb_dump(root); \
  SIT(i); \
  total++; \
  RB_INSERT(root, i); \
} while (0)

#define RB_DELETE_SIMPLE(root, val) do { \
  RB_CHECK(root, bits, total); \
  if (bt_verbose >= BT_VERBOSE_ABSOLUTELY_ALL) \
    rb_dump(root); \
  CIT(i); \
  total--; \
  RB_DELETE(root, i); \
} while (0)

static int
rb_insert(const void *_args)
{
  const struct rb_test_args *args = _args;
  uint N = args->N;
  uint MUL = args->MUL;

  struct rb_test *root = NULL;

#define BIT(x) ((bits[(x) / 64] >> ((x) % 64)) & 1)
#define SIT(x) (bits[(x) / 64] |= (1ULL << ((x) % 64)))
#define CIT(x) (bits[(x) / 64] &= ~(1ULL << ((x) % 64)))
  uint total = 0;
  u64 *bits = alloca(sizeof(u64) * ((N+63) / 64));
  memset(bits, 0, sizeof(u64) * ((N+63) / 64));

  bt_debug("Inserting full tree");
  for (uint i=0; i<N; i++)
    RB_INSERT_SIMPLE(root, i);

  bt_debug("Deleting full tree");
  for (uint i=0; i<N; i++)
    RB_DELETE_SIMPLE(root, i);

  bt_debug("Inserting full tree backwards");
  for (uint i=0; i<N; i++)
    RB_INSERT_SIMPLE(root, N-i-1);

  bt_debug("Deleting full tree");
  for (uint i=0; i<N; i++)
    RB_DELETE_SIMPLE(root, i);

  bt_debug("Inserting full tree");
  for (uint i=0; i<N; i++)
    RB_INSERT_SIMPLE(root, i);

  bt_debug("Deleting full tree backwards");
  for (uint i=0; i<N; i++)
    RB_DELETE_SIMPLE(root, i);

  bt_debug("Running random test");

  for (uint i=0; i<N * MUL; i++) {
    RB_CHECK(root, bits, total);
    if (bt_verbose >= BT_VERBOSE_ABSOLUTELY_ALL)
      rb_dump(root);

    uint tv = (uint) bt_random() % N;
    RB_FIND(root, tv, BIT(tv));

    if (BIT(tv)) {
      bt_debug("Deleting existing value %d\n", tv);
      fflush(stdout);
      CIT(tv);
      total--;
      RB_DELETE(root, tv);
    } else {
      bt_debug("Inserting value %d\n", tv);
      fflush(stdout);
      SIT(tv);
      total++;
      RB_INSERT(root, tv);
    }
  }

  for (uint i=0; i<N; i++) {
    if (!BIT(i))
      continue;

    RB_DELETE_SIMPLE(root, i);
  }
 
  return 1;  
}

#define RUNTEST(n, mul) do { \
  const struct rb_test_args rbta = { .N = n, .MUL = mul }; \
  bt_test_suite_arg_extra(rb_insert, &rbta, BT_FORKING, 30, "redblack insertion test: N=%u, MUL=%u", n, mul); \
} while (0)

int
main(int argc, char **argv)
{
  bt_init(argc, argv);
  RUNTEST(3, 31);
  RUNTEST(7, 17);
  RUNTEST(127, 11);
  RUNTEST(8191, 3);

  return bt_exit_value();
}
