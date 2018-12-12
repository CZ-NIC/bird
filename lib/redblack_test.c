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

#define N 4096
#define MUL 16

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
  *new = (struct rb_test) { .value = val }; \
  REDBLACK_INSERT(struct rb_test, rb_, RBT_KEY, RBT_COMPARE, root, new); \
} while (0)

#define RB_DELETE(root, val) do { \
  struct rb_test *old = REDBLACK_FIND(struct rb_test, rb_, RBT_KEY, RBT_COMPARE, root, val); \
  REDBLACK_DELETE(struct rb_test, rb_, root, old); \
} while (0)

static int
rb_insert(void)
{
  struct rb_test *root = NULL;

#define BIT(x) ((bits[(x) / 64] >> ((x) % 64)) & 1)
#define SIT(x) (bits[(x) / 64] |= (1ULL << ((x) % 64)))
#define CIT(x) (bits[(x) / 64] &= ~(1ULL << ((x) % 64)))
  uint total = 0;
  u64 bits[N / 64] = {};
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
 
  return 1;  
}

int
main(int argc, char **argv)
{
  bt_init(argc, argv);
  bt_test_suite_extra(rb_insert, BT_FORKING, 30, "redblack insertion test");
}
