/*
 *	BIRD Library -- Trie index Tests
 *
 *	(c) 2019 Maria Matejka <mq@jmq.cz>
 *	(c) 2019 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"
#include "lib/tindex.h"

struct test_trie {
  struct tindex *ti;
  u64 *data;
  u64 len;
};

static inline void test_trie_add(struct test_trie *tt, u64 data) {
  u64 idx = tindex_find(tt->ti, &data, 64, 1);

  u64 nlen = tt->len;
  while (idx > nlen)
    nlen *= 2;

  if (nlen > tt->len) {
    tt->data = mb_realloc(tt->data, nlen * sizeof(u64));
    memset(&(tt->data[tt->len]), 0, (nlen - tt->len) * sizeof(u64));
    tt->len = nlen;
  }

  tt->data[idx]++;
}

static inline u64 test_trie_get(struct test_trie *tt, u64 data) {
  u64 idx = tindex_find(tt->ti, &data, 64, 0);
  if (!idx) return 0;
  return tt->data[idx];
}

static int
t_simple(void)
{
  pool *p = rp_new(&root_pool, "tindex test");
  struct test_trie tt = {
    .ti = tindex_new(p),
    .data = mb_allocz(p, sizeof(u64) * 256),
    .len = 256,
  };
 
  bt_assert(tt.ti);
  for (u64 i = 0; i < 20; i++) {
    bt_debug("Trie add: %lu\n", i);
    test_trie_add(&tt, i);
    tindex_dump(tt.ti);
  }

  for (u64 i = 0; i < 20; i++)
    bt_assert(test_trie_get(&tt, i) == 1);

  return 1;
}

int main(int argc, char **argv)
{
  bt_init(argc, argv);
  bt_bird_init();
  bt_test_suite(t_simple, "tindex");
  return bt_exit_value();
}
