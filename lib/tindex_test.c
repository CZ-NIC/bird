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
  u32 dtb[2] = { data >> 32, data };
  u64 idx = tindex_find(tt->ti, dtb, 64, TINDEX_CREATE);
  bt_assert(idx > 0);

  u64 nlen = tt->len;
  while (idx >= nlen)
    nlen *= 2;

  if (nlen > tt->len) {
    tt->data = mb_realloc(tt->data, nlen * sizeof(u64));
    memset(&(tt->data[tt->len]), 0, (nlen - tt->len) * sizeof(u64));
    tt->len = nlen;
  }

  tt->data[idx]++;
}

static inline void test_trie_get(struct test_trie *tt, u64 data, u64 cnt) {
  u64 out = 0;
  u32 dtb[2] = { data >> 32, data };
  u64 idx = tindex_find(tt->ti, dtb, 64, TINDEX_FIND);
  if (idx) out = tt->data[idx];
  bt_assert_msg(out == cnt, "Index %lu shall be in trie %lu times, is %lu times.", data, cnt, out);
}

/*
static inline void test_trie_remove(struct test_trie *tt, u64 data) {
  u64 idx = tindex_find(tt->ti, &data, 64, TINDEX_FIND);
  ASSERT(idx);
  ASSERT(tt->data[idx]);
  if (!--tt->data[idx])
    tindex_delete(tt->ti, idx);
}
*/

static int
t_simple(void)
{
  const u64 mul = 0xf906f046b1fd4863ULL;
  const u64 add = 0xb3a35ec46d09489bULL;
  pool *p = rp_new(&root_pool, "tindex test");
  struct test_trie tt = {
    .ti = tindex_new(p),
    .data = mb_allocz(p, sizeof(u64) * 256),
    .len = 256,
  };

  const u64 max = bt_benchmark ? (1<<19) : (1<<16);
 
  bt_assert(tt.ti);
  for (u64 i = 0; i < max; i++) {
    bt_debug("Trie add: %lu\n", i);
    test_trie_add(&tt, i);
    test_trie_add(&tt, i * mul + add);
  }

  for (u64 i = 0; i < max; i++) {
    test_trie_get(&tt, i, 1);
    test_trie_get(&tt, i * mul + add, 1);
  }

  /*
  for (u64 i = 0; i < 20; i++)
    test_trie_remove(&tt, i);
    */

  tindex_dump(tt.ti);

  return 1;
}

int main(int argc, char **argv)
{
  bt_init(argc, argv);
  bt_bird_init();
  bt_test_suite(t_simple, "tindex");
  return bt_exit_value();
}
