/*
 *	Filters: Utility Functions Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "filter/filter.h"

#define TESTS_NUM		10
#define PREFIXES_NUM 		10
#define PREFIX_TESTS_NUM 	10000

#define BIG_BUFFER_SIZE		10000

struct f_extended_prefix {
  node n; 				/* node in prefixes list */
  struct f_prefix prefix;
  int l;
  int h;
};

static u32
xrandom(u32 max)
{
  return ((u32)bt_random() % max);
}

static int
is_prefix_included(list *prefixes, struct f_prefix *needle)
{
  struct f_extended_prefix *n;
  WALK_LIST(n, *prefixes)
  {
    ip_addr cmask = ipa_mkmask(MIN(n->prefix.len, needle->len));

    if ((ipa_compare(ipa_and(n->prefix.ip, cmask), ipa_and(needle->ip, cmask)) == 0) &&
	(n->l <= needle->len) && (needle->len <= n->h))
    {
      bt_debug("FOUND\t" PRIipa "/%d %d-%d\n", ARGipa(n->prefix.ip), n->prefix.len, n->l, n->h);
      return 1; /* OK */
    }
  }
  return 0; /* FAIL */
}

static struct f_prefix
get_random_prefix(void)
{
  struct f_prefix f = {
#ifdef IPV6
      .ip = ipa_build6(bt_random(), bt_random(), bt_random(), bt_random()),
      .len = xrandom(120)+8,
#else
      .ip = ipa_build4(xrandom(256), xrandom(256), xrandom(256), xrandom(256)),
      .len = xrandom(25)+8,
#endif
  };

  return f;
}

static void
generate_random_prefixes(list *prefixes)
{
  int l, h, x, i;
  for (i = 0; i < PREFIXES_NUM; i++)
  {
    struct f_prefix f = get_random_prefix();

#ifdef IPV6
    l = xrandom(129);
    h = xrandom(129);
#else
    l = xrandom(33);
    h = xrandom(33);
#endif
    if (h < l)
    {
      x = l;
      l = h;
      h = x;
    }

    struct f_extended_prefix *px = calloc(1, sizeof(struct f_extended_prefix));
    px->prefix = f;
    px->l = l;
    px->h = h;

    bt_debug("ADD\t" PRIipa "/%d %d-%d\n", ARGipa(px->prefix.ip), px->prefix.len, px->l, px->h);
    add_tail(prefixes, &px->n);
  }
}

static int
t_match_prefix(void)
{
  bt_bird_init_with_simple_configuration();

  uint round;
  for (round = 0; round < TESTS_NUM; round++)
  {
    list prefixes; /* of structs f_extended_prefix */
    init_list(&prefixes);
    struct f_trie *trie = f_new_trie(config->mem, sizeof(struct f_trie_node));

    generate_random_prefixes(&prefixes);
    struct f_extended_prefix *n;
    WALK_LIST(n, prefixes)
    {
      trie_add_prefix(trie, n->prefix.ip, n->prefix.len, n->l, n->h);
    }

    int i;
    for (i = 0; i < PREFIX_TESTS_NUM; i++)
    {
      struct f_prefix f = get_random_prefix();
      bt_debug("TEST\t" PRIipa "/%d\n", ARGipa(f.ip), f.len);

      int should_be = is_prefix_included(&prefixes, &f);
      int is_there  = trie_match_prefix(trie, f.ip, f.len);
      bt_assert_msg(should_be == is_there, "Prefix " PRIipa "/%d %s", ARGipa(f.ip), f.len, (should_be ? "should be founded but was not founded in trie" : "is not inside trie but searching was false positive."));
    }

    struct f_extended_prefix *nxt;
    WALK_LIST_DELSAFE(n, nxt, prefixes)
    {
      free(n);
    }
  }

  return BT_SUCCESS;
}

static int
t_trie_same(void)
{
  bt_bird_init_with_simple_configuration();

  int round;
  for (round = 0; round < TESTS_NUM*4; round++)
  {
    struct f_trie * trie1 = f_new_trie(config->mem, sizeof(struct f_trie_node));
    struct f_trie * trie2 = f_new_trie(config->mem, sizeof(struct f_trie_node));

    list prefixes; /* of structs f_extended_prefix */
    init_list(&prefixes);
    int i;
    for (i = 0; i < 100; i++)
      generate_random_prefixes(&prefixes);

    struct f_extended_prefix *n;
    WALK_LIST(n, prefixes)
    {
      trie_add_prefix(trie1, n->prefix.ip, n->prefix.len, n->l, n->h);
    }
    WALK_LIST_BACKWARDS(n, prefixes)
    {
      trie_add_prefix(trie2, n->prefix.ip, n->prefix.len, n->l, n->h);
    }

    bt_assert_msg(trie_same(trie1, trie2), "Trie1 and trie2 (backward fullfill) are not same!");

    struct f_extended_prefix *nxt;
    WALK_LIST_DELSAFE(n, nxt, prefixes)
    {
      free(n);
    }
  }

  return BT_SUCCESS;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_match_prefix, "Testing random prefix matching");
  bt_test_suite(t_trie_same, "A trie filled forward should be same with a trie filled backward.");

  return bt_end();
}
