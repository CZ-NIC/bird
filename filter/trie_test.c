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
#include "filter/data.h"
#include "conf/conf.h"

#define TESTS_NUM		10
#define PREFIXES_NUM 		10
#define PREFIX_TESTS_NUM 	10000

#define BIG_BUFFER_SIZE		10000

/* Wrapping structure for storing f_prefixes structures in list */
struct f_prefix_node {
  node n;
  struct f_prefix prefix;
};

static u32
xrandom(u32 max)
{
  return (bt_random() % max);
}

static int
is_prefix_included(list *prefixes, struct f_prefix *needle)
{
  struct f_prefix_node *n;
  WALK_LIST(n, *prefixes)
  {
    ip6_addr cmask = ip6_mkmask(MIN(n->prefix.net.pxlen, needle->net.pxlen));

    ip6_addr ip = net6_prefix(&n->prefix.net);
    ip6_addr needle_ip = net6_prefix(&needle->net);

    if ((ipa_compare(ipa_and(ip, cmask), ipa_and(needle_ip, cmask)) == 0) &&
	(n->prefix.lo <= needle->net.pxlen) && (needle->net.pxlen <= n->prefix.hi))
    {
      bt_debug("FOUND\t" PRIip6 "/%d %d-%d\n", ARGip6(net6_prefix(&n->prefix.net)), n->prefix.net.pxlen, n->prefix.lo, n->prefix.hi);
      return 1; /* OK */
    }
  }
  return 0; /* FAIL */
}

static struct f_prefix
get_random_ip6_prefix(void)
{
  struct f_prefix p;
  u8 pxlen = xrandom(120)+8;
  ip6_addr ip6 = ip6_build(bt_random(),bt_random(),bt_random(),bt_random());
  net_addr_ip6 net6 = NET_ADDR_IP6(ip6, pxlen);

  p.net = *((net_addr*) &net6);

  if (bt_random() % 2)
  {
    p.lo = 0;
    p.hi = p.net.pxlen;
  }
  else
  {
    p.lo = p.net.pxlen;
    p.hi = net_max_prefix_length[p.net.type];
  }

  return p;
}

static void
generate_random_ipv6_prefixes(list *prefixes)
{
  int i;
  for (i = 0; i < PREFIXES_NUM; i++)
  {
    struct f_prefix f = get_random_ip6_prefix();

    struct f_prefix_node *px = calloc(1, sizeof(struct f_prefix_node));
    px->prefix = f;

    bt_debug("ADD\t" PRIip6 "/%d %d-%d\n", ARGip6(net6_prefix(&px->prefix.net)), px->prefix.net.pxlen, px->prefix.lo, px->prefix.hi);
    add_tail(prefixes, &px->n);
  }
}

static int
t_match_net(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  uint round;
  for (round = 0; round < TESTS_NUM; round++)
  {
    list prefixes; /* of structs f_extended_prefix */
    init_list(&prefixes);
    struct f_trie *trie = f_new_trie(config->mem, sizeof(struct f_trie_node));

    generate_random_ipv6_prefixes(&prefixes);
    struct f_prefix_node *n;
    WALK_LIST(n, prefixes)
    {
      trie_add_prefix(trie, &n->prefix.net, n->prefix.lo, n->prefix.hi);
    }

    int i;
    for (i = 0; i < PREFIX_TESTS_NUM; i++)
    {
      struct f_prefix f = get_random_ip6_prefix();
      bt_debug("TEST\t" PRIip6 "/%d\n", ARGip6(net6_prefix(&f.net)), f.net.pxlen);

      int should_be = is_prefix_included(&prefixes, &f);
      int is_there  = trie_match_net(trie, &f.net);
      bt_assert_msg(should_be == is_there, "Prefix " PRIip6 "/%d %s", ARGip6(net6_prefix(&f.net)), f.net.pxlen, (should_be ? "should be found in trie" : "should not be found in trie"));
    }

    struct f_prefix_node *nxt;
    WALK_LIST_DELSAFE(n, nxt, prefixes)
    {
      free(n);
    }
  }

  bt_bird_cleanup();
  return 1;
}

static int
t_trie_same(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  int round;
  for (round = 0; round < TESTS_NUM*4; round++)
  {
    struct f_trie * trie1 = f_new_trie(config->mem, sizeof(struct f_trie_node));
    struct f_trie * trie2 = f_new_trie(config->mem, sizeof(struct f_trie_node));

    list prefixes; /* a list of f_extended_prefix structures */
    init_list(&prefixes);
    int i;
    for (i = 0; i < 100; i++)
      generate_random_ipv6_prefixes(&prefixes);

    struct f_prefix_node *n;
    WALK_LIST(n, prefixes)
    {
      trie_add_prefix(trie1, &n->prefix.net, n->prefix.lo, n->prefix.hi);
    }
    WALK_LIST_BACKWARDS(n, prefixes)
    {
      trie_add_prefix(trie2, &n->prefix.net, n->prefix.lo, n->prefix.hi);
    }

    bt_assert(trie_same(trie1, trie2));

    struct f_prefix_node *nxt;
    WALK_LIST_DELSAFE(n, nxt, prefixes)
    {
      free(n);
    }
  }

  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_match_net, "Testing random prefix matching");
  bt_test_suite(t_trie_same, "A trie filled forward should be same with a trie filled backward.");

  return bt_exit_value();
}
