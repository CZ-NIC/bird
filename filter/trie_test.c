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
#define PREFIXES_NUM 		32
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

static inline uint
get_exp_random(void)
{
  uint r, n = 0;

  for (r = bt_random(); r & 1; r = r >> 1)
    n++;

  return n;
}

static inline int
matching_ip4_nets(const net_addr_ip4 *a, const net_addr_ip4 *b)
{
  ip4_addr cmask = ip4_mkmask(MIN(a->pxlen, b->pxlen));
  return ip4_compare(ip4_and(a->prefix, cmask), ip4_and(b->prefix, cmask)) == 0;
}

static inline int
matching_ip6_nets(const net_addr_ip6 *a, const net_addr_ip6 *b)
{
  ip6_addr cmask = ip6_mkmask(MIN(a->pxlen, b->pxlen));
  return ip6_compare(ip6_and(a->prefix, cmask), ip6_and(b->prefix, cmask)) == 0;
}

static inline int
matching_nets(const net_addr *a, const net_addr *b)
{
  if (a->type != b->type)
    return 0;

  return (a->type == NET_IP4) ?
    matching_ip4_nets((const net_addr_ip4 *) a, (const net_addr_ip4 *) b) :
    matching_ip6_nets((const net_addr_ip6 *) a, (const net_addr_ip6 *) b);
}

static int
is_prefix_included(list *prefixes, const net_addr *needle)
{
  struct f_prefix_node *n;
  WALK_LIST(n, *prefixes)
    if (matching_nets(&n->prefix.net, needle) &&
	(n->prefix.lo <= needle->pxlen) && (needle->pxlen <= n->prefix.hi))
    {
      char buf[64];
      bt_format_net(buf, 64, &n->prefix.net);
      bt_debug("FOUND %s %d-%d\n", buf, n->prefix.lo, n->prefix.hi);

      return 1; /* OK */
    }

  return 0; /* FAIL */
}

static void
get_random_net(net_addr *net, int v6)
{
  if (!v6)
  {
    uint pxlen = xrandom(24)+8;
    ip4_addr ip4 = ip4_from_u32((u32) bt_random());
    net_fill_ip4(net, ip4_and(ip4, ip4_mkmask(pxlen)), pxlen);
  }
  else
  {
    uint pxlen = xrandom(120)+8;
    ip6_addr ip6 = ip6_build(bt_random(), bt_random(), bt_random(), bt_random());
    net_fill_ip6(net, ip6_and(ip6, ip6_mkmask(pxlen)), pxlen);
  }
}

static void
get_random_prefix(struct f_prefix *px, int v6)
{
  get_random_net(&px->net, v6);

  if (bt_random() % 2)
  {
    px->lo = 0;
    px->hi = px->net.pxlen;
  }
  else
  {
    px->lo = px->net.pxlen;
    px->hi = net_max_prefix_length[px->net.type];
  }
}

static void
get_random_ip4_subnet(net_addr_ip4 *net, const net_addr_ip4 *src, int pxlen)
{
  *net = NET_ADDR_IP4(ip4_and(src->prefix, ip4_mkmask(pxlen)), pxlen);

  if (pxlen > src->pxlen)
  {
    ip4_addr rnd = ip4_from_u32((u32) bt_random());
    ip4_addr mask = ip4_xor(ip4_mkmask(src->pxlen), ip4_mkmask(pxlen));
    net->prefix = ip4_or(net->prefix, ip4_and(rnd, mask));
  }
}

static void
get_random_ip6_subnet(net_addr_ip6 *net, const net_addr_ip6 *src, int pxlen)
{
  *net = NET_ADDR_IP6(ip6_and(src->prefix, ip6_mkmask(pxlen)), pxlen);

  if (pxlen > src->pxlen)
  {
    ip6_addr rnd = ip6_build(bt_random(), bt_random(), bt_random(), bt_random());
    ip6_addr mask = ip6_xor(ip6_mkmask(src->pxlen), ip6_mkmask(pxlen));
    net->prefix = ip6_or(net->prefix, ip6_and(rnd, mask));
  }
}

static void
get_random_subnet(net_addr *net, const net_addr *src, int pxlen)
{
  if (src->type == NET_IP4)
    get_random_ip4_subnet((net_addr_ip4 *) net, (const net_addr_ip4 *) src, pxlen);
  else
    get_random_ip6_subnet((net_addr_ip6 *) net, (const net_addr_ip6 *) src, pxlen);
}

static void
get_inner_net(net_addr *net, const struct f_prefix *src)
{
  int pxlen, step;

  if (bt_random() % 2)
  {
    step = get_exp_random();
    step = MIN(step, src->hi - src->lo);
    pxlen = (bt_random() % 2) ? (src->lo + step) : (src->hi - step);
  }
  else
    pxlen = src->lo + bt_random() % (src->hi - src->lo + 1);

  get_random_subnet(net, &src->net, pxlen);
}

static void
swap_random_bits_ip4(net_addr_ip4 *net, int num)
{
  for (int i = 0; i < num; i++)
  {
    ip4_addr swap = IP4_NONE;
    ip4_setbit(&swap, bt_random() % net->pxlen);
    net->prefix = ip4_xor(net->prefix, swap);
  }
}

static void
swap_random_bits_ip6(net_addr_ip6 *net, int num)
{
  for (int i = 0; i < num; i++)
  {
    ip6_addr swap = IP6_NONE;
    ip6_setbit(&swap, bt_random() % net->pxlen);
    net->prefix = ip6_xor(net->prefix, swap);
  }
}

static void
swap_random_bits(net_addr *net, int num)
{
  if (net->type == NET_IP4)
    swap_random_bits_ip4((net_addr_ip4 *) net, num);
  else
    swap_random_bits_ip6((net_addr_ip6 *) net, num);
}

static void
get_outer_net(net_addr *net, const struct f_prefix *src)
{
  int pxlen, step;
  int inside = 0;
  int max = net_max_prefix_length[src->net.type];

  if ((src->lo > 0) && (bt_random() % 3))
  {
    step = 1 + get_exp_random();
    step = MIN(step, src->lo);
    pxlen = src->lo - step;
  }
  else if ((src->hi < max) && (bt_random() % 2))
  {
    step = 1 + get_exp_random();
    step = MIN(step, max - src->hi);
    pxlen = src->hi + step;
  }
  else
  {
    pxlen = src->lo + bt_random() % (src->hi - src->lo + 1);
    inside = 1;
  }

  get_random_subnet(net, &src->net, pxlen);

  /* Perhaps swap some bits in prefix */
  if ((net->pxlen > 0) && (inside || (bt_random() % 4)))
    swap_random_bits(net, 1 + get_exp_random());
}

static list *
make_random_prefix_list(linpool *lp, int num, int v6)
{
  list *prefixes = lp_allocz(lp, sizeof(struct f_prefix_node));
  init_list(prefixes);

  for (int i = 0; i < num; i++)
  {
    struct f_prefix_node *px = lp_allocz(lp, sizeof(struct f_prefix_node));
    get_random_prefix(&px->prefix, v6);
    add_tail(prefixes, &px->n);

    char buf[64];
    bt_format_net(buf, 64, &px->prefix.net);
    bt_debug("ADD %s{%d,%d}\n", buf, px->prefix.lo, px->prefix.hi);
  }

  return prefixes;
}

static struct f_trie *
make_trie_from_prefix_list(linpool *lp, list *prefixes)
{
  struct f_trie *trie = f_new_trie(lp, 0);

  struct f_prefix_node *n;
  WALK_LIST(n, *prefixes)
    trie_add_prefix(trie, &n->prefix.net, n->prefix.lo, n->prefix.hi);

  return trie;
}

static void
test_match_net(list *prefixes, struct f_trie *trie, const net_addr *net)
{
  char buf[64];
  bt_format_net(buf, 64, net);
  bt_debug("TEST %s\n", buf);

  int should_be = is_prefix_included(prefixes, net);
  int is_there  = trie_match_net(trie, net);

  bt_assert_msg(should_be == is_there, "Prefix %s %s match", buf,
		(should_be ? "should" : "should not"));
}

static int
t_match_random_net(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  int v6 = 0;
  linpool *lp = lp_new_default(&root_pool);
  for (int round = 0; round < TESTS_NUM; round++)
  {
    list *prefixes = make_random_prefix_list(lp, PREFIXES_NUM, v6);
    struct f_trie *trie = make_trie_from_prefix_list(lp, prefixes);

    for (int i = 0; i < PREFIX_TESTS_NUM; i++)
    {
      net_addr net;
      get_random_net(&net, v6);
      test_match_net(prefixes, trie, &net);
    }

    v6 = !v6;
    lp_flush(lp);
  }

  bt_bird_cleanup();
  return 1;
}

static int
t_match_inner_net(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  int v6 = 0;
  linpool *lp = lp_new_default(&root_pool);
  for (int round = 0; round < TESTS_NUM; round++)
  {
    list *prefixes = make_random_prefix_list(lp, PREFIXES_NUM, v6);
    struct f_trie *trie = make_trie_from_prefix_list(lp, prefixes);

    struct f_prefix_node *n = HEAD(*prefixes);
    for (int i = 0; i < PREFIX_TESTS_NUM; i++)
    {
      net_addr net;
      get_inner_net(&net, &n->prefix);
      test_match_net(prefixes, trie, &net);

      n = NODE_VALID(NODE_NEXT(n)) ? NODE_NEXT(n) : HEAD(*prefixes);
    }

    v6 = !v6;
    lp_flush(lp);
  }

  bt_bird_cleanup();
  return 1;
}

static int
t_match_outer_net(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  int v6 = 0;
  linpool *lp = lp_new_default(&root_pool);
  for (int round = 0; round < TESTS_NUM; round++)
  {
    list *prefixes = make_random_prefix_list(lp, PREFIXES_NUM, v6);
    struct f_trie *trie = make_trie_from_prefix_list(lp, prefixes);

    struct f_prefix_node *n = HEAD(*prefixes);
    for (int i = 0; i < PREFIX_TESTS_NUM; i++)
    {
      net_addr net;
      get_outer_net(&net, &n->prefix);
      test_match_net(prefixes, trie, &net);

      n = NODE_VALID(NODE_NEXT(n)) ? NODE_NEXT(n) : HEAD(*prefixes);
    }

    v6 = !v6;
    lp_flush(lp);
  }

  v6 = !v6;
  bt_bird_cleanup();
  return 1;
}

static int
t_trie_same(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  int v6 = 0;
  linpool *lp = lp_new_default(&root_pool);
  for (int round = 0; round < TESTS_NUM*4; round++)
  {
    list *prefixes = make_random_prefix_list(lp, 100 * PREFIXES_NUM, v6);
    struct f_trie *trie1 = f_new_trie(lp, 0);
    struct f_trie *trie2 = f_new_trie(lp, 0);

    struct f_prefix_node *n;
    WALK_LIST(n, *prefixes)
      trie_add_prefix(trie1, &n->prefix.net, n->prefix.lo, n->prefix.hi);

    WALK_LIST_BACKWARDS(n, *prefixes)
      trie_add_prefix(trie2, &n->prefix.net, n->prefix.lo, n->prefix.hi);

    bt_assert(trie_same(trie1, trie2));

    v6 = !v6;
    lp_flush(lp);
  }

  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_match_random_net, "Testing random prefix matching");
  bt_test_suite(t_match_inner_net, "Testing random inner prefix matching");
  bt_test_suite(t_match_outer_net, "Testing random outer prefix matching");
  bt_test_suite(t_trie_same, "A trie filled forward should be same with a trie filled backward.");

  return bt_exit_value();
}
