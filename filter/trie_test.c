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
#define PREFIX_BENCH_NUM 	100000000

#define TRIE_BUFFER_SIZE	1024
#define TEST_BUFFER_SIZE	(1024*1024)
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

static int
compare_prefixes(const void *a, const void *b)
{
  return net_compare(&((const struct f_prefix *) a)->net,
		     &((const struct f_prefix *) b)->net);
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
get_random_prefix(struct f_prefix *px, int v6, int tight)
{
  get_random_net(&px->net, v6);

  if (tight)
  {
    px->lo = px->hi = px->net.pxlen;
  }
  else if (bt_random() % 2)
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
make_random_prefix_list(int num, int v6, int tight)
{
  list *prefixes = lp_allocz(tmp_linpool, sizeof(struct f_prefix_node));
  init_list(prefixes);

  for (int i = 0; i < num; i++)
  {
    struct f_prefix_node *px = lp_allocz(tmp_linpool, sizeof(struct f_prefix_node));
    get_random_prefix(&px->prefix, v6, tight);
    add_tail(prefixes, &px->n);
  }

  return prefixes;
}

static struct f_trie *
make_trie_from_prefix_list(list *prefixes)
{
  struct f_trie *trie = f_new_trie(tmp_linpool, 0);

  struct f_prefix_node *n;
  WALK_LIST(n, *prefixes)
    trie_add_prefix(trie, &n->prefix.net, n->prefix.lo, n->prefix.hi);

  return trie;
}

/*
 * Read sequence of prefixes from file handle and return prefix list.
 * Each prefix is on one line, sequence terminated by empty line or eof.
 * Arg @plus means prefix should include all longer ones.
 */
static list *
read_prefix_list(FILE *f, int v6, int plus)
{
  ASSERT(!v6);

  uint a0, a1, a2, a3, pl;
  char s[32];
  int n;

  list *pxlist = lp_allocz(tmp_linpool, sizeof(struct f_prefix_node));
  init_list(pxlist);

  errno = 0;
  while (fgets(s, 32, f))
  {
    if (s[0] == '\n')
      return pxlist;

    n = sscanf(s, "%u.%u.%u.%u/%u", &a0, &a1, &a2, &a3, &pl);

    if (n != 5)
      bt_abort_msg("Invalid content of trie_data");

    struct f_prefix_node *px = lp_allocz(tmp_linpool, sizeof(struct f_prefix_node));
    net_fill_ip4(&px->prefix.net, ip4_build(a0, a1, a2, a3), pl);
    px->prefix.lo = pl;
    px->prefix.hi = plus ? IP4_MAX_PREFIX_LENGTH : pl;
    add_tail(pxlist, &px->n);
  }

  bt_syscall(errno, "fgets()");
  return EMPTY_LIST(*pxlist) ? NULL : pxlist;
}

/*
 * Open file, read multiple sequences of prefixes from it. Fill @data with
 * prefix lists and @trie with generated tries. Return number of sequences /
 * tries. Use separate linpool @lp0 for prefix lists and @lp1 for tries.
 * Arg @plus means prefix should include all longer ones.
 */
static int
read_prefix_file(const char *filename, int plus,
		 list *data[], struct f_trie *trie[])
{
  FILE *f = fopen(filename, "r");
  bt_syscall(!f, "fopen(%s)", filename);

  int n = 0;
  list *pxlist;
  while (pxlist = read_prefix_list(f, 0, plus))
  {
    data[n] = pxlist;
    trie[n] = make_trie_from_prefix_list(pxlist);
    bt_debug("NEXT\n");
    n++;
  }

  fclose(f);
  bt_debug("DONE reading %d tries\n", n);

  return n;
}

/*
 * Select random subset of @dn prefixes from prefix list @src of length @sn,
 * and store them to buffer @dst (of size @dn). Prefixes may be chosen multiple
 * times. Randomize order of prefixes in @dst buffer.
 */
static void
select_random_prefix_subset(list *src[], net_addr dst[], int sn, int dn)
{
  int pn = 0;

  if (!dn)
    return;

  /* Compute total prefix number */
  for (int i = 0; i < sn; i++)
    pn += list_length(src[i]);

  /* Change of selecting a prefix */
  int rnd = (pn / dn) + 10;
  int n = 0;

  /* Iterate indefinitely over src array */
  for (int i = 0; 1; i++, i = (i < sn) ? i : 0)
  {
    struct f_prefix_node *px;
    WALK_LIST(px, *src[i])
    {
      if (xrandom(rnd) != 0)
	continue;

      net_copy(&dst[n], &px->prefix.net);
      n++;

      /* We have enough */
      if (n == dn)
	goto done;
    }
  }

done:
  /* Shuffle networks */
  for (int i = 0; i < dn; i++)
  {
    int j = xrandom(dn);

    if (i == j)
      continue;

    net_addr tmp;
    net_copy(&tmp, &dst[i]);
    net_copy(&dst[i], &dst[j]);
    net_copy(&dst[j], &tmp);
  }
}

/* Fill @dst buffer with @dn randomly generated /32 prefixes */
static void
make_random_addresses(net_addr dst[], int dn)
{
  for (int i = 0; i < dn; i++)
    net_fill_ip4(&dst[i], ip4_from_u32((u32) bt_random()), IP4_MAX_PREFIX_LENGTH);
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
  for (int round = 0; round < TESTS_NUM; round++)
  {
    list *prefixes = make_random_prefix_list(PREFIXES_NUM, v6, 0);
    struct f_trie *trie = make_trie_from_prefix_list(prefixes);

    for (int i = 0; i < PREFIX_TESTS_NUM; i++)
    {
      net_addr net;
      get_random_net(&net, v6);
      test_match_net(prefixes, trie, &net);
    }

    v6 = !v6;
    tmp_flush();
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
  for (int round = 0; round < TESTS_NUM; round++)
  {
    list *prefixes = make_random_prefix_list(PREFIXES_NUM, v6, 0);
    struct f_trie *trie = make_trie_from_prefix_list(prefixes);

    struct f_prefix_node *n = HEAD(*prefixes);
    for (int i = 0; i < PREFIX_TESTS_NUM; i++)
    {
      net_addr net;
      get_inner_net(&net, &n->prefix);
      test_match_net(prefixes, trie, &net);

      n = NODE_VALID(NODE_NEXT(n)) ? NODE_NEXT(n) : HEAD(*prefixes);
    }

    v6 = !v6;
    tmp_flush();
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
  for (int round = 0; round < TESTS_NUM; round++)
  {
    list *prefixes = make_random_prefix_list(PREFIXES_NUM, v6, 0);
    struct f_trie *trie = make_trie_from_prefix_list(prefixes);

    struct f_prefix_node *n = HEAD(*prefixes);
    for (int i = 0; i < PREFIX_TESTS_NUM; i++)
    {
      net_addr net;
      get_outer_net(&net, &n->prefix);
      test_match_net(prefixes, trie, &net);

      n = NODE_VALID(NODE_NEXT(n)) ? NODE_NEXT(n) : HEAD(*prefixes);
    }

    v6 = !v6;
    tmp_flush();
  }

  v6 = !v6;
  bt_bird_cleanup();
  return 1;
}

/*
 * Read prefixes from @filename, build set of tries, prepare test data and do
 * PREFIX_BENCH_NUM trie lookups. With @plus = 0, use random subset of known
 * prefixes as test data, with @plus = 1, use randomly generated /32 prefixes
 * as test data.
 */
static int
benchmark_trie_dataset(const char *filename, int plus)
{
  int n = 0;
  list *data[TRIE_BUFFER_SIZE];
  struct f_trie *trie[TRIE_BUFFER_SIZE];
  net_addr *nets;

  bt_reset_suite_case_timer();
  bt_log_suite_case_result(1, "Reading %s", filename, n);
  n = read_prefix_file(filename, plus, data, trie);
  bt_log_suite_case_result(1, "Read prefix data, %d lists, ", n);

  size_t trie_size = rmemsize(tmp_linpool).effective * 1000 / (1024*1024);
  bt_log_suite_case_result(1, "Trie size %u.%03u MB",
			   (uint) (trie_size / 1000), (uint) (trie_size % 1000));

  int t = PREFIX_BENCH_NUM / n;
  int tb = MIN(t, TEST_BUFFER_SIZE);
  nets = tmp_alloc(tb * sizeof(net_addr));

  if (!plus)
    select_random_prefix_subset(data, nets, n, tb);
  else
    make_random_addresses(nets, tb);

  bt_log_suite_case_result(1, "Make test data, %d (%d) tests", t, tb);
  bt_reset_suite_case_timer();

  /*
  int match = 0;
  for (int i = 0; i < t; i++)
    for (int j = 0; j < n; j++)
      test_match_net(data[j], trie[j], &nets[i]);
  */

  int match = 0;
  for (int i = 0; i < t; i++)
    for (int j = 0; j < n; j++)
      if (trie_match_net(trie[j], &nets[i % TEST_BUFFER_SIZE]))
	match++;

  bt_log_suite_case_result(1, "Matching done, %d / %d matches", match, t * n);

  tmp_flush();
  return 1;
}

static int UNUSED
t_bench_trie_datasets_subset(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  /* Specific datasets, not included */
  benchmark_trie_dataset("trie-data-bgp-1", 0);
  benchmark_trie_dataset("trie-data-bgp-10", 0);
  benchmark_trie_dataset("trie-data-bgp-100", 0);
  benchmark_trie_dataset("trie-data-bgp-1000", 0);

  bt_bird_cleanup();

  return 1;
}

static int UNUSED
t_bench_trie_datasets_random(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  /* Specific datasets, not included */
  benchmark_trie_dataset("trie-data-bgp-1", 1);
  benchmark_trie_dataset("trie-data-bgp-10", 1);
  benchmark_trie_dataset("trie-data-bgp-100", 1);
  benchmark_trie_dataset("trie-data-bgp-1000", 1);

  bt_bird_cleanup();

  return 1;
}


static int
t_trie_same(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  int v6 = 0;
  for (int round = 0; round < TESTS_NUM*4; round++)
  {
    list *prefixes = make_random_prefix_list(100 * PREFIXES_NUM, v6, 0);
    struct f_trie *trie1 = f_new_trie(tmp_linpool, 0);
    struct f_trie *trie2 = f_new_trie(tmp_linpool, 0);

    struct f_prefix_node *n;
    WALK_LIST(n, *prefixes)
      trie_add_prefix(trie1, &n->prefix.net, n->prefix.lo, n->prefix.hi);

    WALK_LIST_BACKWARDS(n, *prefixes)
      trie_add_prefix(trie2, &n->prefix.net, n->prefix.lo, n->prefix.hi);

    bt_assert(trie_same(trie1, trie2));

    v6 = !v6;
    tmp_flush();
  }

  bt_bird_cleanup();
  return 1;
}

static inline void
log_networks(const net_addr *a, const net_addr *b)
{
  if (bt_verbose >= BT_VERBOSE_ABSOLUTELY_ALL)
  {
    char buf0[64];
    char buf1[64];
    bt_format_net(buf0, 64, a);
    bt_format_net(buf1, 64, b);
    bt_debug("Found %s expected %s\n", buf0, buf1);
  }
}

static void
test_walk_return_val(struct f_trie *trie, struct f_prefix pxset[], uint count, int include)
{
  if (count == 0)
  {
    net_addr net;
    get_random_net(&net, !trie->ipv4);
    struct f_trie_walk_state tws;
    bt_assert(!trie_walk_init(&tws, trie, &net, include));

    net_addr res;
    bt_assert(!trie_walk_next(&tws, &res));
    return;
  }

  u32 index = xrandom(count);
  net_addr *tested = &pxset[index].net;

  net_addr res;
  struct f_trie_walk_state tws;
  bt_assert(trie_walk_init(&tws, trie, tested, include)); /* return true */
  bt_assert(trie_walk_next(&tws, &res));
  bt_assert(net_equal(tested, &res));

  net_addr rand_net;
  get_random_net(&rand_net, !trie->ipv4);

  for (u32 i = 0; i < count; i++)
  {
    if (net_equal(&pxset[i].net, &rand_net))
      return;
  }

  memset(&res, 0, sizeof(res));
  memset(&tws, 0, sizeof(tws));
  bt_assert(!trie_walk_init(&tws, trie, &rand_net, include)); /* return false */

  if (include)
  {
    if (net_compare(&pxset[count - 1].net, &rand_net) < 0)
      bt_assert(!trie_walk_next(&tws, &res));
    else
    {
      bt_assert(trie_walk_next(&tws, &res));
      bt_assert(net_compare(&rand_net, &res) < 0);
    }
  }
  else
  {
    u32 pos;
    for (pos = 0; pos < count; pos++)
      if (net_compare(&pxset[pos].net, &rand_net) > 0)
	break;

    if (pos < count && net_in_netX(&pxset[pos].net, &rand_net))
    {
      bt_assert(trie_walk_next(&tws, &res));
      bt_assert(net_equal(&pxset[pos].net, &res));
    }
    else
    {
      bt_assert(!trie_walk_next(&tws, &res));
    }
  }
}

static int
t_trie_walk(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  unsigned long r = rand();
  log("random seed for t_trie_walk is %lu", r);
  srandom(r);
  //srandom(732437807);
  //srandom(1182332329);

  for (int round = 0; round < TESTS_NUM*8; round++)
  {
    int level = round / TESTS_NUM;
    int v6 = level % 2;
    int num = PREFIXES_NUM * (int[]){0, 1, 10, 100, 1000}[level / 2];
    int pos = 0, end = 0;
    list *prefixes = make_random_prefix_list(num, v6, 1);
    struct f_trie *trie = make_trie_from_prefix_list(prefixes);
    struct f_prefix *pxset = malloc((num + 1) * sizeof(struct f_prefix));

    struct f_prefix_node *n;
    WALK_LIST(n, *prefixes)
      pxset[pos++] = n->prefix;
    memset(&pxset[pos], 0, sizeof (struct f_prefix));

    qsort(pxset, num, sizeof(struct f_prefix), compare_prefixes);

    /* Test trie_walk_init() return value */
    test_walk_return_val(trie, pxset, num, 0);

    /* Full walk */
    bt_debug("Full walk (round %d, %d nets)\n", round, num);

    pos = 0;
    uint pxc = 0;
    TRIE_WALK(trie, net, NULL)
    {
      log_networks(&net, &pxset[pos].net);
      bt_assert(net_equal(&net, &pxset[pos].net));

      /* Skip possible duplicates */
      while (net_equal(&pxset[pos].net, &pxset[pos + 1].net))
	pos++;

      pos++;
      pxc++;
    }
    TRIE_WALK_END;

    bt_assert(pos == num);
    bt_assert(pxc == trie->prefix_count);
    bt_debug("Full walk done\n");

    /* Prepare net for subnet walk - start with random prefix */
    if (num)
      pos = xrandom(num);
    else
      pos = 0;
    end = pos + (int[]){2, 2, 3, 4}[level / 2];
    end = MIN(end, num);

    struct f_prefix from;
    if (num)
      from = pxset[pos];
    else
      get_random_prefix(&from, v6, 1);

    /* Find a common superprefix to several subsequent prefixes */
    for (; pos < end; pos++)
    {
      if (net_equal(&from.net, &pxset[pos].net))
	continue;

      int common = !v6 ?
	ip4_pxlen(net4_prefix(&from.net), net4_prefix(&pxset[pos].net)) :
	ip6_pxlen(net6_prefix(&from.net), net6_prefix(&pxset[pos].net));
      from.net.pxlen = MIN(from.net.pxlen, common);

      if (!v6)
	((net_addr_ip4 *) &from.net)->prefix =
	  ip4_and(net4_prefix(&from.net), net4_prefix(&pxset[pos].net));
      else
	((net_addr_ip6 *) &from.net)->prefix =
	  ip6_and(net6_prefix(&from.net), net6_prefix(&pxset[pos].net));
    }

    /* Fix irrelevant bits */
    if (!v6)
      ((net_addr_ip4 *) &from.net)->prefix =
	ip4_and(net4_prefix(&from.net), ip4_mkmask(net4_pxlen(&from.net)));
    else
      ((net_addr_ip6 *) &from.net)->prefix =
	ip6_and(net6_prefix(&from.net), ip6_mkmask(net6_pxlen(&from.net)));


    /* Find initial position for final prefix */
    for (pos = 0; pos < num; pos++)
      if (compare_prefixes(&pxset[pos], &from) >= 0)
	break;

    int p0 = pos;
    char buf0[64];
    bt_format_net(buf0, 64, &from.net);
    bt_debug("Subnet walk for %s (round %d, %d nets)\n", buf0, round, num);

    /* Subnet walk */
    TRIE_WALK(trie, net, &from.net)
    {
      log_networks(&net, &pxset[pos].net);
      bt_assert(net_equal(&net, &pxset[pos].net));
      bt_assert(net_in_netX(&net, &from.net));

      /* Skip possible duplicates */
      while (net_equal(&pxset[pos].net, &pxset[pos + 1].net))
	pos++;

      pos++;
    }
    TRIE_WALK_END;

    bt_assert((pos == num) || !net_in_netX(&pxset[pos].net, &from.net));
    bt_debug("Subnet walk done for %s (found %d nets)\n", buf0, pos - p0);

    tmp_flush();
  }

  bt_bird_cleanup();
  return 1;
}

static int
find_covering_nets(struct f_prefix *prefixes, int num, const net_addr *net, net_addr *found)
{
  struct f_prefix key;
  net_addr *n = &key.net;
  int found_num = 0;

  net_copy(n, net);

  while (1)
  {
    struct f_prefix *px =
      bsearch(&key, prefixes, num, sizeof(struct f_prefix), compare_prefixes);

    if (px)
    {
      net_copy(&found[found_num], n);
      found_num++;
    }

    if (n->pxlen == 0)
      return found_num;

    n->pxlen--;

    if (n->type == NET_IP4)
      ip4_clrbit(&((net_addr_ip4 *) n)->prefix, n->pxlen);
    else
      ip6_clrbit(&((net_addr_ip6 *) n)->prefix, n->pxlen);
  }
}

static int
t_trie_walk_to_root(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  for (int round = 0; round < TESTS_NUM * 4; round++)
  {
    int level = round / TESTS_NUM;
    int v6 = level % 2;
    int num = PREFIXES_NUM  * (int[]){32, 512}[level / 2];
    int pos = 0;
    int st = 0, sn = 0, sm = 0;

    list *prefixes = make_random_prefix_list(num, v6, 1);
    struct f_trie *trie = make_trie_from_prefix_list(prefixes);
    struct f_prefix *pxset = malloc((num + 1) * sizeof(struct f_prefix));

    struct f_prefix_node *pxn;
    WALK_LIST(pxn, *prefixes)
      pxset[pos++] = pxn->prefix;
    memset(&pxset[pos], 0, sizeof (struct f_prefix));

    qsort(pxset, num, sizeof(struct f_prefix), compare_prefixes);

    int i;
    for (i = 0; i < (PREFIX_TESTS_NUM / 10); i++)
    {
      net_addr from;
      get_random_net(&from, v6);

      net_addr found[129];
      int found_num = find_covering_nets(pxset, num, &from, found);
      int n = 0;

      if (bt_verbose >= BT_VERBOSE_ABSOLUTELY_ALL)
      {
	char buf[64];
	bt_format_net(buf, 64, &from);
	bt_debug("Lookup for %s (expect %d)\n", buf, found_num);
      }

      /* Walk to root, separate for IPv4 and IPv6 */
      if (!v6)
      {
	TRIE_WALK_TO_ROOT_IP4(trie, (net_addr_ip4 *) &from, net)
	{
	  log_networks((net_addr *) &net, &found[n]);
	  bt_assert((n < found_num) && net_equal((net_addr *) &net, &found[n]));
	  n++;
	}
	TRIE_WALK_TO_ROOT_END;
      }
      else
      {
	TRIE_WALK_TO_ROOT_IP6(trie, (net_addr_ip6 *) &from, net)
	{
	  log_networks((net_addr *) &net, &found[n]);
	  bt_assert((n < found_num) && net_equal((net_addr *) &net, &found[n]));
	  n++;
	}
	TRIE_WALK_TO_ROOT_END;
      }

      bt_assert(n == found_num);

      /* Stats */
      st += n;
      sn += !!n;
      sm = MAX(sm, n);
    }

    bt_debug("Success in %d / %d, sum %d, max %d\n", sn, i, st, sm);

    tmp_flush();
  }

  bt_bird_cleanup();
  return 1;
}

static inline void
test_walk_init(struct f_trie *trie, u32 in_px, u32 in_plen, u32 res_px, u32 res_plen, int has_next)
{
      net_addr_ip4 net = NET_ADDR_IP4(ip4_from_u32(in_px), in_plen);
      struct f_trie_walk_state tws;
      /* return value of trie_walk_init() is tested elsewhere */
      trie_walk_init(&tws, trie, (struct net_addr *) &net, 1);
      net_addr res;
      int b = trie_walk_next(&tws, &res);
      bt_assert(b == has_next);
      if (has_next)
      {
	net_addr_ip4 expected = NET_ADDR_IP4(ip4_from_u32(res_px), res_plen);
	bt_assert(net_equal_ip4((struct net_addr_ip4 *) &res, &expected));
      }
}

/*
 * a very simplistic and deterministic test suite to test all reasoable code paths in
 * trie_walk_init()
 */
static int
t_trie_walk_determ(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  #define EDGE_CASE_COUNT 7
  list *prefixes[EDGE_CASE_COUNT] = { 0 };
  struct f_trie *tries[EDGE_CASE_COUNT] = { 0 };

  bt_debug("Reading data from 'filter/trie-data-edge'\n");
  int n = read_prefix_file("filter/trie-data-edge", 0, prefixes, tries);
  bt_debug("Read data from 'trie-data-edge' %d lists\n", n);

  if (n < EDGE_CASE_COUNT)
  {
    bt_debug("Loaded less lists than expected!\n");
    return 0;
  }

  test_walk_init(tries[0], 100663296,  7 /* 6.0.0.0/7       */, 297795584, 12 /* 17.192.0.0/12   */, 1);
  test_walk_init(tries[0], 201326592, 12 /* 12.0.0.0/12     */, 297795584, 12 /* 17.192.0.0/12   */, 1);
  test_walk_init(tries[0], 297795584, 14 /* 17.192.0.0/14   */, 297811968, 18 /* 17.192.64.00/18 */, 1);
  test_walk_init(tries[0], 297795584, 18 /* 17.192.0.0/24   */, 297811968, 18 /* 17.192.64.00/18 */, 1);
  test_walk_init(tries[0], 297798400, 24 /* 17.192.11.0/24  */, 297811968, 18 /* 17.192.64.0/18  */, 1);
  test_walk_init(tries[0], 297811968, 28 /* 17.192.64.0/28  */, 297811984, 28 /* 17.192.64.16/28 */, 1);
  test_walk_init(tries[0], 297811980, 31 /* 17.192.64.12/31 */, 297811984, 28 /* 17.192.64.16/28 */, 1);

  /*
   * ==============================
   *  Tests on left leaning trie
   */
  struct f_trie *left = tries[1];
  test_walk_init(left,         0,  4 /* 0.0.0.0/4       */,  16777216, 12 /* 1.0.0.0/12 */, 1);
  test_walk_init(left,         0, 12 /* 0.0.0.0/12      */,  16777216, 12 /* 1.0.0.0/12 */, 1);
  test_walk_init(left,         0, 24 /* 0.0.0.0/24      */,  16777216, 12 /* 1.0.0.0/12 */, 1);
  test_walk_init(left,         0, 32 /* 0.0.0.0/32      */,  16777216, 12 /* 1.0.0.0/12 */, 1);
  test_walk_init(left,  16777216, 12 /* 1.0.0.0/12      */,  16777216, 12 /* 1.0.0.0/12 */, 1);
  test_walk_init(left,  16777216, 14 /* 1.0.0.0/14      */,  16842752, 18 /* 1.1.0.0/18 */, 1);
  test_walk_init(left,  16777216, 16 /* 1.0.0.0/16      */,  16842752, 18 /* 1.1.0.0/18 */, 1);
  test_walk_init(left,  16777216, 18 /* 1.0.0.0/18      */,  16842752, 18 /* 1.1.0.0/18 */, 1);
  test_walk_init(left,  16842753, 18 /* 1.1.0.0/18      */,  16842752, 18 /* 1.1.0.0/18 */, 1);
  test_walk_init(left,  16842753, 20 /* 1.1.0.0/20      */,  16843008, 28 /* 1.1.1.0/28 */, 1);
  test_walk_init(left,  16842753, 24 /* 1.1.0.0/24      */,  16843008, 28 /* 1.1.1.0/28 */, 1);
  test_walk_init(left,  16842753, 28 /* 1.1.0.0/28      */,  16843008, 28 /* 1.1.1.0/28 */, 1);
  test_walk_init(left,  16842753, 30 /* 1.1.0.0/30      */,  16843008, 28 /* 1.1.1.0/28 */, 1);
  test_walk_init(left,  16842753, 32 /* 1.1.0.0/32      */,  16843008, 28 /* 1.1.1.0/28 */, 1);

  /* longest path or it's extension */
  test_walk_init(left,  16843009, 28 /* 1.1.1.0/28      */,  16843008, 28 /* 1.1.1.0/28 */, 1);
  test_walk_init(left,  16843009, 30 /* 1.1.1.0/30      */,  16843520, 28 /* 1.1.3.0/28 */, 1);
  test_walk_init(left,  16843009, 32 /* 1.1.1.0/32      */,  16843520, 28 /* 1.1.3.0/28 */, 1);

  /* prefixes `after' longest path */
  test_walk_init(left,  16843264, 23 /* 1.1.2.0/23      */,  16843520, 28 /* 1.1.3.0/28 */, 1);
  test_walk_init(left,  16843264, 24 /* 1.1.2.0/24      */,  16843520, 28 /* 1.1.3.0/28 */, 1);
  test_walk_init(left,  16843264, 26 /* 1.1.2.0/26      */,  16843520, 28 /* 1.1.3.0/28 */, 1);
  test_walk_init(left,  16843264, 28 /* 1.1.2.0/28      */,  16843520, 28 /* 1.1.3.0/28 */, 1);
  test_walk_init(left,  16843264, 32 /* 1.1.2.0/32      */,  16843520, 28 /* 1.1.3.0/28 */, 1);
  test_walk_init(left,  16843521, 28 /* 1.1.3.0/28      */,  16843520, 28 /* 1.1.3.0/28 */, 1);

  /* extension of longest path */
  test_walk_init(left,  16843521, 30 /* 1.1.3.0/30      */,  16844032, 28 /* 1.1.5.0/28 */, 1);
  test_walk_init(left,  16843521, 32 /* 1.1.3.0/32      */,  16844032, 28 /* 1.1.5.0/28 */, 1);

  test_walk_init(left,  16844544, 28 /* 1.1.7.0/28      */,  16844544, 28 /* 1.1.7.0/28 */, 1);
  test_walk_init(left,  16844544, 30 /* 1.1.7.0/30      */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16844544, 32 /* 1.1.7.0/32      */,  16973824, 18 /* 1.3.0.0/18 */, 1);

  test_walk_init(left,  16844801, 24 /* 1.1.8.0/24      */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16844801, 28 /* 1.1.8.0/28      */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16844801, 32 /* 1.1.8.0/32      */,  16973824, 18 /* 1.3.0.0/18 */, 1);

  test_walk_init(left,  16908290, 16 /* 1.2.0.0/16      */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16908290, 18 /* 1.2.0.0/18      */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16908290, 22 /* 1.2.0.0/22      */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16908290, 24 /* 1.2.0.0/24      */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16908290, 28 /* 1.2.0.0/28      */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16908290, 30 /* 1.2.0.0/30      */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16908290, 32 /* 1.2.0.0/32      */,  16973824, 18 /* 1.3.0.0/18 */, 1);

  test_walk_init(left,  16973827, 18 /* 1.3.0.0/18      */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16973827, 20 /* 1.3.0.0/20      */,  17104896, 18 /* 1.5.0.0/18 */, 1);
  test_walk_init(left,  16973827, 22 /* 1.3.0.0/22      */,  17104896, 18 /* 1.5.0.0/18 */, 1);
  test_walk_init(left,  16973827, 24 /* 1.3.0.0/24      */,  17104896, 18 /* 1.5.0.0/18 */, 1);
  test_walk_init(left,  16973827, 28 /* 1.3.0.0/28      */,  17104896, 18 /* 1.5.0.0/18 */, 1);
  test_walk_init(left,  16973827, 30 /* 1.3.0.0/30      */,  17104896, 18 /* 1.5.0.0/18 */, 1);
  test_walk_init(left,  16973827, 32 /* 1.3.0.0/32      */,  17104896, 18 /* 1.5.0.0/18 */, 1);

  test_walk_init(left,  33554432,  9 /* 2.0.0.0/9       */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  33554432, 12 /* 2.0.0.0/12      */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  33554432, 14 /* 2.0.0.0/14      */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  33554432, 18 /* 2.0.0.0/18      */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  33554432, 22 /* 2.0.0.0/22      */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  33554432, 28 /* 2.0.0.0/28      */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  33554432, 30 /* 2.0.0.0/30      */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  33554432, 32 /* 2.0.0.0/32      */,  50331648, 12 /* 3.0.0.0/12 */, 1);

  test_walk_init(left,  50659333, 18 /* 3.5.0.0/18      */,  50659328, 18 /* 3.5.0.0/18 */, 1);
  test_walk_init(left,  50659333, 19 /* 3.5.0.0/19      */,  83886080, 12 /* 5.0.0.0/12 */, 1);
  test_walk_init(left,  50659333, 32 /* 3.5.0.0/32      */,  83886080, 12 /* 5.0.0.0/12 */, 1);
  test_walk_init(left,  50659589, 30 /* 3.5.1.0/30      */,  83886080, 12 /* 5.0.0.0/12 */, 1);
  test_walk_init(left,  50659845, 32 /* 3.5.2.0/32      */,  83886080, 12 /* 5.0.0.0/12 */, 1);
  test_walk_init(left,  50724870, 16 /* 3.6.0.0/16      */,  83886080, 12 /* 5.0.0.0/12 */, 1);
  test_walk_init(left,  50724870, 18 /* 3.6.0.0/18      */,  83886080, 12 /* 5.0.0.0/12 */, 1);

  test_walk_init(left,  67108864,  6 /* 4.0.0.0/6       */,  83886080, 12 /* 5.0.0.0/12 */, 1);
  test_walk_init(left,  67108864, 12 /* 4.0.0.0/12      */,  83886080, 12 /* 5.0.0.0/12 */, 1);
  test_walk_init(left,  67108864, 14 /* 4.0.0.0/14      */,  83886080, 12 /* 5.0.0.0/12 */, 1);
  test_walk_init(left,  67108864, 18 /* 4.0.0.0/18      */,  83886080, 12 /* 5.0.0.0/12 */, 1);
  test_walk_init(left,  67108864, 20 /* 4.0.0.0/20      */,  83886080, 12 /* 5.0.0.0/12 */, 1);
  test_walk_init(left,  67108864, 28 /* 4.0.0.0/28      */,  83886080, 12 /* 5.0.0.0/12 */, 1);
  test_walk_init(left,  67108864, 30 /* 4.0.0.0/30      */,  83886080, 12 /* 5.0.0.0/12 */, 1);
  test_walk_init(left,  67108864, 32 /* 4.0.0.0/32      */,  83886080, 12 /* 5.0.0.0/12 */, 1);
  test_walk_init(left,  83886080, 10 /* 5.0.0.0/10      */,  83886080, 12 /* 5.0.0.0/12 */, 1);

  test_walk_init(left,  83886080, 14 /* 5.0.0.0/14      */,  83951616, 28 /* 5.1.0.0/28 */, 1);
  test_walk_init(left,  83886080, 28 /* 5.0.0.0/28      */,  83951616, 28 /* 5.1.0.0/28 */, 1);
  test_walk_init(left,  83886080, 30 /* 5.0.0.0/30      */,  83951616, 28 /* 5.1.0.0/28 */, 1);
  test_walk_init(left,  83886080, 32 /* 5.0.0.0/32      */,  83951616, 28 /* 5.1.0.0/28 */, 1);

  test_walk_init(left,  83951617, 30 /* 5.1.0.0/30      */, 117440512, 12 /* 7.0.0.0/12 */, 1);
  test_walk_init(left,  83951617, 32 /* 5.1.0.0/32      */, 117440512, 12 /* 7.0.0.0/12 */, 1);
  test_walk_init(left,  84017154, 32 /* 5.2.0.0/32      */, 117440512, 12 /* 7.0.0.0/12 */, 1);
  test_walk_init(left, 100663296,  8 /* 6.0.0.0/8       */, 117440512, 12 /* 7.0.0.0/12 */, 1);
  test_walk_init(left, 100663296, 12 /* 6.0.0.0/12      */, 117440512, 12 /* 7.0.0.0/12 */, 1);
  test_walk_init(left, 100663296, 16 /* 6.0.0.0/16      */, 117440512, 12 /* 7.0.0.0/12 */, 1);
  test_walk_init(left, 100663296, 18 /* 6.0.0.0/18      */, 117440512, 12 /* 7.0.0.0/12 */, 1);
  test_walk_init(left, 100663296, 22 /* 6.0.0.0/22      */, 117440512, 12 /* 7.0.0.0/12 */, 1);
  test_walk_init(left, 100663296, 32 /* 6.0.0.0/32      */, 117440512, 12 /* 7.0.0.0/12 */, 1);
  test_walk_init(left, 117440512,  9 /* 7.0.0.0/9       */, 117440512, 12 /* 7.0.0.0/12 */, 1);
  test_walk_init(left, 117440512, 12 /* 7.0.0.0/12      */, 117440512, 12 /* 7.0.0.0/12 */, 1);

  test_walk_init(left, 117440512, 13 /* 7.0.0.0/13      */,         0,  0 /* N/A        */, 0);
  test_walk_init(left, 117440512, 23 /* 7.0.0.0/23      */,         0,  0 /* N/A        */, 0);
  test_walk_init(left, 117440512, 32 /* 7.0.0.0/32      */,         0,  0 /* N/A        */, 0);
  test_walk_init(left, 117506049, 20 /* 7.1.0.0/20      */,         0,  0 /* N/A        */, 0);
  test_walk_init(left, 117506049, 32 /* 7.1.0.0/32      */,         0,  0 /* N/A        */, 0);
  test_walk_init(left, 134217728,  9 /* 8.0.0.0/9       */,         0,  0 /* N/A        */, 0);
  test_walk_init(left, 134217728, 14 /* 8.0.0.0/14      */,         0,  0 /* N/A        */, 0);
  test_walk_init(left, 134283265, 32 /* 8.1.0.0/32      */,         0,  0 /* N/A        */, 0);

  test_walk_init(left,   4194368, 24 /* 0.64.0.0/24     */,  16777216, 12 /* 1.0.0.0/12 */, 1);
  test_walk_init(left,   4196160, 24 /* 0.64.7.0/24     */,  16777216, 12 /* 1.0.0.0/12 */, 1);
  test_walk_init(left,   4229952, 25 /* 0.64.139.0/25   */,  16777216, 12 /* 1.0.0.0/12 */, 1);
  test_walk_init(left,   4259648, 26 /* 0.64.255.0/26   */,  16777216, 12 /* 1.0.0.0/12 */, 1);
  test_walk_init(left,   8388736, 24 /* 0.128.0.0/24    */,  16777216, 12 /* 1.0.0.0/12 */, 1);
  test_walk_init(left,   8390528, 25 /* 0.128.7.0/25    */,  16777216, 12 /* 1.0.0.0/12 */, 1);
  test_walk_init(left,   8450176, 22 /* 0.128.240.0/22  */,  16777216, 12 /* 1.0.0.0/12 */, 1);
  test_walk_init(left,   8453760, 23 /* 0.128.254.0/23  */,  16777216, 12 /* 1.0.0.0/12 */, 1);
  test_walk_init(left,2147483648,  3 /* 128.0.0.0/3     */,         0,  0 /* N/A        */, 0);
  test_walk_init(left,2147483648,  9 /* 128.0.0.0/9     */,         0,  0 /* N/A        */, 0);
  test_walk_init(left,2148597777, 25 /* 128.17.0.0/25   */,         0,  0 /* N/A        */, 0);
  test_walk_init(left,  20971584, 23 /* 1.64.0.0/23     */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  20973376, 24 /* 1.64.7.0/24     */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  21007168, 24 /* 1.64.139.0/24   */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  25230976, 23 /* 1.128.254.0/23  */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  16859137, 30 /* 1.1.64.0/30     */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16859137, 32 /* 1.1.64.7/32     */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16859137, 32 /* 1.1.64.138/32   */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16859137, 31 /* 1.1.64.240/31   */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16875521, 29 /* 1.1.128.0/29    */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16875521, 32 /* 1.1.128.7/32    */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16875521, 29 /* 1.1.128.240/29  */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16875521, 31 /* 1.1.128.254/31  */,  16973824, 18 /* 1.5.0.0/18 */, 1);
  test_walk_init(left,  16990211, 25 /* 1.3.64.0/25     */,  17104896, 18 /* 1.5.0.0/18 */, 1);
  test_walk_init(left,  16990211, 32 /* 1.3.64.7/32     */,  17104896, 18 /* 1.5.0.0/18 */, 1);
  test_walk_init(left,  16990211, 29 /* 1.3.64.240/29   */,  17104896, 18 /* 1.5.0.0/18 */, 1);
  test_walk_init(left,  16990211, 31 /* 1.3.64.254/31   */,  17104896, 18 /* 1.5.0.0/18 */, 1);
  test_walk_init(left,  17006595, 26 /* 1.3.128.0/26    */,  17104896, 18 /* 1.5.0.0/18 */, 1);
  test_walk_init(left,  17006595, 32 /* 1.3.128.7/32    */,  17104896, 18 /* 1.5.0.0/18 */, 1);
  test_walk_init(left,  17006595, 29 /* 1.3.128.240/29  */,  17104896, 18 /* 1.5.0.0/18 */, 1);
  test_walk_init(left,  17006595, 31 /* 1.3.128.254/31  */,  17104896, 18 /* 1.5.0.0/18 */, 1);
  test_walk_init(left,  17252359, 26 /* 1.7.64.0/26     */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  17252359, 32 /* 1.7.64.7/32     */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  17252359, 28 /* 1.7.64.240/28   */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  17252359, 31 /* 1.7.64.254/31   */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  17268743, 25 /* 1.7.128.0/25    */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  17268743, 32 /* 1.7.128.7/32    */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  17268743, 29 /* 1.7.128.240/29  */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  17268743, 31 /* 1.7.128.254/31  */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left, 125829120,  9 /* 7.128.0.0/9     */,         0,  0 /* N/A        */, 0);
  test_walk_init(left, 125829120, 12 /* 7.128.0.0/12    */,         0,  0 /* N/A        */, 0);

  /* corner cases */
  test_walk_init(left,  17825792, 16 /* 1.16.0.0/16     */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  17825792, 24 /* 1.16.0.0/24     */,  50331648, 12 /* 3.0.0.0/12 */, 1);
  test_walk_init(left,  16846848, 24 /* 1.1.16.0/24     */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16846848, 32 /* 1.1.16.0/32     */,  16973824, 18 /* 1.3.0.0/18 */, 1);
  test_walk_init(left,  16777472, 24 /* 1.0.1.0/24      */,  16842752, 18 /* 1.1.0.0/18 */, 1);
  test_walk_init(left,  16781312, 19 /* 1.0.16.0/19     */,  16842752, 18 /* 1.1.0.0/18 */, 1);

  struct f_trie *corner = tries[3];
  test_walk_init(corner,16777216, 12 /* 1.0.0.0/12      */,  16842752, 16 /* 1.1.0.0/16  */, 1);
  test_walk_init(corner,16908288, 32 /* 1.2.0.0/32      */,  18874368, 12 /* 1.32.0.0/12 */, 1);

  struct f_trie *with_zero = tries[4];
  test_walk_init(with_zero, 50529027, 32 /* 3.3.3.3/32 */, 4294967295, 32 /* 255.255.255.255/32 */, 1);

  struct f_trie *two_px = tries[5];
  test_walk_init(two_px,          0,  0 /* 0.0.0.0/0   */,          0,  0 /* 0.0.0.0/0     */, 1);
  test_walk_init(two_px,          1, 32 /* 0.0.0.1/32  */, 2066546688, 16 /* 123.45.0.0/16 */, 1);
  test_walk_init(two_px, 3355443200,  8 /* 200.0.0.0/8 */,          0,  0 /* N/A           */, 0);
  test_walk_init(two_px,   50529027, 32 /* 3.3.3.3/32  */, 2066546688, 16 /* 123.45.0.0/16 */, 1);

  struct f_trie *root_only = tries[6];
  test_walk_init(root_only,   50529027, 32 /* 3.3.3.3/32  */,          0, 0 /* N/A            */, 0);

  bt_bird_cleanup();
  return 1;
}


static int
t_trie_walk_inclusive(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);

  unsigned long r = rand();
  log("random seed for t_trie_walk_inclusive is %lu", r);
  srandom(r);
  //srandom(1325299055);
  //srandom(25273275);
  //srandom(1959294931);
  //srandom(1182332329);

  for (int round = 0; round < TESTS_NUM*8; round++)
  {
    int level = round / TESTS_NUM;
    int v6 = level % 2;
    int num = PREFIXES_NUM * (int[]){0, 1, 10, 100, 1000}[level / 2];
    int pos = 0, end = 0;
    list *prefixes = make_random_prefix_list(num, v6, 1);
    struct f_trie *trie = make_trie_from_prefix_list(prefixes);
    struct f_prefix *pxset = malloc((num + 1) * sizeof(struct f_prefix));

    struct f_prefix_node *n;
    WALK_LIST(n, *prefixes)
      pxset[pos++] = n->prefix;
    memset(&pxset[pos], 0, sizeof (struct f_prefix));

    qsort(pxset, num, sizeof(struct f_prefix), compare_prefixes);

    /* Test trie_walk_init() return value */
    test_walk_return_val(trie, pxset, num, 1);

    /* Full walk */
    bt_debug("Full walk inclusive (round %d, %d nets)\n", round, num);

    pos = 0;
    uint pxc = 0;
    /* Last argument should have no effect on the walk */
    TRIE_WALK2(trie, net, NULL, 1)
    {
      log_networks(&net, &pxset[pos].net);
      bt_assert(net_equal(&net, &pxset[pos].net));

      /* Skip possible duplicates */
      while (net_equal(&pxset[pos].net, &pxset[pos + 1].net))
       pos++;

      pos++;
      pxc++;
    }
    TRIE_WALK2_END;

    bt_assert(pos == num);
    bt_assert(pxc == trie->prefix_count);
    bt_debug("Full walk inclusive done\n");

    /* Prepare net for subnet walk - start with random prefix from trie */
    if (num)
      pos = xrandom(num);
    else
      pos = 0;
    end = pos + (int[]){2, 2, 3, 4}[level / 2];
    end = MIN(end, num);

    struct f_prefix from;
    if (num)
      from = pxset[pos];
    else
      get_random_prefix(&from, v6, 1);

    /* Find a common superprefix to several subsequent prefixes */
    for (; pos < end; pos++)
    {
      if (net_equal(&from.net, &pxset[pos].net))
	continue;

      int common = !v6 ?
	ip4_pxlen(net4_prefix(&from.net), net4_prefix(&pxset[pos].net)) :
	ip6_pxlen(net6_prefix(&from.net), net6_prefix(&pxset[pos].net));
      from.net.pxlen = MIN(from.net.pxlen, common);

      if (!v6)
	((net_addr_ip4 *) &from.net)->prefix =
	  ip4_and(net4_prefix(&from.net), net4_prefix(&pxset[pos].net));
      else
	((net_addr_ip6 *) &from.net)->prefix =
	  ip6_and(net6_prefix(&from.net), net6_prefix(&pxset[pos].net));
    }

    /* Fix irrelevant bits */
    if (!v6)
      ((net_addr_ip4 *) &from.net)->prefix =
	ip4_and(net4_prefix(&from.net), ip4_mkmask(net4_pxlen(&from.net)));
    else
      ((net_addr_ip6 *) &from.net)->prefix =
	ip6_and(net6_prefix(&from.net), ip6_mkmask(net6_pxlen(&from.net)));


    /* Find initial position for final prefix */
    for (pos = 0; pos < num; pos++)
      if (compare_prefixes(&pxset[pos], &from) >= 0)
	break;

    int p0 = pos;
    char buf0[64];
    bt_format_net(buf0, 64, &from.net);
    bt_debug("Subnet walk inclusive for %s (round %d, %d nets)\n", buf0, round, num);

    /* Subnet walk */
    TRIE_WALK2(trie, net, &from.net, 1)
    {
      bt_assert(net_compare(&net, &pxset[pos].net) >= 0);

      bt_assert(net_compare(&net, &from.net) >= 0);

      if (!net_equal(&net, &pxset[pos + 1].net) || !(net_compare(&net, &from.net) >= 0))
      {
	/* Make sure that net is from inserted prefixes */
	bt_format_net(buf0, 64, &net);
	bt_debug("got: %s", buf0);
	bt_format_net(buf0, 64, &pxset[pos].net);
	bt_debug(" expected %s", buf0);
	if (pos + 1 < num)
	{
	  bt_format_net(buf0, 64, &pxset[pos + 1].net);
	  bt_debug(" (next: %s)\n", buf0);
	}
	else
	  bt_debug("\n");
      }

      bt_assert(net_equal(&net, &pxset[pos].net));
      bt_assert(net_compare(&net, &from.net) >= 0);


      /* Skip possible duplicates */
      while (net_equal(&pxset[pos].net, &pxset[pos + 1].net))
	pos++;

      pos++;

    }
    TRIE_WALK2_END;


    bt_debug("pos == num %u %u; p0 %u \n", pos, num, p0);
    bt_debug("Subnet walk done inclusive for %s (found %d nets)\n", buf0, pos - p0);
    bt_assert(pos == num);

    /* Prepare net for subnet walk - start with random prefix (likely not from trie) */
    get_random_prefix(&from, v6, 1);

    for (pos = 0; pos < num; pos++)
      if (compare_prefixes(&pxset[pos], &from) >= 0)
	break;

    p0 = pos;
    bt_format_net(buf0, 64, &from.net);
    bt_debug("Subnet walk inclusive for random %s (round %d, %d nets)\n", buf0, round, num);

    /* Subnet walk */
    TRIE_WALK2(trie, net, &from.net, 1)
    {
      bt_assert(net_equal(&net, &pxset[pos].net));
      bt_assert(net_compare(&net, &from.net) >= 0);

      while (net_equal(&pxset[pos].net, &pxset[pos + 1].net))
	pos++;

      pos++;
    }
    TRIE_WALK2_END;

    bt_debug("Subnet walk inclusive for random %s (found %d nets from %d)\n", buf0, pos - p0, num - p0);
    bt_assert(pos == num);

    tmp_flush();
  }

  bt_bird_cleanup();
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
  bt_test_suite(t_trie_walk, "Testing TRIE_WALK() on random tries");
  bt_test_suite(t_trie_walk_to_root, "Testing TRIE_WALK_TO_ROOT() on random tries");
  bt_test_suite(t_trie_walk_inclusive, "Testing TRIE_WALK2() on random tries");
  bt_test_suite(t_trie_walk_determ, "Testing trie_walk_init() on edge case tries deterministically");

  // bt_test_suite(t_bench_trie_datasets_subset, "Benchmark tries from datasets by random subset of nets");
  // bt_test_suite(t_bench_trie_datasets_random, "Benchmark tries from datasets by generated addresses");

  return bt_exit_value();
}
