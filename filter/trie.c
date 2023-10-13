/*
 *	Filters: Trie for prefix sets
 *
 *	(c) 2009--2021 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2009--2021 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Trie for prefix sets
 *
 * We use a (compressed) trie to represent prefix sets. Every node in the trie
 * represents one prefix (&addr/&plen) and &plen also indicates the index of
 * bits in the address that are used to branch at the node. Note that such
 * prefix is not necessary a member of the prefix set, it is just a canonical
 * prefix associated with a node. Prefix lengths of nodes are aligned to
 * multiples of &TRIE_STEP (4) and there is 16-way branching in each
 * node. Therefore, we say that a node is associated with a range of prefix
 * lengths (&plen .. &plen + TRIE_STEP - 1).
 *
 * The prefix set is not just a set of prefixes, it is defined by a set of
 * prefix patterns. Each prefix pattern consists of &ppaddr/&pplen and two
 * integers: &low and &high. The tested prefix &paddr/&plen matches that pattern
 * if the first MIN(&plen, &pplen) bits of &paddr and &ppaddr are the same and
 * &low <= &plen <= &high.
 *
 * There are two ways to represent accepted prefixes for a node. First, there is
 * a bitmask &local, which represents independently all 15 prefixes that extend
 * the canonical prefix of the node and are within a range of prefix lengths
 * associated with the node. E.g., for node 10.0.0.0/8 they are 10.0.0.0/8,
 * 10.0.0.0/9, 10.128.0.0/9, .. 10.224.0.0/11. This order (first by length, then
 * lexicographically) is used for indexing the bitmask &local, starting at
 * position 1. I.e., index is 2^(plen - base) + offset within the same length,
 * see function trie_local_mask6() for details.
 *
 * Second, we use a bitmask &accept to represent accepted prefix lengths at a
 * node. The bit is set means that all prefixes of given length that are either
 * subprefixes or superprefixes of the canonical prefix are accepted. As there
 * are 33 prefix lengths (0..32 for IPv4), but there is just one prefix of zero
 * length in the whole trie so we have &zero flag in &f_trie (indicating whether
 * the trie accepts prefix 0.0.0.0/0) as a special case, and &accept bitmask
 * represents accepted prefix lengths from 1 to 32.
 *
 * One complication is handling of prefix patterns with unaligned prefix length.
 * When such pattern is to be added, we add a primary node above (with rounded
 * down prefix length &nlen) and a set of secondary nodes below (with rounded up
 * prefix lengths &slen). Accepted prefix lengths of the original prefix pattern
 * are then represented in different places based on their lengths. For prefixes
 * shorter than &nlen, it is &accept bitmask of the primary node, for prefixes
 * between &nlen and &slen - 1 it is &local bitmask of the primary node, and for
 * prefixes longer of equal &slen it is &accept bitmasks of secondary nodes.
 *
 * There are two cases in prefix matching - a match when the length of the
 * prefix is smaller that the length of the prefix pattern, (&plen < &pplen) and
 * otherwise. The second case is simple - we just walk through the trie and look
 * at every visited node whether that prefix accepts our prefix length (&plen).
 * The first case is tricky - we do not want to examine every descendant of a
 * final node, so (when we create the trie) we have to propagate that
 * information from nodes to their ascendants.
 *
 * There are two kinds of propagations - propagation from child's &accept
 * bitmask to parent's &accept bitmask, and propagation from child's &accept
 * bitmask to parent's &local bitmask. The first kind is simple - as all
 * superprefixes of a parent are also all superprefixes of appropriate length of
 * a child, then we can just add (by bitwise or) a child &accept mask masked by
 * parent prefix length mask to the parent &accept mask. This handles prefixes
 * shorter than node &plen.
 *
 * The second kind of propagation is necessary to handle superprefixes of a
 * child that are represented by parent &local mask - that are in the range of
 * prefix lengths associated with the parent. For each accepted (by child
 * &accept mask) prefix length from that range, we need to set appropriate bit
 * in &local mask. See function trie_amask_to_local() for details.
 *
 * There are four cases when we walk through a trie:
 *
 * - we are in NULL
 * - we are out of path (prefixes are inconsistent)
 * - we are in the wanted (final) node (node length == &plen)
 * - we are beyond the end of path (node length > &plen)
 * - we are still on path and keep walking (node length < &plen)
 *
 * The walking code in trie_match_net() is structured according to these cases.
 *
 * Iteration over prefixes in a trie can be done using TRIE_WALK() macro, or
 * directly using trie_walk_init() and trie_walk_next() functions. The second
 * approach allows suspending the iteration and continuing in it later.
 * Prefixes are enumerated in the usual lexicographic order and may be
 * restricted to a subset of the trie (all subnets of a specified prefix).
 *
 * Note that the trie walk does not reliably enumerate `implicit' prefixes
 * defined by &low and &high fields in prefix patterns, it is supposed to be
 * used on tries constructed from `explicit' prefixes (&low == &plen == &high
 * in call to trie_add_prefix()).
 *
 * The trie walk has three basic state variables stored in the struct
 * &f_trie_walk_state -- the current node in &stack[stack_pos], &accept_length
 * for iteration over inter-node prefixes (non-branching prefixes on compressed
 * path between the current node and its parent node, stored in the bitmap
 * &accept of the current node) and &local_pos for iteration over intra-node
 * prefixes (stored in the bitmap &local).
 *
 * The trie also supports longest-prefix-match query by trie_match_longest_ip4()
 * and it can be extended to iteration over all covering prefixes for a given
 * prefix (from longest to shortest) using TRIE_WALK_TO_ROOT_IP4() macro. There
 * are also IPv6 versions (for practical reasons, these functions and macros are
 * separate for IPv4 and IPv6). There is the same limitation to enumeration of
 * `implicit' prefixes like with the previous TRIE_WALK() macro.
 */

#include "nest/bird.h"
#include "lib/string.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/data.h"


/*
 * In the trie_add_prefix(), we use ip_addr (assuming that it is the same as
 * ip6_addr) to handle both IPv4 and IPv6 prefixes. In contrast to rest of the
 * BIRD, IPv4 addresses are just zero-padded from right. That is why we have
 * ipt_from_ip4() and ipt_to_ip4() macros below.
 */

#define ipa_mkmask(x) ip6_mkmask(x)
#define ipa_masklen(x) ip6_masklen(&x)
#define ipa_pxlen(x,y) ip6_pxlen(x,y)
#define ipa_getbit(a,p) ip6_getbit(a,p)
#define ipa_getbits(a,p,n) ip6_getbits(a,p,n)
#define ipa_setbits(a,p,n) ip6_setbits(a,p,n)
#define trie_local_mask(a,b,c) trie_local_mask6(a,b,c)

#define ipt_from_ip4(x) _MI6(_I(x), 0, 0, 0)
#define ipt_to_ip4(x) _MI4(_I0(x))


/**
 * f_new_trie - allocates and returns a new empty trie
 * @lp: linear pool to allocate items from
 * @data_size: user data attached to node
 */
struct f_trie *
f_new_trie(linpool *lp, uint data_size)
{
  struct f_trie * ret;
  ret = lp_allocz(lp, sizeof(struct f_trie) + data_size);
  ret->lp = lp;
  ret->ipv4 = -1;
  ret->data_size = data_size;
  return ret;
}

static inline struct f_trie_node4 *
new_node4(struct f_trie *t, uint plen, uint local, ip4_addr paddr, ip4_addr pmask, ip4_addr amask)
{
  struct f_trie_node4 *n = lp_allocz(t->lp, sizeof(struct f_trie_node4) + t->data_size);
  n->plen = plen;
  n->local = local;
  n->addr = paddr;
  n->mask = pmask;
  n->accept = amask;
  return n;
}

static inline struct f_trie_node6 *
new_node6(struct f_trie *t, uint plen, uint local, ip6_addr paddr, ip6_addr pmask, ip6_addr amask)
{
  struct f_trie_node6 *n = lp_allocz(t->lp, sizeof(struct f_trie_node6) + t->data_size);
  n->plen = plen;
  n->local = local;
  n->addr = paddr;
  n->mask = pmask;
  n->accept = amask;
  return n;
}

static inline struct f_trie_node *
new_node(struct f_trie *t, uint plen, uint local, ip_addr paddr, ip_addr pmask, ip_addr amask)
{
  if (t->ipv4)
    return (struct f_trie_node *) new_node4(t, plen, local, ipt_to_ip4(paddr), ipt_to_ip4(pmask), ipt_to_ip4(amask));
  else
    return (struct f_trie_node *) new_node6(t, plen, local, ipa_to_ip6(paddr), ipa_to_ip6(pmask), ipa_to_ip6(amask));
}

static inline void
attach_node4(struct f_trie_node4 *parent, struct f_trie_node4 *child)
{
  parent->c[ip4_getbits(child->addr, parent->plen, TRIE_STEP)] = child;
}

static inline void
attach_node6(struct f_trie_node6 *parent, struct f_trie_node6 *child)
{
  parent->c[ip6_getbits(child->addr, parent->plen, TRIE_STEP)] = child;
}

static inline void
attach_node(struct f_trie_node *parent, struct f_trie_node *child, int v4)
{
  if (v4)
    attach_node4(&parent->v4, &child->v4);
  else
    attach_node6(&parent->v6, &child->v6);
}


/*
 * Internal prefixes of a node a represented by the local bitmask, each bit for
 * one prefix. Bit 0 is unused, Bit 1 is for the main prefix of the node,
 * remaining bits correspond to subprefixes by this pattern:
 *
 *          1
 *      2       3
 *    4   5   6   7
 *   8 9 A B C D E F
 *
 * E.g. for 10.0.0.0/8 node, the 10.64.0.0/10 would be position 5.
 */

/*
 * Compute appropriate mask representing prefix px/plen in local bitmask of node
 * with prefix length nlen. Assuming that nlen <= plen < (nlen + TRIE_STEP).
 */
static inline uint
trie_local_mask4(ip4_addr px, uint plen, uint nlen)
{
  uint step = plen - nlen;
  uint pos = (1u << step) + ip4_getbits(px, nlen, step);
  return 1u << pos;
}

static inline uint
trie_local_mask6(ip6_addr px, uint plen, uint nlen)
{
  uint step = plen - nlen;
  uint pos = (1u << step) + ip6_getbits(px, nlen, step);
  return 1u << pos;
}

/*
 * Compute an appropriate local mask (for a node with prefix length nlen)
 * representing prefixes of px that are accepted by amask and fall within the
 * range associated with that node. Used for propagation of child accept mask
 * to parent local mask.
 */
static inline uint
trie_amask_to_local(ip_addr px, ip_addr amask, uint nlen)
{
  uint local = 0;

  for (uint plen = MAX(nlen, 1); plen < (nlen + TRIE_STEP); plen++)
    if (ipa_getbit(amask, plen - 1))
      local |= trie_local_mask(px, plen, nlen);

  return local;
}

/*
 * Compute a bitmask representing a level of subprefixes (of the same length),
 * using specified position as a root. E.g., level 2 from root position 3 would
 * be bit positions C-F, returned as bitmask 0xf000.
 */
static inline uint
trie_level_mask(uint pos, uint level)
{
  return ((1u << (1u << level)) - 1) << (pos << level);
}


#define GET_ADDR(N,F,X) ((X) ? ipt_from_ip4((N)->v4.F) : ipa_from_ip6((N)->v6.F))
#define SET_ADDR(N,F,X,V) ({ if (X) (N)->v4.F =ipt_to_ip4(V); else (N)->v6.F =ipa_to_ip6(V); })

#define GET_LOCAL(N,X) ((X) ? (N)->v4.local : (N)->v6.local)
#define ADD_LOCAL(N,X,V) ({ uint v_ = (V); if (X) (N)->v4.local |= v_; else (N)->v6.local |= v_; })

#define GET_CHILD(N,X,I) ((X) ? (struct f_trie_node *) (N)->v4.c[I] : (struct f_trie_node *) (N)->v6.c[I])


static void *
trie_add_node(struct f_trie *t, uint plen, ip_addr px, uint local, uint l, uint h)
{
  uint l_ = l ? (l - 1) : 0;
  ip_addr amask = (l_ < h) ? ipa_xor(ipa_mkmask(l_), ipa_mkmask(h)) : IPA_NONE;
  ip_addr pmask = ipa_mkmask(plen);
  ip_addr paddr = ipa_and(px, pmask);
  struct f_trie_node *o = NULL;
  struct f_trie_node *n = &t->root;
  int v4 = t->ipv4;

  /* Add all bits for each active level (0x0002 0x000c 0x00f0 0xff00) */
  for (uint i = 0; i < TRIE_STEP; i++)
    if ((l <= (plen + i)) && ((plen + i) <= h))
      local |= trie_level_mask(1, i);

  DBG("Insert node %I/%u (%I %x)\n", paddr, plen, amask, local);
  while (n)
    {
      ip_addr naddr = GET_ADDR(n, addr, v4);
      ip_addr nmask = GET_ADDR(n, mask, v4);
      ip_addr accept = GET_ADDR(n, accept, v4);
      ip_addr cmask = ipa_and(nmask, pmask);
      uint nlen = v4 ? n->v4.plen : n->v6.plen;

      DBG("Found node %I/%u (%I %x)\n",
	  naddr, nlen, accept, v4 ? n->v4.local : n->v6.local);

      if (ipa_compare(ipa_and(paddr, cmask), ipa_and(naddr, cmask)))
        {
	  /* We are out of path - we have to add branching node 'b'
	     between node 'o' and node 'n', and attach new node 'a'
	     as the other child of 'b'. */
	  int blen = ROUND_DOWN_POW2(ipa_pxlen(paddr, naddr), TRIE_STEP);
	  ip_addr bmask = ipa_mkmask(blen);
	  ip_addr baddr = ipa_and(px, bmask);

	  /* Merge accept masks from children to get accept mask for node 'b' */
	  ip_addr baccm = ipa_and(ipa_or(amask, accept), bmask);
	  uint bloc = trie_amask_to_local(naddr, accept, blen) |
	              trie_amask_to_local(paddr, amask, blen);

	  struct f_trie_node *a = new_node(t, plen, local, paddr, pmask, amask);
	  struct f_trie_node *b = new_node(t, blen, bloc, baddr, bmask, baccm);
	  attach_node(o, b, v4);
	  attach_node(b, n, v4);
	  attach_node(b, a, v4);
	  t->prefix_count++;

	  DBG("Case 1\n");
	  return a;
	}

      if (plen < nlen)
	{
	  /* We add new node 'a' between node 'o' and node 'n' */
	  amask = ipa_or(amask, ipa_and(accept, pmask));
	  local |= trie_amask_to_local(naddr, accept, plen);
	  struct f_trie_node *a = new_node(t, plen, local, paddr, pmask, amask);
	  attach_node(o, a, v4);
	  attach_node(a, n, v4);
	  t->prefix_count++;

	  DBG("Case 2\n");
	  return a;
	}

      if (plen == nlen)
	{
	  /* We already found added node in trie. Just update accept and local mask */
	  accept = ipa_or(accept, amask);
	  SET_ADDR(n, accept, v4, accept);

	  if ((GET_LOCAL(n, v4) & local) != local)
	    t->prefix_count++;

	  ADD_LOCAL(n, v4, local);

	  DBG("Case 3\n");
	  return n;
	}

      /* Update accept mask part M2 and go deeper */
      accept = ipa_or(accept, ipa_and(amask, nmask));
      SET_ADDR(n, accept, v4, accept);
      ADD_LOCAL(n, v4, trie_amask_to_local(paddr, amask, nlen));

      DBG("Step %u\n", ipa_getbits(paddr, nlen));

      /* n->plen < plen and plen <= 32 (128) */
      o = n;
      n = GET_CHILD(n, v4, ipa_getbits(paddr, nlen, TRIE_STEP));
    }

  /* We add new tail node 'a' after node 'o' */
  struct f_trie_node *a = new_node(t, plen, local, paddr, pmask, amask);
  attach_node(o, a, v4);
  t->prefix_count++;

  DBG("Case 4\n");
  return a;
}

/**
 * trie_add_prefix
 * @t: trie to add to
 * @net: IP network prefix
 * @l: prefix lower bound
 * @h: prefix upper bound
 *
 * Adds prefix (prefix pattern) @n to trie @t.  @l and @h are lower
 * and upper bounds on accepted prefix lengths, both inclusive.
 * 0 <= l, h <= 32 (128 for IPv6).
 *
 * Returns a pointer to the allocated node. The function can return a pointer to
 * an existing node if @px and @plen are the same. If px/plen == 0/0 (or ::/0),
 * a pointer to the root node is returned. Returns NULL when called with
 * mismatched IPv4/IPv6 net type.
 */
void *
trie_add_prefix(struct f_trie *t, const net_addr *net, uint l, uint h)
{
  uint plen = net_pxlen(net);
  ip_addr px;
  int v4;

  switch (net->type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
    px = ipt_from_ip4(net4_prefix(net));
    v4 = 1;
    break;

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
  case NET_IP6_SADR:
    px = ipa_from_ip6(net6_prefix(net));
    v4 = 0;
    break;

  default:
    bug("invalid type");
  }

  if (t->ipv4 != v4)
  {
    if (t->ipv4 < 0)
      t->ipv4 = v4;
    else
      return NULL;
  }

  DBG("\nInsert net %N (%u-%u)\n", net, l, h);

  if (l == 0)
    t->zero = 1;

  if (h < plen)
    plen = h;

  /* Primary node length, plen rounded down */
  uint nlen = ROUND_DOWN_POW2(plen, TRIE_STEP);

  if (plen == nlen)
    return trie_add_node(t, nlen, px, 0, l,  h);

  /* Secondary node length, plen rouned up */
  uint slen = nlen + TRIE_STEP;
  void *node = NULL;

  /*
   * For unaligned prefix lengths it is more complicated. We need to encode
   * matching prefixes of lengths from l to h. There are three cases of lengths:
   *
   * 1) 0..nlen are encoded by the accept mask of the primary node
   * 2) nlen..(slen-1) are encoded by the local mask of the primary node
   * 3) slen..max are encoded in secondary nodes
   */

  if (l < slen)
  {
    uint local = 0;

    /* Compute local bits for accepted nlen..(slen-1) prefixes */
    for (uint i = 0; i < TRIE_STEP; i++)
      if ((l <= (nlen + i)) && ((nlen + i) <= h))
      {
	uint pos = (1u << i) + ipa_getbits(px, nlen, i);
	uint len = ((nlen + i) <= plen) ? 1 : (1u << (nlen + i - plen));

	/* We need to fill 'len' bits starting at 'pos' position */
	local |= ((1u << len) - 1) << pos;
      }

    /* Add the primary node */
    node = trie_add_node(t, nlen, px, local, l,  nlen);
  }

  if (slen <= h)
  {
    uint l2 = MAX(l, slen);
    uint max = (1u << (slen - plen));

    /* Add secondary nodes */
    for (uint i = 0; i < max; i++)
      node = trie_add_node(t, slen, ipa_setbits(px,  slen - 1, i), 0, l2,  h);
  }

  return node;
}


static int
trie_match_net4(const struct f_trie *t, ip4_addr px, uint plen)
{
  if (plen == 0)
    return t->zero;

  int plentest = plen - 1;
  uint nlen = ROUND_DOWN_POW2(plen, TRIE_STEP);
  uint local = trie_local_mask4(px, plen, nlen);
  const struct f_trie_node4 *n = &t->root.v4;

  while (n)
  {
    /* We are out of path */
    if (!ip4_prefix_equal(px, n->addr, MIN(plen, n->plen)))
      return 0;

    /* Check local mask */
    if ((n->plen == nlen) && (n->local & local))
      return 1;

    /* Check accept mask */
    if (ip4_getbit(n->accept, plentest))
      return 1;

    /* We finished trie walk and still no match */
    if (nlen <= n->plen)
      return 0;

    /* Choose children */
    n =  n->c[ip4_getbits(px, n->plen, TRIE_STEP)];
  }

  return 0;
}

static int
trie_match_net6(const struct f_trie *t, ip6_addr px, uint plen)
{
  if (plen == 0)
    return t->zero;

  int plentest = plen - 1;
  uint nlen = ROUND_DOWN_POW2(plen, TRIE_STEP);
  uint local = trie_local_mask6(px, plen, nlen);
  const struct f_trie_node6 *n = &t->root.v6;

  while (n)
  {
    /* We are out of path */
    if (!ip6_prefix_equal(px, n->addr, MIN(plen, n->plen)))
      return 0;

    /* Check local mask */
    if ((n->plen == nlen) && (n->local & local))
      return 1;

    /* Check accept mask */
    if (ip6_getbit(n->accept, plentest))
      return 1;

    /* We finished trie walk and still no match */
    if (nlen <= n->plen)
      return 0;

    /* Choose children */
    n =  n->c[ip6_getbits(px, n->plen, TRIE_STEP)];
  }

  return 0;
}

/**
 * trie_match_net
 * @t: trie
 * @n: net address
 *
 * Tries to find a matching net in the trie such that
 * prefix @n matches that prefix pattern. Returns 1 if there
 * is such prefix pattern in the trie.
 */
int
trie_match_net(const struct f_trie *t, const net_addr *n)
{
  switch (n->type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
    return t->ipv4 ? trie_match_net4(t, net4_prefix(n), net_pxlen(n)) : 0;

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
    return !t->ipv4 ? trie_match_net6(t, net6_prefix(n), net_pxlen(n)) : 0;

  default:
    return 0;
  }
}


/**
 * trie_match_longest_ip4
 * @t: trie
 * @net: net address
 * @dst: return value
 * @found0: optional returned bitmask of found nodes
 *
 * Perform longest prefix match for the address @net and return the resulting
 * prefix in the buffer @dst. The bitmask @found0 is used to report lengths of
 * prefixes on the path from the root to the resulting prefix. E.g., if there is
 * also a /20 shorter matching prefix, then 20-th bit is set in @found0. This
 * can be used to enumerate all matching prefixes for the network @net using
 * function trie_match_next_longest_ip4() or macro TRIE_WALK_TO_ROOT_IP4().
 *
 * This function assumes IPv4 trie, there is also an IPv6 variant. The @net
 * argument is typed as net_addr_ip4, but would accept any IPv4-based net_addr,
 * like net4_prefix(). Anyway, returned @dst is always net_addr_ip4.
 *
 * Result: 1 if a matching prefix was found, 0 if not.
 */
int
trie_match_longest_ip4(const struct f_trie *t, const net_addr_ip4 *net, net_addr_ip4 *dst, ip4_addr *found0)
{
  ASSERT(t->ipv4);

  const ip4_addr prefix = net->prefix;
  const int pxlen = net->pxlen;

  const struct f_trie_node4 *n = &t->root.v4;
  int len = 0;

  ip4_addr found = IP4_NONE;
  int last = -1;

  while (n)
  {
    /* We are out of path */
    if (!ip4_prefix_equal(prefix, n->addr, MIN(pxlen, n->plen)))
      goto done;

    /* Check accept mask */
    for (; len < n->plen; len++)
    {
      if (len > pxlen)
	goto done;

      if (ip4_getbit(n->accept, len - 1))
      {
	/* len is always < 32 due to len < n->plen */
	ip4_setbit(&found, len);
	last = len;
      }
    }

    /* Special case for max length, there is only one valid local position */
    if (len == IP4_MAX_PREFIX_LENGTH)
    {
      if (n->local & (1u << 1))
	last = len;

      goto done;
    }

    /* Check local mask */
    for (int pos = 1; pos < (1 << TRIE_STEP); pos = 2 * pos + ip4_getbit(prefix, len), len++)
    {
      if (len > pxlen)
	goto done;

      if (n->local & (1u << pos))
      {
	/* len is always < 32 due to special case above */
	ip4_setbit(&found, len);
	last = len;
      }
    }

    /* Choose child */
    n = n->c[ip4_getbits(prefix, n->plen, TRIE_STEP)];
  }

done:
  if (last < 0)
    return 0;

  *dst = NET_ADDR_IP4(ip4_and(prefix, ip4_mkmask(last)), last);

  if (found0)
    *found0 = found;

  return 1;
}


/**
 * trie_match_longest_ip6
 * @t: trie
 * @net: net address
 * @dst: return value
 * @found0: optional returned bitmask of found nodes
 *
 * Perform longest prefix match for the address @net and return the resulting
 * prefix in the buffer @dst. The bitmask @found0 is used to report lengths of
 * prefixes on the path from the root to the resulting prefix. E.g., if there is
 * also a /20 shorter matching prefix, then 20-th bit is set in @found0. This
 * can be used to enumerate all matching prefixes for the network @net using
 * function trie_match_next_longest_ip6() or macro TRIE_WALK_TO_ROOT_IP6().
 *
 * This function assumes IPv6 trie, there is also an IPv4 variant. The @net
 * argument is typed as net_addr_ip6, but would accept any IPv6-based net_addr,
 * like net6_prefix(). Anyway, returned @dst is always net_addr_ip6.
 *
 * Result: 1 if a matching prefix was found, 0 if not.
 */
int
trie_match_longest_ip6(const struct f_trie *t, const net_addr_ip6 *net, net_addr_ip6 *dst, ip6_addr *found0)
{
  ASSERT(!t->ipv4);

  const ip6_addr prefix = net->prefix;
  const int pxlen = net->pxlen;

  const struct f_trie_node6 *n = &t->root.v6;
  int len = 0;

  ip6_addr found = IP6_NONE;
  int last = -1;

  while (n)
  {
    /* We are out of path */
    if (!ip6_prefix_equal(prefix, n->addr, MIN(pxlen, n->plen)))
      goto done;

    /* Check accept mask */
    for (; len < n->plen; len++)
    {
      if (len > pxlen)
	goto done;

      if (ip6_getbit(n->accept, len - 1))
      {
	/* len is always < 128 due to len < n->plen */
	ip6_setbit(&found, len);
	last = len;
      }
    }

    /* Special case for max length, there is only one valid local position */
    if (len == IP6_MAX_PREFIX_LENGTH)
    {
      if (n->local & (1u << 1))
	last = len;

      goto done;
    }

    /* Check local mask */
    for (int pos = 1; pos < (1 << TRIE_STEP); pos = 2 * pos + ip6_getbit(prefix, len), len++)
    {
      if (len > pxlen)
	goto done;

      if (n->local & (1u << pos))
      {
	/* len is always < 128 due to special case above */
	ip6_setbit(&found, len);
	last = len;
      }
    }

    /* Choose child */
    n = n->c[ip6_getbits(prefix, n->plen, TRIE_STEP)];
  }

done:
  if (last < 0)
    return 0;

  *dst = NET_ADDR_IP6(ip6_and(prefix, ip6_mkmask(last)), last);

  if (found0)
    *found0 = found;

  return 1;
}

#define SAME_PREFIX(A,B,X,L) ((X) ? ip4_prefix_equal((A)->v4.addr, net4_prefix(B), (L)) : ip6_prefix_equal((A)->v6.addr, net6_prefix(B), (L)))
#define GET_NET_BITS(N,X,A,B) ((X) ? ip4_getbits(net4_prefix(N), (A), (B)) : ip6_getbits(net6_prefix(N), (A), (B)))

/**
 * trie_walk_init
 * @s: walk state
 * @t: trie
 * @net: optional subnet for walk
 *
 * Initialize walk state for subsequent walk through nodes of the trie @t by
 * trie_walk_next(). The argument @net allows to restrict walk to given subnet,
 * otherwise full walk over all nodes is used. This is done by finding node at
 * or below @net and starting position in it.
 */
void
trie_walk_init(struct f_trie_walk_state *s, const struct f_trie *t, const net_addr *net)
{
  *s = (struct f_trie_walk_state) {
    .ipv4 = t->ipv4,
    .accept_length = 0,
    .start_pos = 1,
    .local_pos = 1,
    .stack_pos = 0,
    .stack[0] = &t->root
  };

  if (!net)
    return;

  /* We want to find node of level at least plen */
  int plen = ROUND_DOWN_POW2(net->pxlen, TRIE_STEP);
  const struct f_trie_node *n = &t->root;
  const int v4 = t->ipv4;

  while (n)
  {
    int nlen = v4 ? n->v4.plen : n->v6.plen;

    /* We are out of path */
    if (!SAME_PREFIX(n, net, v4, MIN(net->pxlen, nlen)))
      break;

    /* We found final node */
    if (nlen >= plen)
    {
      if (nlen == plen)
      {
	/* Find proper local_pos, while accept_length is not used */
	int step = net->pxlen - plen;
	s->start_pos = s->local_pos = (1u << step) + GET_NET_BITS(net, v4, plen, step);
	s->accept_length = plen;
      }
      else
      {
	/* Start from pos 1 in local node, but first try accept mask */
	s->accept_length = net->pxlen;
      }

      s->stack[0] = n;
      return;
    }

    /* Choose child */
    n = GET_CHILD(n, v4, GET_NET_BITS(net, v4, nlen, TRIE_STEP));
  }

  s->stack[0] = NULL;
  return;
}

#define GET_ACCEPT_BIT(N,X,B) ((X) ? ip4_getbit((N)->v4.accept, (B)) : ip6_getbit((N)->v6.accept, (B)))
#define GET_LOCAL_BIT(N,X,B) (((X) ? (N)->v4.local : (N)->v6.local) & (1u << (B)))

/**
 * trie_walk_next
 * @s: walk state
 * @net: return value
 *
 * Find the next prefix in the trie walk and return it in the buffer @net.
 * Prefixes are walked in the usual lexicographic order and may be restricted
 * to a subset of the trie during walk setup by trie_walk_init(). Note that the
 * trie walk does not iterate reliably over 'implicit' prefixes defined by &low
 * and &high fields in prefix patterns, it is supposed to be used on tries
 * constructed from 'explicit' prefixes (&low == &plen == &high in call to
 * trie_add_prefix()).
 *
 * Result: 1 if the next prefix was found, 0 for the end of walk.
 */
int
trie_walk_next(struct f_trie_walk_state *s, net_addr *net)
{
  const struct f_trie_node *n = s->stack[s->stack_pos];
  int len = s->accept_length;
  int pos = s->local_pos;
  int v4 = s->ipv4;

  /*
   * The walk has three basic state variables -- n, len and pos. In each node n,
   * we first walk superprefixes (by len in &accept bitmask), and then we walk
   * internal positions (by pos in &local bitmask). These positions are:
   *
   *          1
   *      2       3
   *    4   5   6   7
   *   8 9 A B C D E F
   *
   * We walk them depth-first, including virtual positions 10-1F that are
   * equivalent of position 1 in child nodes 0-F.
   */

  if (!n)
  {
    memset(net, 0, v4 ? sizeof(net_addr_ip4) : sizeof(net_addr_ip6));
    return 0;
  }

next_node:;
  /* Current node prefix length */
  int nlen = v4 ? n->v4.plen : n->v6.plen;

  /* First, check for accept prefix */
  for (; len < nlen; len++)
    if (GET_ACCEPT_BIT(n, v4, len - 1))
    {
      if (v4)
	net_fill_ip4(net, ip4_and(n->v4.addr, ip4_mkmask(len)), len);
      else
	net_fill_ip6(net, ip6_and(n->v6.addr, ip6_mkmask(len)), len);

      s->local_pos = pos;
      s->accept_length = len + 1;
      return 1;
    }

next_pos:
  /* Bottom of this node */
  if (pos >= (1 << TRIE_STEP))
  {
    const struct f_trie_node *child = GET_CHILD(n, v4, pos - (1 << TRIE_STEP));
    int dir = 0;

    /* No child node */
    if (!child)
    {
      /* Step up until return from left child (pos is even) */
      do
      {
	/* Step up from start node */
	if ((s->stack_pos == 0) && (pos == s->start_pos))
	{
	  s->stack[0] = NULL;
	  memset(net, 0, v4 ? sizeof(net_addr_ip4) : sizeof(net_addr_ip6));
	  return 0;
	}

	/* Top of this node */
	if (pos == 1)
	{
	  ASSERT(s->stack_pos);
	  const struct f_trie_node *old = n;

	  /* Move to parent node */
	  s->stack_pos--;
	  n = s->stack[s->stack_pos];
	  nlen = v4 ? n->v4.plen : n->v6.plen;

	  pos = v4 ?
	    ip4_getbits(old->v4.addr, nlen, TRIE_STEP) :
	    ip6_getbits(old->v6.addr, nlen, TRIE_STEP);
	  pos += (1 << TRIE_STEP);
	  len = nlen;

	  ASSERT(GET_CHILD(n, v4, pos - (1 << TRIE_STEP)) == old);
	}

	/* Step up */
	dir = pos % 2;
	pos = pos / 2;
      }
      while (dir);

      /* Continue with step down to the right child */
      pos = 2 * pos + 1;
      goto next_pos;
    }

    /* Move to child node */
    pos = 1;
    len = nlen + TRIE_STEP;

    s->stack_pos++;
    n = s->stack[s->stack_pos] = child;
    goto next_node;
  }

  /* Check for local prefix */
  if (GET_LOCAL_BIT(n, v4, pos))
  {
    /* Convert pos to address of local network */
    int x = (pos >= 2) + (pos >= 4) + (pos >= 8);
    int y = pos & ((1u << x) - 1);

    if (v4)
      net_fill_ip4(net, !x ? n->v4.addr : ip4_setbits(n->v4.addr, nlen + x - 1, y), nlen + x);
    else
      net_fill_ip6(net, !x ? n->v6.addr : ip6_setbits(n->v6.addr, nlen + x - 1, y), nlen + x);

    s->local_pos = 2 * pos;
    s->accept_length = len;
    return 1;
  }

  /* Step down */
  pos = 2 * pos;
  goto next_pos;
}


static int
trie_node_same4(const struct f_trie_node4 *t1, const struct f_trie_node4 *t2)
{
  if ((t1 == NULL) && (t2 == NULL))
    return 1;

  if ((t1 == NULL) || (t2 == NULL))
    return 0;

  if ((t1->plen != t2->plen) ||
      (! ip4_equal(t1->addr, t2->addr)) ||
      (! ip4_equal(t1->accept, t2->accept)))
    return 0;

  for (uint i = 0; i < (1 << TRIE_STEP); i++)
    if (! trie_node_same4(t1->c[i], t2->c[i]))
      return 0;

  return 1;
}

static int
trie_node_same6(const struct f_trie_node6 *t1, const struct f_trie_node6 *t2)
{
  if ((t1 == NULL) && (t2 == NULL))
    return 1;

  if ((t1 == NULL) || (t2 == NULL))
    return 0;

  if ((t1->plen != t2->plen) ||
      (! ip6_equal(t1->addr, t2->addr)) ||
      (! ip6_equal(t1->accept, t2->accept)))
    return 0;

  for (uint i = 0; i < (1 << TRIE_STEP); i++)
    if (! trie_node_same6(t1->c[i], t2->c[i]))
      return 0;

  return 1;
}

/**
 * trie_same
 * @t1: first trie to be compared
 * @t2: second one
 *
 * Compares two tries and returns 1 if they are same
 */
int
trie_same(const struct f_trie *t1, const struct f_trie *t2)
{
  if ((t1->zero != t2->zero) || (t1->ipv4 != t2->ipv4))
    return 0;

  if (t1->ipv4)
    return trie_node_same4(&t1->root.v4, &t2->root.v4);
  else
    return trie_node_same6(&t1->root.v6, &t2->root.v6);
}


static const u8 log2[16] = {0, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3};

static void
trie_node_format(const struct f_trie_node *n, buffer *buf, int v4)
{
  if (n == NULL)
    return;

  if (v4)
  {
    if (ip4_nonzero(n->v4.accept))
      buffer_print(buf, "%I4/%d{%I4}, ", n->v4.addr, n->v4.plen, n->v4.accept);
  }
  else
  {
    if (ip6_nonzero(n->v6.accept))
      buffer_print(buf, "%I6/%d{%I6}, ", n->v6.addr, n->v6.plen, n->v6.accept);
  }

  int nlen = v4 ? n->v4.plen : n->v6.plen;
  uint local = v4 ? n->v4.local : n->v6.local;

  for (int i = (nlen ? 0 : 1); i < TRIE_STEP; i++)
    if (GET_ACCEPT_BIT(n, v4, nlen + i - 1))
      local &= ~trie_level_mask(1, i);

  for (int pos = 2; local && (pos < (1 << TRIE_STEP)); pos++)
    if (local & (1u << pos))
    {
      int lvl = log2[pos];
      int plen = nlen + lvl;

      int i;
      for (i = 0; lvl + i < TRIE_STEP; i++)
      {
	uint lmask = trie_level_mask(pos, i);

	if ((local & lmask) != lmask)
	  break;

	local &= ~lmask;
      }

      uint addr_bits = pos & ((1u << lvl) - 1);
      uint accept_bits = (1u << i) - 1;
      int h = plen + i - 1;

      if (v4)
      {
	ip4_addr addr = ip4_setbits(n->v4.addr, plen - 1, addr_bits);
	ip4_addr mask = ip4_setbits(IP4_NONE, h - 1, accept_bits);
	buffer_print(buf, "%I4/%d{%I4}, ", addr, plen, mask);
      }
      else
      {
	ip6_addr addr = ip6_setbits(n->v6.addr, plen - 1, addr_bits);
	ip6_addr mask = ip6_setbits(IP6_NONE, h - 1, accept_bits);
	buffer_print(buf, "%I6/%d{%I6}, ", addr, plen, mask);
      }
    }

  for (int i = 0; i < (1 << TRIE_STEP); i++)
    trie_node_format(GET_CHILD(n, v4, i), buf, v4);
}

/**
 * trie_format
 * @t: trie to be formatted
 * @buf: destination buffer
 *
 * Prints the trie to the supplied buffer.
 */
void
trie_format(const struct f_trie *t, buffer *buf)
{
  buffer_puts(buf, "[");

  if (t->zero)
    buffer_print(buf, "%I/%d, ", t->ipv4 ? IPA_NONE4 : IPA_NONE6, 0);

  trie_node_format(&t->root, buf, t->ipv4);

  if (buf->pos == buf->end)
    return;

  /* Undo last separator */
  if (buf->pos[-1] != '[')
    buf->pos -= 2;

  buffer_puts(buf, "]");
}
