/*
 *	Filters: Trie for prefix sets
 *
 *	(c) 2009--2020 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2009--2020 CZ.NIC z.s.p.o.
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

#define GET_ADDR(N,F,X) ((X) ? ipt_from_ip4((N)->v4.F) : ipa_from_ip6((N)->v6.F))
#define SET_ADDR(N,F,X,V) ({ if (X) (N)->v4.F =ipt_to_ip4(V); else (N)->v6.F =ipa_to_ip6(V); })

#define ADD_LOCAL(N,X,V) ({ uint v_ = (V); if (X) (N)->v4.local |= v_; else (N)->v6.local |= v_; })

#define GET_CHILD(N,F,X,I) ((X) ? (struct f_trie_node *) (N)->v4.c[I] : (struct f_trie_node *) (N)->v6.c[I])


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
      local |= ((1u << (1u << i)) - 1) << (1u << i);

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

	  DBG("Case 2\n");
	  return a;
	}

      if (plen == nlen)
	{
	  /* We already found added node in trie. Just update accept and local mask */
	  accept = ipa_or(accept, amask);
	  SET_ADDR(n, accept, v4, accept);
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
      n = GET_CHILD(n, c, v4, ipa_getbits(paddr, nlen, TRIE_STEP));
    }

  /* We add new tail node 'a' after node 'o' */
  struct f_trie_node *a = new_node(t, plen, local, paddr, pmask, amask);
  attach_node(o, a, v4);

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
  case NET_IP4: px = ipt_from_ip4(net4_prefix(net)); v4 = 1; break;
  case NET_IP6: px = ipa_from_ip6(net6_prefix(net)); v4 = 0; break;
  default: bug("invalid type");
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
  ip4_addr pmask = ip4_mkmask(plen);
  ip4_addr paddr = ip4_and(px, pmask);

  if (plen == 0)
    return t->zero;

  int plentest = plen - 1;
  uint nlen = ROUND_DOWN_POW2(plen, TRIE_STEP);
  uint local = trie_local_mask4(px, plen, nlen);
  const struct f_trie_node4 *n = &t->root.v4;

  while (n)
  {
    ip4_addr cmask = ip4_and(n->mask, pmask);

    /* We are out of path */
    if (ip4_compare(ip4_and(paddr, cmask), ip4_and(n->addr, cmask)))
      return 0;

    /* Check local mask */
    if ((n->plen == nlen) && (n->local & local))
      return 1;

    /* Check accept mask */
    if (ip4_getbit(n->accept, plentest))
      return 1;

    /* We finished trie walk and still no match */
    if (plen <= n->plen)
      return 0;

    /* Choose children */
    n =  n->c[ip4_getbits(paddr, n->plen, TRIE_STEP)];
  }

  return 0;
}

static int
trie_match_net6(const struct f_trie *t, ip6_addr px, uint plen)
{
  ip6_addr pmask = ip6_mkmask(plen);
  ip6_addr paddr = ip6_and(px, pmask);

  if (plen == 0)
    return t->zero;

  int plentest = plen - 1;
  uint nlen = ROUND_DOWN_POW2(plen, TRIE_STEP);
  uint local = trie_local_mask6(px, plen, nlen);
  const struct f_trie_node6 *n = &t->root.v6;

  while (n)
  {
    ip6_addr cmask = ip6_and(n->mask, pmask);

    /* We are out of path */
    if (ip6_compare(ip6_and(paddr, cmask), ip6_and(n->addr, cmask)))
      return 0;

    /* Check local mask */
    if ((n->plen == nlen) && (n->local & local))
      return 1;

    /* Check accept mask */
    if (ip6_getbit(n->accept, plentest))
      return 1;

    /* We finished trie walk and still no match */
    if (plen <= n->plen)
      return 0;

    /* Choose children */
    n =  n->c[ip6_getbits(paddr, n->plen, TRIE_STEP)];
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

static void
trie_node_format4(const struct f_trie_node4 *t, buffer *buf)
{
  if (t == NULL)
    return;

  if (ip4_nonzero(t->accept))
    buffer_print(buf, "%I4/%d{%I4}, ", t->addr, t->plen, t->accept);

  for (uint i = 0; i < (1 << TRIE_STEP); i++)
    trie_node_format4(t->c[i], buf);
}

static void
trie_node_format6(const struct f_trie_node6 *t, buffer *buf)
{
  if (t == NULL)
    return;

  if (ip6_nonzero(t->accept))
    buffer_print(buf, "%I6/%d{%I6}, ", t->addr, t->plen, t->accept);

  for (uint i = 0; i < (1 << TRIE_STEP); i++)
    trie_node_format6(t->c[i], buf);
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

  if (t->ipv4)
    trie_node_format4(&t->root.v4, buf);
  else
    trie_node_format6(&t->root.v6, buf);

  if (buf->pos == buf->end)
    return;

  /* Undo last separator */
  if (buf->pos[-1] != '[')
    buf->pos -= 2;

  buffer_puts(buf, "]");
}
