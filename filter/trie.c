/*
 *	Filters: Trie for prefix sets
 *
 *	Copyright 2009 Ondrej Zajicek <santiago@crfreenet.org>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Trie for prefix sets
 *
 * We use a (compressed) trie to represent prefix sets. Every node
 * in the trie represents one prefix (&addr/&plen) and &plen also
 * indicates the index of the bit in the address that is used to
 * branch at the node. If we need to represent just a set of
 * prefixes, it would be simple, but we have to represent a
 * set of prefix patterns. Each prefix pattern consists of
 * &ppaddr/&pplen and two integers: &low and &high, and a prefix
 * &paddr/&plen matches that pattern if the first MIN(&plen, &pplen)
 * bits of &paddr and &ppaddr are the same and &low <= &plen <= &high.
 *
 * We use a bitmask (&accept) to represent accepted prefix lengths
 * at a node. As there are 33 prefix lengths (0..32 for IPv4), but
 * there is just one prefix of zero length in the whole trie so we
 * have &zero flag in &f_trie (indicating whether the trie accepts
 * prefix 0.0.0.0/0) as a special case, and &accept bitmask
 * represents accepted prefix lengths from 1 to 32.
 *
 * There are two cases in prefix matching - a match when the length
 * of the prefix is smaller that the length of the prefix pattern,
 * (&plen < &pplen) and otherwise. The second case is simple - we
 * just walk through the trie and look at every visited node
 * whether that prefix accepts our prefix length (&plen). The
 * first case is tricky - we don't want to examine every descendant
 * of a final node, so (when we create the trie) we have to propagate
 * that information from nodes to their ascendants.
 *
 * Suppose that we have two masks (M1 and M2) for a node. Mask M1
 * represents accepted prefix lengths by just the node and mask M2
 * represents accepted prefix lengths by the node or any of its
 * descendants. Therefore M2 is a bitwise or of M1 and children's
 * M2 and this is a maintained invariant during trie building.
 * Basically, when we want to match a prefix, we walk through the trie,
 * check mask M1 for our prefix length and when we came to
 * final node, we check mask M2.
 *
 * There are two differences in the real implementation. First,
 * we use a compressed trie so there is a case that we skip our
 * final node (if it is not in the trie) and we came to node that
 * is either extension of our prefix, or completely out of path
 * In the first case, we also have to check M2.
 *
 * Second, we really need not to maintain two separate bitmasks.
 * Checks for mask M1 are always larger than &applen and we need
 * just the first &pplen bits of mask M2 (if trie compression
 * hadn't been used it would suffice to know just $applen-th bit),
 * so we have to store them together in &accept mask - the first
 * &pplen bits of mask M2 and then mask M1.
 *
 * There are four cases when we walk through a trie:
 *
 * - we are in NULL
 * - we are out of path (prefixes are inconsistent)
 * - we are in the wanted (final) node (node length == &plen)
 * - we are beyond the end of path (node length > &plen)
 * - we are still on path and keep walking (node length < &plen)
 *
 * The walking code in trie_match_prefix() is structured according to
 * these cases.
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
#define ipa_getbit(x,n) ip6_getbit(x,n)

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
new_node4(struct f_trie *t, int plen, ip4_addr paddr, ip4_addr pmask, ip4_addr amask)
{
  struct f_trie_node4 *n = lp_allocz(t->lp, sizeof(struct f_trie_node4) + t->data_size);
  n->plen = plen;
  n->addr = paddr;
  n->mask = pmask;
  n->accept = amask;
  return n;
}

static inline struct f_trie_node6 *
new_node6(struct f_trie *t, int plen, ip6_addr paddr, ip6_addr pmask, ip6_addr amask)
{
  struct f_trie_node6 *n = lp_allocz(t->lp, sizeof(struct f_trie_node6) + t->data_size);
  n->plen = plen;
  n->addr = paddr;
  n->mask = pmask;
  n->accept = amask;
  return n;
}

static inline struct f_trie_node *
new_node(struct f_trie *t, int plen, ip_addr paddr, ip_addr pmask, ip_addr amask)
{
  if (t->ipv4)
    return (struct f_trie_node *) new_node4(t, plen, ipt_to_ip4(paddr), ipt_to_ip4(pmask), ipt_to_ip4(amask));
  else
    return (struct f_trie_node *) new_node6(t, plen, ipa_to_ip6(paddr), ipa_to_ip6(pmask), ipa_to_ip6(amask));
}

static inline void
attach_node4(struct f_trie_node4 *parent, struct f_trie_node4 *child)
{
  parent->c[ip4_getbit(child->addr, parent->plen) ? 1 : 0] = child;
}

static inline void
attach_node6(struct f_trie_node6 *parent, struct f_trie_node6 *child)
{
  parent->c[ip6_getbit(child->addr, parent->plen) ? 1 : 0] = child;
}

static inline void
attach_node(struct f_trie_node *parent, struct f_trie_node *child, int v4)
{
  if (v4)
    attach_node4(&parent->v4, &child->v4);
  else
    attach_node6(&parent->v6, &child->v6);
}

#define GET_ADDR(N,F,X) ((X) ? ipt_from_ip4((N)->v4.F) : ipa_from_ip6((N)->v6.F))
#define SET_ADDR(N,F,X,V) ({ if (X) (N)->v4.F =ipt_to_ip4(V); else (N)->v6.F =ipa_to_ip6(V); })

#define GET_CHILD(N,F,X,I) ((X) ? (struct f_trie_node *) (N)->v4.c[I] : (struct f_trie_node *) (N)->v6.c[I])
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

  if (l == 0)
    t->zero = 1;
  else
    l--;

  if (h < plen)
    plen = h;

  ip_addr amask = ipa_xor(ipa_mkmask(l), ipa_mkmask(h));
  ip_addr pmask = ipa_mkmask(plen);
  ip_addr paddr = ipa_and(px, pmask);
  struct f_trie_node *o = NULL;
  struct f_trie_node *n = &t->root;

  while (n)
    {
      ip_addr naddr = GET_ADDR(n, addr, v4);
      ip_addr nmask = GET_ADDR(n, mask, v4);
      ip_addr accept = GET_ADDR(n, accept, v4);
      ip_addr cmask = ipa_and(nmask, pmask);
      uint nlen = v4 ? n->v4.plen : n->v6.plen;

      if (ipa_compare(ipa_and(paddr, cmask), ipa_and(naddr, cmask)))
        {
	  /* We are out of path - we have to add branching node 'b'
	     between node 'o' and node 'n', and attach new node 'a'
	     as the other child of 'b'. */
	  int blen = ipa_pxlen(paddr, naddr);
	  ip_addr bmask = ipa_mkmask(blen);
	  ip_addr baddr = ipa_and(px, bmask);

	  /* Merge accept masks from children to get accept mask for node 'b' */
	  ip_addr baccm = ipa_and(ipa_or(amask, accept), bmask);

	  struct f_trie_node *a = new_node(t, plen, paddr, pmask, amask);
	  struct f_trie_node *b = new_node(t, blen, baddr, bmask, baccm);
	  attach_node(o, b, v4);
	  attach_node(b, n, v4);
	  attach_node(b, a, v4);
	  return a;
	}

      if (plen < nlen)
	{
	  /* We add new node 'a' between node 'o' and node 'n' */
	  amask = ipa_or(amask, ipa_and(accept, pmask));
	  struct f_trie_node *a = new_node(t, plen, paddr, pmask, amask);
	  attach_node(o, a, v4);
	  attach_node(a, n, v4);
	  return a;
	}

      if (plen == nlen)
	{
	  /* We already found added node in trie. Just update accept mask */
	  accept = ipa_or(accept, amask);
	  SET_ADDR(n, accept, v4, accept);
	  return n;
	}

      /* Update accept mask part M2 and go deeper */
      accept = ipa_or(accept, ipa_and(amask, nmask));
      SET_ADDR(n, accept, v4, accept);

      /* n->plen < plen and plen <= 32 (128) */
      o = n;
      n = GET_CHILD(n, c, v4, ipa_getbit(paddr, nlen) ? 1 : 0);
    }

  /* We add new tail node 'a' after node 'o' */
  struct f_trie_node *a = new_node(t, plen, paddr, pmask, amask);
  attach_node(o, a, v4);

  return a;
}

static int
trie_match_net4(const struct f_trie *t, ip4_addr px, uint plen)
{
  ip4_addr pmask = ip4_mkmask(plen);
  ip4_addr paddr = ip4_and(px, pmask);

  if (plen == 0)
    return t->zero;

  int plentest = plen - 1;
  const struct f_trie_node4 *n = &t->root.v4;

  while (n)
  {
    ip4_addr cmask = ip4_and(n->mask, pmask);

    /* We are out of path */
    if (ip4_compare(ip4_and(paddr, cmask), ip4_and(n->addr, cmask)))
      return 0;

    /* Check accept mask */
    if (ip4_getbit(n->accept, plentest))
      return 1;

    /* We finished trie walk and still no match */
    if (plen <= n->plen)
      return 0;

    /* Choose children */
    n =  n->c[(ip4_getbit(paddr, n->plen)) ? 1 : 0];
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
  const struct f_trie_node6 *n = &t->root.v6;

  while (n)
  {
    ip6_addr cmask = ip6_and(n->mask, pmask);

    /* We are out of path */
    if (ip6_compare(ip6_and(paddr, cmask), ip6_and(n->addr, cmask)))
      return 0;

    /* Check accept mask */
    if (ip6_getbit(n->accept, plentest))
      return 1;

    /* We finished trie walk and still no match */
    if (plen <= n->plen)
      return 0;

    /* Choose children */
    n =  n->c[(ip6_getbit(paddr, n->plen)) ? 1 : 0];
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

  return trie_node_same4(t1->c[0], t2->c[0]) && trie_node_same4(t1->c[1], t2->c[1]);
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

  return trie_node_same6(t1->c[0], t2->c[0]) && trie_node_same6(t1->c[1], t2->c[1]);
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

  trie_node_format4(t->c[0], buf);
  trie_node_format4(t->c[1], buf);
}

static void
trie_node_format6(const struct f_trie_node6 *t, buffer *buf)
{
  if (t == NULL)
    return;

  if (ip6_nonzero(t->accept))
    buffer_print(buf, "%I6/%d{%I6}, ", t->addr, t->plen, t->accept);

  trie_node_format6(t->c[0], buf);
  trie_node_format6(t->c[1], buf);
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
