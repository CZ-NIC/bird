/*
 *	BIRD Internet Routing Daemon -- Multiway Prefix Tries
 *
 *	(c) 2009--2021 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2009--2021 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_FILTER_TRIE_H_
#define _BIRD_FILTER_TRIE_H_

#include "nest/bird.h"
#include "lib/types-enums.h"
#include "lib/types-union.h"

/* IP prefix range structure */
struct f_prefix {
  net_addr net;		/* The matching prefix must match this net */
  u8 lo, hi;		/* And its length must fit between lo and hi */
};

#ifdef ENABLE_COMPACT_TRIES
/* Compact 4-way tries */
#define TRIE_STEP		2
#define TRIE_STACK_LENGTH	65
#else
/* Faster 16-way tries */
#define TRIE_STEP		4
#define TRIE_STACK_LENGTH	33
#endif

struct f_trie_node4
{
  ip4_addr addr, mask, accept;
  u16 plen;
  u16 local;
  struct f_trie_node4 *c[1 << TRIE_STEP];
};

struct f_trie_node6
{
  ip6_addr addr, mask, accept;
  u16 plen;
  u16 local;
  struct f_trie_node6 *c[1 << TRIE_STEP];
};

struct f_trie_node
{
  union {
    struct f_trie_node4 v4;
    struct f_trie_node6 v6;
  };
};

struct f_trie
{
  linpool *lp;
  u8 zero;
  s8 ipv4;				/* -1 for undefined / empty */
  u16 data_size;			/* Additional data for each trie node */
  u32 prefix_count;			/* Works only for restricted tries (pxlen == l == h) */
  struct f_trie_node root;		/* Root trie node */
};

struct f_trie_walk_state
{
  u8 ipv4;
  u8 accept_length;			/* Current inter-node prefix position */
  u8 start_pos;				/* Initial prefix position in stack[0] */
  u8 local_pos;				/* Current intra-node prefix position */
  u8 stack_pos;				/* Current node in stack below */
  const struct f_trie_node *stack[TRIE_STACK_LENGTH];
};

struct f_trie *f_new_trie(linpool *lp, uint data_size);
void *trie_add_prefix(struct f_trie *t, const net_addr *n, uint l, uint h);
int trie_match_net(const struct f_trie *t, const net_addr *n);
int trie_match_longest_ip4(const struct f_trie *t, const net_addr_ip4 *net, net_addr_ip4 *dst, ip4_addr *found0);
int trie_match_longest_ip6(const struct f_trie *t, const net_addr_ip6 *net, net_addr_ip6 *dst, ip6_addr *found0);
void trie_walk_init(struct f_trie_walk_state *s, const struct f_trie *t, const net_addr *from);
int trie_walk_next(struct f_trie_walk_state *s, net_addr *net);
int trie_same(const struct f_trie *t1, const struct f_trie *t2);
void trie_format(const struct f_trie *t, buffer *buf);

static inline int
trie_match_next_longest_ip4(net_addr_ip4 *n, ip4_addr *found)
{
  while (n->pxlen)
  {
    n->pxlen--;
    ip4_clrbit(&n->prefix, n->pxlen);

    if (ip4_getbit(*found, n->pxlen))
      return 1;
  }

  return 0;
}

static inline int
trie_match_next_longest_ip6(net_addr_ip6 *n, ip6_addr *found)
{
  while (n->pxlen)
  {
    n->pxlen--;
    ip6_clrbit(&n->prefix, n->pxlen);

    if (ip6_getbit(*found, n->pxlen))
      return 1;
  }

  return 0;
}


#define TRIE_WALK_TO_ROOT_IP4(trie, net, dst) ({		\
  net_addr_ip4 dst;						\
  ip4_addr _found;						\
  for (int _n = trie_match_longest_ip4(trie, net, &dst, &_found); \
       _n;							\
       _n = trie_match_next_longest_ip4(&dst, &_found))

#define TRIE_WALK_TO_ROOT_IP6(trie, net, dst) ({		\
  net_addr_ip6 dst;						\
  ip6_addr _found;						\
  for (int _n = trie_match_longest_ip6(trie, net, &dst, &_found); \
       _n;							\
       _n = trie_match_next_longest_ip6(&dst, &_found))

#define TRIE_WALK_TO_ROOT_END })


#define TRIE_WALK(trie, net, from) ({				\
  net_addr net;							\
  struct f_trie_walk_state tws_;				\
  trie_walk_init(&tws_, trie, from);				\
  while (trie_walk_next(&tws_, &net))

#define TRIE_WALK_END })


#endif
