/*
 *	BIRD -- Routing Tables
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Routing tables
 *
 * Routing tables are probably the most important structures BIRD uses. They
 * hold all the information about known networks, the associated routes and
 * their attributes.
 *
 * There are multiple routing tables (a primary one together with any
 * number of secondary ones if requested by the configuration). Each table
 * is basically a FIB containing entries describing the individual
 * destination networks. For each network (represented by structure &net),
 * there is a one-way linked list of route entries (&rte), the first entry
 * on the list being the best one (i.e., the one we currently use
 * for routing), the order of the other ones is undetermined.
 *
 * The &rte contains information about the route. There are net and src, which
 * together forms a key identifying the route in a routing table. There is a
 * pointer to a &rta structure (see the route attribute module for a precise
 * explanation) holding the route attributes, which are primary data about the
 * route. There are several technical fields used by routing table code (route
 * id, REF_* flags), There is also the pflags field, holding protocol-specific
 * flags. They are not used by routing table code, but by protocol-specific
 * hooks. In contrast to route attributes, they are not primary data and their
 * validity is also limited to the routing table.
 *
 * There are several mechanisms that allow automatic update of routes in one
 * routing table (dst) as a result of changes in another routing table (src).
 * They handle issues of recursive next hop resolving, flowspec validation and
 * RPKI validation.
 *
 * The first such mechanism is handling of recursive next hops. A route in the
 * dst table has an indirect next hop address, which is resolved through a route
 * in the src table (which may also be the same table) to get an immediate next
 * hop. This is implemented using structure &hostcache attached to the src
 * table, which contains &hostentry structures for each tracked next hop
 * address. These structures are linked from recursive routes in dst tables,
 * possibly multiple routes sharing one hostentry (as many routes may have the
 * same indirect next hop). There is also a trie in the hostcache, which matches
 * all prefixes that may influence resolving of tracked next hops.
 *
 * When a best route changes in the src table, the hostcache is notified using
 * an auxiliary export request, which checks using the trie whether the
 * change is relevant and if it is, then it schedules asynchronous hostcache
 * recomputation. The recomputation is done by rt_update_hostcache() (called
 * as an event of src table), it walks through all hostentries and resolves
 * them (by rt_update_hostentry()). It also updates the trie. If a change in
 * hostentry resolution was found, then it schedules asynchronous nexthop
 * recomputation of associated dst table. That is done by rt_next_hop_update()
 * (called from rt_event() of dst table), it iterates over all routes in the dst
 * table and re-examines their hostentries for changes. Note that in contrast to
 * hostcache update, next hop update can be interrupted by main loop. These two
 * full-table walks (over hostcache and dst table) are necessary due to absence
 * of direct lookups (route -> affected nexthop, nexthop -> its route).
 *
 * The second mechanism is for flowspec validation, where validity of flowspec
 * routes depends of resolving their network prefixes in IP routing tables. This
 * is similar to the recursive next hop mechanism, but simpler as there are no
 * intermediate hostcache and hostentries (because flows are less likely to
 * share common net prefix than routes sharing a common next hop). Every dst
 * table has its own export request in every src table. Each dst table has its
 * own trie of prefixes that may influence validation of flowspec routes in it
 * (flowspec_trie).
 *
 * When a best route changes in the src table, the notification mechanism is
 * invoked by the export request which checks its dst table's trie to see
 * whether the change is relevant, and if so, an asynchronous re-validation of
 * flowspec routes in the dst table is scheduled. That is also done by function
 * rt_next_hop_update(), like nexthop recomputation above. It iterates over all
 * flowspec routes and re-validates them. It also recalculates the trie.
 *
 * Note that in contrast to the hostcache update, here the trie is recalculated
 * during the rt_next_hop_update(), which may be interleaved with IP route
 * updates. The trie is flushed at the beginning of recalculation, which means
 * that such updates may use partial trie to see if they are relevant. But it
 * works anyway! Either affected flowspec was already re-validated and added to
 * the trie, then IP route change would match the trie and trigger a next round
 * of re-validation, or it was not yet re-validated and added to the trie, but
 * will be re-validated later in this round anyway.
 *
 * The third mechanism is used for RPKI re-validation of IP routes and it is the
 * simplest. It is also an auxiliary export request belonging to the
 * appropriate channel, triggering its reload/refeed timer after a settle time.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/rt.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/resource.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/string.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/data.h"
#include "lib/hash.h"
#include "lib/string.h"
#include "lib/alloca.h"
#include "lib/flowspec.h"
#include "lib/idm.h"

#ifdef CONFIG_BGP
#include "proto/bgp/bgp.h"
#endif

#include <stdatomic.h>

pool *rt_table_pool;

list routing_tables;
list deleted_routing_tables;

struct rt_cork rt_cork;

/* Data structures for export journal */
#define RT_PENDING_EXPORT_ITEMS		(page_size - sizeof(struct rt_export_block)) / sizeof(struct rt_pending_export)

struct rt_export_block {
  node n;
  _Atomic u32 end;
  _Atomic _Bool not_last;
  struct rt_pending_export export[];
};

static void rt_free_hostcache(struct rtable_private *tab);
static void rt_update_hostcache(void *tab);
static void rt_next_hop_update(struct rtable_private *tab);
static void rt_nhu_uncork(void *_tab);
static inline void rt_next_hop_resolve_rte(rte *r);
static inline void rt_flowspec_resolve_rte(rte *r, struct channel *c);
static inline void rt_prune_table(struct rtable_private *tab);
static void rt_kick_prune_timer(struct rtable_private *tab);
static void rt_feed_by_fib(void *);
static void rt_feed_by_trie(void *);
static void rt_feed_equal(void *);
static void rt_feed_for(void *);
static void rt_check_cork_low(struct rtable_private *tab);
static void rt_check_cork_high(struct rtable_private *tab);
static void rt_cork_release_hook(void *);
static void rt_shutdown(void *);
static void rt_delete(void *);

static void rt_export_used(struct rt_table_exporter *, const char *, const char *);
static void rt_export_cleanup(struct rtable_private *tab);

static int rte_same(rte *x, rte *y);

const char *rt_import_state_name_array[TIS_MAX] = {
  [TIS_DOWN] = "DOWN",
  [TIS_UP] = "UP",
  [TIS_STOP] = "STOP",
  [TIS_FLUSHING] = "FLUSHING",
  [TIS_WAITING] = "WAITING",
  [TIS_CLEARED] = "CLEARED",
};

const char *rt_export_state_name_array[TES_MAX] = {
  [TES_DOWN] = "DOWN",
  [TES_HUNGRY] = "HUNGRY",
  [TES_FEEDING] = "FEEDING",
  [TES_READY] = "READY",
  [TES_STOP] = "STOP"
};

const char *rt_import_state_name(u8 state)
{
  if (state >= TIS_MAX)
    return "!! INVALID !!";
  else
    return rt_import_state_name_array[state];
}

const char *rt_export_state_name(u8 state)
{
  if (state >= TES_MAX)
    return "!! INVALID !!";
  else
    return rt_export_state_name_array[state];
}

static struct hostentry *rt_get_hostentry(struct rtable_private *tab, ip_addr a, ip_addr ll, rtable *dep);

static inline rtable *rt_priv_to_pub(struct rtable_private *tab) { return RT_PUB(tab); }
static inline rtable *rt_pub_to_pub(rtable *tab) { return tab; }
#define RT_ANY_TO_PUB(tab)	_Generic((tab),rtable*:rt_pub_to_pub,struct rtable_private*:rt_priv_to_pub)((tab))

#define rt_trace(tab, level, fmt, args...)  do {\
  rtable *t = RT_ANY_TO_PUB((tab));		\
  if (t->config->debug & (level))		\
    log(L_TRACE "%s: " fmt, t->name, ##args);	\
} while (0)

static void
net_init_with_trie(struct fib *f, void *N)
{
  struct rtable_private *tab = SKIP_BACK(struct rtable_private, fib, f);
  net *n = N;

  if (tab->trie)
    trie_add_prefix(tab->trie, n->n.addr, n->n.addr->pxlen, n->n.addr->pxlen);

  if (tab->trie_new)
    trie_add_prefix(tab->trie_new, n->n.addr, n->n.addr->pxlen, n->n.addr->pxlen);
}

static inline net *
net_route_ip4_trie(struct rtable_private *t, const net_addr_ip4 *n0)
{
  TRIE_WALK_TO_ROOT_IP4(t->trie, n0, n)
  {
    net *r;
    if (r = net_find_valid(t, (net_addr *) &n))
      return r;
  }
  TRIE_WALK_TO_ROOT_END;

  return NULL;
}

static inline net *
net_route_vpn4_trie(struct rtable_private *t, const net_addr_vpn4 *n0)
{
  TRIE_WALK_TO_ROOT_IP4(t->trie, (const net_addr_ip4 *) n0, px)
  {
    net_addr_vpn4 n = NET_ADDR_VPN4(px.prefix, px.pxlen, n0->rd);

    net *r;
    if (r = net_find_valid(t, (net_addr *) &n))
      return r;
  }
  TRIE_WALK_TO_ROOT_END;

  return NULL;
}

static inline net *
net_route_ip6_trie(struct rtable_private *t, const net_addr_ip6 *n0)
{
  TRIE_WALK_TO_ROOT_IP6(t->trie, n0, n)
  {
    net *r;
    if (r = net_find_valid(t, (net_addr *) &n))
      return r;
  }
  TRIE_WALK_TO_ROOT_END;

  return NULL;
}

static inline net *
net_route_vpn6_trie(struct rtable_private *t, const net_addr_vpn6 *n0)
{
  TRIE_WALK_TO_ROOT_IP6(t->trie, (const net_addr_ip6 *) n0, px)
  {
    net_addr_vpn6 n = NET_ADDR_VPN6(px.prefix, px.pxlen, n0->rd);

    net *r;
    if (r = net_find_valid(t, (net_addr *) &n))
      return r;
  }
  TRIE_WALK_TO_ROOT_END;

  return NULL;
}

static inline void *
net_route_ip6_sadr_trie(struct rtable_private *t, const net_addr_ip6_sadr *n0)
{
  TRIE_WALK_TO_ROOT_IP6(t->trie, (const net_addr_ip6 *) n0, px)
  {
    net_addr_ip6_sadr n = NET_ADDR_IP6_SADR(px.prefix, px.pxlen, n0->src_prefix, n0->src_pxlen);
    net *best = NULL;
    int best_pxlen = 0;

    /* We need to do dst first matching. Since sadr addresses are hashed on dst
       prefix only, find the hash table chain and go through it to find the
       match with the longest matching src prefix. */
    for (struct fib_node *fn = fib_get_chain(&t->fib, (net_addr *) &n); fn; fn = fn->next)
    {
      net_addr_ip6_sadr *a = (void *) fn->addr;

      if (net_equal_dst_ip6_sadr(&n, a) &&
	  net_in_net_src_ip6_sadr(&n, a) &&
	  (a->src_pxlen >= best_pxlen))
      {
	best = fib_node_to_user(&t->fib, fn);
	best_pxlen = a->src_pxlen;
      }
    }

    if (best)
      return best;
  }
  TRIE_WALK_TO_ROOT_END;

  return NULL;
}

static inline net *
net_route_ip4_fib(struct rtable_private *t, const net_addr_ip4 *n0)
{
  net_addr_ip4 n;
  net_copy_ip4(&n, n0);

  net *r;
  while (r = net_find_valid(t, (net_addr *) &n), (!r) && (n.pxlen > 0))
  {
    n.pxlen--;
    ip4_clrbit(&n.prefix, n.pxlen);
  }

  return r;
}

static inline net *
net_route_vpn4_fib(struct rtable_private *t, const net_addr_vpn4 *n0)
{
  net_addr_vpn4 n;
  net_copy_vpn4(&n, n0);

  net *r;
  while (r = net_find_valid(t, (net_addr *) &n), (!r) && (n.pxlen > 0))
  {
    n.pxlen--;
    ip4_clrbit(&n.prefix, n.pxlen);
  }

  return r;
}

static inline net *
net_route_ip6_fib(struct rtable_private *t, const net_addr_ip6 *n0)
{
  net_addr_ip6 n;
  net_copy_ip6(&n, n0);

  net *r;
  while (r = net_find_valid(t, (net_addr *) &n), (!r) && (n.pxlen > 0))
  {
    n.pxlen--;
    ip6_clrbit(&n.prefix, n.pxlen);
  }

  return r;
}

static inline net *
net_route_vpn6_fib(struct rtable_private *t, const net_addr_vpn6 *n0)
{
  net_addr_vpn6 n;
  net_copy_vpn6(&n, n0);

  net *r;
  while (r = net_find_valid(t, (net_addr *) &n), (!r) && (n.pxlen > 0))
  {
    n.pxlen--;
    ip6_clrbit(&n.prefix, n.pxlen);
  }

  return r;
}

static inline void *
net_route_ip6_sadr_fib(struct rtable_private *t, const net_addr_ip6_sadr *n0)
{
  net_addr_ip6_sadr n;
  net_copy_ip6_sadr(&n, n0);

  while (1)
  {
    net *best = NULL;
    int best_pxlen = 0;

    /* We need to do dst first matching. Since sadr addresses are hashed on dst
       prefix only, find the hash table chain and go through it to find the
       match with the longest matching src prefix. */
    for (struct fib_node *fn = fib_get_chain(&t->fib, (net_addr *) &n); fn; fn = fn->next)
    {
      net_addr_ip6_sadr *a = (void *) fn->addr;

      if (net_equal_dst_ip6_sadr(&n, a) &&
	  net_in_net_src_ip6_sadr(&n, a) &&
	  (a->src_pxlen >= best_pxlen))
      {
	best = fib_node_to_user(&t->fib, fn);
	best_pxlen = a->src_pxlen;
      }
    }

    if (best)
      return best;

    if (!n.dst_pxlen)
      break;

    n.dst_pxlen--;
    ip6_clrbit(&n.dst_prefix, n.dst_pxlen);
  }

  return NULL;
}

net *
net_route(struct rtable_private *tab, const net_addr *n)
{
  ASSERT(tab->addr_type == n->type);

  switch (n->type)
  {
  case NET_IP4:
    if (tab->trie)
      return net_route_ip4_trie(tab, (net_addr_ip4 *) n);
    else
      return net_route_ip4_fib (tab, (net_addr_ip4 *) n);

  case NET_VPN4:
    if (tab->trie)
      return net_route_vpn4_trie(tab, (net_addr_vpn4 *) n);
    else
      return net_route_vpn4_fib (tab, (net_addr_vpn4 *) n);

  case NET_IP6:
    if (tab->trie)
      return net_route_ip6_trie(tab, (net_addr_ip6 *) n);
    else
      return net_route_ip6_fib (tab, (net_addr_ip6 *) n);

  case NET_VPN6:
    if (tab->trie)
      return net_route_vpn6_trie(tab, (net_addr_vpn6 *) n);
    else
      return net_route_vpn6_fib (tab, (net_addr_vpn6 *) n);

  case NET_IP6_SADR:
    if (tab->trie)
      return net_route_ip6_sadr_trie(tab, (net_addr_ip6_sadr *) n);
    else
      return net_route_ip6_sadr_fib (tab, (net_addr_ip6_sadr *) n);

  default:
    return NULL;
  }
}


static int
net_roa_check_ip4_trie(struct rtable_private *tab, const net_addr_ip4 *px, u32 asn)
{
  int anything = 0;

  TRIE_WALK_TO_ROOT_IP4(tab->trie, px, px0)
  {
    net_addr_roa4 roa0 = NET_ADDR_ROA4(px0.prefix, px0.pxlen, 0, 0);

    struct fib_node *fn;
    for (fn = fib_get_chain(&tab->fib, (net_addr *) &roa0); fn; fn = fn->next)
    {
      net_addr_roa4 *roa = (void *) fn->addr;
      net *r = fib_node_to_user(&tab->fib, fn);

      if (net_equal_prefix_roa4(roa, &roa0) && r->routes && rte_is_valid(&r->routes->rte))
      {
	anything = 1;
	if (asn && (roa->asn == asn) && (roa->max_pxlen >= px->pxlen))
	  return ROA_VALID;
      }
    }
  }
  TRIE_WALK_TO_ROOT_END;

  return anything ? ROA_INVALID : ROA_UNKNOWN;
}

static int
net_roa_check_ip4_fib(struct rtable_private *tab, const net_addr_ip4 *px, u32 asn)
{
  struct net_addr_roa4 n = NET_ADDR_ROA4(px->prefix, px->pxlen, 0, 0);
  struct fib_node *fn;
  int anything = 0;

  while (1)
  {
    for (fn = fib_get_chain(&tab->fib, (net_addr *) &n); fn; fn = fn->next)
    {
      net_addr_roa4 *roa = (void *) fn->addr;
      net *r = fib_node_to_user(&tab->fib, fn);

      if (net_equal_prefix_roa4(roa, &n) && r->routes && rte_is_valid(&r->routes->rte))
      {
	anything = 1;
	if (asn && (roa->asn == asn) && (roa->max_pxlen >= px->pxlen))
	  return ROA_VALID;
      }
    }

    if (n.pxlen == 0)
      break;

    n.pxlen--;
    ip4_clrbit(&n.prefix, n.pxlen);
  }

  return anything ? ROA_INVALID : ROA_UNKNOWN;
}

static int
net_roa_check_ip6_trie(struct rtable_private *tab, const net_addr_ip6 *px, u32 asn)
{
  int anything = 0;

  TRIE_WALK_TO_ROOT_IP6(tab->trie, px, px0)
  {
    net_addr_roa6 roa0 = NET_ADDR_ROA6(px0.prefix, px0.pxlen, 0, 0);

    struct fib_node *fn;
    for (fn = fib_get_chain(&tab->fib, (net_addr *) &roa0); fn; fn = fn->next)
    {
      net_addr_roa6 *roa = (void *) fn->addr;
      net *r = fib_node_to_user(&tab->fib, fn);

      if (net_equal_prefix_roa6(roa, &roa0) && r->routes && rte_is_valid(&r->routes->rte))
      {
	anything = 1;
	if (asn && (roa->asn == asn) && (roa->max_pxlen >= px->pxlen))
	  return ROA_VALID;
      }
    }
  }
  TRIE_WALK_TO_ROOT_END;

  return anything ? ROA_INVALID : ROA_UNKNOWN;
}

static int
net_roa_check_ip6_fib(struct rtable_private *tab, const net_addr_ip6 *px, u32 asn)
{
  struct net_addr_roa6 n = NET_ADDR_ROA6(px->prefix, px->pxlen, 0, 0);
  struct fib_node *fn;
  int anything = 0;

  while (1)
  {
    for (fn = fib_get_chain(&tab->fib, (net_addr *) &n); fn; fn = fn->next)
    {
      net_addr_roa6 *roa = (void *) fn->addr;
      net *r = fib_node_to_user(&tab->fib, fn);

      if (net_equal_prefix_roa6(roa, &n) && r->routes && rte_is_valid(&r->routes->rte))
      {
	anything = 1;
	if (asn && (roa->asn == asn) && (roa->max_pxlen >= px->pxlen))
	  return ROA_VALID;
      }
    }

    if (n.pxlen == 0)
      break;

    n.pxlen--;
    ip6_clrbit(&n.prefix, n.pxlen);
  }

  return anything ? ROA_INVALID : ROA_UNKNOWN;
}

/**
 * roa_check - check validity of route origination in a ROA table
 * @tab: ROA table
 * @n: network prefix to check
 * @asn: AS number of network prefix
 *
 * Implements RFC 6483 route validation for the given network prefix. The
 * procedure is to find all candidate ROAs - ROAs whose prefixes cover the given
 * network prefix. If there is no candidate ROA, return ROA_UNKNOWN. If there is
 * a candidate ROA with matching ASN and maxlen field greater than or equal to
 * the given prefix length, return ROA_VALID. Otherwise, return ROA_INVALID. If
 * caller cannot determine origin AS, 0 could be used (in that case ROA_VALID
 * cannot happen). Table @tab must have type NET_ROA4 or NET_ROA6, network @n
 * must have type NET_IP4 or NET_IP6, respectively.
 */
int
net_roa_check(rtable *tp, const net_addr *n, u32 asn)
{
  int out = ROA_UNKNOWN;

  RT_LOCKED(tp, tab)
  {
    if ((tab->addr_type == NET_ROA4) && (n->type == NET_IP4))
    {
      if (tab->trie)
	out = net_roa_check_ip4_trie(tab, (const net_addr_ip4 *) n, asn);
      else
	out = net_roa_check_ip4_fib (tab, (const net_addr_ip4 *) n, asn);
    }
    else if ((tab->addr_type == NET_ROA6) && (n->type == NET_IP6))
    {
      if (tab->trie)
	out = net_roa_check_ip6_trie(tab, (const net_addr_ip6 *) n, asn);
      else
	out = net_roa_check_ip6_fib (tab, (const net_addr_ip6 *) n, asn);
    }
    else
      out = ROA_UNKNOWN;	/* Should not happen */
  }
  return out;
}

/**
 * rte_find - find a route
 * @net: network node
 * @src: route source
 *
 * The rte_find() function returns a pointer to a route for destination @net
 * which is from route source @src. List end pointer is returned if no route is found.
 */
static struct rte_storage **
rte_find(net *net, struct rte_src *src)
{
  struct rte_storage **e = &net->routes;

  while ((*e) && (*e)->rte.src != src)
    e = &(*e)->next;

  return e;
}


struct rte_storage *
rte_store(const rte *r, net *net, struct rtable_private *tab)
{
  struct rte_storage *e = sl_alloc(tab->rte_slab);

  e->rte = *r;
  e->rte.net = net->n.addr;

  rt_lock_source(e->rte.src);

  if (ea_is_cached(e->rte.attrs))
    e->rte.attrs = rta_clone(e->rte.attrs);
  else
    e->rte.attrs = rta_lookup(e->rte.attrs, 1);

  return e;
}

/**
 * rte_free - delete a &rte
 * @e: &struct rte_storage to be deleted
 * @tab: the table which the rte belongs to
 *
 * rte_free() deletes the given &rte from the routing table it's linked to.
 */

void
rte_free(struct rte_storage *e)
{
  rt_unlock_source(e->rte.src);
  rta_free(e->rte.attrs);
  sl_free(e);
}

static int				/* Actually better or at least as good as */
rte_better(rte *new, rte *old)
{
  int (*better)(rte *, rte *);

  if (!rte_is_valid(old))
    return 1;
  if (!rte_is_valid(new))
    return 0;

  u32 np = rt_get_preference(new);
  u32 op = rt_get_preference(old);

  if (np > op)
    return 1;
  if (np < op)
    return 0;
  if (new->src->owner->class != old->src->owner->class)
    {
      /*
       *  If the user has configured protocol preferences, so that two different protocols
       *  have the same preference, try to break the tie by comparing addresses. Not too
       *  useful, but keeps the ordering of routes unambiguous.
       */
      return new->src->owner->class > old->src->owner->class;
    }
  if (better = new->src->owner->class->rte_better)
    return better(new, old);
  return 0;
}

static int
rte_mergable(rte *pri, rte *sec)
{
  int (*mergable)(rte *, rte *);

  if (!rte_is_valid(pri) || !rte_is_valid(sec))
    return 0;

  if (rt_get_preference(pri) != rt_get_preference(sec))
    return 0;

  if (pri->src->owner->class != sec->src->owner->class)
    return 0;

  if (mergable = pri->src->owner->class->rte_mergable)
    return mergable(pri, sec);

  return 0;
}

static void
rte_trace(const char *name, const rte *e, int dir, const char *msg)
{
  log(L_TRACE "%s %c %s %N src %uL %uG %uS id %u %s",
      name, dir, msg, e->net,
      e->src->private_id, e->src->global_id, e->stale_cycle, e->id,
      rta_dest_name(rte_dest(e)));
}

static inline void
channel_rte_trace_in(uint flag, struct channel *c, const rte *e, const char *msg)
{
  if ((c->debug & flag) || (c->proto->debug & flag))
    rte_trace(c->in_req.name, e, '>', msg);
}

static inline void
channel_rte_trace_out(uint flag, struct channel *c, const rte *e, const char *msg)
{
  if ((c->debug & flag) || (c->proto->debug & flag))
    rte_trace(c->out_req.name, e, '<', msg);
}

static inline void
rt_rte_trace_in(uint flag, struct rt_import_request *req, const rte *e, const char *msg)
{
  if (req->trace_routes & flag)
    rte_trace(req->name, e, '>', msg);
}

#if 0
// seems to be unused at all
static inline void
rt_rte_trace_out(uint flag, struct rt_export_request *req, const rte *e, const char *msg)
{
  if (req->trace_routes & flag)
    rte_trace(req->name, e, '<', msg);
}
#endif

static uint
rte_feed_count(net *n)
{
  uint count = 0;
  for (struct rte_storage *e = n->routes; e; e = e->next)
    count++;

  return count;
}

static void
rte_feed_obtain(net *n, struct rte **feed, uint count)
{
  uint i = 0;
  for (struct rte_storage *e = n->routes; e; e = e->next)
    {
      ASSERT_DIE(i < count);
      feed[i++] = &e->rte;
    }

  ASSERT_DIE(i == count);
}

static rte *
export_filter(struct channel *c, rte *rt, int silent)
{
  struct proto *p = c->proto;
  const struct filter *filter = c->out_filter;
  struct channel_export_stats *stats = &c->export_stats;

  /* Do nothing if we have already rejected the route */
  if (silent && bmap_test(&c->export_reject_map, rt->id))
    goto reject_noset;

  int v = p->preexport ? p->preexport(c, rt) : 0;
  if (v < 0)
    {
      if (silent)
	goto reject_noset;

      stats->updates_rejected++;
      if (v == RIC_REJECT)
	channel_rte_trace_out(D_FILTERS, c, rt, "rejected by protocol");
      goto reject;

    }
  if (v > 0)
    {
      if (!silent)
	channel_rte_trace_out(D_FILTERS, c, rt, "forced accept by protocol");
      goto accept;
    }

  v = filter && ((filter == FILTER_REJECT) ||
		 (f_run(filter, rt,
			(silent ? FF_SILENT : 0)) > F_ACCEPT));
  if (v)
    {
      if (silent)
	goto reject;

      stats->updates_filtered++;
      channel_rte_trace_out(D_FILTERS, c, rt, "filtered out");
      goto reject;
    }

 accept:
  /* We have accepted the route */
  bmap_clear(&c->export_reject_map, rt->id);
  return rt;

 reject:
  /* We have rejected the route by filter */
  bmap_set(&c->export_reject_map, rt->id);

reject_noset:
  /* Discard temporary rte */
  return NULL;
}

static void
do_rt_notify(struct channel *c, const net_addr *net, rte *new, const rte *old)
{
  struct proto *p = c->proto;
  struct channel_export_stats *stats = &c->export_stats;

  if (c->refeeding && new)
    c->refeed_count++;

  if (!old && new)
    if (CHANNEL_LIMIT_PUSH(c, OUT))
    {
      stats->updates_rejected++;
      channel_rte_trace_out(D_FILTERS, c, new, "rejected [limit]");
      return;
    }

  if (!new && old)
    CHANNEL_LIMIT_POP(c, OUT);

  if (new)
    stats->updates_accepted++;
  else
    stats->withdraws_accepted++;

  if (old)
    bmap_clear(&c->export_map, old->id);

  if (new)
    bmap_set(&c->export_map, new->id);

  if (p->debug & D_ROUTES)
  {
    if (new && old)
      channel_rte_trace_out(D_ROUTES, c, new, "replaced");
    else if (new)
      channel_rte_trace_out(D_ROUTES, c, new, "added");
    else if (old)
      channel_rte_trace_out(D_ROUTES, c, old, "removed");
  }

  p->rt_notify(p, c, net, new, old);
}

static void
rt_notify_basic(struct channel *c, const net_addr *net, rte *new, rte *old)
{
  if (new && old && rte_same(new, old))
  {
    if ((new->id != old->id) && bmap_test(&c->export_map, old->id))
    {
      bmap_set(&c->export_map, new->id);
      bmap_clear(&c->export_map, old->id);
    }
    return;
  }

  if (new)
    new = export_filter(c, new, 0);

  if (old && !bmap_test(&c->export_map, old->id))
    old = NULL;

  if (!new && !old)
    return;

  do_rt_notify(c, net, new, old);
}

static void
channel_rpe_mark_seen(struct rt_export_request *req, struct rt_pending_export *rpe)
{
  struct channel *c = SKIP_BACK(struct channel, out_req, req);

  rpe_mark_seen(req->hook, rpe);
  if (rpe->old)
    bmap_clear(&c->export_reject_map, rpe->old->rte.id);
}

void
rt_notify_accepted(struct rt_export_request *req, const net_addr *n, struct rt_pending_export *first,
    struct rte **feed, uint count)
{
  struct channel *c = SKIP_BACK(struct channel, out_req, req);

  rte nb0, *new_best = NULL;
  const rte *old_best = NULL;

  for (uint i = 0; i < count; i++)
  {
    if (!rte_is_valid(feed[i]))
      continue;

    /* Has been already rejected, won't bother with it */
    if (!c->refeeding && bmap_test(&c->export_reject_map, feed[i]->id))
      continue;

    /* Previously exported */
    if (!old_best && bmap_test(&c->export_map, feed[i]->id))
    {
      /* is still best */
      if (!new_best)
      {
	DBG("rt_notify_accepted: idempotent\n");
	goto done;
      }

      /* is superseded */
      old_best = feed[i];
      break;
    }

    /* Have no new best route yet */
    if (!new_best)
    {
      /* Try this route not seen before */
      nb0 = *feed[i];
      new_best = export_filter(c, &nb0, 0);
      DBG("rt_notify_accepted: checking route id %u: %s\n", feed[i]->id, new_best ? "ok" : "no");
    }
  }

done:
  /* Check obsolete routes for previously exported */
  RPE_WALK(first, rpe, NULL)
  {
    channel_rpe_mark_seen(req, rpe);
    if (rpe->old)
    {
      if (bmap_test(&c->export_map, rpe->old->rte.id))
      {
	ASSERT_DIE(old_best == NULL);
	old_best = &rpe->old->rte;
      }
    }
  }

  /* Nothing to export */
  if (new_best || old_best)
    do_rt_notify(c, n, new_best, old_best);
  else
    DBG("rt_notify_accepted: nothing to export\n");
}

rte *
rt_export_merged(struct channel *c, struct rte **feed, uint count, linpool *pool, int silent)
{
  _Thread_local static rte rloc;

  // struct proto *p = c->proto;
  struct nexthop_adata *nhs = NULL;
  rte *best0 = feed[0];
  rte *best = NULL;

  if (!rte_is_valid(best0))
    return NULL;

  /* Already rejected, no need to re-run the filter */
  if (!c->refeeding && bmap_test(&c->export_reject_map, best0->id))
    return NULL;

  rloc = *best0;
  best = export_filter(c, &rloc, silent);

  if (!best)
    /* Best route doesn't pass the filter */
    return NULL;

  if (!rte_is_reachable(best))
    /* Unreachable routes can't be merged */
    return best;

  for (uint i = 1; i < count; i++)
  {
    if (!rte_mergable(best0, feed[i]))
      continue;

    rte tmp0 = *feed[i];
    rte *tmp = export_filter(c, &tmp0, 1);

    if (!tmp || !rte_is_reachable(tmp))
      continue;

    eattr *nhea = ea_find(tmp->attrs, &ea_gen_nexthop);
    ASSERT_DIE(nhea);

    if (nhs)
      nhs = nexthop_merge(nhs, (struct nexthop_adata *) nhea->u.ptr, c->merge_limit, pool);
    else
      nhs = (struct nexthop_adata *) nhea->u.ptr;
  }

  if (nhs)
  {
    eattr *nhea = ea_find(best->attrs, &ea_gen_nexthop);
    ASSERT_DIE(nhea);

    nhs = nexthop_merge(nhs, (struct nexthop_adata *) nhea->u.ptr, c->merge_limit, pool);

    ea_set_attr(&best->attrs,
	EA_LITERAL_DIRECT_ADATA(&ea_gen_nexthop, 0, &nhs->ad));
  }

  return best;
}

void
rt_notify_merged(struct rt_export_request *req, const net_addr *n, struct rt_pending_export *first,
    struct rte **feed, uint count)
{
  struct channel *c = SKIP_BACK(struct channel, out_req, req);

  // struct proto *p = c->proto;

#if 0 /* TODO: Find whether this check is possible when processing multiple changes at once. */
  /* Check whether the change is relevant to the merged route */
  if ((new_best == old_best) &&
      (new_changed != old_changed) &&
      !rte_mergable(new_best, new_changed) &&
      !rte_mergable(old_best, old_changed))
    return;
#endif

  rte *old_best = NULL;
  /* Find old best route */
  for (uint i = 0; i < count; i++)
    if (bmap_test(&c->export_map, feed[i]->id))
    {
      old_best = feed[i];
      break;
    }

  /* Check obsolete routes for previously exported */
  RPE_WALK(first, rpe, NULL)
  {
    channel_rpe_mark_seen(req, rpe);
    if (rpe->old)
    {
      if (bmap_test(&c->export_map, rpe->old->rte.id))
      {
	ASSERT_DIE(old_best == NULL);
	old_best = &rpe->old->rte;
      }
    }
  }

  /* Prepare new merged route */
  rte *new_merged = count ? rt_export_merged(c, feed, count, tmp_linpool, 0) : NULL;

  if (new_merged || old_best)
    do_rt_notify(c, n, new_merged, old_best);
}

void
rt_notify_optimal(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *first)
{
  struct channel *c = SKIP_BACK(struct channel, out_req, req);
  rte *o = RTE_VALID_OR_NULL(first->old_best);
  struct rte_storage *new_best = first->new_best;

  RPE_WALK(first, rpe, NULL)
  {
    channel_rpe_mark_seen(req, rpe);
    new_best = rpe->new_best;
  }

  rte n0 = RTE_COPY_VALID(new_best);
  if (n0.src || o)
    rt_notify_basic(c, net, n0.src ? &n0 : NULL, o);
}

void
rt_notify_any(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *first)
{
  struct channel *c = SKIP_BACK(struct channel, out_req, req);

  rte *n = RTE_VALID_OR_NULL(first->new);
  rte *o = RTE_VALID_OR_NULL(first->old);

  if (!n && !o)
  {
    channel_rpe_mark_seen(req, first);
    return;
  }

  struct rte_src *src = n ? n->src : o->src;
  struct rte_storage *new_latest = first->new;

  RPE_WALK(first, rpe, src)
  {
    channel_rpe_mark_seen(req, rpe);
    new_latest = rpe->new;
  }

  rte n0 = RTE_COPY_VALID(new_latest);
  if (n0.src || o)
    rt_notify_basic(c, net, n0.src ? &n0 : NULL, o);
}

void
rt_feed_any(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *rpe UNUSED, rte **feed, uint count)
{
  struct channel *c = SKIP_BACK(struct channel, out_req, req);

  for (uint i=0; i<count; i++)
    if (rte_is_valid(feed[i]))
    {
      rte n0 = *feed[i];
      rt_notify_basic(c, net, &n0, NULL);
    }
}

void
rpe_mark_seen(struct rt_export_hook *hook, struct rt_pending_export *rpe)
{
  bmap_set(&hook->seq_map, rpe->seq);
}

struct rt_pending_export *
rpe_next(struct rt_pending_export *rpe, struct rte_src *src)
{
  struct rt_pending_export *next = atomic_load_explicit(&rpe->next, memory_order_acquire);

  if (!next)
    return NULL;

  if (!src)
    return next;

  while (rpe = next)
    if (src == (rpe->new ? rpe->new->rte.src : rpe->old->rte.src))
      return rpe;
    else
      next = atomic_load_explicit(&rpe->next, memory_order_acquire);

  return NULL;
}

static struct rt_pending_export * rt_next_export_fast(struct rt_pending_export *last);
static int
rte_export(struct rt_table_export_hook *th, struct rt_pending_export *rpe)
{
  rtable *tab = RT_PUB(SKIP_BACK(struct rtable_private, exporter, th->table));
  struct rt_export_hook *hook = &th->h;
  if (bmap_test(&hook->seq_map, rpe->seq))
    goto ignore;	/* Seen already */

  const net_addr *n = rpe->new_best ? rpe->new_best->rte.net : rpe->old_best->rte.net;

  switch (hook->req->addr_mode)
    {
      case TE_ADDR_NONE:
	break;

      case TE_ADDR_IN:
	if (!net_in_netX(n, hook->req->addr))
	  goto ignore;
	break;

      case TE_ADDR_EQUAL:
	if (!net_equal(n, hook->req->addr))
	  goto ignore;
	break;

      case TE_ADDR_FOR:
	bug("Continuos export of best prefix match not implemented yet.");

      default:
	bug("Strange table export address mode: %d", hook->req->addr_mode);
    }

  if (rpe->new)
    hook->stats.updates_received++;
  else
    hook->stats.withdraws_received++;

  if (hook->req->export_one)
    hook->req->export_one(hook->req, n, rpe);
  else if (hook->req->export_bulk)
  {
    net *net = SKIP_BACK(struct network, n.addr, (net_addr (*)[0]) n);
    RT_LOCK(tab);
    uint count = rte_feed_count(net);
    rte **feed = NULL;
    if (count)
    {
      feed = alloca(count * sizeof(rte *));
      rte_feed_obtain(net, feed, count);
    }
    RT_UNLOCK(tab);
    hook->req->export_bulk(hook->req, n, rpe, feed, count);
  }
  else
    bug("Export request must always provide an export method");

ignore:
  /* Get the next export if exists */
  th->rpe_next = rt_next_export_fast(rpe);

  /* The last block may be available to free */
  int used = (PAGE_HEAD(th->rpe_next) != PAGE_HEAD(rpe));

  /* Releasing this export for cleanup routine */
  DBG("store hook=%p last_export=%p seq=%lu\n", hook, rpe, rpe->seq);
  atomic_store_explicit(&th->last_export, rpe, memory_order_release);

  return used;
}

/**
 * rte_announce - announce a routing table change
 * @tab: table the route has been added to
 * @net: network in question
 * @new: the new or changed route
 * @old: the previous route replaced by the new one
 * @new_best: the new best route for the same network
 * @old_best: the previous best route for the same network
 *
 * This function gets a routing table update and announces it to all protocols
 * that are connected to the same table by their channels.
 *
 * There are two ways of how routing table changes are announced. First, there
 * is a change of just one route in @net (which may caused a change of the best
 * route of the network). In this case @new and @old describes the changed route
 * and @new_best and @old_best describes best routes. Other routes are not
 * affected, but in sorted table the order of other routes might change.
 *
 * The function announces the change to all associated channels. For each
 * channel, an appropriate preprocessing is done according to channel &ra_mode.
 * For example, %RA_OPTIMAL channels receive just changes of best routes.
 *
 * In general, we first call preexport() hook of a protocol, which performs
 * basic checks on the route (each protocol has a right to veto or force accept
 * of the route before any filter is asked). Then we consult an export filter
 * of the channel and verify the old route in an export map of the channel.
 * Finally, the rt_notify() hook of the protocol gets called.
 *
 * Note that there are also calls of rt_notify() hooks due to feed, but that is
 * done outside of scope of rte_announce().
 */
static void
rte_announce(struct rtable_private *tab, net *net, struct rte_storage *new, struct rte_storage *old,
	     struct rte_storage *new_best, struct rte_storage *old_best)
{
  int new_best_valid = rte_is_valid(RTE_OR_NULL(new_best));
  int old_best_valid = rte_is_valid(RTE_OR_NULL(old_best));

  if ((new == old) && (new_best == old_best))
    return;

  if (new_best_valid)
    new_best->rte.sender->stats.pref++;
  if (old_best_valid)
    old_best->rte.sender->stats.pref--;

  if (EMPTY_LIST(tab->exporter.e.hooks) && EMPTY_LIST(tab->exporter.pending))
  {
    /* No export hook and no pending exports to cleanup. We may free the route immediately. */
    if (!old)
      return;

    hmap_clear(&tab->id_map, old->rte.id);
    rte_free(old);
    return;
  }

  /* Get the pending export structure */
  struct rt_export_block *rpeb = NULL, *rpebsnl = NULL;
  u32 end = 0;

  if (!EMPTY_LIST(tab->exporter.pending))
  {
    rpeb = TAIL(tab->exporter.pending);
    end = atomic_load_explicit(&rpeb->end, memory_order_relaxed);
    if (end >= RT_PENDING_EXPORT_ITEMS)
    {
      ASSERT_DIE(end == RT_PENDING_EXPORT_ITEMS);
      rpebsnl = rpeb;

      rpeb = NULL;
      end = 0;
    }
  }

  if (!rpeb)
  {
    rpeb = alloc_page();
    *rpeb = (struct rt_export_block) {};
    add_tail(&tab->exporter.pending, &rpeb->n);
  }

  /* Fill the pending export */
  struct rt_pending_export *rpe = &rpeb->export[rpeb->end];
  *rpe = (struct rt_pending_export) {
    .new = new,
    .new_best = new_best,
    .old = old,
    .old_best = old_best,
    .seq = tab->exporter.next_seq++,
  };

  DBGL("rte_announce: table=%s net=%N new=%p id %u from %s old=%p id %u from %s new_best=%p id %u old_best=%p id %u seq=%lu",
      tab->name, net->n.addr,
      new, new ? new->rte.id : 0, new ? new->rte.sender->req->name : NULL,
      old, old ? old->rte.id : 0, old ? old->rte.sender->req->name : NULL,
      new_best, old_best, rpe->seq);

  ASSERT_DIE(atomic_fetch_add_explicit(&rpeb->end, 1, memory_order_release) == end);

  if (rpebsnl)
  {
    _Bool f = 0;
    ASSERT_DIE(atomic_compare_exchange_strong_explicit(&rpebsnl->not_last, &f, 1,
	  memory_order_release, memory_order_relaxed));
  }

  /* Append to the same-network squasher list */
  if (net->last)
  {
    struct rt_pending_export *rpenull = NULL;
    ASSERT_DIE(atomic_compare_exchange_strong_explicit(
	  &net->last->next, &rpenull, rpe,
	  memory_order_relaxed,
	  memory_order_relaxed));

  }

  net->last = rpe;

  if (!net->first)
    net->first = rpe;

  if (tab->exporter.first == NULL)
    tab->exporter.first = rpe;

  rt_check_cork_high(tab);
}

static struct rt_pending_export *
rt_next_export_fast(struct rt_pending_export *last)
{
  /* Get the whole export block and find our position in there. */
  struct rt_export_block *rpeb = PAGE_HEAD(last);
  u32 pos = (last - &rpeb->export[0]);
  u32 end = atomic_load_explicit(&rpeb->end, memory_order_acquire);
  ASSERT_DIE(pos < end);

  /* Next is in the same block. */
  if (++pos < end)
    return &rpeb->export[pos];

  /* There is another block. */
  if (atomic_load_explicit(&rpeb->not_last, memory_order_acquire))
  {
    /* This is OK to do non-atomically because of the not_last flag. */
    rpeb = NODE_NEXT(rpeb);
    return &rpeb->export[0];
  }

  /* There is nothing more. */
  return NULL;
}

static struct rt_pending_export *
rt_next_export(struct rt_table_export_hook *hook, struct rt_table_exporter *tab)
{
  ASSERT_DIE(RT_IS_LOCKED(SKIP_BACK(struct rtable_private, exporter, tab)));

  /* As the table is locked, it is safe to reload the last export pointer */
  struct rt_pending_export *last = atomic_load_explicit(&hook->last_export, memory_order_acquire);

  /* It is still valid, let's reuse it */
  if (last)
    return rt_next_export_fast(last);

  /* No, therefore we must process the table's first pending export */
  else
    return tab->first;
}

static inline void
rt_send_export_event(struct rt_export_hook *hook)
{
  ev_send(hook->req->list, &hook->event);
}

static void
rt_announce_exports(struct settle *s)
{
  RT_LOCKED(RT_PUB(SKIP_BACK(struct rtable_private, export_settle, s)), tab)
    if (!EMPTY_LIST(tab->exporter.pending))
    {
      struct rt_export_hook *c; node *n;
      WALK_LIST2(c, n, tab->exporter.e.hooks, n)
      {
	if (atomic_load_explicit(&c->export_state, memory_order_acquire) != TES_READY)
	  continue;

	rt_send_export_event(c);
      }
    }
}

static void
rt_kick_export_settle(struct rtable_private *tab)
{
  tab->export_settle.cf = tab->rr_counter ? tab->config->export_rr_settle : tab->config->export_settle;
  settle_kick(&tab->export_settle, tab->loop);
}

static void
rt_import_announce_exports(void *_hook)
{
  struct rt_import_hook *hook = _hook;
  if (hook->import_state == TIS_CLEARED)
  {
    void (*stopped)(struct rt_import_request *) = hook->stopped;
    struct rt_import_request *req = hook->req;

    RT_LOCKED(hook->table, tab)
    {
      req->hook = NULL;

      rt_trace(tab, D_EVENTS, "Hook %s stopped", req->name);
      rem_node(&hook->n);
      mb_free(hook);
      rt_unlock_table(tab);
    }

    stopped(req);
    return;
  }

  rt_trace(hook->table, D_EVENTS, "Announcing exports after imports from %s", hook->req->name);
  birdloop_flag(hook->table->loop, RTF_EXPORT);
}

static struct rt_pending_export *
rt_last_export(struct rt_table_exporter *tab)
{
  struct rt_pending_export *rpe = NULL;

  if (!EMPTY_LIST(tab->pending))
  {
    /* We'll continue processing exports from this export on */
    struct rt_export_block *reb = TAIL(tab->pending);
    ASSERT_DIE(reb->end);
    rpe = &reb->export[reb->end - 1];
  }

  return rpe;
}

#define RT_EXPORT_BULK	1024

static void
rt_export_hook(void *_data)
{
  struct rt_table_export_hook *c = _data;
  rtable *tab = SKIP_BACK(rtable, priv.exporter, c->table);

  ASSERT_DIE(atomic_load_explicit(&c->h.export_state, memory_order_relaxed) == TES_READY);

  if (!c->rpe_next)
  {
    RT_LOCK(tab);
    c->rpe_next = rt_next_export(c, c->table);

    if (!c->rpe_next)
    {
      rt_export_used(c->table, c->h.req->name, "done exporting");
      RT_UNLOCK(tab);
      return;
    }

    RT_UNLOCK(tab);
  }

  int used = 0;
  int no_next = 0;

  /* Process the export */
  for (uint i=0; i<RT_EXPORT_BULK; i++)
  {
    used += rte_export(c, c->rpe_next);

    if (!c->rpe_next)
    {
      no_next = 1;
      break;
    }
  }

  if (used)
    RT_LOCKED(tab, t)
      if (no_next || t->cork_active)
	rt_export_used(c->table, c->h.req->name, no_next ? "finished export bulk" : "cork active");

  rt_send_export_event(&c->h);
}


static inline int
rte_validate(struct channel *ch, rte *e)
{
  int c;
  const net_addr *n = e->net;

  if (!net_validate(n))
  {
    log(L_WARN "Ignoring bogus prefix %N received via %s",
	n, ch->proto->name);
    return 0;
  }

  /* FIXME: better handling different nettypes */
  c = !net_is_flow(n) ?
    net_classify(n): (IADDR_HOST | SCOPE_UNIVERSE);
  if ((c < 0) || !(c & IADDR_HOST) || ((c & IADDR_SCOPE_MASK) <= SCOPE_LINK))
  {
    log(L_WARN "Ignoring bogus route %N received via %s",
	n, ch->proto->name);
    return 0;
  }

  if (net_type_match(n, NB_DEST))
  {
    eattr *nhea = ea_find(e->attrs, &ea_gen_nexthop);
    int dest = nhea_dest(nhea);

    if (dest == RTD_NONE)
    {
      log(L_WARN "Ignoring route %N with no destination received via %s",
	  n, ch->proto->name);
      return 0;
    }

    if ((dest == RTD_UNICAST) &&
	!nexthop_is_sorted((struct nexthop_adata *) nhea->u.ptr))
    {
      log(L_WARN "Ignoring unsorted multipath route %N received via %s",
	  n, ch->proto->name);
      return 0;
    }
  }
  else if (ea_find(e->attrs, &ea_gen_nexthop))
  {
    log(L_WARN "Ignoring route %N having a nexthop attribute received via %s",
	n, ch->proto->name);
    return 0;
  }

  return 1;
}

static int
rte_same(rte *x, rte *y)
{
  /* rte.flags / rte.pflags are not checked, as they are internal to rtable */
  return
    x->attrs == y->attrs &&
    x->src == y->src &&
    rte_is_filtered(x) == rte_is_filtered(y);
}

static inline int rte_is_ok(rte *e) { return e && !rte_is_filtered(e); }

static int
rte_recalculate(struct rtable_private *table, struct rt_import_hook *c, net *net, rte *new, struct rte_src *src)
{
  struct rt_import_request *req = c->req;
  struct rt_import_stats *stats = &c->stats;
  struct rte_storage *old_best_stored = net->routes, *old_stored = NULL;
  rte *old_best = old_best_stored ? &old_best_stored->rte : NULL;
  rte *old = NULL;

  /* If the new route is identical to the old one, we find the attributes in
   * cache and clone these with no performance drop. OTOH, if we were to lookup
   * the attributes, such a route definitely hasn't been anywhere yet,
   * therefore it's definitely worth the time. */
  struct rte_storage *new_stored = NULL;
  if (new)
    new = &(new_stored = rte_store(new, net, table))->rte;

  /* Find and remove original route from the same protocol */
  struct rte_storage **before_old = rte_find(net, src);

  if (*before_old)
    {
      old = &(old_stored = (*before_old))->rte;

      /* If there is the same route in the routing table but from
       * a different sender, then there are two paths from the
       * source protocol to this routing table through transparent
       * pipes, which is not allowed.
       * We log that and ignore the route. */
      if (old->sender != c)
	{
	  if (!old->generation && !new->generation)
	    bug("Two protocols claim to author a route with the same rte_src in table %s: %N %s/%u:%u",
		c->table->name, net->n.addr, old->src->owner->name, old->src->private_id, old->src->global_id);

	  log_rl(&table->rl_pipe, L_ERR "Route source collision in table %s: %N %s/%u:%u",
		c->table->name, net->n.addr, old->src->owner->name, old->src->private_id, old->src->global_id);
	}

	  if (new && rte_same(old, &new_stored->rte))
	    {
	      /* No changes, ignore the new route and refresh the old one */
	      old->stale_cycle = new->stale_cycle;

	      if (!rte_is_filtered(new))
		{
		  stats->updates_ignored++;
		  rt_rte_trace_in(D_ROUTES, req, new, "ignored");
		}

	      /* We need to free the already stored route here before returning */
	      rte_free(new_stored);
	      return 0;
	  }

	*before_old = (*before_old)->next;
	table->rt_count--;
    }

  if (!old && !new)
    {
      stats->withdraws_ignored++;
      return 0;
    }

  /* If rejected by import limit, we need to pretend there is no route */
  if (req->preimport && (req->preimport(req, new, old) == 0))
  {
    rte_free(new_stored);
    new_stored = NULL;
    new = NULL;
  }

  int new_ok = rte_is_ok(new);
  int old_ok = rte_is_ok(old);

  if (new_ok)
    stats->updates_accepted++;
  else if (old_ok)
    stats->withdraws_accepted++;
  else
    stats->withdraws_ignored++;

  if (old_ok || new_ok)
    table->last_rt_change = current_time();

  if (table->config->sorted)
    {
      /* If routes are sorted, just insert new route to appropriate position */
      if (new_stored)
	{
	  struct rte_storage **k;
	  if ((before_old != &net->routes) && !rte_better(new, &SKIP_BACK(struct rte_storage, next, before_old)->rte))
	    k = before_old;
	  else
	    k = &net->routes;

	  for (; *k; k=&(*k)->next)
	    if (rte_better(new, &(*k)->rte))
	      break;

	  new_stored->next = *k;
	  *k = new_stored;

	  table->rt_count++;
	}
    }
  else
    {
      /* If routes are not sorted, find the best route and move it on
	 the first position. There are several optimized cases. */

      if (src->owner->rte_recalculate &&
	  src->owner->rte_recalculate(table, net, new_stored ? &new_stored->rte : NULL, old, old_best))
	goto do_recalculate;

      if (new_stored && rte_better(&new_stored->rte, old_best))
	{
	  /* The first case - the new route is cleary optimal,
	     we link it at the first position */

	  new_stored->next = net->routes;
	  net->routes = new_stored;

	  table->rt_count++;
	}
      else if (old == old_best)
	{
	  /* The second case - the old best route disappeared, we add the
	     new route (if we have any) to the list (we don't care about
	     position) and then we elect the new optimal route and relink
	     that route at the first position and announce it. New optimal
	     route might be NULL if there is no more routes */

	do_recalculate:
	  /* Add the new route to the list */
	  if (new_stored)
	    {
	      new_stored->next = *before_old;
	      *before_old = new_stored;

	      table->rt_count++;
	    }

	  /* Find a new optimal route (if there is any) */
	  if (net->routes)
	    {
	      struct rte_storage **bp = &net->routes;
	      for (struct rte_storage **k=&(*bp)->next; *k; k=&(*k)->next)
		if (rte_better(&(*k)->rte, &(*bp)->rte))
		  bp = k;

	      /* And relink it */
	      struct rte_storage *best = *bp;
	      *bp = best->next;
	      best->next = net->routes;
	      net->routes = best;
	    }
	}
      else if (new_stored)
	{
	  /* The third case - the new route is not better than the old
	     best route (therefore old_best != NULL) and the old best
	     route was not removed (therefore old_best == net->routes).
	     We just link the new route to the old/last position. */

	  new_stored->next = *before_old;
	  *before_old = new_stored;

	  table->rt_count++;
	}
      /* The fourth (empty) case - suboptimal route was removed, nothing to do */
    }

  if (new_stored)
    {
      new_stored->rte.lastmod = current_time();
      new_stored->rte.id = hmap_first_zero(&table->id_map);
      hmap_set(&table->id_map, new_stored->rte.id);
    }

  /* Log the route change */
  if (new_ok)
    rt_rte_trace_in(D_ROUTES, req, &new_stored->rte, new_stored == net->routes ? "added [best]" : "added");
  else if (old_ok)
    {
      if (old != old_best)
	rt_rte_trace_in(D_ROUTES, req, old, "removed");
      else if (net->routes && rte_is_ok(&net->routes->rte))
	rt_rte_trace_in(D_ROUTES, req, old, "removed [replaced]");
      else
	rt_rte_trace_in(D_ROUTES, req, old, "removed [sole]");
    }
  else
    if (req->trace_routes & D_ROUTES)
      log(L_TRACE "%s > ignored %N %s->%s", req->name, net->n.addr, old ? "filtered" : "none", new ? "filtered" : "none");

  /* Propagate the route change */
  rte_announce(table, net, new_stored, old_stored,
      net->routes, old_best_stored);

  return 1;
}

int
channel_preimport(struct rt_import_request *req, rte *new, rte *old)
{
  struct channel *c = SKIP_BACK(struct channel, in_req, req);

  if (new && !old)
    if (CHANNEL_LIMIT_PUSH(c, RX))
      return 0;

  if (!new && old)
    CHANNEL_LIMIT_POP(c, RX);

  int new_in = new && !rte_is_filtered(new);
  int old_in = old && !rte_is_filtered(old);

  if (new_in && !old_in)
    if (CHANNEL_LIMIT_PUSH(c, IN))
      if (c->in_keep & RIK_REJECTED)
      {
	new->flags |= REF_FILTERED;
	return 1;
      }
      else
	return 0;

  if (!new_in && old_in)
    CHANNEL_LIMIT_POP(c, IN);

  return 1;
}

void
rte_update(struct channel *c, const net_addr *n, rte *new, struct rte_src *src)
{
  if (!c->in_req.hook)
  {
    log(L_WARN "%s.%s: Called rte_update without import hook", c->proto->name, c->name);
    return;
  }

  ASSERT(c->channel_state == CS_UP);

  /* The import reloader requires prefilter routes to be the first layer */
  if (new && (c->in_keep & RIK_PREFILTER))
    if (ea_is_cached(new->attrs) && !new->attrs->next)
      new->attrs = ea_clone(new->attrs);
    else
      new->attrs = ea_lookup(new->attrs, 0);

  const struct filter *filter = c->in_filter;
  struct channel_import_stats *stats = &c->import_stats;

  if (new)
    {
      new->net = n;

      int fr;

      stats->updates_received++;
      if ((filter == FILTER_REJECT) ||
	((fr = f_run(filter, new, 0)) > F_ACCEPT))
	{
	  stats->updates_filtered++;
	  channel_rte_trace_in(D_FILTERS, c, new, "filtered out");

	  if (c->in_keep & RIK_REJECTED)
	    new->flags |= REF_FILTERED;
	  else
	    new = NULL;
	}

      if (new)
	if (net_is_flow(n))
	  rt_flowspec_resolve_rte(new, c);
	else
	  rt_next_hop_resolve_rte(new);

      if (new && !rte_validate(c, new))
	{
	  channel_rte_trace_in(D_FILTERS, c, new, "invalid");
	  stats->updates_invalid++;
	  new = NULL;
	}

    }
  else
    stats->withdraws_received++;

  rte_import(&c->in_req, n, new, src);

  /* Now the route attributes are kept by the in-table cached version
   * and we may drop the local handle */
  if (new && (c->in_keep & RIK_PREFILTER))
  {
    /* There may be some updates on top of the original attribute block */
    ea_list *a = new->attrs;
    while (a->next)
      a = a->next;

    ea_free(a);
  }

}

void
rte_import(struct rt_import_request *req, const net_addr *n, rte *new, struct rte_src *src)
{
  struct rt_import_hook *hook = req->hook;
  if (!hook)
  {
    log(L_WARN "%s: Called rte_import without import hook", req->name);
    return;
  }

  RT_LOCKED(hook->table, tab)
  {
    net *nn;
    if (new)
    {
      /* Use the actual struct network, not the dummy one */
      nn = net_get(tab, n);
      new->net = nn->n.addr;
      new->sender = hook;

      /* Set the stale cycle */
      new->stale_cycle = hook->stale_set;
    }
    else if (!(nn = net_find(tab, n)))
    {
      req->hook->stats.withdraws_ignored++;
      if (req->trace_routes & D_ROUTES)
	log(L_TRACE "%s > ignored %N withdraw", req->name, n);
      RT_RETURN(tab);
    }

    /* Recalculate the best route */
    if (rte_recalculate(tab, hook, nn, new, src))
      ev_send(req->list, &hook->announce_event);
  }
}

/* Check rtable for best route to given net whether it would be exported do p */
int
rt_examine(rtable *tp, net_addr *a, struct channel *c, const struct filter *filter)
{
  rte rt = {};

  RT_LOCKED(tp, t)
  {
    net *n = net_find(t, a);
    if (n)
      rt = RTE_COPY_VALID(n->routes);
  }

  if (!rt.src)
    return 0;

  int v = c->proto->preexport ? c->proto->preexport(c, &rt) : 0;
  if (v == RIC_PROCESS)
    v = (f_run(filter, &rt, FF_SILENT) <= F_ACCEPT);

  return v > 0;
}

static void
rt_table_export_done(void *hh)
{
  struct rt_table_export_hook *hook = hh;
  struct rt_export_request *req = hook->h.req;
  void (*stopped)(struct rt_export_request *) = hook->h.stopped;
  rtable *t = SKIP_BACK(rtable, priv.exporter, hook->table);

  RT_LOCKED(t, tab)
  {
    DBG("Export hook %p in table %s finished uc=%u\n", hook, tab->name, tab->use_count);

    /* Drop pending exports */
    rt_export_used(&tab->exporter, hook->h.req->name, "stopped");

    /* Do the common code; this frees the hook */
    rt_export_stopped(&hook->h);
  }

  /* Report the channel as stopped. */
  CALL(stopped, req);

  /* Unlock the table; this may free it */
  rt_unlock_table(t);
}

void
rt_export_stopped(struct rt_export_hook *hook)
{
  /* Unlink from the request */
  hook->req->hook = NULL;

  /* Unlist */
  rem_node(&hook->n);

  /* Free the hook itself together with its pool */
  rfree(hook->pool);
}

static inline void
rt_set_import_state(struct rt_import_hook *hook, u8 state)
{
  hook->last_state_change = current_time();
  hook->import_state = state;

  CALL(hook->req->log_state_change, hook->req, state);
}

void
rt_set_export_state(struct rt_export_hook *hook, u8 state)
{
  hook->last_state_change = current_time();
  u8 old = atomic_exchange_explicit(&hook->export_state, state, memory_order_release);

  if (old != state)
    CALL(hook->req->log_state_change, hook->req, state);
}

void
rt_request_import(rtable *t, struct rt_import_request *req)
{
  RT_LOCKED(t, tab)
  {
    rt_lock_table(tab);

    struct rt_import_hook *hook = req->hook = mb_allocz(tab->rp, sizeof(struct rt_import_hook));

    hook->announce_event = (event) { .hook = rt_import_announce_exports, .data = hook };

    DBG("Lock table %s for import %p req=%p uc=%u\n", tab->name, hook, req, tab->use_count);

    hook->req = req;
    hook->table = t;

    rt_set_import_state(hook, TIS_UP);
    add_tail(&tab->imports, &hook->n);
  }
}

void
rt_stop_import(struct rt_import_request *req, void (*stopped)(struct rt_import_request *))
{
  ASSERT_DIE(req->hook);
  struct rt_import_hook *hook = req->hook;

  RT_LOCKED(hook->table, tab)
  {
    rt_schedule_prune(tab);
    rt_set_import_state(hook, TIS_STOP);
    hook->stopped = stopped;

    /* Cancel table rr_counter */
    if (hook->stale_set != hook->stale_pruned)
      tab->rr_counter -= (hook->stale_set - hook->stale_pruned);

    tab->rr_counter++;

    hook->stale_set = hook->stale_pruned = hook->stale_pruning = hook->stale_valid = 0;
  }
}

static void rt_table_export_start_feed(struct rtable_private *tab, struct rt_table_export_hook *hook);
static void
rt_table_export_uncork(void *_hook)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  struct rt_table_export_hook *hook = _hook;
  struct birdloop *loop = hook->h.req->list->loop;

  if (loop != &main_birdloop)
    birdloop_enter(loop);

  u8 state;
  switch (state = atomic_load_explicit(&hook->h.export_state, memory_order_relaxed))
  {
    case TES_HUNGRY:
      RT_LOCKED(RT_PUB(SKIP_BACK(struct rtable_private, exporter, hook->table)), tab)
	if ((state = atomic_load_explicit(&hook->h.export_state, memory_order_relaxed)) == TES_HUNGRY)
	  rt_table_export_start_feed(tab, hook);
      if (state != TES_STOP)
	break;
      /* fall through */
    case TES_STOP:
      rt_stop_export_common(&hook->h);
      break;
    default:
      bug("Uncorking a table export in a strange state: %u", state);
  }

  if (loop != &main_birdloop)
    birdloop_leave(loop);
}

static void
rt_table_export_start_locked(struct rtable_private *tab, struct rt_export_request *req)
{
  struct rt_exporter *re = &tab->exporter.e;
  rt_lock_table(tab);

  req->hook = rt_alloc_export(re, sizeof(struct rt_table_export_hook));
  req->hook->req = req;

  struct rt_table_export_hook *hook = SKIP_BACK(struct rt_table_export_hook, h, req->hook);
  hook->h.event = (event) {
    .hook = rt_table_export_uncork,
    .data = hook,
  };

  if (rt_cork_check(&hook->h.event))
    rt_set_export_state(&hook->h, TES_HUNGRY);
  else
    rt_table_export_start_feed(tab, hook);
}

static void
rt_table_export_start_feed(struct rtable_private *tab, struct rt_table_export_hook *hook)
{
  struct rt_exporter *re = &tab->exporter.e;
  struct rt_export_request *req = hook->h.req;

  /* stats zeroed by mb_allocz */
  switch (req->addr_mode)
  {
    case TE_ADDR_IN:
      if (tab->trie && net_val_match(tab->addr_type, NB_IP))
      {
	hook->walk_state = mb_allocz(hook->h.pool, sizeof (struct f_trie_walk_state));
	hook->walk_lock = rt_lock_trie(tab);
	trie_walk_init(hook->walk_state, tab->trie, req->addr);
	hook->h.event.hook = rt_feed_by_trie;
	hook->walk_last.type = 0;
	break;
      }
      /* fall through */
    case TE_ADDR_NONE:
      FIB_ITERATE_INIT(&hook->feed_fit, &tab->fib);
      hook->h.event.hook = rt_feed_by_fib;
      break;

    case TE_ADDR_EQUAL:
      hook->h.event.hook = rt_feed_equal;
      break;

    case TE_ADDR_FOR:
      hook->h.event.hook = rt_feed_for;
      break;

    default:
      bug("Requested an unknown export address mode");
  }

  DBG("New export hook %p req %p in table %s uc=%u\n", hook, req, tab->name, tab->use_count);

  struct rt_pending_export *rpe = rt_last_export(hook->table);
  DBG("store hook=%p last_export=%p seq=%lu\n", hook, rpe, rpe ? rpe->seq : 0);
  atomic_store_explicit(&hook->last_export, rpe, memory_order_relaxed);

  rt_init_export(re, req->hook);
}

static void
rt_table_export_start(struct rt_exporter *re, struct rt_export_request *req)
{
  RT_LOCKED(SKIP_BACK(rtable, priv.exporter.e, re), tab)
    rt_table_export_start_locked(tab, req);
}
 
void rt_request_export(rtable *t, struct rt_export_request *req)
{
  RT_LOCKED(t, tab)
    rt_table_export_start_locked(tab, req);  /* Is locked inside */
}

void
rt_request_export_other(struct rt_exporter *re, struct rt_export_request *req)
{
  return re->class->start(re, req);
}

struct rt_export_hook *
rt_alloc_export(struct rt_exporter *re, uint size)
{
  pool *p = rp_new(re->rp, "Export hook");
  struct rt_export_hook *hook = mb_allocz(p, size);

  hook->pool = p;
  hook->table = re;

  hook->n = (node) {};
  add_tail(&re->hooks, &hook->n);

  return hook;
}

void
rt_init_export(struct rt_exporter *re UNUSED, struct rt_export_hook *hook)
{
  hook->event.data = hook;

  bmap_init(&hook->seq_map, hook->pool, 1024);

  /* Regular export */
  rt_set_export_state(hook, TES_FEEDING);
  rt_send_export_event(hook);
}

static int
rt_table_export_stop_locked(struct rt_export_hook *hh)
{
  struct rt_table_export_hook *hook = SKIP_BACK(struct rt_table_export_hook, h, hh);
  struct rtable_private *tab = SKIP_BACK(struct rtable_private, exporter, hook->table);

  switch (atomic_load_explicit(&hh->export_state, memory_order_relaxed))
  {
    case TES_HUNGRY:
      rt_trace(tab, D_EVENTS, "Stopping export hook %s must wait for uncorking", hook->h.req->name);
      return 0;
    case TES_FEEDING:
      switch (hh->req->addr_mode)
      {
	case TE_ADDR_IN:
	  if (hook->walk_lock)
	  {
	    rt_unlock_trie(tab, hook->walk_lock);
	    hook->walk_lock = NULL;
	    mb_free(hook->walk_state);
	    hook->walk_state = NULL;
	    break;
	  }
	  /* fall through */
	case TE_ADDR_NONE:
	  fit_get(&tab->fib, &hook->feed_fit);
	  break;
      }
      break;

    case TES_STOP:
      bug("Tried to repeatedly stop the same export hook %s", hook->h.req->name);
  }

  rt_trace(tab, D_EVENTS, "Stopping export hook %s right now", hook->h.req->name);
  return 1;
}

static void
rt_table_export_stop(struct rt_export_hook *hh)
{
  struct rt_table_export_hook *hook = SKIP_BACK(struct rt_table_export_hook, h, hh);
  int ok = 0;
  rtable *t = SKIP_BACK(rtable, priv.exporter, hook->table);
  if (RT_IS_LOCKED(t))
    ok = rt_table_export_stop_locked(hh);
  else
    RT_LOCKED(t, tab)
      ok = rt_table_export_stop_locked(hh);

  if (ok)
    rt_stop_export_common(hh);
  else
    rt_set_export_state(&hook->h, TES_STOP);
}

void
rt_stop_export(struct rt_export_request *req, void (*stopped)(struct rt_export_request *))
{
  ASSERT_DIE(birdloop_inside(req->list->loop));
  ASSERT_DIE(req->hook);
  struct rt_export_hook *hook = req->hook;

  /* Set the stopped callback */
  hook->stopped = stopped;

  /* Run the stop code */
  if (hook->table->class->stop)
    hook->table->class->stop(hook);
  else
    rt_stop_export_common(hook);
}

void
rt_stop_export_common(struct rt_export_hook *hook)
{
  /* Update export state */
  rt_set_export_state(hook, TES_STOP);

  /* Reset the event as the stopped event */
  hook->event.hook = hook->table->class->done;

  /* Run the stopped event */
  rt_send_export_event(hook);
}

/**
 * rt_refresh_begin - start a refresh cycle
 * @t: related routing table
 * @c related channel
 *
 * This function starts a refresh cycle for given routing table and announce
 * hook. The refresh cycle is a sequence where the protocol sends all its valid
 * routes to the routing table (by rte_update()). After that, all protocol
 * routes (more precisely routes with @c as @sender) not sent during the
 * refresh cycle but still in the table from the past are pruned. This is
 * implemented by marking all related routes as stale by REF_STALE flag in
 * rt_refresh_begin(), then marking all related stale routes with REF_DISCARD
 * flag in rt_refresh_end() and then removing such routes in the prune loop.
 */
void
rt_refresh_begin(struct rt_import_request *req)
{
  struct rt_import_hook *hook = req->hook;
  ASSERT_DIE(hook);
  ASSERT_DIE(hook->stale_set == hook->stale_valid);

  RT_LOCKED(hook->table, tab)
  {

  /* If the pruning routine is too slow */
  if ((hook->stale_pruned < hook->stale_valid) && (hook->stale_pruned + 128 < hook->stale_valid)
      || (hook->stale_pruned > hook->stale_valid) && (hook->stale_pruned > hook->stale_valid + 128))
  {
    log(L_WARN "Route refresh flood in table %s", hook->table->name);
    FIB_WALK(&tab->fib, net, n)
      {
       for (struct rte_storage *e = n->routes; e; e = e->next)
         if (e->rte.sender == req->hook)
           e->rte.stale_cycle = 0;
      }
    FIB_WALK_END;
    tab->rr_counter -= hook->stale_set - hook->stale_pruned;
    hook->stale_set = 1;
    hook->stale_valid = 0;
    hook->stale_pruned = 0;
  }
  /* Setting a new value of the stale modifier */
  else if (!++hook->stale_set)
  {
    /* Let's reserve the stale_cycle zero value for always-invalid routes */
    hook->stale_set = 1;
    hook->stale_valid = 0;
  }

  /* The table must know that we're route-refreshing */
  tab->rr_counter++;

  if (req->trace_routes & D_STATES)
    log(L_TRACE "%s: route refresh begin [%u]", req->name, hook->stale_set);

  }
}

/**
 * rt_refresh_end - end a refresh cycle
 * @t: related routing table
 * @c: related channel
 *
 * This function ends a refresh cycle for given routing table and announce
 * hook. See rt_refresh_begin() for description of refresh cycles.
 */
void
rt_refresh_end(struct rt_import_request *req)
{
  struct rt_import_hook *hook = req->hook;
  ASSERT_DIE(hook);

  RT_LOCKED(hook->table, tab)
  {
    hook->stale_valid++;
    ASSERT_DIE(hook->stale_set == hook->stale_valid);

    /* Here we can't kick the timer as we aren't in the table service loop */
    rt_schedule_prune(tab);

    if (req->trace_routes & D_STATES)
      log(L_TRACE "%s: route refresh end [%u]", req->name, hook->stale_valid);
  }
}

/**
 * rte_dump - dump a route
 * @e: &rte to be dumped
 *
 * This functions dumps contents of a &rte to debug output.
 */
void
rte_dump(struct rte_storage *e)
{
  debug("%-1N ", e->rte.net);
  debug("PF=%02x ", e->rte.pflags);
  ea_dump(e->rte.attrs);
  debug("\n");
}

/**
 * rt_dump - dump a routing table
 * @t: routing table to be dumped
 *
 * This function dumps contents of a given routing table to debug output.
 */
void
rt_dump(rtable *tp)
{
  RT_LOCKED(tp, t)
  {

  debug("Dump of routing table <%s>%s\n", t->name, t->deleted ? " (deleted)" : "");
#ifdef DEBUGGING
  fib_check(&t->fib);
#endif
  FIB_WALK(&t->fib, net, n)
    {
      for(struct rte_storage *e=n->routes; e; e=e->next)
	rte_dump(e);
    }
  FIB_WALK_END;
  debug("\n");

  }
}

/**
 * rt_dump_all - dump all routing tables
 *
 * This function dumps contents of all routing tables to debug output.
 */
void
rt_dump_all(void)
{
  rtable *t;
  node *n;

  WALK_LIST2(t, n, routing_tables, n)
    rt_dump(t);

  WALK_LIST2(t, n, deleted_routing_tables, n)
    rt_dump(t);
}

void
rt_dump_hooks(rtable *tp)
{
  RT_LOCKED(tp, tab)
  {

  debug("Dump of hooks in routing table <%s>%s\n", tab->name, tab->deleted ? " (deleted)" : "");
  debug("  nhu_state=%u use_count=%d rt_count=%u\n",
      tab->nhu_state, tab->use_count, tab->rt_count);
  debug("  last_rt_change=%t gc_time=%t gc_counter=%d prune_state=%u\n",
      tab->last_rt_change, tab->gc_time, tab->gc_counter, tab->prune_state);

  struct rt_import_hook *ih;
  WALK_LIST(ih, tab->imports)
  {
    ih->req->dump_req(ih->req);
    debug("  Import hook %p requested by %p: pref=%u"
       " last_state_change=%t import_state=%u stopped=%p\n",
       ih, ih->req, ih->stats.pref,
       ih->last_state_change, ih->import_state, ih->stopped);
  }

  struct rt_table_export_hook *eh;
  WALK_LIST(eh, tab->exporter.e.hooks)
  {
    eh->h.req->dump_req(eh->h.req);
    debug("  Export hook %p requested by %p:"
       " refeed_pending=%u last_state_change=%t export_state=%u\n",
       eh, eh->h.req, eh->refeed_pending, eh->h.last_state_change,
       atomic_load_explicit(&eh->h.export_state, memory_order_relaxed));
  }
  debug("\n");

  }
}

void
rt_dump_hooks_all(void)
{
  rtable *t;
  node *n;

  debug("Dump of all table hooks\n");

  WALK_LIST2(t, n, routing_tables, n)
    rt_dump_hooks(t);

  WALK_LIST2(t, n, deleted_routing_tables, n)
    rt_dump_hooks(t);
}

static inline void
rt_schedule_nhu(struct rtable_private *tab)
{
  if (tab->nhu_corked)
  {
    if (!(tab->nhu_corked & NHU_SCHEDULED))
      tab->nhu_corked |= NHU_SCHEDULED;
  }
  else if (!(tab->nhu_state & NHU_SCHEDULED))
  {
    rt_trace(tab, D_EVENTS, "Scheduling NHU");

    /* state change:
     *   NHU_CLEAN   -> NHU_SCHEDULED
     *   NHU_RUNNING -> NHU_DIRTY
     */
    if ((tab->nhu_state |= NHU_SCHEDULED) == NHU_SCHEDULED)
      birdloop_flag(tab->loop, RTF_NHU);
  }
}

void
rt_schedule_prune(struct rtable_private *tab)
{
  if (tab->prune_state == 0)
    birdloop_flag(tab->loop, RTF_CLEANUP);

  /* state change 0->1, 2->3 */
  tab->prune_state |= 1;
}

static void
rt_export_used(struct rt_table_exporter *e, const char *who, const char *why)
{
  struct rtable_private *tab = SKIP_BACK(struct rtable_private, exporter, e);
  ASSERT_DIE(RT_IS_LOCKED(tab));

  rt_trace(tab, D_EVENTS, "Export cleanup requested by %s %s", who, why);

  if (tab->export_used)
    return;

  tab->export_used = 1;
  birdloop_flag(tab->loop, RTF_CLEANUP);
}

static void
rt_flag_handler(struct birdloop_flag_handler *fh, u32 flags)
{
  RT_LOCKED(RT_PUB(SKIP_BACK(struct rtable_private, fh, fh)), tab)
  {
    ASSERT_DIE(birdloop_inside(tab->loop));
    rt_lock_table(tab);

    if (flags & RTF_NHU)
      rt_next_hop_update(tab);

    if (flags & RTF_EXPORT)
      rt_kick_export_settle(tab);

    if (flags & RTF_CLEANUP)
    {
      if (tab->export_used)
	rt_export_cleanup(tab);

      if (tab->prune_state)
	rt_prune_table(tab);
    }

    rt_unlock_table(tab);
  }
}

static void
rt_prune_timer(timer *t)
{
  RT_LOCKED((rtable *) t->data, tab)
    if (tab->gc_counter >= tab->config->gc_threshold)
      rt_schedule_prune(tab);
}

static void
rt_kick_prune_timer(struct rtable_private *tab)
{
  /* Return if prune is already scheduled */
  if (tm_active(tab->prune_timer) || (tab->prune_state & 1))
    return;

  /* Randomize GC period to +/- 50% */
  btime gc_period = tab->config->gc_period;
  gc_period = (gc_period / 2) + (random_u32() % (uint) gc_period);
  tm_start_in(tab->prune_timer, gc_period, tab->loop);
}


static void
rt_flowspec_export_one(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *first)
{
  struct rt_flowspec_link *ln = SKIP_BACK(struct rt_flowspec_link, req, req);
  rtable *dst_pub = ln->dst;
  ASSUME(rt_is_flow(dst_pub));
  struct rtable_private *dst = RT_LOCK(dst_pub);

  /* No need to inspect it further if recalculation is already scheduled */
  if ((dst->nhu_state == NHU_SCHEDULED) || (dst->nhu_state == NHU_DIRTY)
      || !trie_match_net(dst->flowspec_trie, net))
  {
    RT_UNLOCK(dst_pub);
    rpe_mark_seen_all(req->hook, first, NULL);
    return;
  }

  /* This net may affect some flowspecs, check the actual change */
  rte *o = RTE_VALID_OR_NULL(first->old_best);
  struct rte_storage *new_best = first->new_best;

  RPE_WALK(first, rpe, NULL)
  {
    rpe_mark_seen(req->hook, rpe);
    new_best = rpe->new_best;
  }

  /* Yes, something has actually changed. Schedule the update. */
  if (o != RTE_VALID_OR_NULL(new_best))
    rt_schedule_nhu(dst);

  RT_UNLOCK(dst_pub);
}

static void
rt_flowspec_dump_req(struct rt_export_request *req)
{
  struct rt_flowspec_link *ln = SKIP_BACK(struct rt_flowspec_link, req, req);
  debug("  Flowspec link for table %s (%p)\n", ln->dst->name, req);
}

static void
rt_flowspec_log_state_change(struct rt_export_request *req, u8 state)
{
  struct rt_flowspec_link *ln = SKIP_BACK(struct rt_flowspec_link, req, req);
  rt_trace(ln->dst, D_STATES, "Flowspec link from %s export state changed to %s",
      ln->src->name, rt_export_state_name(state));
}

static struct rt_flowspec_link *
rt_flowspec_find_link(struct rtable_private *src, rtable *dst)
{
  struct rt_table_export_hook *hook; node *n;
  WALK_LIST2(hook, n, src->exporter.e.hooks, h.n)
    switch (atomic_load_explicit(&hook->h.export_state, memory_order_acquire))
    {
      case TES_HUNGRY:
      case TES_FEEDING:
      case TES_READY:
	if (hook->h.req->export_one == rt_flowspec_export_one)
	{
	  struct rt_flowspec_link *ln = SKIP_BACK(struct rt_flowspec_link, req, hook->h.req);
	  if (ln->dst == dst)
	    return ln;
	}
    }

  return NULL;
}

void
rt_flowspec_link(rtable *src_pub, rtable *dst_pub)
{
  ASSERT(rt_is_ip(src_pub));
  ASSERT(rt_is_flow(dst_pub));

  int lock_dst = 0;

  birdloop_enter(dst_pub->loop);

  RT_LOCKED(src_pub, src)
  {
    struct rt_flowspec_link *ln = rt_flowspec_find_link(src, dst_pub);

    if (!ln)
    {
      pool *p = src->rp;
      ln = mb_allocz(p, sizeof(struct rt_flowspec_link));
      ln->src = src_pub;
      ln->dst = dst_pub;
      ln->req = (struct rt_export_request) {
	.name = mb_sprintf(p, "%s.flowspec.notifier", dst_pub->name),
	.list = birdloop_event_list(dst_pub->loop),
	.trace_routes = src->config->debug,
	.dump_req = rt_flowspec_dump_req,
	.log_state_change = rt_flowspec_log_state_change,
	.export_one = rt_flowspec_export_one,
      };

      rt_table_export_start_locked(src, &ln->req);

      lock_dst = 1;
    }

    ln->uc++;
  }

  if (lock_dst)
    rt_lock_table(dst_pub);

  birdloop_leave(dst_pub->loop);
}

static void
rt_flowspec_link_stopped(struct rt_export_request *req)
{
  struct rt_flowspec_link *ln = SKIP_BACK(struct rt_flowspec_link, req, req);
  rtable *dst = ln->dst;

  mb_free(ln);
  rt_unlock_table(dst);
}

void
rt_flowspec_unlink(rtable *src, rtable *dst)
{
  birdloop_enter(dst->loop);

  struct rt_flowspec_link *ln;
  RT_LOCKED(src, t)
  {
    ln = rt_flowspec_find_link(t, dst);

    ASSERT(ln && (ln->uc > 0));

    if (!--ln->uc)
      rt_stop_export(&ln->req, rt_flowspec_link_stopped);
  }

  birdloop_leave(dst->loop);
}

static void
rt_flowspec_reset_trie(struct rtable_private *tab)
{
  linpool *lp = tab->flowspec_trie->lp;
  int ipv4 = tab->flowspec_trie->ipv4;

  lp_flush(lp);
  tab->flowspec_trie = f_new_trie(lp, 0);
  tab->flowspec_trie->ipv4 = ipv4;
}

static void
rt_free(resource *_r)
{
  struct rtable_private *r = SKIP_BACK(struct rtable_private, r, _r);

  DOMAIN_FREE(rtable, r->lock);

  DBG("Deleting routing table %s\n", r->name);
  ASSERT_DIE(r->use_count == 0);

  r->config->table = NULL;
  rem_node(&r->n);

  if (r->hostcache)
    rt_free_hostcache(r);

  /* Freed automagically by the resource pool
  fib_free(&r->fib);
  hmap_free(&r->id_map);
  rfree(r->rt_event);
  mb_free(r);
  */
}

static void
rt_res_dump(resource *_r)
{
  struct rtable_private *r = SKIP_BACK(struct rtable_private, r, _r);

  debug("name \"%s\", addr_type=%s, rt_count=%u, use_count=%d\n",
      r->name, net_label[r->addr_type], r->rt_count, r->use_count);
}

static struct resclass rt_class = {
  .name = "Routing table",
  .size = sizeof(rtable),
  .free = rt_free,
  .dump = rt_res_dump,
  .lookup = NULL,
  .memsize = NULL,
};

static const struct rt_exporter_class rt_table_exporter_class = {
  .start = rt_table_export_start,
  .stop = rt_table_export_stop,
  .done = rt_table_export_done,
};

void
rt_exporter_init(struct rt_exporter *e)
{
  init_list(&e->hooks);
}

static struct idm rtable_idm;
uint rtable_max_id = 0;

rtable *
rt_setup(pool *pp, struct rtable_config *cf)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  pool *p = rp_newf(pp, "Routing table %s", cf->name);

  struct rtable_private *t = ralloc(p, &rt_class);
  t->rp = p;

  t->rte_slab = sl_new(p, sizeof(struct rte_storage));

  t->name = cf->name;
  t->config = cf;
  t->addr_type = cf->addr_type;
  t->id = idm_alloc(&rtable_idm);
  if (t->id >= rtable_max_id)
    rtable_max_id = t->id + 1;

  t->lock = DOMAIN_NEW(rtable, t->name);

  fib_init(&t->fib, p, t->addr_type, sizeof(net), OFFSETOF(net, n), 0, NULL);

  if (cf->trie_used)
  {
    t->trie = f_new_trie(lp_new_default(p), 0);
    t->trie->ipv4 = net_val_match(t->addr_type, NB_IP4 | NB_VPN4 | NB_ROA4);

    t->fib.init = net_init_with_trie;
  }

  init_list(&t->imports);

  hmap_init(&t->id_map, p, 1024);
  hmap_set(&t->id_map, 0);

  t->fh = (struct birdloop_flag_handler) { .hook = rt_flag_handler, };
  t->nhu_uncork_event = ev_new_init(p, rt_nhu_uncork, t);
  t->prune_timer = tm_new_init(p, rt_prune_timer, t, 0, 0);
  t->last_rt_change = t->gc_time = current_time();

  t->export_settle = SETTLE_INIT(&cf->export_settle, rt_announce_exports, NULL);

  t->exporter = (struct rt_table_exporter) {
    .e = {
      .class = &rt_table_exporter_class,
      .addr_type = t->addr_type,
      .rp = t->rp,
    },
    .next_seq = 1,
  };

  rt_exporter_init(&t->exporter.e);

  init_list(&t->exporter.pending);

  t->cork_threshold = cf->cork_threshold;

  t->rl_pipe = (struct tbf) TBF_DEFAULT_LOG_LIMITS;

  if (rt_is_flow(RT_PUB(t)))
  {
    t->flowspec_trie = f_new_trie(lp_new_default(p), 0);
    t->flowspec_trie->ipv4 = (t->addr_type == NET_FLOW4);
  }

  /* Start the service thread */
  t->loop = birdloop_new(p, DOMAIN_ORDER(service), mb_sprintf(p, "Routing table %s", t->name));
  birdloop_enter(t->loop);
  birdloop_flag_set_handler(t->loop, &t->fh);
  birdloop_leave(t->loop);

  return RT_PUB(t);
}

/**
 * rt_init - initialize routing tables
 *
 * This function is called during BIRD startup. It initializes the
 * routing table module.
 */
void
rt_init(void)
{
  rta_init();
  rt_table_pool = rp_new(&root_pool, "Routing tables");
  init_list(&routing_tables);
  init_list(&deleted_routing_tables);
  ev_init_list(&rt_cork.queue, &main_birdloop, "Route cork release");
  rt_cork.run = (event) { .hook = rt_cork_release_hook };
  idm_init(&rtable_idm, rt_table_pool, 256);
}


/**
 * rt_prune_table - prune a routing table
 *
 * The prune loop scans routing tables and removes routes belonging to flushing
 * protocols, discarded routes and also stale network entries. It is called from
 * rt_event(). The event is rescheduled if the current iteration do not finish
 * the table. The pruning is directed by the prune state (@prune_state),
 * specifying whether the prune cycle is scheduled or running, and there
 * is also a persistent pruning iterator (@prune_fit).
 *
 * The prune loop is used also for channel flushing. For this purpose, the
 * channels to flush are marked before the iteration and notified after the
 * iteration.
 */
static void
rt_prune_table(struct rtable_private *tab)
{
  struct fib_iterator *fit = &tab->prune_fit;
  int limit = 2000;

  struct rt_import_hook *ih;
  node *n, *x;

  rt_trace(tab, D_STATES, "Pruning");
#ifdef DEBUGGING
  fib_check(&tab->fib);
#endif

  if (tab->prune_state == 0)
    return;

  if (tab->prune_state == 1)
  {
    /* Mark channels to flush */
    WALK_LIST2(ih, n, tab->imports, n)
      if (ih->import_state == TIS_STOP)
	rt_set_import_state(ih, TIS_FLUSHING);
      else if ((ih->stale_valid != ih->stale_pruning) && (ih->stale_pruning == ih->stale_pruned))
      {
	ih->stale_pruning = ih->stale_valid;

	if (ih->req->trace_routes & D_STATES)
	  log(L_TRACE "%s: table prune after refresh begin [%u]", ih->req->name, ih->stale_pruning);
      }

    FIB_ITERATE_INIT(fit, &tab->fib);
    tab->prune_state = 2;

    tab->gc_counter = 0;
    tab->gc_time = current_time();

    if (tab->prune_trie)
    {
      /* Init prefix trie pruning */
      tab->trie_new = f_new_trie(lp_new_default(tab->rp), 0);
      tab->trie_new->ipv4 = tab->trie->ipv4;
    }
  }

again:
  FIB_ITERATE_START(&tab->fib, fit, net, n)
    {
    rescan:
      if (limit <= 0)
      {
	FIB_ITERATE_PUT(fit);
	birdloop_flag(tab->loop, RTF_CLEANUP);
	return;
      }

      for (struct rte_storage *e=n->routes; e; e=e->next)
      {
	struct rt_import_hook *s = e->rte.sender;
	if ((s->import_state == TIS_FLUSHING) ||
	    (e->rte.stale_cycle < s->stale_valid) ||
	    (e->rte.stale_cycle > s->stale_set))
	  {
	    rte_recalculate(tab, e->rte.sender, n, NULL, e->rte.src);
	    limit--;

	    goto rescan;
	  }
      }

      if (!n->routes && !n->first)		/* Orphaned FIB entry */
	{
	  FIB_ITERATE_PUT(fit);
	  fib_delete(&tab->fib, n);
	  goto again;
	}

      if (tab->trie_new)
      {
	trie_add_prefix(tab->trie_new, n->n.addr, n->n.addr->pxlen, n->n.addr->pxlen);
	limit--;
      }
    }
  FIB_ITERATE_END;

  rt_trace(tab, D_EVENTS, "Prune done, scheduling export timer");
  rt_kick_export_settle(tab);

#ifdef DEBUGGING
  fib_check(&tab->fib);
#endif

  /* state change 2->0, 3->1 */
  if (tab->prune_state &= 1)
    birdloop_flag(tab->loop, RTF_CLEANUP);

  if (tab->trie_new)
  {
    /* Finish prefix trie pruning */

    if (!tab->trie_lock_count)
    {
      rfree(tab->trie->lp);
    }
    else
    {
      ASSERT(!tab->trie_old);
      tab->trie_old = tab->trie;
      tab->trie_old_lock_count = tab->trie_lock_count;
      tab->trie_lock_count = 0;
    }

    tab->trie = tab->trie_new;
    tab->trie_new = NULL;
    tab->prune_trie = 0;
  }
  else
  {
    /* Schedule prefix trie pruning */
    if (tab->trie && !tab->trie_old && (tab->trie->prefix_count > (2 * tab->fib.entries)))
    {
      /* state change 0->1, 2->3 */
      tab->prune_state |= 1;
      tab->prune_trie = 1;
    }
  }

  /* Close flushed channels */
  WALK_LIST2_DELSAFE(ih, n, x, tab->imports, n)
    if (ih->import_state == TIS_FLUSHING)
    {
      DBG("flushing %s %s rr %u", ih->req->name, tab->name, tab->rr_counter);
      ih->flush_seq = tab->exporter.next_seq;
      rt_set_import_state(ih, TIS_WAITING);
      tab->rr_counter--;
      tab->wait_counter++;
    }
    else if (ih->stale_pruning != ih->stale_pruned)
    {
      DBG("pruning %s %s rr %u set %u valid %u pruning %u pruned %u", ih->req->name, tab->name, tab->rr_counter, ih->stale_set, ih->stale_valid, ih->stale_pruning, ih->stale_pruned);
      tab->rr_counter -= (ih->stale_pruning - ih->stale_pruned);
      ih->stale_pruned = ih->stale_pruning;
      if (ih->req->trace_routes & D_STATES)
	log(L_TRACE "%s: table prune after refresh end [%u]", ih->req->name, ih->stale_pruned);
    }

  /* In some cases, we may want to directly proceed to export cleanup */
  if (EMPTY_LIST(tab->exporter.e.hooks) && tab->wait_counter)
    rt_export_cleanup(tab);
}

static void
rt_export_cleanup(struct rtable_private *tab)
{
  tab->export_used = 0;

  u64 min_seq = ~((u64) 0);
  struct rt_pending_export *last_export_to_free = NULL;
  struct rt_pending_export *first = tab->exporter.first;
  int want_prune = 0;

  struct rt_table_export_hook *eh;
  node *n;
  WALK_LIST2(eh, n, tab->exporter.e.hooks, h.n)
  {
    switch (atomic_load_explicit(&eh->h.export_state, memory_order_acquire))
    {
      /* Export cleanup while feeding isn't implemented */
      case TES_FEEDING:
	goto done;

      /* States not interfering with export cleanup */
      case TES_DOWN:	/* This should not happen at all */
	log(L_WARN "%s: Export cleanup found hook %s in explicit state TES_DOWN", tab->name, eh->h.req->name);
	/* fall through */
      case TES_HUNGRY:	/* Feeding waiting for uncork */
      case TES_STOP:	/* No more export will happen on this hook */
	continue;

      /* Regular export */
      case TES_READY:
	{
	  struct rt_pending_export *last = atomic_load_explicit(&eh->last_export, memory_order_acquire);
	  if (!last)
	    /* No last export means that the channel has exported nothing since last cleanup */
	    goto done;

	  else if (min_seq > last->seq)
	  {
	    min_seq = last->seq;
	    last_export_to_free = last;
	  }
	  continue;
	}

      default:
	bug("%s: Strange export state of hook %s: %d", tab->name, eh->h.req->name, atomic_load_explicit(&eh->h.export_state, memory_order_relaxed));
    }
  }

  tab->exporter.first = last_export_to_free ? rt_next_export_fast(last_export_to_free) : NULL;

  rt_trace(tab, D_STATES, "Export cleanup, old exporter.first seq %lu, new %lu, min_seq %ld",
      first ? first->seq : 0,
      tab->exporter.first ? tab->exporter.first->seq : 0,
      min_seq);

  WALK_LIST2(eh, n, tab->exporter.e.hooks, h.n)
  {
    if (atomic_load_explicit(&eh->h.export_state, memory_order_acquire) != TES_READY)
      continue;

    struct rt_pending_export *last = atomic_load_explicit(&eh->last_export, memory_order_acquire);
    if (last == last_export_to_free)
    {
      /* This may fail when the channel managed to export more inbetween. This is OK. */
      atomic_compare_exchange_strong_explicit(
	  &eh->last_export, &last, NULL,
	  memory_order_release,
	  memory_order_relaxed);

      DBG("store hook=%p last_export=NULL\n", eh);
    }
  }

  while (first && (first->seq <= min_seq))
  {
    ASSERT_DIE(first->new || first->old);

    const net_addr *n = first->new ?
      first->new->rte.net :
      first->old->rte.net;
    net *net = SKIP_BACK(struct network, n.addr, (net_addr (*)[0]) n);

    ASSERT_DIE(net->first == first);

    if (first == net->last)
      /* The only export here */
      net->last = net->first = NULL;
    else
      /* First is now the next one */
      net->first = atomic_load_explicit(&first->next, memory_order_relaxed);

    want_prune += !net->routes && !net->first;

    /* For now, the old route may be finally freed */
    if (first->old)
    {
      rt_rte_trace_in(D_ROUTES, first->old->rte.sender->req, &first->old->rte, "freed");
      hmap_clear(&tab->id_map, first->old->rte.id);
      rte_free(first->old);
    }

#ifdef LOCAL_DEBUG
    memset(first, 0xbd, sizeof(struct rt_pending_export));
#endif

    struct rt_export_block *reb = HEAD(tab->exporter.pending);
    ASSERT_DIE(reb == PAGE_HEAD(first));

    u32 pos = (first - &reb->export[0]);
    u32 end = atomic_load_explicit(&reb->end, memory_order_relaxed);
    ASSERT_DIE(pos < end);

    struct rt_pending_export *next = NULL;

    if (++pos < end)
      next = &reb->export[pos];
    else
    {
      rem_node(&reb->n);

#ifdef LOCAL_DEBUG
      memset(reb, 0xbe, page_size);
#endif

      free_page(reb);

      if (EMPTY_LIST(tab->exporter.pending))
      {
	rt_trace(tab, D_EVENTS, "Resetting export seq");

	node *n;
	WALK_LIST2(eh, n, tab->exporter.e.hooks, h.n)
	{
	  if (atomic_load_explicit(&eh->h.export_state, memory_order_acquire) != TES_READY)
	    continue;

	  ASSERT_DIE(atomic_load_explicit(&eh->last_export, memory_order_acquire) == NULL);
	  bmap_reset(&eh->h.seq_map, 1024);
	}

	tab->exporter.next_seq = 1;
      }
      else
      {
	reb = HEAD(tab->exporter.pending);
	next = &reb->export[0];
      }
    }

    first = next;
  }

  rt_check_cork_low(tab);

done:;
  struct rt_import_hook *ih; node *x;
  if (tab->wait_counter)
    WALK_LIST2_DELSAFE(ih, n, x, tab->imports, n)
      if (ih->import_state == TIS_WAITING)
	if (!first || (first->seq >= ih->flush_seq))
	{
	  ih->import_state = TIS_CLEARED;
	  tab->wait_counter--;
	  ev_send(ih->req->list, &ih->announce_event);
	}

  if ((tab->gc_counter += want_prune) >= tab->config->gc_threshold)
    rt_kick_prune_timer(tab);

  if (tab->export_used)
    birdloop_flag(tab->loop, RTF_CLEANUP);

  if (EMPTY_LIST(tab->exporter.pending))
    settle_cancel(&tab->export_settle);
}

static void
rt_cork_release_hook(void *data UNUSED)
{
  do synchronize_rcu();
  while (
      !atomic_load_explicit(&rt_cork.active, memory_order_acquire) &&
      ev_run_list(&rt_cork.queue)
      );
}

/**
 * rt_lock_trie - lock a prefix trie of a routing table
 * @tab: routing table with prefix trie to be locked
 *
 * The prune loop may rebuild the prefix trie and invalidate f_trie_walk_state
 * structures. Therefore, asynchronous walks should lock the prefix trie using
 * this function. That allows the prune loop to rebuild the trie, but postpones
 * its freeing until all walks are done (unlocked by rt_unlock_trie()).
 *
 * Return a current trie that will be locked, the value should be passed back to
 * rt_unlock_trie() for unlocking.
 *
 */
struct f_trie *
rt_lock_trie(struct rtable_private *tab)
{
  ASSERT(tab->trie);

  tab->trie_lock_count++;
  return tab->trie;
}

/**
 * rt_unlock_trie - unlock a prefix trie of a routing table
 * @tab: routing table with prefix trie to be locked
 * @trie: value returned by matching rt_lock_trie()
 *
 * Done for trie locked by rt_lock_trie() after walk over the trie is done.
 * It may free the trie and schedule next trie pruning.
 */
void
rt_unlock_trie(struct rtable_private *tab, struct f_trie *trie)
{
  ASSERT(trie);

  if (trie == tab->trie)
  {
    /* Unlock the current prefix trie */
    ASSERT(tab->trie_lock_count);
    tab->trie_lock_count--;
  }
  else if (trie == tab->trie_old)
  {
    /* Unlock the old prefix trie */
    ASSERT(tab->trie_old_lock_count);
    tab->trie_old_lock_count--;

    /* Free old prefix trie that is no longer needed */
    if (!tab->trie_old_lock_count)
    {
      rfree(tab->trie_old->lp);
      tab->trie_old = NULL;

      /* Kick prefix trie pruning that was postponed */
      if (tab->trie && (tab->trie->prefix_count > (2 * tab->fib.entries)))
      {
	tab->prune_trie = 1;
	rt_kick_prune_timer(tab);
      }
    }
  }
  else
    log(L_BUG "Invalid arg to rt_unlock_trie()");
}


void
rt_preconfig(struct config *c)
{
  init_list(&c->tables);

  c->def_tables[NET_IP4] = cf_define_symbol(cf_get_symbol("master4"), SYM_TABLE, table, NULL);
  c->def_tables[NET_IP6] = cf_define_symbol(cf_get_symbol("master6"), SYM_TABLE, table, NULL);
}

void
rt_postconfig(struct config *c)
{
  uint num_tables = list_length(&c->tables);
  btime def_gc_period = 400 MS * num_tables;
  def_gc_period = MAX(def_gc_period, 10 S);
  def_gc_period = MIN(def_gc_period, 600 S);

  struct rtable_config *rc;
  WALK_LIST(rc, c->tables)
    if (rc->gc_period == (uint) -1)
      rc->gc_period = (uint) def_gc_period;

  for (uint net_type = 0; net_type < NET_MAX; net_type++)
    if (c->def_tables[net_type] && !c->def_tables[net_type]->table)
    {
      c->def_tables[net_type]->class = SYM_VOID;
      c->def_tables[net_type] = NULL;
    }
}


/*
 * Some functions for handing internal next hop updates
 * triggered by rt_schedule_nhu().
 */

void
ea_set_hostentry(ea_list **to, rtable *dep, rtable *src, ip_addr gw, ip_addr ll, u32 lnum, u32 labels[lnum])
{
  struct {
    struct adata ad;
    struct hostentry *he;
    u32 labels[0];
  } *head = (void *) tmp_alloc_adata(sizeof *head + sizeof(u32) * lnum - sizeof(struct adata));

  RT_LOCKED(src, tab)
    head->he = rt_get_hostentry(tab, gw, ll, dep);
  memcpy(head->labels, labels, lnum * sizeof(u32));

  ea_set_attr(to, EA_LITERAL_DIRECT_ADATA(
	&ea_gen_hostentry, 0, &head->ad));
}


static void
rta_apply_hostentry(ea_list **to, struct hostentry_adata *head)
{
  struct hostentry *he = head->he;
  u32 *labels = head->labels;
  u32 lnum = (u32 *) (head->ad.data + head->ad.length) - labels;

  ea_set_attr_u32(to, &ea_gen_igp_metric, 0, he->igp_metric);

  if (!he->src)
  {
    ea_set_dest(to, 0, RTD_UNREACHABLE);
    return;
  }

  eattr *he_nh_ea = ea_find(he->src, &ea_gen_nexthop);
  ASSERT_DIE(he_nh_ea);

  struct nexthop_adata *nhad = (struct nexthop_adata *) he_nh_ea->u.ptr;
  int idest = nhea_dest(he_nh_ea);

  if ((idest != RTD_UNICAST) ||
      !lnum && he->nexthop_linkable)
  { /* Just link the nexthop chain, no label append happens. */
    ea_copy_attr(to, he->src, &ea_gen_nexthop);
    return;
  }

  uint total_size = OFFSETOF(struct nexthop_adata, nh);

  NEXTHOP_WALK(nh, nhad)
  {
    if (nh->labels + lnum > MPLS_MAX_LABEL_STACK)
    {
      log(L_WARN "Sum of label stack sizes %d + %d = %d exceedes allowed maximum (%d)",
	    nh->labels, lnum, nh->labels + lnum, MPLS_MAX_LABEL_STACK);
      continue;
    }

    total_size += NEXTHOP_SIZE_CNT(nh->labels + lnum);
  }

  if (total_size == OFFSETOF(struct nexthop_adata, nh))
  {
    log(L_WARN "No valid nexthop remaining, setting route unreachable");

    struct nexthop_adata nha = {
      .ad.length = NEXTHOP_DEST_SIZE,
      .dest = RTD_UNREACHABLE,
    };

    ea_set_attr_data(to, &ea_gen_nexthop, 0, &nha.ad.data, nha.ad.length);
    return;
  }

  struct nexthop_adata *new = (struct nexthop_adata *) tmp_alloc_adata(total_size);
  struct nexthop *dest = &new->nh;

  NEXTHOP_WALK(nh, nhad)
  {
    if (nh->labels + lnum > MPLS_MAX_LABEL_STACK)
      continue;

    memcpy(dest, nh, NEXTHOP_SIZE(nh));
    if (lnum)
    {
      memcpy(&(dest->label[dest->labels]), labels, lnum * sizeof labels[0]);
      dest->labels += lnum;
    }

    if (ipa_nonzero(nh->gw))
      /* Router nexthop */
      dest->flags = (dest->flags & RNF_ONLINK);
    else if (!(nh->iface->flags & IF_MULTIACCESS) || (nh->iface->flags & IF_LOOPBACK))
      dest->gw = IPA_NONE;		/* PtP link - no need for nexthop */
    else if (ipa_nonzero(he->link))
      dest->gw = he->link;		/* Device nexthop with link-local address known */
    else
      dest->gw = he->addr;		/* Device nexthop with link-local address unknown */

    dest = NEXTHOP_NEXT(dest);
  }

  /* Fix final length */
  new->ad.length = (void *) dest - (void *) new->ad.data;
  ea_set_attr(to, EA_LITERAL_DIRECT_ADATA(
	&ea_gen_nexthop, 0, &new->ad));
}

static inline struct hostentry_adata *
rta_next_hop_outdated(ea_list *a)
{
  /* First retrieve the hostentry */
  eattr *heea = ea_find(a, &ea_gen_hostentry);
  if (!heea)
    return NULL;

  struct hostentry_adata *head = (struct hostentry_adata *) heea->u.ptr;

  /* If no nexthop is present, we have to create one */
  eattr *a_nh_ea = ea_find(a, &ea_gen_nexthop);
  if (!a_nh_ea)
    return head;

  struct nexthop_adata *nhad = (struct nexthop_adata *) a_nh_ea->u.ptr;

  /* Shortcut for unresolvable hostentry */
  if (!head->he->src)
    return NEXTHOP_IS_REACHABLE(nhad) ? head : NULL;

  /* Comparing our nexthop with the hostentry nexthop */
  eattr *he_nh_ea = ea_find(head->he->src, &ea_gen_nexthop);

  return (
      (ea_get_int(a, &ea_gen_igp_metric, IGP_METRIC_UNKNOWN) != head->he->igp_metric) ||
      (!head->he->nexthop_linkable) ||
      (!he_nh_ea != !a_nh_ea) ||
      (he_nh_ea && a_nh_ea && !adata_same(he_nh_ea->u.ptr, a_nh_ea->u.ptr)))
    ? head : NULL;
}

static inline int
rt_next_hop_update_rte(rte *old, rte *new)
{
  struct hostentry_adata *head = rta_next_hop_outdated(old->attrs);
  if (!head)
    return 0;

  *new = *old;
  rta_apply_hostentry(&new->attrs, head);
  return 1;
}

static inline void
rt_next_hop_resolve_rte(rte *r)
{
  eattr *heea = ea_find(r->attrs, &ea_gen_hostentry);
  if (!heea)
    return;

  struct hostentry_adata *head = (struct hostentry_adata *) heea->u.ptr;

  rta_apply_hostentry(&r->attrs, head);
}

#ifdef CONFIG_BGP

static inline int
net_flow_has_dst_prefix(const net_addr *n)
{
  ASSUME(net_is_flow(n));

  if (n->pxlen)
    return 1;

  if (n->type == NET_FLOW4)
  {
    const net_addr_flow4 *n4 = (void *) n;
    return (n4->length > sizeof(net_addr_flow4)) && (n4->data[0] == FLOW_TYPE_DST_PREFIX);
  }
  else
  {
    const net_addr_flow6 *n6 = (void *) n;
    return (n6->length > sizeof(net_addr_flow6)) && (n6->data[0] == FLOW_TYPE_DST_PREFIX);
  }
}

static inline int
rta_as_path_is_empty(ea_list *a)
{
  eattr *e = ea_find(a, "bgp_path");
  return !e || (as_path_getlen(e->u.ptr) == 0);
}

static inline u32
rta_get_first_asn(ea_list *a)
{
  eattr *e = ea_find(a, "bgp_path");
  u32 asn;

  return (e && as_path_get_first_regular(e->u.ptr, &asn)) ? asn : 0;
}

static inline enum flowspec_valid
rt_flowspec_check(rtable *tab_ip, rtable *tab_flow, const net_addr *n, ea_list *a, int interior)
{
  ASSERT(rt_is_ip(tab_ip));
  ASSERT(rt_is_flow(tab_flow));

  /* RFC 8955 6. a) Flowspec has defined dst prefix */
  if (!net_flow_has_dst_prefix(n))
    return FLOWSPEC_INVALID;

  /* RFC 9117 4.1. Accept  AS_PATH is empty (fr */
  if (interior && rta_as_path_is_empty(a))
    return FLOWSPEC_VALID;


  /* RFC 8955 6. b) Flowspec and its best-match route have the same originator */

  /* Find flowspec dst prefix */
  net_addr dst;
  if (n->type == NET_FLOW4)
    net_fill_ip4(&dst, net4_prefix(n), net4_pxlen(n));
  else
    net_fill_ip6(&dst, net6_prefix(n), net6_pxlen(n));

  rte rb = {};
  net_addr_union nau;
  RT_LOCKED(tab_ip, tip)
  {
    ASSERT(tip->trie);
    /* Find best-match BGP unicast route for flowspec dst prefix */
    net *nb = net_route(tip, &dst);
    if (nb)
    {
      rb = RTE_COPY_VALID(nb->routes);
      rta_clone(rb.attrs);
      net_copy(&nau.n, nb->n.addr);
      rb.net = &nau.n;
    }
  }

  /* Register prefix to trie for tracking further changes */
  int max_pxlen = (n->type == NET_FLOW4) ? IP4_MAX_PREFIX_LENGTH : IP6_MAX_PREFIX_LENGTH;
  RT_LOCKED(tab_flow, tfl)
    trie_add_prefix(tfl->flowspec_trie, &dst, (rb.net ? rb.net->pxlen : 0), max_pxlen);

  /* No best-match BGP route -> no flowspec */
  if (!rb.attrs || (rt_get_source_attr(&rb) != RTS_BGP))
    return FLOWSPEC_INVALID;

  /* Find ORIGINATOR_ID values */
  u32 orig_a = ea_get_int(a, "bgp_originator_id", 0);
  u32 orig_b = ea_get_int(rb.attrs, "bgp_originator_id", 0);

  /* Originator is either ORIGINATOR_ID (if present), or BGP neighbor address (if not) */
  if ((orig_a != orig_b) || (!orig_a && !orig_b && !ipa_equal(
	  ea_get_ip(a, &ea_gen_from, IPA_NONE),
	  ea_get_ip(rb.attrs, &ea_gen_from, IPA_NONE)
	  )))
    return FLOWSPEC_INVALID;


  /* Find ASN of the best-match route, for use in next checks */
  u32 asn_b = rta_get_first_asn(rb.attrs);
  if (!asn_b)
    return FLOWSPEC_INVALID;

  /* RFC 9117 4.2. For EBGP, flowspec and its best-match route are from the same AS */
  if (!interior && (rta_get_first_asn(a) != asn_b))
    return FLOWSPEC_INVALID;

  /* RFC 8955 6. c) More-specific routes are from the same AS as the best-match route */
  RT_LOCKED(tab_ip, tip)
  {
    TRIE_WALK(tip->trie, subnet, &dst)
    {
      net *nc = net_find_valid(tip, &subnet);
      if (!nc)
	continue;

      const rte *rc = &nc->routes->rte;
      if (rt_get_source_attr(rc) != RTS_BGP)
	RT_RETURN(tip, FLOWSPEC_INVALID);

      if (rta_get_first_asn(rc->attrs) != asn_b)
	RT_RETURN(tip, FLOWSPEC_INVALID);
    }
    TRIE_WALK_END;
  }

  return FLOWSPEC_VALID;
}

#endif /* CONFIG_BGP */

static int
rt_flowspec_update_rte(rtable *tab, rte *r, rte *new)
{
#ifdef CONFIG_BGP
  if (r->generation || (rt_get_source_attr(r) != RTS_BGP))
    return 0;

  struct bgp_channel *bc = (struct bgp_channel *) SKIP_BACK(struct channel, in_req, r->sender->req);
  if (!bc->base_table)
    return 0;

  struct bgp_proto *p = SKIP_BACK(struct bgp_proto, p, bc->c.proto);

  enum flowspec_valid old = rt_get_flowspec_valid(r),
		      valid = rt_flowspec_check(bc->base_table, tab, r->net, r->attrs, p->is_interior);

  if (old == valid)
    return 0;

  *new = *r;
  ea_set_attr_u32(&new->attrs, &ea_gen_flowspec_valid, 0, valid);
  return 1;
#else
  return 0;
#endif
}

static inline void
rt_flowspec_resolve_rte(rte *r, struct channel *c)
{
#ifdef CONFIG_BGP
  enum flowspec_valid valid, old = rt_get_flowspec_valid(r);
  struct bgp_channel *bc = (struct bgp_channel *) c;

  if (	(rt_get_source_attr(r) == RTS_BGP)
     && (c->channel == &channel_bgp)
     && (bc->base_table))
  {
    struct bgp_proto *p = SKIP_BACK(struct bgp_proto, p, bc->c.proto);
    valid = rt_flowspec_check(
	bc->base_table,
	c->in_req.hook->table,
	r->net, r->attrs, p->is_interior);
  }
  else
    valid = FLOWSPEC_UNKNOWN;

  if (valid == old)
    return;

  if (valid == FLOWSPEC_UNKNOWN)
    ea_unset_attr(&r->attrs, 0, &ea_gen_flowspec_valid);
  else
    ea_set_attr_u32(&r->attrs, &ea_gen_flowspec_valid, 0, valid);
#endif
}

static inline int
rt_next_hop_update_net(struct rtable_private *tab, net *n)
{
  uint count = 0;
  int is_flow = net_is_flow(n->n.addr);

  struct rte_storage *old_best = n->routes;
  if (!old_best)
    return 0;

  for (struct rte_storage *e, **k = &n->routes; e = *k; k = &e->next)
    count++;

  if (!count)
    return 0;

  struct rte_multiupdate {
    struct rte_storage *old, *new_stored;
    rte new;
  } *updates = tmp_allocz(sizeof(struct rte_multiupdate) * (count+1));

  struct rt_pending_export *last_pending = n->last;

  uint pos = 0;
  for (struct rte_storage *e, **k = &n->routes; e = *k; k = &e->next)
    updates[pos++].old = e;

  /* This is an exceptional place where table can be unlocked while keeping its data:
   * the reason why this is safe is that NHU must be always run from the same
   * thread as cleanup routines, therefore the only real problem may arise when
   * some importer does a change on this particular net (destination) while NHU
   * is being computed. Statistically, this should almost never happen. In such
   * case, we just drop all the computed changes and do it once again.
   * */
  RT_UNLOCK(tab);

  uint mod = 0;
  if (is_flow)
    for (uint i = 0; i < pos; i++)
      mod += rt_flowspec_update_rte(RT_PUB(tab), &updates[i].old->rte, &updates[i].new);

  else
    for (uint i = 0; i < pos; i++)
      mod += rt_next_hop_update_rte(&updates[i].old->rte, &updates[i].new);

  RT_LOCK(RT_PUB(tab));

  if (!mod)
    return 0;

  /* Something has changed inbetween, retry NHU. */
  if (last_pending != n->last)
    return rt_next_hop_update_net(tab, n);

  /* Now we reconstruct the original linked list */
  struct rte_storage **nptr = &n->routes;
  for (uint i = 0; i < pos; i++)
  {
    updates[i].old->next = NULL;

    struct rte_storage *put;
    if (updates[i].new.attrs)
      put = updates[i].new_stored = rte_store(&updates[i].new, n, tab);
    else
      put = updates[i].old;

    *nptr = put;
    nptr = &put->next;
  }
  *nptr = NULL;

  /* Call the pre-comparison hooks */
  for (uint i = 0; i < pos; i++)
    if (updates[i].new_stored)
      {
	/* Get a new ID for the route */
	updates[i].new_stored->rte.lastmod = current_time();
	updates[i].new_stored->rte.id = hmap_first_zero(&tab->id_map);
	hmap_set(&tab->id_map, updates[i].new_stored->rte.id);

	/* Call a pre-comparison hook */
	/* Not really an efficient way to compute this */
	if (updates[i].old->rte.src->owner->rte_recalculate)
	  updates[i].old->rte.src->owner->rte_recalculate(tab, n, &updates[i].new_stored->rte, &updates[i].old->rte, &old_best->rte);
      }

#if DEBUGGING
  {
    uint t = 0;
    for (struct rte_storage *e = n->routes; e; e = e->next)
      t++;
    ASSERT_DIE(t == pos);
    ASSERT_DIE(pos == count);
  }
#endif

  /* Find the new best route */
  struct rte_storage **new_best = NULL;
  for (struct rte_storage *e, **k = &n->routes; e = *k; k = &e->next)
    {
      if (!new_best || rte_better(&e->rte, &(*new_best)->rte))
	new_best = k;
    }

  /* Relink the new best route to the first position */
  struct rte_storage *new = *new_best;
  if (new != n->routes)
    {
      *new_best = new->next;
      new->next = n->routes;
      n->routes = new;
    }

  uint total = 0;
  /* Announce the changes */
  for (uint i=0; i<count; i++)
  {
    if (!updates[i].new_stored)
      continue;

    _Bool nb = (new->rte.src == updates[i].new.src), ob = (i == 0);
    const char *best_indicator[2][2] = {
      { "autoupdated", "autoupdated [-best]" },
      { "autoupdated [+best]", "autoupdated [best]" }
    };
    rt_rte_trace_in(D_ROUTES, updates[i].new.sender->req, &updates[i].new, best_indicator[nb][ob]);
    rte_announce(tab, n, updates[i].new_stored, updates[i].old, new, old_best);

    total++;
  }

  return total;
}

static void
rt_nhu_uncork(void *_tab)
{
  RT_LOCKED((rtable *) _tab, tab)
  {
    ASSERT_DIE(tab->nhu_corked);
    ASSERT_DIE(tab->nhu_state == 0);

    /* Reset the state */
    tab->nhu_state = tab->nhu_corked;
    tab->nhu_corked = 0;
    rt_trace(tab, D_STATES, "Next hop updater uncorked");

    birdloop_flag(tab->loop, RTF_NHU);
  }
}

static void
rt_next_hop_update(struct rtable_private *tab)
{
  ASSERT_DIE(birdloop_inside(tab->loop));

  if (tab->nhu_corked)
    return;

  if (!tab->nhu_state)
    return;

  /* Check corkedness */
  if (rt_cork_check(tab->nhu_uncork_event))
  {
    rt_trace(tab, D_STATES, "Next hop updater corked");
    if ((tab->nhu_state & NHU_RUNNING)
	&& !EMPTY_LIST(tab->exporter.pending))
      rt_kick_export_settle(tab);

    tab->nhu_corked = tab->nhu_state;
    tab->nhu_state = 0;
    return;
  }

  struct fib_iterator *fit = &tab->nhu_fit;
  int max_feed = 32;

  /* Initialize a new run */
  if (tab->nhu_state == NHU_SCHEDULED)
  {
    FIB_ITERATE_INIT(fit, &tab->fib);
    tab->nhu_state = NHU_RUNNING;

    if (tab->flowspec_trie)
      rt_flowspec_reset_trie(tab);
  }

  /* Walk the fib one net after another */
  FIB_ITERATE_START(&tab->fib, fit, net, n)
    {
      if (max_feed <= 0)
	{
	  FIB_ITERATE_PUT(fit);
	  birdloop_flag(tab->loop, RTF_NHU);
	  return;
	}
      lp_state lps;
      lp_save(tmp_linpool, &lps);
      max_feed -= rt_next_hop_update_net(tab, n);
      lp_restore(tmp_linpool, &lps);
    }
  FIB_ITERATE_END;

  /* Finished NHU, cleanup */
  rt_trace(tab, D_EVENTS, "NHU done, scheduling export timer");
  rt_kick_export_settle(tab);

  /* State change:
   *   NHU_DIRTY   -> NHU_SCHEDULED
   *   NHU_RUNNING -> NHU_CLEAN
   */
  if ((tab->nhu_state &= NHU_SCHEDULED) == NHU_SCHEDULED)
    birdloop_flag(tab->loop, RTF_NHU);
}

void
rt_new_default_table(struct symbol *s)
{
  for (uint addr_type = 0; addr_type < NET_MAX; addr_type++)
    if (s == new_config->def_tables[addr_type])
    {
      s->table = rt_new_table(s, addr_type);
      return;
    }

  bug("Requested an unknown new default table: %s", s->name);
}

struct rtable_config *
rt_get_default_table(struct config *cf, uint addr_type)
{
  struct symbol *ts = cf->def_tables[addr_type];
  if (!ts)
    return NULL;

  if (!ts->table)
    rt_new_default_table(ts);

  return ts->table;
}

struct rtable_config *
rt_new_table(struct symbol *s, uint addr_type)
{
  struct rtable_config *c = cfg_allocz(sizeof(struct rtable_config));

  if (s == new_config->def_tables[addr_type])
    s->table = c;
  else
    cf_define_symbol(s, SYM_TABLE, table, c);

  c->name = s->name;
  c->addr_type = addr_type;
  c->gc_threshold = 1000;
  c->gc_period = (uint) -1;	/* set in rt_postconfig() */
  c->cork_threshold.low = 1024;
  c->cork_threshold.high = 8192;
  c->export_settle = (struct settle_config) {
    .min = 1 MS,
    .max = 100 MS,
  };
  c->export_rr_settle = (struct settle_config) {
    .min = 100 MS,
    .max = 3 S,
  };
  c->debug = new_config->table_debug;

  add_tail(&new_config->tables, &c->n);

  /* First table of each type is kept as default */
  if (! new_config->def_tables[addr_type])
    new_config->def_tables[addr_type] = s;

  return c;
}

/**
 * rt_lock_table - lock a routing table
 * @r: routing table to be locked
 *
 * Lock a routing table, because it's in use by a protocol,
 * preventing it from being freed when it gets undefined in a new
 * configuration.
 */
void
rt_lock_table_priv(struct rtable_private *r, const char *file, uint line)
{
  rt_trace(r, D_STATES, "Locked at %s:%d", file, line);
  r->use_count++;
}

/**
 * rt_unlock_table - unlock a routing table
 * @r: routing table to be unlocked
 *
 * Unlock a routing table formerly locked by rt_lock_table(),
 * that is decrease its use count and delete it if it's scheduled
 * for deletion by configuration changes.
 */
void
rt_unlock_table_priv(struct rtable_private *r, const char *file, uint line)
{
  rt_trace(r, D_STATES, "Unlocked at %s:%d", file, line);
  if (!--r->use_count && r->deleted)
    /* Stop the service thread to finish this up */
    ev_send(&global_event_list, ev_new_init(r->rp, rt_shutdown, r));
}

static void
rt_shutdown(void *tab_)
{
  struct rtable_private *r = tab_;
  birdloop_stop(r->loop, rt_delete, r);
}

static void
rt_delete(void *tab_)
{
  birdloop_enter(&main_birdloop);

  /* We assume that nobody holds the table reference now as use_count is zero.
   * Anyway the last holder may still hold the lock. Therefore we lock and
   * unlock it the last time to be sure that nobody is there. */
  struct rtable_private *tab = RT_LOCK((rtable *) tab_);
  struct config *conf = tab->deleted;

  RT_UNLOCK(RT_PUB(tab));

  rfree(tab->rp);
  config_del_obstacle(conf);

  birdloop_leave(&main_birdloop);
}


static void
rt_check_cork_low(struct rtable_private *tab)
{
  if (!tab->cork_active)
    return;

  if (tab->deleted || !tab->exporter.first || (tab->exporter.first->seq + tab->cork_threshold.low > tab->exporter.next_seq))
  {
    tab->cork_active = 0;
    rt_cork_release();

    rt_trace(tab, D_STATES, "Uncorked");
  }
}

static void
rt_check_cork_high(struct rtable_private *tab)
{
  if (!tab->deleted && !tab->cork_active && tab->exporter.first && (tab->exporter.first->seq + tab->cork_threshold.high <= tab->exporter.next_seq))
  {
    tab->cork_active = 1;
    rt_cork_acquire();
    rt_export_used(&tab->exporter, tab->name, "corked");

    rt_trace(tab, D_STATES, "Corked");
  }
}


static int
rt_reconfigure(struct rtable_private *tab, struct rtable_config *new, struct rtable_config *old)
{
  if ((new->addr_type != old->addr_type) ||
      (new->sorted != old->sorted) ||
      (new->trie_used != old->trie_used))
    return 0;

  DBG("\t%s: same\n", new->name);
  new->table = RT_PUB(tab);
  tab->name = new->name;
  tab->config = new;

  if (tab->hostcache)
    tab->hostcache->req.trace_routes = new->debug;

  struct rt_table_export_hook *hook; node *n;
  WALK_LIST2(hook, n, tab->exporter.e.hooks, h.n)
    if (hook->h.req->export_one == rt_flowspec_export_one)
      hook->h.req->trace_routes = new->debug;

  tab->cork_threshold = new->cork_threshold;

  if (new->cork_threshold.high != old->cork_threshold.high)
    rt_check_cork_high(tab);

  if (new->cork_threshold.low != old->cork_threshold.low)
    rt_check_cork_low(tab);

  return 1;
}

static struct rtable_config *
rt_find_table_config(struct config *cf, char *name)
{
  struct symbol *sym = cf_find_symbol(cf, name);
  return (sym && (sym->class == SYM_TABLE)) ? sym->table : NULL;
}

/**
 * rt_commit - commit new routing table configuration
 * @new: new configuration
 * @old: original configuration or %NULL if it's boot time config
 *
 * Scan differences between @old and @new configuration and modify
 * the routing tables according to these changes. If @new defines a
 * previously unknown table, create it, if it omits a table existing
 * in @old, schedule it for deletion (it gets deleted when all protocols
 * disconnect from it by calling rt_unlock_table()), if it exists
 * in both configurations, leave it unchanged.
 */
void
rt_commit(struct config *new, struct config *old)
{
  struct rtable_config *o, *r;

  DBG("rt_commit:\n");
  if (old)
    {
      WALK_LIST(o, old->tables)
	{
	  struct rtable_private *tab = RT_LOCK(o->table);

	  if (tab->deleted)
	  {
	    RT_UNLOCK(tab);
	    continue;
	  }

	  r = rt_find_table_config(new, o->name);
	  if (r && !new->shutdown && rt_reconfigure(tab, r, o))
	  {
	    RT_UNLOCK(tab);
	    continue;
	  }

	  DBG("\t%s: deleted\n", o->name);
	  tab->deleted = old;
	  config_add_obstacle(old);
	  rt_lock_table(tab);

	  if (tab->hostcache)
	  {
	    rt_stop_export(&tab->hostcache->req, NULL);
	    if (ev_get_list(&tab->hostcache->update) == &rt_cork.queue)
	      ev_postpone(&tab->hostcache->update);
	  }

	  rt_check_cork_low(tab);
	  rt_unlock_table(tab);

	  RT_UNLOCK(tab);
	}
    }

  WALK_LIST(r, new->tables)
    if (!r->table)
      {
	r->table = rt_setup(rt_table_pool, r);
	DBG("\t%s: created\n", r->name);
	add_tail(&routing_tables, &r->table->n);
      }
  DBG("\tdone\n");
}

static void
rt_feed_done(struct rt_export_hook *c)
{
  c->event.hook = rt_export_hook;

  rt_set_export_state(c, TES_READY);

  rt_send_export_event(c);
}

#define MAX_FEED_BLOCK	1024
typedef struct {
  uint cnt, pos;
  union {
    struct rt_pending_export *rpe;
    struct {
      rte **feed;
      uint *start;
    };
  };
} rt_feed_block;

static int
rt_prepare_feed(struct rt_table_export_hook *c, net *n, rt_feed_block *b)
{
  if (n->routes)
  {
    if (c->h.req->export_bulk)
    {
      uint cnt = rte_feed_count(n);
      if (b->cnt && (b->cnt + cnt > MAX_FEED_BLOCK))
	return 0;

      if (!b->cnt)
      {
	b->feed = tmp_alloc(sizeof(rte *) * MAX(MAX_FEED_BLOCK, cnt));
	b->start = tmp_alloc(sizeof(uint) * ((cnt >= MAX_FEED_BLOCK) ? 2 : (MAX_FEED_BLOCK + 2 - cnt)));
      }

      rte_feed_obtain(n, &b->feed[b->cnt], cnt);
      b->start[b->pos++] = b->cnt;
      b->cnt += cnt;
    }
    else if (b->pos == MAX_FEED_BLOCK)
      return 0;
    else
    {
      if (!b->pos)
	b->rpe = tmp_alloc(sizeof(struct rt_pending_export) * MAX_FEED_BLOCK);

      b->rpe[b->pos++] = (struct rt_pending_export) { .new = n->routes, .new_best = n->routes };
    }
  }

  rpe_mark_seen_all(&c->h, n->first, NULL);
  return 1;
}

static void
rt_process_feed(struct rt_table_export_hook *c, rt_feed_block *b)
{
  if (!b->pos)
    return;

  if (c->h.req->export_bulk)
  {
    b->start[b->pos] = b->cnt;
    for (uint p = 0; p < b->pos; p++)
    {
      rte **feed = &b->feed[b->start[p]];
      c->h.req->export_bulk(c->h.req, feed[0]->net, NULL, feed, b->start[p+1] - b->start[p]);
    }
  }
  else
    for (uint p = 0; p < b->pos; p++)
      c->h.req->export_one(c->h.req, b->rpe[p].new->rte.net, &b->rpe[p]);
}

/**
 * rt_feed_by_fib - advertise all routes to a channel by walking a fib
 * @c: channel to be fed
 *
 * This function performs one pass of advertisement of routes to a channel that
 * is in the ES_FEEDING state. It is called by the protocol code as long as it
 * has something to do. (We avoid transferring all the routes in single pass in
 * order not to monopolize CPU time.)
 */
static void
rt_feed_by_fib(void *data)
{
  struct rt_table_export_hook *c = data;
  struct fib_iterator *fit = &c->feed_fit;
  rt_feed_block block = {};

  ASSERT(atomic_load_explicit(&c->h.export_state, memory_order_relaxed) == TES_FEEDING);

  RT_LOCKED(RT_PUB(SKIP_BACK(struct rtable_private, exporter, c->table)), tab)
  {

  FIB_ITERATE_START(&tab->fib, fit, net, n)
    {
      if ((c->h.req->addr_mode == TE_ADDR_NONE) || net_in_netX(n->n.addr, c->h.req->addr))
      {
	if (!rt_prepare_feed(c, n, &block))
	{
	  FIB_ITERATE_PUT(fit);
	  RT_UNLOCK(tab);
	  rt_process_feed(c, &block);
	  rt_send_export_event(&c->h);
	  return;
	}
      }
    }
  FIB_ITERATE_END;
  }

  rt_process_feed(c, &block);
  rt_feed_done(&c->h);
}

static void
rt_feed_by_trie(void *data)
{
  struct rt_table_export_hook *c = data;
  rt_feed_block block = {};

  RT_LOCKED(RT_PUB(SKIP_BACK(struct rtable_private, exporter, c->table)), tab)
  {

  ASSERT_DIE(c->walk_state);
  struct f_trie_walk_state *ws = c->walk_state;

  ASSERT(atomic_load_explicit(&c->h.export_state, memory_order_relaxed) == TES_FEEDING);

  do {
    if (!c->walk_last.type)
      continue;

    net *n = net_find(tab, &c->walk_last);
    if (!n)
      continue;

    if (!rt_prepare_feed(c, n, &block))
    {
      RT_UNLOCK(tab);
      rt_process_feed(c, &block);
      rt_send_export_event(&c->h);
      return;
    }
  }
  while (trie_walk_next(ws, &c->walk_last));

  rt_unlock_trie(tab, c->walk_lock);
  c->walk_lock = NULL;

  mb_free(c->walk_state);
  c->walk_state = NULL;

  c->walk_last.type = 0;

  }

  rt_process_feed(c, &block);
  rt_feed_done(&c->h);
}

static void
rt_feed_equal(void *data)
{
  struct rt_table_export_hook *c = data;
  rt_feed_block block = {};
  net *n;

  RT_LOCKED(RT_PUB(SKIP_BACK(struct rtable_private, exporter, c->table)), tab)
  {
    ASSERT_DIE(atomic_load_explicit(&c->h.export_state, memory_order_relaxed) == TES_FEEDING);
    ASSERT_DIE(c->h.req->addr_mode == TE_ADDR_EQUAL);

    if (n = net_find(tab, c->h.req->addr))
      ASSERT_DIE(rt_prepare_feed(c, n, &block));
  }

  if (n)
    rt_process_feed(c, &block);

  rt_feed_done(&c->h);
}

static void
rt_feed_for(void *data)
{
  struct rt_table_export_hook *c = data;
  rt_feed_block block = {};
  net *n;

  RT_LOCKED(RT_PUB(SKIP_BACK(struct rtable_private, exporter, c->table)), tab)
  {
    ASSERT_DIE(atomic_load_explicit(&c->h.export_state, memory_order_relaxed) == TES_FEEDING);
    ASSERT_DIE(c->h.req->addr_mode == TE_ADDR_FOR);

    if (n = net_route(tab, c->h.req->addr))
      ASSERT_DIE(rt_prepare_feed(c, n, &block));
  }

  if (n)
    rt_process_feed(c, &block);

  rt_feed_done(&c->h);
}


/*
 *	Import table
 */

void channel_reload_export_bulk(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *rpe UNUSED, rte **feed, uint count)
{
  struct channel *c = SKIP_BACK(struct channel, reload_req, req);

  for (uint i=0; i<count; i++)
    if (feed[i]->sender == c->in_req.hook)
    {
      /* Strip the later attribute layers */
      rte new = *feed[i];
      while (new.attrs->next)
	new.attrs = new.attrs->next;

      /* And reload the route */
      rte_update(c, net, &new, new.src);
    }
}


/*
 *	Hostcache
 */

static inline u32
hc_hash(ip_addr a, rtable *dep)
{
  return ipa_hash(a) ^ ptr_hash(dep);
}

static inline void
hc_insert(struct hostcache *hc, struct hostentry *he)
{
  uint k = he->hash_key >> hc->hash_shift;
  he->next = hc->hash_table[k];
  hc->hash_table[k] = he;
}

static inline void
hc_remove(struct hostcache *hc, struct hostentry *he)
{
  struct hostentry **hep;
  uint k = he->hash_key >> hc->hash_shift;

  for (hep = &hc->hash_table[k]; *hep != he; hep = &(*hep)->next);
  *hep = he->next;
}

#define HC_DEF_ORDER 10
#define HC_HI_MARK *4
#define HC_HI_STEP 2
#define HC_HI_ORDER 16			/* Must be at most 16 */
#define HC_LO_MARK /5
#define HC_LO_STEP 2
#define HC_LO_ORDER 10

static void
hc_alloc_table(struct hostcache *hc, pool *p, unsigned order)
{
  uint hsize = 1 << order;
  hc->hash_order = order;
  hc->hash_shift = 32 - order;
  hc->hash_max = (order >= HC_HI_ORDER) ? ~0U : (hsize HC_HI_MARK);
  hc->hash_min = (order <= HC_LO_ORDER) ?  0U : (hsize HC_LO_MARK);

  hc->hash_table = mb_allocz(p, hsize * sizeof(struct hostentry *));
}

static void
hc_resize(struct hostcache *hc, pool *p, unsigned new_order)
{
  struct hostentry **old_table = hc->hash_table;
  struct hostentry *he, *hen;
  uint old_size = 1 << hc->hash_order;
  uint i;

  hc_alloc_table(hc, p, new_order);
  for (i = 0; i < old_size; i++)
    for (he = old_table[i]; he != NULL; he=hen)
      {
	hen = he->next;
	hc_insert(hc, he);
      }
  mb_free(old_table);
}

static struct hostentry *
hc_new_hostentry(struct hostcache *hc, pool *p, ip_addr a, ip_addr ll, rtable *dep, unsigned k)
{
  struct hostentry *he = sl_alloc(hc->slab);

  *he = (struct hostentry) {
    .addr = a,
    .link = ll,
    .tab = dep,
    .hash_key = k,
  };

  add_tail(&hc->hostentries, &he->ln);
  hc_insert(hc, he);

  hc->hash_items++;
  if (hc->hash_items > hc->hash_max)
    hc_resize(hc, p, hc->hash_order + HC_HI_STEP);

  return he;
}

static void
hc_delete_hostentry(struct hostcache *hc, pool *p, struct hostentry *he)
{
  rta_free(he->src);

  rem_node(&he->ln);
  hc_remove(hc, he);
  sl_free(he);

  hc->hash_items--;
  if (hc->hash_items < hc->hash_min)
    hc_resize(hc, p, hc->hash_order - HC_LO_STEP);
}

static void
hc_notify_dump_req(struct rt_export_request *req)
{
  debug("  Table %s (%p)\n", req->name, req);
}

static void
hc_notify_log_state_change(struct rt_export_request *req, u8 state)
{
  struct hostcache *hc = SKIP_BACK(struct hostcache, req, req);
  rt_trace((rtable *) hc->update.data, D_STATES, "HCU Export state changed to %s", rt_export_state_name(state));
}

static void
hc_notify_export_one(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *first)
{
  struct hostcache *hc = SKIP_BACK(struct hostcache, req, req);

  /* No interest in this update, mark seen only */
  int interested = 1;
  RT_LOCKED((rtable *) hc->update.data, tab)
    if (ev_active(&hc->update) || !trie_match_net(hc->trie, net))
    {
      rpe_mark_seen_all(req->hook, first, NULL);
      interested = 0;
    }

  if (!interested)
    return;

  /* This net may affect some hostentries, check the actual change */
  rte *o = RTE_VALID_OR_NULL(first->old_best);
  struct rte_storage *new_best = first->new_best;

  RPE_WALK(first, rpe, NULL)
  {
    rpe_mark_seen(req->hook, rpe);
    new_best = rpe->new_best;
  }

  /* Yes, something has actually changed. Do the hostcache update. */
  if (o != RTE_VALID_OR_NULL(new_best))
    RT_LOCKED((rtable *) hc->update.data, tab)
      if ((atomic_load_explicit(&req->hook->export_state, memory_order_acquire) == TES_READY)
	  && !ev_active(&hc->update))
	ev_send_loop(tab->loop, &hc->update);
}


static void
rt_init_hostcache(struct rtable_private *tab)
{
  struct hostcache *hc = mb_allocz(tab->rp, sizeof(struct hostcache));
  init_list(&hc->hostentries);

  hc->hash_items = 0;
  hc_alloc_table(hc, tab->rp, HC_DEF_ORDER);
  hc->slab = sl_new(tab->rp, sizeof(struct hostentry));

  hc->lp = lp_new(tab->rp);
  hc->trie = f_new_trie(hc->lp, 0);

  hc->update = (event) {
    .hook = rt_update_hostcache,
    .data = tab,
  };

  hc->req = (struct rt_export_request) {
    .name = mb_sprintf(tab->rp, "%s.hcu.notifier", tab->name),
    .list = &global_work_list,
    .trace_routes = tab->config->debug,
    .dump_req = hc_notify_dump_req,
    .log_state_change = hc_notify_log_state_change,
    .export_one = hc_notify_export_one,
  };

  rt_table_export_start_locked(tab, &hc->req);

  tab->hostcache = hc;
}

static void
rt_free_hostcache(struct rtable_private *tab)
{
  struct hostcache *hc = tab->hostcache;

  node *n;
  WALK_LIST(n, hc->hostentries)
    {
      struct hostentry *he = SKIP_BACK(struct hostentry, ln, n);
      rta_free(he->src);

      if (he->uc)
	log(L_ERR "Hostcache is not empty in table %s", tab->name);
    }

  /* Freed automagically by the resource pool
  rfree(hc->slab);
  rfree(hc->lp);
  mb_free(hc->hash_table);
  mb_free(hc);
  */
}

static int
if_local_addr(ip_addr a, struct iface *i)
{
  struct ifa *b;

  WALK_LIST(b, i->addrs)
    if (ipa_equal(a, b->ip))
      return 1;

  return 0;
}

u32
rt_get_igp_metric(const rte *rt)
{
  eattr *ea = ea_find(rt->attrs, "igp_metric");

  if (ea)
    return ea->u.data;

  if (rt_get_source_attr(rt) == RTS_DEVICE)
    return 0;

  if (rt->src->owner->class->rte_igp_metric)
    return rt->src->owner->class->rte_igp_metric(rt);

  return IGP_METRIC_UNKNOWN;
}

static int
rt_update_hostentry(struct rtable_private *tab, struct hostentry *he)
{
  ea_list *old_src = he->src;
  int direct = 0;
  int pxlen = 0;

  /* Reset the hostentry */
  he->src = NULL;
  he->nexthop_linkable = 0;
  he->igp_metric = 0;

  net_addr he_addr;
  net_fill_ip_host(&he_addr, he->addr);
  net *n = net_route(tab, &he_addr);
  if (n)
    {
      struct rte_storage *e = n->routes;
      ea_list *a = e->rte.attrs;
      u32 pref = rt_get_preference(&e->rte);

      for (struct rte_storage *ee = n->routes; ee; ee = ee->next)
	if (rte_is_valid(&ee->rte) &&
	    (rt_get_preference(&ee->rte) >= pref) &&
	    ea_find(ee->rte.attrs, &ea_gen_hostentry))
	{
	  /* Recursive route should not depend on another recursive route */
	  log(L_WARN "Next hop address %I resolvable through recursive route for %N",
	      he->addr, n->n.addr);
	  goto done;
	}

      pxlen = n->n.addr->pxlen;

      eattr *nhea = ea_find(a, &ea_gen_nexthop);
      ASSERT_DIE(nhea);
      struct nexthop_adata *nhad = (void *) nhea->u.ptr;

      if (NEXTHOP_IS_REACHABLE(nhad))
	  NEXTHOP_WALK(nh, nhad)
	    if (ipa_zero(nh->gw))
	      {
		if (if_local_addr(he->addr, nh->iface))
		  {
		    /* The host address is a local address, this is not valid */
		    log(L_WARN "Next hop address %I is a local address of iface %s",
			he->addr, nh->iface->name);
		    goto done;
		  }

		direct++;
	      }

      he->src = rta_clone(a);
      he->nexthop_linkable = !direct;
      he->igp_metric = rt_get_igp_metric(&e->rte);
    }

done:
  /* Add a prefix range to the trie */
  trie_add_prefix(tab->hostcache->trie, &he_addr, pxlen, he_addr.pxlen);

  rta_free(old_src);
  return old_src != he->src;
}

static void
rt_update_hostcache(void *data)
{
  rtable **nhu_pending;

  RT_LOCKED((rtable *) data, tab)
  {

  struct hostcache *hc = tab->hostcache;

  /* Shutdown shortcut */
  if (!hc->req.hook)
    RT_RETURN(tab);

  if (rt_cork_check(&hc->update))
  {
    rt_trace(tab, D_STATES, "Hostcache update corked");
    RT_RETURN(tab);
  }

  /* Destination schedule map */
  nhu_pending = tmp_allocz(sizeof(rtable *) * rtable_max_id);

  struct hostentry *he;
  node *n, *x;

  /* Reset the trie */
  lp_flush(hc->lp);
  hc->trie = f_new_trie(hc->lp, 0);

  WALK_LIST_DELSAFE(n, x, hc->hostentries)
    {
      he = SKIP_BACK(struct hostentry, ln, n);
      if (!he->uc)
	{
	  hc_delete_hostentry(hc, tab->rp, he);
	  continue;
	}

      if (rt_update_hostentry(tab, he))
	nhu_pending[he->tab->id] = he->tab;
    }
  }

  for (uint i=0; i<rtable_max_id; i++)
    if (nhu_pending[i])
      RT_LOCKED(nhu_pending[i], dst)
	rt_schedule_nhu(dst);
}

static struct hostentry *
rt_get_hostentry(struct rtable_private *tab, ip_addr a, ip_addr ll, rtable *dep)
{
  ip_addr link = ipa_zero(ll) ? a : ll;
  struct hostentry *he;

  if (!tab->hostcache)
    rt_init_hostcache(tab);

  u32 k = hc_hash(a, dep);
  struct hostcache *hc = tab->hostcache;
  for (he = hc->hash_table[k >> hc->hash_shift]; he != NULL; he = he->next)
    if (ipa_equal(he->addr, a) && ipa_equal(he->link, link) && (he->tab == dep))
      return he;

  he = hc_new_hostentry(hc, tab->rp, a, link, dep, k);
  rt_update_hostentry(tab, he);
  return he;
}


/*
 *  Documentation for functions declared inline in route.h
 */
#if 0

/**
 * net_find - find a network entry
 * @tab: a routing table
 * @addr: address of the network
 *
 * net_find() looks up the given network in routing table @tab and
 * returns a pointer to its &net entry or %NULL if no such network
 * exists.
 */
static inline net *net_find(rtable *tab, net_addr *addr)
{ DUMMY; }

/**
 * net_get - obtain a network entry
 * @tab: a routing table
 * @addr: address of the network
 *
 * net_get() looks up the given network in routing table @tab and
 * returns a pointer to its &net entry. If no such entry exists, it's
 * created.
 */
static inline net *net_get(rtable *tab, net_addr *addr)
{ DUMMY; }

/**
 * rte_cow - copy a route for writing
 * @r: a route entry to be copied
 *
 * rte_cow() takes a &rte and prepares it for modification. The exact action
 * taken depends on the flags of the &rte -- if it's a temporary entry, it's
 * just returned unchanged, else a new temporary entry with the same contents
 * is created.
 *
 * The primary use of this function is inside the filter machinery -- when
 * a filter wants to modify &rte contents (to change the preference or to
 * attach another set of attributes), it must ensure that the &rte is not
 * shared with anyone else (and especially that it isn't stored in any routing
 * table).
 *
 * Result: a pointer to the new writable &rte.
 */
static inline rte * rte_cow(rte *r)
{ DUMMY; }

#endif
