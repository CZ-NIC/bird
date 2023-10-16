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
 * rt_notify_hostcache(), which immediately checks using the trie whether the
 * change is relevant and if it is, then it schedules asynchronous hostcache
 * recomputation. The recomputation is done by rt_update_hostcache() (called
 * from rt_event() of src table), it walks through all hostentries and resolves
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
 * share common net prefix than routes sharing a common next hop). In src table,
 * there is a list of dst tables (list flowspec_links), this list is updated by
 * flowpsec channels (by rt_flowspec_link() and rt_flowspec_unlink() during
 * channel start/stop). Each dst table has its own trie of prefixes that may
 * influence validation of flowspec routes in it (flowspec_trie).
 *
 * When a best route changes in the src table, rt_flowspec_notify() immediately
 * checks all dst tables from the list using their tries to see whether the
 * change is relevant for them. If it is, then an asynchronous re-validation of
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
 * simplest. It is just a list of subscribers in src table, who are notified
 * when any change happened, but only after a settle time. Also, in RPKI case
 * the dst is not a table, but a channel, who refeeds routes through a filter.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/mpls.h"
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

#ifdef CONFIG_BGP
#include "proto/bgp/bgp.h"
#endif

pool *rt_table_pool;

static slab *rte_slab;
linpool *rte_update_pool;

list routing_tables;

static void rt_free_hostcache(rtable *tab);
static void rt_notify_hostcache(rtable *tab, net *net);
static void rt_update_hostcache(rtable *tab);
static void rt_next_hop_update(rtable *tab);
static inline void rt_prune_table(rtable *tab);
static inline void rt_schedule_notify(rtable *tab);
static void rt_flowspec_notify(rtable *tab, net *net);
static void rt_kick_prune_timer(rtable *tab);


static void
net_init_with_trie(struct fib *f, void *N)
{
  rtable *tab = SKIP_BACK(rtable, fib, f);
  net *n = N;

  if (tab->trie)
    trie_add_prefix(tab->trie, n->n.addr, n->n.addr->pxlen, n->n.addr->pxlen);

  if (tab->trie_new)
    trie_add_prefix(tab->trie_new, n->n.addr, n->n.addr->pxlen, n->n.addr->pxlen);
}

static inline net *
net_route_ip4_trie(rtable *t, const net_addr_ip4 *n0)
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
net_route_vpn4_trie(rtable *t, const net_addr_vpn4 *n0)
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
net_route_ip6_trie(rtable *t, const net_addr_ip6 *n0)
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
net_route_vpn6_trie(rtable *t, const net_addr_vpn6 *n0)
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
net_route_ip6_sadr_trie(rtable *t, const net_addr_ip6_sadr *n0)
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
net_route_ip4_fib(rtable *t, const net_addr_ip4 *n0)
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
net_route_vpn4_fib(rtable *t, const net_addr_vpn4 *n0)
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
net_route_ip6_fib(rtable *t, const net_addr_ip6 *n0)
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
net_route_vpn6_fib(rtable *t, const net_addr_vpn6 *n0)
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
net_route_ip6_sadr_fib(rtable *t, const net_addr_ip6_sadr *n0)
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
net_route(rtable *tab, const net_addr *n)
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
net_roa_check_ip4_trie(rtable *tab, const net_addr_ip4 *px, u32 asn)
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

      if (net_equal_prefix_roa4(roa, &roa0) && rte_is_valid(r->routes))
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
net_roa_check_ip4_fib(rtable *tab, const net_addr_ip4 *px, u32 asn)
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

      if (net_equal_prefix_roa4(roa, &n) && rte_is_valid(r->routes))
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
net_roa_check_ip6_trie(rtable *tab, const net_addr_ip6 *px, u32 asn)
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

      if (net_equal_prefix_roa6(roa, &roa0) && rte_is_valid(r->routes))
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
net_roa_check_ip6_fib(rtable *tab, const net_addr_ip6 *px, u32 asn)
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

      if (net_equal_prefix_roa6(roa, &n) && rte_is_valid(r->routes))
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
net_roa_check(rtable *tab, const net_addr *n, u32 asn)
{
  if ((tab->addr_type == NET_ROA4) && (n->type == NET_IP4))
  {
    if (tab->trie)
      return net_roa_check_ip4_trie(tab, (const net_addr_ip4 *) n, asn);
    else
      return net_roa_check_ip4_fib (tab, (const net_addr_ip4 *) n, asn);
  }
  else if ((tab->addr_type == NET_ROA6) && (n->type == NET_IP6))
  {
    if (tab->trie)
      return net_roa_check_ip6_trie(tab, (const net_addr_ip6 *) n, asn);
    else
      return net_roa_check_ip6_fib (tab, (const net_addr_ip6 *) n, asn);
  }
  else
    return ROA_UNKNOWN;	/* Should not happen */
}

/**
 * rte_find - find a route
 * @net: network node
 * @src: route source
 *
 * The rte_find() function returns a route for destination @net
 * which is from route source @src.
 */
rte *
rte_find(net *net, struct rte_src *src)
{
  rte *e = net->routes;

  while (e && e->src != src)
    e = e->next;
  return e;
}

/**
 * rte_get_temp - get a temporary &rte
 * @a: attributes to assign to the new route (a &rta; in case it's
 * un-cached, rte_update() will create a cached copy automatically)
 * @src: route source
 *
 * Create a temporary &rte and bind it with the attributes @a.
 */
rte *
rte_get_temp(rta *a, struct rte_src *src)
{
  rte *e = sl_alloc(rte_slab);

  e->attrs = a;
  e->id = 0;
  e->flags = 0;
  e->pflags = 0;
  rt_lock_source(e->src = src);
  return e;
}

rte *
rte_do_cow(rte *r)
{
  rte *e = sl_alloc(rte_slab);

  memcpy(e, r, sizeof(rte));

  rt_lock_source(e->src);
  e->attrs = rta_clone(r->attrs);
  e->flags = 0;
  return e;
}

/**
 * rte_cow_rta - get a private writable copy of &rte with writable &rta
 * @r: a route entry to be copied
 * @lp: a linpool from which to allocate &rta
 *
 * rte_cow_rta() takes a &rte and prepares it and associated &rta for
 * modification. There are three possibilities: First, both &rte and &rta are
 * private copies, in that case they are returned unchanged.  Second, &rte is
 * private copy, but &rta is cached, in that case &rta is duplicated using
 * rta_do_cow(). Third, both &rte is shared and &rta is cached, in that case
 * both structures are duplicated by rte_do_cow() and rta_do_cow().
 *
 * Note that in the second case, cached &rta loses one reference, while private
 * copy created by rta_do_cow() is a shallow copy sharing indirect data (eattrs,
 * nexthops, ...) with it. To work properly, original shared &rta should have
 * another reference during the life of created private copy.
 *
 * Result: a pointer to the new writable &rte with writable &rta.
 */
rte *
rte_cow_rta(rte *r, linpool *lp)
{
  if (!rta_is_cached(r->attrs))
    return r;

  r = rte_cow(r);
  rta *a = rta_do_cow(r->attrs, lp);
  rta_free(r->attrs);
  r->attrs = a;
  return r;
}

static int				/* Actually better or at least as good as */
rte_better(rte *new, rte *old)
{
  int (*better)(rte *, rte *);

  if (!rte_is_valid(old))
    return 1;
  if (!rte_is_valid(new))
    return 0;

  if (new->attrs->pref > old->attrs->pref)
    return 1;
  if (new->attrs->pref < old->attrs->pref)
    return 0;
  if (new->src->proto->proto != old->src->proto->proto)
    {
      /*
       *  If the user has configured protocol preferences, so that two different protocols
       *  have the same preference, try to break the tie by comparing addresses. Not too
       *  useful, but keeps the ordering of routes unambiguous.
       */
      return new->src->proto->proto > old->src->proto->proto;
    }
  if (better = new->src->proto->rte_better)
    return better(new, old);
  return 0;
}

static int
rte_mergable(rte *pri, rte *sec)
{
  int (*mergable)(rte *, rte *);

  if (!rte_is_valid(pri) || !rte_is_valid(sec))
    return 0;

  if (pri->attrs->pref != sec->attrs->pref)
    return 0;

  if (pri->src->proto->proto != sec->src->proto->proto)
    return 0;

  if (mergable = pri->src->proto->rte_mergable)
    return mergable(pri, sec);

  return 0;
}

static void
rte_trace(struct channel *c, rte *e, int dir, char *msg)
{
  log(L_TRACE "%s.%s %c %s %N %luL %uG %s",
      c->proto->name, c->name ?: "?", dir, msg, e->net->n.addr, e->src->private_id, e->src->global_id,
      rta_dest_name(e->attrs->dest));
}

static inline void
rte_trace_in(uint flag, struct channel *c, rte *e, char *msg)
{
  if ((c->debug & flag) || (c->proto->debug & flag))
    rte_trace(c, e, '>', msg);
}

static inline void
rte_trace_out(uint flag, struct channel *c, rte *e, char *msg)
{
  if ((c->debug & flag) || (c->proto->debug & flag))
    rte_trace(c, e, '<', msg);
}

static rte *
export_filter_(struct channel *c, rte *rt0, rte **rt_free, linpool *pool, int silent)
{
  struct proto *p = c->proto;
  const struct filter *filter = c->out_filter;
  struct proto_stats *stats = &c->stats;
  rte *rt;
  int v;

  rt = rt0;
  *rt_free = NULL;

  v = p->preexport ? p->preexport(c, rt) : 0;
  if (v < 0)
    {
      if (silent)
	goto reject;

      stats->exp_updates_rejected++;
      if (v == RIC_REJECT)
	rte_trace_out(D_FILTERS, c, rt, "rejected by protocol");
      goto reject;
    }
  if (v > 0)
    {
      if (!silent)
	rte_trace_out(D_FILTERS, c, rt, "forced accept by protocol");
      goto accept;
    }

  v = filter && ((filter == FILTER_REJECT) ||
		 (f_run(filter, &rt, pool,
			(silent ? FF_SILENT : 0)) > F_ACCEPT));
  if (v)
    {
      if (silent)
	goto reject;

      stats->exp_updates_filtered++;
      rte_trace_out(D_FILTERS, c, rt, "filtered out");
      goto reject;
    }

 accept:
  if (rt != rt0)
    *rt_free = rt;
  return rt;

 reject:
  /* Discard temporary rte */
  if (rt != rt0)
    rte_free(rt);
  return NULL;
}

static inline rte *
export_filter(struct channel *c, rte *rt0, rte **rt_free, int silent)
{
  return export_filter_(c, rt0, rt_free, rte_update_pool, silent);
}

static void
do_rt_notify(struct channel *c, net *net, rte *new, rte *old, int refeed)
{
  struct proto *p = c->proto;
  struct proto_stats *stats = &c->stats;

  if (refeed && new)
    c->refeed_count++;

  /* Apply export limit */
  struct channel_limit *l = &c->out_limit;
  if (l->action && !old && new)
  {
    if (stats->exp_routes >= l->limit)
      channel_notify_limit(c, l, PLD_OUT, stats->exp_routes);

    if (l->state == PLS_BLOCKED)
    {
      stats->exp_updates_rejected++;
      rte_trace_out(D_FILTERS, c, new, "rejected [limit]");
      return;
    }
  }

  /* Apply export table */
  if (c->out_table && !rte_update_out(c, net->n.addr, new, old, refeed))
    return;

  if (new)
    stats->exp_updates_accepted++;
  else
    stats->exp_withdraws_accepted++;

  if (old)
  {
    bmap_clear(&c->export_map, old->id);
    stats->exp_routes--;
  }

  if (new)
  {
    bmap_set(&c->export_map, new->id);
    stats->exp_routes++;
  }

  if (p->debug & D_ROUTES)
  {
    if (new && old)
      rte_trace_out(D_ROUTES, c, new, "replaced");
    else if (new)
      rte_trace_out(D_ROUTES, c, new, "added");
    else if (old)
      rte_trace_out(D_ROUTES, c, old, "removed");
  }

  p->rt_notify(p, c, net, new, old);
}

static void
rt_notify_basic(struct channel *c, net *net, rte *new, rte *old, int refeed)
{
  // struct proto *p = c->proto;
  rte *new_free = NULL;

  if (new)
    c->stats.exp_updates_received++;
  else
    c->stats.exp_withdraws_received++;

  if (new)
    new = export_filter(c, new, &new_free, 0);

  if (old && !bmap_test(&c->export_map, old->id))
    old = NULL;

  if (!new && !old)
    return;

  do_rt_notify(c, net, new, old, refeed);

  /* Discard temporary rte */
  if (new_free)
    rte_free(new_free);
}

static void
rt_notify_accepted(struct channel *c, net *net, rte *new_changed, rte *old_changed, int refeed)
{
  // struct proto *p = c->proto;
  rte *new_best = NULL;
  rte *old_best = NULL;
  rte *new_free = NULL;
  int new_first = 0;

  /*
   * We assume that there are no changes in net route order except (added)
   * new_changed and (removed) old_changed. Therefore, the function is not
   * compatible with deterministic_med (where nontrivial reordering can happen
   * as a result of a route change) and with recomputation of recursive routes
   * due to next hop update (where many routes can be changed in one step).
   *
   * Note that we need this assumption just for optimizations, we could just
   * run full new_best recomputation otherwise.
   *
   * There are three cases:
   * feed or old_best is old_changed -> we need to recompute new_best
   * old_best is before new_changed -> new_best is old_best, ignore
   * old_best is after new_changed -> try new_changed, otherwise old_best
   */

  if (net->routes)
    c->stats.exp_updates_received++;
  else
    c->stats.exp_withdraws_received++;

  /* Find old_best - either old_changed, or route for net->routes */
  if (old_changed && bmap_test(&c->export_map, old_changed->id))
    old_best = old_changed;
  else
  {
    for (rte *r = net->routes; rte_is_valid(r); r = r->next)
    {
      if (bmap_test(&c->export_map, r->id))
      {
	old_best = r;
	break;
      }

      /* Note if new_changed found before old_best */
      if (r == new_changed)
	new_first = 1;
    }
  }

  /* Find new_best */
  if ((new_changed == old_changed) || (old_best == old_changed))
  {
    /* Feed or old_best changed -> find first accepted by filters */
    for (rte *r = net->routes; rte_is_valid(r); r = r->next)
      if (new_best = export_filter(c, r, &new_free, 0))
	break;
  }
  else
  {
    /* Other cases -> either new_changed, or old_best (and nothing changed) */
    if (new_first && (new_changed = export_filter(c, new_changed, &new_free, 0)))
      new_best = new_changed;
    else
      return;
  }

  if (!new_best && !old_best)
    return;

  do_rt_notify(c, net, new_best, old_best, refeed);

  /* Discard temporary rte */
  if (new_free)
    rte_free(new_free);
}


static struct nexthop *
nexthop_merge_rta(struct nexthop *nhs, rta *a, linpool *pool, int max)
{
  return nexthop_merge(nhs, &(a->nh), 1, 0, max, pool);
}

rte *
rt_export_merged(struct channel *c, net *net, rte **rt_free, linpool *pool, int silent)
{
  // struct proto *p = c->proto;
  struct nexthop *nhs = NULL;
  rte *best0, *best, *rt0, *rt, *tmp;

  best0 = net->routes;
  *rt_free = NULL;

  if (!rte_is_valid(best0))
    return NULL;

  best = export_filter_(c, best0, rt_free, pool, silent);

  if (!best || !rte_is_reachable(best))
    return best;

  for (rt0 = best0->next; rt0; rt0 = rt0->next)
  {
    if (!rte_mergable(best0, rt0))
      continue;

    rt = export_filter_(c, rt0, &tmp, pool, 1);

    if (!rt)
      continue;

    if (rte_is_reachable(rt))
      nhs = nexthop_merge_rta(nhs, rt->attrs, pool, c->merge_limit);

    if (tmp)
      rte_free(tmp);
  }

  if (nhs)
  {
    nhs = nexthop_merge_rta(nhs, best->attrs, pool, c->merge_limit);

    if (nhs->next)
    {
      best = rte_cow_rta(best, pool);
      nexthop_link(best->attrs, nhs);
    }
  }

  if (best != best0)
    *rt_free = best;

  return best;
}

static void
rt_notify_merged(struct channel *c, net *net, rte *new_changed, rte *old_changed,
		 rte *new_best, rte *old_best, int refeed)
{
  // struct proto *p = c->proto;
  rte *new_free = NULL;

  /* We assume that all rte arguments are either NULL or rte_is_valid() */

  /* This check should be done by the caller */
  if (!new_best && !old_best)
    return;

  /* Check whether the change is relevant to the merged route */
  if ((new_best == old_best) &&
      (new_changed != old_changed) &&
      !rte_mergable(new_best, new_changed) &&
      !rte_mergable(old_best, old_changed))
    return;

  if (new_best)
    c->stats.exp_updates_received++;
  else
    c->stats.exp_withdraws_received++;

  /* Prepare new merged route */
  if (new_best)
    new_best = rt_export_merged(c, net, &new_free, rte_update_pool, 0);

  /* Check old merged route */
  if (old_best && !bmap_test(&c->export_map, old_best->id))
    old_best = NULL;

  if (!new_best && !old_best)
    return;

  do_rt_notify(c, net, new_best, old_best, refeed);

  /* Discard temporary rte */
  if (new_free)
    rte_free(new_free);
}


/**
 * rte_announce - announce a routing table change
 * @tab: table the route has been added to
 * @type: type of route announcement (RA_UNDEF or RA_ANY)
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
 * Second, There is a bulk change of multiple routes in @net, with shared best
 * route selection. In such case separate route changes are described using
 * @type of %RA_ANY, with @new and @old specifying the changed route, while
 * @new_best and @old_best are NULL. After that, another notification is done
 * where @new_best and @old_best are filled (may be the same), but @new and @old
 * are NULL.
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
rte_announce(rtable *tab, uint type, net *net, rte *new, rte *old,
	     rte *new_best, rte *old_best)
{
  if (!rte_is_valid(new))
    new = NULL;

  if (!rte_is_valid(old))
    old = NULL;

  if (!rte_is_valid(new_best))
    new_best = NULL;

  if (!rte_is_valid(old_best))
    old_best = NULL;

  if (!new && !old && !new_best && !old_best)
    return;

  if (new_best != old_best)
  {
    if (new_best)
      new_best->sender->stats.pref_routes++;
    if (old_best)
      old_best->sender->stats.pref_routes--;

    if (tab->hostcache)
      rt_notify_hostcache(tab, net);

    if (!EMPTY_LIST(tab->flowspec_links))
      rt_flowspec_notify(tab, net);
  }

  rt_schedule_notify(tab);

  struct channel *c; node *n;
  WALK_LIST2(c, n, tab->channels, table_node)
  {
    if (c->export_state == ES_DOWN)
      continue;

    if (type && (type != c->ra_mode))
      continue;

    switch (c->ra_mode)
    {
    case RA_OPTIMAL:
      if (new_best != old_best)
	rt_notify_basic(c, net, new_best, old_best, 0);
      break;

    case RA_ANY:
      if (new != old)
	rt_notify_basic(c, net, new, old, 0);
      break;

    case RA_ACCEPTED:
      /*
       * The (new != old) condition is problematic here, as it would break
       * the second usage pattern (announcement after bulk change, used in
       * rt_next_hop_update_net(), which sends both new and old as NULL).
       *
       * But recursive next hops do not work with sorted tables anyways,
       * such configuration is forbidden in BGP and not supported in
       * rt_notify_accepted().
       *
       * The condition is needed to eliminate spurious announcements where
       * both old and new routes are not valid (so they are NULL).
       */
      if (new != old)
	rt_notify_accepted(c, net, new, old, 0);
      break;

    case RA_MERGED:
      rt_notify_merged(c, net, new, old, new_best, old_best, 0);
      break;
    }
  }
}

static inline int
rte_validate(rte *e)
{
  int c;
  net *n = e->net;

  if (!net_validate(n->n.addr))
  {
    log(L_WARN "Ignoring bogus prefix %N received via %s",
	n->n.addr, e->sender->proto->name);
    return 0;
  }

  /* FIXME: better handling different nettypes */
  c = !net_is_flow(n->n.addr) ?
    net_classify(n->n.addr): (IADDR_HOST | SCOPE_UNIVERSE);
  if ((c < 0) || !(c & IADDR_HOST) || ((c & IADDR_SCOPE_MASK) <= SCOPE_LINK))
  {
    log(L_WARN "Ignoring bogus route %N received via %s",
	n->n.addr, e->sender->proto->name);
    return 0;
  }

  if (net_type_match(n->n.addr, NB_DEST) == !e->attrs->dest)
  {
    /* Exception for flowspec that failed validation */
    if (net_is_flow(n->n.addr) && (e->attrs->dest == RTD_UNREACHABLE))
      return 1;

    log(L_WARN "Ignoring route %N with invalid dest %d received via %s",
	n->n.addr, e->attrs->dest, e->sender->proto->name);
    return 0;
  }

  if ((e->attrs->dest == RTD_UNICAST) && !nexthop_is_sorted(&(e->attrs->nh)))
  {
    log(L_WARN "Ignoring unsorted multipath route %N received via %s",
	n->n.addr, e->sender->proto->name);
    return 0;
  }

  return 1;
}

/**
 * rte_free - delete a &rte
 * @e: &rte to be deleted
 *
 * rte_free() deletes the given &rte from the routing table it's linked to.
 */
void
rte_free(rte *e)
{
  rt_unlock_source(e->src);
  if (rta_is_cached(e->attrs))
    rta_free(e->attrs);
  sl_free(e);
}

static inline void
rte_free_quick(rte *e)
{
  rt_unlock_source(e->src);
  rta_free(e->attrs);
  sl_free(e);
}

int
rte_same(rte *x, rte *y)
{
  /* rte.flags / rte.pflags are not checked, as they are internal to rtable */
  return
    x->attrs == y->attrs &&
    x->src == y->src &&
    rte_is_filtered(x) == rte_is_filtered(y);
}

static inline int rte_is_ok(rte *e) { return e && !rte_is_filtered(e); }

static void
rte_recalculate(struct channel *c, net *net, rte *new, struct rte_src *src)
{
  struct proto *p = c->proto;
  struct rtable *table = c->table;
  struct proto_stats *stats = &c->stats;
  static struct tbf rl_pipe = TBF_DEFAULT_LOG_LIMITS;
  rte *before_old = NULL;
  rte *old_best = net->routes;
  rte *old = NULL;
  rte **k;

  k = &net->routes;			/* Find and remove original route from the same protocol */
  while (old = *k)
    {
      if (old->src == src)
	{
	  /* If there is the same route in the routing table but from
	   * a different sender, then there are two paths from the
	   * source protocol to this routing table through transparent
	   * pipes, which is not allowed.
	   *
	   * We log that and ignore the route. If it is withdraw, we
	   * ignore it completely (there might be 'spurious withdraws',
	   * see FIXME in do_rte_announce())
	   */
	  if (old->sender->proto != p)
	    {
	      if (new)
		{
		  log_rl(&rl_pipe, L_ERR "Pipe collision detected when sending %N to table %s",
		      net->n.addr, table->name);
		  rte_free_quick(new);
		}
	      return;
	    }

	  if (new && rte_same(old, new))
	    {
	      /* No changes, ignore the new route and refresh the old one */

	      old->flags &= ~(REF_STALE | REF_DISCARD | REF_MODIFY);

	      if (!rte_is_filtered(new))
		{
		  stats->imp_updates_ignored++;
		  rte_trace_in(D_ROUTES, c, new, "ignored");
		}

	      rte_free_quick(new);
	      return;
	    }
	  *k = old->next;
	  table->rt_count--;
	  break;
	}
      k = &old->next;
      before_old = old;
    }

  /* Save the last accessed position */
  rte **pos = k;

  if (!old)
    before_old = NULL;

  if (!old && !new)
    {
      stats->imp_withdraws_ignored++;
      return;
    }

  int new_ok = rte_is_ok(new);
  int old_ok = rte_is_ok(old);

  struct channel_limit *l = &c->rx_limit;
  if (l->action && !old && new && !c->in_table)
    {
      u32 all_routes = stats->imp_routes + stats->filt_routes;

      if (all_routes >= l->limit)
	channel_notify_limit(c, l, PLD_RX, all_routes);

      if (l->state == PLS_BLOCKED)
	{
	  /* In receive limit the situation is simple, old is NULL so
	     we just free new and exit like nothing happened */

	  stats->imp_updates_ignored++;
	  rte_trace_in(D_FILTERS, c, new, "ignored [limit]");
	  rte_free_quick(new);
	  return;
	}
    }

  l = &c->in_limit;
  if (l->action && !old_ok && new_ok)
    {
      if (stats->imp_routes >= l->limit)
	channel_notify_limit(c, l, PLD_IN, stats->imp_routes);

      if (l->state == PLS_BLOCKED)
	{
	  /* In import limit the situation is more complicated. We
	     shouldn't just drop the route, we should handle it like
	     it was filtered. We also have to continue the route
	     processing if old or new is non-NULL, but we should exit
	     if both are NULL as this case is probably assumed to be
	     already handled. */

	  stats->imp_updates_ignored++;
	  rte_trace_in(D_FILTERS, c, new, "ignored [limit]");

	  if (c->in_keep_filtered)
	    new->flags |= REF_FILTERED;
	  else
	    { rte_free_quick(new); new = NULL; }

	  /* Note that old && !new could be possible when
	     c->in_keep_filtered changed in the recent past. */

	  if (!old && !new)
	    return;

	  new_ok = 0;
	  goto skip_stats1;
	}
    }

  if (new_ok)
    stats->imp_updates_accepted++;
  else if (old_ok)
    stats->imp_withdraws_accepted++;
  else
    stats->imp_withdraws_ignored++;

  if (old_ok || new_ok)
    table->last_rt_change = current_time();

 skip_stats1:

  if (new)
    rte_is_filtered(new) ? stats->filt_routes++ : stats->imp_routes++;
  if (old)
    rte_is_filtered(old) ? stats->filt_routes-- : stats->imp_routes--;

  if (table->config->sorted)
    {
      /* If routes are sorted, just insert new route to appropriate position */
      if (new)
	{
	  if (before_old && !rte_better(new, before_old))
	    k = &before_old->next;
	  else
	    k = &net->routes;

	  for (; *k; k=&(*k)->next)
	    if (rte_better(new, *k))
	      break;

	  new->next = *k;
	  *k = new;

	  table->rt_count++;
	}
    }
  else
    {
      /* If routes are not sorted, find the best route and move it on
	 the first position. There are several optimized cases. */

      if (src->proto->rte_recalculate && src->proto->rte_recalculate(table, net, new, old, old_best))
	goto do_recalculate;

      if (new && rte_better(new, old_best))
	{
	  /* The first case - the new route is cleary optimal,
	     we link it at the first position */

	  new->next = net->routes;
	  net->routes = new;

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
	  if (new)
	    {
	      new->next = *pos;
	      *pos = new;

	      table->rt_count++;
	    }

	  /* Find a new optimal route (if there is any) */
	  if (net->routes)
	    {
	      rte **bp = &net->routes;
	      for (k=&(*bp)->next; *k; k=&(*k)->next)
		if (rte_better(*k, *bp))
		  bp = k;

	      /* And relink it */
	      rte *best = *bp;
	      *bp = best->next;
	      best->next = net->routes;
	      net->routes = best;
	    }
	}
      else if (new)
	{
	  /* The third case - the new route is not better than the old
	     best route (therefore old_best != NULL) and the old best
	     route was not removed (therefore old_best == net->routes).
	     We just link the new route to the old/last position. */

	  new->next = *pos;
	  *pos = new;

	  table->rt_count++;
	}
      /* The fourth (empty) case - suboptimal route was removed, nothing to do */
    }

  if (new)
    {
      new->lastmod = current_time();

      if (!old)
        {
	  new->id = hmap_first_zero(&table->id_map);
	  hmap_set(&table->id_map, new->id);
	}
      else
	new->id = old->id;
    }

  /* Log the route change */
  if ((c->debug & D_ROUTES) || (p->debug & D_ROUTES))
    {
      if (new_ok)
	rte_trace(c, new, '>', new == net->routes ? "added [best]" : "added");
      else if (old_ok)
	{
	  if (old != old_best)
	    rte_trace(c, old, '>', "removed");
	  else if (rte_is_ok(net->routes))
	    rte_trace(c, old, '>', "removed [replaced]");
	  else
	    rte_trace(c, old, '>', "removed [sole]");
	}
    }

  /* Propagate the route change */
  rte_announce(table, RA_UNDEF, net, new, old, net->routes, old_best);

  if (!net->routes &&
      (table->gc_counter++ >= table->config->gc_threshold))
    rt_kick_prune_timer(table);

  if (old_ok && p->rte_remove)
    p->rte_remove(net, old);
  if (new_ok && p->rte_insert)
    p->rte_insert(net, new);

  if (old)
    {
      if (!new)
	hmap_clear(&table->id_map, old->id);

      rte_free_quick(old);
    }
}

static int rte_update_nest_cnt;		/* Nesting counter to allow recursive updates */

static inline void
rte_update_lock(void)
{
  rte_update_nest_cnt++;
}

static inline void
rte_update_unlock(void)
{
  if (!--rte_update_nest_cnt)
    lp_flush(rte_update_pool);
}

/**
 * rte_update - enter a new update to a routing table
 * @table: table to be updated
 * @c: channel doing the update
 * @net: network node
 * @p: protocol submitting the update
 * @src: protocol originating the update
 * @new: a &rte representing the new route or %NULL for route removal.
 *
 * This function is called by the routing protocols whenever they discover
 * a new route or wish to update/remove an existing route. The right announcement
 * sequence is to build route attributes first (either un-cached with @aflags set
 * to zero or a cached one using rta_lookup(); in this case please note that
 * you need to increase the use count of the attributes yourself by calling
 * rta_clone()), call rte_get_temp() to obtain a temporary &rte, fill in all
 * the appropriate data and finally submit the new &rte by calling rte_update().
 *
 * @src specifies the protocol that originally created the route and the meaning
 * of protocol-dependent data of @new. If @new is not %NULL, @src have to be the
 * same value as @new->attrs->proto. @p specifies the protocol that called
 * rte_update(). In most cases it is the same protocol as @src. rte_update()
 * stores @p in @new->sender;
 *
 * When rte_update() gets any route, it automatically validates it (checks,
 * whether the network and next hop address are valid IP addresses and also
 * whether a normal routing protocol doesn't try to smuggle a host or link
 * scope route to the table), converts all protocol dependent attributes stored
 * in the &rte to temporary extended attributes, consults import filters of the
 * protocol to see if the route should be accepted and/or its attributes modified,
 * stores the temporary attributes back to the &rte.
 *
 * Now, having a "public" version of the route, we
 * automatically find any old route defined by the protocol @src
 * for network @n, replace it by the new one (or removing it if @new is %NULL),
 * recalculate the optimal route for this destination and finally broadcast
 * the change (if any) to all routing protocols by calling rte_announce().
 *
 * All memory used for attribute lists and other temporary allocations is taken
 * from a special linear pool @rte_update_pool and freed when rte_update()
 * finishes.
 */

void
rte_update2(struct channel *c, const net_addr *n, rte *new, struct rte_src *src)
{
  struct proto *p = c->proto;
  struct proto_stats *stats = &c->stats;
  const struct filter *filter = c->in_filter;
  struct mpls_fec *fec = NULL;
  net *nn;

  ASSERT(c->channel_state == CS_UP);

  rte_update_lock();
  if (new)
    {
      /* Create a temporary table node */
      nn = alloca(sizeof(net) + n->length);
      memset(nn, 0, sizeof(net) + n->length);
      net_copy(nn->n.addr, n);

      new->net = nn;
      new->sender = c;

      stats->imp_updates_received++;
      if (!rte_validate(new))
	{
	  rte_trace_in(D_FILTERS, c, new, "invalid");
	  stats->imp_updates_invalid++;
	  goto drop;
	}

      if (filter == FILTER_REJECT)
	{
	  stats->imp_updates_filtered++;
	  rte_trace_in(D_FILTERS, c, new, "filtered out");

	  if (! c->in_keep_filtered)
	    goto drop;

	  /* new is a private copy, i could modify it */
	  new->flags |= REF_FILTERED;
	}
      else if (filter)
	{
	  int fr = f_run(filter, &new, rte_update_pool, 0);
	  if (fr > F_ACCEPT)
	  {
	    stats->imp_updates_filtered++;
	    rte_trace_in(D_FILTERS, c, new, "filtered out");

	    if (! c->in_keep_filtered)
	      goto drop;

	    new->flags |= REF_FILTERED;
	  }
	}

      if (p->mpls_map)
        {
	  if (mpls_handle_rte(p->mpls_map, n, new, rte_update_pool, &fec) < 0)
	    {
	      rte_trace_in(D_FILTERS, c, new, "invalid");
	      stats->imp_updates_invalid++;
	      goto drop;
	    }
	}

      if (!rta_is_cached(new->attrs)) /* Need to copy attributes */
	new->attrs = rta_lookup(new->attrs);
      new->flags |= REF_COW;

      /* Use the actual struct network, not the dummy one */
      nn = net_get(c->table, n);
      new->net = nn;
    }
  else
    {
      stats->imp_withdraws_received++;

      if (!(nn = net_find(c->table, n)) || !src)
	{
	  stats->imp_withdraws_ignored++;
	  rte_update_unlock();
	  return;
	}
    }

 recalc:
  /* And recalculate the best route */
  rte_recalculate(c, nn, new, src);

  if (p->mpls_map)
    mpls_handle_rte_cleanup(p->mpls_map, &fec);

  rte_update_unlock();
  return;

 drop:
  rte_free(new);
  new = NULL;
  if (nn = net_find(c->table, n))
    goto recalc;

  rte_update_unlock();
}

/* Independent call to rte_announce(), used from next hop
   recalculation, outside of rte_update(). new must be non-NULL */
static inline void
rte_announce_i(rtable *tab, uint type, net *net, rte *new, rte *old,
	       rte *new_best, rte *old_best)
{
  rte_update_lock();
  rte_announce(tab, type, net, new, old, new_best, old_best);
  rte_update_unlock();
}

static inline void
rte_discard(rte *old)	/* Non-filtered route deletion, used during garbage collection */
{
  rte_update_lock();
  rte_recalculate(old->sender, old->net, NULL, old->src);
  rte_update_unlock();
}

/* Modify existing route by protocol hook, used for long-lived graceful restart */
static inline void
rte_modify(rte *old)
{
  rte_update_lock();

  rte *new = old->sender->proto->rte_modify(old, rte_update_pool);
  if (new != old)
  {
    if (new)
    {
      if (!rta_is_cached(new->attrs))
	new->attrs = rta_lookup(new->attrs);
      new->flags = (old->flags & ~REF_MODIFY) | REF_COW;
    }

    rte_recalculate(old->sender, old->net, new, old->src);
  }

  rte_update_unlock();
}

/* Check rtable for best route to given net whether it would be exported do p */
int
rt_examine(rtable *t, net_addr *a, struct channel *c, const struct filter *filter)
{
  struct proto *p = c->proto;
  net *n = net_find(t, a);
  rte *rt = n ? n->routes : NULL;

  if (!rte_is_valid(rt))
    return 0;

  rte_update_lock();

  /* Rest is stripped down export_filter() */
  int v = p->preexport ? p->preexport(c, rt) : 0;
  if (v == RIC_PROCESS)
    v = (f_run(filter, &rt, rte_update_pool, FF_SILENT) <= F_ACCEPT);

  /* Discard temporary rte */
  if (rt != n->routes)
    rte_free(rt);

  rte_update_unlock();

  return v > 0;
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
rt_refresh_begin(rtable *t, struct channel *c)
{
  FIB_WALK(&t->fib, net, n)
    {
      rte *e;
      for (e = n->routes; e; e = e->next)
	if (e->sender == c)
	  e->flags |= REF_STALE;
    }
  FIB_WALK_END;
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
rt_refresh_end(rtable *t, struct channel *c)
{
  int prune = 0;

  FIB_WALK(&t->fib, net, n)
    {
      rte *e;
      for (e = n->routes; e; e = e->next)
	if ((e->sender == c) && (e->flags & REF_STALE))
	  {
	    e->flags |= REF_DISCARD;
	    prune = 1;
	  }
    }
  FIB_WALK_END;

  if (prune)
    rt_schedule_prune(t);
}

void
rt_modify_stale(rtable *t, struct channel *c)
{
  int prune = 0;

  FIB_WALK(&t->fib, net, n)
    {
      rte *e;
      for (e = n->routes; e; e = e->next)
	if ((e->sender == c) && (e->flags & REF_STALE) && !(e->flags & REF_FILTERED))
	  {
	    e->flags |= REF_MODIFY;
	    prune = 1;
	  }
    }
  FIB_WALK_END;

  if (prune)
    rt_schedule_prune(t);
}

/**
 * rte_dump - dump a route
 * @e: &rte to be dumped
 *
 * This functions dumps contents of a &rte to debug output.
 */
void
rte_dump(rte *e)
{
  net *n = e->net;
  debug("%-1N ", n->n.addr);
  debug("PF=%02x ", e->pflags);
  rta_dump(e->attrs);
  debug("\n");
}

/**
 * rt_dump - dump a routing table
 * @t: routing table to be dumped
 *
 * This function dumps contents of a given routing table to debug output.
 */
void
rt_dump(rtable *t)
{
  debug("Dump of routing table <%s>\n", t->name);
#ifdef DEBUGGING
  fib_check(&t->fib);
#endif
  FIB_WALK(&t->fib, net, n)
    {
      rte *e;
      for(e=n->routes; e; e=e->next)
	rte_dump(e);
    }
  FIB_WALK_END;
  debug("\n");
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
}

static inline void
rt_schedule_hcu(rtable *tab)
{
  if (tab->hcu_scheduled)
    return;

  tab->hcu_scheduled = 1;
  ev_schedule(tab->rt_event);
}

static inline void
rt_schedule_nhu(rtable *tab)
{
  if (tab->nhu_state == NHU_CLEAN)
    ev_schedule(tab->rt_event);

  /* state change:
   *   NHU_CLEAN   -> NHU_SCHEDULED
   *   NHU_RUNNING -> NHU_DIRTY
   */
  tab->nhu_state |= NHU_SCHEDULED;
}

void
rt_schedule_prune(rtable *tab)
{
  if (tab->prune_state == 0)
    ev_schedule(tab->rt_event);

  /* state change 0->1, 2->3 */
  tab->prune_state |= 1;
}


static void
rt_event(void *ptr)
{
  rtable *tab = ptr;

  rt_lock_table(tab);

  if (tab->hcu_scheduled)
    rt_update_hostcache(tab);

  if (tab->nhu_state)
    rt_next_hop_update(tab);

  if (tab->prune_state)
    rt_prune_table(tab);

  rt_unlock_table(tab);
}


static void
rt_prune_timer(timer *t)
{
  rtable *tab = t->data;

  if (tab->gc_counter >= tab->config->gc_threshold)
    rt_schedule_prune(tab);
}

static void
rt_kick_prune_timer(rtable *tab)
{
  /* Return if prune is already scheduled */
  if (tm_active(tab->prune_timer) || (tab->prune_state & 1))
    return;

  /* Randomize GC period to +/- 50% */
  btime gc_period = tab->config->gc_period;
  gc_period = (gc_period / 2) + (random_u32() % (uint) gc_period);
  tm_start(tab->prune_timer, gc_period);
}


static inline btime
rt_settled_time(rtable *tab)
{
  ASSUME(tab->base_settle_time != 0);

  return MIN(tab->last_rt_change + tab->config->min_settle_time,
	     tab->base_settle_time + tab->config->max_settle_time);
}

static void
rt_settle_timer(timer *t)
{
  rtable *tab = t->data;

  if (!tab->base_settle_time)
    return;

  btime settled_time = rt_settled_time(tab);
  if (current_time() < settled_time)
  {
    tm_set(tab->settle_timer, settled_time);
    return;
  }

  /* Settled */
  tab->base_settle_time = 0;

  struct rt_subscription *s;
  WALK_LIST(s, tab->subscribers)
    s->hook(s);
}

static void
rt_kick_settle_timer(rtable *tab)
{
  tab->base_settle_time = current_time();

  if (!tab->settle_timer)
    tab->settle_timer = tm_new_init(tab->rp, rt_settle_timer, tab, 0, 0);

  if (!tm_active(tab->settle_timer))
    tm_set(tab->settle_timer, rt_settled_time(tab));
}

static inline void
rt_schedule_notify(rtable *tab)
{
  if (EMPTY_LIST(tab->subscribers))
    return;

  if (tab->base_settle_time)
    return;

  rt_kick_settle_timer(tab);
}

void
rt_subscribe(rtable *tab, struct rt_subscription *s)
{
  s->tab = tab;
  rt_lock_table(tab);
  add_tail(&tab->subscribers, &s->n);
}

void
rt_unsubscribe(struct rt_subscription *s)
{
  rem_node(&s->n);
  rt_unlock_table(s->tab);
}

static struct rt_flowspec_link *
rt_flowspec_find_link(rtable *src, rtable *dst)
{
  struct rt_flowspec_link *ln;
  WALK_LIST(ln, src->flowspec_links)
    if ((ln->src == src) && (ln->dst == dst))
      return ln;

  return NULL;
}

void
rt_flowspec_link(rtable *src, rtable *dst)
{
  ASSERT(rt_is_ip(src));
  ASSERT(rt_is_flow(dst));

  struct rt_flowspec_link *ln = rt_flowspec_find_link(src, dst);

  if (!ln)
  {
    rt_lock_table(src);
    rt_lock_table(dst);

    ln = mb_allocz(src->rp, sizeof(struct rt_flowspec_link));
    ln->src = src;
    ln->dst = dst;
    add_tail(&src->flowspec_links, &ln->n);
  }

  ln->uc++;
}

void
rt_flowspec_unlink(rtable *src, rtable *dst)
{
  struct rt_flowspec_link *ln = rt_flowspec_find_link(src, dst);

  ASSERT(ln && (ln->uc > 0));

  ln->uc--;

  if (!ln->uc)
  {
    rem_node(&ln->n);
    mb_free(ln);

    rt_unlock_table(src);
    rt_unlock_table(dst);
  }
}

static void
rt_flowspec_notify(rtable *src, net *net)
{
  /* Only IP tables are src links */
  ASSERT(rt_is_ip(src));

  struct rt_flowspec_link *ln;
  WALK_LIST(ln, src->flowspec_links)
  {
    rtable *dst = ln->dst;
    ASSERT(rt_is_flow(dst));

    /* No need to inspect it further if recalculation is already active */
    if ((dst->nhu_state == NHU_SCHEDULED) || (dst->nhu_state == NHU_DIRTY))
      continue;

    if (trie_match_net(dst->flowspec_trie, net->n.addr))
      rt_schedule_nhu(dst);
  }
}

static void
rt_flowspec_reset_trie(rtable *tab)
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
  rtable *r = (rtable *) _r;

  DBG("Deleting routing table %s\n", r->name);
  ASSERT_DIE(r->use_count == 0);

  if (r->internal)
    return;

  r->config->table = NULL;
  rem_node(&r->n);

  if (r->hostcache)
    rt_free_hostcache(r);

  /* Freed automagically by the resource pool
  fib_free(&r->fib);
  hmap_free(&r->id_map);
  rfree(r->rt_event);
  rfree(r->settle_timer);
  mb_free(r);
  */
}

static void
rt_res_dump(resource *_r)
{
  rtable *r = (rtable *) _r;
  debug("name \"%s\", addr_type=%s, rt_count=%u, use_count=%d\n",
      r->name, net_label[r->addr_type], r->rt_count, r->use_count);
}

static struct resclass rt_class = {
  .name = "Routing table",
  .size = sizeof(struct rtable),
  .free = rt_free,
  .dump = rt_res_dump,
  .lookup = NULL,
  .memsize = NULL,
};

rtable *
rt_setup(pool *pp, struct rtable_config *cf)
{
  pool *p = rp_newf(pp, "Routing table %s", cf->name);

  rtable *t = ralloc(p, &rt_class);
  t->rp = p;

  t->name = cf->name;
  t->config = cf;
  t->addr_type = cf->addr_type;

  fib_init(&t->fib, p, t->addr_type, sizeof(net), OFFSETOF(net, n), 0, NULL);

  if (cf->trie_used)
  {
    t->trie = f_new_trie(lp_new_default(p), 0);
    t->trie->ipv4 = net_val_match(t->addr_type, NB_IP4 | NB_VPN4 | NB_ROA4);

    t->fib.init = net_init_with_trie;
  }

  init_list(&t->channels);
  init_list(&t->flowspec_links);
  init_list(&t->subscribers);

  hmap_init(&t->id_map, p, 1024);
  hmap_set(&t->id_map, 0);

  if (!(t->internal = cf->internal))
  {
    t->rt_event = ev_new_init(p, rt_event, t);
    t->prune_timer = tm_new_init(p, rt_prune_timer, t, 0, 0);
    t->last_rt_change = t->gc_time = current_time();

    if (rt_is_flow(t))
    {
      t->flowspec_trie = f_new_trie(lp_new_default(p), 0);
      t->flowspec_trie->ipv4 = (t->addr_type == NET_FLOW4);
    }
  }

  return t;
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
  rte_update_pool = lp_new_default(rt_table_pool);
  rte_slab = sl_new(rt_table_pool, sizeof(rte));
  init_list(&routing_tables);
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
rt_prune_table(rtable *tab)
{
  struct fib_iterator *fit = &tab->prune_fit;
  int limit = 2000;

  struct channel *c;
  node *n, *x;

  DBG("Pruning route table %s\n", tab->name);
#ifdef DEBUGGING
  fib_check(&tab->fib);
#endif

  if (tab->prune_state == 0)
    return;

  if (tab->prune_state == 1)
  {
    /* Mark channels to flush */
    WALK_LIST2(c, n, tab->channels, table_node)
      if (c->channel_state == CS_FLUSHING)
	c->flush_active = 1;

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
      rte *e;

    rescan:
      if (limit <= 0)
      {
	FIB_ITERATE_PUT(fit);
	ev_schedule(tab->rt_event);
	return;
      }

      for (e=n->routes; e; e=e->next)
      {
	if (e->sender->flush_active || (e->flags & REF_DISCARD))
	  {
	    rte_discard(e);
	    limit--;

	    goto rescan;
	  }

	if (e->flags & REF_MODIFY)
	  {
	    rte_modify(e);
	    limit--;

	    goto rescan;
	  }
      }

      if (!n->routes)		/* Orphaned FIB entry */
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

#ifdef DEBUGGING
  fib_check(&tab->fib);
#endif

  /* state change 2->0, 3->1 */
  tab->prune_state &= 1;

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

  if (tab->prune_state > 0)
    ev_schedule(tab->rt_event);

  /* FIXME: This should be handled in a better way */
  rt_prune_sources();

  /* Close flushed channels */
  WALK_LIST2_DELSAFE(c, n, x, tab->channels, table_node)
    if (c->flush_active)
      {
	c->flush_active = 0;
	channel_set_state(c, CS_DOWN);
      }

  return;
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
rt_lock_trie(rtable *tab)
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
rt_unlock_trie(rtable *tab, struct f_trie *trie)
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
	rt_schedule_prune(tab);
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

  rt_new_table(cf_get_symbol(c, "master4"), NET_IP4);
  rt_new_table(cf_get_symbol(c, "master6"), NET_IP6);
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
}


/*
 * Some functions for handing internal next hop updates
 * triggered by rt_schedule_nhu().
 */

void
rta_apply_hostentry(rta *a, struct hostentry *he, mpls_label_stack *mls)
{
  a->hostentry = he;
  a->dest = he->dest;
  a->igp_metric = he->igp_metric;

  if (a->dest != RTD_UNICAST)
  {
    /* No nexthop */
no_nexthop:
    a->nh = (struct nexthop) {};
    if (mls)
    { /* Store the label stack for later changes */
      a->nh.labels_orig = a->nh.labels = mls->len;
      memcpy(a->nh.label, mls->stack, mls->len * sizeof(u32));
    }
    return;
  }

  if (((!mls) || (!mls->len)) && he->nexthop_linkable)
  { /* Just link the nexthop chain, no label append happens. */
    memcpy(&(a->nh), &(he->src->nh), nexthop_size(&(he->src->nh)));
    return;
  }

  struct nexthop *nhp = NULL, *nhr = NULL;
  int skip_nexthop = 0;

  for (struct nexthop *nh = &(he->src->nh); nh; nh = nh->next)
  {
    if (skip_nexthop)
      skip_nexthop--;
    else
    {
      nhr = nhp;
      nhp = (nhp ? (nhp->next = lp_alloc(rte_update_pool, NEXTHOP_MAX_SIZE)) : &(a->nh));
    }

    memset(nhp, 0, NEXTHOP_MAX_SIZE);
    nhp->iface = nh->iface;
    nhp->weight = nh->weight;

    if (mls)
    {
      nhp->labels = nh->labels + mls->len;
      nhp->labels_orig = mls->len;
      if (nhp->labels <= MPLS_MAX_LABEL_STACK)
      {
	memcpy(nhp->label, nh->label, nh->labels * sizeof(u32)); /* First the hostentry labels */
	memcpy(&(nhp->label[nh->labels]), mls->stack, mls->len * sizeof(u32)); /* Then the bottom labels */
      }
      else
      {
	log(L_WARN "Sum of label stack sizes %d + %d = %d exceedes allowed maximum (%d)",
	    nh->labels, mls->len, nhp->labels, MPLS_MAX_LABEL_STACK);
	skip_nexthop++;
	continue;
      }
    }
    else if (nh->labels)
    {
      nhp->labels = nh->labels;
      nhp->labels_orig = 0;
      memcpy(nhp->label, nh->label, nh->labels * sizeof(u32));
    }

    if (ipa_nonzero(nh->gw))
    {
      nhp->gw = nh->gw;			/* Router nexthop */
      nhp->flags |= (nh->flags & RNF_ONLINK);
    }
    else if (!(nh->iface->flags & IF_MULTIACCESS) || (nh->iface->flags & IF_LOOPBACK))
      nhp->gw = IPA_NONE;		/* PtP link - no need for nexthop */
    else if (ipa_nonzero(he->link))
      nhp->gw = he->link;		/* Device nexthop with link-local address known */
    else
      nhp->gw = he->addr;		/* Device nexthop with link-local address unknown */
  }

  if (skip_nexthop)
    if (nhr)
      nhr->next = NULL;
    else
    {
      a->dest = RTD_UNREACHABLE;
      log(L_WARN "No valid nexthop remaining, setting route unreachable");
      goto no_nexthop;
    }
}

static inline int
rta_next_hop_outdated(rta *a)
{
  struct hostentry *he = a->hostentry;

  if (!he)
    return 0;

  if (!he->src)
    return a->dest != RTD_UNREACHABLE;

  return (a->dest != he->dest) || (a->igp_metric != he->igp_metric) ||
    (!he->nexthop_linkable) || !nexthop_same(&(a->nh), &(he->src->nh));
}

static inline rte *
rt_next_hop_update_rte(rtable *tab UNUSED, rte *old)
{
  if (!rta_next_hop_outdated(old->attrs))
    return NULL;

  rta *a = alloca(RTA_MAX_SIZE);
  memcpy(a, old->attrs, rta_size(old->attrs));

  mpls_label_stack mls = { .len = a->nh.labels_orig };
  memcpy(mls.stack, &a->nh.label[a->nh.labels - mls.len], mls.len * sizeof(u32));

  rta_apply_hostentry(a, old->attrs->hostentry, &mls);
  a->cached = 0;

  rte *e = sl_alloc(rte_slab);
  memcpy(e, old, sizeof(rte));
  e->attrs = rta_lookup(a);
  rt_lock_source(e->src);

  return e;
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
rta_as_path_is_empty(rta *a)
{
  eattr *e = ea_find(a->eattrs, EA_CODE(PROTOCOL_BGP, BA_AS_PATH));
  return !e || (as_path_getlen(e->u.ptr) == 0);
}

static inline u32
rta_get_first_asn(rta *a)
{
  eattr *e = ea_find(a->eattrs, EA_CODE(PROTOCOL_BGP, BA_AS_PATH));
  u32 asn;

  return (e && as_path_get_first_regular(e->u.ptr, &asn)) ? asn : 0;
}

int
rt_flowspec_check(rtable *tab_ip, rtable *tab_flow, const net_addr *n, rta *a, int interior)
{
  ASSERT(rt_is_ip(tab_ip));
  ASSERT(rt_is_flow(tab_flow));
  ASSERT(tab_ip->trie);

  /* RFC 8955 6. a) Flowspec has defined dst prefix */
  if (!net_flow_has_dst_prefix(n))
    return 0;

  /* RFC 9117 4.1. Accept  AS_PATH is empty (fr */
  if (interior && rta_as_path_is_empty(a))
    return 1;


  /* RFC 8955 6. b) Flowspec and its best-match route have the same originator */

  /* Find flowspec dst prefix */
  net_addr dst;
  if (n->type == NET_FLOW4)
    net_fill_ip4(&dst, net4_prefix(n), net4_pxlen(n));
  else
    net_fill_ip6(&dst, net6_prefix(n), net6_pxlen(n));

  /* Find best-match BGP unicast route for flowspec dst prefix */
  net *nb = net_route(tab_ip, &dst);
  rte *rb = nb ? nb->routes : NULL;

  /* Register prefix to trie for tracking further changes */
  int max_pxlen = (n->type == NET_FLOW4) ? IP4_MAX_PREFIX_LENGTH : IP6_MAX_PREFIX_LENGTH;
  trie_add_prefix(tab_flow->flowspec_trie, &dst, (nb ? nb->n.addr->pxlen : 0), max_pxlen);

  /* No best-match BGP route -> no flowspec */
  if (!rb || (rb->attrs->source != RTS_BGP))
    return 0;

  /* Find ORIGINATOR_ID values */
  u32 orig_a = ea_get_int(a->eattrs, EA_CODE(PROTOCOL_BGP, BA_ORIGINATOR_ID), 0);
  u32 orig_b = ea_get_int(rb->attrs->eattrs, EA_CODE(PROTOCOL_BGP, BA_ORIGINATOR_ID), 0);

  /* Originator is either ORIGINATOR_ID (if present), or BGP neighbor address (if not) */
  if ((orig_a != orig_b) || (!orig_a && !orig_b && !ipa_equal(a->from, rb->attrs->from)))
    return 0;


  /* Find ASN of the best-match route, for use in next checks */
  u32 asn_b = rta_get_first_asn(rb->attrs);
  if (!asn_b)
    return 0;

  /* RFC 9117 4.2. For EBGP, flowspec and its best-match route are from the same AS */
  if (!interior && (rta_get_first_asn(a) != asn_b))
    return 0;

  /* RFC 8955 6. c) More-specific routes are from the same AS as the best-match route */
  TRIE_WALK(tab_ip->trie, subnet, &dst)
  {
    net *nc = net_find_valid(tab_ip, &subnet);
    if (!nc)
      continue;

    rte *rc = nc->routes;
    if (rc->attrs->source != RTS_BGP)
      return 0;

    if (rta_get_first_asn(rc->attrs) != asn_b)
      return 0;
  }
  TRIE_WALK_END;

  return 1;
}

#endif /* CONFIG_BGP */

static rte *
rt_flowspec_update_rte(rtable *tab, rte *r)
{
#ifdef CONFIG_BGP
  if ((r->attrs->source != RTS_BGP) || (r->sender->proto != r->src->proto))
    return NULL;

  struct bgp_channel *bc = (struct bgp_channel *) r->sender;
  if (!bc->base_table)
    return NULL;

  const net_addr *n = r->net->n.addr;
  struct bgp_proto *p = (void *) r->src->proto;
  int valid = rt_flowspec_check(bc->base_table, tab, n, r->attrs, p->is_interior);
  int dest = valid ? RTD_NONE : RTD_UNREACHABLE;

  if (dest == r->attrs->dest)
    return NULL;

  rta *a = alloca(RTA_MAX_SIZE);
  memcpy(a, r->attrs, rta_size(r->attrs));
  a->dest = dest;
  a->cached = 0;

  rte *new = sl_alloc(rte_slab);
  memcpy(new, r, sizeof(rte));
  new->attrs = rta_lookup(a);
  rt_lock_source(new->src);

  return new;
#else
  return NULL;
#endif
}


static inline int
rt_next_hop_update_net(rtable *tab, net *n)
{
  rte **k, *e, *new, *old_best, **new_best;
  int count = 0;
  int free_old_best = 0;

  old_best = n->routes;
  if (!old_best)
    return 0;

  for (k = &n->routes; e = *k; k = &e->next)
  {
    if (!net_is_flow(n->n.addr))
      new = rt_next_hop_update_rte(tab, e);
    else
      new = rt_flowspec_update_rte(tab, e);

    if (new)
      {
	*k = new;

	rte_trace_in(D_ROUTES, new->sender, new, "updated");
	rte_announce_i(tab, RA_ANY, n, new, e, NULL, NULL);

	/* Call a pre-comparison hook */
	/* Not really an efficient way to compute this */
	if (e->src->proto->rte_recalculate)
	  e->src->proto->rte_recalculate(tab, n, new, e, NULL);

	if (e != old_best)
	  rte_free_quick(e);
	else /* Freeing of the old best rte is postponed */
	  free_old_best = 1;

	e = new;
	count++;
      }
  }

  if (!count)
    return 0;

  /* Find the new best route */
  new_best = NULL;
  for (k = &n->routes; e = *k; k = &e->next)
    {
      if (!new_best || rte_better(e, *new_best))
	new_best = k;
    }

  /* Relink the new best route to the first position */
  new = *new_best;
  if (new != n->routes)
    {
      *new_best = new->next;
      new->next = n->routes;
      n->routes = new;
    }

  /* Announce the new best route */
  if (new != old_best)
    rte_trace_in(D_ROUTES, new->sender, new, "updated [best]");

  /* Propagate changes */
  rte_announce_i(tab, RA_UNDEF, n, NULL, NULL, n->routes, old_best);

  if (free_old_best)
    rte_free_quick(old_best);

  return count;
}

static void
rt_next_hop_update(rtable *tab)
{
  struct fib_iterator *fit = &tab->nhu_fit;
  int max_feed = 32;

  if (tab->nhu_state == NHU_CLEAN)
    return;

  if (tab->nhu_state == NHU_SCHEDULED)
    {
      FIB_ITERATE_INIT(fit, &tab->fib);
      tab->nhu_state = NHU_RUNNING;

      if (tab->flowspec_trie)
	rt_flowspec_reset_trie(tab);
    }

  FIB_ITERATE_START(&tab->fib, fit, net, n)
    {
      if (max_feed <= 0)
	{
	  FIB_ITERATE_PUT(fit);
	  ev_schedule(tab->rt_event);
	  return;
	}
      max_feed -= rt_next_hop_update_net(tab, n);
    }
  FIB_ITERATE_END;

  /* State change:
   *   NHU_DIRTY   -> NHU_SCHEDULED
   *   NHU_RUNNING -> NHU_CLEAN
   */
  tab->nhu_state &= 1;

  if (tab->nhu_state != NHU_CLEAN)
    ev_schedule(tab->rt_event);
}


struct rtable_config *
rt_new_table(struct symbol *s, uint addr_type)
{
  /* Hack that allows to 'redefine' the master table */
  if ((s->class == SYM_TABLE) &&
      (s->table == new_config->def_tables[addr_type]) &&
      ((addr_type == NET_IP4) || (addr_type == NET_IP6)))
    return s->table;

  struct rtable_config *c = cfg_allocz(sizeof(struct rtable_config));

  cf_define_symbol(new_config, s, SYM_TABLE, table, c);
  c->name = s->name;
  c->addr_type = addr_type;
  c->gc_threshold = 1000;
  c->gc_period = (uint) -1;	/* set in rt_postconfig() */
  c->min_settle_time = 1 S;
  c->max_settle_time = 20 S;

  add_tail(&new_config->tables, &c->n);

  /* First table of each type is kept as default */
  if (! new_config->def_tables[addr_type])
    new_config->def_tables[addr_type] = c;

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
rt_lock_table(rtable *r)
{
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
rt_unlock_table(rtable *r)
{
  if (!--r->use_count && r->deleted)
    {
      struct config *conf = r->deleted;

      /* Delete the routing table by freeing its pool */
      rt_shutdown(r);
      config_del_obstacle(conf);
    }
}

static int
rt_reconfigure(rtable *tab, struct rtable_config *new, struct rtable_config *old)
{
  if ((new->addr_type != old->addr_type) ||
      (new->sorted != old->sorted) ||
      (new->trie_used != old->trie_used))
    return 0;

  DBG("\t%s: same\n", new->name);
  new->table = tab;
  tab->name = new->name;
  tab->config = new;

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
	  rtable *tab = o->table;
	  if (tab->deleted)
	    continue;

	  r = rt_find_table_config(new, o->name);
	  if (r && !new->shutdown && rt_reconfigure(tab, r, o))
	    continue;

	  DBG("\t%s: deleted\n", o->name);
	  tab->deleted = old;
	  config_add_obstacle(old);
	  rt_lock_table(tab);
	  rt_unlock_table(tab);
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

static inline void
do_feed_channel(struct channel *c, net *n, rte *e)
{
  rte_update_lock();
  if (c->ra_mode == RA_ACCEPTED)
    rt_notify_accepted(c, n, NULL, NULL, c->refeeding);
  else if (c->ra_mode == RA_MERGED)
    rt_notify_merged(c, n, NULL, NULL, e, e, c->refeeding);
  else /* RA_BASIC */
    rt_notify_basic(c, n, e, e, c->refeeding);
  rte_update_unlock();
}

/**
 * rt_feed_channel - advertise all routes to a channel
 * @c: channel to be fed
 *
 * This function performs one pass of advertisement of routes to a channel that
 * is in the ES_FEEDING state. It is called by the protocol code as long as it
 * has something to do. (We avoid transferring all the routes in single pass in
 * order not to monopolize CPU time.)
 */
int
rt_feed_channel(struct channel *c)
{
  struct fib_iterator *fit = &c->feed_fit;
  int max_feed = 256;

  ASSERT(c->export_state == ES_FEEDING);

  if (!c->feed_active)
    {
      FIB_ITERATE_INIT(fit, &c->table->fib);
      c->feed_active = 1;
    }

  FIB_ITERATE_START(&c->table->fib, fit, net, n)
    {
      rte *e = n->routes;
      if (max_feed <= 0)
	{
	  FIB_ITERATE_PUT(fit);
	  return 0;
	}

      if ((c->ra_mode == RA_OPTIMAL) ||
	  (c->ra_mode == RA_ACCEPTED) ||
	  (c->ra_mode == RA_MERGED))
	if (rte_is_valid(e))
	  {
	    /* In the meantime, the protocol may fell down */
	    if (c->export_state != ES_FEEDING)
	      goto done;

	    do_feed_channel(c, n, e);
	    max_feed--;
	  }

      if (c->ra_mode == RA_ANY)
	for(e = n->routes; e; e = e->next)
	  {
	    /* In the meantime, the protocol may fell down */
	    if (c->export_state != ES_FEEDING)
	      goto done;

	    if (!rte_is_valid(e))
	      continue;

	    do_feed_channel(c, n, e);
	    max_feed--;
	  }
    }
  FIB_ITERATE_END;

done:
  c->feed_active = 0;
  return 1;
}

/**
 * rt_feed_baby_abort - abort protocol feeding
 * @c: channel
 *
 * This function is called by the protocol code when the protocol stops or
 * ceases to exist during the feeding.
 */
void
rt_feed_channel_abort(struct channel *c)
{
  if (c->feed_active)
    {
      /* Unlink the iterator */
      fit_get(&c->table->fib, &c->feed_fit);
      c->feed_active = 0;
    }
}


/*
 *	Import table
 */

int
rte_update_in(struct channel *c, const net_addr *n, rte *new, struct rte_src *src)
{
  struct rtable *tab = c->in_table;
  rte *old, **pos;
  net *net;

  if (new)
  {
    net = net_get(tab, n);

    if (!rta_is_cached(new->attrs))
      new->attrs = rta_lookup(new->attrs);
  }
  else
  {
    net = net_find(tab, n);

    if (!net)
      goto drop_withdraw;
  }

  /* Find the old rte */
  for (pos = &net->routes; old = *pos; pos = &old->next)
    if (old->src == src)
    {
      if (new && rte_same(old, new))
      {
	/* Refresh the old rte, continue with update to main rtable */
	if (old->flags & (REF_STALE | REF_DISCARD | REF_MODIFY))
	{
	  old->flags &= ~(REF_STALE | REF_DISCARD | REF_MODIFY);

	  return 1;
	}

	goto drop_update;
      }

      /* Move iterator if needed */
      if (old == c->reload_next_rte)
	c->reload_next_rte = old->next;

      /* Remove the old rte */
      *pos = old->next;
      tab->rt_count--;
      break;
    }

  if (!old && !new)
    goto drop_withdraw;

  struct channel_limit *l = &c->rx_limit;
  if (l->action && !old && new)
  {
    if (tab->rt_count >= l->limit)
      channel_notify_limit(c, l, PLD_RX, tab->rt_count);

    if (l->state == PLS_BLOCKED)
    {
      /* Required by rte_trace_in() */
      new->net = net;

      rte_trace_in(D_FILTERS, c, new, "ignored [limit]");
      goto drop_update;
    }
  }

  if (new)
  {
    /* Insert the new rte */
    rte *e = rte_do_cow(new);
    e->flags |= REF_COW;
    e->net = net;
    e->sender = c;
    e->lastmod = current_time();
    e->next = *pos;
    *pos = new = e;
    tab->rt_count++;

    if (!old)
    {
      new->id = hmap_first_zero(&tab->id_map);
      hmap_set(&tab->id_map, new->id);
    }
    else
      new->id = old->id;
  }

  rte_announce(tab, RA_ANY, net, new, old, NULL, NULL);

  if (old)
  {
    if (!new)
      hmap_clear(&tab->id_map, old->id);

    rte_free_quick(old);
  }

  if (!net->routes)
    fib_delete(&tab->fib, net);

  return 1;

drop_update:
  c->stats.imp_updates_received++;
  c->stats.imp_updates_ignored++;
  rte_free(new);

  if (!net->routes)
    fib_delete(&tab->fib, net);

  return 0;

drop_withdraw:
  c->stats.imp_withdraws_received++;
  c->stats.imp_withdraws_ignored++;
  return 0;
}

int
rt_reload_channel(struct channel *c)
{
  struct rtable *tab = c->in_table;
  struct fib_iterator *fit = &c->reload_fit;
  int max_feed = 64;

  ASSERT(c->channel_state == CS_UP);

  if (!c->reload_active)
  {
    FIB_ITERATE_INIT(fit, &tab->fib);
    c->reload_active = 1;
  }

  do {
    for (rte *e = c->reload_next_rte; e; e = e->next)
    {
      if (max_feed-- <= 0)
      {
	c->reload_next_rte = e;
	debug("%s channel reload burst split (max_feed=%d)", c->proto->name, max_feed);
	return 0;
      }

      rte_update2(c, e->net->n.addr, rte_do_cow(e), e->src);
    }

    c->reload_next_rte = NULL;

    FIB_ITERATE_START(&tab->fib, fit, net, n)
    {
      if (c->reload_next_rte = n->routes)
      {
	FIB_ITERATE_PUT_NEXT(fit, &tab->fib);
	break;
      }
    }
    FIB_ITERATE_END;
  }
  while (c->reload_next_rte);

  c->reload_active = 0;
  return 1;
}

void
rt_reload_channel_abort(struct channel *c)
{
  if (c->reload_active)
  {
    /* Unlink the iterator */
    fit_get(&c->in_table->fib, &c->reload_fit);
    c->reload_next_rte = NULL;
    c->reload_active = 0;
  }
}

void
rt_prune_sync(rtable *t, int all)
{
  struct fib_iterator fit;

  FIB_ITERATE_INIT(&fit, &t->fib);

again:
  FIB_ITERATE_START(&t->fib, &fit, net, n)
  {
    rte *e, **ee = &n->routes;

    while (e = *ee)
    {
      if (all || (e->flags & (REF_STALE | REF_DISCARD)))
      {
	*ee = e->next;
	rte_free_quick(e);
	t->rt_count--;
      }
      else
	ee = &e->next;
    }

    if (all || !n->routes)
    {
      FIB_ITERATE_PUT(&fit);
      fib_delete(&t->fib, n);
      goto again;
    }
  }
  FIB_ITERATE_END;
}


/*
 *	Export table
 */

int
rte_update_out(struct channel *c, const net_addr *n, rte *new, rte *old0, int refeed)
{
  struct rtable *tab = c->out_table;
  struct rte_src *src;
  rte *old, **pos;
  net *net;

  if (new)
  {
    net = net_get(tab, n);
    src = new->src;

    if (!rta_is_cached(new->attrs))
      new->attrs = rta_lookup(new->attrs);
  }
  else
  {
    net = net_find(tab, n);
    src = old0->src;

    if (!net)
      goto drop_withdraw;
  }

  /* Find the old rte */
  for (pos = &net->routes; old = *pos; pos = &old->next)
    if ((c->ra_mode != RA_ANY) || (old->src == src))
    {
      if (new && rte_same(old, new))
      {
	/* REF_STALE / REF_DISCARD not used in export table */
	/*
	if (old->flags & (REF_STALE | REF_DISCARD | REF_MODIFY))
	{
	  old->flags &= ~(REF_STALE | REF_DISCARD | REF_MODIFY);
	  return 1;
	}
	*/

	goto drop_update;
      }

      /* Remove the old rte */
      *pos = old->next;
      rte_free_quick(old);
      tab->rt_count--;

      break;
    }

  if (!new)
  {
    if (!old)
      goto drop_withdraw;

    if (!net->routes)
      fib_delete(&tab->fib, net);

    return 1;
  }

  /* Insert the new rte */
  rte *e = rte_do_cow(new);
  e->flags |= REF_COW;
  e->net = net;
  e->sender = c;
  e->lastmod = current_time();
  e->next = *pos;
  *pos = e;
  tab->rt_count++;
  return 1;

drop_update:
  return refeed;

drop_withdraw:
  return 0;
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
rt_init_hostcache(rtable *tab)
{
  struct hostcache *hc = mb_allocz(tab->rp, sizeof(struct hostcache));
  init_list(&hc->hostentries);

  hc->hash_items = 0;
  hc_alloc_table(hc, tab->rp, HC_DEF_ORDER);
  hc->slab = sl_new(tab->rp, sizeof(struct hostentry));

  hc->lp = lp_new(tab->rp);
  hc->trie = f_new_trie(hc->lp, 0);

  tab->hostcache = hc;
}

static void
rt_free_hostcache(rtable *tab)
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

static void
rt_notify_hostcache(rtable *tab, net *net)
{
  if (tab->hcu_scheduled)
    return;

  if (trie_match_net(tab->hostcache->trie, net->n.addr))
    rt_schedule_hcu(tab);
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
rt_get_igp_metric(rte *rt)
{
  eattr *ea = ea_find(rt->attrs->eattrs, EA_GEN_IGP_METRIC);

  if (ea)
    return ea->u.data;

  if (rt->attrs->source == RTS_DEVICE)
    return 0;

  if (rt->src->proto->rte_igp_metric)
    return rt->src->proto->rte_igp_metric(rt);

  return IGP_METRIC_UNKNOWN;
}

static int
rt_update_hostentry(rtable *tab, struct hostentry *he)
{
  rta *old_src = he->src;
  int direct = 0;
  int pxlen = 0;

  /* Reset the hostentry */
  he->src = NULL;
  he->dest = RTD_UNREACHABLE;
  he->nexthop_linkable = 0;
  he->igp_metric = 0;

  net_addr he_addr;
  net_fill_ip_host(&he_addr, he->addr);
  net *n = net_route(tab, &he_addr);
  if (n)
    {
      rte *e = n->routes;
      rta *a = e->attrs;
      word pref = a->pref;

      for (rte *ee = n->routes; ee; ee = ee->next)
	if ((ee->attrs->pref >= pref) && ee->attrs->hostentry)
	{
	  /* Recursive route should not depend on another recursive route */
	  log(L_WARN "Next hop address %I resolvable through recursive route for %N",
	      he->addr, n->n.addr);
	  goto done;
	}

      pxlen = n->n.addr->pxlen;

      if (a->dest == RTD_UNICAST)
	{
	  for (struct nexthop *nh = &(a->nh); nh; nh = nh->next)
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
	}

      he->src = rta_clone(a);
      he->dest = a->dest;
      he->nexthop_linkable = !direct;
      he->igp_metric = rt_get_igp_metric(e);
    }

done:
  /* Add a prefix range to the trie */
  trie_add_prefix(tab->hostcache->trie, &he_addr, pxlen, he_addr.pxlen);

  rta_free(old_src);
  return old_src != he->src;
}

static void
rt_update_hostcache(rtable *tab)
{
  struct hostcache *hc = tab->hostcache;
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
	rt_schedule_nhu(he->tab);
    }

  tab->hcu_scheduled = 0;
}

struct hostentry *
rt_get_hostentry(rtable *tab, ip_addr a, ip_addr ll, rtable *dep)
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
  he->owner = tab;
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
