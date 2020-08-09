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
 * The &rte contains information specific to the route (preference, protocol
 * metrics, time of last modification etc.) and a pointer to a &rta structure
 * (see the route attribute module for a precise explanation) holding the
 * remaining route attributes which are expected to be shared by multiple
 * routes in order to conserve memory.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/resource.h"
#include "lib/event.h"
#include "lib/string.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/data.h"
#include "lib/hash.h"
#include "lib/string.h"
#include "lib/alloca.h"

#ifdef CONFIG_RIP
#include "proto/rip/rip.h"
#endif

#ifdef CONFIG_OSPF
#include "proto/ospf/ospf.h"
#endif

#ifdef CONFIG_BGP
#include "proto/bgp/bgp.h"
#endif

#include <stdlib.h>

pool *rt_table_pool;

static slab *rte_slab;
static linpool *rte_update_pool;

list routing_tables;

static void rt_free_hostcache(rtable *tab);
static void rt_notify_hostcache(rtable *tab, net *net);
static void rt_update_hostcache(rtable *tab);
static void rt_next_hop_update(rtable *tab);
static inline void rt_prune_table(rtable *tab);

struct tbf rl_pipe = TBF_DEFAULT_LOG_LIMITS;

#define RT_OBS_BUF_SIZE	256

/* Like fib_route(), but skips empty net entries */
static inline void *
net_route_ip4(rtable *t, net_addr_ip4 *n)
{
  net *r;

  while (r = net_find_valid(t, (net_addr *) n), (!r) && (n->pxlen > 0))
  {
    n->pxlen--;
    ip4_clrbit(&n->prefix, n->pxlen);
  }

  return r;
}

static inline void *
net_route_ip6(rtable *t, net_addr_ip6 *n)
{
  net *r;

  while (r = net_find_valid(t, (net_addr *) n), (!r) && (n->pxlen > 0))
  {
    n->pxlen--;
    ip6_clrbit(&n->prefix, n->pxlen);
  }

  return r;
}

static inline void *
net_route_ip6_sadr(rtable *t, net_addr_ip6_sadr *n)
{
  struct fib_node *fn;

  while (1)
  {
    net *best = NULL;
    int best_pxlen = 0;

    /* We need to do dst first matching. Since sadr addresses are hashed on dst
       prefix only, find the hash table chain and go through it to find the
       match with the smallest matching src prefix. */
    for (fn = fib_get_chain(&t->fib, (net_addr *) n); fn; fn = fn->next)
    {
      net_addr_ip6_sadr *a = (void *) fn->addr;

      if (net_equal_dst_ip6_sadr(n, a) &&
	  net_in_net_src_ip6_sadr(n, a) &&
	  (a->src_pxlen >= best_pxlen))
      {
	best = fib_node_to_user(&t->fib, fn);
	best_pxlen = a->src_pxlen;
      }
    }

    if (best)
      return best;

    if (!n->dst_pxlen)
      break;

    n->dst_pxlen--;
    ip6_clrbit(&n->dst_prefix, n->dst_pxlen);
  }

  return NULL;
}

void *
net_route(rtable *tab, const net_addr *n)
{
  ASSERT(tab->addr_type == n->type);

  net_addr *n0 = alloca(n->length);
  net_copy(n0, n);

  switch (n->type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
    return net_route_ip4(tab, (net_addr_ip4 *) n0);

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
    return net_route_ip6(tab, (net_addr_ip6 *) n0);

  case NET_IP6_SADR:
    return net_route_ip6_sadr(tab, (net_addr_ip6_sadr *) n0);

  default:
    return NULL;
  }
}


static int
net_roa_check_ip4(rtable *tab, const net_addr_ip4 *px, u32 asn)
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
net_roa_check_ip6(rtable *tab, const net_addr_ip6 *px, u32 asn)
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
    return net_roa_check_ip4(tab, (const net_addr_ip4 *) n, asn);
  else if ((tab->addr_type == NET_ROA6) && (n->type == NET_IP6))
    return net_roa_check_ip6(tab, (const net_addr_ip6 *) n, asn);
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
struct rte_storage **
rte_find(net *net, struct rte_src *src)
{
  struct rte_storage **e = &net->routes;

  while ((*e) && (*e)->src != src)
    e = &((*e)->next);

  return e;
}

struct rte_storage *
rte_store(const rte *r, net *n)
{
  struct rte_storage *e = sl_alloc(rte_slab);
  *e = (struct rte_storage) {
    .attrs = r->attrs,
    .net = n,
    .src = r->src,
    .sender = r->sender,
    .generation = r->generation,
  };

  rt_lock_source(e->src);

  if (e->attrs)
    if (e->attrs->cached)
      e->attrs = rta_clone(r->attrs);
    else
      e->attrs = rta_lookup(r->attrs);

  debug("Route store: %p attrs %p next %p\n", e, e->attrs, e->next);
  debug("\tnet %N src %u/%u sender %s.%s gen %u\n",
      n->n.addr, e->src->private_id, e->src->global_id,
      e->sender->proto->name, e->sender->name, e->generation);
  return e;
}

void
rte_copy_metadata(struct rte_storage *dest, struct rte_storage *src)
{
  dest->flags = src->flags & REF_FILTERED;
  dest->pflags = src->pflags;
}

/**
 * rte_free - delete a &rte
 * @e: &rte to be deleted
 *
 * rte_free() deletes the given &rte from the routing table it's linked to.
 */
void
rte_free(struct rte_storage *e)
{
  debug("Route free: %p attrs %p next %p\n", e, e->attrs, e->next);
  debug("\tnet %N src %u/%u sender %s.%s gen %u\n",
      e->net->n.addr, e->src->private_id, e->src->global_id,
      e->sender->proto->name, e->sender->name, e->generation);

  rt_unlock_source(e->src);
  if (e->attrs)
    rta_free(e->attrs);
  *e = (struct rte_storage) {};
  sl_free(rte_slab, e);
}

enum export_filter_result
{
  EFR_PREEXPORT_ACCEPT = 1,
  EFR_FILTER_ACCEPT,
  EFR_FILTER_REJECT,
  EFR_PREEXPORT_REJECT,
  EFR_CACHED_REJECT,
} new_efr;

struct rte_export_internal {
  net *net;
  struct rte_storage *new, *old, *old_stored;
  struct rte_export pub;
  u32 refeed:1;
};

//_Thread_local static struct rte_export_internal rei;

static int				/* Actually better or at least as good as */
rte_better(struct rte_storage *new, struct rte_storage *old)
{
  int (*better)(struct rte_storage *, struct rte_storage *);

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
rte_mergable(struct rte_storage *pri, struct rte_storage *sec)
{
  int (*mergable)(struct rte_storage *, struct rte_storage *);

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

#define RTE_TRACE_TO_DEBUG

static void
rte_trace(struct proto *p, rte *e, int dir, char *msg)
{
  log(L_TRACE "%s %c %s %N %s", p->name, dir, msg, e->net, rta_dest_name(e->attrs->dest));
#ifdef TRACE_TO_DEBUG
  debug("%s %c %s %N %s", p->name, dir, msg, e->net, rta_dest_name(e->attrs->dest));
#endif
}

static inline void
rte_trace_in(uint flag, struct proto *p, rte *e, char *msg)
{
  if (p->debug & flag)
    rte_trace(p, e, '>', msg);
}

static inline void
rte_trace_out(uint flag, struct proto *p, rte *e, char *msg)
{
  if (p->debug & flag)
    rte_trace(p, e, '<', msg);
}

enum export_filter_result
export_filter_(struct channel *c, struct rte *rt, u32 id, linpool *pool, int silent)
{
  struct proto *p = c->proto;
  const struct filter *filter = c->out_filter;
  struct proto_stats *stats = &c->stats;
  int v;
  enum export_filter_result efr = 0;

  /* Do nothing if we have already rejected the route */
  if (silent && bmap_test(&c->export_reject_map, id))
    return EFR_CACHED_REJECT;

  v = p->preexport ? p->preexport(c, rt) : 0;
  if (v < 0)
    {
      efr = EFR_PREEXPORT_REJECT;
      if (silent)
	goto reject;

      stats->exp_updates_rejected++;
      if (v == RIC_REJECT)
	rte_trace_out(D_FILTERS, p, rt, "rejected by protocol");
      goto reject;
    }
  if (v > 0)
    {
      efr = EFR_PREEXPORT_ACCEPT;
      if (!silent)
	rte_trace_out(D_FILTERS, p, rt, "forced accept by protocol");
      goto accept;
    }

  v = filter && ((filter == FILTER_REJECT) ||
		 (f_run(filter, rt, pool,
			(silent ? FF_SILENT : 0)) > F_ACCEPT));
  if (v)
    {
      efr = EFR_FILTER_REJECT;
      if (silent)
	goto reject;

      stats->exp_updates_filtered++;
      rte_trace_out(D_FILTERS, p, rt, "filtered out");
      goto reject;
    }

  efr = EFR_FILTER_ACCEPT;

 accept:
  /* We have accepted the route */
  bmap_clear(&c->export_reject_map, id);
  return efr;

 reject:
  /* We have rejected the route */
  bmap_set(&c->export_reject_map, id);
  rt->attrs = NULL;
  return efr;
}

enum export_filter_result
export_filter(struct channel *c, rte *rt, u32 id, int silent)
{
  return export_filter_(c, rt, id, rte_update_pool, silent);
}

static int
rte_same_storage(struct rte_storage *x, struct rte_storage *y)
{
  return !x && !y || x && y && x->attrs == y->attrs &&
    x->src == y->src &&
    rte_is_filtered(x) == rte_is_filtered(y);
}

static _Bool
rt_notify_basic(struct channel *c, struct rte_export_internal *e)
{
  struct rte_export *ep = &(e->pub);
  if (e->new)
    c->stats.exp_updates_received++;
  else
    c->stats.exp_withdraws_received++;

  if (e->new)
  {
    ep->new = rte_copy(e->new);
    ep->new_id = e->new->id;

    if (export_filter(c, &ep->new, ep->new_id, 0) >= EFR_FILTER_REJECT)
      /* If reject, send a withdraw */
      ep->new.attrs = NULL;
  }

  if (e->old && bmap_test(&c->export_map, e->old->id))
  {
    ep->old = rte_copy(e->old);
    ep->old_id = e->old->id;
  }

  return RTE_EXPORT_IS_OK(ep);
}

static _Bool
rt_notify_accepted(struct channel *c, struct rte_export_internal *e)
{
  // struct proto *p = c->proto;
  struct rte_export *ep = &(e->pub);
  struct rte_storage *old_best = NULL;
  _Bool have_new = 0;

  if (e->net->routes)
    c->stats.exp_updates_received++;
  else
    c->stats.exp_withdraws_received++;

  /* Find the new best if any new route is better than the old one */
  for (struct rte_storage *r = e->net->routes; r; r = r->next)
  {
    /* Currently exported */
    if (bmap_test(&c->export_map, r->id))
    {
      if (have_new)
      {
	/* We already have a better route */
	old_best = r;
	break;
      }
      else if (rte_is_valid(r))
      {
	/* No change happened */
	return 0;
      }
      else
      {
	/* Withdrawing the old best route */
	old_best = r;
	continue;
      }
    }

    /* We already have a best route */
    if (have_new)
      continue;

    /* Not considering an invalid route for export */
    if (!rte_is_valid(r))
      continue;

    /* Already rejected */
    if (bmap_test(&c->export_reject_map, r->id))
      continue;

    /* A new route to check */
    ep->new = rte_copy(r);
    if (export_filter(c, &ep->new, ep->new_id = r->id, 0) <= EFR_FILTER_ACCEPT)
      if (old_best)
	break;
      else
	have_new = 1;
  }

  /* No export before, no export after */
  if (!have_new && !old_best)
    return 0;

  if (old_best)
  {
    ep->old = rte_copy(old_best);
    ep->old_id = old_best->id;
  }

  return 1;
}


static struct nexthop *
nexthop_merge_rta(struct nexthop *nhs, rta *a, linpool *pool, int max)
{
  return nexthop_merge(nhs, &(a->nh), 1, 0, max, pool);
}

_Bool
rt_export_merged(struct channel *c, net *net, rte *best, linpool *pool, int silent)
{
  // struct proto *p = c->proto;
  struct nexthop *nhs = NULL;
  struct rte_storage *best0 = net->routes;

  if (!rte_is_valid(best0))
    return 0;

  *best = rte_copy(best0);
  if (export_filter_(c, best, best0->id, pool, silent) >= EFR_FILTER_REJECT)
    /* Best route doesn't pass the filter */
    return 0;

  if (!rte_is_reachable(best))
    /* Unreachable routes can't be merged */
    return 1;

  for (struct rte_storage *rt0 = best0->next; rt0; rt0 = rt0->next)
  {
    if (!rte_mergable(best0, rt0))
      continue;

    struct rte tmp = rte_copy(rt0);
    if (export_filter_(c, &tmp, rt0->id, pool, 1) >= EFR_FILTER_REJECT)
      continue;

    if (!rte_is_reachable(&tmp))
      continue;

    nhs = nexthop_merge_rta(nhs, tmp.attrs, pool, c->merge_limit);
  }

  if (nhs)
  {
    nhs = nexthop_merge_rta(nhs, best->attrs, pool, c->merge_limit);

    if (nhs->next)
      best->attrs = rta_cow(best->attrs, pool);

    nexthop_link(best->attrs, nhs);
  }

  return 1;
}

#define VALID_OR_NULL(w)  rte_is_valid(w) ? w : NULL

static _Bool
rt_notify_merged(struct channel *c, struct rte_export_internal *e, struct rte_update *u, uint n)
{
  /* Try to find whether the change is even relevant */
  struct rte_storage *old_best = VALID_OR_NULL(u[0].old_best);
  struct rte_storage *new_best = VALID_OR_NULL(u[n-1].new_best);

  /* Nothing happened, nothing to announce */
  if (!old_best && !new_best)
    return 0;

  /* Best route change: definitely relevant */
  if (!rte_same_storage(old_best, new_best))
    goto relevant;

  /* Here the best route has not changed,
   * checking whether the mergable routes have been affected */
  for (uint i=0; i<n; i++)
    if (rte_mergable(old_best, VALID_OR_NULL(u[i].old))
	|| rte_mergable(old_best, VALID_OR_NULL(u[i].new)))
      goto relevant;

  /* Nothing relevant happened, nothing to announce */
  return 0;

relevant:
  if (new_best)
    c->stats.exp_updates_received++;
  else
    c->stats.exp_withdraws_received++;

  struct rte_export *ep = &(e->pub);

  /* Prepare new merged route */
  if (new_best)
  {
    ep->new_id = new_best->id;
    if (!rt_export_merged(c, e->net, &ep->new, rte_update_pool, 0))
      ep->new.attrs = NULL;
  }

  /* Check old merged route */
  if (old_best && bmap_test(&c->export_map, old_best->id))
  {
    ep->old_id = old_best->id;
    ep->old = rte_copy(old_best);
  }

  return RTE_EXPORT_IS_OK(ep);
}

static _Bool
rte_export_limits(struct channel *c, struct rte_export_internal *e)
{
  struct rte_export *ep = &(e->pub);

  struct proto *p = c->proto;
  struct proto_stats *stats = &c->stats;

  if (e->refeed && ep->new.attrs)
    c->refeed_count++;

  /* Apply export limit */
  struct channel_limit *l = &c->out_limit;
  if (l->action && !ep->old.attrs && ep->new.attrs)
  {
    if (stats->exp_routes >= l->limit)
      channel_notify_limit(c, l, PLD_OUT, stats->exp_routes);

    if (l->state == PLS_BLOCKED)
    {
      stats->exp_updates_rejected++;
      rte_trace_out(D_FILTERS, p, &ep->new, "rejected [limit]");
      return 0;
    }
  }

  return 1;
}

static _Bool
rte_export_store(struct channel *c, struct rte_export_internal *e)
{
  /* Apply export table */
  if (c->out_table)
  {
    if (!rte_update_out(c, &(e->pub.new), &(e->pub.old), &(e->old_stored), e->refeed))
      return 0;
  }
  else if (c->out_filter != FILTER_ACCEPT)
    /* We aren't sure about the old route attributes */
    e->pub.old.attrs = NULL;

  return 1;
}

static void
rte_export_meta(struct channel *c, struct rte_export *ep)
{
  struct proto_stats *stats = &c->stats;
  struct proto *p = c->proto;

  if (RTE_EXPORT_NEW_OK(ep))
    stats->exp_updates_accepted++;
  else
    stats->exp_withdraws_accepted++;

  if (RTE_EXPORT_OLD_OK(ep))
  {
    bmap_clear(&c->export_map, ep->old_id);
    stats->exp_routes--;
  }

  if (RTE_EXPORT_NEW_OK(ep))
  {
    bmap_set(&c->export_map, ep->new_id);
    stats->exp_routes++;
  }

  if (p->debug & D_ROUTES)
    switch (rte_export_kind(ep))
    {
      case REX_NOTHING:		bug("Idempotent exports should have been ignored by now");
      case REX_ANNOUNCEMENT:	rte_trace_out(D_ROUTES, p, &ep->new, "added"); break;
      case REX_WITHDRAWAL:	rte_trace_out(D_ROUTES, p, &ep->old, "removed"); break;
      case REX_UPDATE:		rte_trace_out(D_ROUTES, p, &ep->new, "replaced"); break;
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

/* Route export event
 *
 * In general, we first call preexport() hook of a protocol, which performs
 * basic checks on the route (each protocol has a right to veto or force accept
 * of the route before any filter is asked). Then we consult an export filter
 * of the channel and verify the old route in an export map of the channel.
 * Finally, the rt_notify() hook of the protocol gets called.
 */

static void
rte_export(struct channel *c, struct rte_update *u, uint n)
{
  DBG("channel %s.%s: processing %u exports of batch %lu/%lu from table %s\n",
      c->proto->name, c->name, n, c->last_export, c->table->total_updates, c->table->name);

  const uint ra_mode = c->ra_mode;
  _Bool accepted = 0;

  struct rte_export_internal ei = {
    .net = u[0].new->net,
  };

  rte_update_lock();
  for (uint i=0; i<n; i++)
  {
    if (i && ra_mode != RA_ANY)
      break;

    switch (ra_mode)
    {
      case RA_OPTIMAL:
	ei.new = VALID_OR_NULL(u[n-1].new_best);
	ei.old = VALID_OR_NULL(u[0].old_best);

	if (!rte_same_storage(ei.new, ei.old))
	  accepted = rt_notify_basic(c, &ei);
	break;

      case RA_ANY:
	ei.new = VALID_OR_NULL(u[i].new);
	ei.old = VALID_OR_NULL(u[i].old);

	if (!rte_same_storage(ei.new, ei.old))
	  accepted = rt_notify_basic(c, &ei);
	break;

      case RA_ACCEPTED:
	accepted = rt_notify_accepted(c, &ei);
	break;

      case RA_MERGED:
	accepted = rt_notify_merged(c, &ei, u, n);
	break;

      default:
	bug("Strange channel route announcement mode");
    }

    if (!accepted)
    {
      DBG("Idempotent export.\n");
      continue;
    }

    if (!rte_export_limits(c, &ei))
      continue;

    if (!rte_export_store(c, &ei))
      goto store_free;

    rte_export_meta(c, &ei.pub);

    c->proto->rt_notify(c, &ei.pub);

store_free:
    if (ei.old_stored)
      rte_free(ei.old_stored);
  }

  for (uint i=0; i<n; i++)
    if (rte_is_valid(u[i].old))
      bmap_clear(&c->export_reject_map, u[i].old->id);

  rte_update_unlock();
}

static int rte_export_sort_cmp(const void *_a, const void *_b)
{
  const struct rte_update *a = _a, *b = _b;

  /* Sorting exports from a single table, same net_addr equals same net. */
  if (a->new->net < b->new->net)
    return -1;

  if (a->new->net > b->new->net)
    return 1;

  /* Keep the order for same-net exports. */
  if (a->pos < b->pos)
    return -1;

  if (a->pos > b->pos)
    return 1;

  return 0;
}

static void rte_export_event(void *data)
{
  struct channel *c = data;
  struct rte_update local_updates[RT_OBS_BUF_SIZE];
  u64 prune_limit = 0;

  while (c->last_export < c->table->total_updates)
  {
    u64 bpos = c->last_export % RT_OBS_BUF_SIZE;
    u64 epos = c->table->total_updates % RT_OBS_BUF_SIZE;
    u64 total = 0;

    if (bpos >= epos)
    {
      /* Exports are overlapping the end of the buffer */
      memcpy(local_updates, &c->table->pending_updates[bpos], sizeof(struct rte_update) * (RT_OBS_BUF_SIZE - bpos));
      total = RT_OBS_BUF_SIZE - bpos;
      bpos = 0;
    }

    if (bpos < epos)
    {
      /* Either the remainder of the exports at the beginning of the buffer
       * or all of them at once */
      memcpy(&local_updates[total], &c->table->pending_updates[bpos], sizeof(struct rte_update) * (epos - bpos));
      total += epos - bpos;
    }

    qsort(local_updates, total, sizeof(struct rte_update), rte_export_sort_cmp);

    u64 first = 0, next = 1, processed = 0;
    while (next < total)
    {
      if (local_updates[first].new->net == local_updates[next].new->net)
      {
	next++;
	continue;
      }

      rte_export(c, &local_updates[first], next - first);
      processed += next - first;
      first = next;
      next++;
    }

    rte_export(c, &local_updates[first], next - first);
    processed += next - first;

    ASSERT_DIE(processed == total);

    c->last_export += total;
    prune_limit += total;

    if (prune_limit > RT_OBS_BUF_SIZE / 4)
    {
      rt_schedule_prune(c->table);
      prune_limit = 0;
    }

    ev_suspend();
  }

  rt_schedule_prune(c->table);
}

void
channel_run_exports(struct channel *c)
{
  if (!c->export_event)
    c->export_event = ev_new_init(c->proto->pool, rte_export_event, c);
  ev_schedule(c->export_event);
}

static void
rt_run_exports(struct rtable *tab)
{
  tab->export_scheduled = 0;

  struct channel *c;
  node *n;
  WALK_LIST2(c, n, tab->channels, table_node)
    if (c->channel_state == CS_UP && c->export_state == ES_READY)
      channel_run_exports(c);
}

static inline void
rt_schedule_export(rtable *tab)
{
  if (tab->export_scheduled == 0)
    ev_schedule(tab->rt_event);

  tab->export_scheduled = 1;
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
 * The update is always a change of just one route in @net (which may caused a
 * change of the best route of the network). Routes @new and @old describe the
 * changed route and @new_best and @old_best describe best routes. Other routes
 * are not affected, but in sorted table the order of other routes might
 * change.
 *
 * The function stores the change and schedules the appropriate events.
 */
static void
rte_announce(rtable *tab, net *net, struct rte_storage *new, struct rte_storage *old,
	     struct rte_storage *new_best, struct rte_storage *old_best)
{
  if (new_best != old_best)
  {
    if (new_best)
      new_best->sender->stats.pref_routes++;
    if (old_best)
      old_best->sender->stats.pref_routes--;

    if (tab->hostcache)
      rt_notify_hostcache(tab, net);
  }

  if (tab->total_updates - tab->cleared_updates >= RT_OBS_BUF_SIZE)
    bug("Too many updates pending, not implemented yet");

  /* Check invariant */
  ASSERT(!old || !(old->flags & REF_OBSOLETE));

  /* Put the route update to the first empty place */
  if (old)
  {
    old->next = new;
    old->flags |= REF_OBSOLETE;
  }

  u64 pos = tab->total_updates++ % RT_OBS_BUF_SIZE;

  tab->pending_updates[pos] = (struct rte_update) {
    .new = new, .old = old,
    .new_best = new_best, .old_best = old_best,
    .pos = pos,
  };

  DBG("put export %lu (new %p a %p old %p a %p) from table %s\n",
      tab->total_updates, new, new ? new->attrs : NULL, old, old ? old->attrs : NULL, tab->name);

  rt_schedule_export(tab);
}

static void
rte_report_pipe_collision(struct channel *c, struct network *net, struct rte_storage *old, struct rte *new)
{
  if (!old->generation && !new->generation)
    bug("Two protocols claim to author a route with the same rte_src in table %s: %N %s/%u:%u",
	c->table->name, net->n.addr, old->src->proto->name, old->src->private_id, old->src->global_id);

  log_rl(&rl_pipe, L_ERR "Route source collision in table %s: %N %s/%u:%u",
	c->table->name, net->n.addr, old->src->proto->name, old->src->private_id, old->src->global_id);

  if (config->pipe_debug)
  {
    if (old->generation)
      old->sender->proto->rte_track(old->sender, net->n.addr, old->src);

    if (new->generation)
      c->proto->rte_track(c, net->n.addr, new->src);
  }
}

static int
rte_same(struct rte_storage *x, rte *y, _Bool fy)
{
  /* rte.flags are not checked, as they are mostly internal to rtable */
  return
    x->attrs == y->attrs &&
    x->src == y->src &&
    rte_is_filtered(x) == fy;
}

static struct rte_storage *
rte_recalc_find_best(struct rte_storage *new)
{
  if (!new)
    return NULL;
  
  struct rte_storage **bp = &new;
  for (struct rte_storage **k=&(*bp)->next; *k; k=&(*k)->next)
    if (rte_better(*k, *bp))
      bp = k;

  /* And relink it */
  struct rte_storage *best = *bp;
  *bp = best->next;
  best->next = new;
  return best;
}

static void
rt_maybe_schedule_prune(struct rtable *table, uint count)
{
  if (((table->gc_counter += count) >= table->config->gc_max_ops) &&
      (table->gc_time + table->config->gc_min_time <= current_time()))
    rt_schedule_prune(table);
}

static void NONNULL(1,2)
rte_recalculate(net *net, struct rte_storage *new, struct rte_storage *old, struct rte_storage **before_old)
{
  struct channel *c = new->sender;
  struct proto *p = c->proto;
  struct proto_stats *stats = &c->stats;
  struct rtable *table = c->table;

  /* Update channel statistics */
  if (new->attrs)
    rte_is_filtered(new) ? stats->filt_routes++ : stats->imp_routes++;
  if (old)
    rte_is_filtered(old) ? stats->filt_routes-- : stats->imp_routes--;

  /* Store the input state */
  _Bool new_ok = new->attrs && !rte_is_filtered(new);
  _Bool old_ok = old && !rte_is_filtered(old);

  /* Keep the old best route for recalculation purposes */
  struct rte_storage *old_best = net->routes;

  /* Remove the old route from the chain */
  /* TODO: Do this later together with recalculation */
  if (old)
  {
    *before_old = old->next;
    table->rt_count--;
  }

  if (new->attrs)
    table->rt_count++;

  if (table->config->sorted)
    {
      /* If routes are sorted, just insert new route to appropriate position */
      /* Try to insert the route to the old position or new route to beginning. */
      struct rte_storage **k = before_old ?: &net->routes;

      /* But if the new route is better than the preceeding route,
       * we have to start comparing from the best route. */
      if (k != &net->routes &&
	  rte_better(new, SKIP_BACK(struct rte_storage, next, k)))
	k = &net->routes;

      for (; *k; k=&(*k)->next)
	if (rte_better(new, *k))
	  break;

      new->next = *k;
      *k = new;
    }
  else
    {
      /* If routes are not sorted, find the best route and move it on
	 the first position. There are several optimized cases. */

      if (new->attrs && new->src->proto->rte_recalculate && new->src->proto->rte_recalculate(table, net, new, old, old_best))
	goto do_recalculate;

      if (new->attrs && rte_better(new, old_best))
	{
	  /* The first case - the new route is clearly optimal,
	     we link it at the first position */

	  new->next = net->routes;
	  net->routes = new;

	}
      else if (old == old_best)
	{
	  /* The second case - the old best route disappeared, we add the
	     new route (if we have any) to the list (we don't care about
	     position) and then we elect the new optimal route and relink
	     that route at the first position and announce it. New optimal
	     route might be NULL if there is no more routes */

	do_recalculate:
	  /* Add the new route to the list and find best route */
	  new->next = *before_old;
	  *before_old = new;
	  net->routes = rte_recalc_find_best(net->routes);
	}
      else
	{
	  /* The third case - the new route is not better than the old
	     best route (therefore old_best != NULL) and the old best
	     route was not removed (therefore old_best == net->routes).
	     Or there is no new route at all.
	     We just link the new route or the withdraw marker
	     after the old best route. */

	  ASSERT(net->routes != NULL);
	  new->next = *before_old;
	  *before_old = new;
	}
    }

  if (new_ok)
    {
      new->lastmod = current_time();
      new->id = hmap_first_zero(&table->id_map);
      hmap_set(&table->id_map, new->id);
    }

  /* Log the route change */
  if (p->debug & D_ROUTES)
    {
      if (new_ok)
      {
	rte new_copy = rte_copy(new);
	rte_trace(p, &new_copy, '>', new == net->routes ? "added [best]" : "added");
      }
      else if (old_ok)
	{
	  rte old_copy = rte_copy(old);
	  if (old != old_best)
	    rte_trace(p, &old_copy, '>', "removed");
	  else if (net->routes && !rte_is_filtered(net->routes))
	    rte_trace(p, &old_copy, '>', "removed [replaced]");
	  else
	    rte_trace(p, &old_copy, '>', "removed [sole]");
	}
    }

  /* Propagate the route change */
  rte_announce(table, net, new, old, net->routes, old_best);

  if (!net->routes)
    rt_maybe_schedule_prune(table, 1);

  if (old_ok && p->rte_remove)
    p->rte_remove(net, old);
  if (new_ok && p->rte_insert)
    p->rte_insert(net, new);
}

static int NONNULL(1) rte_update_in(rte *new);
static void NONNULL(1) rte_update2(rte *new);

void NONNULL(1)
rte_update(rte *new)
{
  ASSERT(new->sender);
  ASSERT(new->sender->channel_state == CS_UP);
  ASSERT(new->net);
  ASSERT(new->src);

  if (new->attrs && !new->attrs->pref)
  {
    ASSERT(!new->attrs->cached);
    new->attrs->pref = new->sender->preference;
  }

  if (new->sender->in_table && !rte_update_in(new))
    return;

  rte_update2(new);
}

static void NONNULL(1)
rte_update2(rte *new)
{
  struct channel *c = new->sender;
  struct proto *p = c->proto;
  struct proto_stats *stats = &c->stats;
  const struct filter *filter = c->in_filter;

  _Bool filtered = 0;

  if (new->generation && !p->rte_track)
    bug("Announced a non-authored route without rte_track() implemented");

  if (new->attrs)
    stats->imp_updates_received++;
  else
    stats->imp_withdraws_received++;

  rte_update_lock();

  if (!net_validate(new->net))
  {
    log(L_WARN "Ignoring bogus prefix %N received via %s.%s",
	new->net, c->proto->name, c->name);
    goto invalid;
  }

  /* FIXME: better handling different nettypes */
  int cl = !net_is_flow(new->net) ?
    net_classify(new->net): (IADDR_HOST | SCOPE_UNIVERSE);
  if ((cl < 0) || !(cl & IADDR_HOST) || ((cl & IADDR_SCOPE_MASK) <= SCOPE_LINK))
  {
    log(L_WARN "Ignoring bogus route %N received via %s.%s",
	new->net, c->proto->name, c->name);
    goto invalid;
  }

  if (new->attrs)
    {
      if (net_type_match(new->net, NB_DEST) == !new->attrs->dest)
      {
	log(L_WARN "Ignoring route %N with invalid dest %d received via %s.%s",
	    new->net, new->attrs->dest, c->proto->name, c->name);
	goto invalid;
      }

      if ((new->attrs->dest == RTD_UNICAST) && !nexthop_is_sorted(&(new->attrs->nh)))
      {
	log(L_WARN "Ignoring unsorted multipath route %N received via %s.%s",
	    new->net, c->proto->name, c->name);
	goto invalid;
      }

      if ((filter == FILTER_REJECT) || (filter && (f_run(filter, new, rte_update_pool, 0) > F_ACCEPT)))
	{
	  stats->imp_updates_filtered++;
	  rte_trace_in(D_FILTERS, p, new, "filtered out");
	  filtered = 1;
	}
    }

  /* Find a table record */
  net *nn;

  if (new->attrs && (!filtered || c->in_keep_filtered))
    /* This is an update and it shall pass to the table */
    nn = net_get(c->table, new->net);
  else
  {
    /* This is a withdraw and it need not be in the table */
    nn = net_find(c->table, new->net);

    if (!nn) /* No previous table record found */
    {
      if (!new->attrs) /* Regular withdraw */
	stats->imp_withdraws_ignored++;

      rte_update_unlock();
      return;
    }

    /* Drop the attributes as they aren't for anything now. */
    new->attrs = NULL;
  }

  struct rte_storage *old = NULL, **before_old = NULL;

  /* Find the original route from the same protocol */
  old = *(before_old = rte_find(nn, new->src));

  /* Idempotent withdraw. Do nothing. */
  if (!old && !new->attrs)
    {
      stats->imp_withdraws_ignored++;
      return;
    }

  /* If there is the same route in the routing table but from
   * a different sender, then there are two paths from the
   * source protocol to this routing table through transparent
   * pipes, which is not allowed.
   * We log that and ignore the route. */
  if (old && (old->sender->proto != p))
    return rte_report_pipe_collision(c, nn, old, new);

  /* If the route is the same, then we just ignore the update and
   * refresh the old route */
  if (old && new->attrs && rte_same(old, new, filtered))
    {
      old->flags &= ~(REF_STALE | REF_DISCARD | REF_MODIFY);

      if (!filtered)
	{
	  stats->imp_updates_ignored++;
	  rte_trace_in(D_ROUTES, p, new, "ignored");
	}

      return;
    }

  _Bool new_ok = new->attrs && !filtered;
  _Bool old_ok = old && !rte_is_filtered(old);

  struct channel_limit *l = &c->rx_limit;
  if (l->action && !old && new->attrs && !c->in_table)
    {
      u32 all_routes = stats->imp_routes + stats->filt_routes;

      if (all_routes >= l->limit)
	channel_notify_limit(c, l, PLD_RX, all_routes);

      if (l->state == PLS_BLOCKED)
	{
	  /* In receive limit the situation is simple, old is NULL so
	     we just free new and exit like nothing happened */

	  stats->imp_updates_ignored++;
	  rte_trace_in(D_FILTERS, p, new, "ignored [limit]");
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
	  rte_trace_in(D_FILTERS, p, new, "ignored [limit]");

	  if (c->in_keep_filtered)
	    filtered = 1;
	  else
	    new->attrs = NULL;

	  /* Note that old && !new could be possible when
	     c->in_keep_filtered changed in the recent past. */

	  if (!old && !new->attrs)
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

 skip_stats1:;

  /* Store the new route now, it is going to be inserted. */
  struct rte_storage *new_stored = rte_store(new, nn);

  if (filtered)
    new_stored->flags |= REF_FILTERED;

  /* And recalculate the best route */
  rte_recalculate(nn, new_stored, old, before_old);
  rte_update_unlock();
  return;

 invalid:
  if (new->attrs)
  {
    stats->imp_updates_invalid++;
    rte_trace_in(D_FILTERS, p, new, "invalid");
  }
  else
    stats->imp_withdraws_invalid++;

  rte_update_unlock();
  return;
}

/* Modify existing route by protocol hook, used for long-lived graceful restart */
static inline void
rte_modify(struct rte_storage **before_old)
{
  struct rte_storage *old = *before_old;

  rte_update_lock();

  rte nloc = {
    .net = old->net->n.addr,
    .src = old->src,
    .attrs = old->sender->proto->rte_modify(old, rte_update_pool),
    .sender = old->sender,
    .generation = old->generation,
  };

  struct rte_storage *new = rte_store(&nloc, old->net);
  new->flags |= old->flags & REF_FILTERED;

  if (new->attrs != old->attrs)
    /* Exchange the route for a new one */
    rte_recalculate(old->net, new, old, before_old);
  else
    /* Keep the old route */
    old->flags &= ~REF_MODIFY;

  rte_update_unlock();
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
      for (struct rte_storage *e = n->routes; e; e = e->next)
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
      for (struct rte_storage *e = n->routes; e; e = e->next)
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
      for (struct rte_storage *e = n->routes; e; e = e->next)
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
rte_dump(struct rte_storage *e)
{
  net *n = e->net;
  debug("%-1N ", n->n.addr);
  debug("p=%s src=(%u/%u) ", e->src->proto->name, e->src->private_id, e->src->global_id);
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
      for(struct rte_storage *e=n->routes; e; e=e->next)
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

  WALK_LIST(t, routing_tables)
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

  if (tab->export_scheduled)
    rt_run_exports(tab);

  if (tab->prune_state)
    rt_prune_table(tab);

  rt_unlock_table(tab);
}

void
rt_setup(pool *p, rtable *t, struct rtable_config *cf)
{
  bzero(t, sizeof(*t));
  t->name = cf->name;
  t->config = cf;
  t->addr_type = cf->addr_type;
  fib_init(&t->fib, p, t->addr_type, sizeof(net), OFFSETOF(net, n), 0, NULL);
  init_list(&t->channels);

  hmap_init(&t->id_map, p, 1024);
  hmap_set(&t->id_map, 0);

  t->pending_updates = mb_alloc(rt_table_pool, sizeof(struct rte_update) * RT_OBS_BUF_SIZE);

  t->rt_event = ev_new_init(p, rt_event, t);
  t->gc_time = current_time();
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
  rte_slab = sl_new(rt_table_pool, sizeof(struct rte_storage));
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
  int limit = 128;

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
    u64 last_export = tab->total_updates;
    WALK_LIST2(c, n, tab->channels, table_node)
    {
      /* Mark channels to flush */
      if (c->channel_state == CS_FLUSHING)
      {
	c->flush_active = 1;
	c->withdraws_pending = 0;
      }

      /* Find the oldest export processed by all channels */
      if (c->channel_state == CS_UP &&
	  c->export_state == ES_READY &&
	  c->last_export < last_export)
	last_export = c->last_export;
    }

    ASSERT(last_export >= tab->cleared_updates);

    for (u64 e = tab->cleared_updates; e < last_export; e++)
    {
      struct rte_update *u = &tab->pending_updates[e % RT_OBS_BUF_SIZE];
      debug("Clearing update %lu/%lu/%lu in table %s\n",
	  e, last_export, tab->total_updates, tab->name);

      /* Free the withdrawn route */
      if (u->old)
      {
	hmap_clear(&tab->id_map, u->old->id);
	rte_free(u->old);
      }

      /* Mark the withdraw indicator for discard */
      if (!u->new->attrs)
	u->new->flags |= REF_DISCARD;
    }

    tab->cleared_updates = last_export;

    FIB_ITERATE_INIT(fit, &tab->fib);
    tab->prune_state = 2;
  }

again:
  FIB_ITERATE_START(&tab->fib, fit, net, n)
    {
    rescan:
      for (struct rte_storage *e, **ep = &n->routes; e = *ep; ep = &((*ep)->next))
      {
	/* Dropping the marked withdraw indicators */
	while (!e->attrs && (e->flags & REF_DISCARD))
	{
	  DBG("withdraw indicator %p (lastmod %lu) drop\n", e, e->lastmod);

	  /* Remove it from the list */
	  *ep = e->next;

	  /* Finally free */
	  rte_free(e);

	  /* Move to the next entry */
	  if (e = *ep)
	    continue;

	  /* No more entries in this list */
	  FIB_ITERATE_PUT_NEXT(fit, &tab->fib);
	  goto again;
	}

	if (e->sender->flush_active && !e->attrs)
	{
	  e->sender->withdraws_pending = 1;
	  tab->prune_state |= 1;
	  continue;
	}

	if (e->sender->flush_active || (e->flags & REF_DISCARD))
	  {
	    if (limit <= 0)
	      {
		FIB_ITERATE_PUT(fit);
		ev_schedule(tab->rt_event);
		return;
	      }

	    /* Discard the route */
	    rte_update_lock();
	    rte ew = {
	      .net = e->net->n.addr,
	      .src = e->src,
	      .sender = e->sender,
	      .generation = e->generation,
	    };
	    DBG("route %p for %N (attrs %p src %p lastmod %lu) discard\n", e, ew.net, e->attrs, ew.src, e->lastmod);
	    struct rte_storage *es = rte_store(&ew, e->net);
	    es->flags |= e->flags & REF_FILTERED;
	    rte_recalculate(e->net, es, e, ep);
	    rte_update_unlock();

	    limit--;

	    goto rescan;
	  }

	if (e->flags & REF_MODIFY)
	  {
	    if (limit <= 0)
	      {
		FIB_ITERATE_PUT(fit);
		ev_schedule(tab->rt_event);
		return;
	      }

	    rte_modify(ep);
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
    }
  FIB_ITERATE_END;

#ifdef DEBUGGING
  fib_check(&tab->fib);
#endif

  tab->gc_counter = 0;
  tab->gc_time = current_time();

  /* state change 2->0, 3->1 */
  tab->prune_state &= 1;

  if (tab->prune_state > 0)
    ev_schedule(tab->rt_event);

  /* FIXME: This should be handled in a better way */
  rt_prune_sources();

  /* Close flushed channels */
  WALK_LIST2_DELSAFE(c, n, x, tab->channels, table_node)
    if (c->flush_active)
    {
      c->flush_active = 0;
      if (c->withdraws_pending)
	/* Wait for pending withdraws */
	c->withdraws_pending = 0;
      else
	/* No pending withdraws */
	channel_set_state(c, CS_DOWN);
    }

  return;
}

void
rt_preconfig(struct config *c)
{
  init_list(&c->tables);

  rt_new_table(cf_get_symbol("master4"), NET_IP4);
  rt_new_table(cf_get_symbol("master6"), NET_IP6);
}


/*
 * Some functions for handing internal next hop updates
 * triggered by rt_schedule_nhu().
 */

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

static inline struct rte_storage *
rt_next_hop_update_rte(struct rte_storage *old)
{
  rta *a = alloca(RTA_MAX_SIZE);
  memcpy(a, old->attrs, rta_size(old->attrs));

  mpls_label_stack mls = { .len = a->nh.labels_orig };
  memcpy(mls.stack, &a->nh.label[a->nh.labels - mls.len], mls.len * sizeof(u32));

  rta_apply_hostentry(a, old->attrs->hostentry, &mls);
  a->cached = 0;

  rte e = {
    .attrs = a,
    .net = old->net->n.addr,
    .src = old->src,
    .sender = old->sender,
    .generation = old->generation,
  };

  rte_trace_in(D_ROUTES, old->sender->proto, &e, "updated");

  struct rte_storage *new = rte_store(&e, old->net);
  rte_copy_metadata(new, old);
  return new;
}

static struct rte_storage *
rte_recalc_sort(struct rte_storage *chain)
{
  ASSERT(chain);

  /* Single route -> nothing to do */
  if (!chain->next)
    return chain;

  /* Simple insert sort (TODO: something faster for long chains) */
  struct rte_storage *best = chain, *next = chain->next, *cur;
  chain->next = NULL;

  while (cur = next)
  {
    next = cur->next;
    for (struct rte_storage **k = &best; *k; k = &((*k)->next))
      if (rte_better(cur, *k))
      {
	cur->next = *k;
	*k = cur;
	break;
      }
  }

  return best;
}

static inline int
rt_next_hop_update_net(rtable *tab, net *n)
{
  /* Get how many of them are affected */
  uint count = 0;
  for (struct rte_storage **k = &n->routes, *e; e = *k; k = &e->next)
    if (rte_is_valid(e) && rta_next_hop_outdated(e->attrs))
      count++;

  if (!count)
    return 0;

  /* Get the changes */
  struct rte_multiupdate {
    struct rte_storage *new, *old, **before_old;
  } *updates = alloca(sizeof(struct rte_multiupdate) * count);

  uint i = 0;
  for (struct rte_storage **k = &n->routes, *e; e = *k; k = &e->next)
    if (rte_is_valid(e) && rta_next_hop_outdated(e->attrs))
      updates[i++] = (struct rte_multiupdate) {
	.new = rt_next_hop_update_rte(e),
	.old = e,
	.before_old = k,
      };

  ASSERT_DIE(i == count);

  /* One change is equivalent to standard recalculate */
  if (count == 1)
  {
    rte_recalculate(n, updates[0].new, updates[0].old, updates[0].before_old);
    return 1;
  }
  
  /* Keep the old best pointer for now */
  struct rte_storage *old_best = n->routes;

  /* One time for all the routes */
  btime now = current_time();

  /* Replace all the routes */
  for (uint i=0; i<count; i++)
  {
    /* Get new IDs for them */
    updates[i].new->id = hmap_first_zero(&tab->id_map);
    hmap_set(&tab->id_map, updates[i].new->id);

    /* Set the lastmod */
    updates[i].new->lastmod = now;

    if (i && (updates[i].before_old == &(updates[i-1].old->next)))
    {
      /* Adjacent to the previous changed one */
      ASSERT(updates[i-1].new->next == updates[i].old);
      updates[i-1].new->next = updates[i].new;
      updates[i].new->next = updates[i].old->next;
    }
    else
    {
      /* The previous route has not been changed */
      ASSERT(*updates[i].before_old == updates[i].old);
      *updates[i].before_old = updates[i].new;
      updates[i].new->next = updates[i].old->next;
    }

    rte new_copy = rte_copy(updates[i].new);
    rte_trace(updates[i].new->sender->proto, &new_copy, '~',
	"recursive hexthop update");
  }

  /* More changes, replace all of them, trigger one recalculate */
  if (tab->config->sorted)
    n->routes = rte_recalc_sort(n->routes);

  else
  {
    for (uint i=0; i<count; i++)
      if (updates[i].new->src->proto->rte_recalculate)
	updates[i].new->src->proto->rte_recalculate(tab, n, updates[i].new, updates[i].old, old_best);

    n->routes = rte_recalc_find_best(n->routes);
  }

  rte best_copy = rte_copy(n->routes);
  rte_trace(best_copy.sender->proto, &best_copy, '~',
      (n->routes == old_best) ? "best not changed" : "best chosen");

  /* First announce all the non-old-best changes */
  for (uint i=1; i<count; i++)
    rte_announce(tab, n, updates[i].new, updates[i].old, old_best, old_best);

  /* Then announce the old best change */
  rte_announce(tab, n, updates[0].new, updates[0].old, n->routes, old_best);

  rt_maybe_schedule_prune(tab, count);

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

  cf_define_symbol(s, SYM_TABLE, table, c);
  c->name = s->name;
  c->addr_type = addr_type;
  c->gc_max_ops = 1000;
  c->gc_min_time = 5;

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
      DBG("Deleting routing table %s\n", r->name);
      r->config->table = NULL;
      if (r->hostcache)
	rt_free_hostcache(r);
      rem_node(&r->n);
      fib_free(&r->fib);
      hmap_free(&r->id_map);
      mb_free(r->pending_updates);
      rfree(r->rt_event);
      mb_free(r);
      config_del_obstacle(conf);
    }
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
	  rtable *ot = o->table;
	  if (!ot->deleted)
	    {
	      r = rt_find_table_config(new, o->name);
	      if (r && (r->addr_type == o->addr_type) && !new->shutdown)
		{
		  DBG("\t%s: same\n", o->name);
		  r->table = ot;
		  ot->name = r->name;
		  ot->config = r;
		  if (o->sorted != r->sorted)
		    log(L_WARN "Reconfiguration of rtable sorted flag not implemented");
		}
	      else
		{
		  DBG("\t%s: deleted\n", o->name);
		  ot->deleted = old;
		  config_add_obstacle(old);
		  rt_lock_table(ot);
		  rt_unlock_table(ot);
		}
	    }
	}
    }

  WALK_LIST(r, new->tables)
    if (!r->table)
      {
	rtable *t = mb_allocz(rt_table_pool, sizeof(struct rtable));
	DBG("\t%s: created\n", r->name);
	rt_setup(rt_table_pool, t, r);
	add_tail(&routing_tables, &t->n);
	r->table = t;
      }
  DBG("\tdone\n");
}

static uint
rt_feed_channel_net_internal(struct channel *c, net *nn, btime from, btime to)
{
  if (!nn->routes)
    return 0;

  if (c->ra_mode == RA_ANY)
  {
    uint cnt = 0;
    for (struct rte_storage *r = nn->routes; r; r = r->next)
      if (rte_is_valid(r) && (r->lastmod >= from) && (r->lastmod < to))
	cnt++;

    if (!cnt)
      return 0;

    struct rte_update *u = alloca(sizeof(struct rte_update) * cnt);
    uint i = 0;
    struct rte_storage *new_best = VALID_OR_NULL(nn->routes);
    for (struct rte_storage *r = nn->routes; r; r = r->next)
      if (rte_is_valid(r))
	u[i++] = (struct rte_update) { .new_best = new_best, .new = r };

    rte_export(c, u, cnt);
    return cnt;
  }
  else
  {
    struct rte_update u = { .new_best = nn->routes, .new = nn->routes };
    rte_export(c, &u, 1);
    return 1;
  }
}

uint
rt_feed_channel_net(struct channel *c, net_addr *n)
{
  net *nn = net_find(c->table, n);
  if (!nn)
    return 0;

  return rt_feed_channel_net_internal(c, nn, 0, TIME_INFINITY);
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
void
rt_feed_channel(struct channel *c)
{
  struct fib_iterator *fit = &c->feed_fit;
  int max_feed = 256;

  ASSERT(c->export_state == ES_FEEDING);
  ASSERT(!c->refeed_lastmod_max);

restart:
  FIB_ITERATE_INIT(fit, &c->table->fib);

  c->last_export = c->table->total_updates;
  c->refeed_lastmod_max = current_time();

wakeup:
  FIB_ITERATE_START(&c->table->fib, fit, net, n)
    {
      if (max_feed <= 0)
	{
	  FIB_ITERATE_PUT(fit);
	  ev_suspend();
	  goto wakeup;
	}

      max_feed -= rt_feed_channel_net_internal(c, n, c->refeed_lastmod_min, c->refeed_lastmod_max);
    }
  FIB_ITERATE_END;

  if (c->table->total_updates - c->last_export > RT_OBS_BUF_SIZE)
  {
    c->refeed_lastmod_min = c->refeed_lastmod_max;
    goto restart;
  }

  c->feed_active = 0;
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

static int
rte_update_in(rte *new)
{
  struct channel *c = new->sender;
  struct rtable *tab = c->in_table;
  struct rte_storage *old, **parent;
  net *net;

  if (new->attrs)
  {
    net = net_get(tab, new->net);

    if (!rta_is_cached(new->attrs))
      new->attrs = rta_lookup(new->attrs);
  }
  else
  {
    net = net_find(tab, new->net);

    if (!net)
      goto drop_withdraw;
  }

  /* Find the old rte */
  old = *(parent = rte_find(net, new->src));

  if (old)
    {
      if (new->attrs && rte_same(old, new, 0))
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
      *parent = old->next;

      rte_free(old);
      tab->rt_count--;
    }

  if (!new->attrs)
  {
    if (!old)
      goto drop_withdraw;

    return 1;
  }

  struct channel_limit *l = &c->rx_limit;
  if (l->action && !old)
  {
    if (tab->rt_count >= l->limit)
      channel_notify_limit(c, l, PLD_RX, tab->rt_count);

    if (l->state == PLS_BLOCKED)
    {
      rte_trace_in(D_FILTERS, c->proto, new, "ignored [limit]");
      goto drop_update;
    }
  }

  /* Insert the new rte */
  struct rte_storage *e = rte_store(new, net);
  e->lastmod = current_time();
  e->next = *parent;
  *parent = e;
  tab->rt_count++;
  return 1;

drop_update:
  c->stats.imp_updates_received++;
  c->stats.imp_updates_ignored++;
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
    for (struct rte_storage *e = c->reload_next_rte; e; e = e->next)
    {
      if (max_feed-- <= 0)
      {
	c->reload_next_rte = e;
	debug("%s channel reload burst split (max_feed=%d)", c->proto->name, max_feed);
	return 0;
      }

      rte eloc = rte_copy(e);
      rte_update2(&eloc);
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
  FIB_WALK(&t->fib, net, n)
  {
    struct rte_storage *e, **ee = &n->routes;
    while (e = *ee)
    {
      if (all || (e->flags & (REF_STALE | REF_DISCARD)))
      {
	*ee = e->next;
	rte_free(e);
	t->rt_count--;
      }
      else
	ee = &e->next;
    }
  }
  FIB_WALK_END;
}


/*
 *	Export table
 */

int
rte_update_out(struct channel *c, rte *new, rte *old, struct rte_storage **old_stored, int refeed)
{
  struct rtable *tab = c->out_table;
  struct rte_storage **pos;
  net *net;

  if (new->attrs)
  {
    net = net_get(tab, new->net);

    if (!rta_is_cached(new->attrs))
      new->attrs = rta_lookup(new->attrs);
  }
  else
  {
    net = net_find(tab, old->net);

    if (!net)
      goto drop_withdraw;
  }

  /* Find the old rte */
  if (c->ra_mode == RA_ANY)
    pos = rte_find(net, old->src);
  else
    pos = &net->routes;

  if (*pos)
  {
    if (new && rte_same(*pos, new, 0))
      goto drop_update;

    /* Keep the old rte */
    *old_stored = *pos;
    *old = rte_copy(*pos);

    /* Remove the old rte from the list */
    *pos = (*pos)->next;
    tab->rt_count--;
  }

  if (!new->attrs)
  {
    if (!*old_stored)
      goto drop_withdraw;

    return 1;
  }

  /* Insert the new rte */
  struct rte_storage *e = rte_store(new, net);
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
hc_alloc_table(struct hostcache *hc, unsigned order)
{
  uint hsize = 1 << order;
  hc->hash_order = order;
  hc->hash_shift = 32 - order;
  hc->hash_max = (order >= HC_HI_ORDER) ? ~0U : (hsize HC_HI_MARK);
  hc->hash_min = (order <= HC_LO_ORDER) ?  0U : (hsize HC_LO_MARK);

  hc->hash_table = mb_allocz(rt_table_pool, hsize * sizeof(struct hostentry *));
}

static void
hc_resize(struct hostcache *hc, unsigned new_order)
{
  struct hostentry **old_table = hc->hash_table;
  struct hostentry *he, *hen;
  uint old_size = 1 << hc->hash_order;
  uint i;

  hc_alloc_table(hc, new_order);
  for (i = 0; i < old_size; i++)
    for (he = old_table[i]; he != NULL; he=hen)
      {
	hen = he->next;
	hc_insert(hc, he);
      }
  mb_free(old_table);
}

static struct hostentry *
hc_new_hostentry(struct hostcache *hc, ip_addr a, ip_addr ll, rtable *dep, unsigned k)
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
    hc_resize(hc, hc->hash_order + HC_HI_STEP);

  return he;
}

static void
hc_delete_hostentry(struct hostcache *hc, struct hostentry *he)
{
  rta_free(he->src);

  rem_node(&he->ln);
  hc_remove(hc, he);
  sl_free(hc->slab, he);

  hc->hash_items--;
  if (hc->hash_items < hc->hash_min)
    hc_resize(hc, hc->hash_order - HC_LO_STEP);
}

static void
rt_init_hostcache(rtable *tab)
{
  struct hostcache *hc = mb_allocz(rt_table_pool, sizeof(struct hostcache));
  init_list(&hc->hostentries);

  hc->hash_items = 0;
  hc_alloc_table(hc, HC_DEF_ORDER);
  hc->slab = sl_new(rt_table_pool, sizeof(struct hostentry));

  hc->lp = lp_new(rt_table_pool, LP_GOOD_SIZE(1024));
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

  rfree(hc->slab);
  rfree(hc->lp);
  mb_free(hc->hash_table);
  mb_free(hc);
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
rt_get_igp_metric(rta *a)
{
  eattr *ea;

  if (ea = ea_find(a->eattrs, EA_GEN_IGP_METRIC))
    return ea->u.data;

#ifdef CONFIG_OSPF
  if ((a->source == RTS_OSPF) ||
      (a->source == RTS_OSPF_IA) ||
      (a->source == RTS_OSPF_EXT1))
    return ea_find(a->eattrs, EA_OSPF_METRIC1)->u.data;
#endif

#ifdef CONFIG_RIP
  if (ea = ea_find(a->eattrs, EA_RIP_METRIC))
    return ea->u.data;
#endif

#ifdef CONFIG_BGP
  if (a->source == RTS_BGP)
  {
    u64 metric = bgp_total_aigp_metric(a);
    return (u32) MIN(metric, (u64) IGP_METRIC_UNKNOWN);
  }
#endif

  if (a->source == RTS_DEVICE)
    return 0;

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
  net *n = net_route(tab, &he_addr); /* This always returns a valid route or NULL */
  if (n)
    {
      rta *a = n->routes->attrs;
      pxlen = n->n.addr->pxlen;

      if (a->hostentry)
	{
	  /* Recursive route should not depend on another recursive route */
	  log(L_WARN "Next hop address %I resolvable through recursive route for %N",
	      he->addr, n->n.addr);
	  goto done;
	}

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
      he->igp_metric = rt_get_igp_metric(a);
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
	  hc_delete_hostentry(hc, he);
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
  struct hostentry *he;

  if (!tab->hostcache)
    rt_init_hostcache(tab);

  u32 k = hc_hash(a, dep);
  struct hostcache *hc = tab->hostcache;
  for (he = hc->hash_table[k >> hc->hash_shift]; he != NULL; he = he->next)
    if (ipa_equal(he->addr, a) && (he->tab == dep))
      return he;

  he = hc_new_hostentry(hc, a, ipa_zero(ll) ? a : ll, dep, k);
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
