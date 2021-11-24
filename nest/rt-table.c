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
#include "lib/timer.h"
#include "lib/string.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/data.h"
#include "lib/hash.h"
#include "lib/string.h"
#include "lib/alloca.h"

#include <stdatomic.h>

pool *rt_table_pool;

list routing_tables;

/* Data structures for export journal */
#define RT_PENDING_EXPORT_ITEMS		(page_size - sizeof(struct rt_export_block)) / sizeof(struct rt_pending_export)

struct rt_export_block {
  node n;
  _Atomic u32 end;
  _Atomic _Bool not_last;
  struct rt_pending_export export[];
};

static void rt_free_hostcache(rtable_private *tab);
static void rt_notify_hostcache(rtable_private *tab, net *net);
static void rt_update_hostcache(void *tab);
static void rt_next_hop_update(void *tab);
static inline void rt_prune_table(void *tab);
static inline void rt_schedule_notify(rtable_private *tab);
static void rt_feed_channel(void *);

static inline void rt_export_used(rtable_private *tab);
static void rt_export_cleanup(void *tab);

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

struct event_cork rt_cork;

static inline void
rte_update_lock(struct channel *c)
{
  c->rte_update_nest_cnt++;
}

static inline void
rte_update_unlock(struct channel *c)
{
  if (!--c->rte_update_nest_cnt)
    lp_flush(c->rte_update_pool);
}

/* Like fib_route(), but skips empty net entries */
static inline void *
net_route_ip4(rtable_private *t, net_addr_ip4 *n)
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
net_route_ip6(rtable_private *t, net_addr_ip6 *n)
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
net_route_ip6_sadr(rtable_private *t, net_addr_ip6_sadr *n)
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
net_route(rtable_private *tab, const net_addr *n)
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
net_roa_check_ip4(rtable *t, const net_addr_ip4 *px, u32 asn)
{
  struct net_addr_roa4 n = NET_ADDR_ROA4(px->prefix, px->pxlen, 0, 0);
  struct fib_node *fn;
  int anything = 0;

  RT_LOCK(t);
  rtable_private *tab = RT_PRIV(t);

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
	{
	  RT_UNLOCK(tab);
	  return ROA_VALID;
	}
      }
    }

    if (n.pxlen == 0)
      break;

    n.pxlen--;
    ip4_clrbit(&n.prefix, n.pxlen);
  }

  RT_UNLOCK(tab);
  return anything ? ROA_INVALID : ROA_UNKNOWN;
}

static int
net_roa_check_ip6(rtable *t, const net_addr_ip6 *px, u32 asn)
{
  struct net_addr_roa6 n = NET_ADDR_ROA6(px->prefix, px->pxlen, 0, 0);
  struct fib_node *fn;
  int anything = 0;

  RT_LOCK(t);
  rtable_private *tab = RT_PRIV(t);

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
	{
	  RT_UNLOCK(tab);
	  return ROA_VALID;
	}
      }
    }

    if (n.pxlen == 0)
      break;

    n.pxlen--;
    ip6_clrbit(&n.prefix, n.pxlen);
  }

  RT_UNLOCK(tab);
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
rte_store(const rte *r, net *net, rtable_private *tab)
{
  struct rte_storage *e = sl_alloc(tab->rte_slab);

  e->rte = *r;
  e->rte.net = net->n.addr;

  rt_lock_source(e->rte.src);

  if (e->rte.attrs->cached)
    e->rte.attrs = rta_clone(e->rte.attrs);
  else
    e->rte.attrs = rta_lookup(e->rte.attrs);

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
rte_free(struct rte_storage *e, rtable_private *tab)
{
  rt_unlock_source(e->rte.src);
  rta_free(e->rte.attrs);
  sl_free(tab->rte_slab, e);
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

  if (pri->attrs->pref != sec->attrs->pref)
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
  log(L_TRACE "%s %c %s %N src %uL %uG %uS id %u %s%s",
      name, dir, msg, e->net,
      e->src->private_id, e->src->global_id, e->stale_cycle, e->id,
      rta_dest_name(e->attrs->dest),
      rte_is_filtered(e) ? " (filtered)" : "");
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
    if (rte_is_valid(RTES_OR_NULL(e)))
      count++;
  return count;
}

static void
rte_feed_obtain(net *n, struct rte **feed, uint count)
{
  uint i = 0;
  for (struct rte_storage *e = n->routes; e; e = e->next)
    if (rte_is_valid(RTES_OR_NULL(e)))
    {
      ASSERT_DIE(i < count);
      feed[i++] = &e->rte;
    }
  ASSERT_DIE(i == count);
}

static rte *
export_filter_(struct channel *c, rte *rt, linpool *pool, int silent)
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
		 (f_run(filter, rt, pool,
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

static inline rte *
export_filter(struct channel *c, rte *rt, int silent)
{
  return export_filter_(c, rt, c->rte_update_pool, silent);
}

void do_rt_notify_direct(struct channel *c, const net_addr *net, rte *new, const rte *old);

static void
do_rt_notify(struct channel *c, const net_addr *net, rte *new, const rte *old)
{
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

  /* Store route export state */
  if (old)
    bmap_clear(&c->export_map, old->id);

  if (new)
    bmap_set(&c->export_map, new->id);

  /* Apply export table */
  if (c->out_table)
    rte_import(&c->out_table->push, net, new, old ? old->src : new->src);
  else
    do_rt_notify_direct(c, net, new, old);
}

void
do_rt_notify_direct(struct channel *c, const net_addr *net, rte *new, const rte *old)
{
  struct proto *p = c->proto;
  struct channel_export_stats *stats = &c->export_stats;

  if (new)
    stats->updates_accepted++;
  else
    stats->withdraws_accepted++;

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
  if (new)
    new = export_filter(c, new, 0);

  if (old && !bmap_test(&c->export_map, old->id))
    old = NULL;

  if (old && (old->sender == c->in_req.hook))
    bug("bad-behaved pipe");

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
rt_notify_accepted(struct rt_export_request *req, const net_addr *n, struct rt_pending_export *rpe,
    struct rte **feed, uint count)
{
  struct channel *c = SKIP_BACK(struct channel, out_req, req);

  rte_update_lock(c);

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
  while (rpe)
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
    rpe = rpe_next(rpe, NULL);
  }

  /* Nothing to export */
  if (new_best || old_best)
    do_rt_notify(c, n, new_best, old_best);
  else
    DBG("rt_notify_accepted: nothing to export\n");

  rte_update_unlock(c);
}


static struct nexthop *
nexthop_merge_rta(struct nexthop *nhs, rta *a, linpool *pool, int max)
{
  return nexthop_merge(nhs, &(a->nh), 1, 0, max, pool);
}

rte *
rt_export_merged(struct channel *c, struct rte **feed, uint count, linpool *pool, int silent)
{
  _Thread_local static rte rloc;

  // struct proto *p = c->proto;
  struct nexthop *nhs = NULL;
  rte *best0 = feed[0];
  rte *best = NULL;

  if (!rte_is_valid(best0))
    return NULL;

  /* Already rejected, no need to re-run the filter */
  if (!c->refeeding && bmap_test(&c->export_reject_map, best0->id))
    return NULL;

  rloc = *best0;
  best = export_filter_(c, &rloc, pool, silent);

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
    rte *tmp = export_filter_(c, &tmp0, pool, 1);

    if (!tmp || !rte_is_reachable(tmp))
      continue;

    nhs = nexthop_merge_rta(nhs, tmp->attrs, pool, c->merge_limit);
  }

  if (nhs)
  {
    nhs = nexthop_merge_rta(nhs, best->attrs, pool, c->merge_limit);

    if (nhs->next)
    {
      best->attrs = rta_cow(best->attrs, pool);
      nexthop_link(best->attrs, nhs);
    }
  }

  return best;
}

void
rt_notify_merged(struct rt_export_request *req, const net_addr *n, struct rt_pending_export *rpe,
    struct rte **feed, uint count)
{
  struct channel *c = SKIP_BACK(struct channel, out_req, req);

  rte_update_lock(c);
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
  while (rpe)
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
    rpe = rpe_next(rpe, NULL);
  }

  /* Prepare new merged route */
  rte *new_merged = count ? rt_export_merged(c, feed, count, c->rte_update_pool, 0) : NULL;

  if (new_merged || old_best)
    do_rt_notify(c, n, new_merged, old_best);

  rte_update_unlock(c);
}

void
rt_notify_optimal(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *rpe)
{
  struct channel *c = SKIP_BACK(struct channel, out_req, req);
  rte_update_lock(c);
  rte *old = RTES_OR_NULL(rpe->old_best);
  struct rte_storage *new_best = rpe->new_best;

  while (rpe)
  {
    channel_rpe_mark_seen(req, rpe);
    new_best = rpe->new_best;
    rpe = rpe_next(rpe, NULL);
  }

  if (&new_best->rte != old)
  {
    rte n0, *new = RTES_CLONE(new_best, &n0);
    rt_notify_basic(c, net, new, old);
  }

  rte_update_unlock(c);
}

void
rt_notify_any(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *rpe)
{
  struct channel *c = SKIP_BACK(struct channel, out_req, req);
  rte_update_lock(c);
  struct rte_src *src = rpe->new ? rpe->new->rte.src : rpe->old->rte.src;
  rte *old = RTES_OR_NULL(rpe->old);
  struct rte_storage *new_any = rpe->new;

  while (rpe)
  {
    channel_rpe_mark_seen(req, rpe);
    new_any = rpe->new;
    rpe = rpe_next(rpe, src);
  }

  if (&new_any->rte != old)
  {
    rte n0, *new = RTES_CLONE(new_any, &n0);
    rt_notify_basic(c, net, new, old);
  }

  rte_update_unlock(c);
}

void
rt_feed_any(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *rpe UNUSED, rte **feed, uint count)
{
  struct channel *c = SKIP_BACK(struct channel, out_req, req);
  rte_update_lock(c);

  for (uint i=0; i<count; i++)
  {
    rte n0 = *feed[i];
    rt_notify_basic(c, net, &n0, NULL);
  }

  rte_update_unlock(c);
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
static void
rte_export(struct rt_export_hook *hook, struct rt_pending_export *rpe)
{
  if (bmap_test(&hook->seq_map, rpe->seq))
    goto seen;

  const net_addr *n = rpe->new_best ? rpe->new_best->rte.net : rpe->old_best->rte.net;

  if (rpe->new)
    hook->stats.updates_received++;
  else
    hook->stats.withdraws_received++;

  if (hook->req->export_one)
    hook->req->export_one(hook->req, n, rpe);
  else if (hook->req->export_bulk)
  {
    RT_LOCK(hook->table);
    net *net = SKIP_BACK(struct network, n.addr, (net_addr (*)[0]) n);
    uint count = rte_feed_count(net);
    rte **feed = NULL;
    if (count)
    {
      feed = alloca(count * sizeof(rte *));
      rte_feed_obtain(net, feed, count);
    }
    RT_UNLOCK(hook->table);
    hook->req->export_bulk(hook->req, n, rpe, feed, count);
  }
  else
    bug("Export request must always provide an export method");

seen:
  /* Get the next export if exists */
  hook->rpe_next = rt_next_export_fast(rpe);

  /* The last block may be available to free */
  if (PAGE_HEAD(hook->rpe_next) != PAGE_HEAD(rpe))
  {
    RT_LOCK(hook->table);
    rt_export_used(RT_PRIV(hook->table));
    RT_UNLOCK(hook->table);
  }

  /* Releasing this export for cleanup routine */
  DBG("store hook=%p last_export=%p seq=%lu\n", hook, rpe, rpe->seq);
  atomic_store_explicit(&hook->last_export, rpe, memory_order_release);
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
rte_announce(rtable_private *tab, net *net, struct rte_storage *new, struct rte_storage *old,
	     struct rte_storage *new_best, struct rte_storage *old_best)
{
  if (!new_best || !rte_is_valid(&new_best->rte))
    new_best = NULL;

  if (!old_best || !rte_is_valid(&old_best->rte))
    old_best = NULL;

  if (!new || !rte_is_valid(&new->rte))
    new = NULL;

  if (old && !rte_is_valid(&old->rte))
  {
    /* Filtered old route isn't announced, should be freed immediately. */
    rte_free(old, tab);
    old = NULL;
  }

  if ((new == old) && (new_best == old_best))
    return;

  if (new_best != old_best)
  {
    if (new_best)
      new_best->rte.sender->stats.pref++;
    if (old_best)
      old_best->rte.sender->stats.pref--;

    if (tab->hostcache)
      rt_notify_hostcache(tab, net);
  }

  if (EMPTY_LIST(tab->exports) && EMPTY_LIST(tab->pending_exports))
  {
    /* No export hook and no pending exports to cleanup. We may free the route immediately. */
    if (!old)
      return;

    hmap_clear(&tab->id_map, old->rte.id);
    rte_free(old, tab);
    return;
  }

  /* Get the pending export structure */
  struct rt_export_block *rpeb = NULL, *rpebsnl = NULL;
  u32 end = 0;

  if (!EMPTY_LIST(tab->pending_exports))
  {
    rpeb = TAIL(tab->pending_exports);
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
    rpeb = alloc_page(tab->rp);
    *rpeb = (struct rt_export_block) {};
    add_tail(&tab->pending_exports, &rpeb->n);
  }

  /* Fill the pending export */
  struct rt_pending_export *rpe = &rpeb->export[rpeb->end];
  *rpe = (struct rt_pending_export) {
    .new = new,
    .new_best = new_best,
    .old = old,
    .old_best = old_best,
    .seq = tab->next_export_seq++,
  };

  DBG("rte_announce: table=%s net=%N new=%p from %p old=%p from %p new_best=%p old_best=%p seq=%lu\n", tab->name, net->n.addr, new, new ? new->sender : NULL, old, old ? old->sender : NULL, new_best, old_best, rpe->seq);

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

  if (tab->first_export == NULL)
    tab->first_export = rpe;

  if (!EMPTY_LIST(tab->exports) &&
      (tab->first_export->seq + tab->config->cork_limit <= tab->next_export_seq) &&
      !tab->cork_active)
  {
    if (config->table_debug)
      log(L_TRACE "%s: cork activated", tab->name);

    ev_cork(&rt_cork);
    tab->cork_active = 1;
  }
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
rt_next_export(struct rt_export_hook *hook, rtable_private *tab)
{
  /* As the table is locked, it is safe to reload the last export pointer */
  struct rt_pending_export *last = atomic_load_explicit(&hook->last_export, memory_order_acquire);

  /* It is still valid, let's reuse it */
  if (last)
    return rt_next_export_fast(last);

  /* No, therefore we must process the table's first pending export */
  else
    return tab->first_export;
}

static inline void
rt_send_export_event(struct rt_export_hook *hook)
{
  ev_send(hook->req->list, hook->event);
}

static void
rt_announce_exports(void *data)
{
  rtable_private *tab = data;
  ASSERT_DIE(birdloop_inside(tab->loop));

  rt_schedule_notify(tab);

  struct rt_export_hook *c; node *n;
  WALK_LIST2(c, n, tab->exports, n)
  {
    if (atomic_load_explicit(&c->export_state, memory_order_acquire) != TES_READY)
      continue;

    rt_send_export_event(c);
  }
}

static void
rt_import_announce_exports(void *data)
{
  struct rt_import_hook *hook = data;
  RT_LOCKED(hook->table, tab)
  {
    if (hook->import_state == TIS_CLEARED)
    {
      rfree(hook->export_announce_event);

      ev_send(hook->stopped->list, hook->stopped);
      rem_node(&hook->n);
      mb_free(hook);
      rt_unlock_table(tab);
    }
    else
      ev_send_loop(tab->loop, tab->announce_event);
  }
}

static struct rt_pending_export *
rt_last_export(rtable_private *tab)
{
  struct rt_pending_export *rpe = NULL;

  if (!EMPTY_LIST(tab->pending_exports))
  {
    /* We'll continue processing exports from this export on */
    struct rt_export_block *reb = TAIL(tab->pending_exports);
    ASSERT_DIE(reb->end);
    rpe = &reb->export[reb->end - 1];
  }

  return rpe;
}

#define RT_EXPORT_BULK	1024

static void
rt_export_hook(void *_data)
{
  struct rt_export_hook *c = _data;

  ASSERT_DIE(atomic_load_explicit(&c->export_state, memory_order_relaxed) == TES_READY);

  if (!c->rpe_next)
  {
    RT_LOCK(c->table);
    c->rpe_next = rt_next_export(c, RT_PRIV(c->table));

    if (!c->rpe_next)
    {
      rt_export_used(RT_PRIV(c->table));
      RT_UNLOCK(c->table);
      return;
    }

    RT_UNLOCK(c->table);
  }

  /* Process the export */
  for (uint i=0; i<RT_EXPORT_BULK; i++)
  {
    rte_export(c, c->rpe_next);

    if (!c->rpe_next)
      break;
  }

  rt_send_export_event(c);
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

  if (net_type_match(n, NB_DEST) == !e->attrs->dest)
  {
    log(L_WARN "Ignoring route %N with invalid dest %d received via %s",
	n, e->attrs->dest, ch->proto->name);
    return 0;
  }

  if ((e->attrs->dest == RTD_UNICAST) && !nexthop_is_sorted(&(e->attrs->nh)))
  {
    log(L_WARN "Ignoring unsorted multipath route %N received via %s",
	n, ch->proto->name);
    return 0;
  }

  return 1;
}

static int
rte_same(rte *x, rte *y)
{
  /* rte.flags are not checked, as they are mostly internal to rtable */
  return
    x->attrs == y->attrs &&
    x->pflags == y->pflags &&
    x->src == y->src &&
    rte_is_filtered(x) == rte_is_filtered(y);
}

static inline int rte_is_ok(rte *e) { return e && !rte_is_filtered(e); }

static void
rte_recalculate(rtable_private *table, struct rt_import_hook *c, net *net, rte *new, struct rte_src *src)
{
  struct rt_import_request *req = c->req;
  struct rt_import_stats *stats = &c->stats;
  struct rte_storage *old_best_stored = net->routes, *old_stored = NULL;
  rte *old_best = old_best_stored ? &old_best_stored->rte : NULL;
  rte *old = NULL;

  /* Set the stale cycle unless already set */
  if (new && !(new->flags & REF_USE_STALE))
    new->stale_cycle = c->stale_set;

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

	  if (new && rte_same(old, new))
	    {
	      /* No changes, ignore the new route and refresh the old one */
	      old->stale_cycle = new->stale_cycle;

	      if (!rte_is_filtered(new))
		{
		  stats->updates_ignored++;
		  rt_rte_trace_in(D_ROUTES, req, new, "ignored");
		}
	      return;
	  }

	*before_old = (*before_old)->next;
	table->rt_count--;
    }

  if (!old && !new)
    {
      stats->withdraws_ignored++;
      return;
    }

  if (req->preimport)
    new = req->preimport(req, new, old);

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

  struct rte_storage *new_stored = new ? rte_store(new, net, table) : NULL;

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

  _Bool nb = (new_stored == net->routes);
  _Bool ob = (old_best == old);

  /* Log the route change */
  if (new_ok && old_ok)
    {
      const char *best_indicator[2][2] = { { "updated", "updated [-best]" }, { "updated [+best]", "updated [best]" } };
      rt_rte_trace_in(D_ROUTES, req, &new_stored->rte, best_indicator[nb][ob]);
    }
  else if (new_ok)
    rt_rte_trace_in(D_ROUTES, req, &new_stored->rte,
	(!net->routes->next || !rte_is_ok(&net->routes->next->rte)) ? "added [sole]" :
	nb ? "added [best]" : "added");
  else if (old_ok)
    rt_rte_trace_in(D_ROUTES, req, old,
	(!net->routes || !rte_is_ok(&net->routes->rte)) ? "removed [sole]" :
	ob ? "removed [best]" : "removed");

  /* Propagate the route change */
  rte_announce(table, net, new_stored, old_stored,
      net->routes, old_best_stored);

  ev_send(req->list, c->export_announce_event);

  if (!net->routes &&
      (table->gc_counter++ >= table->config->gc_max_ops) &&
      (table->gc_time + table->config->gc_min_time <= current_time()))
    rt_schedule_prune(table);

#if 0
  /* Enable and reimplement these callbacks if anybody wants to use them */
  if (old_ok && p->rte_remove)
    p->rte_remove(net, old);
  if (new_ok && p->rte_insert)
    p->rte_insert(net, &new_stored->rte);
#endif

}

rte *
channel_preimport(struct rt_import_request *req, rte *new, rte *old)
{
  struct channel *c = SKIP_BACK(struct channel, in_req, req);

  if (!c->in_table)
  {
    if (new && !old)
      if (CHANNEL_LIMIT_PUSH(c, RX))
	return NULL;

    if (!new && old)
      CHANNEL_LIMIT_POP(c, RX);
  }

  int new_in = new && !rte_is_filtered(new);
  int old_in = old && !rte_is_filtered(old);

  if (new_in && !old_in)
    if (CHANNEL_LIMIT_PUSH(c, IN))
      if (c->in_keep_filtered)
      {
	new->flags |= REF_FILTERED;
	return new;
      }
      else
	return NULL;

  if (!new_in && old_in)
    CHANNEL_LIMIT_POP(c, IN);

  return new;
}

rte *
channel_in_preimport(struct rt_import_request *req, rte *new, rte *old)
{
  struct channel_aux_table *cat = SKIP_BACK(struct channel_aux_table, push, req);

  if (new && !old)
    if (CHANNEL_LIMIT_PUSH(cat->c, RX))
      return NULL;

  if (!new && old)
    CHANNEL_LIMIT_POP(cat->c, RX);

  return new;
}

void rte_update_direct(struct channel *c, const net_addr *n, rte *new, struct rte_src *src);

void
rte_update(struct channel *c, const net_addr *n, rte *new, struct rte_src *src)
{
  if (!c->in_req.hook)
    return;

  ASSERT(c->channel_state == CS_UP);

  if (c->in_table)
    rte_import(&c->in_table->push, n, new, src);
  else
    rte_update_direct(c, n, new, src);
}

void
rte_update_direct(struct channel *c, const net_addr *n, rte *new, struct rte_src *src)
{
  const struct filter *filter = c->in_filter;
  struct channel_import_stats *stats = &c->import_stats;

  rte_update_lock(c);
  if (new)
    {
      new->net = n;

      int fr;

      stats->updates_received++;
      if (!rte_validate(c, new))
	{
	  channel_rte_trace_in(D_FILTERS, c, new, "invalid");
	  stats->updates_invalid++;
	  new = NULL;
	}
      else if ((filter == FILTER_REJECT) ||
	((fr = f_run(filter, new, c->rte_update_pool, 0)) > F_ACCEPT))
	{
	  stats->updates_filtered++;
	  channel_rte_trace_in(D_FILTERS, c, new, "filtered out");

	  if (c->in_keep_filtered)
	    new->flags |= REF_FILTERED;
	  else
	    new = NULL;
	}
    }
  else
    stats->withdraws_received++;

  rte_import(&c->in_req, n, new, src);

  rte_update_unlock(c);
}

void
rte_import(struct rt_import_request *req, const net_addr *n, rte *new, struct rte_src *src)
{
  struct rt_import_hook *hook = req->hook;
  if (!hook)
    return;

  RT_LOCK(hook->table);
  rtable_private *tab = RT_PRIV(hook->table);

  net *nn;
  if (new)
    {
      /* Use the actual struct network, not the dummy one */
      nn = net_get(tab, n);
      new->net = nn->n.addr;
      new->sender = hook;
    }
  else if (!(nn = net_find(tab, n)))
    {
      req->hook->stats.withdraws_ignored++;
      RT_UNLOCK(tab);
      return;
    }

  /* And recalculate the best route */
  rte_recalculate(tab, hook, nn, new, src);
  RT_UNLOCK(tab);
}

/* Check rtable for best route to given net whether it would be exported do p */
int
rt_examine(rtable_private *t, net_addr *a, struct channel *c, const struct filter *filter)
{
  net *n = net_find(t, a);

  if (!n || !n->routes)
    return 0;

  rte rt = n->routes->rte;

  if (!rte_is_valid(&rt))
    return 0;

  rte_update_lock(c);

  /* Rest is stripped down export_filter() */
  int v = c->proto->preexport ? c->proto->preexport(c, &rt) : 0;
  if (v == RIC_PROCESS)
    v = (f_run(filter, &rt, c->rte_update_pool, FF_SILENT) <= F_ACCEPT);

  rte_update_unlock(c);

  return v > 0;
}

static void
rt_export_stopped(void *data)
{
  struct rt_export_hook *hook = data;

  RT_LOCKED(hook->table, tab)
  {
    /* Drop pending exports */
    rt_export_used(tab);

    /* Unlist */
    rem_node(&hook->n);
  }

  /* Report the channel as stopped. */
  hook->stopped(hook->req);

  RT_LOCKED(hook->table, tab)
  {
    /* Free the hook together with its coroutine. */
    rfree(hook->pool);
    rt_unlock_table(tab);

    DBG("Export hook %p in table %s finished uc=%u\n", hook, tab->name, tab->use_count);
  }
}


static inline void
rt_set_import_state(struct rt_import_hook *hook, u8 state)
{
  hook->last_state_change = current_time();
  hook->import_state = state;

  if (hook->req->log_state_change)
    hook->req->log_state_change(hook->req, state);
}

static inline void
rt_set_export_state(struct rt_export_hook *hook, u8 state)
{
  hook->last_state_change = current_time();
  atomic_store_explicit(&hook->export_state, state, memory_order_release);

  if (hook->req->log_state_change)
    hook->req->log_state_change(hook->req, state);
}

void
rt_request_import(rtable *t, struct rt_import_request *req)
{
  RT_LOCK(t);
  rtable_private *tab = RT_PRIV(t);
  rt_lock_table(tab);

  struct rt_import_hook *hook = req->hook = mb_allocz(tab->rp, sizeof(struct rt_import_hook));

  DBG("Lock table %s for import %p req=%p uc=%u\n", tab->name, hook, req, tab->use_count);

  hook->req = req;
  hook->table = t;

  hook->export_announce_event = ev_new_init(tab->rp, rt_import_announce_exports, hook);

  if (!hook->stale_set)
    hook->stale_set = hook->stale_valid = hook->stale_pruning = hook->stale_pruned = 1;

  rt_set_import_state(hook, TIS_UP);

  hook->n = (node) {};
  add_tail(&tab->imports, &hook->n);

  RT_UNLOCK(t);
}

void
rt_stop_import(struct rt_import_request *req, event *stopped)
{
  ASSERT_DIE(req->hook);
  struct rt_import_hook *hook = req->hook;

  rtable_private *tab = RT_LOCK(hook->table);

  rt_schedule_prune(tab);

  rt_set_import_state(hook, TIS_STOP);
  hook->stopped = stopped;

  if (hook->stale_set < hook->stale_valid)
    if (!--tab->rr_count)
      rt_schedule_notify(tab);

  RT_UNLOCK(tab);
}

void
rt_request_export(rtable *t, struct rt_export_request *req)
{
  RT_LOCK(t);
  rtable_private *tab = RT_PRIV(t);
  rt_lock_table(tab);

  pool *p = rp_new(tab->rp, "Export hook");
  struct rt_export_hook *hook = req->hook = mb_allocz(p, sizeof(struct rt_export_hook));
  hook->pool = p;
  
  hook->req = req;
  hook->table = t;

  /* stats zeroed by mb_allocz */

  bmap_init(&hook->seq_map, p, 1024);

  rt_set_export_state(hook, TES_HUNGRY);

  hook->n = (node) {};
  add_tail(&tab->exports, &hook->n);

  DBG("New export hook %p req %p in table %s uc=%u\n", hook, req, tab->name, tab->use_count);

  hook->event = ev_new_init(p, rt_feed_channel, hook);
  RT_UNLOCK(t);

  rt_send_export_event(hook);
}

void
rt_stop_export(struct rt_export_request *req, void (*stopped)(struct rt_export_request *))
{
  ASSERT_DIE(req->hook);
  struct rt_export_hook *hook = req->hook;

  RT_LOCK(hook->table);
  rtable_private *tab = RT_PRIV(hook->table);

  /* Stop feeding */
  ev_postpone(hook->event);

  if (atomic_load_explicit(&hook->export_state, memory_order_relaxed) == TES_FEEDING)
    fit_get(&tab->fib, &hook->feed_fit);

  hook->event->hook = rt_export_stopped;
  hook->stopped = stopped;

  rt_send_export_event(hook);

  RT_UNLOCK(hook->table);

  rt_set_export_state(hook, TES_STOP);
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
 * implemented by setting rte->stale_cycle to req->stale_set in rte_update()
 * and then dropping all routes with old stale_cycle values in table prune loop. */
void
rt_refresh_begin(struct rt_import_request *req)
{
  struct rt_import_hook *hook = req->hook;
  ASSERT_DIE(hook);

  RT_LOCK(hook->table);
  rtable_private *tab = RT_PRIV(hook->table);

  ASSERT_DIE(hook->stale_set == hook->stale_valid);

  /* If the pruning routine is too slow */
  if ((hook->stale_pruned < hook->stale_valid) && (hook->stale_pruned + 128 < hook->stale_valid)
      || (hook->stale_pruned > hook->stale_valid) && (hook->stale_pruned > hook->stale_valid + 128))
  {
    log(L_WARN "Route refresh flood in table %s", tab->name);
    FIB_WALK(&tab->fib, net, n)
      {
	for (struct rte_storage *e = n->routes; e; e = e->next)
	  if (e->rte.sender == req->hook)
	    e->rte.stale_cycle = 0;
      }
    FIB_WALK_END;
    hook->stale_set = 1;
    hook->stale_valid = 0;
    hook->stale_pruned = 0;
  }
  else if (!++hook->stale_set)
  {
    /* Let's reserve the stale_cycle zero value for always-invalid routes */
    hook->stale_set = 1;
    hook->stale_valid = 0;
  }

  tab->rr_count++;

  if (req->trace_routes & D_STATES)
    log(L_TRACE "%s: route refresh begin [%u]", req->name, hook->stale_set);

  RT_UNLOCK(tab);
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

  rtable_private *tab = RT_LOCK(hook->table);
  hook->stale_valid++;
  ASSERT_DIE(hook->stale_set == hook->stale_valid);

  rt_schedule_prune(tab);

  if (req->trace_routes & D_STATES)
    log(L_TRACE "%s: route refresh end [%u]", req->name, hook->stale_valid);

  if (!--tab->rr_count)
    rt_schedule_notify(tab);

  RT_UNLOCK(tab);
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
  rta_dump(e->rte.attrs);
  debug("\n");
}

/**
 * rt_dump - dump a routing table
 * @t: routing table to be dumped
 *
 * This function dumps contents of a given routing table to debug output.
 */
void
rt_dump(rtable *tab)
{
  RT_LOCK(tab);
  rtable_private *t = RT_PRIV(tab);
  debug("Dump of routing table <%s>%s\n", t->name, t->delete_event ? " (deleted)" : "");
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
  RT_UNLOCK(tab);
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

void
rt_dump_hooks(rtable *t)
{
  RT_LOCK(t);
  rtable_private *tab = RT_PRIV(t);
  debug("Dump of hooks in routing table <%s>%s\n", tab->name, tab->delete_event ? " (deleted)" : "");
  debug("  nhu_state=%u hcu_scheduled=%u use_count=%d rt_count=%u\n",
      atomic_load(&tab->nhu_state), ev_active(tab->hcu_event), tab->use_count, tab->rt_count);
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

  struct rt_export_hook *eh;
  WALK_LIST(eh, tab->exports)
  {
    eh->req->dump_req(eh->req);
    debug("  Export hook %p requested by %p:"
       " refeed_pending=%u last_state_change=%t export_state=%u\n",
       eh, eh->req, eh->refeed_pending, eh->last_state_change, atomic_load_explicit(&eh->export_state, memory_order_relaxed));
  }
  debug("\n");
  RT_UNLOCK(t);
}

void
rt_dump_hooks_all(void)
{
  rtable *t;
  node *n;

  debug("Dump of all table hooks\n");

  WALK_LIST2(t, n, routing_tables, n)
    rt_dump_hooks(t);
}

static inline void
rt_schedule_nhu(rtable *tab)
{
  atomic_fetch_or_explicit(&tab->nhu_state, NHU_SCHEDULED, memory_order_acq_rel);
  ev_send_loop(tab->loop, tab->nhu_event);

  /* state change:
   *   NHU_CLEAN   -> NHU_SCHEDULED
   *   NHU_RUNNING -> NHU_DIRTY
   */
}

void
rt_schedule_prune(rtable_private *tab)
{
  if (tab->prune_state == 0)
    ev_send_loop(tab->loop, tab->prune_event);

  /* state change 0->1, 2->3 */
  tab->prune_state |= 1;
}

void
rt_export_used(rtable_private *tab)
{
  if (config->table_debug)
    log(L_TRACE "%s: Export cleanup requested", tab->name);

  ev_send_loop(tab->loop, tab->ec_event);
}

static inline btime
rt_settled_time(rtable_private *tab)
{
  ASSUME(tab->base_settle_time != 0);

  btime min_settle_time = tab->rr_count ? tab->config->min_rr_settle_time : tab->config->min_settle_time;
  btime max_settle_time = tab->rr_count ? tab->config->max_rr_settle_time : tab->config->max_settle_time;

  DBG("settled time computed from %t %t %t %t as %t / %t, now is %t\n",
      tab->name, tab->last_rt_change, min_settle_time,
	     tab->base_settle_time, max_settle_time,
	     tab->last_rt_change + min_settle_time,
	     tab->base_settle_time + max_settle_time, current_time());

  return MIN(tab->last_rt_change + min_settle_time,
	     tab->base_settle_time + max_settle_time);
}

static void
rt_settle_timer(timer *t)
{
  rtable_private *tab = t->data;
  ASSERT_DIE(birdloop_inside(tab->loop));

  if (!tab->base_settle_time)
    return;

  btime settled_time = rt_settled_time(tab);
  if (current_time() < settled_time)
  {
    tm_set_in(tab->settle_timer, settled_time, tab->loop);
    return;
  }

  /* Settled */
  tab->base_settle_time = 0;

  struct rt_subscription *s;
  WALK_LIST(s, tab->subscribers)
    ev_send(s->event->list, s->event);
}

static void
rt_kick_settle_timer(rtable_private *tab)
{
  tab->base_settle_time = current_time();

  if (!tab->settle_timer)
    tab->settle_timer = tm_new_init(tab->rp, rt_settle_timer, tab, 0, 0);

  if (!tm_active(tab->settle_timer))
    tm_set_in(tab->settle_timer, rt_settled_time(tab), tab->loop);
}

static inline void
rt_schedule_notify(rtable_private *tab)
{
  if (EMPTY_LIST(tab->subscribers))
    return;

  if (tab->base_settle_time)
    return;

  rt_kick_settle_timer(tab);
}

void
rt_subscribe(rtable *t, struct rt_subscription *s)
{
  s->tab = t;
  RT_LOCKED(t, tab)
  {
    rt_lock_table(tab);
    DBG("rt_subscribe(%s)\n", tab->name);
    add_tail(&tab->subscribers, &s->n);
  }
}

void
rt_unsubscribe(struct rt_subscription *s)
{
  RT_LOCKED(s->tab, tab)
  {
    rem_node(&s->n);
    if (EMPTY_LIST(tab->subscribers) && tm_active(tab->settle_timer))
      tm_stop(tab->settle_timer);
    rt_unlock_table(tab);
  }
}

static void
rt_free(resource *_r)
{
  rtable_private *r = (rtable_private *) _r;

  DBG("Deleting routing table %s\n", r->name);
  ASSERT_DIE(r->use_count == 0);
  ASSERT_DIE(r->rt_count == 0);
  ASSERT_DIE(!r->cork_active);
  ASSERT_DIE(EMPTY_LIST(r->imports));
  ASSERT_DIE(EMPTY_LIST(r->exports));

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
  RT_LOCKED((rtable *) _r, r)
  debug("name \"%s\", addr_type=%s, rt_count=%u, use_count=%d\n",
      r->name, net_label[r->addr_type], r->rt_count, r->use_count);
}

static struct resclass rt_class = {
  .name = "Routing table",
  .size = sizeof(rtable_private),
  .free = rt_free,
  .dump = rt_res_dump,
  .lookup = NULL,
  .memsize = NULL,
};

rtable *
rt_setup(pool *pp, struct rtable_config *cf)
{
  int ns = strlen("Routing table ") + strlen(cf->name) + 1;
  void *nb = mb_alloc(pp, ns);
  ASSERT_DIE(ns - 1 == bsnprintf(nb, ns, "Routing table %s", cf->name));

  pool *p = rp_new(pp, nb);

  rtable_private *t = ralloc(p, &rt_class);
  t->rp = p;

  t->rte_slab = sl_new(p, sizeof(struct rte_storage));

  t->name = cf->name;
  t->config = cf;
  t->addr_type = cf->addr_type;

  fib_init(&t->fib, p, t->addr_type, sizeof(net), OFFSETOF(net, n), 0, NULL);

  init_list(&t->imports);
  init_list(&t->exports);

  hmap_init(&t->id_map, p, 1024);
  hmap_set(&t->id_map, 0);

  init_list(&t->pending_exports);
  init_list(&t->subscribers);

  t->loop = birdloop_new(p, DOMAIN_ORDER(rtable), nb);

  t->announce_event = ev_new_init(p, rt_announce_exports, t);
  t->ec_event = ev_new_init(p, rt_export_cleanup, t);
  t->prune_event = ev_new_init(p, rt_prune_table, t);
  t->hcu_event = ev_new_init(p, rt_update_hostcache, t);
  t->nhu_event = ev_new_init(p, rt_next_hop_update, t);

  t->nhu_event->cork = &rt_cork;
  t->prune_event->cork = &rt_cork;

  t->last_rt_change = t->gc_time = current_time();
  t->next_export_seq = 1;

  t->rl_pipe = (struct tbf) TBF_DEFAULT_LOG_LIMITS;

  t->nhu_lp = lp_new_default(p);

  mb_move(nb, p);
  return (rtable *) t;
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
  ev_init_cork(&rt_cork, "Route Table Cork");
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
rt_prune_table(void *data)
{
  rtable_private *tab = data;
  ASSERT_DIE(birdloop_inside(tab->loop));

  struct fib_iterator *fit = &tab->prune_fit;
  int limit = 512;

  struct rt_import_hook *ih;
  node *n, *x;

  DBG("Pruning route table %s\n", tab->name);
#ifdef DEBUGGING
  fib_check(&tab->fib);
#endif

  if (tab->prune_state == 0)
    return;

  rt_lock_table(tab);

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
  }

again:
  FIB_ITERATE_START(&tab->fib, fit, net, n)
    {
    rescan:
      for (struct rte_storage *e=n->routes; e; e=e->next)
      {
	struct rt_import_hook *s = e->rte.sender;

	if ((s->import_state == TIS_FLUSHING) ||
	    (e->rte.stale_cycle < s->stale_valid) ||
	    (e->rte.stale_cycle > s->stale_set))
	  {
	    if (limit <= 0)
	      {
		FIB_ITERATE_PUT(fit);
		ev_send_loop(tab->loop, tab->prune_event);
		rt_unlock_table(tab);
		return;
	      }

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
    }
  FIB_ITERATE_END;

#ifdef DEBUGGING
  fib_check(&tab->fib);
#endif

  tab->gc_counter = 0;
  tab->gc_time = current_time();

  /* state change 2->0, 3->1 */
  if (tab->prune_state &= 1)
    ev_send_loop(tab->loop, tab->prune_event);

  uint flushed_channels = 0;

  /* Close flushed channels */
  WALK_LIST2_DELSAFE(ih, n, x, tab->imports, n)
    if (ih->import_state == TIS_FLUSHING)
    {
      ih->flush_seq = tab->next_export_seq;
      rt_set_import_state(ih, TIS_WAITING);
      flushed_channels++;
    }
    else if (ih->stale_pruning != ih->stale_pruned)
    {
      ih->stale_pruned = ih->stale_pruning;

      if (ih->req->trace_routes & D_STATES)
	log(L_TRACE "%s: table prune after refresh end [%u]", ih->req->name, ih->stale_pruned);
    }

  /* In some cases, we may want to directly proceed to export cleanup */
  if (EMPTY_LIST(tab->exports) && flushed_channels)
    rt_export_cleanup(tab);

  rt_unlock_table(tab);
}

static void
rt_export_cleanup(void *data)
{
  rtable_private *tab = data;
  ASSERT_DIE(birdloop_inside(tab->loop));

  u64 min_seq = ~((u64) 0);
  struct rt_pending_export *last_export_to_free = NULL;
  struct rt_pending_export *first_export = tab->first_export;

  struct rt_export_hook *eh;
  node *n;
  WALK_LIST2(eh, n, tab->exports, n)
  {
    switch (atomic_load_explicit(&eh->export_state, memory_order_acquire))
    {
      case TES_DOWN:
      case TES_HUNGRY:
	continue;

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
	/* It's only safe to cleanup when the export state is idle or regular. No feeding or stopping allowed. */
	goto done;
    }
  }

  tab->first_export = last_export_to_free ? rt_next_export_fast(last_export_to_free) : NULL;

  if (config->table_debug)
    log(L_TRACE "%s: Export cleanup, old first_export seq %lu, new %lu, min_seq %ld",
      tab->name,
      first_export ? first_export->seq : 0,
      tab->first_export ? tab->first_export->seq : 0,
      min_seq);

  WALK_LIST2(eh, n, tab->exports, n)
  {
    if (atomic_load_explicit(&eh->export_state, memory_order_acquire) != TES_READY)
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

  while (first_export && (first_export->seq <= min_seq))
  {
    ASSERT_DIE(first_export->new || first_export->old);

    const net_addr *n = first_export->new ?
      first_export->new->rte.net :
      first_export->old->rte.net;
    net *net = SKIP_BACK(struct network, n.addr, (net_addr (*)[0]) n);

    ASSERT_DIE(net->first == first_export);
    
    if (first_export == net->last)
      /* The only export here */
      net->last = net->first = NULL;
    else
      /* First is now the next one */
      net->first = atomic_load_explicit(&first_export->next, memory_order_relaxed);

    /* For now, the old route may be finally freed */
    if (first_export->old)
    {
      rt_rte_trace_in(D_ROUTES, first_export->old->rte.sender->req, &first_export->old->rte, "freed");
      hmap_clear(&tab->id_map, first_export->old->rte.id);
      rte_free(first_export->old, tab);
    }

#ifdef LOCAL_DEBUG
    memset(first_export, 0xbd, sizeof(struct rt_pending_export));
#endif

    struct rt_export_block *reb = HEAD(tab->pending_exports);
    ASSERT_DIE(reb == PAGE_HEAD(first_export));

    u32 pos = (first_export - &reb->export[0]);
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

      free_page(tab->rp, reb);

      if (EMPTY_LIST(tab->pending_exports))
      {
	if (config->table_debug)
	  log(L_TRACE "%s: Resetting export seq", tab->name);

	node *n;
	WALK_LIST2(eh, n, tab->exports, n)
	{
	  if (atomic_load_explicit(&eh->export_state, memory_order_acquire) != TES_READY)
	    continue;

	  ASSERT_DIE(atomic_load_explicit(&eh->last_export, memory_order_acquire) == NULL);
	  bmap_reset(&eh->seq_map, 1024);
	}

	tab->next_export_seq = 1;
      }
      else
      {
	reb = HEAD(tab->pending_exports);
	next = &reb->export[0];
      }
    }

    first_export = next;
  }

done:;
  struct rt_import_hook *ih; node *x;
  WALK_LIST2_DELSAFE(ih, n, x, tab->imports, n)
    if (ih->import_state == TIS_WAITING)
      if (!first_export || (first_export->seq >= ih->flush_seq))
      {
	ih->import_state = TIS_CLEARED;
	ev_send(ih->req->list, ih->export_announce_event);
      }

  if (EMPTY_LIST(tab->pending_exports) && ev_active(tab->announce_event))
    ev_postpone(tab->announce_event);

  /* If reduced to at most one export block pending */
  if (tab->cork_active &&
      ((!tab->first_export) || (tab->first_export->seq + 128 > tab->next_export_seq)))
  {
    tab->cork_active = 0;
    ev_uncork(&rt_cork);
    if (config->table_debug)
      log(L_TRACE "%s: cork released", tab->name);
  }
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
rta_apply_hostentry(rta *a, struct hostentry *he, mpls_label_stack *mls, linpool *lp)
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
      nhp = (nhp ? (nhp->next = lp_alloc(lp, NEXTHOP_MAX_SIZE)) : &(a->nh));
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
rt_next_hop_update_rte(rtable_private *tab, net *n, rte *old)
{
  rta *a = alloca(RTA_MAX_SIZE);
  memcpy(a, old->attrs, rta_size(old->attrs));

  mpls_label_stack mls = { .len = a->nh.labels_orig };
  memcpy(mls.stack, &a->nh.label[a->nh.labels - mls.len], mls.len * sizeof(u32));

  rta_apply_hostentry(a, old->attrs->hostentry, &mls, tab->nhu_lp);
  a->cached = 0;

  rte e0 = *old;
  e0.attrs = a;

  return rte_store(&e0, n, tab);
}

static inline int
rt_next_hop_update_net(rtable_private *tab, net *n)
{
  struct rte_storage *new;
  int count = 0;

  struct rte_storage *old_best = n->routes;
  if (!old_best)
    return 0;

  for (struct rte_storage *e, **k = &n->routes; e = *k; k = &e->next)
    if (rta_next_hop_outdated(e->rte.attrs))
      count++;

  if (!count)
    return 0;

  struct rte_multiupdate {
    struct rte_storage *old, *new;
  } *updates = alloca(sizeof(struct rte_multiupdate) * count);

  int pos = 0;
  for (struct rte_storage *e, **k = &n->routes; e = *k; k = &e->next)
    if (rta_next_hop_outdated(e->rte.attrs))
      {
	struct rte_storage *new = rt_next_hop_update_rte(tab, n, &e->rte);

	/* Call a pre-comparison hook */
	/* Not really an efficient way to compute this */
	if (e->rte.src->owner->rte_recalculate)
	  e->rte.src->owner->rte_recalculate(tab, n, &new->rte, &e->rte, &old_best->rte);

	updates[pos++] = (struct rte_multiupdate) {
	  .old = e,
	  .new = new,
	};

	/* Replace the route in the list */
	new->next = e->next;
	*k = e = new;

	/* Get a new ID for the route */
	new->rte.lastmod = current_time();
	new->rte.id = hmap_first_zero(&tab->id_map);
	hmap_set(&tab->id_map, new->rte.id);

	lp_flush(tab->nhu_lp);
      }

  ASSERT_DIE(pos == count);

  /* Find the new best route */
  struct rte_storage **new_best = NULL;
  for (struct rte_storage *e, **k = &n->routes; e = *k; k = &e->next)
    {
      if (!new_best || rte_better(&e->rte, &(*new_best)->rte))
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

  /* Announce the changes */
  for (int i=0; i<count; i++)
  {
    _Bool nb = (new == updates[i].new), ob = (old_best == updates[i].old);
    const char *best_indicator[2][2] = {
      { "autoupdated", "autoupdated [-best]" },
      { "autoupdated [+best]", "autoupdated [best]" }
    };
    rt_rte_trace_in(D_ROUTES, updates[i].new->rte.sender->req, &updates[i].new->rte, best_indicator[nb][ob]);
    rte_announce(tab, n, updates[i].new, updates[i].old, new, old_best);
  }

  return count;
}

static void
rt_next_hop_update(void *data)
{
  rtable_private *tab = data;
  ASSERT_DIE(birdloop_inside(tab->loop));

  struct fib_iterator *fit = &tab->nhu_fit;
  int max_feed = 32;

  if (atomic_load_explicit(&tab->nhu_state, memory_order_acquire) == NHU_CLEAN)
    return;

  rt_lock_table(tab);

  if (atomic_load_explicit(&tab->nhu_state, memory_order_acquire) == NHU_SCHEDULED)
    {
      FIB_ITERATE_INIT(fit, &tab->fib);
      ASSERT_DIE(atomic_exchange_explicit(&tab->nhu_state, NHU_RUNNING, memory_order_acq_rel) == NHU_SCHEDULED);
    }

  FIB_ITERATE_START(&tab->fib, fit, net, n)
    {
      if (max_feed <= 0)
	{
	  FIB_ITERATE_PUT(fit);
	  ev_send_loop(tab->loop, tab->nhu_event);
	  rt_unlock_table(tab);
	  return;
	}
      max_feed -= rt_next_hop_update_net(tab, n);
    }
  FIB_ITERATE_END;

  /* State change:
   *   NHU_DIRTY   -> NHU_SCHEDULED
   *   NHU_RUNNING -> NHU_CLEAN
   */
  if (atomic_fetch_and_explicit(&tab->nhu_state, NHU_SCHEDULED, memory_order_acq_rel) != NHU_RUNNING)
    ev_send_loop(tab->loop, tab->nhu_event);

  ev_send_loop(tab->loop, tab->announce_event);

  rt_unlock_table(tab);
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
  c->min_settle_time = 1 S;
  c->max_settle_time = 20 S;
  c->min_rr_settle_time = 30 S;
  c->max_rr_settle_time = 90 S;
  c->cork_limit = 4 * page_size / sizeof(struct rt_pending_export);
  c->config = new_config;

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
rt_lock_table(rtable_private *r)
{
  r->use_count++;
}

static void
rt_loop_stopped(void *data)
{
  rtable_private *r = data;
  birdloop_free(r->loop);
  r->loop = NULL;
  r->prune_event->list = r->ec_event->list = NULL;
  r->nhu_event->list = r->hcu_event->list = NULL;
  r->announce_event->list = NULL;
  ev_send(r->delete_event->list, r->delete_event);
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
rt_unlock_table(rtable_private *r)
{
  if (!--r->use_count && r->delete_event &&
      !r->prune_state && !atomic_load_explicit(&r->nhu_state, memory_order_acquire))
    /* Delete the routing table by freeing its pool */
    birdloop_stop_self(r->loop, rt_loop_stopped, r);
}

static struct rtable_config *
rt_find_table_config(struct config *cf, char *name)
{
  struct symbol *sym = cf_find_symbol(cf, name);
  return (sym && (sym->class == SYM_TABLE)) ? sym->table : NULL;
}

static void
rt_done(void *data)
{
  rtable_private *t = data;
  ASSERT_DIE(t->loop == NULL);

  struct rtable_config *tc = t->config;
  struct config *c = tc->config;

  tc->table = NULL;
  rem_node(&t->n);

  if (t->hostcache)
    rt_free_hostcache(t);

  rfree(t->delete_event);
  rfree(t->rp);

  config_del_obstacle(c);
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
	  RT_LOCK(o->table);
	  rtable_private *ot = RT_PRIV(o->table);
	  if (!ot->delete_event)
	    {
	      r = rt_find_table_config(new, o->name);
	      if (r && (r->addr_type == o->addr_type) && !new->shutdown)
		{
		  DBG("\t%s: same\n", o->name);
		  r->table = (rtable *) ot;
		  ot->name = r->name;
		  ot->config = r;
		  if (o->sorted != r->sorted)
		    log(L_WARN "Reconfiguration of rtable sorted flag not implemented");
		}
	      else
		{
		  DBG("\t%s: deleted\n", o->name);
		  rt_lock_table(ot);
		  ot->delete_event = ev_new_init(&root_pool, rt_done, ot);
		  ot->delete_event->list = &global_event_list;
		  config_add_obstacle(old);
		  rt_unlock_table(ot);
		}
	    }
	  RT_UNLOCK(o->table);
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

/**
 * rt_feed_channel - advertise all routes to a channel
 * @c: channel to be fed
 *
 * This function performs one pass of advertisement of routes to a channel that
 * is in the ES_FEEDING state. It is called by the protocol code as long as it
 * has something to do. (We avoid transferring all the routes in single pass in
 * order not to monopolize CPU time.)
 */
static void
rt_feed_channel(void *data)
{
  struct rt_export_hook *c = data;

  struct fib_iterator *fit = &c->feed_fit;
  int max_feed = 256;

  rtable_private *tab;
  if (c->export_state == TES_HUNGRY)
  {
    rt_set_export_state(c, TES_FEEDING);

    tab = RT_LOCK(c->table);

    struct rt_pending_export *rpe = rt_last_export(tab);
    DBG("store hook=%p last_export=%p seq=%lu\n", c, rpe, rpe ? rpe->seq : 0);
    atomic_store_explicit(&c->last_export, rpe, memory_order_relaxed);

    FIB_ITERATE_INIT(&c->feed_fit, &tab->fib);
  }
  else
    tab = RT_LOCK(c->table);

  ASSERT_DIE(c->export_state == TES_FEEDING);

redo:
  FIB_ITERATE_START(&tab->fib, fit, net, n)
    {
      if (max_feed <= 0)
	{
	  FIB_ITERATE_PUT(fit);
	  rt_send_export_event(c);

	  RT_UNLOCK(c->table);
	  return;
	}

      if (atomic_load_explicit(&c->export_state, memory_order_acquire) != TES_FEEDING)
      {
	RT_UNLOCK(c->table);
	return;
      }

      if (!n->routes || !rte_is_valid(&n->routes->rte))
	; /* if no route, do nothing */
      else if (c->req->export_bulk)
      {
	uint count = rte_feed_count(n);
	if (count)
	{
	  rte **feed = alloca(count * sizeof(rte *));
	  rte_feed_obtain(n, feed, count);

	  struct rt_pending_export *rpe_last, *rpe_first = n->first;
	  for (struct rt_pending_export *rpe = rpe_first; rpe; rpe = rpe_next(rpe, NULL))
	    rpe_last = rpe;

	  FIB_ITERATE_PUT_NEXT(fit, &tab->fib);
	  RT_UNLOCK(c->table);

	  c->req->export_bulk(c->req, n->n.addr, NULL, feed, count);

	  RT_LOCK(c->table);

	  for (struct rt_pending_export *rpe = rpe_first; rpe; rpe = rpe_next(rpe, NULL))
	  {
	    rpe_mark_seen(c, rpe);
	    if (rpe == rpe_last)
	      break;
	    ASSERT_DIE(rpe->seq < rpe_last->seq);
	  }

	  max_feed -= count;

	  goto redo;
	}
      }
      else if (c->req->export_one)
      {
	struct rt_pending_export rpe = { .new = n->routes, .new_best = n->routes };

	struct rt_pending_export *rpe_last, *rpe_first = n->first;
	for (struct rt_pending_export *rpe = rpe_first; rpe; rpe = rpe_next(rpe, NULL))
	  rpe_last = rpe;

	FIB_ITERATE_PUT_NEXT(fit, &tab->fib);
	RT_UNLOCK(c->table);

	c->req->export_one(c->req, n->n.addr, &rpe);

	RT_LOCK(c->table);
	for (struct rt_pending_export *rpe = rpe_first; rpe; rpe = rpe_next(rpe, NULL))
	{
	  rpe_mark_seen(c, rpe);
	  if (rpe == rpe_last)
	    break;
	  ASSERT_DIE(rpe->seq < rpe_last->seq);
	}

	max_feed--;
	goto redo;
      }
      else
	bug("Export request must always provide an export method");
    }
  FIB_ITERATE_END;

  c->event->hook = rt_export_hook;
  rt_send_export_event(c);

  RT_UNLOCK(c->table);

  rt_set_export_state(c, TES_READY);
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
  sl_free(hc->slab, he);

  hc->hash_items--;
  if (hc->hash_items < hc->hash_min)
    hc_resize(hc, p, hc->hash_order - HC_LO_STEP);
}

static void
rt_init_hostcache(rtable_private *tab)
{
  struct hostcache *hc = mb_allocz(tab->rp, sizeof(struct hostcache));
  init_list(&hc->hostentries);

  hc->hash_items = 0;
  hc_alloc_table(hc, tab->rp, HC_DEF_ORDER);
  hc->slab = sl_new(tab->rp, sizeof(struct hostentry));

  hc->lp = lp_new(tab->rp, LP_GOOD_SIZE(1024));
  hc->trie = f_new_trie(hc->lp, 0);

  tab->hostcache = hc;
}

static void
rt_free_hostcache(rtable_private *tab)
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
rt_notify_hostcache(rtable_private *tab, net *net)
{
  if (ev_active(tab->hcu_event))
    return;

  if (trie_match_net(tab->hostcache->trie, net->n.addr))
    ev_send_loop(tab->loop, tab->hcu_event);
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

  if (rt->src->owner->class->rte_igp_metric)
    return rt->src->owner->class->rte_igp_metric(rt);

  return IGP_METRIC_UNKNOWN;
}

static int
rt_update_hostentry(rtable_private *tab, struct hostentry *he)
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
      struct rte_storage *e = n->routes;
      rta *a = e->rte.attrs;
      word pref = a->pref;

      for (struct rte_storage *ee = n->routes; ee; ee = ee->next)
	if ((ee->rte.attrs->pref >= pref) && ee->rte.attrs->hostentry)
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
  rtable_private *tab = data;
  ASSERT_DIE(birdloop_inside(tab->loop));

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
}

struct hostentry *
rt_get_hostentry(rtable *t, ip_addr a, ip_addr ll, rtable *dep)
{
  struct hostentry *he;

  rtable_private *tab = RT_LOCK(t);

  if (!tab->hostcache)
    rt_init_hostcache(tab);

  u32 k = hc_hash(a, dep);
  struct hostcache *hc = tab->hostcache;
  for (he = hc->hash_table[k >> hc->hash_shift]; he != NULL; he = he->next)
    if (ipa_equal(he->addr, a) && (he->tab == dep))
      goto done;

  he = hc_new_hostentry(hc, tab->rp, a, ipa_zero(ll) ? a : ll, dep, k);
  rt_update_hostentry(tab, he);

done:
  RT_UNLOCK(t);
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
