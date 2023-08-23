/*
 *	BIRD -- The Babel protocol
 *
 *	Copyright (c) 2015--2016 Toke Hoiland-Jorgensen
 * 	(c) 2016--2017 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2016--2017 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	This file contains the main routines for handling and sending TLVs, as
 *	well as timers and interaction with the nest.
 */

/**
 * DOC: The Babel protocol
 *
 * The Babel is a loop-avoiding distance-vector routing protocol that is robust
 * and efficient both in ordinary wired networks and in wireless mesh networks.
 *
 * The Babel protocol keeps state for each neighbour in a &babel_neighbor
 * struct, tracking received Hello and I Heard You (IHU) messages. A
 * &babel_interface struct keeps hello and update times for each interface, and
 * a separate hello seqno is maintained for each interface.
 *
 * For each prefix, Babel keeps track of both the possible routes (with next hop
 * and router IDs), as well as the feasibility distance for each prefix and
 * router id. The prefix itself is tracked in a &babel_entry struct, while the
 * possible routes for the prefix are tracked as &babel_route entries and the
 * feasibility distance is maintained through &babel_source structures.
 *
 * The main route selection is done in babel_select_route(). This is called when
 * an entry is updated by receiving updates from the network or when modified by
 * internal timers. The function selects from feasible and reachable routes the
 * one with the lowest metric to be announced to the core.
 *
 * Supported standards:
 * RFC 8966 - The Babel Routing Protocol
 * RFC 8967 - MAC Authentication for Babel
 * RFC 9079 - Source Specific Routing for Babel
 * RFC 9229 - IPv4 Routes with IPv6 Next Hop for Babel
 */

#include <stdlib.h>
#include "babel.h"

#define LOG_PKT_AUTH(msg, args...) \
  log_rl(&p->log_pkt_tbf, L_AUTH "%s: " msg, p->p.name, args)

/*
 * Is one number greater or equal than another mod 2^16? This is based on the
 * definition of serial number space in RFC 1982. Note that arguments are of
 * uint type to avoid integer promotion to signed integer.
 */
static inline int ge_mod64k(uint a, uint b)
{ return (u16)(a - b) < 0x8000; }

/* Strict inequality version of the above */
static inline int gt_mod64k(uint a, uint b)
{ return ge_mod64k(a, b) && a != b; }

static void babel_expire_requests(struct babel_proto *p, struct babel_entry *e);
static void babel_select_route(struct babel_proto *p, struct babel_entry *e, struct babel_route *mod);
static inline void babel_announce_retraction(struct babel_proto *p, struct babel_entry *e);
static void babel_send_route_request(struct babel_proto *p, struct babel_entry *e, struct babel_neighbor *n);
static void babel_send_seqno_request(struct babel_proto *p, struct babel_entry *e, struct babel_seqno_request *sr, struct babel_neighbor *n);
static void babel_update_cost(struct babel_neighbor *n);
static inline void babel_kick_timer(struct babel_proto *p);
static inline void babel_iface_kick_timer(struct babel_iface *ifa);

/*
 *	Functions to maintain data structures
 */

static void
babel_init_entry(struct fib *f UNUSED, void *E)
{
  struct babel_entry *e = E;

  e->updated = current_time();
  init_list(&e->requests);
  init_list(&e->sources);
  init_list(&e->routes);
}

static inline struct babel_entry *
babel_find_entry(struct babel_proto *p, const net_addr *n)
{
  struct fib *rtable = (n->type == NET_IP4) ? &p->ip4_rtable : &p->ip6_rtable;
  return fib_find(rtable, n);
}

static struct babel_entry *
babel_get_entry(struct babel_proto *p, const net_addr *n)
{
  struct fib *rtable = (n->type == NET_IP4) ? &p->ip4_rtable : &p->ip6_rtable;
  struct babel_entry *e = fib_get(rtable, n);
  return e;
}

static struct babel_source *
babel_find_source(struct babel_entry *e, u64 router_id)
{
  struct babel_source *s;

  WALK_LIST(s, e->sources)
    if (s->router_id == router_id)
      return s;

  return NULL;
}

static struct babel_source *
babel_get_source(struct babel_proto *p, struct babel_entry *e, u64 router_id,
                 u16 initial_seqno)
{
  struct babel_source *s = babel_find_source(e, router_id);

  if (s)
    return s;

  s = sl_allocz(p->source_slab);
  s->router_id = router_id;
  s->expires = current_time() + BABEL_GARBAGE_INTERVAL;
  s->seqno = initial_seqno;
  s->metric = BABEL_INFINITY;
  add_tail(&e->sources, NODE s);

  return s;
}

static void
babel_expire_sources(struct babel_proto *p UNUSED, struct babel_entry *e)
{
  struct babel_source *n, *nx;
  btime now_ = current_time();

  WALK_LIST_DELSAFE(n, nx, e->sources)
  {
    if (n->expires && n->expires <= now_)
    {
      rem_node(NODE n);
      sl_free(n);
    }
  }
}

static struct babel_route *
babel_find_route(struct babel_entry *e, struct babel_neighbor *n)
{
  struct babel_route *r;

  WALK_LIST(r, e->routes)
    if (r->neigh == n)
      return r;

  return NULL;
}

static struct babel_route *
babel_get_route(struct babel_proto *p, struct babel_entry *e, struct babel_neighbor *nbr)
{
  struct babel_route *r = babel_find_route(e, nbr);

  if (r)
    return r;

  r = sl_allocz(p->route_slab);

  r->e = e;
  r->neigh = nbr;
  add_tail(&e->routes, NODE r);
  add_tail(&nbr->routes, NODE &r->neigh_route);

  return r;
}

static inline void
babel_retract_route(struct babel_proto *p, struct babel_route *r)
{
  r->metric = r->advert_metric = BABEL_INFINITY;

  if (r == r->e->selected)
    babel_select_route(p, r->e, r);
}

static void
babel_flush_route(struct babel_proto *p UNUSED, struct babel_route *r)
{
  DBG("Babel: Flush route %N router_id %lR neigh %I\n",
      r->e->n.addr, r->router_id, r->neigh->addr);

  rem_node(NODE r);
  rem_node(&r->neigh_route);

  if (r->e->selected == r)
    r->e->selected = NULL;

  sl_free(r);
}

static void
babel_expire_route(struct babel_proto *p, struct babel_route *r)
{
  struct babel_config *cf = (void *) p->p.cf;

  TRACE(D_EVENTS, "Route expiry timer for %N router-id %lR fired",
	r->e->n.addr, r->router_id);

  if (r->metric < BABEL_INFINITY)
  {
    r->metric = r->advert_metric = BABEL_INFINITY;
    r->expires = current_time() + cf->hold_time;
  }
  else
  {
    babel_flush_route(p, r);
  }
}

static void
babel_refresh_route(struct babel_proto *p, struct babel_route *r)
{
  if (r == r->e->selected)
    babel_send_route_request(p, r->e, r->neigh);

  r->refresh_time = 0;
}

static void
babel_expire_routes_(struct babel_proto *p, struct fib *rtable)
{
  struct babel_config *cf = (void *) p->p.cf;
  struct babel_route *r, *rx;
  struct fib_iterator fit;
  btime now_ = current_time();

  FIB_ITERATE_INIT(&fit, rtable);

loop:
  FIB_ITERATE_START(rtable, &fit, struct babel_entry, e)
  {
    int changed = 0;

    WALK_LIST_DELSAFE(r, rx, e->routes)
    {
      if (r->refresh_time && r->refresh_time <= now_)
	babel_refresh_route(p, r);

      if (r->expires && r->expires <= now_)
      {
	changed = changed || (r == e->selected);
	babel_expire_route(p, r);
      }
    }

    if (changed)
    {
      /*
       * We have to restart the iteration because there may be a cascade of
       * synchronous events babel_select_route() -> nest table change ->
       * babel_rt_notify() -> rtable change, invalidating hidden variables.
       */
      FIB_ITERATE_PUT(&fit);
      babel_select_route(p, e, NULL);
      goto loop;
    }

    /* Clean up stale entries */
    if ((e->valid == BABEL_ENTRY_STALE) && ((e->updated + cf->hold_time) <= now_))
      e->valid = BABEL_ENTRY_DUMMY;

    /* Clean up unreachable route */
    if (e->unreachable && (!e->valid || (e->router_id == p->router_id)))
    {
      FIB_ITERATE_PUT(&fit);
      babel_announce_retraction(p, e);
      goto loop;
    }

    babel_expire_sources(p, e);
    babel_expire_requests(p, e);

    /* Remove empty entries */
    if (!e->valid && EMPTY_LIST(e->routes) && EMPTY_LIST(e->sources) && EMPTY_LIST(e->requests))
    {
      FIB_ITERATE_PUT(&fit);
      fib_delete(rtable, e);
      goto loop;
    }
  }
  FIB_ITERATE_END;
}

static void
babel_expire_routes(struct babel_proto *p)
{
  babel_expire_routes_(p, &p->ip4_rtable);
  babel_expire_routes_(p, &p->ip6_rtable);
}

/*
 * Add seqno request to the table of pending requests (RFC 8966 3.2.6) and send
 * it to network. Do nothing if it is already in the table.
 */

static void
babel_add_seqno_request(struct babel_proto *p, struct babel_entry *e,
			u64 router_id, u16 seqno, u8 hop_count,
			struct babel_neighbor *target)
{
  struct babel_seqno_request *sr;
  btime now_ = current_time();

  WALK_LIST(sr, e->requests)
    if (sr->router_id == router_id)
    {
      /*
       * To suppress duplicates, check if we already have a newer (higher seqno)
       * outstanding request. If we do, suppress this request if the outstanding
       * request is one we originated ourselves. If the outstanding request is
       * forwarded, suppress only if this request is also one we're forwarding
       * *and* we're within the duplicate suppression time of that request (see
       * below).
       */
      if (ge_mod64k(sr->seqno, seqno) &&
          (!sr->forwarded || (target && now_ < sr->dup_suppress_time)))
	return;

      rem_node(NODE sr);

      /* Allow upgrading from forwarded to non-forwarded */
      if (!target)
        sr->forwarded = 0;

      goto found;
    }

  /* No entries found */
  sr = sl_allocz(p->seqno_slab);
  sr->forwarded = !!target;

found:
  sr->router_id = router_id;
  sr->seqno = seqno;
  sr->hop_count = hop_count ?: BABEL_INITIAL_HOP_COUNT;
  sr->count = 0;

  if (sr->forwarded)
  {
    /*
     * We want to keep the entry around for a reasonable period of time so it
     * can be used to trigger an update (through babel_satisfy_seqno_request()).
     * However, duplicate suppression should only trigger for a short period of
     * time so it suppresses duplicates from multiple sources, but not
     * retransmissions from the same source. Hence we keep two timers.
     */
    sr->expires = now_ + BABEL_SEQNO_FORWARD_EXPIRY;
    sr->dup_suppress_time = now_ + BABEL_SEQNO_DUP_SUPPRESS_TIME;
  }
  else
  {
    sr->expires = now_ + BABEL_SEQNO_REQUEST_EXPIRY;
  }

  add_tail(&e->requests, NODE sr);
  babel_send_seqno_request(p, e, sr, target);
}

static void
babel_generate_seqno_request(struct babel_proto *p, struct babel_entry *e,
                             u64 router_id, u16 seqno, struct babel_neighbor *target)
{
  struct babel_seqno_request req = {
    .router_id = router_id,
    .seqno = seqno,
    .hop_count = BABEL_INITIAL_HOP_COUNT,
  };

  babel_send_seqno_request(p, e, &req, target);
}

static void
babel_remove_seqno_request(struct babel_proto *p UNUSED, struct babel_seqno_request *sr)
{
  rem_node(NODE sr);
  sl_free(sr);
}

static int
babel_satisfy_seqno_request(struct babel_proto *p, struct babel_entry *e,
			   u64 router_id, u16 seqno)
{
  struct babel_seqno_request *sr;

  WALK_LIST(sr, e->requests)
    if ((sr->router_id == router_id) && ge_mod64k(seqno, sr->seqno))
    {
      /* Found the request, remove it */
      babel_remove_seqno_request(p, sr);
      return 1;
    }

  return 0;
}

static void
babel_expire_requests(struct babel_proto *p, struct babel_entry *e)
{
  struct babel_seqno_request *sr, *srx;
  btime now_ = current_time();

  WALK_LIST_DELSAFE(sr, srx, e->requests)
  {
    /* Handle expired requests - resend or remove */
    if (sr->expires && sr->expires <= now_)
    {
      if (!sr->forwarded && sr->count < BABEL_SEQNO_REQUEST_RETRY)
      {
	sr->count++;
	sr->expires += (BABEL_SEQNO_REQUEST_EXPIRY << sr->count);
        babel_send_seqno_request(p, e, sr, NULL);
      }
      else
      {
	TRACE(D_EVENTS, "Seqno request for %N router-id %lR expired",
	      e->n.addr, sr->router_id);

	babel_remove_seqno_request(p, sr);
	continue;
      }
    }
  }
}

static struct babel_neighbor *
babel_find_neighbor(struct babel_iface *ifa, ip_addr addr)
{
  struct babel_neighbor *nbr;

  WALK_LIST(nbr, ifa->neigh_list)
    if (ipa_equal(nbr->addr, addr))
      return nbr;

  return NULL;
}

static struct babel_neighbor *
babel_get_neighbor(struct babel_iface *ifa, ip_addr addr)
{
  struct babel_proto *p = ifa->proto;
  struct babel_neighbor *nbr = babel_find_neighbor(ifa, addr);

  if (nbr)
    return nbr;

  TRACE(D_EVENTS, "New neighbor %I on %s", addr, ifa->iface->name);

  nbr = mb_allocz(ifa->pool, sizeof(struct babel_neighbor));
  nbr->ifa = ifa;
  nbr->addr = addr;
  nbr->rxcost = BABEL_INFINITY;
  nbr->txcost = BABEL_INFINITY;
  nbr->cost = BABEL_INFINITY;
  nbr->init_expiry = current_time() + BABEL_INITIAL_NEIGHBOR_TIMEOUT;
  init_list(&nbr->routes);
  add_tail(&ifa->neigh_list, NODE nbr);

  return nbr;
}

static void
babel_flush_neighbor(struct babel_proto *p, struct babel_neighbor *nbr)
{
  struct babel_route *r;
  node *n;

  TRACE(D_EVENTS, "Removing neighbor %I on %s", nbr->addr, nbr->ifa->iface->name);

  WALK_LIST_FIRST(n, nbr->routes)
  {
    r = SKIP_BACK(struct babel_route, neigh_route, n);
    babel_retract_route(p, r);
    babel_flush_route(p, r);
  }

  nbr->ifa = NULL;
  rem_node(NODE nbr);
  mb_free(nbr);
}

static void
babel_expire_ihu(struct babel_proto *p, struct babel_neighbor *nbr)
{
  TRACE(D_EVENTS, "IHU from nbr %I on %s expired", nbr->addr, nbr->ifa->iface->name);

  nbr->txcost = BABEL_INFINITY;
  nbr->ihu_expiry = 0;
  babel_update_cost(nbr);
}

static void
babel_expire_hello(struct babel_proto *p, struct babel_neighbor *nbr, btime now_)
{
again:
  nbr->hello_map <<= 1;

  if (nbr->hello_cnt < 16)
    nbr->hello_cnt++;

  nbr->hello_expiry += nbr->last_hello_int;

  /* We may expire multiple hellos if last_hello_int is too short */
  if (nbr->hello_map && nbr->hello_expiry <= now_)
    goto again;

  TRACE(D_EVENTS, "Hello from nbr %I on %s expired, %d left",
	nbr->addr, nbr->ifa->iface->name, u32_popcount(nbr->hello_map));

  if (nbr->hello_map)
    babel_update_cost(nbr);
  else
    babel_flush_neighbor(p, nbr);
}

static void
babel_expire_neighbors(struct babel_proto *p)
{
  struct babel_iface *ifa;
  struct babel_neighbor *nbr, *nbx;
  btime now_ = current_time();

  WALK_LIST(ifa, p->interfaces)
  {
    WALK_LIST_DELSAFE(nbr, nbx, ifa->neigh_list)
    {
      if (nbr->ihu_expiry && nbr->ihu_expiry <= now_)
        babel_expire_ihu(p, nbr);

      if (nbr->init_expiry && nbr->init_expiry <= now_)
      { babel_flush_neighbor(p, nbr); continue; }

      if (nbr->hello_expiry && nbr->hello_expiry <= now_)
      { babel_expire_hello(p, nbr, now_); continue; }
    }
  }
}

/*
 *	Best route selection
 */

/*
 * From the RFC (section 3.5.1):
 *
 * a route advertisement carrying the quintuple (prefix, plen, router-id, seqno,
 * metric) is feasible if one of the following conditions holds:
 *
 * - metric is infinite; or
 *
 * - no entry exists in the source table indexed by (id, prefix, plen); or
 *
 * - an entry (prefix, plen, router-id, seqno', metric') exists in the source
 *   table, and either
 *   - seqno' < seqno or
 *   - seqno = seqno' and metric < metric'.
 */
static inline int
babel_is_feasible(struct babel_source *s, u16 seqno, u16 metric)
{
  return !s ||
    (metric == BABEL_INFINITY) ||
    gt_mod64k(seqno, s->seqno) ||
    ((seqno == s->seqno) && (metric < s->metric));
}

/* Simple additive metric - Appendix 3.1 in the RFC */
static inline u16
babel_compute_metric(struct babel_neighbor *n, uint metric)
{
  return MIN(metric + n->cost, BABEL_INFINITY);
}

static void
babel_update_cost(struct babel_neighbor *nbr)
{
  struct babel_proto *p = nbr->ifa->proto;
  struct babel_iface_config *cf = nbr->ifa->cf;
  uint rcv = u32_popcount(nbr->hello_map); // number of bits set
  uint max = nbr->hello_cnt;
  uint rxcost = BABEL_INFINITY;	/* Cost to announce in IHU */
  uint txcost = BABEL_INFINITY;	/* Effective cost for route selection */

  if (!rcv || !nbr->ifa->up)
    goto done;

  switch (cf->type)
  {
  case BABEL_IFACE_TYPE_WIRED:
  case BABEL_IFACE_TYPE_TUNNEL:
    /* k-out-of-j selection - Appendix 2.1 in the RFC. */

    /* Link is bad if less than cf->limit/16 of expected hellos were received */
    if (rcv * 16 < cf->limit * max)
      break;

    rxcost =  cf->rxcost;
    txcost = nbr->txcost;
    break;

  case BABEL_IFACE_TYPE_WIRELESS:
    /*
     * ETX - Appendix 2.2 in the RFC.
     *
     * alpha  = prob. of successful transmission estimated by the neighbor
     * beta   = prob. of successful transmission estimated by the router
     * rxcost = nominal rxcost of the router / beta
     * txcost = nominal rxcost of the neighbor / (alpha * beta)
     *        = received txcost / beta
     *
     * Note that received txcost is just neighbor's rxcost. Beta is rcv/max,
     * we use inverse values of beta (i.e. max/rcv) to stay in integers.
     */
    rxcost = MIN( cf->rxcost * max / rcv, BABEL_INFINITY);
    txcost = MIN(nbr->txcost * max / rcv, BABEL_INFINITY);
    break;
  }

  if (cf->rtt_cost && nbr->srtt > cf->rtt_min)
  {
    uint rtt_cost = cf->rtt_cost;

    if (nbr->srtt < cf->rtt_max)
    {
      uint rtt_interval = cf->rtt_max TO_US - cf->rtt_min TO_US;
      uint rtt_diff = (nbr->srtt TO_US - cf->rtt_min TO_US);

      rtt_cost = (rtt_cost * rtt_diff) / rtt_interval;
    }

    txcost = MIN(txcost + rtt_cost, BABEL_INFINITY);

    TRACE(D_EVENTS, "Added RTT cost %u to nbr %I on %s with srtt %t ms",
	  rtt_cost, nbr->addr, nbr->ifa->iface->name, nbr->srtt * 1000);
  }

done:
  /* If RX cost changed, send IHU with next Hello */
  if (rxcost != nbr->rxcost)
  {
    nbr->rxcost = rxcost;
    nbr->ihu_cnt = 0;
  }

  /* If link cost changed, run route selection */
  if (txcost != nbr->cost)
  {
    TRACE(D_EVENTS, "Cost of nbr %I on %s changed from %u to %u",
	  nbr->addr, nbr->ifa->iface->name, nbr->cost, txcost);

    nbr->cost = txcost;

    struct babel_route *r; node *n;
    WALK_LIST2(r, n, nbr->routes, neigh_route)
    {
      r->metric = babel_compute_metric(nbr, r->advert_metric);
      babel_select_route(p, r->e, r);
    }
  }
}

/**
 * babel_announce_rte - announce selected route to the core
 * @p: Babel protocol instance
 * @e: Babel route entry to announce
 *
 * This function announces a Babel entry to the core if it has a selected
 * incoming path, and retracts it otherwise. If there is no selected route but
 * the entry is valid and ours, the unreachable route is announced instead.
 */
static void
babel_announce_rte(struct babel_proto *p, struct babel_entry *e)
{
  struct babel_route *r = e->selected;
  struct channel *c = (e->n.addr->type == NET_IP4) ? p->ip4_channel : p->ip6_channel;

  if (r)
  {
    rta a0 = {
      .source = RTS_BABEL,
      .scope = SCOPE_UNIVERSE,
      .dest = RTD_UNICAST,
      .pref = c->preference,
      .from = r->neigh->addr,
      .nh.gw = r->next_hop,
      .nh.iface = r->neigh->ifa->iface,
      .eattrs = alloca(sizeof(ea_list) + 3*sizeof(eattr)),
    };

    *a0.eattrs = (ea_list) { .count = 3 };
    a0.eattrs->attrs[0] = (eattr) {
      .id = EA_BABEL_METRIC,
      .type = EAF_TYPE_INT,
      .u.data = r->metric,
    };

    struct adata *ad = alloca(sizeof(struct adata) + sizeof(u64));
    ad->length = sizeof(u64);
    memcpy(ad->data, &(r->router_id), sizeof(u64));
    a0.eattrs->attrs[1] = (eattr) {
      .id = EA_BABEL_ROUTER_ID,
      .type = EAF_TYPE_OPAQUE,
      .u.ptr = ad,
    };

    a0.eattrs->attrs[2] = (eattr) {
      .id = EA_BABEL_SEQNO,
      .type = EAF_TYPE_INT,
      .u.data = r->seqno,
    };

    /*
     * If we cannot find a reachable neighbour, set the entry to be onlink. This
     * makes it possible to, e.g., assign /32 addresses on a mesh interface and
     * have routing work.
     */
    if (!neigh_find(&p->p, r->next_hop, r->neigh->ifa->iface, 0))
      a0.nh.flags = RNF_ONLINK;

    rta *a = rta_lookup(&a0);
    rte *rte = rte_get_temp(a, p->p.main_source);

    e->unreachable = 0;
    rte_update2(c, e->n.addr, rte, p->p.main_source);
  }
  else if (e->valid && (e->router_id != p->router_id))
  {
    /* Unreachable */
    rta a0 = {
      .source = RTS_BABEL,
      .scope = SCOPE_UNIVERSE,
      .dest = RTD_UNREACHABLE,
      .pref = 1,
    };

    rta *a = rta_lookup(&a0);
    rte *rte = rte_get_temp(a, p->p.main_source);

    e->unreachable = 1;
    rte_update2(c, e->n.addr, rte, p->p.main_source);
  }
  else
  {
    /* Retraction */
    e->unreachable = 0;
    rte_update2(c, e->n.addr, NULL, p->p.main_source);
  }
}

/* Special case of babel_announce_rte() just for retraction */
static inline void
babel_announce_retraction(struct babel_proto *p, struct babel_entry *e)
{
  struct channel *c = (e->n.addr->type == NET_IP4) ? p->ip4_channel : p->ip6_channel;
  e->unreachable = 0;
  rte_update2(c, e->n.addr, NULL, p->p.main_source);
}


/**
 * babel_select_route - select best route for given route entry
 * @p: Babel protocol instance
 * @e: Babel entry to select the best route for
 * @mod: Babel route that was modified or NULL if unspecified
 *
 * Select the best reachable and feasible route for a given prefix among the
 * routes received from peers, and propagate it to the nest. This just selects
 * the reachable and feasible route with the lowest metric, but keeps selected
 * the old one in case of tie.
 *
 * If no feasible route is available for a prefix that previously had a route
 * selected, a seqno request is sent to try to get a valid route. If the entry
 * is valid and not owned by us, the unreachable route is announced to the nest
 * (to blackhole packets going to it, as per section 2.8). It is later removed
 * by babel_expire_routes(). Otherwise, the route is just removed from the nest.
 *
 * Argument @mod is used to optimize best route calculation. When specified, the
 * function can assume that only the @mod route was modified to avoid full best
 * route selection and announcement when non-best route was modified in minor
 * way. The caller is advised to not call babel_select_route() when no change is
 * done (e.g. periodic route updates) to avoid unnecessary announcements of the
 * same best route. The caller is not required to call the function in case of a
 * retraction of a non-best route.
 *
 * Note that the function does not active triggered updates. That is done by
 * babel_rt_notify() when the change is propagated back to Babel.
 */
static void
babel_select_route(struct babel_proto *p, struct babel_entry *e, struct babel_route *mod)
{
  struct babel_route *r, *best = e->selected;

  /* Shortcut if only non-best was modified */
  if (mod && (mod != best))
  {
    /* Either select modified route, or keep old best route */
    if ((mod->metric < (best ? best->metric : BABEL_INFINITY)) && mod->feasible)
      best = mod;
    else
      return;
  }
  else
  {
    /* Selected route may be modified and no longer admissible */
    if (!best || (best->metric == BABEL_INFINITY) || !best->feasible)
      best = NULL;

    /* Find the best feasible route from all routes */
    WALK_LIST(r, e->routes)
      if ((r->metric < (best ? best->metric : BABEL_INFINITY)) && r->feasible)
	best = r;
  }

  if (best)
  {
    if (best != e->selected)
      TRACE(D_EVENTS, "Picked new route for prefix %N: router-id %lR metric %d",
	    e->n.addr, best->router_id, best->metric);
  }
  else if (e->selected)
  {
    /*
     * We have lost all feasible routes. We have to broadcast seqno request
     * (Section 3.8.2.1) and keep unreachable route for a while (section 2.8).
     * The later is done automatically by babel_announce_rte().
     */

    TRACE(D_EVENTS, "Lost feasible route for prefix %N", e->n.addr);
    if (e->valid && (e->selected->router_id == e->router_id))
      babel_add_seqno_request(p, e, e->selected->router_id, e->selected->seqno + 1, 0, NULL);
  }
  else
    return;

  e->selected = best;
  babel_announce_rte(p, e);
}

/*
 *	Functions to send replies
 */

static void
babel_send_ack(struct babel_iface *ifa, ip_addr dest, u16 nonce)
{
  struct babel_proto *p = ifa->proto;
  union babel_msg msg = {};

  TRACE(D_PACKETS, "Sending ACK to %I with nonce %d", dest, nonce);

  msg.type = BABEL_TLV_ACK;
  msg.ack.nonce = nonce;

  babel_send_unicast(&msg, ifa, dest);
}

static void
babel_build_ihu(union babel_msg *msg, struct babel_iface *ifa, struct babel_neighbor *n)
{
  struct babel_proto *p = ifa->proto;

  msg->type = BABEL_TLV_IHU;
  msg->ihu.addr = n->addr;
  msg->ihu.rxcost = n->rxcost;
  msg->ihu.interval = ifa->cf->ihu_interval;

  if (n->last_tstamp_rcvd && ifa->cf->rtt_send)
  {
    msg->ihu.tstamp = n->last_tstamp;
    msg->ihu.tstamp_rcvd = n->last_tstamp_rcvd TO_US;
  }

  TRACE(D_PACKETS, "Sending IHU for %I with rxcost %d interval %t",
        msg->ihu.addr, msg->ihu.rxcost, (btime) msg->ihu.interval);
}

static void
babel_send_ihu(struct babel_iface *ifa, struct babel_neighbor *n)
{
  union babel_msg msg = {};
  babel_build_ihu(&msg, ifa, n);
  babel_send_unicast(&msg, ifa, n->addr);
  n->ihu_cnt = BABEL_IHU_INTERVAL_FACTOR;
}

static void
babel_send_ihus(struct babel_iface *ifa)
{
  struct babel_neighbor *n;
  WALK_LIST(n, ifa->neigh_list)
  {
    if (n->hello_cnt && (--n->ihu_cnt <= 0))
    {
      union babel_msg msg = {};
      babel_build_ihu(&msg, ifa, n);
      babel_enqueue(&msg, ifa);
      n->ihu_cnt = BABEL_IHU_INTERVAL_FACTOR;
    }
  }
}

static void
babel_send_hello(struct babel_iface *ifa, uint interval)
{
  struct babel_proto *p = ifa->proto;
  union babel_msg msg = {};

  msg.type = BABEL_TLV_HELLO;
  msg.hello.seqno = ifa->hello_seqno++;
  msg.hello.interval = interval ?: ifa->cf->hello_interval;

  if (ifa->cf->rtt_send)
    msg.hello.tstamp = 1; /* real timestamp will be set on TLV write */

  TRACE(D_PACKETS, "Sending hello on %s with seqno %d interval %t",
	ifa->ifname, msg.hello.seqno, (btime) msg.hello.interval);

  babel_enqueue(&msg, ifa);

  babel_send_ihus(ifa);
}

static void
babel_send_route_request(struct babel_proto *p, struct babel_entry *e, struct babel_neighbor *n)
{
  union babel_msg msg = {};

  TRACE(D_PACKETS, "Sending route request for %N to %I", e->n.addr, n->addr);

  msg.type = BABEL_TLV_ROUTE_REQUEST;
  net_copy(&msg.route_request.net, e->n.addr);

  babel_send_unicast(&msg, n->ifa, n->addr);
}

static void
babel_send_wildcard_request(struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  union babel_msg msg = {};

  TRACE(D_PACKETS, "Sending wildcard route request on %s", ifa->ifname);

  msg.type = BABEL_TLV_ROUTE_REQUEST;
  msg.route_request.full = 1;

  babel_enqueue(&msg, ifa);
}

static void
babel_send_seqno_request(struct babel_proto *p, struct babel_entry *e,
                         struct babel_seqno_request *sr, struct babel_neighbor *n)
{
  union babel_msg msg = {};

  msg.type = BABEL_TLV_SEQNO_REQUEST;
  msg.seqno_request.hop_count = sr->hop_count;
  msg.seqno_request.seqno = sr->seqno;
  msg.seqno_request.router_id = sr->router_id;
  net_copy(&msg.seqno_request.net, e->n.addr);

  if (n)
  {
    TRACE(D_PACKETS, "Sending seqno request for %N router-id %lR seqno %d to %I on %s",
          e->n.addr, sr->router_id, sr->seqno, n->addr, n->ifa->ifname);

    babel_send_unicast(&msg, n->ifa, n->addr);
  }
  else
  {
    TRACE(D_PACKETS, "Sending broadcast seqno request for %N router-id %lR seqno %d",
	  e->n.addr, sr->router_id, sr->seqno);

    struct babel_iface *ifa;
    WALK_LIST(ifa, p->interfaces)
      babel_enqueue(&msg, ifa);
  }
}

/**
 * babel_send_update - send route table updates
 * @ifa: Interface to transmit on
 * @changed: Only send entries changed since this time
 *
 * This function produces update TLVs for all entries changed since the time
 * indicated by the &changed parameter and queues them for transmission on the
 * selected interface. During the process, the feasibility distance for each
 * transmitted entry is updated.
 */
static void
babel_send_update_(struct babel_iface *ifa, btime changed, struct fib *rtable)
{
  struct babel_proto *p = ifa->proto;

  /* Update increase was requested */
  if (p->update_seqno_inc)
  {
    p->update_seqno++;
    p->update_seqno_inc = 0;
  }

  FIB_WALK(rtable, struct babel_entry, e)
  {
    if (!e->valid)
      continue;

    /* Our own seqno might have changed, in which case we update the routes we
       originate. */
    if ((e->router_id == p->router_id) && (e->seqno < p->update_seqno))
    {
      e->seqno = p->update_seqno;
      e->updated = current_time();
    }

    /* Skip routes that weren't updated since 'changed' time */
    if (e->updated < changed)
      continue;

    TRACE(D_PACKETS, "Sending update for %N router-id %lR seqno %d metric %d",
	  e->n.addr, e->router_id, e->seqno, e->metric);

    union babel_msg msg = {};
    msg.type = BABEL_TLV_UPDATE;
    msg.update.interval = ifa->cf->update_interval;
    msg.update.seqno = e->seqno;
    msg.update.metric = e->metric;
    msg.update.router_id = e->router_id;
    net_copy(&msg.update.net, e->n.addr);

    if (e->n.addr->type == NET_IP4)
    {
      /* Always prefer IPv4 nexthop if set */
      if (ipa_nonzero(ifa->next_hop_ip4))
        msg.update.next_hop = ifa->next_hop_ip4;

      /* Only send IPv6 nexthop if enabled */
      else if (ifa->cf->ext_next_hop)
        msg.update.next_hop = ifa->next_hop_ip6;
    }
    else
      msg.update.next_hop = ifa->next_hop_ip6;

    /* Do not send route if next hop is unknown, e.g. no configured IPv4 address */
    if (ipa_zero(msg.update.next_hop))
      continue;

    babel_enqueue(&msg, ifa);

    /* RFC 8966 3.7.3 - update feasibility distance for redistributed routes */
    if (e->router_id != p->router_id)
    {
      struct babel_source *s = babel_get_source(p, e, e->router_id, msg.update.seqno);
      s->expires = current_time() + BABEL_GARBAGE_INTERVAL;

      if (gt_mod64k(msg.update.seqno, s->seqno) ||
	  ((msg.update.seqno == s->seqno) && (msg.update.metric < s->metric)))
      {
	s->seqno = msg.update.seqno;
	s->metric = msg.update.metric;
      }
    }
  }
  FIB_WALK_END;
}

static void
babel_send_update(struct babel_iface *ifa, btime changed)
{
  struct babel_proto *p = ifa->proto;

  babel_send_update_(ifa, changed, &p->ip4_rtable);
  babel_send_update_(ifa, changed, &p->ip6_rtable);
}

static void
babel_trigger_iface_update(struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;

  /* Interface not active or already scheduled */
  if (!ifa->up || ifa->want_triggered)
    return;

  TRACE(D_EVENTS, "Scheduling triggered updates for %s seqno %d",
	ifa->iface->name, p->update_seqno);

  ifa->want_triggered = current_time();
  babel_iface_kick_timer(ifa);
}

/* Sends and update on all interfaces. */
static void
babel_trigger_update(struct babel_proto *p)
{
  if (p->triggered)
    return;

  struct babel_iface *ifa;
  WALK_LIST(ifa, p->interfaces)
    babel_trigger_iface_update(ifa);

  p->triggered = 1;
}

/* A retraction is an update with an infinite metric */
static void
babel_send_retraction(struct babel_iface *ifa, net_addr *n)
{
  struct babel_proto *p = ifa->proto;
  union babel_msg msg = {};

  TRACE(D_PACKETS, "Sending retraction for %N seqno %d", n, p->update_seqno);

  msg.type = BABEL_TLV_UPDATE;
  msg.update.interval = ifa->cf->update_interval;
  msg.update.seqno = p->update_seqno;
  msg.update.metric = BABEL_INFINITY;
  msg.update.net = *n;

  babel_enqueue(&msg, ifa);
}

static void
babel_send_wildcard_retraction(struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  union babel_msg msg = {};

  TRACE(D_PACKETS, "Sending wildcard retraction on %s", ifa->ifname);

  msg.type = BABEL_TLV_UPDATE;
  msg.update.wildcard = 1;
  msg.update.interval = ifa->cf->update_interval;
  msg.update.seqno = p->update_seqno;
  msg.update.metric = BABEL_INFINITY;

  babel_enqueue(&msg, ifa);
}


/*
 *	TLV handler helpers
 */

/* Update hello history according to Appendix A1 of the RFC */
static void
babel_update_hello_history(struct babel_neighbor *n, u16 seqno, uint interval)
{
  /*
   * Compute the difference between expected and received seqno (modulo 2^16).
   * If the expected and received seqnos are within 16 of each other, the modular
   * difference is going to be less than 16 for one of the directions. Otherwise,
   * the values differ too much, so just reset the state.
   */

  u16 delta = ((uint) seqno - (uint) n->next_hello_seqno);

  if ((delta == 0) || (n->hello_cnt == 0))
  {
    /* Do nothing */
  }
  else if (delta <= 16)
  {
    /* Sending node decreased interval; fast-forward */
    n->hello_map <<= delta;
    n->hello_cnt = MIN(n->hello_cnt + delta, 16);
  }
  else if (delta >= 0xfff0)
  {
    u8 diff = (0xffff - delta);
    /* Sending node increased interval; undo history */
    n->hello_map >>= diff;
    n->hello_cnt = (diff < n->hello_cnt) ? n->hello_cnt - diff : 0;
  }
  else
  {
    /* Note state reset - flush entries */
    n->hello_map = n->hello_cnt = 0;
  }

  /* Current entry */
  n->hello_map = (n->hello_map << 1) | 1;
  n->next_hello_seqno = seqno+1;
  if (n->hello_cnt < 16) n->hello_cnt++;

  /* Update expiration */
  n->hello_expiry = current_time() + BABEL_HELLO_EXPIRY_FACTOR(interval);
  n->last_hello_int = interval;

  /* Disable initial timeout */
  n->init_expiry = 0;
}


/*
 *	TLV handlers
 */

void
babel_handle_ack_req(union babel_msg *m, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_msg_ack_req *msg = &m->ack_req;

  TRACE(D_PACKETS, "Handling ACK request nonce %d interval %t",
	msg->nonce, (btime) msg->interval);

  babel_send_ack(ifa, msg->sender, msg->nonce);
}

void
babel_handle_hello(union babel_msg *m, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_msg_hello *msg = &m->hello;

  TRACE(D_PACKETS, "Handling hello seqno %d interval %t",
	msg->seqno, (btime) msg->interval);

  struct babel_neighbor *n = babel_get_neighbor(ifa, msg->sender);
  struct babel_iface_config *cf = n->ifa->cf;
  int first_hello = !n->hello_cnt;

  if (msg->tstamp)
  {
    n->last_tstamp = msg->tstamp;
    n->last_tstamp_rcvd = msg->pkt_received;
  }
  babel_update_hello_history(n, msg->seqno, msg->interval);
  babel_update_cost(n);

  /* Speed up session establishment by sending IHU immediately */
  if (first_hello)
  {
    /* if using RTT, all IHUs must be paired with hellos */
    if(cf->rtt_send)
      babel_send_hello(ifa, 0);
    else
      babel_send_ihu(ifa, n);
  }
}

void
babel_handle_ihu(union babel_msg *m, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_msg_ihu *msg = &m->ihu;

  /* Ignore IHUs that are not about us */
  if ((msg->ae != BABEL_AE_WILDCARD) && !ipa_equal(msg->addr, ifa->addr))
    return;

  TRACE(D_PACKETS, "Handling IHU rxcost %d interval %t",
	msg->rxcost, (btime) msg->interval);

  struct babel_neighbor *n = babel_get_neighbor(ifa, msg->sender);
  n->txcost = msg->rxcost;
  n->ihu_expiry = current_time() + BABEL_IHU_EXPIRY_FACTOR(msg->interval);

  if (msg->tstamp)
  {
    u32 rtt_sample = 0, pkt_received = msg->pkt_received TO_US;
    int remote_time, full_time;

    /* processing time reported by peer */
    remote_time = (n->last_tstamp - msg->tstamp_rcvd);
    /* time since we sent the last timestamp - RTT including remote time */
    full_time = (pkt_received - msg->tstamp);

    /* sanity checks */
    if (remote_time < 0 || full_time < 0 ||
        remote_time US_ > BABEL_RTT_MAX_VALUE || full_time US_ > BABEL_RTT_MAX_VALUE)
      goto out;

    if (remote_time < full_time)
      rtt_sample = full_time - remote_time;

    if (n->srtt)
    {
      uint decay = n->ifa->cf->rtt_decay;

      n->srtt = (decay * rtt_sample + (256 - decay) * n->srtt) / 256;
    }
    else
      n->srtt = rtt_sample;

    TRACE(D_EVENTS, "RTT sample for neighbour %I on %s: %u us (srtt %t ms)",
          n->addr, ifa->ifname, rtt_sample, n->srtt * 1000);
  }

out:
  babel_update_cost(n);
}

/**
 * babel_handle_update - handle incoming route updates
 * @m: Incoming update TLV
 * @ifa: Interface the update was received on
 *
 * This function is called as a handler for update TLVs and handles the updating
 * and maintenance of route entries in Babel's internal routing cache. The
 * handling follows the actions described in the Babel RFC, and at the end of
 * each update handling, babel_select_route() is called on the affected entry to
 * optionally update the selected routes and propagate them to the core.
 */
void
babel_handle_update(union babel_msg *m, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_msg_update *msg = &m->update;

  struct babel_neighbor *nbr;
  struct babel_entry *e;
  struct babel_source *s;
  struct babel_route *r, *best;
  node *n;
  int feasible, metric;

  if (msg->wildcard)
    TRACE(D_PACKETS, "Handling wildcard retraction", msg->seqno);
  else
    TRACE(D_PACKETS, "Handling update for %N with seqno %d metric %d",
	  &msg->net, msg->seqno, msg->metric);

  nbr = babel_find_neighbor(ifa, msg->sender);
  if (!nbr)
  {
    DBG("Babel: Haven't heard from neighbor %I; ignoring update.\n", msg->sender);
    return;
  }

  if (msg->router_id == p->router_id)
  {
    DBG("Babel: Ignoring update for our own router ID.\n");
    return;
  }

  struct channel *c = (msg->net.type == NET_IP4) ? p->ip4_channel : p->ip6_channel;
  if (!c || (c->channel_state != CS_UP))
  {
    DBG("Babel: Ignoring update for inactive address family.\n");
    return;
  }

  /* Reject IPv4 via IPv6 routes if disabled */
  if ((msg->net.type == NET_IP4) && ipa_is_ip6(msg->next_hop) && !ifa->cf->ext_next_hop)
  {
    DBG("Babel: Ignoring disabled IPv4 via IPv6 route.\n");
    return;
  }

  /* Retraction */
  if (msg->metric == BABEL_INFINITY)
  {
    if (msg->wildcard)
    {
      /*
       * Special case: This is a retraction of all prefixes announced by this
       * neighbour (see second-to-last paragraph of section 4.4.9 in the RFC).
       */
      WALK_LIST(n, nbr->routes)
      {
	r = SKIP_BACK(struct babel_route, neigh_route, n);
	babel_retract_route(p, r);
      }
    }
    else
    {
      e = babel_find_entry(p, &msg->net);

      if (!e)
	return;

      /* The route entry indexed by neighbour */
      r = babel_find_route(e, nbr);

      if (!r)
	return;

      /* Router-id, next-hop and seqno are ignored for retractions */
      babel_retract_route(p, r);
    }

    /* Done with retractions */
    return;
  }

  /* Regular update */
  e = babel_get_entry(p, &msg->net);
  r = babel_get_route(p, e, nbr); /* the route entry indexed by neighbour */
  s = babel_find_source(e, msg->router_id); /* for feasibility */
  feasible = babel_is_feasible(s, msg->seqno, msg->metric);
  metric = babel_compute_metric(nbr, msg->metric);
  best = e->selected;

  /*
   * RFC 8966 3.8.2.2 - dealing with unfeasible updates. Generate a one-off
   * (not retransmitted) unicast seqno request to the originator of this update.
   * Note: !feasible -> s exists, check for 's' is just for clarity / safety.
   */
  if (!feasible && s && (metric != BABEL_INFINITY) &&
      (!best || (r == best) || (metric < best->metric)))
    babel_generate_seqno_request(p, e, s->router_id, s->seqno + 1, nbr);

  /* Special case - ignore unfeasible update to best route */
  if (r == best && !feasible && (msg->router_id == r->router_id))
    return;

  r->expires = current_time() + BABEL_ROUTE_EXPIRY_FACTOR(msg->interval);
  r->refresh_time = current_time() + BABEL_ROUTE_REFRESH_FACTOR(msg->interval);

  /* No further processing if there is no change */
  if ((r->feasible == feasible) && (r->seqno == msg->seqno) &&
      (r->metric == metric) && (r->advert_metric == msg->metric) &&
      (r->router_id == msg->router_id) && ipa_equal(r->next_hop, msg->next_hop))
    return;

  /* Last paragraph above - update the entry */
  r->feasible = feasible;
  r->seqno = msg->seqno;
  r->metric = metric;
  r->advert_metric = msg->metric;
  r->router_id = msg->router_id;
  r->next_hop = msg->next_hop;

  /* If received update satisfies seqno request, we send triggered updates */
  if (babel_satisfy_seqno_request(p, e, msg->router_id, msg->seqno))
  {
    babel_trigger_update(p);
    e->updated = current_time();
  }

  babel_select_route(p, e, r);
}

void
babel_handle_route_request(union babel_msg *m, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_msg_route_request *msg = &m->route_request;

  /* RFC 8966 3.8.1.1 */

  /* Wildcard request - full update on the interface */
  if (msg->full)
  {
    TRACE(D_PACKETS, "Handling wildcard route request");
    ifa->want_triggered = 1;
    return;
  }

  TRACE(D_PACKETS, "Handling route request for %N", &msg->net);

  /* Non-wildcard request - see if we have an entry for the route.
     If not, send a retraction, otherwise send an update. */
  struct babel_entry *e = babel_find_entry(p, &msg->net);
  if (!e)
  {
    babel_send_retraction(ifa, &msg->net);
  }
  else
  {
    babel_trigger_iface_update(ifa);
    e->updated = current_time();
  }
}

static struct babel_neighbor *
babel_find_seqno_request_target(struct babel_entry *e, struct babel_neighbor *skip)
{
  struct babel_route *r, *best_feasible = NULL, *best_any = NULL;

  WALK_LIST(r, e->routes)
  {
    if (r->neigh == skip)
      continue;

    if (r->feasible && (!best_feasible || r->metric < best_feasible->metric))
      best_feasible = r;

    if (!best_any || r->metric < best_any->metric)
      best_any = r;
  }

  if (best_feasible)
    return best_feasible->neigh;

  if (best_any)
    return best_any->neigh;

  return NULL;
}

void
babel_handle_seqno_request(union babel_msg *m, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_msg_seqno_request *msg = &m->seqno_request;

  /* RFC 8966 3.8.1.2 */

  TRACE(D_PACKETS, "Handling seqno request for %N router-id %lR seqno %d hop count %d",
	&msg->net, msg->router_id, msg->seqno, msg->hop_count);

  /* Ignore if we have no such entry or entry has infinite metric */
  struct babel_entry *e = babel_find_entry(p, &msg->net);
  if (!e || !e->valid || (e->metric == BABEL_INFINITY))
    return;

  /* Trigger update on incoming interface if we have a selected route with
     different router id or seqno no smaller than requested */
  if ((e->router_id != msg->router_id) || ge_mod64k(e->seqno, msg->seqno))
  {
    babel_trigger_iface_update(ifa);
    e->updated = current_time();
    return;
  }

  /* Seqno is larger; check if we own the router id */
  if (msg->router_id == p->router_id)
  {
    /* Ours; seqno increase and trigger global update */
    p->update_seqno_inc = 1;
    babel_trigger_update(p);
  }
  else if (msg->hop_count > 1)
  {
    /* Not ours; forward if TTL allows it */

    struct babel_neighbor *nbr, *target;

    nbr = babel_find_neighbor(ifa, msg->sender);
    if (!nbr)
      return;

    target = babel_find_seqno_request_target(e, nbr);
    if (!target)
    {
      TRACE(D_PACKETS, "No neighbor to forward seqno request for %N router-id %lR seqno %d to",
            e->n.addr, msg->router_id, msg->seqno);
      return;
    }

    babel_add_seqno_request(p, e, msg->router_id, msg->seqno, msg->hop_count-1, target);
  }
}

/*
 *      Authentication functions
 */

/**
 * babel_auth_reset_index - Reset authentication index on interface
 * @ifa: Interface to reset
 *
 * This function resets the authentication index and packet counter for an
 * interface, and should be called on interface configuration, or when the
 * packet counter overflows.
 */
void
babel_auth_reset_index(struct babel_iface *ifa)
{
  random_bytes(ifa->auth_index, BABEL_AUTH_INDEX_LEN);
  ifa->auth_pc = 1;
}

static void
babel_auth_send_challenge_request(struct babel_iface *ifa, struct babel_neighbor *n)
{
  struct babel_proto *p = ifa->proto;
  union babel_msg msg = {};

  TRACE(D_PACKETS, "Sending challenge request to %I on %s",
	n->addr, ifa->ifname);

  random_bytes(n->auth_nonce, BABEL_AUTH_NONCE_LEN);
  n->auth_nonce_expiry = current_time() + BABEL_AUTH_CHALLENGE_TIMEOUT;
  n->auth_next_challenge = current_time() + BABEL_AUTH_CHALLENGE_INTERVAL;

  msg.type = BABEL_TLV_CHALLENGE_REQUEST;
  msg.challenge.nonce_len = BABEL_AUTH_NONCE_LEN;
  msg.challenge.nonce = n->auth_nonce;

  babel_send_unicast(&msg, ifa, n->addr);
}

static void
babel_auth_send_challenge_reply(struct babel_iface *ifa, struct babel_neighbor *n, struct babel_msg_auth *rcv)
{
  struct babel_proto *p = ifa->proto;
  union babel_msg msg = {};

  TRACE(D_PACKETS, "Sending challenge reply to %I on %s",
	n->addr, ifa->ifname);

  n->auth_next_challenge_reply = current_time() + BABEL_AUTH_CHALLENGE_INTERVAL;

  msg.type = BABEL_TLV_CHALLENGE_REPLY;
  msg.challenge.nonce_len = rcv->challenge_len;
  msg.challenge.nonce = rcv->challenge;

  babel_send_unicast(&msg, ifa, n->addr);
}

int
babel_auth_check_pc(struct babel_iface *ifa, struct babel_msg_auth *msg)
{
  struct babel_proto *p = ifa->proto;
  struct babel_neighbor *n;

  /*
   * We create the neighbour entry at this point because it makes it easier to
   * rate limit challenge replies; this is explicitly allowed by the spec (see
   * Section 4.3).
   */
  n = babel_get_neighbor(ifa, msg->sender);

  /* (3b) Handle challenge request */
  if (msg->challenge_seen && (n->auth_next_challenge_reply <= current_time()))
    babel_auth_send_challenge_reply(ifa, n, msg);

  /* (4a) If PC TLV is missing, drop the packet */
  if (!msg->pc_seen)
  {
    LOG_PKT_AUTH("Authentication failed for %I on %s - missing or invalid PC",
                 msg->sender, ifa->ifname);
    return 0;
  }

  /* (4b) On successful challenge, update PC and index to current values */
  if (msg->challenge_reply_seen &&
      (n->auth_nonce_expiry > current_time()) &&
      !memcmp(msg->challenge_reply, n->auth_nonce, BABEL_AUTH_NONCE_LEN))
  {
    n->auth_index_len = msg->index_len;
    memcpy(n->auth_index, msg->index, msg->index_len);

    n->auth_pc_unicast = msg->pc;
    n->auth_pc_multicast = msg->pc;
    n->auth_passed = 1;

    return 1;
  }

  /* (5) If index differs, send challenge and drop the packet */
  if ((n->auth_index_len != msg->index_len) ||
      memcmp(n->auth_index, msg->index, msg->index_len))
  {
    TRACE(D_PACKETS, "Index mismatch for packet from %I via %s",
	  msg->sender, ifa->ifname);

    if (n->auth_next_challenge <= current_time())
      babel_auth_send_challenge_request(ifa, n);

    return 0;
  }

  /*
   * (6) Index matches; only accept if PC is greater than last. We keep separate
   * counters for unicast and multicast because multicast packets can be delayed
   * significantly on wireless networks (enough to be received out of order).
   * Separate counters are safe because the packet destination address is part
   * of the MAC pseudo-header (so unicast packets can't be replayed as multicast
   * and vice versa).
   */
  u32 auth_pc = msg->unicast ? n->auth_pc_unicast : n->auth_pc_multicast;
  if (auth_pc >= msg->pc)
  {
    LOG_PKT_AUTH("Authentication failed for %I on %s - "
		 "lower %s packet counter (rcv %u, old %u)",
                 msg->sender, ifa->ifname,
		 msg->unicast ? "unicast" : "multicast",
		 msg->pc, auth_pc);
    return 0;
  }

  if (msg->unicast)
    n->auth_pc_unicast = msg->pc;
  else
    n->auth_pc_multicast = msg->pc;

  n->auth_passed = 1;

  return 1;
}


/*
 *	Babel interfaces
 */

/**
 * babel_iface_timer - Babel interface timer handler
 * @t: Timer
 *
 * This function is called by the per-interface timer and triggers sending of
 * periodic Hello's and both triggered and periodic updates. Periodic Hello's
 * and updates are simply handled by setting the next_{hello,regular} variables
 * on the interface, and triggering an update (and resetting the variable)
 * whenever 'now' exceeds that value.
 *
 * For triggered updates, babel_trigger_iface_update() will set the
 * want_triggered field on the interface to a timestamp value. If this is set
 * (and the next_triggered time has passed; this is a rate limiting mechanism),
 * babel_send_update() will be called with this timestamp as the second
 * parameter. This causes updates to be send consisting of only the routes that
 * have changed since the time saved in want_triggered.
 *
 * Mostly when an update is triggered, the route being modified will be set to
 * the value of 'now' at the time of the trigger; the >= comparison for
 * selecting which routes to send in the update will make sure this is included.
 */
static void
babel_iface_timer(timer *t)
{
  struct babel_iface *ifa = t->data;
  struct babel_proto *p = ifa->proto;
  btime hello_period = ifa->cf->hello_interval;
  btime update_period = ifa->cf->update_interval;
  btime now_ = current_time();

  if (now_ >= ifa->next_hello)
  {
    babel_send_hello(ifa, 0);
    ifa->next_hello += hello_period * (1 + (now_ - ifa->next_hello) / hello_period);
  }

  if (now_ >= ifa->next_regular)
  {
    TRACE(D_EVENTS, "Sending regular updates on %s", ifa->ifname);
    babel_send_update(ifa, 0);
    ifa->next_regular += update_period * (1 + (now_ - ifa->next_regular) / update_period);
    ifa->want_triggered = 0;
    p->triggered = 0;
  }
  else if (ifa->want_triggered && (now_ >= ifa->next_triggered))
  {
    TRACE(D_EVENTS, "Sending triggered updates on %s", ifa->ifname);
    babel_send_update(ifa, ifa->want_triggered);
    ifa->next_triggered = now_ + MIN(1 S, update_period / 2);
    ifa->want_triggered = 0;
    p->triggered = 0;
  }

  btime next_event = MIN(ifa->next_hello, ifa->next_regular);
  if (ifa->want_triggered) next_event = MIN(next_event, ifa->next_triggered);
  tm_set(ifa->timer, next_event);
}

static inline void
babel_iface_kick_timer(struct babel_iface *ifa)
{
  if (ifa->timer->expires > (current_time() + 100 MS))
    tm_start(ifa->timer, 100 MS);
}

static void
babel_iface_start(struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;

  TRACE(D_EVENTS, "Starting interface %s", ifa->ifname);

  ifa->next_hello = current_time() + (random() % ifa->cf->hello_interval);
  ifa->next_regular = current_time() + (random() % ifa->cf->update_interval);
  ifa->next_triggered = current_time() + MIN(1 S, ifa->cf->update_interval / 2);
  ifa->want_triggered = 0;	/* We send an immediate update (below) */
  tm_start(ifa->timer, 100 MS);
  ifa->up = 1;

  babel_send_hello(ifa, 0);
  babel_send_wildcard_retraction(ifa);
  babel_send_wildcard_request(ifa);
  babel_send_update(ifa, 0);	/* Full update */
}

static void
babel_iface_stop(struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_neighbor *nbr;
  struct babel_route *r;
  node *n;

  TRACE(D_EVENTS, "Stopping interface %s", ifa->ifname);

  /*
   * Rather than just flushing the neighbours, we set the metric of their routes
   * to infinity. This allows us to keep the neighbour hello state for when the
   * interface comes back up. The routes will also be kept until they expire.
   */
  WALK_LIST(nbr, ifa->neigh_list)
  {
    WALK_LIST(n, nbr->routes)
    {
      r = SKIP_BACK(struct babel_route, neigh_route, n);
      babel_retract_route(p, r);
    }
  }

  tm_stop(ifa->timer);
  ifa->up = 0;
}

static inline int
babel_iface_link_up(struct babel_iface *ifa)
{
  return !ifa->cf->check_link || (ifa->iface->flags & IF_LINK_UP);
}

static void
babel_iface_update_state(struct babel_iface *ifa)
{
  int up = ifa->sk && babel_iface_link_up(ifa);

  if (up == ifa->up)
    return;

  if (up)
    babel_iface_start(ifa);
  else
    babel_iface_stop(ifa);
}

static void
babel_iface_update_addr4(struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;

  ip_addr addr4 = ifa->iface->addr4 ? ifa->iface->addr4->ip : IPA_NONE;
  ifa->next_hop_ip4 = ipa_nonzero(ifa->cf->next_hop_ip4) ? ifa->cf->next_hop_ip4 : addr4;

  if (ipa_zero(ifa->next_hop_ip4) && p->ip4_channel && !ifa->cf->ext_next_hop)
    log(L_WARN "%s: Missing IPv4 next hop address for %s", p->p.name, ifa->ifname);

  if (ifa->up)
    babel_iface_kick_timer(ifa);
}

static void
babel_iface_update_buffers(struct babel_iface *ifa)
{
  if (!ifa->sk)
    return;

  uint mtu = MAX(BABEL_MIN_MTU, ifa->iface->mtu);
  uint rbsize = ifa->cf->rx_buffer ?: mtu;
  uint tbsize = ifa->cf->tx_length ?: mtu;
  rbsize = MAX(rbsize, tbsize);

  sk_set_rbsize(ifa->sk, rbsize);
  sk_set_tbsize(ifa->sk, tbsize);

  ifa->tx_length = tbsize - BABEL_OVERHEAD;

  babel_auth_set_tx_overhead(ifa);
}

static struct babel_iface*
babel_find_iface(struct babel_proto *p, struct iface *what)
{
  struct babel_iface *ifa;

  WALK_LIST (ifa, p->interfaces)
    if (ifa->iface == what)
      return ifa;

  return NULL;
}

static void
babel_iface_locked(struct object_lock *lock)
{
  struct babel_iface *ifa = lock->data;
  struct babel_proto *p = ifa->proto;

  if (!babel_open_socket(ifa))
  {
    log(L_ERR "%s: Cannot open socket for %s", p->p.name, ifa->iface->name);
    return;
  }

  babel_iface_update_buffers(ifa);
  babel_iface_update_state(ifa);
}

static void
babel_add_iface(struct babel_proto *p, struct iface *new, struct babel_iface_config *ic)
{
  struct babel_iface *ifa;

  TRACE(D_EVENTS, "Adding interface %s", new->name);

  pool *pool = rp_new(p->p.pool, new->name);

  ifa = mb_allocz(pool, sizeof(struct babel_iface));
  ifa->proto = p;
  ifa->iface = new;
  ifa->cf = ic;
  ifa->pool = pool;
  ifa->ifname = new->name;
  ifa->addr = new->llv6->ip;

  add_tail(&p->interfaces, NODE ifa);

  ip_addr addr4 = new->addr4 ? new->addr4->ip : IPA_NONE;
  ifa->next_hop_ip4 = ipa_nonzero(ic->next_hop_ip4) ? ic->next_hop_ip4 : addr4;
  ifa->next_hop_ip6 = ipa_nonzero(ic->next_hop_ip6) ? ic->next_hop_ip6 : ifa->addr;

  if (ipa_zero(ifa->next_hop_ip4) && p->ip4_channel && !ic->ext_next_hop)
    log(L_WARN "%s: Missing IPv4 next hop address for %s", p->p.name, ifa->ifname);

  init_list(&ifa->neigh_list);
  ifa->hello_seqno = 1;

  if (ic->auth_type != BABEL_AUTH_NONE)
    babel_auth_reset_index(ifa);

  ifa->timer = tm_new_init(ifa->pool, babel_iface_timer, ifa, 0, 0);

  init_list(&ifa->msg_queue);
  ifa->send_event = ev_new_init(ifa->pool, babel_send_queue, ifa);

  struct object_lock *lock = olock_new(ifa->pool);
  lock->type = OBJLOCK_UDP;
  lock->addr = IP6_BABEL_ROUTERS;
  lock->port = ifa->cf->port;
  lock->iface = ifa->iface;
  lock->hook = babel_iface_locked;
  lock->data = ifa;

  olock_acquire(lock);
}

static void
babel_remove_iface(struct babel_proto *p, struct babel_iface *ifa)
{
  TRACE(D_EVENTS, "Removing interface %s", ifa->iface->name);

  struct babel_neighbor *n;
  WALK_LIST_FIRST(n, ifa->neigh_list)
    babel_flush_neighbor(p, n);

  rem_node(NODE ifa);

  rfree(ifa->pool); /* contains ifa itself, locks, socket, etc */
}

static int
iface_is_valid(struct babel_proto *p, struct iface *iface)
{
  if (!(iface->flags & IF_MULTICAST))
  {
    log(L_ERR "%s: Interface %s does not support multicast",
	p->p.name, iface->name);

    return 0;
  }

  return 1;
}

static void
babel_if_notify(struct proto *P, unsigned flags, struct iface *iface)
{
  struct babel_proto *p = (void *) P;
  struct babel_config *cf = (void *) P->cf;
  struct babel_iface *ifa = babel_find_iface(p, iface);

  if (iface->flags & IF_IGNORE)
    return;

  /* Add, remove or restart interface */
  if (flags & (IF_CHANGE_UPDOWN | IF_CHANGE_LLV6))
  {
    if (ifa)
      babel_remove_iface(p, ifa);

    if (!(iface->flags & IF_UP))
      return;

    /* Ignore ifaces without link-local address */
    if (!iface->llv6)
      return;

    struct babel_iface_config *ic = (void *) iface_patt_find(&cf->iface_list, iface, NULL);

    if (ic && iface_is_valid(p, iface))
      babel_add_iface(p, iface, ic);

    return;
  }

  if (!ifa)
    return;

  if (flags & IF_CHANGE_ADDR4)
    babel_iface_update_addr4(ifa);

  if (flags & IF_CHANGE_MTU)
    babel_iface_update_buffers(ifa);

  if (flags & IF_CHANGE_LINK)
    babel_iface_update_state(ifa);
}

static int
babel_reconfigure_iface(struct babel_proto *p, struct babel_iface *ifa, struct babel_iface_config *new)
{
  struct babel_iface_config *old = ifa->cf;

  /* Change of these options would require to reset the iface socket */
  if ((new->port != old->port) ||
      (new->tx_tos != old->tx_tos) ||
      (new->tx_priority != old->tx_priority))
    return 0;

  TRACE(D_EVENTS, "Reconfiguring interface %s", ifa->iface->name);

  ifa->cf = new;

  ip_addr addr4 = ifa->iface->addr4 ? ifa->iface->addr4->ip : IPA_NONE;
  ifa->next_hop_ip4 = ipa_nonzero(new->next_hop_ip4) ? new->next_hop_ip4 : addr4;
  ifa->next_hop_ip6 = ipa_nonzero(new->next_hop_ip6) ? new->next_hop_ip6 : ifa->addr;

  babel_iface_update_buffers(ifa);

  if ((new->auth_type != BABEL_AUTH_NONE) && (new->auth_type != old->auth_type))
    babel_auth_reset_index(ifa);

  if (ipa_zero(ifa->next_hop_ip4) && p->ip4_channel && !new->ext_next_hop)
    log(L_WARN "%s: Missing IPv4 next hop address for %s", p->p.name, ifa->ifname);

  if (ifa->next_hello > (current_time() + new->hello_interval))
    ifa->next_hello = current_time() + (random() % new->hello_interval);

  if (ifa->next_regular > (current_time() + new->update_interval))
    ifa->next_regular = current_time() + (random() % new->update_interval);

  if (new->check_link != old->check_link)
    babel_iface_update_state(ifa);

  if (ifa->up)
    babel_iface_kick_timer(ifa);

  return 1;
}

static void
babel_reconfigure_ifaces(struct babel_proto *p, struct babel_config *cf)
{
  struct iface *iface;

  WALK_LIST(iface, iface_list)
  {
    if (p->p.vrf_set && !if_in_vrf(iface, p->p.vrf))
      continue;

    if (!(iface->flags & IF_UP))
      continue;

    /* Ignore ifaces without link-local address */
    if (!iface->llv6)
      continue;

    struct babel_iface *ifa = babel_find_iface(p, iface);
    struct babel_iface_config *ic = (void *) iface_patt_find(&cf->iface_list, iface, NULL);

    if (ic && !iface_is_valid(p, iface))
      ic = NULL;

    if (ifa && ic)
    {
      if (babel_reconfigure_iface(p, ifa, ic))
	continue;

      /* Hard restart */
      log(L_INFO "%s: Restarting interface %s", p->p.name, ifa->iface->name);
      babel_remove_iface(p, ifa);
      babel_add_iface(p, iface, ic);
    }

    if (ifa && !ic)
      babel_remove_iface(p, ifa);

    if (!ifa && ic)
      babel_add_iface(p, iface, ic);
  }
}


/*
 *	Debugging and info output functions
 */

static void
babel_dump_source(struct babel_source *s)
{
  debug("Source router_id %lR seqno %d metric %d expires %t\n",
	s->router_id, s->seqno, s->metric,
	s->expires ? s->expires - current_time() : 0);
}

static void
babel_dump_route(struct babel_route *r)
{
  debug("Route neigh %I if %s seqno %d metric %d/%d router_id %lR expires %t\n",
	r->neigh->addr, r->neigh->ifa->ifname, r->seqno, r->advert_metric, r->metric,
	r->router_id, r->expires ? r->expires - current_time() : 0);
}

static void
babel_dump_entry(struct babel_entry *e)
{
  struct babel_source *s;
  struct babel_route *r;

  debug("Babel: Entry %N:\n", e->n.addr);

  WALK_LIST(s,e->sources)
  { debug(" "); babel_dump_source(s); }

  WALK_LIST(r,e->routes)
  {
    debug(" ");
    if (r == e->selected) debug("*");
    babel_dump_route(r);
  }
}

static void
babel_dump_neighbor(struct babel_neighbor *n)
{
  debug("Neighbor %I txcost %d hello_map %x next seqno %d expires %t/%t\n",
	n->addr, n->txcost, n->hello_map, n->next_hello_seqno,
	n->hello_expiry ? n->hello_expiry - current_time() : 0,
        n->ihu_expiry ? n->ihu_expiry - current_time() : 0);
}

static void
babel_dump_iface(struct babel_iface *ifa)
{
  struct babel_neighbor *n;

  debug("Babel: Interface %s addr %I rxcost %d type %d hello seqno %d intervals %t %t",
	ifa->ifname, ifa->addr, ifa->cf->rxcost, ifa->cf->type, ifa->hello_seqno,
	ifa->cf->hello_interval, ifa->cf->update_interval);
  debug(" next hop v4 %I next hop v6 %I\n", ifa->next_hop_ip4, ifa->next_hop_ip6);

  WALK_LIST(n, ifa->neigh_list)
  { debug(" "); babel_dump_neighbor(n); }
}

static void
babel_dump(struct proto *P)
{
  struct babel_proto *p = (struct babel_proto *) P;
  struct babel_iface *ifa;

  debug("Babel: router id %lR update seqno %d\n", p->router_id, p->update_seqno);

  WALK_LIST(ifa, p->interfaces)
    babel_dump_iface(ifa);

  FIB_WALK(&p->ip4_rtable, struct babel_entry, e)
  {
    babel_dump_entry(e);
  }
  FIB_WALK_END;
  FIB_WALK(&p->ip6_rtable, struct babel_entry, e)
  {
    babel_dump_entry(e);
  }
  FIB_WALK_END;
}

static void
babel_get_route_info(rte *rte, byte *buf)
{
  u64 rid = 0;
  eattr *e = ea_find(rte->attrs->eattrs, EA_BABEL_ROUTER_ID);
  if (e)
    memcpy(&rid, e->u.ptr->data, sizeof(u64));

  buf += bsprintf(buf, " (%d/%d) [%lR]", rte->attrs->pref,
      ea_get_int(rte->attrs->eattrs, EA_BABEL_METRIC, BABEL_INFINITY), rid);
}

static int
babel_get_attr(const eattr *a, byte *buf, int buflen UNUSED)
{
  switch (a->id)
  {
  case EA_BABEL_METRIC:
    bsprintf(buf, "metric: %d", a->u.data);
    return GA_FULL;

  case EA_BABEL_ROUTER_ID:
  {
    u64 rid = 0;
    memcpy(&rid, a->u.ptr->data, sizeof(u64));
    bsprintf(buf, "router_id: %lR", rid);
    return GA_FULL;
  }

  case EA_BABEL_SEQNO:
    return GA_HIDDEN;

  default:
    return GA_UNKNOWN;
  }
}

void
babel_show_interfaces(struct proto *P, const char *iff)
{
  struct babel_proto *p = (void *) P;
  struct babel_iface *ifa = NULL;
  struct babel_neighbor *nbr = NULL;

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1023, "%s: is not up", p->p.name);
    return;
  }

  cli_msg(-1023, "%s:", p->p.name);
  cli_msg(-1023, "%-10s %-6s %-5s %7s %6s %7s %-15s %s",
	  "Interface", "State", "Auth", "RX cost", "Nbrs", "Timer",
	  "Next hop (v4)", "Next hop (v6)");

  WALK_LIST(ifa, p->interfaces)
  {
    if (iff && !patmatch(iff, ifa->iface->name))
      continue;

    int nbrs = 0;
    WALK_LIST(nbr, ifa->neigh_list)
	nbrs++;

    btime timer = MIN(ifa->next_regular, ifa->next_hello) - current_time();
    cli_msg(-1023, "%-10s %-6s %-5s %7u %6u %7t %-15I %I",
	    ifa->iface->name, (ifa->up ? "Up" : "Down"),
            (ifa->cf->auth_type == BABEL_AUTH_MAC ?
             (ifa->cf->auth_permissive ? "Perm" : "Yes") : "No"),
	    ifa->cf->rxcost, nbrs, MAX(timer, 0),
	    ifa->next_hop_ip4, ifa->next_hop_ip6);
  }
}

void
babel_show_neighbors(struct proto *P, const char *iff)
{
  struct babel_proto *p = (void *) P;
  struct babel_iface *ifa = NULL;
  struct babel_neighbor *n = NULL;
  struct babel_route *r = NULL;

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1024, "%s: is not up", p->p.name);
    return;
  }

  cli_msg(-1024, "%s:", p->p.name);
  cli_msg(-1024, "%-25s %-10s %6s %6s %6s %7s %4s %9s",
	  "IP address", "Interface", "Metric", "Routes", "Hellos", "Expires", "Auth", "RTT (ms)");

  WALK_LIST(ifa, p->interfaces)
  {
    if (iff && !patmatch(iff, ifa->iface->name))
      continue;

    WALK_LIST(n, ifa->neigh_list)
    {
      int rts = 0;
      WALK_LIST(r, n->routes)
        rts++;

      uint hellos = u32_popcount(n->hello_map);
      btime timer = (n->hello_expiry ?: n->init_expiry) - current_time();
      cli_msg(-1024, "%-25I %-10s %6u %6u %6u %7t %-4s %9t",
	      n->addr, ifa->iface->name, n->cost, rts, hellos, MAX(timer, 0),
              n->auth_passed ? "Yes" : "No",
              n->srtt * 1000);
    }
  }
}

static void
babel_show_entries_(struct babel_proto *p, struct fib *rtable)
{
  int width = babel_sadr_enabled(p) ? -54 : -24;

  FIB_WALK(rtable, struct babel_entry, e)
  {
    struct babel_route *r = NULL;
    uint rts = 0, srcs = 0;
    node *n;

    WALK_LIST(n, e->routes)
      rts++;

    WALK_LIST(n, e->sources)
      srcs++;

    if (e->valid)
      cli_msg(-1025, "%-*N %-23lR %6u %5u %7u %7u", width,
	      e->n.addr, e->router_id, e->metric, e->seqno, rts, srcs);
    else if (r = e->selected)
      cli_msg(-1025, "%-*N %-23lR %6u %5u %7u %7u", width,
	      e->n.addr, r->router_id, r->metric, r->seqno, rts, srcs);
    else
      cli_msg(-1025, "%-*N %-23s %6s %5s %7u %7u", width,
	      e->n.addr, "<none>", "-", "-", rts, srcs);
  }
  FIB_WALK_END;
}

void
babel_show_entries(struct proto *P)
{
  struct babel_proto *p = (void *) P;
  int width = babel_sadr_enabled(p) ? -54 : -24;

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1025, "%s: is not up", p->p.name);
    return;
  }

  cli_msg(-1025, "%s:", p->p.name);
  cli_msg(-1025, "%-*s %-23s %6s %5s %7s %7s", width,
	  "Prefix", "Router ID", "Metric", "Seqno", "Routes", "Sources");

  babel_show_entries_(p, &p->ip4_rtable);
  babel_show_entries_(p, &p->ip6_rtable);
}

static void
babel_show_routes_(struct babel_proto *p, struct fib *rtable)
{
  int width = babel_sadr_enabled(p) ? -54 : -24;

  FIB_WALK(rtable, struct babel_entry, e)
  {
    struct babel_route *r;
    WALK_LIST(r, e->routes)
    {
      char c = (r == e->selected) ? '*' : (r->feasible ? '+' : ' ');
      btime time = r->expires ? r->expires - current_time() : 0;
      cli_msg(-1025, "%-*N %-25I %-10s %5u %c %5u %7t", width,
	      e->n.addr, r->next_hop, r->neigh->ifa->ifname,
	      r->metric, c, r->seqno, MAX(time, 0));
    }
  }
  FIB_WALK_END;
}

void
babel_show_routes(struct proto *P)
{
  struct babel_proto *p = (void *) P;
  int width = babel_sadr_enabled(p) ? -54 : -24;

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1025, "%s: is not up", p->p.name);
    return;
  }

  cli_msg(-1025, "%s:", p->p.name);
  cli_msg(-1025, "%-*s %-25s %-9s %6s F %5s %7s", width,
	  "Prefix", "Nexthop", "Interface", "Metric", "Seqno", "Expires");

  babel_show_routes_(p, &p->ip4_rtable);
  babel_show_routes_(p, &p->ip6_rtable);
}


/*
 *	Babel protocol glue
 */

/**
 * babel_timer - global timer hook
 * @t: Timer
 *
 * This function is called by the global protocol instance timer and handles
 * expiration of routes and neighbours as well as pruning of the seqno request
 * cache.
 */
static void
babel_timer(timer *t)
{
  struct babel_proto *p = t->data;

  babel_expire_routes(p);
  babel_expire_neighbors(p);
}

static inline void
babel_kick_timer(struct babel_proto *p)
{
  if (p->timer->expires > (current_time() + 100 MS))
    tm_start(p->timer, 100 MS);
}


static int
babel_preexport(struct channel *C, struct rte *new)
{
  struct rta *a = new->attrs;
  /* Reject our own unreachable routes */
  if ((a->dest == RTD_UNREACHABLE) && (new->src->proto == C->proto))
    return -1;

  return 0;
}

/*
 * babel_rt_notify - core tells us about new route (possibly our own),
 * so store it into our data structures.
 */
static void
babel_rt_notify(struct proto *P, struct channel *c UNUSED, struct network *net,
		struct rte *new, struct rte *old UNUSED)
{
  struct babel_proto *p = (void *) P;
  struct babel_entry *e;

  if (new)
  {
    /* Update */
    uint rt_seqno;
    uint rt_metric = ea_get_int(new->attrs->eattrs, EA_BABEL_METRIC, 0);
    u64 rt_router_id = 0;

    if (new->src->proto == P)
    {
      rt_seqno = ea_find(new->attrs->eattrs, EA_BABEL_SEQNO)->u.data;
      eattr *e = ea_find(new->attrs->eattrs, EA_BABEL_ROUTER_ID);
      if (e)
	memcpy(&rt_router_id, e->u.ptr->data, sizeof(u64));
    }
    else
    {
      rt_seqno = p->update_seqno;
      rt_router_id = p->router_id;
    }

    if (rt_metric > BABEL_INFINITY)
    {
      log(L_WARN "%s: Invalid babel_metric value %u for route %N",
	  p->p.name, rt_metric, net->n.addr);
      rt_metric = BABEL_INFINITY;
    }

    e = babel_get_entry(p, net->n.addr);

    /* Activate triggered updates */
    if ((e->valid != BABEL_ENTRY_VALID) ||
	(e->router_id != rt_router_id))
    {
      babel_trigger_update(p);
      e->updated = current_time();
    }

    e->valid = BABEL_ENTRY_VALID;
    e->seqno = rt_seqno;
    e->metric = rt_metric;
    e->router_id = rt_router_id;
  }
  else
  {
    /* Withdraw */
    e = babel_find_entry(p, net->n.addr);

    if (!e || e->valid != BABEL_ENTRY_VALID)
      return;

    e->valid = BABEL_ENTRY_STALE;
    e->metric = BABEL_INFINITY;

    babel_trigger_update(p);
    e->updated = current_time();
  }
}

static int
babel_rte_better(struct rte *new, struct rte *old)
{
  uint new_metric = ea_get_int(new->attrs->eattrs, EA_BABEL_METRIC, BABEL_INFINITY);
  uint old_metric = ea_get_int(old->attrs->eattrs, EA_BABEL_METRIC, BABEL_INFINITY);

  return new_metric < old_metric;
}

static u32
babel_rte_igp_metric(struct rte *rt)
{
  return ea_get_int(rt->attrs->eattrs, EA_BABEL_METRIC, BABEL_INFINITY);
}


static void
babel_postconfig(struct proto_config *CF)
{
  struct babel_config *cf = (void *) CF;
  struct channel_config *ip4, *ip6, *ip6_sadr;

  ip4 = proto_cf_find_channel(CF, NET_IP4);
  ip6 = proto_cf_find_channel(CF, NET_IP6);
  ip6_sadr = proto_cf_find_channel(CF, NET_IP6_SADR);

  if (ip6 && ip6_sadr)
    cf_error("Both ipv6 and ipv6-sadr channels");

  cf->ip4_channel = ip4;
  cf->ip6_channel = ip6 ?: ip6_sadr;
}

static struct proto *
babel_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct babel_proto *p = (void *) P;
  struct babel_config *cf = (void *) CF;

  proto_configure_channel(P, &p->ip4_channel, cf->ip4_channel);
  proto_configure_channel(P, &p->ip6_channel, cf->ip6_channel);

  P->if_notify = babel_if_notify;
  P->rt_notify = babel_rt_notify;
  P->preexport = babel_preexport;
  P->rte_better = babel_rte_better;
  P->rte_igp_metric = babel_rte_igp_metric;

  return P;
}

static inline void
babel_randomize_router_id(struct babel_proto *p)
{
  p->router_id &= (u64) 0xffffffff;
  p->router_id |= ((u64) random()) << 32;
  TRACE(D_EVENTS, "Randomized router ID to %lR", p->router_id);
}

static int
babel_start(struct proto *P)
{
  struct babel_proto *p = (void *) P;
  struct babel_config *cf = (void *) P->cf;
  u8 ip6_type = cf->ip6_channel ? cf->ip6_channel->net_type : NET_IP6;

  fib_init(&p->ip4_rtable, P->pool, NET_IP4, sizeof(struct babel_entry),
	   OFFSETOF(struct babel_entry, n), 0, babel_init_entry);
  fib_init(&p->ip6_rtable, P->pool, ip6_type, sizeof(struct babel_entry),
	   OFFSETOF(struct babel_entry, n), 0, babel_init_entry);

  init_list(&p->interfaces);
  p->timer = tm_new_init(P->pool, babel_timer, p, 1 S, 0);
  tm_start(p->timer, 1 S);
  p->update_seqno = 1;
  p->router_id = proto_get_router_id(&cf->c);

  if (cf->randomize_router_id)
    babel_randomize_router_id(p);

  p->route_slab = sl_new(P->pool, sizeof(struct babel_route));
  p->source_slab = sl_new(P->pool, sizeof(struct babel_source));
  p->msg_slab = sl_new(P->pool, sizeof(struct babel_msg_node));
  p->seqno_slab = sl_new(P->pool, sizeof(struct babel_seqno_request));

  p->log_pkt_tbf = (struct tbf){ .rate = 1, .burst = 5 };

  return PS_UP;
}

static inline void
babel_iface_shutdown(struct babel_iface *ifa)
{
  if (ifa->sk)
  {
    /*
     * Retract all our routes and lower the hello interval so peers' neighbour
     * state expires quickly
     */
    babel_send_hello(ifa, BABEL_MIN_INTERVAL);
    babel_send_wildcard_retraction(ifa);
    babel_send_queue(ifa);
  }
}

static int
babel_shutdown(struct proto *P)
{
  struct babel_proto *p = (void *) P;
  struct babel_iface *ifa;

  TRACE(D_EVENTS, "Shutdown requested");

  WALK_LIST(ifa, p->interfaces)
    babel_iface_shutdown(ifa);

  return PS_DOWN;
}

static int
babel_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct babel_proto *p = (void *) P;
  struct babel_config *new = (void *) CF;
  u8 ip6_type = new->ip6_channel ? new->ip6_channel->net_type : NET_IP6;

  TRACE(D_EVENTS, "Reconfiguring");

  if (p->ip6_rtable.addr_type != ip6_type)
    return 0;

  if (!proto_configure_channel(P, &p->ip4_channel, new->ip4_channel) ||
      !proto_configure_channel(P, &p->ip6_channel, new->ip6_channel))
    return 0;

  p->p.cf = CF;
  babel_reconfigure_ifaces(p, new);

  babel_trigger_update(p);
  babel_kick_timer(p);

  return 1;
}


struct protocol proto_babel = {
  .name =		"Babel",
  .template =		"babel%d",
  .class =		PROTOCOL_BABEL,
  .preference =		DEF_PREF_BABEL,
  .channel_mask =	NB_IP | NB_IP6_SADR,
  .proto_size =		sizeof(struct babel_proto),
  .config_size =	sizeof(struct babel_config),
  .postconfig =		babel_postconfig,
  .init =		babel_init,
  .dump =		babel_dump,
  .start =		babel_start,
  .shutdown =		babel_shutdown,
  .reconfigure =	babel_reconfigure,
  .get_route_info =	babel_get_route_info,
  .get_attr =		babel_get_attr
};

void
babel_build(void)
{
  proto_build(&proto_babel);
}
