/*
 *	BIRD -- Routing Tables
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2019--2024 Maria Matejka <mq@jmq.cz>
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
#include "lib/idm.h"

#ifdef CONFIG_BGP
#include "proto/bgp/bgp.h"
#endif

#include <stdatomic.h>

pool *rt_table_pool;

list routing_tables;
list deleted_routing_tables;

#define RT_INITIAL_ROUTES_BLOCK_SIZE   128

struct rt_cork rt_cork;

/* Data structures for export journal */

static void rt_free_hostcache(struct rtable_private *tab);
static void rt_hcu_uncork(callback *);
static void rt_update_hostcache(void *tab);
static void rt_next_hop_update(void *_tab);
static void rt_nhu_uncork(callback *);
static inline void rt_next_hop_resolve_rte(rte *r);
static inline void rt_flowspec_resolve_rte(rte *r, struct channel *c);
static void rt_refresh_trace(struct rtable_private *tab, struct rt_import_hook *ih, const char *msg);
static void rt_kick_prune_timer(struct rtable_private *tab);
static void rt_prune_table(void *_tab);
static void rt_check_cork_low(struct rtable_private *tab);
static void rt_check_cork_high(struct rtable_private *tab);
static void rt_shutdown(void *);
static void rt_delete(void *);

int rte_same(const rte *x, const rte *y);

static inline void rt_rte_trace_in(uint flag, struct rt_import_request *req, const rte *e, const char *msg);

const char *rt_import_state_name_array[TIS_MAX] = {
  [TIS_DOWN] = "DOWN",
  [TIS_UP] = "UP",
  [TIS_STOP] = "STOP",
  [TIS_FLUSHING] = "FLUSHING",
  [TIS_WAITING] = "WAITING",
  [TIS_CLEARED] = "CLEARED",
};

const char *rt_export_state_name_array[TES_MAX] = {
#define RT_EXPORT_STATES_ENUM_HELPER(p) [TES_##p] = #p,
  MACRO_FOREACH(RT_EXPORT_STATES_ENUM_HELPER, RT_EXPORT_STATES)
#undef RT_EXPORT_STATES_ENUM_HELPER
};

const char *rt_import_state_name(u8 state)
{
  if (state >= TIS_MAX)
    return "!! INVALID !!";
  else
    return rt_import_state_name_array[state];
}

const char *rt_export_state_name(enum rt_export_state state)
{
  ASSERT_DIE((state < TES_MAX) && (state >= 0));

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

#define req_trace(r, level, fmt, args...) do {	\
  if (r->trace_routes & (level))		\
    log(L_TRACE "%s: " fmt, r->name, ##args);	\
} while (0)

#define channel_trace(c, level, fmt, args...)  do {\
  if ((c->debug & (level)) || (c->proto->debug & (level)))	\
    log(L_TRACE "%s.%s: " fmt, c->proto->name, c->name, ##args);\
} while (0)

/*
 * Lockless table feeding helpers
 */
struct rtable_reading {
  rtable *t;
  struct rcu_unwinder *u;
};

#define RT_READ_ANCHORED(_o, _i, _u)  \
  struct rtable_reading _s##_i = { .t = _o, .u = _u, }, *_i = &_s##_i;

#define RT_READ(_o, _i) RCU_ANCHOR(_u##_i); RT_READ_ANCHORED(_o, _i, _u##_i);

#define RT_READ_RETRY(tr) RCU_RETRY(tr->u)

#define RT_READ_LOCKED(_o, _i) \
  ASSERT_DIE(RT_IS_LOCKED(_o));	\
  struct rtable_reading _s##_i = { .t = RT_PUB(_o), .u = RCU_WONT_RETRY, }, *_i = &_s##_i;


#define RTE_IS_OBSOLETE(s)  ((s)->rte.flags & REF_OBSOLETE)
#define RTE_OBSOLETE_CHECK(tr, _s) ({	\
    struct rte_storage *s = _s;		\
    if (s && RTE_IS_OBSOLETE(s))	\
      RT_READ_RETRY(tr);		\
    s; })

#define NET_READ_WALK_ROUTES(tr, n, ptr, r)						\
  for (struct rte_storage *r, * _Atomic *ptr = &(n)->routes;				\
      r = RTE_OBSOLETE_CHECK(tr, atomic_load_explicit(ptr, memory_order_acquire));	\
      ptr = &r->next)

#define NET_READ_BEST_ROUTE(tr, n)	RTE_OBSOLETE_CHECK(tr, atomic_load_explicit(&n->routes, memory_order_acquire))

#define NET_WALK_ROUTES(priv, n, ptr, r)					\
  for (struct rte_storage *r = ({ ASSERT_DIE(RT_IS_LOCKED(priv)); NULL; }),	\
			  * _Atomic *ptr = &(n)->routes;			\
      r = atomic_load_explicit(ptr, memory_order_acquire);			\
      ptr = &r->next)
#define NET_BEST_ROUTE(priv, n)		({ ASSERT_DIE(RT_IS_LOCKED(priv)); atomic_load_explicit(&n->routes, memory_order_acquire); })

static inline net *
net_find(struct rtable_reading *tr, const struct netindex *i)
{
  u32 rbs = atomic_load_explicit(&tr->t->routes_block_size, memory_order_acquire);
  if (i->index >= rbs)
    return NULL;

  net *routes = atomic_load_explicit(&tr->t->routes, memory_order_acquire);
  return &(routes[i->index]);
}

static inline net *
net_find_valid(struct rtable_reading *tr, netindex_hash *nh, const net_addr *addr)
{
  struct netindex *i = net_find_index(nh, addr);
  if (!i)
    return NULL;

  net *n = net_find(tr, i);
  if (!n)
    return NULL;

  struct rte_storage *s = NET_READ_BEST_ROUTE(tr, n);

  if (!s || !rte_is_valid(&s->rte))
    return NULL;

  return n;
}

static inline void *
net_route_ip6_sadr_trie(struct rtable_reading *tr, netindex_hash *nh, const net_addr_ip6_sadr *n0)
{
  u32 bs = atomic_load_explicit(&tr->t->routes_block_size, memory_order_acquire);
  const struct f_trie *trie = atomic_load_explicit(&tr->t->trie, memory_order_acquire);
  TRIE_WALK_TO_ROOT_IP6(trie, (const net_addr_ip6 *) n0, px)
  {
    net_addr_union n = {
      .ip6_sadr = NET_ADDR_IP6_SADR(px.prefix, px.pxlen, n0->src_prefix, n0->src_pxlen),
    };

    while (1)
    {
      struct netindex *i = net_find_index(nh, &n.n);
      if (i && (i->index < bs))
      {
	net *cur = &(atomic_load_explicit(&tr->t->routes, memory_order_acquire)[i->index]);
	struct rte_storage *s = NET_READ_BEST_ROUTE(tr, cur);

	if (s && rte_is_valid(&s->rte))
	  return s;
      }

      if (!n.ip6_sadr.src_pxlen)
	break;

      ip6_clrbit(&n.ip6_sadr.src_prefix, --n.ip6_sadr.src_pxlen);
    }
  }
  TRIE_WALK_TO_ROOT_END;

  return NULL;
}


static inline void *
net_route_ip6_sadr_fib(struct rtable_reading *tr, netindex_hash *nh, const net_addr_ip6_sadr *n0)
{
  u32 bs = atomic_load_explicit(&tr->t->routes_block_size, memory_order_acquire);

  net_addr_ip6_sadr n;
  net_copy_ip6_sadr(&n, n0);

  while (1)
  {
    net_addr_union nn = {
      .ip6_sadr = n,
    };

    while (1)
    {
      struct netindex *i = net_find_index(nh, &nn.n);
      if (i && (i->index < bs))
      {
	net *cur = &(atomic_load_explicit(&tr->t->routes, memory_order_acquire)[i->index]);
	struct rte_storage *s = NET_READ_BEST_ROUTE(tr, cur);

	if (s && rte_is_valid(&s->rte))
	  return s;
      }

      if (!nn.ip6_sadr.src_pxlen)
	break;

      ip6_clrbit(&nn.ip6_sadr.src_prefix, --nn.ip6_sadr.src_pxlen);
    }

    if (!n.dst_pxlen)
      break;

    n.dst_pxlen--;
    ip6_clrbit(&n.dst_prefix, n.dst_pxlen);
  }

  return NULL;
}

static net *
net_route(struct rtable_reading *tr, const net_addr *n)
{
  ASSERT(tr->t->addr_type == n->type);
  SKIP_BACK_DECLARE(net_addr_union, nu, n, n);

  const struct f_trie *trie = atomic_load_explicit(&tr->t->trie, memory_order_acquire);

  netindex_hash *nh = tr->t->netindex;

#define TW(ipv, what) \
  TRIE_WALK_TO_ROOT_IP##ipv(trie, &(nu->ip##ipv), var) \
  { what(ipv, var); } \
  TRIE_WALK_TO_ROOT_END; return NULL;

#define FW(ipv, what) do { \
  net_addr_union nuc; net_copy(&nuc.n, n); \
  while (1) { \
    what(ipv, nuc.ip##ipv); if (!nuc.n.pxlen) return NULL; \
    nuc.n.pxlen--; ip##ipv##_clrbit(&nuc.ip##ipv.prefix, nuc.ip##ipv.pxlen); \
  } \
} while(0); return NULL;

#define FVR_IP(ipv, var) \
    net *r; if (r = net_find_valid(tr, nh, (net_addr *) &var)) return r;

#define FVR_VPN(ipv, var) \
    net_addr_vpn##ipv _var0 = NET_ADDR_VPN##ipv(var.prefix, var.pxlen, nu->vpn##ipv.rd); FVR_IP(ipv, _var0);

  if (trie)
    switch (n->type) {
      case NET_IP4:   TW(4, FVR_IP);
      case NET_VPN4:  TW(4, FVR_VPN);
      case NET_IP6:   TW(6, FVR_IP);
      case NET_VPN6:  TW(6, FVR_VPN);

      case NET_IP6_SADR:
	return net_route_ip6_sadr_trie(tr, nh, (net_addr_ip6_sadr *) n);
      default:
	return NULL;
    }
  else
    switch (n->type) {
      case NET_IP4:   FW(4, FVR_IP);
      case NET_VPN4:  FW(4, FVR_VPN);
      case NET_IP6:   FW(6, FVR_IP);
      case NET_VPN6:  FW(6, FVR_VPN);

      case NET_IP6_SADR:
	return net_route_ip6_sadr_fib (tr, nh, (net_addr_ip6_sadr *) n);
      default:
	return NULL;
    }

#undef TW
#undef FW
#undef FVR_IP
#undef FVR_VPN
}

/*
 * ROA aggregation subsystem
 */

struct rt_roa_aggregator {
  struct rt_stream stream;
  struct rte_owner sources;
  struct rte_src *main_source;
  struct rt_export_request src;
  event event;
};

static void
rt_dump_roa_aggregator_dst_req(struct rt_import_request *req)
{
  debug("  ROA aggregator import request req=%p", req);
}

static void
rt_dump_roa_aggregator_src_req(struct rt_export_request *req)
{
  debug("  ROA aggregator export request req=%p", req);
}

static void
rt_roa_aggregator_state_change(struct rt_import_request *req, u8 state)
{
  if (req->trace_routes & D_STATES)
    log("%s: import state changed to %s",
	req->name, rt_import_state_name(state));
}

struct rt_roa_aggregated_adata {
  adata ad;
  u32 padding;
  struct { u32 asn, max_pxlen; } u[0];
};

#define ROA_AGGR_COUNT(rad)   (((typeof (&(rad)->u[0])) (rad->ad.data + rad->ad.length)) - &(rad)->u[0])

static void
ea_roa_aggregate_format(const eattr *a, byte *buf, uint size)
{
  SKIP_BACK_DECLARE(struct rt_roa_aggregated_adata, rad, ad, a->u.ptr);
  uint cnt = ROA_AGGR_COUNT(rad);
  for (uint upos = 0; upos < cnt; upos++)
  {
    int x = bsnprintf(buf, size, "as %u max %u, ", rad->u[upos].asn, rad->u[upos].max_pxlen);
    size -= x;
    buf += x;
    if (size < 30)
    {
      bsnprintf(buf, size, " ... ");
      return;
    }
  }

  buf[-2] = 0;
}

static struct ea_class ea_roa_aggregated = {
  .name = "roa_aggregated",
  .type = T_ROA_AGGREGATED,
  .format = ea_roa_aggregate_format,
};

/*
 * In the main ROA table, there are separate ROAs. To make it possible to fetch
 * all the relevant ROA records for a given prefix in a reasonable amount of time,
 * we aggregate all the ROAs with the same minimal prefix to one record.
 *
 * With that, there may be one loop traversing the ROA trie upwards, where the
 * total number of table access is always capped by 128, or 32 for legacy IP.
 */

static void
rt_aggregate_roa(void *_rag)
{
  struct rt_roa_aggregator *rag = _rag;

  RT_EXPORT_WALK(&rag->src, u) TMP_SAVED
  {
    /* Watch updates in the main ROA table on the best feed. These should
     * provide us with an information whether there is or isn't some record
     * with that prefix, maxlen and ASN. */
    bool withdraw = 0;
    const net_addr *nroa = NULL;
    switch (u->kind)
    {
      case RT_EXPORT_STOP:
	bug("Main table export stopped");
	break;

      case RT_EXPORT_FEED:
	bug("Somebody tried to refeed the ROA aggregator, that should be impossible");
	break;

      case RT_EXPORT_UPDATE:
	nroa = u->update->new ? u->update->new->net : u->update->old->net;
	withdraw = !u->update->new;
	ASSUME(!u->update->new || !u->update->old || (u->update->new->net == u->update->old->net));
	break;
    }

    /* We have to split the record to the prefix which is stored in @nip,
     * and ASN and max_pxlen which get stored in the aggregated list. */
    net_addr_union nip;
    net_copy(&nip.n, nroa);

    uint asn, max_pxlen;

    switch (nip.n.type)
    {
      case NET_ROA6: nip.n.type = NET_IP6;
		     nip.n.length = net_addr_length[NET_IP6];
		     asn = nip.roa6.asn;
		     max_pxlen = nip.roa6.max_pxlen;
		     break;
      case NET_ROA4: nip.n.type = NET_IP4;
		     nip.n.length = net_addr_length[NET_IP4];
		     asn = nip.roa4.asn;
		     max_pxlen = nip.roa4.max_pxlen;
		     break;
      default: bug("exported garbage from ROA table");
    }

    /* What is the current state in the aggregated table? */
    rte prev = rt_net_best(rag->stream.dst_tab, &nip.n);
    const struct rt_roa_aggregated_adata rad0 = {}, *rad = &rad0;
    uint count = 0;

    /* Fetch the aggregated list if exists */
    if (prev.attrs)
    {
      eattr *ea = ea_find(prev.attrs, &ea_roa_aggregated);
      rad = SKIP_BACK(struct rt_roa_aggregated_adata, ad, ea->u.ptr);
      count = ROA_AGGR_COUNT(rad);
    }

    /* Find where the item belongs; we expect the count to be low so we don't bother
     * with interval bisection. If this ever becomes a performance problem,
     * it's easy to update.
     *
     * After this block, if found, then p is the pointer, otherwise p is the position
     * where to insert.
     * */
    bool found = false;
    uint p = 0;
    for (p = 0; p < count; p++)
      if (rad->u[p].asn > asn)
	break;
      else if (rad->u[p].asn == asn)
	if (rad->u[p].max_pxlen > max_pxlen)
	  break;
	else if (rad->u[p].max_pxlen == max_pxlen)
	{
	  found = true;
	  break;
	}

    /* Found, no withdraw, nothing to do */
    if (found && !withdraw)
      continue;

    /* Not found, withdraw, nothing to do but weird */
    if (withdraw && !found)
    {
      log(L_WARN "%s: ROA Aggregator ignored withdraw of %N, not found", rag->src.name, nroa);
      continue;
    }

    /* Allocate the new list. We expect it to be short. */
    struct rt_roa_aggregated_adata *rad_new = tmp_alloc(sizeof *rad_new + (count + 1) * sizeof rad_new->u[0]);

    if (found && withdraw)
    {
      /* Found, withdraw */
      count--;

      memcpy(&rad_new->u[0], &rad->u[0], p * sizeof rad->u[0]);
      memcpy(&rad_new->u[p], &rad->u[p+1], (count - p) * sizeof rad->u[0]);
    }
    else
    {
      /* Not found, insert */
      ASSUME(!found && !withdraw);
      memcpy(&rad_new->u[0], &rad->u[0], p * sizeof rad->u[0]);
      memcpy(&rad_new->u[p+1], &rad->u[p], (count - p) * sizeof rad->u[0]);

      rad_new->u[p].asn = asn;
      rad_new->u[p].max_pxlen = max_pxlen;

      count++;
    }

    /* Finalize the adata */
    rad_new->ad.length = (byte *) &rad_new->u[count] - rad_new->ad.data;

    /* Import the aggregated record */
    rte r = {
      .src = rag->main_source,
    };

    ea_set_attr(&r.attrs, EA_LITERAL_DIRECT_ADATA(&ea_roa_aggregated, 0, &rad_new->ad));

    rte_import(&rag->stream.dst, &nip.n, &r, rag->main_source);

#if 0
    /* Do not split ROA aggregator, we want this to be finished asap */
    MAYBE_DEFER_TASK(rag->src.r.target, rag->src.r.event,
	"export to %s", rag->src.name);
#endif
  }
}

static void
rt_setup_roa_aggregator(rtable *t)
{
  rtable *src = t->config->master.src->table;
  struct rt_roa_aggregator *rag;
  {
    RT_LOCK(t, tab);
    char *ragname = mb_sprintf(tab->rp, "%s.roa-aggregator", src->name);
    rag = mb_alloc(tab->rp, sizeof *rag);
    *rag = (struct rt_roa_aggregator) {
      .stream = {
	.dst = {
	  .name = ragname,
	  .trace_routes = tab->debug,
	  .loop = t->loop,
	  .dump_req = rt_dump_roa_aggregator_dst_req,
	  .log_state_change = rt_roa_aggregator_state_change,
	},
	.dst_tab = t,
      },
      .src = {
	.name = ragname,
	.r = {
	  .target = birdloop_event_list(t->loop),
	  .event = &rag->event,
	},
	.pool = birdloop_pool(t->loop),
	.dump = rt_dump_roa_aggregator_src_req,
	.trace_routes = tab->debug,
      },
      .event = {
	.hook = rt_aggregate_roa,
	.data = rag,
      },
    };

    rt_init_sources(&rag->sources, ragname, birdloop_event_list(t->loop));
    rag->main_source = rt_get_source_o(&rag->sources, 0);

    tab->master = &rag->stream;
  }

  rt_request_import(t, &rag->stream.dst);
  rt_export_subscribe(src, best, &rag->src);

  /* Process the (empty) feed immediately. */
  rt_aggregate_roa(rag);
}

static void
rt_roa_aggregator_sources_gone(void *t)
{
  rt_unlock_table((rtable *) t);
}

static void
rt_stop_roa_aggregator(rtable *t)
{
  struct rt_roa_aggregator *rag;
  RT_LOCKED(t, tab)
  {
    rag = SKIP_BACK(struct rt_roa_aggregator, stream, tab->master);

    rt_lock_table(tab);
    rt_destroy_sources(&rag->sources, ev_new_init(tab->rp,
	  rt_roa_aggregator_sources_gone, tab));
    rt_unlock_source(rag->main_source);
  }

  /* Stopping both import and export.
   * All memory will be freed with table shutdown,
   * no need to do anything from import done callback */
  rt_stop_import(&rag->stream.dst, NULL);
  rt_export_unsubscribe(best, &rag->src);
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
  SKIP_BACK_DECLARE(net_addr_union, nu, n, n);
  int anything = 0;

  rtable *aux = tp->config->roa_aux_table->table;

#define TW(ipv) do {								\
  TRIE_WALK_TO_ROOT_IP##ipv(trie, &(nu->ip##ipv), var) {			\
    rte r = rt_net_best(aux, (net_addr *) &var);				\
    if (!r.attrs) continue;							\
    SKIP_BACK_DECLARE(struct rt_roa_aggregated_adata, rad,			\
	ad, ea_get_adata(r.attrs, &ea_roa_aggregated));				\
    uint count = ROA_AGGR_COUNT(rad);						\
    for (uint p = 0; p < count; p++)						\
      if ((rad->u[p].max_pxlen >= nu->ip##ipv.pxlen) &&				\
	  (rad->u[p].asn == asn))						\
	return ROA_VALID;							\
      else									\
	anything = 1;								\
  } TRIE_WALK_TO_ROOT_END;							\
} while (0)

  RT_READ(aux, tr);

  {
    const struct f_trie *trie = atomic_load_explicit(&tr->t->trie, memory_order_acquire);
    ASSERT_DIE(trie);

    if ((tp->addr_type == NET_ROA4) && (n->type == NET_IP4))
      TW(4);
    else if ((tp->addr_type == NET_ROA6) && (n->type == NET_IP6))
      TW(6);
    else
      log(L_WARN "Trying to run roa_check() of %s in %s",
	  net_label[n->type], net_label[tr->t->addr_type]);
  }

  return anything ? ROA_INVALID : ROA_UNKNOWN;
#undef TW
}

/**
 * aspa_check - check validity of AS Path in an ASPA table
 * @tab: ASPA table
 * @path: AS Path to check
 *
 * Implements draft-ietf-sidrops-aspa-verification-16.
 */
enum aspa_result aspa_check(rtable *tab, const adata *path, bool force_upstream)
{
  /* Restore tmp linpool state after this check */
  CLEANUP(lp_saved_cleanup) struct lp_state *_lps = lp_save(tmp_linpool);

  /* No support for confed paths */
  if (as_path_contains_confed(path))
    return ASPA_INVALID;

  /* No support for AS_SET */
  /* See draft-ietf-sidrops-aspa-verification section 6 */
  if (as_path_contains_set(path))
    return ASPA_INVALID;

  /* Check path length; we assume just AS_SEQUENCE segments */
  uint len = as_path_getlen(path);
  if (len == 0)
    return ASPA_INVALID;

  /* Normalize the AS Path: drop stuffings */
  u32 *asns = alloca(sizeof(u32) * len);
  uint ppos = 0;
  uint nsz = 0;
  while (as_path_walk(path, &ppos, &asns[nsz]))
    if ((nsz == 0) || (asns[nsz] != asns[nsz-1]))
      nsz++;

  /* Find the provider blocks for every AS on the path
   * and check allowed directions */
  uint max_up = 0, min_up = 0, max_down = 0, min_down = 0;

  RT_READ(tab, tr);

  for (uint ap=0; ap<nsz; ap++)
  {
    net_addr_union nau = { .aspa = NET_ADDR_ASPA(asns[ap]), };

    /* Find some ASPAs */
    struct netindex *ni = net_find_index(tr->t->netindex, &nau.n);
    net *n = ni ? net_find(tr, ni) : NULL;

    bool found = false, down = false, up = false;

    if (n) NET_READ_WALK_ROUTES(tr, n, ep, e)
    {
      if (!rte_is_valid(&e->rte))
	continue;

      eattr *ea = ea_find(e->rte.attrs, &ea_gen_aspa_providers);
      if (!ea)
	continue;

      /* Actually found some ASPA */
      found = true;

      for (uint i=0; i * sizeof(u32) < ea->u.ptr->length; i++)
      {
	if ((ap > 0) && ((u32 *) ea->u.ptr->data)[i] == asns[ap-1])
	  up = true;
	if ((ap + 1 < nsz) && ((u32 *) ea->u.ptr->data)[i] == asns[ap+1])
	  down = true;

	if (down && up)
	  /* Both peers found */
	  goto end_of_aspa;
      }
    }
end_of_aspa:;

    /* Fast path for the upstream check */
    if (force_upstream)
    {
      if (!found)
	/* Move min-upstream */
	min_up = ap;
      else if (ap && !up)
	/* Exists but doesn't allow this upstream */
	return ASPA_INVALID;
    }

    /* Fast path for no ASPA here */
    else if (!found)
    {
      /* Extend max-downstream (min-downstream is stopped by unknown) */
      max_down = ap+1;

      /* Move min-upstream (can't include unknown) */
      min_up = ap;
    }

    /* ASPA exists and downstream may be extended */
    else if (down)
    {
      /* Extending max-downstream always */
      max_down = ap+1;

      /* Extending min-downstream unless unknown seen */
      if (min_down == ap)
	min_down = ap+1;

      /* Downstream only */
      if (!up)
	min_up = max_up = ap;
    }

    /* No extension for downstream, force upstream only from now */
    else
    {
      force_upstream = 1;

      /* Not even upstream, move the ending here */
      if (!up)
	min_up = max_up = ap;
    }
  }

  /* Is the path surely valid? */
  if (min_up <= min_down)
    return ASPA_VALID;

  /* Is the path maybe valid? */
  if (max_up <= max_down)
    return ASPA_UNKNOWN;

  /* Now there is surely a valley there. */
  return ASPA_INVALID;
}

struct rte_storage *
rte_store(const rte *r, struct netindex *i, struct rtable_private *tab)
{
  struct rte_storage *s = sl_alloc(tab->rte_slab);
  struct rte *e = RTES_WRITE(s);

  *e = *r;
  e->net = i->addr;
  net_lock_index(tab->netindex, i);

  rt_lock_source(e->src);

  e->attrs = ea_lookup(e->attrs, BIT32_ALL(EALS_PREIMPORT, EALS_FILTERED), EALS_IN_TABLE);

#if 0
  debug("(store) %N ", i->addr);
  ea_dump(e->attrs);
  debug("\n");
#endif

  return s;
}

static void rte_free_deferred(struct deferred_call *dc);

struct rte_free_deferred_item {
  struct deferred_call dc;
  struct rte_storage *e;
  rtable *tab;
};

/**
 * rte_free_defer - delete a &rte (happens later)
 * @e: &struct rte_storage to be deleted
 * @tab: the table which the rte belongs to
 *
 * rte_free() deletes the given &rte from the routing table it's linked to.
 */

static void
rte_free(struct rte_storage *e, struct rtable_private *tab)
{
  struct rte_free_deferred_item rfdi = {
    .dc.hook = rte_free_deferred,
    .e = e,
    .tab = RT_PUB(tab),
  };

  if (!tab->rte_free_deferred++)
    rt_lock_table(tab);

  rt_rte_trace_in(D_ROUTES, e->rte.sender->req, &e->rte, "freeing");
  defer_call(&rfdi.dc, sizeof rfdi);
}

static void
rte_free_deferred(struct deferred_call *dc)
{
  SKIP_BACK_DECLARE(struct rte_free_deferred_item, rfdi, dc, dc);

  struct rte_storage *e = rfdi->e;
  RT_LOCK(rfdi->tab, tab);

  /* No need for synchronize_rcu, implied by the deferred_call */

  struct netindex *i = RTE_GET_NETINDEX(&e->rte);
  net_unlock_index(tab->netindex, i);

  rt_unlock_source(e->rte.src);

  ea_free(e->rte.attrs);
  sl_free(e);

  if (!--tab->rte_free_deferred)
    rt_unlock_table(tab);
}

static int				/* Actually better or at least as good as */
rte_better(const rte *new, const rte *old)
{
  int (*better)(const rte *, const rte *);

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
rte_mergable(const rte *pri, const rte *sec)
{
  int (*mergable)(const rte *, const rte *);

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
  log(L_TRACE "%s %c %s %N ptr %p (%u) src %luL %uG %uS id %u %s",
      name, dir, msg, e->net, e, NET_TO_INDEX(e->net)->index,
      e->src->private_id, e->src->global_id, e->stale_cycle, e->id,
      rta_dest_name(rte_dest(e)));
}

static inline void
channel_rte_trace_in(uint flag, struct channel *c, const rte *e, const char *msg)
{
  if ((c->debug & flag) || (c->proto->debug & flag))
    log(L_TRACE "%s > %s %N ptr %p (-) src %luL %uG %uS id %u %s",
	c->in_req.name, msg, e->net, e,
	e->src->private_id, e->src->global_id, e->stale_cycle, e->id,
	rta_dest_name(rte_dest(e)));
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
rte_feed_count(struct rtable_reading *tr, net *n)
{
  uint count = 0;
  NET_READ_WALK_ROUTES(tr, n, ep, e)
    count++;

  return count;
}

#if 0
static void
rte_feed_obtain(struct rtable_reading *tr, net *n, const rte **feed, uint count)
{
  uint i = 0;
  NET_READ_WALK_ROUTES(tr, n, ep, e)
  {
    if (i >= count)
      RT_READ_RETRY(tr);

    feed[i++] = &e->rte;
  }

  if (i != count)
    RT_READ_RETRY(tr);
}
#endif

static void
rte_feed_obtain_copy(struct rtable_reading *tr, net *n, rte *feed, uint count)
{
  uint i = 0;
  NET_READ_WALK_ROUTES(tr, n, ep, e)
  {
    if (i >= count)
      RT_READ_RETRY(tr);

    feed[i++] = e->rte;
    ea_free_later(ea_ref(e->rte.attrs));
  }

  if (i != count)
    RT_READ_RETRY(tr);
}

/**
 * export_filter - evaluate export filters
 * @c: related channel
 * @rt: route to evaluate; mutable, may be modified by the filters (!)
 * @silent: no logging, reuse old results
 *
 * Evaluate the filters on the export, including the preexport hook
 * of the exporting protocol. Returns the result of the filter, i.e.
 * true if accept, false if reject.
 */
static bool
export_filter(struct channel *c, rte *rt, int silent)
{
  struct proto *p = c->proto;
  const struct filter *filter = c->out_filter;
  struct channel_export_stats *stats = &c->export_stats;

  /* Do nothing if we have already rejected the route */
  if (silent && bmap_test(&c->export_rejected_map, rt->id))
    return false;

  /* Check protocol's preferences */
  int v = p->preexport ? p->preexport(c, rt) : 0;
  if (v < 0)
    {
      if (silent)
	return false;

      stats->updates_rejected++;
      if (v == RIC_REJECT)
	channel_rte_trace_out(D_FILTERS, c, rt, "rejected by protocol");
      return false;

    }
  if (v > 0)
    {
      if (!silent)
	channel_rte_trace_out(D_FILTERS, c, rt, "forced accept by protocol");
      return true;
    }

  /* Evaluate actual filters */
  v = filter && ((filter == FILTER_REJECT) ||
		 (f_run(filter, rt,
			(silent ? FF_SILENT : 0)) > F_ACCEPT));
  if (v)
    {
      if (silent)
	return false;

      stats->updates_filtered++;
      channel_rte_trace_out(D_FILTERS, c, rt, "filtered out");
      return false;
    }

  return true;
}

#define EXPORT_FLAG_BAD(c, e)  log(L_ERR "%s.%s: Export flag inconsistency at %s:%d, route id %u. If frequent, please tell the developers.", (c)->proto->name, (c)->name, __FILE__, __LINE__, (e)->id);
#define EXPORT_FLAG_EXPECT(c, e, kind, state)	do { \
  if (bmap_test(&(c)->export_##kind##_map, (e)->id) == (state)) break; \
  EXPORT_FLAG_BAD((c), (e)); \
  if (state) bmap_set(&(c)->export_##kind##_map, (e)->id); \
  else bmap_clear(&(c)->export_##kind##_map, (e)->id); \
} while (0)

/**
 * do_rt_notify - actually export the route to the protocol
 * @c: channel to use
 * @net: related network
 * @new: announced route
 * @old: withdrawn route
 *
 * This function does all the common things which must happen before the
 * protocol's rt_notify() hook is called, most notably channel limit checks,
 * stats update and logging.
 */
static void
do_rt_notify(struct channel *c, const net_addr *net, rte *new, const rte *old)
{
  struct proto *p = c->proto;
  struct channel_export_stats *stats = &c->export_stats;

  ASSERT_DIE(old || new);

  rt_log(c, new, old, RTWH_EXPORT_LIMITS);

  /* One more route, push to the limit */
  if (!old && new)
    if (CHANNEL_LIMIT_PUSH(c, OUT))
    {
      stats->updates_limited++;
      channel_rte_trace_out(D_FILTERS, c, new, "rejected [limit]");
      return;
    }

  /* One less route, pop from the limit */
  if (!new && old)
    CHANNEL_LIMIT_POP(c, OUT);

  /* Count statistics */
  if (new)
    stats->updates_accepted++;
  else
    stats->withdraws_accepted++;

  /* Update accepted map to keep track whether this route needs to be
   * withdrawn in future. */
  if (old)
    bmap_clear(&c->export_accepted_map, old->id);

  if (new)
    bmap_set(&c->export_accepted_map, new->id);

  /* Logging */
  if (new && old)
    channel_rte_trace_out(D_ROUTES, c, new, "replaced");
  else if (new)
    channel_rte_trace_out(D_ROUTES, c, new, "added");
  else if (old)
    channel_rte_trace_out(D_ROUTES, c, old, "removed");

  /* Call the protocol hook */
  rt_log(c, new, old, RTWH_EXPORT_NOTIFY);
  p->rt_notify(p, c, net, new, old);
  rt_log(c, new, old, RTWH_EXPORT_NOTIFIED);
}

/**
 * rt_notify_basic - common route exporter for RA_OPTIMAL and RA_ANY
 * @c: channel to use
 * @new: announced route
 * @old: withdrawn route
 *
 * This function expects to get refined pairs of announced and withdrawn route
 * which have already been selected so that the old route has been seen before.
 */
static void
rt_notify_basic(struct channel *c, const rte *new, const rte *old, const rte *trte)
{
  /* Ignore idempotent withdraws */
  if (!new && !old)
  {
    channel_rte_trace_out(D_ROUTES, c, trte, "idempotent withdraw");
    c->export_stats.withdraws_ignored++;
    return;
  }

  rt_log(c, new, old, RTWH_EXPORT_BAS_IN);

  /* Refeed consideration: old may be NULL if refeeding after filter change. */
  if (!old && new)
  {
    int nacc = bmap_test(&c->export_accepted_map, new->id);
    int nrej = bmap_test(&c->export_rejected_map, new->id);

    /* Has indeed been seen, thus old = new. */
    if (nacc || nrej)
    {
      old = new;
      if (nacc && nrej)
	EXPORT_FLAG_BAD(c, new);
    }

    rt_log(c, new, old, RTWH_EXPORT_BAS_REF + !!nacc + 2*!!nrej);
  }

  /* Have we exported the old route? */
  if (old)
  {
    /* If the old route exists, it is either in rejected or in accepted map. */
    if (bmap_test(&c->export_rejected_map, old->id))
    {
      /* Consistency check, complain and clean up. */
      EXPORT_FLAG_EXPECT(c, old, accepted, 0);

      /* Drop the old rejected bit from the map, the old route id
       * gets released after exports. */
      bmap_clear(&c->export_rejected_map, old->id);

      /* Treat old rejected as never seen. */
      old = NULL;
    }

    /* Accepted bit is dropped in do_rt_notify() */
  }

  /* Run the filters for the new route */
  rte n0, *np = NULL;
  if (new)
  {
    /* Consistency check of the new route, if really new */
    if (new != old)
    {
      EXPORT_FLAG_EXPECT(c, new, accepted, 0);
      EXPORT_FLAG_EXPECT(c, new, rejected, 0);
    }

    n0 = *new;
    if (export_filter(c, &n0, 0))
      np = &n0;
    else
      bmap_set(&c->export_rejected_map, new->id);
  }

  /* Withdraw to withdraw. */
  if (!np && !old)
  {
    channel_rte_trace_out(D_ROUTES, c, trte, "idempotent withdraw (filtered on export)");
    /* No stats update, done in export_filter() */
    return;
  }

  /* OK, notify. */
  do_rt_notify(c, trte->net, np, old);
}

/**
 * channel_notify_optimal - process the export queue for RA_OPTIMAL
 * @_channel: channel to use
 *
 * Actually an event hook. Walks the export journal and distills pairs of
 * announced and withdrawn routes for rt_notify_basic(). Scheduled when the
 * journal gets some new items.
 */
void
channel_notify_optimal(void *_channel)
{
  struct channel *c = _channel;

  RT_EXPORT_WALK(&c->out_req, u)
  {
    switch (u->kind)
    {
      case RT_EXPORT_STOP:
	bug("Main table export stopped");

      case RT_EXPORT_FEED:
	{
	  /* There is either zero or one new route, and if one, it's first */
	  uint oldpos = (u->feed->block[0].flags & REF_OBSOLETE) ? 0 : 1;
	  rte *new = oldpos ? &u->feed->block[0] : NULL;

	  /* The feed _only_ puts here the unprocessed exports, and the first one
	   * is the first one unprocessed which contains a route possibly exported
	   * before. All the others should never be seen. */
	  rte *old = (oldpos < u->feed->count_routes) ? &u->feed->block[oldpos] : NULL;

	  /* Check whether it was actually seen because the best route may also be flapping
	   * up-down. Therefore the first unseen export may actually have no old route
	   * and we would falsely accuse the next one to be seen. */
	  bool oacc = old && bmap_test(&c->export_accepted_map, old->id);
	  bool orej = old && bmap_test(&c->export_rejected_map, old->id);

	  /* Not seen */
	  if (!oacc && !orej)
	    old = NULL;

	  /* Consistency check of the following exports */
	  for (uint o = oldpos + 1; o < u->feed->count_routes; o++)
	  {
	    rte *oo = &u->feed->block[o];
	    if (old && (oo->id == old->id))
	      continue;

	    /* This is a route not yet seen, no accepted/rejected flags should be there. */
	    EXPORT_FLAG_EXPECT(c, oo, accepted, 0);
	    EXPORT_FLAG_EXPECT(c, oo, rejected, 0);
	  }

	  ASSERT_DIE(!new || rte_is_valid(new));
	  ASSERT_DIE(!old || rte_is_valid(old));

	  /* And announce */
	  rt_notify_basic(c, new, old, &u->feed->block[0]);
	}
	break;

      case RT_EXPORT_UPDATE:
	{
	  /* Basic: the first update */
	  const rte *new = u->update->new;
	  const rte *old = u->update->old;
	  const rte *trte = new ?: old;

	  rt_log(c, new, old, RTWH_EXPORT_ANY_UIN);

	  /* Update the stats */
	  if (new)
	    c->out_req.stats.updates_received++;
	  else
	    c->out_req.stats.withdraws_received++;

	  /* Squashing subsequent updates */
	  for (SKIP_BACK_DECLARE(const struct rt_pending_export, rpe, it, u->update);
	      rpe = atomic_load_explicit(&rpe->next, memory_order_acquire) ;)
	    /* For RA_OPTIMAL, all updates would be used */
	  {

	    /* Fix the stats: the old item is squashed (ignored) */
	    if (new)
	      c->export_stats.updates_ignored++;
	    else
	      c->export_stats.withdraws_ignored++;

	    /* Squash the item */
	    new = rpe->it.new;
	    rt_export_processed(&c->out_req, rpe->it.seq);

	    /* Fix the stats: the new update is received */
	    if (new)
	      c->out_req.stats.updates_received++;
	    else
	      c->out_req.stats.withdraws_received++;

	    rt_log(c, new, old, RTWH_EXPORT_ANY_USQUASH);
	  }

	  /* No invalid routes allowed in the best export */
	  ASSERT_DIE(!new || rte_is_valid(new));
	  ASSERT_DIE(!old || rte_is_valid(old));

	  /* And announce */
	  rt_notify_basic(c, new, old, trte);

	}
	break;
    }

    MAYBE_DEFER_TASK(c->out_req.r.target, c->out_req.r.event,
	"export to %s.%s (regular)", c->proto->name, c->name);
  }
}


void
channel_notify_any(void *_channel)
{
  struct channel *c = _channel;

  RT_EXPORT_WALK(&c->out_req, u)
  {
    switch (u->kind)
    {
      case RT_EXPORT_STOP:
	bug("Main table export stopped");

      case RT_EXPORT_FEED:
	{
	  /* Find where the old route block begins */
	  uint oldpos = 0;
	  while ((oldpos < u->feed->count_routes) && !(u->feed->block[oldpos].flags & REF_OBSOLETE))
	    oldpos++;

	  /* Send updates one after another */
	  for (uint i = 0; i < oldpos; i++)
	  {
	    rte *new = &u->feed->block[i];
	    rte *old = NULL;

	    /* Find the old route for this src (if exists) */
	    for (uint o = oldpos; o < u->feed->count_routes; o++)
	    {
	      rte *oo = &u->feed->block[o];
	      if (new->src != oo->src)
		continue;

	      if (old)
	      {
		EXPORT_FLAG_EXPECT(c, oo, accepted, 0);
		EXPORT_FLAG_EXPECT(c, oo, rejected, 0);
		oo->src = NULL;
	      }
	      else
		old = oo;
	    }

	    rt_log(c, new, old, RTWH_EXPORT_ANY_FRAW);

	    /* Invalid routes become withdraws */
	    if (!rte_is_valid(new))
	      new = NULL;

	    if (!rte_is_valid(old))
	      old = NULL;

	    /* And notify. */
	    rt_notify_basic(c, new, old, &u->feed->block[i]);

	    /* Mark old processed */
	    if (old)
	      old->src = NULL;

	    rt_log(c, new, old, RTWH_EXPORT_ANY_FPROC);
	  }

	  /* Send withdraws if we saw updates before */
	  for (uint o = oldpos; o < u->feed->count_routes; o++)
	  {
	    rte *oo = &u->feed->block[o];
	    if (oo->src && rte_is_valid(oo))
	    {
	      bool oacc = bmap_test(&c->export_accepted_map, oo->id);
	      bool orej = bmap_test(&c->export_rejected_map, oo->id);

	      rt_log(c, NULL, oo, RTWH_EXPORT_ANY_FRAW);

	      if (oacc || orej)
		rt_notify_basic(c, NULL, oo, oo);
	    }
	  }

	}
	break;

      case RT_EXPORT_UPDATE:
	{
	  const rte *new = u->update->new;
	  const rte *old = u->update->old;
	  const rte *trte = new ?: old;
	  struct rte_src *src = trte->src;

	  /* Update the stats */
	  if (new)
	    c->out_req.stats.updates_received++;
	  else
	    c->out_req.stats.withdraws_received++;

	  /* Squashing subsequent updates */
	  for (SKIP_BACK_DECLARE(const struct rt_pending_export, rpe, it, u->update);
	      rpe = atomic_load_explicit(&rpe->next, memory_order_acquire) ;)
	  {
	    /* Either new is the same as this update's "old". Then the squash
	     * is obvious.
	     *
	     * Or we're squashing an update-from-nothing upon a withdrawal,
	     * and then src must match.
	     */
	    if (rpe->it.old != new)
	      continue;

	    if (!new && (rpe->it.new->src != src))
	      continue;

	    /* Fix the stats: the old item is squashed (ignored) */
	    if (new)
	      c->export_stats.updates_ignored++;
	    else
	      c->export_stats.withdraws_ignored++;

	    /* Squash the item */
	    new = rpe->it.new;
	    rt_export_processed(&c->out_req, rpe->it.seq);

	    /* Fix the stats: the new update is received */
	    if (new)
	      c->out_req.stats.updates_received++;
	    else
	      c->out_req.stats.withdraws_received++;
	  }

	  /* Invalid routes become withdraws */
	  if (!rte_is_valid(new))
	    new = NULL;

	  if (!rte_is_valid(old))
	    old = NULL;

	  /* And announce */
	  rt_notify_basic(c, new, old, trte);

	}
	break;
    }

    MAYBE_DEFER_TASK(c->out_req.r.target, c->out_req.r.event,
	"export to %s.%s (regular)", c->proto->name, c->name);
  }
}

#if 0
#define RT_NOTIFY_DEBUG(fmt...)	log(L_TRACE "rt_notify_accepted: " fmt, ##fmt)
#else
#define RT_NOTIFY_DEBUG(...)
#endif

static void
rt_notify_accepted(struct channel *c, const struct rt_export_feed *feed)
{
  rte *old_best = NULL, *new_best = NULL;
  bool feeding = rt_net_is_feeding(&c->out_req, feed->ni->addr);
  bool idempotent = 0;

  RT_NOTIFY_DEBUG("%s feed for %N with %u routes", feeding ? "refeed" : "regular", feed->ni->addr, feed->count_routes);

  for (uint i = 0; i < feed->count_routes; i++)
  {
    rte *r = &feed->block[i];

    /* Previously exported */
    if (!old_best && bmap_test(&c->export_accepted_map, r->id))
    {
      RT_NOTIFY_DEBUG("route %u id %u previously exported, is old best", i, r->id);
      old_best = r;

      /* Is being withdrawn */
      if (r->flags & REF_OBSOLETE)
	RT_NOTIFY_DEBUG("route %u id %u is also obsolete", i, r->id);

      /* Is still the best and need not be refed anyway */
      else if (!new_best && !feeding)
      {
	RT_NOTIFY_DEBUG("route %u id %u is also new best (idempotent)", i, r->id);
	new_best = r;
	idempotent = 1;
      }
    }

    /* Unflag obsolete routes */
    else if (r->flags & REF_OBSOLETE)
    {
      RT_NOTIFY_DEBUG("route %u id %u is obsolete", i, r->id);
      bmap_clear(&c->export_rejected_map, r->id);
    }

    /* Mark invalid as rejected */
    else if (!rte_is_valid(r))
    {
      RT_NOTIFY_DEBUG("route %u id %u is invalid", i, r->id);
      bmap_set(&c->export_rejected_map, r->id);
    }

    /* Already rejected */
    else if (!feeding && bmap_test(&c->export_rejected_map, r->id))
      RT_NOTIFY_DEBUG("route %u id %u has been rejected before", i, r->id);

    /* No new best route yet and this is a valid candidate */
    else if (!new_best)
    {
      /* This branch should not be executed if this route is old best */
      ASSERT_DIE(feeding || (r != old_best));

      /* Have no new best route yet, try this route not seen before */
      if (export_filter(c, r, 0))
        new_best = r;
      else
	bmap_set(&c->export_rejected_map, r->id);

      RT_NOTIFY_DEBUG("route %u id %u is a new_best candidate %s", i, r->id,
	  new_best ? "and is accepted" : "but got rejected");
    }

    /* Just a debug message for the last case */
    else
    {
      RT_NOTIFY_DEBUG("route %u id %u is suboptimal, not checking", i, r->id);
    }
  }

  /* Nothing to export */
  if (!idempotent && (new_best || old_best))
    do_rt_notify(c, feed->ni->addr, new_best, old_best);
  else
  {
    RT_NOTIFY_DEBUG("nothing to export for %N", feed->ni->addr);
  }
}

void
channel_notify_accepted(void *_channel)
{
  struct channel *c = _channel;

  RT_EXPORT_WALK(&c->out_req, u)
  {
    switch (u->kind)
    {
      case RT_EXPORT_STOP:
	bug("Main table export stopped");

      case RT_EXPORT_FEED:
	if (u->feed->count_routes)
	  rt_notify_accepted(c, u->feed);
	break;

      case RT_EXPORT_UPDATE:
	{
	  struct rt_export_feed *f = rt_net_feed(c->table, u->update->new ? u->update->new->net : u->update->old->net, SKIP_BACK(struct rt_pending_export, it, u->update));
	  rt_notify_accepted(c, f);
	  for (uint i=0; i<f->count_exports; i++)
	    rt_export_processed(&c->out_req, f->exports[i]);
	  break;
	}
    }

    MAYBE_DEFER_TASK(c->out_req.r.target, c->out_req.r.event,
	"export to %s.%s (secondary)", c->proto->name, c->name);
  }
}

rte *
rt_export_merged(struct channel *c, const struct rt_export_feed *feed, linpool *pool, int silent)
{
  bool feeding = !silent && rt_net_is_feeding(&c->out_req, feed->ni->addr);

  // struct proto *p = c->proto;
  struct nexthop_adata *nhs = NULL;
  rte *best = &feed->block[0];

  /* First route is obsolete */
  if (best->flags & REF_OBSOLETE)
    return NULL;

  /* First route is invalid */
  if (!rte_is_valid(best))
    return NULL;

  /* Already rejected, no need to re-run the filter */
  if (!feeding && bmap_test(&c->export_rejected_map, best->id))
    return NULL;

  /* Best route doesn't pass the filter */
  if (!export_filter(c, best, silent))
  {
    if (!silent)
      bmap_set(&c->export_rejected_map, best->id);
    return NULL;
  }

  /* Unreachable routes can't be merged */
  if (!rte_is_reachable(best))
    return best;

  for (uint i = 1; i < feed->count_routes; i++)
  {
    rte *r = &feed->block[i];

    /* Obsolete routes can't be merged */
    if (r->flags & REF_OBSOLETE)
      break;

    /* Failed to pass mergable test */
    if (!rte_mergable(best, r))
      continue;

    /* Already rejected by filters */
    if (!feeding && bmap_test(&c->export_rejected_map, r->id))
      continue;

    /* New route rejected */
    if (!export_filter(c, r, silent))
    {
      if (!silent)
	bmap_set(&c->export_rejected_map, r->id);
      continue;
    }

    /* New route unreachable */
    if (!rte_is_reachable(r))
      continue;

    /* Merging next hops */
    eattr *nhea = ea_find(r->attrs, &ea_gen_nexthop);
    ASSERT_DIE(nhea);

    if (nhs)
      nhs = nexthop_merge(nhs, (struct nexthop_adata *) nhea->u.ptr, c->merge_limit, pool);
    else
      nhs = (struct nexthop_adata *) nhea->u.ptr;
  }

  /* There is some nexthop, we shall set the merged version to the route */
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

static void
rt_notify_merged(struct channel *c, const struct rt_export_feed *f)
{
  const rte *old_best = NULL;
  /* Find old best route */
  for (uint i = 0; i < f->count_routes; i++)
    if (bmap_test(&c->export_accepted_map, f->block[i].id))
    {
      old_best = &f->block[i];
      break;
    }

  /* Prepare new merged route */
  rte *new_merged = f->count_routes ? rt_export_merged(c, f, tmp_linpool, 0) : NULL;

  /* And notify the protocol */
  if (new_merged || old_best)
    do_rt_notify(c, f->ni->addr, new_merged, old_best);
}


void
channel_notify_merged(void *_channel)
{
  struct channel *c = _channel;

  RT_EXPORT_WALK(&c->out_req, u)
  {
    switch (u->kind)
    {
      case RT_EXPORT_STOP:
	bug("Main table export stopped");

      case RT_EXPORT_FEED:
	if (u->feed->count_routes)
	  rt_notify_merged(c, u->feed);
	break;

      case RT_EXPORT_UPDATE:
	{
	  struct rt_export_feed *f = rt_net_feed(c->table, u->update->new ? u->update->new->net : u->update->old->net, SKIP_BACK(struct rt_pending_export, it, u->update));
	  rt_notify_merged(c, f);
	  for (uint i=0; i<f->count_exports; i++)
	    rt_export_processed(&c->out_req, f->exports[i]);
	  break;
	}
    }

    MAYBE_DEFER_TASK(c->out_req.r.target, c->out_req.r.event,
	"export to %s.%s (merged)", c->proto->name, c->name);
  }
}

static void
rt_flush_best(struct rtable_private *tab, u64 upto)
{
  u64 last_seq = 0;
  RT_EXPORT_WALK(&tab->best_req, u)
  {
    ASSERT_DIE(u->kind == RT_EXPORT_UPDATE);
    ASSERT_DIE(u->update->seq <= upto);
    last_seq = u->update->seq;
    if (last_seq == upto)
      return;
  }

  rt_trace(tab, D_STATES, "Export best full flushed regular up to %lu", last_seq);
}

static struct rt_pending_export *
rte_announce_to(struct rt_exporter *e, struct rt_net_pending_export *npe, const rte *new, const rte *old)
{
  if (new == old)
    return NULL;

  struct rt_pending_export rpe = {
    .it = {
      .new = new,
      .old = old,
    },
  };

  struct rt_export_item *rei = rt_exporter_push(e, &rpe.it);
  if (!rei)
    return NULL;

  SKIP_BACK_DECLARE(struct rt_pending_export, pushed, it, rei);

  struct rt_pending_export *last = atomic_load_explicit(&npe->last, memory_order_relaxed);
  if (last)
    ASSERT_DIE(atomic_exchange_explicit(&last->next, pushed, memory_order_acq_rel) == NULL);

  atomic_store_explicit(&npe->last, pushed, memory_order_release);
  if (!atomic_load_explicit(&npe->first, memory_order_relaxed))
    atomic_store_explicit(&npe->first, pushed, memory_order_release);

  return pushed;
}

static void
rte_announce(struct rtable_private *tab, const struct netindex *i UNUSED, net *net, const rte *new, const rte *old,
	     const rte *new_best, const rte *old_best)
{
  /* Update network count */
  tab->net_count += (!!new_best - !!old_best);

  int new_best_valid = rte_is_valid(new_best);
  int old_best_valid = rte_is_valid(old_best);

  if ((new == old) && (new_best == old_best))
    return;

  if (new_best_valid)
    new_best->sender->stats.pref++;
  if (old_best_valid)
    old_best->sender->stats.pref--;

  /* Try to push */
  struct rt_pending_export *best_rpe = NULL;
  struct rt_pending_export *all_rpe = rte_announce_to(&tab->export_all, &net->all, new, old);
  if (all_rpe)
  {
    /* Also best may have changed */
    best_rpe = rte_announce_to(&tab->export_best, &net->best,
	new_best_valid ? new_best : NULL, old_best_valid ? old_best : NULL);
    if (best_rpe)
      /* Announced best, need an anchor to all */
      best_rpe->seq_all = all_rpe->it.seq;
    else if (!lfjour_pending_items(&tab->export_best.journal))
      /* Best is idle, flush its recipient immediately */
      rt_flush_best(tab, all_rpe->it.seq);

    rt_check_cork_high(tab);
  }
  else
  {
    /* Not announced anything, cleanup now */
    ASSERT_DIE(new_best == old_best);
    hmap_clear(&tab->id_map, old->id);
    rte_free(SKIP_BACK(struct rte_storage, rte, old), tab);
  }
}

static net *
rt_cleanup_find_net(struct rtable_private *tab, struct rt_pending_export *rpe)
{
  /* Find the appropriate struct network */
  ASSERT_DIE(rpe->it.new || rpe->it.old);
  const net_addr *n = rpe->it.new ?
    rpe->it.new->net :
    rpe->it.old->net;
  struct netindex *ni = NET_TO_INDEX(n);
  ASSERT_DIE(ni->index < atomic_load_explicit(&tab->routes_block_size, memory_order_relaxed));
  net *routes = atomic_load_explicit(&tab->routes, memory_order_relaxed);
  return &routes[ni->index];
}

static bool
rt_cleanup_update_pointers(struct rt_net_pending_export *npe, struct rt_pending_export *rpe)
{
  struct rt_pending_export *first = atomic_load_explicit(&npe->first, memory_order_relaxed);
  struct rt_pending_export *last = atomic_load_explicit(&npe->last, memory_order_relaxed);
  ASSERT_DIE(rpe == first);

  atomic_store_explicit(
      &npe->first,
      atomic_load_explicit(&rpe->next, memory_order_relaxed),
      memory_order_release
      );

  if (rpe != last)
    return 0;

  atomic_store_explicit(&npe->last, NULL, memory_order_release);
  return 1;
}

static void
rt_cleanup_export_best(struct lfjour *j, struct lfjour_item *i)
{
  SKIP_BACK_DECLARE(struct rt_pending_export, rpe, it.li, i);
  SKIP_BACK_DECLARE(struct rtable_private, tab, export_best.journal, j);
  rt_flush_best(tab, rpe->seq_all);

  /* Find the appropriate struct network */
  net *net = rt_cleanup_find_net(tab, rpe);

  /* Update the first and last pointers */
  rt_cleanup_update_pointers(&net->best, rpe);
}

static void
rt_cleanup_export_all(struct lfjour *j, struct lfjour_item *i)
{
  SKIP_BACK_DECLARE(struct rt_pending_export, rpe, it.li, i);
  SKIP_BACK_DECLARE(struct rtable_private, tab, export_all.journal, j);

  /* Find the appropriate struct network */
  net *net = rt_cleanup_find_net(tab, rpe);

  /* Update the first and last pointers */
  bool is_last = rt_cleanup_update_pointers(&net->all, rpe);

  /* Free the old route */
  if (rpe->it.old)
  {
    ASSERT_DIE(rpe->it.old->flags & REF_OBSOLETE);
    hmap_clear(&tab->id_map, rpe->it.old->id);
    rte_free(SKIP_BACK(struct rte_storage, rte, rpe->it.old), tab);
  }

  if (is_last)
    tab->gc_counter++;
}

static void
rt_dump_best_req(struct rt_export_request *req)
{
  SKIP_BACK_DECLARE(struct rtable_private, tab, best_req, req);
  debug("  Table %s best cleanup request (%p)\n", tab->name, req);
}

static void
rt_import_cleared(void *_ih)
{
  struct rt_import_hook *hook = _ih;

  ASSERT_DIE(hook->import_state == TIS_CLEARED);

  /* Local copy of the otherwise freed callback data */
  void (*stopped)(struct rt_import_request *) = hook->stopped;
  struct rt_import_request *req = hook->req;

  /* Finally uncouple from the table */
  RT_LOCKED(hook->table, tab)
  {
    req->hook = NULL;

    rt_trace(tab, D_EVENTS, "Hook %s stopped", req->name);
    rem_node(&hook->n);
    mb_free(hook);
    rt_unlock_table(tab);
  }

  /* And call the callback */
  CALL(stopped, req);
}

static void
rt_cleanup_done_all(struct rt_exporter *e, u64 end_seq)
{
  SKIP_BACK_DECLARE(struct rtable_private, tab, export_all, e);
  ASSERT_DIE(DG_IS_LOCKED(tab->lock.rtable));

  if (~end_seq)
    rt_trace(tab, D_STATES, "Export all cleanup done up to seq %lu", end_seq);
  else
    rt_trace(tab, D_STATES, "Export all cleanup complete");

  rt_check_cork_low(tab);

  struct rt_import_hook *ih; node *x, *n;
  uint cleared_counter = 0;
  if (tab->wait_counter)
    WALK_LIST2_DELSAFE(ih, n, x, tab->imports, n)
      if (ih->import_state == TIS_WAITING)
      {
	if (end_seq >= ih->flush_seq)
	{
	  ih->import_state = TIS_CLEARED;
	  tab->wait_counter--;
	  cleared_counter++;

	  ih->cleanup_event = (event) {
	    .hook = rt_import_cleared,
	    .data = ih,
	  };
	  ev_send_loop(ih->req->loop, &ih->cleanup_event);
	}
      }

  if (!EMPTY_LIST(tab->imports) &&
      (tab->gc_counter >= tab->config->gc_threshold))
    rt_kick_prune_timer(tab);
}

static void
rt_cleanup_done_best(struct rt_exporter *e, u64 end_seq)
{
  SKIP_BACK_DECLARE(struct rtable_private, tab, export_best, e);

  if (~end_seq)
    rt_trace(tab, D_STATES, "Export best cleanup done up to seq %lu", end_seq);
  else
  {
    rt_trace(tab, D_STATES, "Export best cleanup complete, flushing regular");
    rt_flush_best(tab, ~0ULL);
  }
}

#define RT_EXPORT_BULK	1024

static inline int
rte_validate(struct channel *ch, rte *e)
{
  int c;
  const net_addr *n = e->net;

#define IGNORING(pre, post) do { \
    log(L_WARN "%s.%s: Ignoring " pre " %N " post, ch->proto->name, ch->name, n); \
    return 0; \
  } while (0)

  if (!net_validate(n))
    IGNORING("bogus prefix", "");

  /* FIXME: better handling different nettypes */
  c = !net_is_flow(n) ?
    net_classify(n): (IADDR_HOST | SCOPE_UNIVERSE);
  if ((c < 0) || !(c & IADDR_HOST) || ((c & IADDR_SCOPE_MASK) <= SCOPE_LINK))
    IGNORING("bogus route", "");

  if (net_type_match(n, NB_DEST))
  {
    eattr *nhea = ea_find(e->attrs, &ea_gen_nexthop);
    int dest = nhea_dest(nhea);

    if (dest == RTD_NONE)
      IGNORING("route", "with no destination");

    if ((dest == RTD_UNICAST) &&
	!nexthop_is_sorted((struct nexthop_adata *) nhea->u.ptr))
      IGNORING("unsorted multipath route", "");
  }
  else if (ea_find(e->attrs, &ea_gen_nexthop))
    IGNORING("route", "having a superfluous nexthop attribute");

  return 1;
}

int
rte_same(const rte *x, const rte *y)
{
  /* rte.flags / rte.pflags are not checked, as they are internal to rtable */
  return
    (x == y) || (
     (x->attrs == y->attrs) ||
     ((!x->attrs->stored || !y->attrs->stored) && ea_same(x->attrs, y->attrs))
    ) &&
    x->src == y->src &&
    rte_is_filtered(x) == rte_is_filtered(y);
}

static inline int rte_is_ok(const rte *e) { return e && !rte_is_filtered(e); }

static void
rte_recalculate(struct rtable_private *table, struct rt_import_hook *c, struct netindex *i, net *net, rte *new, struct rte_src *src)
{
  struct rt_import_request *req = c->req;
  struct rt_import_stats *stats = &c->stats;
  struct rte_storage *old_best_stored = NET_BEST_ROUTE(table, net);
  const rte *old_best = old_best_stored ? &old_best_stored->rte : NULL;

  /* If the new route is identical to the old one, we find the attributes in
   * cache and clone these with no performance drop. OTOH, if we were to lookup
   * the attributes, such a route definitely hasn't been anywhere yet,
   * therefore it's definitely worth the time. */
  struct rte_storage *new_stored = NULL;
  if (new)
  {
    new_stored = rte_store(new, i, table);
    new = RTES_WRITE(new_stored);
  }

  struct rte_storage * _Atomic *last_ptr = NULL;
  struct rte_storage *old_stored = NULL;
  const rte *old = NULL;

  /* Find the original route from the same protocol */
  NET_WALK_ROUTES(table, net, ep, e)
  {
    last_ptr = &e->next;
    if (e->rte.src == src)
      if (old_stored)
	bug("multiple routes in table with the same src");
      else
	old_stored = e;
  }

  if (old_stored)
    {
      old = &old_stored->rte;

      /* If there is the same route in the routing table but from
       * a different sender, then there are two paths from the
       * source protocol to this routing table through transparent
       * pipes, which is not allowed.
       * We log that and ignore the route. */
      if (old->sender != c)
	{
	  if (!old->generation && !new->generation)
	    bug("Two protocols claim to author a route with the same rte_src in table %s: %N %s/%u:%u",
		c->table->name, i->addr, old->src->owner->name, old->src->private_id, old->src->global_id);

	  log_rl(&table->rl_pipe, L_ERR "Route source collision in table %s: %N %s/%u:%u",
		c->table->name, i->addr, old->src->owner->name, old->src->private_id, old->src->global_id);

	  /* Ignore the whole update */
	  if (new)
	  {
	    rt_rte_trace_in(D_ROUTES, req, new, "collided");
	    rte_free(new_stored, table);
	    return;
	  }
	}

	  if (new && rte_same(old, &new_stored->rte))
	    {
	      /* No changes, ignore the new route and refresh the old one */
	      old_stored->stale_cycle = new->stale_cycle;

	      if (!rte_is_filtered(new))
		{
		  stats->updates_ignored++;
		  rt_rte_trace_in(D_ROUTES, req, new, "ignored");
		}

	      /* We need to free the already stored route here before returning */
	      rte_free(new_stored, table);
	      return;
	  }
    }

  if (!old && !new)
    {
      stats->withdraws_ignored++;
      return;
    }

  /* If rejected by import limit, we need to pretend there is no route */
  if (req->preimport && (req->preimport(req, new, old) == 0))
  {
    rte_free(new_stored, table);
    new_stored = NULL;
    new = NULL;
  }

  if (!new && !old)
  {
    stats->withdraws_ignored++;
    return;
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

  /* Finalize the new stored route */
  if (new_stored)
    {
      new->lastmod = current_time();
      new->id = hmap_first_zero(&table->id_map);
      hmap_set(&table->id_map, new->id);
    }

  rt_log(c->req, new, old, RTWH_IMPORT);

  /* We need to add a spinlock sentinel to the beginning */
  _Thread_local static struct rte_storage local_sentinel = { .flags = REF_OBSOLETE, };
  atomic_store_explicit(&local_sentinel.next, old_best_stored, memory_order_release);
  atomic_store_explicit(&net->routes, &local_sentinel, memory_order_release);

  /* Mark also the old route as obsolete. */
  if (old_stored)
    old_stored->flags |= REF_OBSOLETE;

  if (table->config->sorted)
    {
      /* If routes are sorted, just insert new route to appropriate position */
      if (new_stored)
	{
	  struct rte_storage * _Atomic *k = &local_sentinel.next, *kk;
	  for (; kk = atomic_load_explicit(k, memory_order_relaxed); k = &kk->next)
	    if ((kk != old_stored) && rte_better(new, &kk->rte))
	      break;

	  /* Do not flip the operation order, the list must stay consistent */
	  atomic_store_explicit(&new_stored->next, kk, memory_order_release);
	  atomic_store_explicit(k, new_stored, memory_order_release);

	  table->rt_count++;
	}
    }
  else
    {
      /* If routes are not sorted, find the best route and move it on
	 the first position. There are several optimized cases. */

      if (src->owner->rte_recalculate &&
	  src->owner->rte_recalculate(table, net, new_stored, old_stored, old_best_stored))
	goto do_recalculate;

      if (new_stored && rte_better(&new_stored->rte, old_best))
	{
	  /* The first case - the new route is clearly optimal,
	     we link it at the first position */

	  /* First link to the chain */
	  atomic_store_explicit(&new_stored->next,
	      atomic_load_explicit(&local_sentinel.next, memory_order_acquire),
	      memory_order_release);

	  /* And then link to the added route */
	  atomic_store_explicit(&local_sentinel.next, new_stored, memory_order_release);

	  table->rt_count++;
	}
      else if (old == old_best)
	{
	  /* The second case - the old best route will disappear, we add the
	     new route (if we have any) to the list (we don't care about
	     position) and then we elect the new optimal route and relink
	     that route at the first position and announce it. New optimal
	     route might be NULL if there is no more routes */

	do_recalculate:
	  /* Add the new route to the list right behind the old one */
	  if (new_stored)
	  {
	    /* There is the same piece of code several lines farther. Needs refactoring.
	     * The old_stored check is needed because of the possible jump from deterministic med */
	    if (old_stored)
	    {
	      atomic_store_explicit(&new_stored->next, atomic_load_explicit(&old_stored->next, memory_order_relaxed), memory_order_release);
	      atomic_store_explicit(&old_stored->next, new_stored, memory_order_release);
	    }
	    else
	    {
	      atomic_store_explicit(&new_stored->next, NULL, memory_order_release);
	      atomic_store_explicit(last_ptr, new_stored, memory_order_release);
	    }

	    table->rt_count++;
	  }

	  /* Find a new optimal route (if there is any) */
	  struct rte_storage * _Atomic *bp = &local_sentinel.next;
	  struct rte_storage *best = atomic_load_explicit(bp, memory_order_relaxed);

	  /* Best can't be the old one */
	  if (best == old_stored)
	  {
	    bp = &best->next;
	    best = atomic_load_explicit(bp, memory_order_relaxed);
	  }

	  if (best)
	  {
	    for (struct rte_storage *kk, * _Atomic *k = &best->next;
		kk = atomic_load_explicit(k, memory_order_relaxed);
		k = &kk->next)
	      if (rte_better(&kk->rte, &best->rte))
		best = atomic_load_explicit(bp = k, memory_order_relaxed);

	    /* Now we know which route is the best one, we have to relink it
	     * to the front place. */

	    /* First we wait until all readers finish */
	    synchronize_rcu();
	    /* Now all readers must have seen the local spinlock sentinel
	     * and will wait until we re-arrange the structure */

	    /* The best route gets removed from its original place */
	    atomic_store_explicit(bp,
		atomic_load_explicit(&best->next, memory_order_relaxed),
		memory_order_release);

	    /* After the best route, the original chain shall be linked */
	    atomic_store_explicit(&best->next,
		atomic_load_explicit(&local_sentinel.next, memory_order_relaxed),
		memory_order_release);

	    /* And now we finally link the best route first */
	    atomic_store_explicit(&local_sentinel.next, best, memory_order_release);
	  }
	}
      else if (new_stored)
	{
	  /* The third case - the new route is not better than the old
	     best route (therefore old_best != NULL) and the old best
	     route was not removed (therefore old_best == net->routes).
	     We just link the new route to the old/last position. */

	  if (old_stored)
	  {
	    atomic_store_explicit(&new_stored->next,
		atomic_load_explicit(&old_stored->next, memory_order_relaxed),
		memory_order_release);
	    atomic_store_explicit(&old_stored->next, new_stored, memory_order_release);
	  }
	  else
	  {
	    atomic_store_explicit(&new_stored->next, NULL, memory_order_relaxed);
	    atomic_store_explicit(last_ptr, new_stored, memory_order_release);
	  }
	}
      /* The fourth (empty) case - suboptimal route is being removed, nothing to do */
    }

  /* Finally drop the old route */
  if (old_stored)
  {
    uint seen = 0;
    NET_WALK_ROUTES(table, net, ep, e)
      if (e == old_stored)
      {
	ASSERT_DIE(e->rte.src == src);
	atomic_store_explicit(ep,
	    atomic_load_explicit(&e->next, memory_order_relaxed),
	    memory_order_release);
	ASSERT_DIE(!seen++);
      }
    ASSERT_DIE(seen == 1);
  }

  struct rte_storage *new_best = atomic_load_explicit(&local_sentinel.next, memory_order_relaxed);

  /* Log the route change */
  if (new_ok)
    rt_rte_trace_in(D_ROUTES, req, &new_stored->rte, new_stored == new_best ? "added [best]" : "added");
  else if (old_ok)
    {
      if (old != old_best)
	rt_rte_trace_in(D_ROUTES, req, old, "removed");
      else if (new_best && rte_is_ok(&new_best->rte))
	rt_rte_trace_in(D_ROUTES, req, old, "removed [replaced]");
      else
	rt_rte_trace_in(D_ROUTES, req, old, "removed [sole]");
    }
  else
    if (req->trace_routes & D_ROUTES)
      log(L_TRACE "%s > ignored %N %s->%s", req->name, i->addr, old ? "filtered" : "none", new ? "filtered" : "none");

  rt_log(c->req, RTE_OR_NULL(new_best), old_best, RTWH_BEST);

  /* Propagate the route change */
  rte_announce(table, i, net,
      RTE_OR_NULL(new_stored), RTE_OR_NULL(old_stored),
      RTE_OR_NULL(new_best), RTE_OR_NULL(old_best_stored));

  /* Now we can finally release the changes back for reading */
  atomic_store_explicit(&net->routes, new_best, memory_order_release);

  return;
}

int
channel_preimport(struct rt_import_request *req, rte *new, const rte *old)
{
  SKIP_BACK_DECLARE(struct channel, c, in_req, req);

  if (new && !old)
    if (CHANNEL_LIMIT_PUSH(c, RX))
    {
      c->import_stats.updates_limited_rx++;
      return 0;
    }

  if (!new && old)
    CHANNEL_LIMIT_POP(c, RX);

  int new_in = new && !rte_is_filtered(new);
  int old_in = old && !rte_is_filtered(old);

  int verdict = 1;

  if (new_in && !old_in)
    if (CHANNEL_LIMIT_PUSH(c, IN))
      if (c->in_keep & RIK_REJECTED)
	new->flags |= REF_FILTERED;
      else
      {
	c->import_stats.updates_limited_in++;
	verdict = 0;
      }

  if (!new_in && old_in)
    CHANNEL_LIMIT_POP(c, IN);

  mpls_rte_preimport(new_in ? new : NULL, old_in ? old : NULL);

  if (new)
    bmap_set(&c->imported_map, NET_TO_INDEX(new->net)->index);

  return verdict;
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

  /* Storing prefilter routes as an explicit layer */
  if (new && (c->in_keep & RIK_PREFILTER))
    new->attrs = ea_lookup_tmp(new->attrs, 0, EALS_PREIMPORT);

#if 0
  debug("%s.%s -(prefilter)-> %s: %N ", c->proto->name, c->name, c->table->name, n);
  if (new) ea_dump(new->attrs);
  else debug("withdraw");
  debug("\n");
#endif

  const struct filter *filter = c->in_filter;
  struct channel_import_stats *stats = &c->import_stats;
  struct mpls_fec *fec = NULL;

  if (new)
    {
      new->net = n;
      new->sender = c->in_req.hook;

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

      if (new && c->proto->mpls_channel)
	if (mpls_handle_rte(c->proto->mpls_channel, n, new, &fec) < 0)
	  {
	    channel_rte_trace_in(D_FILTERS, c, new, "invalid");
	    stats->updates_invalid++;
	    new = NULL;
	  }

      if (new)
      {
	new->attrs = ea_lookup_tmp(new->attrs,
	    (c->in_keep & RIK_PREFILTER) ? BIT32_ALL(EALS_PREIMPORT) : 0, EALS_FILTERED);

	if (net_is_flow(n))
	  rt_flowspec_resolve_rte(new, c);
	else
	  rt_next_hop_resolve_rte(new);
      }

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

  if (fec)
  {
    mpls_unlock_fec(fec);
    DBGL( "Unlock FEC %p (rte_update %N)", fec, n);
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
    u32 bs = atomic_load_explicit(&tab->routes_block_size, memory_order_acquire);

    struct netindex *i;
    net *routes = atomic_load_explicit(&tab->routes, memory_order_acquire);
    net *nn;
    if (new)
    {
      /* An update */
      /* Set auxiliary values */
      new->stale_cycle = hook->stale_set;
      new->sender = hook;

      /* Allocate the key structure */
      i = net_get_index(tab->netindex, n);
      new->net = i->addr;

      /* Block size update */
      u32 nbs = bs;
      while (i->index >= nbs)
	nbs *= 2;

      if (nbs > bs)
      {
	net *nb = mb_alloc(tab->rp, nbs * sizeof *nb);
	memcpy(&nb[0], routes, bs * sizeof *nb);
	memset(&nb[bs], 0, (nbs - bs) * sizeof *nb);
	ASSERT_DIE(atomic_compare_exchange_strong_explicit(
	      &tab->routes, &routes, nb,
	      memory_order_acq_rel, memory_order_relaxed));
	ASSERT_DIE(atomic_compare_exchange_strong_explicit(
	      &tab->routes_block_size, &bs, nbs,
	      memory_order_acq_rel, memory_order_relaxed));
	ASSERT_DIE(atomic_compare_exchange_strong_explicit(
	      &tab->export_all.max_feed_index, &bs, nbs,
	      memory_order_acq_rel, memory_order_relaxed));
	ASSERT_DIE(atomic_compare_exchange_strong_explicit(
	      &tab->export_best.max_feed_index, &bs, nbs,
	      memory_order_acq_rel, memory_order_relaxed));

	synchronize_rcu();
	mb_free(routes);

	routes = nb;
      }

      /* Update table tries */
      struct f_trie *trie = atomic_load_explicit(&tab->trie, memory_order_relaxed);
      if (trie)
	trie_add_prefix(trie, i->addr, i->addr->pxlen, i->addr->pxlen);

      if (tab->trie_new)
	trie_add_prefix(tab->trie_new, i->addr, i->addr->pxlen, i->addr->pxlen);
    }
    else if ((i = net_find_index(tab->netindex, n)) && (i->index < bs))
      /* Found an block where we can withdraw from */
      ;
    else
    {
      /* No route for this net is present at all. Ignore right now. */
      req->hook->stats.withdraws_ignored++;
      if (req->trace_routes & D_ROUTES)
	log(L_TRACE "%s > ignored %N withdraw", req->name, n);
      return;
    }

    /* Resolve the net structure */
    nn = &routes[i->index];

    /* Recalculate the best route. */
    rte_recalculate(tab, hook, i, nn, new, src);
  }
}

/*
 *	Feeding
 */

static net *
rt_net_feed_get_net(struct rtable_reading *tr, uint index)
{
  /* Get the route block from the table */
  net *routes = atomic_load_explicit(&tr->t->routes, memory_order_acquire);
  u32 bs = atomic_load_explicit(&tr->t->routes_block_size, memory_order_acquire);

  /* Nothing to actually feed */
  if (index >= bs)
    return NULL;

  /* We have a net to feed! */
  return &routes[index];
}

static const struct rt_pending_export *
rt_net_feed_validate_first(
    struct rtable_reading *tr,
    const struct rt_pending_export *first_in_net,
    const struct rt_pending_export *last_in_net,
    const struct rt_pending_export *first)
{
  /* Inconsistent input */
  if (!first_in_net != !last_in_net)
    RT_READ_RETRY(tr);

  if (!first)
    return first_in_net;

  /* Export item validity check: we must find it between first_in_net and last_in_net */
  const struct rt_pending_export *rpe = first_in_net;
  while (rpe)
    if (rpe == first)
      return first;
    else if (rpe == last_in_net)
      /* Got to the end without finding the beginning */
      break;
    else
      rpe = atomic_load_explicit(&rpe->next, memory_order_acquire);

  /* Not found, inconsistent export, retry */
  RT_READ_RETRY(tr);
}

static struct rt_export_feed *
rt_net_feed_index(struct rtable_reading *tr, net *n, struct bmap *seen, bool (*prefilter)(struct rt_export_feeder *, const net_addr *), struct rt_export_feeder *f, const struct rt_pending_export *first)
{
  /* Get the feed itself. It may change under our hands tho. */
  struct rt_pending_export *first_in_net, *last_in_net;
  first_in_net = atomic_load_explicit(&n->all.first, memory_order_acquire);
  last_in_net = atomic_load_explicit(&n->all.last, memory_order_acquire);

  first = rt_net_feed_validate_first(tr, first_in_net, last_in_net, first);

  /* Count the elements */
  uint rcnt = rte_feed_count(tr, n);
  uint ecnt = 0;
  uint ocnt = 0;
  for (const struct rt_pending_export *rpe = first; rpe;
      rpe = atomic_load_explicit(&rpe->next, memory_order_acquire))
    if (!seen || !bmap_test(seen, rpe->it.seq))
    {
      ecnt++;
      if (rpe->it.old)
	ocnt++;
    }

  if (ecnt) {
    const net_addr *a = (first->it.new ?: first->it.old)->net;
    if (prefilter && !prefilter(f, a))
      return NULL;
  }

  struct rt_export_feed *feed = NULL;

  if (rcnt || ocnt || ecnt)
  {
    if (!ecnt && prefilter && !prefilter(f, NET_READ_BEST_ROUTE(tr, n)->rte.net))
      return NULL;

    feed = rt_alloc_feed(rcnt+ocnt, ecnt);

    if (rcnt)
      rte_feed_obtain_copy(tr, n, feed->block, rcnt);

    if (ecnt)
    {
      uint e = 0;
      uint rpos = rcnt;
      for (const struct rt_pending_export *rpe = first; rpe;
	  rpe = atomic_load_explicit(&rpe->next, memory_order_acquire))
	if (!seen || !bmap_test(seen, rpe->it.seq))
	{
	  if (e >= ecnt)
	    RT_READ_RETRY(tr);

	  feed->exports[e++] = rpe->it.seq;

	  /* Copy also obsolete routes */
	  if (rpe->it.old)
	  {
	    ASSERT_DIE(rpos < rcnt + ocnt);
	    feed->block[rpos++] = *rpe->it.old;
	    ea_free_later(ea_ref(rpe->it.old->attrs));
	  }
	}

      ASSERT_DIE(e == ecnt);
    }

    feed->ni = NET_TO_INDEX(feed->block[0].net);
  }

  /* Check that it indeed didn't change and the last export is still the same. */
  if (
      (first_in_net != atomic_load_explicit(&n->all.first, memory_order_acquire))
   || (last_in_net != atomic_load_explicit(&n->all.last, memory_order_acquire)))
    RT_READ_RETRY(tr);

  return feed;
}

static struct rt_export_feed *
rt_net_feed_internal(struct rtable_reading *tr, u32 index, struct bmap *seen, bool (*prefilter)(struct rt_export_feeder *, const net_addr *), struct rt_export_feeder *f, const struct rt_pending_export *first)
{
  net *n = rt_net_feed_get_net(tr, index);
  if (!n)
    return &rt_feed_index_out_of_range;

  return rt_net_feed_index(tr, n, seen, prefilter, f, first);
}

struct rt_export_feed *
rt_net_feed(rtable *t, const net_addr *a, const struct rt_pending_export *first)
{
  RT_READ(t, tr);
  const struct netindex *ni = net_find_index(tr->t->netindex, a);
  return ni ? rt_net_feed_internal(tr, ni->index, NULL, NULL, NULL, first) : NULL;
}

static struct rt_export_feed *
rt_feed_net_all(struct rt_exporter *e, struct rcu_unwinder *u, u32 index, struct bmap *seen, bool (*prefilter)(struct rt_export_feeder *, const net_addr *), struct rt_export_feeder *f, const struct rt_export_item *_first)
{
  RT_READ_ANCHORED(SKIP_BACK(rtable, export_all, e), tr, u);
  return rt_net_feed_internal(tr, index, seen, prefilter, f, SKIP_BACK(const struct rt_pending_export, it, _first));
}

rte
rt_net_best(rtable *t, const net_addr *a)
{
  rte rt = {};

  RT_READ(t, tr);

  struct netindex *i = net_find_index(t->netindex, a);
  net *n = i ? net_find(tr, i) : NULL;
  if (!n)
    return rt;

  struct rte_storage *e = NET_READ_BEST_ROUTE(tr, n);
  if (!e || !rte_is_valid(&e->rte))
    return rt;

  ASSERT_DIE(e->rte.net == i->addr);
  ea_free_later(ea_ref(e->rte.attrs));
  return RTE_COPY(e);
}

static struct rt_export_feed *
rt_feed_net_best(struct rt_exporter *e, struct rcu_unwinder *u, u32 index, struct bmap *seen, bool (*prefilter)(struct rt_export_feeder *, const net_addr *), struct rt_export_feeder *f, const struct rt_export_item *_first)
{
  SKIP_BACK_DECLARE(rtable, t, export_best, e);
  SKIP_BACK_DECLARE(const struct rt_pending_export, first, it, _first);

  RT_READ_ANCHORED(t, tr, u);

  net *n = rt_net_feed_get_net(tr, index);
  if (!n)
    return &rt_feed_index_out_of_range;
    /* No more to feed, we are fed up! */

  const struct rt_pending_export *first_in_net, *last_in_net;
  first_in_net = atomic_load_explicit(&n->best.first, memory_order_acquire);
  last_in_net = atomic_load_explicit(&n->best.last, memory_order_acquire);
  first = rt_net_feed_validate_first(tr, first_in_net, last_in_net, first);

  struct rte_storage *best = NET_READ_BEST_ROUTE(tr, n);
  if (best && !rte_is_valid(&best->rte))
    best = NULL;

  uint ecnt = 0, ocnt = 0;
  bool export_in_map = true;
  for (const struct rt_pending_export *rpe = first; rpe;
      rpe = atomic_load_explicit(&rpe->next, memory_order_acquire))
    if (seen && bmap_test(seen, rpe->it.seq))
      ASSERT_DIE(export_in_map);
    else
    {
      export_in_map = false;
      ecnt++;
      if (rpe->it.old && (!best || (rpe->it.old != &best->rte)))
	ocnt++;
    }

  if (ecnt) {
    const net_addr *a = (first->it.new ?: first->it.old)->net;
    if (prefilter && !prefilter(f, a))
      return NULL;
  }

  if (!ecnt && (!best || prefilter && !prefilter(f, best->rte.net)))
    return NULL;

  struct rt_export_feed *feed = rt_alloc_feed(!!best + ocnt, ecnt);
  uint bpos = 0;
  if (best)
  {
    feed->block[bpos++] = best->rte;
    feed->ni = NET_TO_INDEX(best->rte.net);
  }
  else
    feed->ni = NET_TO_INDEX((first->it.new ?: first->it.old)->net);

  if (ecnt)
  {
    uint e = 0;
    for (const struct rt_pending_export *rpe = first; rpe;
	rpe = atomic_load_explicit(&rpe->next, memory_order_acquire))
      if (!seen || !bmap_test(seen, rpe->it.seq))
      {
	if (e >= ecnt)
	  RT_READ_RETRY(tr);

	feed->exports[e++] = rpe->it.seq;
	if (rpe->it.old && (!best || (rpe->it.old != &best->rte)))
	{
	  ASSERT_DIE(bpos < !!best + ocnt);
	  feed->block[bpos] = *rpe->it.old;
	  feed->block[bpos].flags |= REF_OBSOLETE;
	  bpos++;
	}
      }

    ASSERT_DIE(bpos == !!best + ocnt);
    ASSERT_DIE(e == ecnt);
  }

  /* Check that it indeed didn't change and the last export is still the same. */
  if (
      (first_in_net != atomic_load_explicit(&n->best.first, memory_order_acquire))
      || (last_in_net != atomic_load_explicit(&n->best.last, memory_order_acquire)))
    RT_READ_RETRY(tr);

  /* And we're finally done */
  return feed;
}


/* Check rtable for best route to given net whether it would be exported do p */
int
rt_examine(rtable *t, net_addr *a, struct channel *c, const struct filter *filter)
{
  rte rt = rt_net_best(t, a);

  int v = c->proto->preexport ? c->proto->preexport(c, &rt) : 0;
  if (v == RIC_PROCESS)
    v = (f_run(filter, &rt, FF_SILENT) <= F_ACCEPT);

  return v > 0;
}

static inline void
rt_set_import_state(struct rt_import_hook *hook, u8 state)
{
  hook->last_state_change = current_time();
  hook->import_state = state;

  CALL(hook->req->log_state_change, hook->req, state);
}

void
rt_request_import(rtable *t, struct rt_import_request *req)
{
  RT_LOCKED(t, tab)
  {
    rt_lock_table(tab);

    struct rt_import_hook *hook = req->hook = mb_allocz(tab->rp, sizeof(struct rt_import_hook));

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
    rt_set_import_state(hook, TIS_STOP);
    hook->stopped = stopped;

    rt_refresh_trace(tab, hook, "stop import");

    /* Cancel table rr_counter */
    if (hook->stale_set != hook->stale_pruned)
      tab->rr_counter -= ((int) hook->stale_set - (int) hook->stale_pruned);

    tab->rr_counter++;

    hook->stale_set = hook->stale_pruned = hook->stale_pruning = hook->stale_valid = 0;

    rt_schedule_prune(tab);
  }
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

  RT_LOCKED(hook->table, tab)
  {

  /* If the pruning routine is too slow */
  if (((hook->stale_set - hook->stale_pruned) & 0xff) >= 240)
  {
    log(L_WARN "Route refresh flood in table %s (stale_set=%u, stale_pruned=%u)", hook->table->name, hook->stale_set, hook->stale_pruned);

    /* Forcibly set all old routes' stale cycle to zero. */
    u32 bs = atomic_load_explicit(&tab->routes_block_size, memory_order_relaxed);
    net *routes = atomic_load_explicit(&tab->routes, memory_order_relaxed);
    for (u32 i = 0; i < bs; i++)
      NET_WALK_ROUTES(tab, &routes[i], ep, e)
	if (e->rte.sender == req->hook)
	  e->stale_cycle = 0;

    /* Smash the route refresh counter and zero everything. */
    tab->rr_counter -= ((int) hook->stale_set - (int) hook->stale_pruned);
    hook->stale_set = hook->stale_valid = hook->stale_pruning = hook->stale_pruned = 0;
  }

  /* Now we can safely increase the stale_set modifier */
  hook->stale_set++;

  /* The table must know that we're route-refreshing */
  tab->rr_counter++;

  rt_refresh_trace(tab, hook, "route refresh begin");
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
    /* Now valid routes are only those one with the latest stale_set value */
    UNUSED uint cnt = hook->stale_set - hook->stale_valid;
    hook->stale_valid = hook->stale_set;

    /* Here we can't kick the timer as we aren't in the table service loop */
    rt_schedule_prune(tab);

    rt_refresh_trace(tab, hook, "route refresh end");
  }
}

/**
 * rt_refresh_trace - log information about route refresh
 * @tab: table
 * @ih: import hook doing the route refresh
 * @msg: what is happening
 *
 * This function consistently logs route refresh messages.
 */
static void
rt_refresh_trace(struct rtable_private *tab, struct rt_import_hook *ih, const char *msg)
{
  if (ih->req->trace_routes & D_STATES)
    log(L_TRACE "%s: %s: rr %u set %u valid %u pruning %u pruned %u", ih->req->name, msg,
	tab->rr_counter, ih->stale_set, ih->stale_valid, ih->stale_pruning, ih->stale_pruned);
}

/**
 * rte_dump - dump a route
 * @e: &rte to be dumped
 *
 * This functions dumps contents of a &rte to debug output.
 */
void
rte_dump(struct dump_request *dreq, struct rte_storage *e)
{
  RDUMP("(%u) %-1N", NET_TO_INDEX(e->rte.net)->index, e->rte.net);
  RDUMP("ID=%d ", e->rte.id);
  RDUMP("SENDER=%s ", e->rte.sender->req->name);
  RDUMP("PF=%02x ", e->rte.pflags);
  RDUMP("SRC=%uG ", e->rte.src->global_id);
  ea_dump(dreq, e->rte.attrs);
  RDUMP("\n");
}

/**
 * rt_dump - dump a routing table
 * @t: routing table to be dumped
 *
 * This function dumps contents of a given routing table to debug output.
 */
void
rt_dump(struct dump_request *dreq, rtable *tab)
{
  RT_READ(tab, tp);

  /* Looking at priv.deleted is technically unsafe but we don't care */
  RDUMP("Dump of routing table <%s>%s\n", tab->name, OBSREF_GET(tab->priv.deleted) ? " (deleted)" : "");

  u32 bs = atomic_load_explicit(&tp->t->routes_block_size, memory_order_relaxed);
  net *routes = atomic_load_explicit(&tp->t->routes, memory_order_relaxed);
  for (u32 i = 0; i < bs; i++)
    NET_READ_WALK_ROUTES(tp, &routes[i], ep, e)
      rte_dump(dreq, e);

  RDUMP("\n");
}

/**
 * rt_dump_all - dump all routing tables
 *
 * This function dumps contents of all routing tables to debug output.
 */
void
rt_dump_all(struct dump_request *dreq)
{
  rtable *t;
  node *n;

  WALK_LIST2(t, n, routing_tables, n)
    rt_dump(dreq, t);

  WALK_LIST2(t, n, deleted_routing_tables, n)
    rt_dump(dreq, t);
}

void
rt_dump_hooks(struct dump_request *dreq, rtable *tp)
{
  RT_LOCKED(tp, tab)
  {

  RDUMP("Dump of hooks in routing table <%s>%s\n", tab->name, OBSREF_GET(tab->deleted) ? " (deleted)" : "");
  RDUMP("  nhu_state=%u use_count=%d rt_count=%u\n",
      tab->nhu_state, tab->use_count, tab->rt_count);
  RDUMP("  last_rt_change=%t gc_time=%t gc_counter=%d prune_state=%u\n",
      tab->last_rt_change, tab->gc_time, tab->gc_counter, tab->prune_state);

  struct rt_import_hook *ih;
  WALK_LIST(ih, tab->imports)
  {
    ih->req->dump_req(ih->req);
    RDUMP("  Import hook %p requested by %p: pref=%u"
       " last_state_change=%t import_state=%u stopped=%p\n",
       ih, ih->req, ih->stats.pref,
       ih->last_state_change, ih->import_state, ih->stopped);
  }

#if 0
  /* FIXME: I'm very lazy to write this now */
  WALK_TLIST(lfjour_recipient, r, &tab->journal.recipients)
  {
    SKIP_BACK_DECLARE(struct rt_export_hook, eh, recipient, r);
    eh->req->dump_req(eh->req);
    RDUMP("  Export hook %p requested by %p:"
       " refeed_pending=%u last_state_change=%t export_state=%u\n",
       eh, eh->req, eh->refeed_pending, eh->last_state_change,
       atomic_load_explicit(&eh->export_state, memory_order_relaxed));
  }
#endif
  RDUMP("\n");

  }
}

void
rt_dump_hooks_all(struct dump_request *dreq)
{
  rtable *t;
  node *n;

  RDUMP("Dump of all table hooks\n");

  WALK_LIST2(t, n, routing_tables, n)
    rt_dump_hooks(dreq, t);

  WALK_LIST2(t, n, deleted_routing_tables, n)
    rt_dump_hooks(dreq, t);
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
      ev_send_loop(tab->loop, tab->nhu_event);
  }
}

void
rt_schedule_prune(struct rtable_private *tab)
{
  /* The table is empty if there are no imports */
  if (EMPTY_LIST(tab->imports))
    return;

  /* state change 0->1, 2->3 */
  tab->prune_state |= 1;
  if (!tab->reconf_end)
    ev_send_loop(tab->loop, tab->prune_event);

  /* If reconfiguring, we explicitly activate the prune after done
   * to stop expensive operations from happening too early. */
}

struct rt_reconf_finished_deferred_call {
  struct deferred_call dc;
  rtable *tab;
};

static void
rt_reconf_finished(struct deferred_call *dc)
{
  /* Reconfiguration ended, let's reinstate prune events */
  ASSERT_DIE(birdloop_inside(&main_birdloop));
  RT_LOCKED(SKIP_BACK(struct rt_reconf_finished_deferred_call, dc, dc)->tab, tab)
  {
    rt_unlock_table(tab);
    if (dc == tab->reconf_end)
    {
      tab->reconf_end = NULL;

      if (tab->prune_state & 1)
	ev_send_loop(tab->loop, tab->prune_event);
    }
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

#define TLIST_PREFIX rt_flowspec_link
#define TLIST_TYPE struct rt_flowspec_link
#define TLIST_ITEM n
#define TLIST_WANT_WALK
#define TLIST_WANT_ADD_TAIL
#define TLIST_DEFINED_BEFORE

struct rt_flowspec_link {
  TLIST_DEFAULT_NODE;
  rtable *src;
  rtable *dst;
  u32 uc;
  struct rt_export_request req;
  event event;
};

#include "lib/tlists.h"


static void
rt_flowspec_export(void *_link)
{
  struct rt_flowspec_link *ln = _link;
  rtable *dst_pub = ln->dst;
  ASSUME(rt_is_flow(dst_pub));

  RT_EXPORT_WALK(&ln->req, u)
  {
    const net_addr *n = NULL;
    switch (u->kind)
    {
      case RT_EXPORT_STOP:
	bug("Main table export stopped");

      case RT_EXPORT_FEED:
	if (u->feed->count_routes)
	  n = u->feed->block[0].net;
	break;

      case RT_EXPORT_UPDATE:
	{
	  /* Conflate following updates */
	  const rte *old = RTE_VALID_OR_NULL(u->update->old);
	  const rte *new = u->update->new;
	  for (
	      SKIP_BACK_DECLARE(struct rt_pending_export, rpe, it, u->update);
	      rpe = atomic_load_explicit(&rpe->next, memory_order_acquire) ;)
	  {
	    ASSERT_DIE(new == rpe->it.old);
	    new = rpe->it.new;
	    rt_export_processed(&ln->req, rpe->it.seq);
	  }

	  /* Ignore idempotent */
	  if ((old == new) || old && new && rte_same(old, new))
	    continue;

	  n = (new ?: old)->net;
	}
	break;
    }

    if (!n)
      continue;

    RT_LOCKED(dst_pub, dst)
    {
      /* No need to inspect it further if recalculation is already scheduled */
      if ((dst->nhu_state == NHU_SCHEDULED) || (dst->nhu_state == NHU_DIRTY))
	break;

      /* Irrelevant prefix */
      if (!trie_match_net(dst->flowspec_trie, n))
	break;

      /* Actually, schedule NHU */
      rt_schedule_nhu(dst);
    }

    MAYBE_DEFER_TASK(birdloop_event_list(dst_pub->loop), &ln->event,
	"flowspec ctl export from %s to %s", ln->src->name, dst_pub->name);
  }
}

static void
rt_flowspec_dump_req(struct rt_export_request *req)
{
  SKIP_BACK_DECLARE(struct rt_flowspec_link, ln, req, req);
  debug("  Flowspec link for table %s (%p)\n", ln->dst->name, req);
}

static struct rt_flowspec_link *
rt_flowspec_find_link(struct rtable_private *src, rtable *dst)
{
  WALK_TLIST(rt_flowspec_link, ln, &src->flowspec_links)
    if (ln->dst == dst)
      switch (rt_export_get_state(&ln->req))
      {
	case TES_FEEDING:
	case TES_READY:
	case TES_PARTIAL:
	  return ln;

	default:
	  bug("Unexpected flowspec link state");
      }

  return NULL;
}

void
rt_flowspec_link(rtable *src_pub, rtable *dst_pub)
{
  ASSERT(rt_is_ip(src_pub));
  ASSERT(rt_is_flow(dst_pub));

  int lock_dst = 0;

  BIRDLOOP_ENTER(dst_pub->loop);

  RT_LOCKED(src_pub, src)
  {
    struct rt_flowspec_link *ln = rt_flowspec_find_link(src, dst_pub);

    if (!ln)
    {
      pool *p = birdloop_pool(dst_pub->loop);
      ln = mb_allocz(p, sizeof(struct rt_flowspec_link));
      ln->src = src_pub;
      ln->dst = dst_pub;
      ln->req = (struct rt_export_request) {
	.name = mb_sprintf(p, "%s.flowspec.notifier", dst_pub->name),
	.r = {
	  .event = &ln->event,
	  .target = birdloop_event_list(dst_pub->loop),
	},
	.pool = p,
	.trace_routes = src->config->debug,
	.dump = rt_flowspec_dump_req,
      };
      ln->event = (event) {
	.hook = rt_flowspec_export,
	.data = ln,
      };
      rt_flowspec_link_add_tail(&src->flowspec_links, ln);

      rtex_export_subscribe(&src->export_best, &ln->req);

      lock_dst = 1;
    }

    ln->uc++;
  }

  if (lock_dst)
    rt_lock_table(dst_pub);
}

void
rt_flowspec_unlink(rtable *src, rtable *dst)
{
  BIRDLOOP_ENTER(dst->loop);

  bool unlock_dst = 0;

  struct rt_flowspec_link *ln;
  RT_LOCKED(src, t)
  {
    ln = rt_flowspec_find_link(t, dst);

    ASSERT(ln && (ln->uc > 0));

    if (!--ln->uc)
    {
      rt_flowspec_link_rem_node(&t->flowspec_links, ln);
      rtex_export_unsubscribe(&ln->req);
      ev_postpone(&ln->event);
      mb_free(ln);
      unlock_dst = 1;
    }
  }

  if (unlock_dst)
    rt_unlock_table(dst);
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

/* ROA digestor */

static void
rt_dump_digestor_req(struct rt_export_request *req)
{
  debug("  ROA update digestor %s (%p)\n", req->name, req);
}

static void
rt_cleanup_digest(struct lfjour *j UNUSED, struct lfjour_item *i)
{
  SKIP_BACK_DECLARE(struct rt_digest, d, li, i);
  rfree(d->trie->lp);
}

static void
rt_announce_digest(struct settle *s)
{
  SKIP_BACK_DECLARE(struct rt_digestor, d, settle, s);

  RT_LOCK(d->tab, tab);

  struct lfjour_item *it = lfjour_push_prepare(&d->digest);
  if (it)
  {
    SKIP_BACK_DECLARE(struct rt_digest, dd, li, it);
    dd->trie = d->trie;
    lfjour_push_commit(&d->digest);
  }
  else
    rfree(d->trie->lp);

  d->trie = f_new_trie(lp_new(tab->rp), 0);
}

static void
rt_digest_update_net(struct rt_digestor *d, struct netindex *ni, uint maxlen)
{
  trie_add_prefix(d->trie, ni->addr, net_pxlen(ni->addr), maxlen);
  settle_kick(&d->settle, d->tab->loop);
}

static void
rt_digest_update(void *_d)
{
  struct rt_digestor *d = _d;
  RT_LOCK(d->tab, tab);

  RT_EXPORT_WALK(&d->req, u)
  {
    struct netindex *ni = NULL;
    switch (u->kind)
    {
      case RT_EXPORT_STOP:
	bug("Main table export stopped");

      case RT_EXPORT_FEED:
	if (u->feed->count_routes)
	  ni = u->feed->ni;
	break;

      case RT_EXPORT_UPDATE:
	ni = NET_TO_INDEX(u->update->new ? u->update->new->net : u->update->old->net);
	break;
    }

    if (ni)
      rt_digest_update_net(d, ni, net_max_prefix_length[tab->addr_type]);

#if 0
    /* Digestor is never splitting, it just digests everything
     * because we prefer to generate one big trie instead of a lot of small ones. */
    MAYBE_DEFER_TASK(birdloop_event_list(tab->loop), &d->event,
	"ROA digestor update in %s", tab->name);
#endif
  }
}


/* Routing table setup and free */

static void
rt_free(resource *_r)
{
  SKIP_BACK_DECLARE(struct rtable_private, r, r, _r);

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
rt_res_dump(struct dump_request *dreq, resource *_r)
{
  SKIP_BACK_DECLARE(struct rtable_private, r, r, _r);

  RDUMP("name \"%s\", addr_type=%s, rt_count=%u, use_count=%d\n",
      r->name, net_label[r->addr_type], r->rt_count, r->use_count);

  RDUMP("Exporter ALL:\n");
  dreq->indent += 3;
  rt_exporter_dump(dreq, &r->export_all);
  dreq->indent -= 3;
  RDUMP("Exporter BEST:\n");
  dreq->indent += 3;
  rt_exporter_dump(dreq, &r->export_best);
  dreq->indent -= 3;
}

static struct resmem
rt_res_memsize(resource *_r)
{
  SKIP_BACK_DECLARE(struct rtable_private, r, r, _r);

  struct resmem amem = rt_exporter_memsize(&r->export_all);
  struct resmem bmem = rt_exporter_memsize(&r->export_best);

  return (struct resmem) {
    .effective = amem.effective + bmem.effective,
    .overhead = amem.overhead + bmem.overhead,
  };
}

static struct resclass rt_class = {
  .name = "Routing table",
  .size = sizeof(rtable),
  .free = rt_free,
  .dump = rt_res_dump,
  .lookup = NULL,
  .memsize = rt_res_memsize,
};

static struct idm rtable_idm;
uint rtable_max_id = 0;

rtable *
rt_setup(pool *pp, struct rtable_config *cf)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  /* Start the service thread */
  struct birdloop *loop = birdloop_new(pp, DOMAIN_ORDER(service), cf->thread_group->group, "Routing table service %s", cf->name);
  BIRDLOOP_ENTER(loop);
  pool *sp = birdloop_pool(loop);

  /* Create the table domain and pool */
  DOMAIN(rtable) dom = DOMAIN_NEW(rtable);
  LOCK_DOMAIN(rtable, dom);

  pool *p = rp_newf(sp, dom.rtable, "Routing table data %s", cf->name);

  /* Create the actual table */
  struct rtable_private *t = ralloc(p, &rt_class);
  t->rp = p;
  t->loop = loop;
  t->lock = dom;

  t->rte_slab = sl_new(p, sizeof(struct rte_storage));

  t->name = cf->name;
  t->config = cf;
  t->addr_type = cf->addr_type;
  t->debug = cf->debug;
  t->id = idm_alloc(&rtable_idm);
  if (t->id >= rtable_max_id)
    rtable_max_id = t->id + 1;

  t->netindex = netindex_hash_new(birdloop_pool(t->loop), birdloop_event_list(t->loop), cf->addr_type);
  atomic_store_explicit(&t->routes, mb_allocz(p, RT_INITIAL_ROUTES_BLOCK_SIZE * sizeof(net)), memory_order_relaxed);
  atomic_store_explicit(&t->routes_block_size, RT_INITIAL_ROUTES_BLOCK_SIZE, memory_order_relaxed);

  if (cf->trie_used)
  {
    struct f_trie *trie = f_new_trie(lp_new_default(p), 0);
    trie->ipv4 = net_val_match(t->addr_type, NB_IP4 | NB_VPN4 | NB_ROA4);
    atomic_store_explicit(&t->trie, trie, memory_order_relaxed);
  }

  init_list(&t->imports);

  hmap_init(&t->id_map, p, 1024);
  hmap_set(&t->id_map, 0);

  t->nhu_event = ev_new_init(p, rt_next_hop_update, t);
  callback_init(&t->nhu_uncork.cb, rt_nhu_uncork, t->loop);
  t->prune_timer = tm_new_init(p, rt_prune_timer, t, 0, 0);
  t->prune_event = ev_new_init(p, rt_prune_table, t);
  t->last_rt_change = t->gc_time = current_time();

  t->export_best = (struct rt_exporter) {
    .journal = {
      .loop = t->loop,
      .domain = t->lock.rtable,
      .item_size = sizeof(struct rt_pending_export),
      .item_done = rt_cleanup_export_best,
    },
    .name = mb_sprintf(p, "%s.export-best", t->name),
    .net_type = t->addr_type,
    .max_feed_index = RT_INITIAL_ROUTES_BLOCK_SIZE,
    .netindex = t->netindex,
    .trace_routes = t->debug,
    .cleanup_done = rt_cleanup_done_best,
    .feed_net = rt_feed_net_best,
  };

  rt_exporter_init(&t->export_best, &cf->export_settle);

  t->export_all = (struct rt_exporter) {
    .journal = {
      .loop = t->loop,
      .domain = t->lock.rtable,
      .item_size = sizeof(struct rt_pending_export),
      .item_done = rt_cleanup_export_all,
    },
    .name = mb_sprintf(p, "%s.export-all", t->name),
    .net_type = t->addr_type,
    .max_feed_index = RT_INITIAL_ROUTES_BLOCK_SIZE,
    .netindex = t->netindex,
    .trace_routes = t->debug,
    .cleanup_done = rt_cleanup_done_all,
    .feed_net = rt_feed_net_all,
  };

  rt_exporter_init(&t->export_all, &cf->export_settle);

  t->best_req = (struct rt_export_request) {
    .name = mb_sprintf(p, "%s.best-cleanup", t->name),
    .pool = p,
    .trace_routes = t->debug,
    .dump = rt_dump_best_req,
  };

  /* Subscribe and pre-feed the best_req */
  rtex_export_subscribe(&t->export_all, &t->best_req);
  RT_EXPORT_WALK(&t->best_req, u)
    ASSERT_DIE(u->kind == RT_EXPORT_FEED);

  t->cork_threshold = cf->cork_threshold;

  t->rl_pipe = (struct tbf) TBF_DEFAULT_LOG_LIMITS;

  if (rt_is_flow(RT_PUB(t)))
  {
    t->flowspec_trie = f_new_trie(lp_new_default(p), 0);
    t->flowspec_trie->ipv4 = (t->addr_type == NET_FLOW4);
  }

  UNLOCK_DOMAIN(rtable, dom);

  CALL(cf->master.setup, RT_PUB(t));

  return RT_PUB(t);
}

void
rt_setup_digestor(struct rtable_private *t)
{
  if (t->export_digest)
    return;

  struct rt_digestor *d = mb_alloc(t->rp, sizeof *d);
  *d = (struct rt_digestor) {
    .tab = RT_PUB(t),
    .req = {
    .name = mb_sprintf(t->rp, "%s.rt-digestor", t->name),
      .r = {
	.target = birdloop_event_list(t->loop),
	.event = &d->event,
      },
      .pool = t->rp,
      .trace_routes = t->debug,
      .dump = rt_dump_digestor_req,
    },
    .digest = {
      .loop = t->loop,
      .domain = t->lock.rtable,
      .item_size = sizeof(struct rt_digest),
      .item_done = rt_cleanup_digest,
    },
    .settle = SETTLE_INIT(&t->config->digest_settle, rt_announce_digest, NULL),
    .event = {
      .hook = rt_digest_update,
      .data = d,
    },
    .trie = f_new_trie(lp_new(t->rp), 0),
  };

  struct settle_config digest_settle_config = {};

  rtex_export_subscribe(&t->export_best, &d->req);
  lfjour_init(&d->digest, &digest_settle_config);

  t->export_digest = d;
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
  rt_table_pool = rp_new(&root_pool, the_bird_domain.the_bird, "Routing tables");
  init_list(&routing_tables);
  init_list(&deleted_routing_tables);
  ev_init_list(&rt_cork.queue, &main_birdloop, "Route cork release");
  rt_cork.dom = DOMAIN_NEW(resource);
  idm_init(&rtable_idm, rt_table_pool, 256);

  ea_register_init(&ea_roa_aggregated);
}

static bool
rt_prune_net(struct rtable_private *tab, struct network *n)
{
  NET_WALK_ROUTES(tab, n, ep, e)
  {
    ASSERT_DIE(!(e->flags & REF_OBSOLETE));
    struct rt_import_hook *s = e->rte.sender;

    bool stale = (s->import_state == TIS_FLUSHING);

    if (!stale)
    {

    /*
     * The range of 0..256 is split by s->stale_* like this:
     *
     *     pruned    pruning     valid      set
     *       |          |          |         |
     * 0     v          v          v         v       256
     * |...........................+++++++++++........|
     *
     * We want to drop everything outside the marked range, thus
     *	    (e->rte.stale_cycle < s->stale_valid) ||
     *	    (e->rte.stale_cycle > s->stale_set))
     *	  looks right.
     *
     * But the pointers may wrap around, and in the following situation, all the routes get pruned:
     *
     *      set         pruned    pruning     valid
     *       |            |          |          |
     * 0     v            v          v          v    256
     * |++++++..................................++++++|
     *
     * In that case, we want
     *	    (e->rte.stale_cycle > s->stale_valid) ||
     *	    (e->rte.stale_cycle < s->stale_set))
     *
     * Full logic table:
     *
     *	   permutation   |  result  |  (S < V) + (S < SC) + (SC < V)
     *	-----------------+----------+---------------------------------
     *   SC <   V <=  S  |   prune  |     0    +    0     +     1    =  1
     *    S <  SC <   V  |   prune  |     1    +    1     +     1    =  3
     *    V <=  S <  SC  |   prune  |     0    +    1     +     0    =  1
     *   SC <=  S <   V  |    keep  |     1    +    0     +     1    =  2
     *    V <= SC <=  S  |    keep  |     0    +    0     +     0    =  0
     *    S <   V <= SC  |    keep  |     1    +    1     +     0    =  2
     *
     * Now the following code hopefully makes sense.
     */

      int sv = (s->stale_set < s->stale_valid);
      int ssc = (s->stale_set < e->rte.stale_cycle);
      int scv = (e->rte.stale_cycle < s->stale_valid);
      stale = (sv + ssc + scv) & 1;
    }

    /* By the C standard, either the importer is flushing and stale_perm is 1,
     * or by the table above, stale_perm is between 0 and 3, where even values
     * say "keep" and odd values say "prune". */

    if (stale)
    {
      /* Announce withdrawal */
      struct netindex *i = RTE_GET_NETINDEX(&e->rte);
      rte_recalculate(tab, e->rte.sender, i, n, NULL, e->rte.src);
      return 1;
    }
  }
  return 0;
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
rt_prune_table(void *_tab)
{
  RT_LOCK((rtable *) _tab, tab);

  struct rt_import_hook *ih;
  node *n, *x;

  rt_trace(tab, D_STATES, "Pruning");

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
	rt_refresh_trace(tab, ih, "table prune after refresh begin");
      }

    tab->prune_index = 0;
    tab->prune_state = 2;

    tab->gc_counter = 0;
    tab->gc_time = current_time();

    if (tab->prune_trie)
    {
      /* Init prefix trie pruning */
      tab->trie_new = f_new_trie(lp_new_default(tab->rp), 0);
      tab->trie_new->ipv4 = atomic_load_explicit(&tab->trie, memory_order_relaxed)->ipv4;
    }
  }

  u32 bs = atomic_load_explicit(&tab->routes_block_size, memory_order_relaxed);
  net *routes = atomic_load_explicit(&tab->routes, memory_order_relaxed);
  for (; tab->prune_index < bs; tab->prune_index++)
    {
      net *n = &routes[tab->prune_index];
      while (rt_prune_net(tab, n))
	MAYBE_DEFER_TASK(birdloop_event_list(tab->loop), tab->prune_event,
	    "%s pruning", tab->name);

      struct rte_storage *e = NET_BEST_ROUTE(tab, n);
      if (tab->trie_new && e)
      {
	const net_addr *a = e->rte.net;
	trie_add_prefix(tab->trie_new, a, a->pxlen, a->pxlen);
      }
    }

  rt_trace(tab, D_EVENTS, "Prune done");
  lfjour_announce_now(&tab->export_all.journal);
  lfjour_announce_now(&tab->export_best.journal);

  /* state change 2->0, 3->1
   * pausing expensive prune while reconfiguring to allow for
   * the imports to settle */
  if ((tab->prune_state &= 1) && !tab->reconf_end)
    ev_send_loop(tab->loop, tab->prune_event);

  struct f_trie *trie = atomic_load_explicit(&tab->trie, memory_order_relaxed);
  if (tab->trie_new)
  {
    /* Finish prefix trie pruning */
    atomic_store_explicit(&tab->trie, tab->trie_new, memory_order_release);
    tab->trie_new = NULL;
    tab->prune_trie = 0;

    rt_trace(tab, D_EVENTS, "Trie prune done, new %p, old %p (%s)",
	tab->trie_new, trie, tab->trie_lock_count ? "still used" : "freeing");

    if (!tab->trie_lock_count)
    {
      synchronize_rcu();
      rfree(trie->lp);
    }
    else
    {
      ASSERT(!tab->trie_old);
      tab->trie_old = trie;
      tab->trie_old_lock_count = tab->trie_lock_count;
      tab->trie_lock_count = 0;
    }
  }
  else
  {
    /* Schedule prefix trie pruning */
    if (trie && !tab->trie_old && (trie->prefix_count > (2 * tab->net_count)))
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
      ih->flush_seq = tab->export_all.journal.next_seq;
      rt_set_import_state(ih, TIS_WAITING);
      tab->rr_counter--;
      tab->wait_counter++;
      lfjour_schedule_cleanup(&tab->export_best.journal);
      lfjour_schedule_cleanup(&tab->export_all.journal);
    }
    else if (ih->stale_pruning != ih->stale_pruned)
    {
      tab->rr_counter -= ((int) ih->stale_pruning - (int) ih->stale_pruned);
      ih->stale_pruned = ih->stale_pruning;
      rt_refresh_trace(tab, ih, "table prune after refresh end");
    }
}

void
rt_cork_send_callback(void *_rcc)
{
  struct rt_uncork_callback *rcc = _rcc;
  callback_activate(&rcc->cb);
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
const struct f_trie *
rt_lock_trie(struct rtable_private *tab)
{
  const struct f_trie *trie = atomic_load_explicit(&tab->trie, memory_order_relaxed);
  ASSERT(trie);

  tab->trie_lock_count++;
  return trie;
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
rt_unlock_trie(struct rtable_private *tab, const struct f_trie *trie)
{
  ASSERT(trie);

  const struct f_trie *tab_trie = atomic_load_explicit(&tab->trie, memory_order_relaxed);

  if (trie == tab_trie)
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
      if (tab_trie && (tab_trie->prefix_count > (2 * tab->net_count)))
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

  c->def_tables[NET_IP4] = cf_implicit_symbol(c, "master4", SYM_TABLE, table, NULL);
  c->def_tables[NET_IP6] = cf_implicit_symbol(c, "master6", SYM_TABLE, table, NULL);
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
  {
    if (rc->gc_period == (uint) -1)
      rc->gc_period = (uint) def_gc_period;

    if (rc->roa_aux_table)
    {
      rc->trie_used = 0; /* Never use trie on base ROA table */
#define COPY(x)	rc->roa_aux_table->x = rc->x;
      MACRO_FOREACH(COPY,
	  digest_settle,
	  export_settle,
	  export_rr_settle,
	  cork_threshold,
	  gc_threshold,
	  gc_period,
	  debug);
#undef COPY
    }
  }

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
    struct hostentry_adata head;
    u32 label_space[];
  } *h;
  u32 sz = sizeof *h + lnum * sizeof(u32);
  h = alloca(sz);
  memset(h, 0, sz);

  RT_LOCKED(src, tab)
    h->head.he = rt_get_hostentry(tab, gw, ll, dep);

  memcpy(h->head.labels, labels, lnum * sizeof(u32));

  ea_set_attr_data(to, &ea_gen_hostentry, 0, h->head.ad.data, (byte *) &h->head.labels[lnum] - h->head.ad.data);
}


static void
rta_apply_hostentry(ea_list **to, struct hostentry_adata *head)
{
  u32 *labels = head->labels;
  u32 lnum = (u32 *) (head->ad.data + head->ad.length) - labels;
  struct hostentry *he = head->he;

  rcu_read_lock();
  u32 version = atomic_load_explicit(&he->version, memory_order_acquire);

  while (1)
  {
    if (version & 1)
    {
      rcu_read_unlock();
      birdloop_yield();
      rcu_read_lock();
      version = atomic_load_explicit(&he->version, memory_order_acquire);
      continue;
    }

    /* Jump-away block for applying the actual attributes */
    do {
      ea_set_attr_u32(to, &ea_gen_igp_metric, 0, he->igp_metric);

      ea_list *src = atomic_load_explicit(&he->src, memory_order_acquire);
      if (!src)
      {
	ea_set_dest(to, 0, RTD_UNREACHABLE);
	break;
      }

      eattr *he_nh_ea = ea_find(src, &ea_gen_nexthop);
      ASSERT_DIE(he_nh_ea);

      struct nexthop_adata *nhad = (struct nexthop_adata *) he_nh_ea->u.ptr;
      int idest = nhea_dest(he_nh_ea);

      if ((idest != RTD_UNICAST) ||
	  !lnum && he->nexthop_linkable)
      {
	/* Just link the nexthop chain, no label append happens. */
	ea_copy_attr(to, src, &ea_gen_nexthop);
	break;
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
	break;
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
    while (0);

    /* Has the HE version changed? */
    u32 end_version = atomic_load_explicit(&he->version, memory_order_acquire);

    /* Stayed stable, we can finalize the route */
    if (end_version == version)
      break;

    /* No, retry once again */
    version = end_version;
  }

  rcu_read_unlock();

  ea_set_attr_u32(to, &ea_gen_hostentry_version, 0, version);
}

static inline int
rt_next_hop_update_rte(const rte *old, rte *new)
{
  eattr *hev = ea_find(old->attrs, &ea_gen_hostentry_version);
  if (!hev)
    return 0;
  u32 last_version = hev->u.data;

  eattr *heea = ea_find(old->attrs, &ea_gen_hostentry);
  ASSERT_DIE(heea);
  struct hostentry_adata *head = (struct hostentry_adata *) heea->u.ptr;

  u32 current_version = atomic_load_explicit(&head->he->version, memory_order_acquire);
  if (current_version == last_version)
    return 0;

  *new = *old;
  new->attrs = ea_strip_to(new->attrs, BIT32_ALL(EALS_PREIMPORT, EALS_FILTERED));
  rta_apply_hostentry(&new->attrs, head);
  return 1;
}

static inline void
rt_next_hop_resolve_rte(rte *r)
{
  eattr *heea = ea_find(r->attrs, &ea_gen_hostentry);
  if (!heea)
    return;

  rta_apply_hostentry(&r->attrs, (struct hostentry_adata *) heea->u.ptr);
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
rt_flowspec_check(rtable *tab_ip, struct rtable_private *tab_flow, const net_addr *n, ea_list *a, int interior)
{
  ASSERT(rt_is_ip(tab_ip));
  ASSERT(rt_is_flow(RT_PUB(tab_flow)));

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

  RT_READ(tab_ip, tip);
  const struct f_trie *ip_trie = atomic_load_explicit(&tip->t->trie, memory_order_relaxed);
  ASSERT_DIE(ip_trie);

  /* Find best-match BGP unicast route for flowspec dst prefix */
  net *nb = net_route(tip, &dst);
  if (nb)
    rb = RTE_COPY_VALID(RTE_OR_NULL(NET_READ_BEST_ROUTE(tip, nb)));

  /* Register prefix to trie for tracking further changes */
  int max_pxlen = (n->type == NET_FLOW4) ? IP4_MAX_PREFIX_LENGTH : IP6_MAX_PREFIX_LENGTH;
  trie_add_prefix(tab_flow->flowspec_trie, &dst, (rb.net ? rb.net->pxlen : 0), max_pxlen);

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
  TRIE_WALK(ip_trie, subnet, &dst)
  {
    net *nc = net_find_valid(tip, tip->t->netindex, &subnet);
    if (!nc)
      continue;

    struct rte_storage *rs = NET_READ_BEST_ROUTE(tip, nc);
    const rte *rc = &rs->rte;
    if (rt_get_source_attr(rc) != RTS_BGP)
      return FLOWSPEC_INVALID;

    if (rta_get_first_asn(rc->attrs) != asn_b)
      return FLOWSPEC_INVALID;
  }
  TRIE_WALK_END;

  return FLOWSPEC_VALID;
}

#endif /* CONFIG_BGP */

static int
rt_flowspec_update_rte(struct rtable_private *tab, const rte *r, rte *new)
{
#ifdef CONFIG_BGP
  if (r->generation || (rt_get_source_attr(r) != RTS_BGP))
    return 0;

  struct bgp_channel *bc = (struct bgp_channel *) SKIP_BACK(struct channel, in_req, r->sender->req);
  if (!bc->base_table)
    return 0;

  SKIP_BACK_DECLARE(struct bgp_proto, p, p, bc->c.proto);

  enum flowspec_valid old = rt_get_flowspec_valid(r),
		      valid = rt_flowspec_check(bc->base_table, tab, r->net, r->attrs, p->is_interior);

  if (old == valid)
    return 0;

  *new = *r;
  new->attrs = ea_strip_to(new->attrs, BIT32_ALL(EALS_PREIMPORT, EALS_FILTERED));
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
     && (c->class == &channel_bgp)
     && (bc->base_table))
  {
    SKIP_BACK_DECLARE(struct bgp_proto, p, p, bc->c.proto);
    RT_LOCKED(c->in_req.hook->table, tab)
      valid = rt_flowspec_check(
	  bc->base_table, tab,
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

static inline void
rt_next_hop_update_net(struct rtable_private *tab, struct netindex *ni, net *n)
{
  uint count = 0;
  int is_flow = net_val_match(tab->addr_type, NB_FLOW);

  struct rte_storage *old_best = NET_BEST_ROUTE(tab, n);
  if (!old_best)
    return;

  NET_WALK_ROUTES(tab, n, ep, e)
    count++;

  if (!count)
    return;

  struct rte_multiupdate {
    struct rte_storage *old, *new_stored;
    rte new;
  } *updates = tmp_allocz(sizeof(struct rte_multiupdate) * (count+1));

  uint pos = 0;
  NET_WALK_ROUTES(tab, n, ep, e)
    updates[pos++].old = e;

  uint mod = 0;
  if (is_flow)
    for (uint i = 0; i < pos; i++)
      mod += rt_flowspec_update_rte(tab, &updates[i].old->rte, &updates[i].new);

  else
    for (uint i = 0; i < pos; i++)
      mod += rt_next_hop_update_rte(&updates[i].old->rte, &updates[i].new);

  if (!mod)
    return;

  /* We add a spinlock sentinel to the beginning */
  struct rte_storage local_sentinel = {
    .flags = REF_OBSOLETE,
    .next = old_best,
  };
  atomic_store_explicit(&n->routes, &local_sentinel, memory_order_release);

  /* Now we mark all the old routes obsolete */
  for (uint i = 0; i < pos; i++)
    if (updates[i].new.attrs)
      updates[i].old->flags |= REF_OBSOLETE;

  /* Wait for readers */
  synchronize_rcu();

  /* And now we go backwards to keep the list properly linked */
  struct rte_storage *next = NULL;
  for (int i = pos - 1; i >= 0; i--)
  {
    struct rte_storage *this;
    if (updates[i].new.attrs)
    {
      rte *new = &updates[i].new;
      new->lastmod = current_time();
      new->id = hmap_first_zero(&tab->id_map);
      hmap_set(&tab->id_map, new->id);
      this = updates[i].new_stored = rte_store(new, ni, tab);
    }
    else
      this = updates[i].old;

    atomic_store_explicit(&this->next, next, memory_order_release);
    next = this;
  }

  /* Add behind the sentinel */
  atomic_store_explicit(&local_sentinel.next, next, memory_order_release);

  /* Call the pre-comparison hooks */
  for (uint i = 0; i < pos; i++)
    if (updates[i].new_stored)
      {
	/* Not really an efficient way to compute this */
	if (updates[i].old->rte.src->owner->rte_recalculate)
	  updates[i].old->rte.src->owner->rte_recalculate(tab, n, updates[i].new_stored, updates[i].old, old_best);
      }

  /* Find the new best route */
  uint best_pos = 0;
  struct rte_storage *new_best = updates[0].new_stored ?: updates[0].old;

  for (uint i = 1; i < pos; i++)
  {
    struct rte_storage *s = updates[i].new_stored ?: updates[i].old;
    if (rte_better(&s->rte, &new_best->rte))
    {
      best_pos = i;
      new_best = s;
    }
  }

  /* Relink the new best route to the first position */
  struct rte_storage * _Atomic *best_prev;
  if (best_pos)
    best_prev = &(updates[best_pos-1].new_stored ?: updates[best_pos-1].old)->next;
  else
    best_prev = &local_sentinel.next;

  /* Unlink from the original place */
  atomic_store_explicit(best_prev,
      atomic_load_explicit(&new_best->next, memory_order_relaxed),
      memory_order_release);

  /* Link out */
  atomic_store_explicit(&new_best->next,
      atomic_load_explicit(&local_sentinel.next, memory_order_relaxed),
      memory_order_release);

  /* Now we have to announce the routes the right way, to not cause any
   * strange problems with consistency. */

  ASSERT_DIE(updates[0].old == old_best);

  /* Find new best route original position */
  uint nbpos = ~0;
  for (uint i=0; i<count; i++)
    if ((updates[i].new_stored == new_best) || (updates[i].old == new_best))
    {
      nbpos = i;
      break;
    }
  ASSERT_DIE(~nbpos);

  struct rt_pending_export *best_rpe =
    (new_best != old_best) ?
    rte_announce_to(&tab->export_best, &n->best, &new_best->rte, &old_best->rte)
    : NULL;

  uint total = 0;
  u64 last_seq = 0;

  /* Announce the changes */
  for (uint i=0; i<count; i++)
  {
    /* Not changed at all */
    if (!updates[i].new_stored)
      continue;

    struct rt_pending_export *this_rpe =
      rte_announce_to(&tab->export_all, &n->all,
	  &updates[i].new_stored->rte, &updates[i].old->rte);

    ASSERT_DIE(this_rpe);
    bool nb = (new_best->rte.src == updates[i].new.src), ob = (i == 0);
    char info[96];
    char best_indicator[2][2] = { { ' ', '+' }, { '-', '=' } };
    bsnprintf(info, sizeof info, "autoupdated [%cbest]", best_indicator[ob][nb]);

    rt_rte_trace_in(D_ROUTES, updates[i].new.sender->req, &updates[i].new, info);

    /* Double announcement of this specific route */
    if (ob && best_rpe)
    {
      ASSERT_DIE(best_rpe->it.old == &updates[i].old->rte);
      ASSERT_DIE(!best_rpe->seq_all);
      best_rpe->seq_all = this_rpe->it.seq;
    }
    else
      last_seq = this_rpe->it.seq;

    total++;
  }

  if (best_rpe && !best_rpe->seq_all)
  {
    ASSERT_DIE(!updates[0].new_stored);
    best_rpe->seq_all = last_seq;
  }

  /* Now we can finally release the changes back into the table */
  atomic_store_explicit(&n->routes, new_best, memory_order_release);

  return;
}

static void
rt_nhu_uncork(callback *cb)
{
  RT_LOCKED(SKIP_BACK(rtable, priv.nhu_uncork.cb, cb), tab)
  {
    ASSERT_DIE(tab->nhu_corked);
    ASSERT_DIE(tab->nhu_state == 0);

    /* Reset the state */
    tab->nhu_state = tab->nhu_corked;
    tab->nhu_corked = 0;
    rt_trace(tab, D_STATES, "Next hop updater uncorked");

    ev_send_loop(tab->loop, tab->nhu_event);
    rt_unlock_table(tab);
  }
}

static void
rt_next_hop_update(void *_tab)
{
  RT_LOCK((rtable *) _tab, tab);

  ASSERT_DIE(birdloop_inside(tab->loop));

  if (tab->nhu_corked)
    return;

  if (!tab->nhu_state)
    return;

  /* Check corkedness */
  if (rt_cork_check(&tab->nhu_uncork))
  {
    rt_trace(tab, D_STATES, "Next hop updater corked");
    rt_lock_table(tab);

    if (tab->nhu_state & NHU_RUNNING)
    {
      lfjour_announce_now(&tab->export_best.journal);
      lfjour_announce_now(&tab->export_all.journal);
    }

    tab->nhu_corked = tab->nhu_state;
    tab->nhu_state = 0;
    return;
  }

  /* Initialize a new run */
  if (tab->nhu_state == NHU_SCHEDULED)
  {
    tab->nhu_index = 0;
    tab->nhu_state = NHU_RUNNING;

    if (tab->flowspec_trie)
      rt_flowspec_reset_trie(tab);
  }

  /* Walk the fib one net after another */
  u32 bs = atomic_load_explicit(&tab->routes_block_size, memory_order_relaxed);
  net *routes = atomic_load_explicit(&tab->routes, memory_order_relaxed);
  for (; tab->nhu_index < bs; tab->nhu_index++)
    {
      net *n = &routes[tab->nhu_index];
      struct rte_storage *s = NET_BEST_ROUTE(tab, n);
      if (!s)
	continue;

      MAYBE_DEFER_TASK(birdloop_event_list(tab->loop), tab->nhu_event,
	  "next hop updater in %s", tab->name);

      TMP_SAVED
	rt_next_hop_update_net(tab, RTE_GET_NETINDEX(&s->rte), n);
    }

  /* Finished NHU, cleanup */
  rt_trace(tab, D_EVENTS, "NHU done, scheduling export timer");

  /* State change:
   *   NHU_DIRTY   -> NHU_SCHEDULED
   *   NHU_RUNNING -> NHU_CLEAN
   */
  if ((tab->nhu_state &= NHU_SCHEDULED) == NHU_SCHEDULED)
    ev_send_loop(tab->loop, tab->nhu_event);
}

void
rt_new_default_table(struct symbol *s)
{
  for (uint addr_type = 0; addr_type < NET_MAX; addr_type++)
    if (s == new_config->def_tables[addr_type])
    {
      ASSERT_DIE(!s->table);
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
rt_new_aux_table(struct rtable_config *c, uint addr_type)
{
  uint sza = strlen(c->name), szb = strlen("!aux");
  char *auxname = alloca(sza + szb + 2);
  memcpy(auxname, c->name, sza);
  memcpy(auxname + sza, "!aux", szb);
  auxname[sza+szb] = 0;

  struct symbol *saux = cf_get_symbol(new_config, auxname);
  return rt_new_table(saux, addr_type);
}

struct rtable_config *
rt_new_table(struct symbol *s, uint addr_type)
{
  if (s->table)
    cf_error("Duplicate configuration of table %s", s->name);

  struct rtable_config *c = cfg_allocz(sizeof(struct rtable_config));

  if (s == new_config->def_tables[addr_type])
    s->table = c;
  else
    cf_define_symbol(new_config, s, SYM_TABLE, table, c);

  c->name = s->name;
  c->addr_type = addr_type;
  c->gc_threshold = 1000;
  c->gc_period = (uint) -1;	/* set in rt_postconfig() */
  c->cork_threshold.low = 32768;
  c->cork_threshold.high = 98304;
  c->export_settle = (struct settle_config) {
    .min = 1 MS,
    .max = 100 MS,
  };
  c->export_rr_settle = (struct settle_config) {
    .min = 100 MS,
    .max = 3 S,
  };
  c->digest_settle = (struct settle_config) {
    .min = 1 S,
    .max = 20 S,
  };
  c->debug = new_config->table_default_debug;

  add_tail(&new_config->tables, &c->n);

  /* First table of each type is kept as default */
  if (! new_config->def_tables[addr_type])
    new_config->def_tables[addr_type] = s;

  /* Custom options per addr_type */
  switch (addr_type) {
    case NET_ROA4:
      c->roa_aux_table = rt_new_aux_table(c, NET_IP4);
      c->roa_aux_table->trie_used = 1;
      c->roa_aux_table->master = (struct rt_stream_config) {
	.src = c,
	.setup = rt_setup_roa_aggregator,
	.stop = rt_stop_roa_aggregator,
      };
      break;

    case NET_ROA6:
      c->roa_aux_table = rt_new_aux_table(c, NET_IP6);
      c->roa_aux_table->trie_used = 1;
      c->roa_aux_table->master = (struct rt_stream_config) {
	.src = c,
	.setup = rt_setup_roa_aggregator,
	.stop = rt_stop_roa_aggregator,
      };
      break;
  }

  thread_group_finalize_config();
  c->thread_group = new_config->default_thread_group;

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
  if (!--r->use_count && OBSREF_GET(r->deleted))
    /* Stop the service thread to finish this up */
    ev_send_loop(r->loop, ev_new_init(r->rp, rt_shutdown, r));
}

static void
rt_shutdown_finished(void *tab_)
{
  rtable *t = tab_;
  RT_LOCK(t, tab);
  birdloop_stop_self(t->loop, rt_delete, t);
}

static void
rt_shutdown(void *tab_)
{
  rtable *t = tab_;
  RT_LOCK(t, tab);
  ASSERT_DIE(birdloop_inside(tab->loop));

  /* Check that the table is indeed pruned */
  tab->prune_state = 0;
  ASSERT_DIE(EMPTY_LIST(tab->imports));
  u32 bs = atomic_load_explicit(&tab->routes_block_size, memory_order_relaxed);
  net *routes = atomic_load_explicit(&tab->routes, memory_order_relaxed);
  for (u32 i = 0; i < bs; i++)
    ASSERT_DIE(atomic_load_explicit(&routes[i].routes, memory_order_relaxed) == NULL);

  if (tab->export_digest)
  {
    rtex_export_unsubscribe(&tab->export_digest->req);
    ASSERT_DIE(EMPTY_TLIST(lfjour_recipient, &tab->export_digest->digest.recipients));
    ev_postpone(&tab->export_digest->event);
    settle_cancel(&tab->export_digest->settle);
  }

  rtex_export_unsubscribe(&tab->best_req);
  if (tab->hostcache)
    rtex_export_unsubscribe(&tab->hostcache->req);

  rt_exporter_shutdown(&tab->export_best, NULL);
  rt_exporter_shutdown(&tab->export_all, NULL);

  rfree(tab->hcu_event);
  tab->hcu_event = NULL;
  rfree(tab->nhu_event);
  tab->nhu_event = NULL;

  netindex_hash_delete(tab->netindex,
      ev_new_init(tab->rp, rt_shutdown_finished, tab),
      birdloop_event_list(tab->loop));
}

static void
rt_delete(void *tab_)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  /* Pull out the last references; TODO: make this generic */
  rtable *tab = tab_;
  DOMAIN(rtable) dom = tab->lock;

  /* We assume that nobody holds the table reference now as use_count is zero.
   * Anyway the last holder may still hold the lock because of the kernel scheduler.
   * Therefore we lock and unlock it the last time to be sure that nobody is there.
   * Also it's semantically more valid to lock when accessing otherwise private things.
   * */
  RT_LOCKED(tab, tp)
    OBSREF_CLEAR(tp->deleted);

  /* Everything is freed by freeing the loop */
  birdloop_free(tab->loop);

  /* Also drop the domain */
  DOMAIN_FREE(rtable, dom);
}


static void
rt_check_cork_low(struct rtable_private *tab)
{
  if (!tab->cork_active)
    return;

  if (OBSREF_GET(tab->deleted) ||
      (lfjour_pending_items(&tab->export_best.journal) < tab->cork_threshold.low)
   && (lfjour_pending_items(&tab->export_all.journal) < tab->cork_threshold.low))
  {
    tab->cork_active = 0;
    rt_cork_release();

    rt_trace(tab, D_STATES, "Uncorked");
  }
}

static void
rt_check_cork_high(struct rtable_private *tab)
{
  if (!OBSREF_GET(tab->deleted) && !tab->cork_active && (
	(lfjour_pending_items(&tab->export_best.journal) >= tab->cork_threshold.low)
     || (lfjour_pending_items(&tab->export_all.journal) >= tab->cork_threshold.low)))
  {
    tab->cork_active = 1;
    rt_cork_acquire();
    lfjour_schedule_cleanup(&tab->export_best.journal);
    lfjour_schedule_cleanup(&tab->export_all.journal);
//    rt_export_used(&tab->exporter, tab->name, "corked");

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

  ASSERT_DIE(new->master.setup == old->master.setup);
  ASSERT_DIE(new->master.stop == old->master.stop);

  DBG("\t%s: same\n", new->name);
  new->table = RT_PUB(tab);
  tab->name = new->name;
  tab->config = new;
  tab->debug = new->debug;
  tab->export_all.trace_routes = tab->export_best.trace_routes = new->debug;
  tab->best_req.trace_routes = new->debug;
  if (tab->export_digest)
    tab->export_digest->req.trace_routes = new->debug;

  if (tab->hostcache)
    tab->hostcache->req.trace_routes = new->debug;

  WALK_TLIST(rt_flowspec_link, ln, &tab->flowspec_links)
    ln->req.trace_routes = new->debug;

  tab->cork_threshold = new->cork_threshold;

  if (new->cork_threshold.high != old->cork_threshold.high)
    rt_check_cork_high(tab);

  if (new->cork_threshold.low != old->cork_threshold.low)
    rt_check_cork_low(tab);

  if (tab->export_digest && (
	(new->digest_settle.min != tab->export_digest->settle.cf.min)
    ||  (new->digest_settle.max != tab->export_digest->settle.cf.max)))
    tab->export_digest->settle.cf = new->digest_settle;

  rt_lock_table(tab); /* Unlocked in rt_reconf_finished() */
  struct rt_reconf_finished_deferred_call rrfdc = {
    .dc.hook = rt_reconf_finished,
    .tab = RT_PUB(tab),
  };

  tab->reconf_end = defer_call(&rrfdc.dc, sizeof rrfdc);

  birdloop_transfer(tab->loop, old->thread_group->group, new->thread_group->group);

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
	bool ok;
	{
	  BIRDLOOP_ENTER(o->table->loop);
	  RT_LOCKED(o->table, tab)
	  {
	    r = OBSREF_GET(tab->deleted) ? NULL : rt_find_table_config(new, o->name);
	    ok = r && !new->shutdown && rt_reconfigure(tab, r, o);
	  }
	}

	if (ok)
	  continue;

	BIRDLOOP_ENTER(o->table->loop);
	RT_LOCKED(o->table, tab)
	{
	  DBG("\t%s: deleted\n", o->name);
	  OBSREF_SET(tab->deleted, old);
	  rt_check_cork_low(tab);
	  rt_lock_table(tab);

	  /* No actual table stopping before reconfiguring the rest.
	   * Table unlocked in the deferred call. */
	  struct rt_reconf_finished_deferred_call rrfdc = {
	    .dc.hook = rt_reconf_finished,
	    .tab = RT_PUB(tab),
	  };

	  tab->reconf_end = defer_call(&rrfdc.dc, sizeof rrfdc);
	}

	CALL(o->table->config->master.stop, o->table);
      }
    }

  WALK_LIST(r, new->tables)
    if (!r->table)
      {
	r->table = rt_setup(rt_table_pool, r);
	DBG("\t%s: created\n", r->name);
	add_tail(&routing_tables, &r->table->n);
      }

  if (!new->table_events_log_name)
    rt_log_close();
  else if (
      !old || !old->table_events_log_name ||
      new->table_events_log_size != old->table_events_log_size ||
      strcmp(new->table_events_log_name, old->table_events_log_name)
      )
    rt_log_open(new->table_events_log_name, new->table_events_log_size);

  DBG("\tdone\n");
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
hc_new_hostentry(struct rtable_private *tab, ip_addr a, ip_addr ll, rtable *dep, unsigned k)
{
  struct hostcache *hc = tab->hostcache;
  pool *p = tab->rp;
  struct hostentry *he = sl_alloc(hc->slab);

  *he = (struct hostentry) {
    .addr = a,
    .link = ll,
    .tab = dep,
    .owner = RT_PUB(tab),
    .hash_key = k,
  };

  if (EMPTY_LIST(hc->hostentries))
    rt_lock_table(tab);

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
  ea_free(atomic_load_explicit(&he->src, memory_order_relaxed));

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
hc_notify_export(void *_hc)
{
  struct hostcache *hc = _hc;

  RT_EXPORT_WALK(&hc->req, u)
  {
    const net_addr *n = NULL;
    switch (u->kind)
    {
      case RT_EXPORT_STOP:
	bug("Main table export stopped");
	break;

      case RT_EXPORT_FEED:
	if (u->feed->count_routes)
	  n = u->feed->block[0].net;
	break;

      case RT_EXPORT_UPDATE:
	{
	  /* Conflate following updates */
	  const rte *old = RTE_VALID_OR_NULL(u->update->old);
	  const rte *new = u->update->new;
	  for (
	      SKIP_BACK_DECLARE(struct rt_pending_export, rpe, it, u->update);
	      rpe = atomic_load_explicit(&rpe->next, memory_order_acquire) ;)
	  {
	    ASSERT_DIE(new == rpe->it.old);
	    new = rpe->it.new;
	    rt_export_processed(&hc->req, rpe->it.seq);
	  }

	  /* Ignore idempotent */
	  if ((old == new) || old && new && rte_same(old, new))
	    continue;

	  n = (new ?: old)->net;
	}
	break;
    }

    if (!n)
      continue;

    RT_LOCK(hc->tab, tab);
    if (ev_active(tab->hcu_event))
      continue;

    if (!trie_match_net(hc->trie, n))
    {
      /* No interest in this update, mark seen only */
      if (hc->req.trace_routes & D_ROUTES)
	log(L_TRACE "%s < boring %N (%u)",
	    hc->req.name, n, NET_TO_INDEX(n)->index);
    }
    else
    {
      if (hc->req.trace_routes & D_ROUTES)
	log(L_TRACE "%s < checking %N (%u)",
	    hc->req.name, n, NET_TO_INDEX(n)->index);

      if ((rt_export_get_state(&hc->req) == TES_READY)
	  && !ev_active(tab->hcu_event))
      {
	if (hc->req.trace_routes & D_EVENTS)
	  log(L_TRACE "%s requesting HCU", hc->req.name);

	ev_send_loop(tab->loop, tab->hcu_event);
      }
    }

    MAYBE_DEFER_TASK(hc->req.r.target, hc->req.r.event,
	"hostcache updater in %s", tab->name);
  }
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

  hc->tab = RT_PUB(tab);

  tab->hcu_event = ev_new_init(tab->rp, rt_update_hostcache, tab);
  callback_init(&tab->hcu_uncork.cb, rt_hcu_uncork, tab->loop);
  tab->hostcache = hc;

  ev_send_loop(tab->loop, tab->hcu_event);
}

static void
rt_free_hostcache(struct rtable_private *tab)
{
  struct hostcache *hc = tab->hostcache;

  node *n;
  WALK_LIST(n, hc->hostentries)
    bug("Hostcache is not empty in table %s", tab->name);

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
  int direct = 0;
  int pxlen = 0;

  /* Signalize work in progress */
  ASSERT_DIE((atomic_fetch_add_explicit(&he->version, 1, memory_order_acq_rel) & 1) == 0);

  /* Reset the hostentry */
  ea_list *old_src = atomic_exchange_explicit(&he->src, NULL, memory_order_acq_rel);
  ea_list *new_src = NULL;
  he->nexthop_linkable = 0;
  he->igp_metric = 0;

  RT_READ_LOCKED(tab, tr);
  net_addr he_addr;
  net_fill_ip_host(&he_addr, he->addr);
  net *n = net_route(tr, &he_addr);
  /*
  log(L_DEBUG "rt_update_hostentry(%s %p) got net_route(%N) = %p",
      tab->name, he, &he_addr, n);
      */
  if (n)
    {
      struct rte_storage *e = NET_BEST_ROUTE(tab, n);
      ea_list *a = e->rte.attrs;
      u32 pref = rt_get_preference(&e->rte);

      NET_WALK_ROUTES(tab, n, ep, ee)
	if (rte_is_valid(&ee->rte) &&
	    (rt_get_preference(&ee->rte) >= pref) &&
	    ea_find(ee->rte.attrs, &ea_gen_hostentry))
	{
	  /* Recursive route should not depend on another recursive route */
	  log(L_WARN "Next hop address %I resolvable through recursive route for %N",
	      he->addr, ee->rte.net);
	  goto done;
	}

      pxlen = e->rte.net->pxlen;

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

      new_src = ea_ref(a);
      he->nexthop_linkable = !direct;
      he->igp_metric = rt_get_igp_metric(&e->rte);

      if ((old_src != new_src) && (tab->debug & D_ROUTES))
	if (ipa_zero(he->link) || ipa_equal(he->link, he->addr))
	  log(L_TRACE "%s: Hostentry %p for %I in %s resolved via %N (%uG)",
	      tab->name, he, he->addr, he->tab->name, e->rte.net, e->rte.src->global_id);
	else
	  log(L_TRACE "%s: Hostentry %p for %I %I in %s resolved via %N (%uG)",
	      tab->name, he, he->addr, he->link, he->tab->name, e->rte.net, e->rte.src->global_id);
    }
  else if (old_src && (tab->debug & D_ROUTES))
    if (ipa_zero(he->link) || ipa_equal(he->link, he->addr))
      log(L_TRACE "%s: Hostentry %p for %I in %s not resolved",
	  tab->name, he, he->addr, he->tab->name);
    else
      log(L_TRACE "%s: Hostentry %p for %I %I in %s not resolved",
	  tab->name, he, he->addr, he->link, he->tab->name);

done:
  /* Signalize work done and wait for readers */
  ASSERT_DIE(atomic_exchange_explicit(&he->src, new_src, memory_order_acq_rel) == NULL);
  ASSERT_DIE((atomic_fetch_add_explicit(&he->version, 1, memory_order_acq_rel) & 1) == 1);
  synchronize_rcu();

  /* Add a prefix range to the trie */
  trie_add_prefix(tab->hostcache->trie, &he_addr, pxlen, he_addr.pxlen);

  ea_free(old_src);
  return old_src != new_src;
}

static void
rt_hcu_uncork(callback *cb)
{
  RT_LOCK(SKIP_BACK(rtable, priv.hcu_uncork.cb, cb), tab);

  ev_send_loop(tab->loop, tab->hcu_event);
}

static void
rt_update_hostcache(void *data)
{
  rtable **nhu_pending;

  RT_LOCKED((rtable *) data, tab)
  {
  struct hostcache *hc = tab->hostcache;

  /* Finish initialization */
  if (!hc->req.name)
  {
    hc->req = (struct rt_export_request) {
      .name = mb_sprintf(tab->rp, "%s.hcu.notifier", tab->name),
      .r = {
	.event = &hc->source_event,
	.target = birdloop_event_list(tab->loop),
      },
      .pool = birdloop_pool(tab->loop),
      .trace_routes = tab->config->debug,
      .dump = hc_notify_dump_req,
    };
    hc->source_event = (event) {
      .hook = hc_notify_export,
      .data = hc,
    };

    rtex_export_subscribe(&tab->export_best, &hc->req);
  }

  /* Shutdown shortcut */
  if (rt_export_get_state(&hc->req) == TES_DOWN)
    return;

  if (rt_cork_check(&tab->hcu_uncork))
  {
    rt_trace(tab, D_STATES, "Hostcache update corked");
    return;
  }

  /* Destination schedule map */
  nhu_pending = tmp_allocz(sizeof(rtable *) * rtable_max_id);

  struct hostentry *he;
  node *n, *x;

  /* Reset the trie */
  lp_flush(hc->lp);
  hc->trie = f_new_trie(hc->lp, 0);

  uint finished = 0, updated = 0, kept = 0;

  WALK_LIST_DELSAFE(n, x, hc->hostentries)
    {
      he = SKIP_BACK(struct hostentry, ln, n);
      if (lfuc_finished(&he->uc))
      {
	hc_delete_hostentry(hc, tab->rp, he);
	finished++;
      }
      else if (rt_update_hostentry(tab, he))
      {
	nhu_pending[he->tab->id] = he->tab;
	updated++;
      }
      else
	kept++;
    }

  if (finished && !updated && !kept)
    rt_unlock_table(tab);

  } /* End of RT_LOCKED() */

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
      break;

  if (he)
  {
    if (tab->debug & D_ROUTES)
      if (ipa_zero(ll))
	log(L_TRACE "%s: Found existing hostentry %p for %I in %s",
	    tab->name, he, a, he->tab->name);
      else
	log(L_TRACE "%s: Found existing hostentry %p for %I %I in %s",
	    tab->name, he, a, ll, he->tab->name);
  }
  else
  {
    he = hc_new_hostentry(tab, a, link, dep, k);
    rt_update_hostentry(tab, he);
  }

  /* Keep the hostentry alive until this task ends */
  lfuc_lock_revive(&he->uc);
  lfuc_unlock(&he->uc, birdloop_event_list(tab->loop), tab->hcu_event);

  return he;
}

rte *
krt_export_net(struct channel *c, const net_addr *a, linpool *lp)
{
  if (c->ra_mode == RA_MERGED)
  {
    struct rt_export_feed *feed = rt_net_feed(c->table, a, NULL);
    if (!feed || !feed->count_routes)
      return NULL;

    if (!bmap_test(&c->export_accepted_map, feed->block[0].id))
      return NULL;

    return rt_export_merged(c, feed, lp, 1);
  }

  static _Thread_local rte best;
  best = rt_net_best(c->table, a);

  if (!best.attrs)
    return NULL;

  if (c->out_filter == FILTER_REJECT)
    return NULL;

  /* We could run krt_preexport() here, but it is already handled by krt_is_installed() */

  if (c->out_filter == FILTER_ACCEPT)
    return &best;

  if (f_run(c->out_filter, &best, FF_SILENT) > F_ACCEPT)
    return NULL;

  return &best;
}
