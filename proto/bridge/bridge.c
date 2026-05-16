/*
 *	BIRD -- Linux Bridge Interface
 *
 *	(c) 2023--2026 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2023--2026 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Bridge
 *
 * The Bridge protocol is responsible for synchronization of BIRD ethernet
 * table with Linux kernel bridge interface (although the code is mostly
 * OS-independent, as Linux-specific parts are in the Netlink code). It is
 * similar to (and based on) the Kernel protocol, but the differences are
 * large enough to treat it as an independent protocol.
 */

/*
 * TODO:
 * - Wait for existence (and active state) of the bridge device
 * - Channel should be R_ANY for BUM routes, but RA_OPTIMAL for others
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/mpls.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/data.h"
#include "lib/string.h"
#include "sysdep/unix/krt.h"

#include "bridge.h"

static struct kbr_vlan * kbr_find_vlan(struct kbr_proto *p, uint ifi, uint vid);
static void kbr_prune_vlans0(struct kbr_proto *p);
static void kbr_prune_vlans1(struct kbr_proto *p);

static struct rte_owner_class kbr_rte_owner_class;

/*
 *	Bridge entries
 */

static void
kbr_trace(struct kbr_proto *p, const net_addr *n, const rte *e, char *msg, bool tunnel)
{
  if (p->p.debug & D_PACKETS)
  {
    struct nexthop_adata *nhad = rte_get_nexthops(e);
    struct nexthop *nh = &nhad->nh;

    if (!nhad)
      log(L_TRACE "%s: %N (invalid nexthop)");
    else if (!NEXTHOP_IS_REACHABLE(nhad))
      log(L_TRACE "%s: %N %s", rta_dest_name(nhad->dest));
    else if (!tunnel || ipa_zero(nh->gw))
      log(L_TRACE "%s: %N dev %s: %s",
	  p->p.name, n, nh->iface->name, msg);
    else
      log(L_TRACE "%s: %N dev %s dst %I vni %u: %s",
	  p->p.name, n, nh->iface->name, nh->gw, (uint) nh->label[0], msg);
  }
}

static inline void
kbr_trace_in(struct kbr_proto *p, const net_addr *n, const rte *e, char *msg)
{
  if (!e)
    return;

  kbr_trace(p, n, e, msg, true);
}

static void
kbr_trace_out(struct kbr_proto *p, const net_addr *n, const rte *new, const rte *old, bool tunnel)
{
  if (new)
    kbr_trace(p, n, new, (old ? "updating" : "installing"), tunnel);
  else if (old)
    kbr_trace(p, n, old, "deleting", tunnel);
}

static bool
kbr_match_fdb(const rte *x, const rte *y)
{
  const struct nexthop_adata *nhad = rte_get_nexthops(x);
  if (!nhad || !NEXTHOP_IS_REACHABLE(nhad))
    return false;

  const struct nexthop_adata *ynhad = rte_get_nexthops(y);
  ASSUME(ynhad && NEXTHOP_IS_REACHABLE(ynhad));

  const struct nexthop *xn = &nhad->nh, *yn = &ynhad->nh;
  return (xn->iface == yn->iface) && ipa_equal(xn->gw, yn->gw);
}



int
kbr_alt_export(const struct rt_prefilter *rpf UNUSED, const net_addr *n)
{
  return mac_zero(net_mac_addr(n));
}

/* Find matching route in the BIRD table */
static struct rte *
kbr_find_fdb(struct kbr_proto *p UNUSED, struct channel *c, const net_addr *n, const rte *ref)
{
  /* For BUM routes, find matching entry */
  if (mac_zero(net_mac_addr(n)))
  {
    struct rt_export_feed *feed = rt_net_feed(c->table, n, NULL);
    if (!feed)
      return NULL;

    for (uint i = 0; i < feed->count_routes; i++)
      if (feed->block[i].flags & REF_OBSOLETE)
	return NULL;
      else if (rte_is_valid(&feed->block[i]) && kbr_match_fdb(&feed->block[i], ref))
	return &feed->block[i];

    return NULL;
  }
  else
  {
    static _Thread_local rte best;
    best = rt_net_best(c->table, n);
    return best.attrs && rte_is_valid(&best) ? &best : NULL;
  }
}

/* Export BIRD route through filters */
static struct rte *
kbr_export_fdb(struct kbr_proto *p UNUSED, struct channel *c, rte *rt)
{
  /* Route should be already exported */
  if (!bmap_test(&c->export_accepted_map, rt->id))
    return NULL;

  /* We could run krt_preexport() here, but it is already handled by export_map */
  const struct filter *filter = c->out_filter;

  if (filter == FILTER_REJECT)
    return NULL;

  if (filter == FILTER_ACCEPT)
    return rt;

  if (f_run(filter, rt, FF_SILENT) > F_ACCEPT)
    return NULL;

  return rt;
}


/*
 * bird async -> ignore
 * bird scan -> review
 * non-bird bridge -> import
 * non-bird tunnel -> ignore
 */

/* Compare if two routes have the same destination */
static bool
kbr_same_dest(const rte *x, const rte *y, bool tunnel)
{
  const struct nexthop_adata *xnhad = rte_get_nexthops(x);
  const struct nexthop_adata *ynhad = rte_get_nexthops(y);

  bool xr = NEXTHOP_IS_REACHABLE(xnhad);
  bool yr = NEXTHOP_IS_REACHABLE(ynhad);

  if (!xr && !yr)
    return (xnhad->dest == ynhad->dest);

  if (xr != yr)
    return false;

  if (tunnel)
    return nexthop_same(xnhad, ynhad);
  else
    /* Bridge fdb entries only contain ifaces */
    return xnhad->nh.iface == ynhad->nh.iface;
}

/* Process FDB entry received from the kernel */
void
kbr_got_fdb(struct kbr_proto *p, const net_addr *n, rte *e, const struct nexthop_adata *nhad, int src, bool scan, bool tunnel)
{
  struct channel *c = p->p.main_channel;

  /* Non-BIRD routes are just imported, both scan and async */
  if (src != KBR_SRC_BIRD)
  {
    /* Import of tunnel FDBs is not supported */
    if (tunnel)
      return;

    if (e) ea_set_attr_u32(&e->attrs, &ea_gen_preference, 0, c->preference);
    rte_update(c, n, e, p->p.main_source);
    return;
  }

  /* BIRD routes are silently ignored in async, that is just echo */
  if (!scan)
    return;

  /* BIRD routes received during scan */
  /* We wait for the initial feed to have correct export state */
  if (!p->ready)
    goto ignore;

  rte *rt0 = kbr_find_fdb(p, c, n, e);

  /* No matching route in BIRD table */
  if (!rt0)
    goto delete;

  rte *new = kbr_export_fdb(p, c, rt0);

  /* Rejected by filters */
  if (!new)
    goto delete;

  /*
   * One BIRD route can represent two kernel FDB entries, bridge entry and tunnel
   * entry (distinguished by tunnel arg). See kbr_rt_notify() for details.
   *
   * In short:
   * MAC is non-zero <-> there should be bridge entry
   * gateway is non-zero <-> there should be tunnel entry
   * (We only check <- direction here)
   */

  if (!tunnel && mac_zero(net_mac_addr(n)))
    goto delete;

  if (tunnel && ipa_zero(nhad->nh.gw))
    goto delete;

  /* Route to this destination was already seen. Strange, but it happens... */
  if (bmap_test(&p->seen_map[tunnel], new->id))
    goto aseen;

  /* Mark route as seen */
  bmap_set(&p->seen_map[tunnel], new->id);

  /* TODO: There also may be changes in route eattrs, we ignore that for now */
  if (!bmap_test(&p->sync_map[tunnel], new->id) || !kbr_same_dest(e, new, tunnel))
    goto update;

  goto seen;

seen:
  kbr_trace_in(p, n, e, "seen");
  return;

aseen:
  kbr_trace_in(p, n, e, "already seen");
  return;

ignore:
  kbr_trace_in(p, n, e, "ignored");
  return;

update:
  kbr_trace_in(p, n, new, "updating");
  if (mac_zero(net_mac_addr(n)))
    kbr_update_fdb(p, n, new, e, tunnel);
  else
    kbr_replace_fdb(p, n, new, e, tunnel);
  return;

delete:
  kbr_trace_in(p, n, e, "deleting");
  if (mac_zero(net_mac_addr(n)))
    kbr_update_fdb(p, n, NULL, e, tunnel);
  else
    kbr_replace_fdb(p, n, NULL, e, tunnel);
  return;
}

/* Install missing FDB entries during pruning phase */
static void
kbr_prune_fdb(struct kbr_proto *p, struct channel *c, const net_addr *n, rte *e)
{
  rte *new = kbr_export_fdb(p, c, e);

  if (!new)
    return;

  if (!mac_zero(net_mac_addr(n)) &&
      !bmap_test(&p->seen_map[0], new->id))
  {
    kbr_trace(p, n, new, "installing", false);
    kbr_replace_fdb(p, n, new, NULL, false);
  }

  struct nexthop_adata *nhad = rte_get_nexthops(e);

  if (ipa_nonzero(nhad->nh.gw) &&
      !bmap_test(&p->seen_map[1], new->id))
  {
    kbr_trace(p, n, new, "installing", true);
    if (mac_zero(net_mac_addr(n)))
      kbr_update_fdb(p, n, new, NULL, true);
    else
      kbr_replace_fdb(p, n, new, NULL, true);
  }
}

static void
kbr_prune_fdbs(struct kbr_proto *p)
{
  struct channel *c = p->p.main_channel;

  /* Should not happen */
  if (!p->ready)
    return;

  TRACE(D_EVENTS, "Prunning bridge table");

  struct rt_export_feeder fx = {
    .name = "bridge.pruner",
    .trace_routes = c->debug,
  };

  /* Synchronous prune of the full table */
  rt_feeder_subscribe(&c->table->export_all, &fx);

  RT_FEED_WALK(&fx, f)
    TMP_SAVED
      if (mac_zero(net_mac_addr(f->ni->addr)))
      {
	/* For BUM routes, handle all tunnel entries */
	for (uint i = 0; i < f->count_routes; i++)
	  if (f->block[i].flags & REF_OBSOLETE)
	    break;
	  else if (rte_is_valid(&f->block[i]))
	    kbr_prune_fdb(p, c, f->ni->addr, &f->block[i]);
      }
      else
      {
	/* For regular routes, handle only the best route */
	if (f->count_routes && rte_is_valid(&f->block[0]))
	  kbr_prune_fdb(p, c, f->ni->addr, &f->block[0]);
      }

  rt_feeder_unsubscribe(&fx);
}

static void
kbr_scan(timer *t)
{
  struct kbr_proto *p = t->data;
  struct channel *c = p->p.main_channel;

  TRACE(D_EVENTS, "Scanning bridge table");

  bmap_reset(&p->seen_map[0], 1024);
  bmap_reset(&p->seen_map[1], 1024);

  if (p->vlan_filtering)
  {
    kbr_do_vlan_scan(p);
    kbr_prune_vlans0(p);
  }

  rt_refresh_begin(&c->in_req);
  kbr_do_fdb_scan(p);
  kbr_prune_fdbs(p);
  rt_refresh_end(&c->in_req);

  if (p->vlan_filtering)
    kbr_prune_vlans1(p);

  if (!p->synced)
    TRACE(D_EVENTS, "Synced");

  p->synced = true;
}

static void
kbr_rt_notify(struct proto *P, struct channel *c UNUSED, const net_addr *n, rte *new, const rte *old)
{
  struct kbr_proto *p = (void *) P;

  /* Before first scan we do not touch the routes */
  if (!p->synced)
    return;

#ifdef CONFIG_EVPN
  /* For managed interfaces we ignore FDB entries when VLAN not active */
  /* For now, we assume EVPN FDB entry <-> direct to managed iface */

  const rte *r = (new ?: old);

  if (p->vlan_filtering && (rt_get_source_attr(r) == RTS_EVPN))
  {
    const struct nexthop_adata *nhad = rte_get_nexthops(r);
    ASSERT_DIE(NEXTHOP_IS_REACHABLE(nhad));
    struct iface *i = nhad->nh.iface;
    struct kbr_vlan *v = kbr_find_vlan(p, i->index, net_vlan_id(n));

    if (!v || !v->active)
    {
      TRACE(D_ROUTES, "%N %s ignored - vlan %u not active on %s",
	    n, (new ? "update" : "withdraw"), net_vlan_id(n), i->name);
      return;
    }
  }
#endif

  /*
   * This code handles peculiarities of Linux bridge behavior, where the bridge
   * device has attached both network interfaces and a tunnel (VXLAN) device.
   * For 'remote' MAC addresses, forwarding entries in the bridge device point
   * to the tunnel device. The tunnel device has another forwarding table with
   * forwarding entries, this time with IP addresses of remote endpoints.
   *
   * BUM frames are propagated by the bridge device to all attached devices, so
   * there is no need to have a bridge forwarding entry, but they must have a
   * tunnel forwarding entry for each destination.
   */

  const struct nexthop_adata *nnhad = new ? rte_get_nexthops(new) : NULL;
  const struct nexthop_adata *onhad = old ? rte_get_nexthops(old) : NULL;

  rte *new_gw = (nnhad && NEXTHOP_IS_REACHABLE(nnhad) && ipa_nonzero(nnhad->nh.gw)) ? new : NULL;
  const rte *old_gw = (onhad && NEXTHOP_IS_REACHABLE(onhad) && ipa_nonzero(onhad->nh.gw)) ? old : NULL;

  /* For regular routes, we have one bridge entry, perhaps also one tunnel entry.
   * For BUM routes, we have multiple tunnel entries, but no bridge entry
   **/
  if (!mac_zero(net_mac_addr(n)))
  {
    kbr_trace_out(p, n, new, old, 0);
    kbr_replace_fdb(p, n, new, old, 0);
  }

  kbr_trace_out(p, n, new_gw, old_gw, 1);
  kbr_replace_fdb(p, n, new_gw, old_gw, 1);
}

static void
kbr_flush_routes(struct kbr_proto *p)
{
  struct channel *c = p->p.main_channel;

  TRACE(D_EVENTS, "Flushing bridge routes");

  struct rt_export_feeder fx = {
    .name = "bridge.flusher",
    .trace_routes = c->debug,
  };

  /* Synchronous flush */
  rt_feeder_subscribe(&c->table->export_all, &fx);

  RT_FEED_WALK(&fx, f)
    TMP_SAVED
      if (mac_zero(net_mac_addr(f->ni->addr)))
      {
	/* For BUM routes, handle all tunnel entries */
	for (uint i = 0; i < f->count_routes; i++)
	  if (f->block[i].flags & REF_OBSOLETE)
	    break;
	  else if (rte_is_valid(&f->block[i]) && bmap_test(&c->export_accepted_map, f->block[i].id))
	    kbr_rt_notify(&p->p, c, f->ni->addr, NULL, &f->block[i]);
      }
      else
      {
	/* For regular routes, handle only the best route */
	if (f->count_routes && rte_is_valid(&f->block[0]) && bmap_test(&c->export_accepted_map, f->block[0].id))
	  kbr_rt_notify(&p->p, c, f->ni->addr, NULL, &f->block[0]);
      }

  rt_feeder_unsubscribe(&fx);
  
}


static int
kbr_preexport(struct channel *C, rte *e)
{
  /* Reject our own routes */
  if (e->src->owner == &C->proto->sources)
    return -1;

  return 0;
}

static int
kbr_reload_routes(struct channel *C, struct rt_feeding_request *rfr)
{
  struct kbr_proto *p = (void *) C->proto;

  if (p->ready)
    tm_start(p->scan_timer, 0);

  if (rfr)
    CALL(rfr->done, rfr);

  return 1;
}

static void
kbr_feed_end(struct channel *C)
{
  struct kbr_proto *p = (void *) C->proto;

  p->ready = true;
  tm_start(p->scan_timer, 0);
}


static inline u32
kbr_metric(const rte *e)
{
  struct eattr *ea = ea_find(e->attrs, &ea_gen_igp_metric) ?: ea_find(e->attrs, &ea_gen_local_metric);
  return ea ? MIN(ea->u.data, IGP_METRIC_UNKNOWN) : 0;
}

static int
kbr_rte_better(const rte *new, const rte *old)
{
  /* This is hack, we should have full BGP-style comparison */
  return kbr_metric(new) < kbr_metric(old);
}


/*
 *	Bridge VLANs
 */

#define VLAN_KEY(v)		v->ifi, v->vid
#define VLAN_NEXT(v)		v->next
#define VLAN_EQ(i1,v1,i2,v2)	i1 == i2 && v1 == v2
#define VLAN_FN(i,v)		hash_value(u32_hash0(v, HASH_PARAM, u32_hash0(i, HASH_PARAM, 0)))

#define VLAN_REHASH		bridge_vlan_rehash
#define VLAN_PARAMS		/8, *2, 2, 2, 4, 16


#define VLAN_VNI_KEY(v)		v->ifi, v->vni
#define VLAN_VNI_NEXT(v)	v->next_vni
#define VLAN_VNI_EQ(i1,v1,i2,v2) i1 == i2 && v1 == v2
#define VLAN_VNI_FN(i,v)	hash_value(u32_hash0(v, HASH_PARAM, u32_hash0(i, HASH_PARAM, 0)))

#define VLAN_VNI_REHASH		bridge_vlan_vni_rehash
#define VLAN_VNI_PARAMS		/8, *2, 2, 2, 4, 16


HASH_DEFINE_REHASH_FN(VLAN, struct kbr_vlan)
HASH_DEFINE_REHASH_FN(VLAN_VNI, struct kbr_vlan)


static struct kbr_vlan *
kbr_find_vlan(struct kbr_proto *p, uint ifi, uint vid)
{
  return HASH_FIND(p->vlan_hash, VLAN, ifi, vid);
}

struct kbr_vlan *
kbr_find_vlan_by_vni(struct kbr_proto *p, uint ifi, uint vni)
{
  if (!p->vlan_vni_hash.data)
    return NULL;

  return HASH_FIND(p->vlan_vni_hash, VLAN_VNI, ifi, vni);
}

static void
kbr_vlan_set_vni(struct kbr_proto *p, struct kbr_vlan *v, uint vni)
{
  if (v->vni_link && (v->vni == vni))
    return;

  struct kbr_vlan *old = HASH_DELETE(p->vlan_vni_hash, VLAN_VNI, v->ifi, v->vni);
  if (old)
    old->vni_link = false;

  if (v->vni_link)
    HASH_REMOVE(p->vlan_vni_hash, VLAN_VNI, v);

  v->vni = vni;
  v->vni_link = true;

  HASH_INSERT2(p->vlan_vni_hash, VLAN_VNI, p->p.pool, v);
}

static void
kbr_vlan_unset_vni(struct kbr_proto *p, struct kbr_vlan *v)
{
  if (v->vni_link)
    HASH_REMOVE(p->vlan_vni_hash, VLAN_VNI, v);

  v->vni = 0;
  v->vni_link = false;
}

static struct kbr_vlan *
kbr_get_vlan(struct kbr_proto *p, uint ifi, uint vid)
{
  struct kbr_vlan *v = kbr_find_vlan(p, ifi, vid);

  if (v)
    return v;

  v = mb_allocz(p->p.pool, sizeof(struct kbr_vlan));

  v->ifi = ifi;
  v->vid = vid;

  HASH_INSERT2(p->vlan_hash, VLAN, p->p.pool, v);

  return v;
}

void
kbr_got_vlan(struct kbr_proto *p, struct iface *i, uint vid, uint flags)
{
  struct kbr_vlan *v = kbr_get_vlan(p, i->index, vid);

  v->flags = flags;
  v->mark_vlan = true;
}

void
kbr_got_vlan_tunnel(struct kbr_proto *p, struct iface *i, uint vid, uint vni, uint flags UNUSED)
{
  struct kbr_vlan *v = kbr_get_vlan(p, i->index, vid);

  v->mark_tunnel = true;
  kbr_vlan_set_vni(p, v, vni);
}

static inline void
kbr_vlan_changed(struct kbr_proto *p)
{
  if (p->ready)
    tm_start(p->scan_timer, 100 MS);
}

static void
kbr_vlan_req_update(struct kbr_proto *p, struct iface *i, uintptr_t owner, uint vid, uint vni)
{
  struct kbr_vlan *v = kbr_get_vlan(p, i->index, vid);

  if ((v->owner == owner) && (v->vni_req == vni))
    return;

  v->vni_req = vni;
  v->owner = owner;
  kbr_vlan_changed(p);

  /* Register the interface as VLAN-managed */
  kbr_get_vlan(p, i->index, 0);
}

static void
kbr_vlan_req_withdraw(struct kbr_proto *p, struct iface *i, uintptr_t owner, uint vid)
{
  struct kbr_vlan *v = kbr_find_vlan(p, i->index, vid);

  if (!v || (v->owner != owner))
    return;

  v->vni_req = 0;
  v->owner = 0;
  kbr_vlan_changed(p);
}

static void
kbr_vlan_req_withdraw_all(struct kbr_proto *p, uintptr_t owner)
{
  bool changed = false;

  HASH_WALK(p->vlan_hash, next, v)
  {
    if (v->owner != owner)
      continue;

    v->vni_req = 0;
    v->owner = 0;
    changed = true;
  }
  HASH_WALK_END;

  if (changed)
    kbr_vlan_changed(p);
}

static void
kbr_vlan_req_notify(ps_subscriber *sub, void *msg, uint len)
{
  ASSERT(len >= sizeof(struct vlan_request));

  struct kbr_proto *p = sub->data;
  struct vlan_request *req = msg;

  TRACE(D_EVENTS, "VLAN %s received for %d VLANs on %s",
	(req->update ? "request" : "withdraw"), (int) req->vlan_count, req->iface->name);

  if (req->update)
  {
    for (int i = 0; i < req->vlan_count; i++)
      kbr_vlan_req_update(p, req->iface, req->owner, req->vlans[i].vid, req->vlans[i].vni);
  }
  else if (req->vlan_count > 0)
  {
    for (int i = 0; i < req->vlan_count; i++)
      kbr_vlan_req_withdraw(p, req->iface, req->owner, req->vlans[i].vid);
  }
  else
    kbr_vlan_req_withdraw_all(p, req->owner);
}

static void
kbr_prune_vlans0(struct kbr_proto *p)
{
  if (!p->vlan_hash.data)
    return;

  HASH_WALK(p->vlan_hash, next, v)
  {
    if (v->owner && (!v->mark_vlan || !v->mark_tunnel || (v->vni_req != v->vni)))
    {
      struct iface *ifa = if_find_by_index(v->ifi);
      if (!ifa) continue;

      TRACE(D_EVENTS, "%s VLAN %u VNI %u on %s",
	    (!v->mark_vlan ? "Adding" : "Updating"), v->vid, v->vni, ifa->name);
      kbr_update_vlan(ifa, v->vid, true, v->mark_vlan, true, v->mark_tunnel, v->vni_req, v->vni);
      kbr_vlan_set_vni(p, v, v->vni_req);
    }

    v->active = !!v->owner;
  }
  HASH_WALK_END;
}

static void
kbr_prune_vlans1(struct kbr_proto *p)
{
  if (!p->vlan_hash.data)
    return;

  HASH_WALK(p->vlan_hash, next, v)
  {

    if (!v->owner && (v->mark_vlan || v->mark_tunnel) && kbr_find_vlan(p, v->ifi, 0))
    {
      struct iface *ifa = if_find_by_index(v->ifi);
      if (!ifa) continue;

      TRACE(D_EVENTS, "Removing VLAN %u on %s", v->vid, ifa->name);
      kbr_update_vlan(ifa, v->vid, false, v->mark_vlan, false, v->mark_tunnel, v->vni_req, v->vni);
      kbr_vlan_unset_vni(p, v);
    }

    v->mark_vlan = false;
    v->mark_tunnel = false;
  }
  HASH_WALK_END;
}


/*
 *	Bridge protocol glue
 */

static bool
kbr_check_iface(struct kbr_proto *p, const struct iface *i)
{
  ea_list *attrs = i->attrs;

  if (!(i->flags & IF_UP))
  {
    log(L_ERR "%s: Interface %s is down", p->p.name, i->name);
    return false;
  }

  u32 if_type = ea_get_int(attrs, &ea_iface_type, IF_TYPE_UNDEF);
  if (if_type != IF_TYPE_BRIDGE)
  {
    log(L_ERR "%s: Interface %s is not a bridge", p->p.name, i->name);
    return false;
  }

  u32 if_vlan_filtering = ea_get_int(attrs, &ea_iface_bridge_vlan_filtering, U32_UNDEF);
  if (p->vlan_filtering && !if_vlan_filtering)
  {
    log(L_WARN "%s: Mismatch in VLAN filtering", p->p.name, i->name);
    return false;
  }

  return true;
}

static void
kbr_postconfig(struct proto_config *CF)
{
  struct kbr_config *cf = (void *) CF;

  if (! proto_cf_main_channel(CF))
    cf_error("Channel not specified");

  if (!cf->bridge_dev)
    cf_error("Bridge device not specified");
}

static struct proto *
kbr_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  // struct kbr_proto *p = (void *) P;
  // struct kbr_config *cf = (void *) CF;

  P->main_channel = proto_add_channel(P, proto_cf_main_channel(CF));

  P->rt_notify = kbr_rt_notify;
  P->preexport = kbr_preexport;
  P->reload_routes = kbr_reload_routes;
  P->export_fed = kbr_feed_end;
  P->sources.class = &kbr_rte_owner_class;

  return P;
}

static int
kbr_start(struct proto *P)
{
  struct kbr_proto *p = (void *) P;
  struct kbr_config *cf = (void *) P->cf;

  p->bridge_dev = cf->bridge_dev;
  p->vlan_filtering = cf->vlan_filtering;

  memset(&p->vlan_hash, 0, sizeof(p->vlan_hash));
  p->vlan_sub = NULL;

  p->scan_timer = tm_new_init(p->p.pool, kbr_scan, p, cf->scan_time, 0);

  bmap_init(&p->sync_map[0], p->p.pool, 1024);
  bmap_init(&p->sync_map[1], p->p.pool, 1024);
  bmap_init(&p->seen_map[0], p->p.pool, 1024);
  bmap_init(&p->seen_map[1], p->p.pool, 1024);

  if (p->vlan_filtering)
  {
    HASH_INIT(p->vlan_hash, p->p.pool, 4);
    HASH_INIT(p->vlan_vni_hash, p->p.pool, 4);

    p->vlan_sub = ps_subscriber_new(p->p.pool, kbr_vlan_req_notify, p);
    ps_subscribe_topic(p->vlan_sub, &vlan_requests, p->bridge_dev->name);
  }

  kbr_check_iface(p, p->bridge_dev);

  kbr_sys_start(p);

  return PS_UP;
}

static int
kbr_shutdown(struct proto *P UNUSED)
{
  struct kbr_proto *p = (void *) P;

  if (p->synced)
    kbr_flush_routes(p);

  p->ready = false;
  p->synced = false;

  kbr_sys_shutdown(p);

  return PS_FLUSH;
}

static int
kbr_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct kbr_proto *p = (void *) P;
  struct kbr_config *cf = (void *) CF;

  if ((p->bridge_dev != cf->bridge_dev) ||
      (p->vlan_filtering != cf->vlan_filtering))
    return 0;

  if (!proto_configure_channel(P, &P->main_channel, proto_cf_main_channel(CF)))
    return 0;

  return 1;
}

static void
kbr_copy_config(struct proto_config *dest UNUSED, struct proto_config *src UNUSED)
{
  /* Just a shallow copy, not many items here */
}

const char * const kbr_src_names[KBR_SRC_MAX] = {
  [KBR_SRC_BIRD]	= "bird",
  [KBR_SRC_LOCAL]	= "local",
  [KBR_SRC_STATIC]	= "static",
  [KBR_SRC_DYNAMIC]	= "dynamic",
};

const char kbr_src_abbrev[KBR_SRC_MAX] = "BLSD";

static void
ea_kbr_source_format(const eattr *a, byte *buf, uint size)
{
  if (a->u.data >= ARRAY_SIZE(kbr_src_names) || !kbr_src_names[a->u.data])
    bsnprintf(buf, size, "?");
  else
    bsnprintf(buf, size, "%s", kbr_src_names[a->u.data]);
}

struct ea_class ea_kbr_source = {
  .name = "kbr_source",
  .legacy_name = "Bridge.source",
  .type = T_ENUM_KBR_SOURCE,
  .format = ea_kbr_source_format,
};

static void
kbr_get_route_info(const rte *rte, byte *buf)
{
  eattr *a = ea_find(rte->attrs, &ea_kbr_source);
  char src = (a && a->u.data < sizeof kbr_src_abbrev) ? kbr_src_abbrev[a->u.data] : '?';

  bsprintf(buf, " %c (%u)", src, rt_get_preference(rte));
}


static struct rte_owner_class kbr_rte_owner_class = {
  .rte_better =		kbr_rte_better,
  .get_route_info =	kbr_get_route_info,
};

struct protocol proto_bridge = {
  .name =		"Bridge",
  .template =		"bridge%d",
  .channel_mask =	NB_ETH,
  .proto_size =		sizeof(struct kbr_proto),
  .config_size =	sizeof(struct kbr_config),
  .postconfig =		kbr_postconfig,
  .init =		kbr_init,
  .start =		kbr_start,
  .shutdown =		kbr_shutdown,
  .reconfigure =	kbr_reconfigure,
  .copy_config = 	kbr_copy_config,
};

void
bridge_build(void)
{
  proto_build(&proto_bridge);

  EA_REGISTER_ALL(
      &ea_kbr_source,
      );
}
