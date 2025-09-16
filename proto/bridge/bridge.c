/*
 *	BIRD -- Linux Bridge Interface
 *
 *	(c) 2023 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2023 CZ.NIC z.s.p.o.
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
 * - Better two-way synchronization, including initial clean-up
 * - Wait for existence (and active state) of the bridge device
 * - Check for consistency of vlan_filtering flag
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

#include "bridge.h"

static struct kbr_vlan * kbr_find_vlan(struct kbr_proto *p, uint ifi, uint vid);
static void kbr_prune_vlans0(struct kbr_proto *p);
static void kbr_prune_vlans1(struct kbr_proto *p);


/*
 *	Bridge entries
 */

void
kbr_got_route(struct kbr_proto *p, const net_addr *n, rte *e, int src UNUSED, int scan UNUSED)
{
  struct channel *c = p->p.main_channel;

  if (e) e->attrs->pref = c->preference;
  rte_update2(c, n, e, p->p.main_source);
}

static void
kbr_scan(timer *t)
{
  struct kbr_proto *p = t->data;
  struct channel *c = p->p.main_channel;

  TRACE(D_EVENTS, "Scanning bridge table");

  if (p->vlan_filtering)
  {
    kbr_do_vlan_scan(p);
    kbr_prune_vlans0(p);
  }

  rt_refresh_begin(c->table, c);
  kbr_do_fdb_scan(p);
  rt_refresh_end(c->table, c);

  if (p->vlan_filtering)
    kbr_prune_vlans1(p);

  /* XXX: Temporary workaround for missing bidirectional sync */
  channel_request_feeding(c);
}

static void
kbr_rt_notify(struct proto *P, struct channel *c0 UNUSED, net *net, rte *new, rte *old)
{
  struct kbr_proto *p = (void *) P;
  const net_addr *n = net->n.addr;

  rte *r = (new ?: old);
  rte *new_gw = (new && ipa_nonzero(new->attrs->nh.gw)) ? new : NULL;
  rte *old_gw = (old && ipa_nonzero(old->attrs->nh.gw)) ? old : NULL;

  /* For managed interfaces we ignore FDB entries when VLAN not active */
  /* For now, we assume EVPN FDB entry <-> direct to managed iface */
  if (p->vlan_filtering && (r->attrs->source == RTS_EVPN))
  {
    struct iface *i = r->attrs->nh.iface;
    struct kbr_vlan *v = kbr_find_vlan(p, i->index, net_vlan_id(n));

    if (!v || !v->active)
    {
      TRACE(D_ROUTES, "%N %s ignored - vlan %u not active on %s",
	    n, (new ? "update" : "withdraw"), net_vlan_id(n), i->name);
      return;
    }
  }

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

  if (mac_zero(net_mac_addr(n)))
  {
    /* For BUM routes, we have multiple tunnel entries, but no bridge entry */
    kbr_update_fdb(n, new_gw, old_gw, 1);
    return;
  }

  /* For regular routes, we have one bridge entry, perhaps also one tunnel entry */
  kbr_replace_fdb(n, new, old, 0);
  kbr_replace_fdb(n, new_gw, old_gw, 1);
}

static inline int
kbr_is_installed(struct channel *c, net *n)
{
  return n->routes && bmap_test(&c->export_map, n->routes->id);
}

static void
kbr_flush_routes(struct kbr_proto *p)
{
  struct channel *c = p->p.main_channel;

  TRACE(D_EVENTS, "Flushing bridge routes");
  FIB_WALK(&c->table->fib, net, n)
  {
    if (kbr_is_installed(c, n))
      kbr_rt_notify(&p->p, c, n, NULL, n->routes);
  }
  FIB_WALK_END;
}


static int
kbr_preexport(struct channel *C, rte *e)
{
  struct kbr_proto *p = (void *) C->proto;

  /* Reject our own routes */
  if (e->src->proto == &p->p)
    return -1;

  return 0;
}

static void
kbr_reload_routes(struct channel *C)
{
  struct kbr_proto *p = (void *) C->proto;

  tm_start(p->scan_timer, 0);
}

static inline u32
kbr_metric(rte *e)
{
  u32 metric = ea_get_int(e->attrs->eattrs, EA_GEN_IGP_METRIC, e->attrs->igp_metric);
  return MIN(metric, IGP_METRIC_UNKNOWN);
}

static int
kbr_rte_better(rte *new, rte *old)
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


HASH_DEFINE_REHASH_FN(VLAN, struct kbr_vlan)

static struct kbr_vlan *
kbr_find_vlan(struct kbr_proto *p, uint ifi, uint vid)
{
  return  HASH_FIND(p->vlan_hash, VLAN, ifi, vid);
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

  v->vni = vni;
  v->mark_tunnel = true;
}

static inline void
kbr_vlan_changed(struct kbr_proto *p)
{
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
    }

    v->mark_vlan = false;
    v->mark_tunnel = false;
  }
  HASH_WALK_END;
}


/*
 *	Bridge protocol glue
 */

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
  P->rte_better = kbr_rte_better;

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
  tm_start(p->scan_timer, 100 MS);

  if (p->vlan_filtering)
  {
    HASH_INIT(p->vlan_hash, p->p.pool, 4);

    p->vlan_sub = ps_subscriber_new(p->p.pool, kbr_vlan_req_notify, p);
    ps_subscribe_topic(p->vlan_sub, &vlan_requests, p->bridge_dev->name);
  }

  kbr_sys_start(p);

  return PS_UP;
}

static int
kbr_shutdown(struct proto *P UNUSED)
{
  struct kbr_proto *p = (void *) P;

  kbr_flush_routes(p);
  kbr_sys_shutdown(p);

  return PS_DOWN;
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

static int
kbr_get_attr(const eattr *a, byte *buf, int buflen UNUSED)
{
  switch (a->id)
  {
  case EA_KBR_SOURCE:;
    const char *src = (a->u.data < KBR_SRC_MAX) ? kbr_src_names[a->u.data] : "?";
    bsprintf(buf, "source: %s", src);
    return GA_FULL;

  default:
    return GA_UNKNOWN;
  }
}

static void
kbr_get_route_info(rte *rte, byte *buf)
{
  eattr *a = ea_find(rte->attrs->eattrs, EA_KBR_SOURCE);
  char src = (a && a->u.data < KBR_SRC_MAX) ? "BLSD"[a->u.data] : '?';

  bsprintf(buf, " %c (%u)", src, rte->attrs->pref);
}


struct protocol proto_bridge = {
  .name =		"Bridge",
  .template =		"bridge%d",
  .class =		PROTOCOL_BRIDGE,
  .channel_mask =	NB_ETH,
  .proto_size =		sizeof(struct kbr_proto),
  .config_size =	sizeof(struct kbr_config),
  .postconfig =		kbr_postconfig,
  .init =		kbr_init,
  .start =		kbr_start,
  .shutdown =		kbr_shutdown,
  .reconfigure =	kbr_reconfigure,
  .copy_config = 	kbr_copy_config,
  .get_attr =		kbr_get_attr,
  .get_route_info =	kbr_get_route_info,
};

void
bridge_build(void)
{
  proto_build(&proto_bridge);
}
