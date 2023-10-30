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
 * - Configuration of VIDs?
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

  rt_refresh_begin(c->table, c);
  kbr_do_scan(p);
  rt_refresh_end(c->table, c);
}

static void
kbr_rt_notify(struct proto *P, struct channel *c0 UNUSED, net *net, rte *new, rte *old)
{
  struct kbr_proto *p UNUSED = (void *) P;

  rte *new_gw = (new && ipa_nonzero(new->attrs->nh.gw)) ? new : NULL;
  rte *old_gw = (old && ipa_nonzero(old->attrs->nh.gw)) ? old : NULL;

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

  if (mac_zero(net_mac_addr(net->n.addr)))
  {
    /* For BUM routes, we have multiple tunnel entries, but no bridge entry */
    kbr_update_fdb(net->n.addr, new_gw, old_gw, 1);
    return;
  }

  /* For regular routes, we have one bridge entry, perhaps also one tunnel entry */
  kbr_replace_fdb(net->n.addr, new, old, 0);
  kbr_replace_fdb(net->n.addr, new_gw, old_gw, 1);
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

  p->scan_timer = tm_new_init(p->p.pool, kbr_scan, p, cf->scan_time, 0);
  tm_start(p->scan_timer, 100 MS);

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
