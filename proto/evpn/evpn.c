/*
 *	BIRD -- BGP/MPLS Ethernet Virtual Private Networks (EVPN)
 *
 *	(c) 2023 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2023 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: BGP/MPLS Ethernet Virtual Private Networks (EVPN)
 *
 * The EVPN protocol implements RFC 7432 BGP Etherent VPNs using VXLAN overlays.
 * It works similarly to L3VPN. It connects ethernet table (one per VRF) with
 * (global) EVPN table. Routes passed from EVPN table to ethernet table are
 * stripped of RD and filtered by import targets, routes passed in the other
 * direction are extended with RD, MPLS/VNI labels, and export targets in
 * extended communities.
 *
 * The EVPN protocol supports MAC (type 2) and IMET (type 3) EVPN routes, there
 * is no support for EAD / ES routes, or routes with non-zero tag. There is also
 * no support for MPLS backbone, just VXLAN overlays.
 *
 * Supported standards:
 * RFC 7432 - BGP MPLS-Based Ethernet VPN
 * RFC 8365 - Network Virtualization Using Ethernet VPN
 */

/*
 * TODO:
 * - Encapsulation community handling
 * - MAC mobility community handling
 * - Review preference handling
 * - Wait for existence (and active state) of the tunnel device
 * - Learn VNI / router address from the tunnel device
 * - Improved VLAN handling
 * - MPLS encapsulation mode
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

#include "evpn.h"

#include "proto/bgp/bgp.h"

#define EA_BGP_NEXT_HOP		EA_CODE(PROTOCOL_BGP, BA_NEXT_HOP)
#define EA_BGP_EXT_COMMUNITY	EA_CODE(PROTOCOL_BGP, BA_EXT_COMMUNITY)
#define EA_BGP_MPLS_LABEL_STACK	EA_CODE(PROTOCOL_BGP, BA_MPLS_LABEL_STACK)

static inline const struct adata * ea_get_adata(ea_list *e, uint id)
{ eattr *a = ea_find(e, id); return a ? a->u.ptr : &null_adata; }

static inline int
mpls_valid_nexthop(const rta *a)
{
  /* MPLS does not support special blackhole targets */
  if (a->dest != RTD_UNICAST)
    return 0;

  /* MPLS does not support ARP / neighbor discovery */
  for (const struct nexthop *nh = &a->nh; nh ; nh = nh->next)
    if (ipa_zero(nh->gw) && (nh->iface->flags & IF_MULTIACCESS))
      return 0;

  return 1;
}

static int
evpn_import_targets(struct evpn_proto *p, const struct adata *list)
{
  return (p->import_target_one) ?
    ec_set_contains(list, p->import_target->from.val.ec) :
    eclist_match_set(list, p->import_target);
}

static struct adata *
evpn_export_targets(struct evpn_proto *p, const struct adata *src)
{
  u32 *s = int_set_get_data(src);
  int len = int_set_get_size(src);

  struct adata *dst = lp_alloc(tmp_linpool, sizeof(struct adata) + (len + p->export_target_length) * sizeof(u32));
  u32 *d = int_set_get_data(dst);
  int end = 0;

  for (int i = 0; i < len; i += 2)
  {
    /* Remove existing route targets */
    uint type = s[i] >> 16;
    if (ec_type_is_rt(type))
      continue;

    d[end++] = s[i];
    d[end++] = s[i+1];
  }

  /* Add new route targets */
  memcpy(d + end, p->export_target_data, p->export_target_length * sizeof(u32));
  end += p->export_target_length;

  /* Set length */
  dst->length = end * sizeof(u32);

  return dst;
}

static inline void
evpn_prepare_import_targets(struct evpn_proto *p)
{
  const struct f_tree *t = p->import_target;
  p->import_target_one = !t->left && !t->right && (t->from.val.ec == t->to.val.ec);
}

static void
evpn_add_ec(const struct f_tree *t, void *P)
{
  struct evpn_proto *p = P;
  ec_put(p->export_target_data, p->export_target_length, t->from.val.ec);
  p->export_target_length += 2;
}

static void
evpn_prepare_export_targets(struct evpn_proto *p)
{
  if (p->export_target_data)
    mb_free(p->export_target_data);

  uint len = 2 * tree_node_count(p->export_target);
  p->export_target_data = mb_alloc(p->p.pool, len * sizeof(u32));
  p->export_target_length = 0;
  tree_walk(p->export_target, evpn_add_ec, p);
  ASSERT(p->export_target_length == len);
}

static void
evpn_announce_mac(struct evpn_proto *p, const net_addr_eth *n0, rte *new)
{
  struct channel *c = p->evpn_channel;

  net_addr *n = alloca(sizeof(net_addr_evpn_mac));
  net_fill_evpn_mac(n, p->rd, 0, n0->mac);

  if (new)
  {
    rta *a = alloca(RTA_MAX_SIZE);
    *a = (rta) {
      .source = RTS_EVPN,
      .scope = SCOPE_UNIVERSE,
      .pref = c->preference,
    };

    struct adata *ad = evpn_export_targets(p, &null_adata);
    ea_set_attr_ptr(&a->eattrs, tmp_linpool, EA_BGP_EXT_COMMUNITY, BAF_OPTIONAL | BAF_TRANSITIVE, EAF_TYPE_EC_SET, ad);

    ea_set_attr_u32(&a->eattrs, tmp_linpool, EA_MPLS_LABEL, 0, EAF_TYPE_INT, p->vni);

    rte *e = rte_get_temp(a, p->p.main_source);
    rte_update2(c, n, e, p->p.main_source);
  }
  else
  {
    rte_update2(c, n, NULL, p->p.main_source);
  }
}

static void
evpn_announce_imet(struct evpn_proto *p, int new)
{
  struct channel *c = p->evpn_channel;

  net_addr *n = alloca(sizeof(net_addr_evpn_imet));
  net_fill_evpn_imet(n, p->rd, 0, p->router_addr);

  if (new)
  {
    rta *a = alloca(RTA_MAX_SIZE);
    *a = (rta) {
      .source = RTS_EVPN,
      .scope = SCOPE_UNIVERSE,
      .pref = c->preference,
    };

    struct adata *ad = evpn_export_targets(p, &null_adata);
    ea_set_attr_ptr(&a->eattrs, tmp_linpool, EA_BGP_EXT_COMMUNITY, BAF_OPTIONAL | BAF_TRANSITIVE, EAF_TYPE_EC_SET, ad);

    rte *e = rte_get_temp(a, p->p.main_source);
    rte_update2(c, n, e, p->p.main_source);
  }
  else
  {
    rte_update2(c, n, NULL, p->p.main_source);
  }
}

#define BAD(msg, args...) \
  ({ log(L_ERR "%s: " msg, p->p.name, ## args); goto withdraw; })


static void
evpn_receive_mac(struct evpn_proto *p, const net_addr_evpn_mac *n0, rte *new)
{
  struct channel *c = p->eth_channel;

  net_addr *n = alloca(sizeof(net_addr_eth));
  net_fill_eth(n, n0->mac, p->vid);

  if (new && rte_resolvable(new))
  {
    eattr *nh = ea_find(new->attrs->eattrs, EA_BGP_NEXT_HOP);
    if (!nh)
      BAD("Missing NEXT_HOP attribute in %N", n0);

    eattr *ms = ea_find(new->attrs->eattrs, EA_BGP_MPLS_LABEL_STACK);
    if (!ms)
      BAD("Missing MPLS label stack in %N", n0);

    rta *a = alloca(RTA_MAX_SIZE);
    *a = (rta) {
      .source = RTS_EVPN,
      .scope = SCOPE_UNIVERSE,
      .dest = RTD_UNICAST,
      .pref = c->preference,
      .nh.gw = *((ip_addr *) nh->u.ptr->data),
      .nh.iface = p->tunnel_dev,
    };

    a->nh.labels = MIN(ms->u.ptr->length / 4, MPLS_MAX_LABEL_STACK);
    memcpy(a->nh.label, ms->u.ptr->data, a->nh.labels * 4);

    rte *e = rte_get_temp(a, p->p.main_source);
    rte_update2(c, n, e, p->p.main_source);
  }
  else
  {
  withdraw:
    rte_update2(c, n, NULL, p->p.main_source);
  }
}

static void
evpn_receive_imet(struct evpn_proto *p, const net_addr_evpn_imet *n0, rte *new)
{
  struct channel *c = p->eth_channel;
  struct rte_src *s = rt_get_source(&p->p, rd_to_u64(n0->rd));

  net_addr *n = alloca(sizeof(net_addr_eth));
  net_fill_eth(n, MAC_NONE, p->vid);

  if (new && rte_resolvable(new))
  {
    eattr *nh = ea_find(new->attrs->eattrs, EA_BGP_NEXT_HOP);

    rta *a = alloca(RTA_MAX_SIZE);
    *a = (rta) {
      .source = RTS_EVPN,
      .scope = SCOPE_UNIVERSE,
      .dest = RTD_UNICAST,
      .pref = c->preference,
      .nh.gw = nh ? *((ip_addr *) nh->u.ptr->data) : IPA_NONE,
      .nh.iface = p->tunnel_dev,
    };

    rte *e = rte_get_temp(a, s);
    rte_update2(c, n, e, s);
  }
  else
  {
    rte_update2(c, n, NULL, s);
  }
}



static void
evpn_rt_notify(struct proto *P, struct channel *c0 UNUSED, net *net, rte *new, rte *old UNUSED)
{
  struct evpn_proto *p = (void *) P;
  const net_addr *n = net->n.addr;

  switch (n->type)
  {
  case NET_ETH:
    evpn_announce_mac(p, (const net_addr_eth *) n, new);
    return;

  case NET_EVPN:
    switch (((const net_addr_evpn *) n)->subtype)
    {
    case NET_EVPN_MAC:
      evpn_receive_mac(p, (const net_addr_evpn_mac *) n, new);
      return;

    case NET_EVPN_IMET:
      evpn_receive_imet(p, (const net_addr_evpn_imet *) n, new);
      return;
    }
    return;

  case NET_MPLS:
    return;
  }
}


static int
evpn_preexport(struct channel *C, rte *e)
{
  struct evpn_proto *p = (void *) C->proto;
  struct proto *pp = e->sender->proto;
  const net_addr *n = e->net->n.addr;

  if (pp == C->proto)
    return -1;	/* Avoid local loops automatically */

  switch (n->type)
  {
  case NET_ETH:
    if (((const net_addr_eth *) n)->vid != p->vid)
      return -1;

    return 0;

  case NET_EVPN:
    return evpn_import_targets(p, ea_get_adata(e->attrs->eattrs, EA_BGP_EXT_COMMUNITY)) ? 0 : -1;

  case NET_MPLS:
    return -1;

  default:
    bug("invalid type");
  }
}

static void
evpn_reload_routes(struct channel *C)
{
  struct evpn_proto *p = (void *) C->proto;

  /* Route reload on one channel is just refeed on the other */
  switch (C->net_type)
  {
  case NET_ETH:
    channel_request_feeding(p->evpn_channel);
    break;

  case NET_EVPN:
    channel_request_feeding(p->eth_channel);
    break;

  case NET_MPLS:
    channel_request_feeding(p->eth_channel);
    break;
  }
}

static inline u32
evpn_metric(rte *e)
{
  u32 metric = ea_get_int(e->attrs->eattrs, EA_GEN_IGP_METRIC, e->attrs->igp_metric);
  return MIN(metric, IGP_METRIC_UNKNOWN);
}

static int
evpn_rte_better(rte *new, rte *old)
{
  /* This is hack, we should have full BGP-style comparison */
  return evpn_metric(new) < evpn_metric(old);
}

static void
evpn_postconfig(struct proto_config *CF)
{
  struct evpn_config *cf = (void *) CF;

  if (!proto_cf_find_channel(CF, NET_ETH))
    cf_error("Ethernet channel not specified");

  if (!proto_cf_find_channel(CF, NET_EVPN))
    cf_error("EVPN channel not specified");

//  if (!proto_cf_find_channel(CF, NET_MPLS))
//    cf_error("MPLS channel not specified");

  if (rd_zero(cf->rd))
    cf_error("Route distinguisher not specified");

  if (!cf->import_target && !cf->export_target)
    cf_error("Route target not specified");

  if (!cf->import_target)
    cf_error("Import target not specified");

  if (!cf->export_target)
    cf_error("Export target not specified");
}

static struct proto *
evpn_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct evpn_proto *p = (void *) P;
  // struct evpn_config *cf = (void *) CF;

  proto_configure_channel(P, &p->eth_channel, proto_cf_find_channel(CF, NET_ETH));
  proto_configure_channel(P, &p->evpn_channel, proto_cf_find_channel(CF, NET_EVPN));
  proto_configure_channel(P, &P->mpls_channel, proto_cf_find_channel(CF, NET_MPLS));

  P->rt_notify = evpn_rt_notify;
  P->preexport = evpn_preexport;
  P->reload_routes = evpn_reload_routes;
  P->rte_better = evpn_rte_better;

  return P;
}

static int
evpn_start(struct proto *P)
{
  struct evpn_proto *p = (void *) P;
  struct evpn_config *cf = (void *) P->cf;

  p->rd = cf->rd;
  p->import_target = cf->import_target;
  p->export_target = cf->export_target;
  p->export_target_data = NULL;

  p->tunnel_dev = cf->tunnel_dev;
  p->router_addr = cf->router_addr;
  p->vni = cf->vni;
  p->vid = cf->vid;

  evpn_prepare_import_targets(p);
  evpn_prepare_export_targets(p);

  proto_setup_mpls_map(P, RTS_EVPN, 1);

  // XXX ?
  if (P->vrf_set)
    P->mpls_map->vrf_iface = P->vrf;

  proto_notify_state(P, PS_UP);

  evpn_announce_imet(p, 1);

  return PS_UP;
}

static int
evpn_shutdown(struct proto *P)
{
  // struct evpn_proto *p = (void *) P;

  proto_shutdown_mpls_map(P, 1);

  return PS_DOWN;
}

static int
evpn_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct evpn_proto *p = (void *) P;
  struct evpn_config *cf = (void *) CF;

  if (!proto_configure_channel(P, &p->eth_channel, proto_cf_find_channel(CF, NET_ETH)) ||
      !proto_configure_channel(P, &p->evpn_channel, proto_cf_find_channel(CF, NET_EVPN)) ||
      !proto_configure_channel(P, &P->mpls_channel, proto_cf_find_channel(CF, NET_MPLS)))
    return 0;

  if (!rd_equal(p->rd, cf->rd) ||
      (p->tunnel_dev != cf->tunnel_dev) ||
      (!ipa_equal(p->router_addr, cf->router_addr)) ||
      (p->vni != cf->vni) ||
      (p->vid != cf->vid))
    return 0;

  int import_changed = !same_tree(p->import_target, cf->import_target);
  int export_changed = !same_tree(p->export_target, cf->export_target);

  /* Update pointers to config structures */
  p->import_target = cf->import_target;
  p->export_target = cf->export_target;

  proto_setup_mpls_map(P, RTS_EVPN, 1);

  if (import_changed)
  {
    TRACE(D_EVENTS, "Import target changed");

    evpn_prepare_import_targets(p);

    if (p->evpn_channel && (p->evpn_channel->channel_state == CS_UP))
      channel_request_feeding(p->evpn_channel);
  }

  if (export_changed)
  {
    TRACE(D_EVENTS, "Export target changed");

    evpn_prepare_export_targets(p);

    if (p->eth_channel && (p->eth_channel->channel_state == CS_UP))
      channel_request_feeding(p->eth_channel);
  }

  return 1;
}

static void
evpn_copy_config(struct proto_config *dest UNUSED, struct proto_config *src UNUSED)
{
  /* Just a shallow copy, not many items here */
}

/*
static void
evpn_get_route_info(rte *rte, byte *buf)
{
  u32 metric = evpn_metric(rte);
  if (metric < IGP_METRIC_UNKNOWN)
    bsprintf(buf, " (%u/%u)", rte->attrs->pref, metric);
  else
    bsprintf(buf, " (%u/?)", rte->attrs->pref);
}
*/


struct protocol proto_evpn = {
  .name =		"EVPN",
  .template =		"evpn%d",
  .class =		PROTOCOL_EVPN,
  .channel_mask =	NB_ETH | NB_EVPN | NB_MPLS,
  .proto_size =		sizeof(struct evpn_proto),
  .config_size =	sizeof(struct evpn_config),
  .postconfig =		evpn_postconfig,
  .init =		evpn_init,
  .start =		evpn_start,
  .shutdown =		evpn_shutdown,
  .reconfigure =	evpn_reconfigure,
  .copy_config = 	evpn_copy_config,
//  .get_route_info =	evpn_get_route_info
};

void
evpn_build(void)
{
  proto_build(&proto_evpn);
}
