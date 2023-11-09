/*
 *	BIRD -- BGP/MPLS IP Virtual Private Networks (L3VPN)
 *
 *	(c) 2022 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: L3VPN
 *
 * The L3VPN protocol implements RFC 4364 BGP/MPLS VPNs using MPLS backbone.
 * It works similarly to pipe. It connects IP table (one per VRF) with (global)
 * VPN table. Routes passed from VPN table to IP table are stripped of RD and
 * filtered by import targets, routes passed in the other direction are extended
 * with RD, MPLS labels and export targets in extended communities. Separate
 * MPLS channel is used to announce MPLS routes for the labels.
 *
 * Note that in contrast to the pipe protocol, L3VPN protocol has both IPv4 and
 * IPv6 channels in one instance, Also both IP and VPN channels are presented to
 * users as separate channels, although that will change in the future.
 *
 * The L3VPN protocol has different default preferences on IP and VPN sides.
 * The reason is that in import direction (VPN->IP) routes should have lower
 * preferences that ones received from local CE (perhaps by EBGP), while in
 * export direction (IP->VPN) routes should have higher preferences that ones
 * received from remote PEs (by IBGP).
 *
 * Supported standards:
 * RFC 4364 - BGP/MPLS IP Virtual Private Networks (L3VPN)
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

#include "l3vpn.h"

#include "proto/pipe/pipe.h"

#include <stdbool.h>

/*
 * TODO:
 * - import/export target reconfiguration
 * - check for simple nodes in export route
 * - replace pair of channels with shared channel for one address family
 * - improve route comparisons in VRFs
 * - optional import/export target all
 * - optional support for route origins
 * - optional automatic assignment of RDs
 * - MPLS-in-IP encapsulation
 */

static struct ea_class *ea_bgp_next_hop,
		       *ea_bgp_ext_community,
		       *ea_bgp_mpls_label_stack;

static inline int
mpls_valid_nexthop(struct nexthop_adata *nhad)
{
  /* MPLS does not support special blackhole targets */
  if (!NEXTHOP_IS_REACHABLE(nhad))
    return 0;

  /* MPLS does not support ARP / neighbor discovery */
  NEXTHOP_WALK(nh, nhad)
    if (ipa_zero(nh->gw) && (nh->iface->flags & IF_MULTIACCESS))
      return 0;

  return 1;
}

static int
l3vpn_import_targets(struct l3vpn_proto *p, const struct adata *list)
{
  return (p->import_target_one) ?
    ec_set_contains(list, p->import_target->from.val.ec) :
    eclist_match_set(list, p->import_target);
}

static struct adata *
l3vpn_export_targets(struct l3vpn_proto *p, const struct adata *src)
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

static void
l3vpn_add_ec(const struct f_tree *t, void *P)
{
  struct l3vpn_proto *p = P;
  ec_put(p->export_target_data, p->export_target_length, t->from.val.ec);
  p->export_target_length += 2;
}

static void
l3vpn_prepare_targets(struct l3vpn_proto *p)
{
  const struct f_tree *t = p->import_target;
  p->import_target_one = !t->left && !t->right && (t->from.val.ec == t->to.val.ec);

  uint len = 2 * tree_node_count(p->export_target);
  p->export_target_data = mb_alloc(p->p.pool, len * sizeof(u32));
  p->export_target_length = 0;
  tree_walk(p->export_target, l3vpn_add_ec, p);
  ASSERT(p->export_target_length == len);
}

/* Convert 64-bit RD to 32bit source ID, unfortunately it has collisions */
static inline struct rte_src * l3vpn_get_source(struct l3vpn_proto *p, u64 rd)
{ return rt_get_source(&p->p, (u32)(rd >> 32) ^ u32_hash(rd)); }
//{ return p->p.main_source; }

static void
l3vpn_rt_notify(struct proto *P, struct channel *c0, const net_addr *n0, rte *new, const rte *old UNUSED)
{
  struct l3vpn_proto *p = (void *) P;
  struct rte_src *src = NULL;
  struct channel *dst = NULL;
  int export;

  net_addr *n = alloca(sizeof(net_addr_vpn6));

  switch (c0->net_type)
  {
  case NET_IP4:
    net_fill_vpn4(n, net4_prefix(n0), net4_pxlen(n0), p->rd);
    src = p->p.main_source;
    dst = p->vpn4_channel;
    export = 1;
    break;

  case NET_IP6:
    net_fill_vpn6(n, net6_prefix(n0), net6_pxlen(n0), p->rd);
    src = p->p.main_source;
    dst = p->vpn6_channel;
    export = 1;
    break;

  case NET_VPN4:
    net_fill_ip4(n, net4_prefix(n0), net4_pxlen(n0));
    src = l3vpn_get_source(p, ((const net_addr_vpn4 *) n0)->rd);
    dst = p->ip4_channel;
    export = 0;
    break;

  case NET_VPN6:
    net_fill_ip6(n, net6_prefix(n0), net6_pxlen(n0));
    src = l3vpn_get_source(p, ((const net_addr_vpn6 *) n0)->rd);
    dst = p->ip6_channel;
    export = 0;
    break;

  case NET_MPLS:
    return;
  }

  const struct adata *ecad = ea_get_adata(new->attrs, ea_bgp_ext_community);
  struct nexthop_adata *nhad_orig = rte_get_nexthops(new);

  if (new)
  {
    new->src = src;

    ea_set_attr_u32(&new->attrs, &ea_gen_source, 0, RTS_L3VPN);
    ea_set_attr_u32(&new->attrs, &ea_gen_preference, 0, dst->preference);

    /* Do not keep original labels, we may assign new ones */
    ea_unset_attr(&new->attrs, 0, &ea_gen_mpls_label);
    ea_unset_attr(&new->attrs, 0, &ea_gen_mpls_policy);

    /* We are crossing VRF boundary, NEXT_HOP is no longer valid */
    ea_unset_attr(&new->attrs, 0, ea_bgp_next_hop);
    ea_unset_attr(&new->attrs, 0, ea_bgp_mpls_label_stack);

    /* Hostentry also validn't */
    ea_unset_attr(&new->attrs, 0, &ea_gen_hostentry);

    if (export)
    {
      struct mpls_channel *mc = (void *) p->p.mpls_channel;
      ea_set_attr_u32(&new->attrs, &ea_gen_mpls_policy, 0, mc->label_policy);

      ea_set_attr(&new->attrs, EA_LITERAL_DIRECT_ADATA(
	    ea_bgp_ext_community, 0, l3vpn_export_targets(p, ecad)));

      /* Replace MPLS-incompatible nexthop with lookup in VRF table */
      if (!nhad_orig || !mpls_valid_nexthop(nhad_orig) && p->p.vrf)
      {
	struct nexthop_adata nhad = {
	  .nh.iface = p->p.vrf,
	  .ad.length = sizeof nhad - sizeof nhad.ad,
	};
	ea_set_attr_data(&new->attrs, &ea_gen_nexthop, 0, nhad.ad.data, nhad.ad.length);
      }

      /* Drop original IGP metric on export;
       * kept on import as a base for L3VPN metric */
      ea_unset_attr(&new->attrs, 0, &ea_gen_igp_metric);
    }

    rte_update(dst, n, new, src);
  }
  else
  {
    rte_update(dst, n, NULL, src);
  }
}


static int
l3vpn_preexport(struct channel *C, rte *e)
{
  struct l3vpn_proto *p = (void *) C->proto;

  if (&C->in_req == e->sender->req)
    return -1;	/* Avoid local loops automatically */

  switch (C->net_type)
  {
  case NET_IP4:
  case NET_IP6:
    return 0;

  case NET_VPN4:
  case NET_VPN6:
    return l3vpn_import_targets(p, ea_get_adata(e->attrs, ea_bgp_ext_community)) ? 0 : -1;

  case NET_MPLS:
    return -1;

  default:
    bug("invalid type");
  }
}

/* TODO: unify the code between l3vpn and pipe */
void pipe_import_by_refeed_free(struct channel_feeding_request *cfr);

static int
l3vpn_reload_routes(struct channel *C, struct channel_import_request *cir)
{
  struct l3vpn_proto *p = (void *) C->proto;
  struct channel *feed = NULL;

  /* Route reload on one channel is just refeed on the other */
  switch (C->net_type)
  {
  case NET_IP4:
    feed = p->vpn4_channel;
    break;

  case NET_IP6:
    feed = p->vpn6_channel;
    break;

  case NET_VPN4:
    feed = p->ip4_channel;
    break;

  case NET_VPN6:
    feed = p->ip6_channel;
    break;

  case NET_MPLS:
    /* FIXME */
    return 1;
  }

  if (cir->trie)
  {
    struct import_to_export_reload *reload = lp_alloc(cir->trie->lp, sizeof *reload);
    *reload = (struct import_to_export_reload) {
      .cir = cir,
      .cfr = {
	      .type = CFRT_AUXILIARY,
	      .done = pipe_import_by_refeed_free,
	      .trie = cir->trie,
	    },
    };
    channel_request_feeding(feed, &reload->cfr);
  }
  else
  {
    /* Route reload on one channel is just refeed on the other */
    channel_request_feeding_dynamic(feed, CFRT_DIRECT);
    cir->done(cir);
  }

  return 1;
}

static int
l3vpn_rte_better(const rte *new, const rte *old)
{
  /* This is hack, we should have full BGP-style comparison */
  return rt_get_igp_metric(new) < rt_get_igp_metric(old);
}

static void
l3vpn_postconfig(struct proto_config *CF)
{
  struct l3vpn_config *cf = (void *) CF;

  if (!!proto_cf_find_channel(CF, NET_IP4) != !!proto_cf_find_channel(CF, NET_VPN4))
    cf_error("For IPv4 L3VPN, both IPv4 and VPNv4 channels must be specified");

  if (!!proto_cf_find_channel(CF, NET_IP6) != !!proto_cf_find_channel(CF, NET_VPN6))
    cf_error("For IPv6 L3VPN, both IPv6 and VPNv6 channels must be specified");

  if (!proto_cf_find_channel(CF, NET_MPLS))
    cf_error("MPLS channel not specified");

  if (!cf->rd)
    cf_error("Route distinguisher not specified");

  if (!cf->import_target && !cf->export_target)
    cf_error("Route target not specified");

  if (!cf->import_target)
    cf_error("Import target not specified");

  if (!cf->export_target)
    cf_error("Export target not specified");
}

static struct proto *
l3vpn_init(struct proto_config *CF)
{
  ASSERT_DIE(the_bird_locked());

  /* Resolve registered BGP attribute classes once */
  static bool bgp_attributes_resolved = 0;
  if (!bgp_attributes_resolved)
  {
    ea_bgp_next_hop = ea_class_find_by_name("bgp_next_hop");
    ea_bgp_ext_community = ea_class_find_by_name("bgp_ext_community");
    ea_bgp_mpls_label_stack = ea_class_find_by_name("bgp_mpls_label_stack");
    bgp_attributes_resolved = 1;
  }

  struct proto *P = proto_new(CF);
  struct l3vpn_proto *p = (void *) P;
  // struct l3vpn_config *cf = (void *) CF;

  proto_configure_channel(P, &p->ip4_channel, proto_cf_find_channel(CF, NET_IP4));
  proto_configure_channel(P, &p->ip6_channel, proto_cf_find_channel(CF, NET_IP6));
  proto_configure_channel(P, &p->vpn4_channel, proto_cf_find_channel(CF, NET_VPN4));
  proto_configure_channel(P, &p->vpn6_channel, proto_cf_find_channel(CF, NET_VPN6));
  proto_configure_channel(P, &P->mpls_channel, proto_cf_find_channel(CF, NET_MPLS));

  P->rt_notify = l3vpn_rt_notify;
  P->preexport = l3vpn_preexport;
  P->reload_routes = l3vpn_reload_routes;

  return P;
}

static int
l3vpn_start(struct proto *P)
{
  struct l3vpn_proto *p = (void *) P;
  struct l3vpn_config *cf = (void *) P->cf;

  p->rd = cf->rd;
  p->import_target = cf->import_target;
  p->export_target = cf->export_target;

  l3vpn_prepare_targets(p);

  proto_setup_mpls_map(P, RTS_L3VPN);

  P->mpls_map->vrf_iface = P->vrf;

  return PS_UP;
}

static int
l3vpn_shutdown(struct proto *P)
{
  // struct l3vpn_proto *p = (void *) P;

  proto_shutdown_mpls_map(P);

  return PS_DOWN;
}

static int
l3vpn_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct l3vpn_proto *p = (void *) P;
  struct l3vpn_config *cf = (void *) CF;

  if (!proto_configure_channel(P, &p->ip4_channel, proto_cf_find_channel(CF, NET_IP4)) ||
      !proto_configure_channel(P, &p->ip6_channel, proto_cf_find_channel(CF, NET_IP6)) ||
      !proto_configure_channel(P, &p->vpn4_channel, proto_cf_find_channel(CF, NET_VPN4)) ||
      !proto_configure_channel(P, &p->vpn6_channel, proto_cf_find_channel(CF, NET_VPN6)) ||
      !proto_configure_channel(P, &P->mpls_channel, proto_cf_find_channel(CF, NET_MPLS)))
    return 0;

  if ((p->rd != cf->rd) ||
      !same_tree(p->import_target, cf->import_target) ||
      !same_tree(p->export_target, cf->export_target))
    return 0;

  /*
  if (!same_tree(p->import_target, cf->import_target))
  {
    if (p->vpn4_channel && (p->vpn4_channel->channel_state == CS_UP))
      channel_request_feeding(p->vpn4_channel);

    if (p->vpn6_channel && (p->vpn6_channel->channel_state == CS_UP))
      channel_request_feeding(p->vpn6_channel);
  }

  if (!same_tree(p->export_target, cf->export_target))
  {
    if (p->ip4_channel && (p->ip4_channel->channel_state == CS_UP))
      channel_request_feeding(p->ip4_channel);

    if (p->ip6_channel && (p->ip6_channel->channel_state == CS_UP))
      channel_request_feeding(p->ip6_channel);
  }
  */

  /* Update pointers to config structures */
  p->import_target = cf->import_target;
  p->export_target = cf->export_target;

  proto_setup_mpls_map(P, RTS_L3VPN);

  return 1;
}

static void
l3vpn_copy_config(struct proto_config *dest UNUSED, struct proto_config *src UNUSED)
{
  /* Just a shallow copy, not many items here */
}

static void
l3vpn_get_route_info(const rte *rte, byte *buf)
{
  u32 metric = rt_get_igp_metric(rte);
  u32 pref = rt_get_preference(rte);

  if (metric < IGP_METRIC_UNKNOWN)
    bsprintf(buf, " (%u/%u)", pref, metric);
  else
    bsprintf(buf, " (%u/?)", pref);
}

struct rte_owner_class l3vpn_rte_owner_class = {
  .get_route_info =	l3vpn_get_route_info,
  .rte_better =		l3vpn_rte_better,
};

struct protocol proto_l3vpn = {
  .name =		"L3VPN",
  .template =		"l3vpn%d",
  .channel_mask =	NB_IP | NB_VPN | NB_MPLS,
  .proto_size =		sizeof(struct l3vpn_proto),
  .config_size =	sizeof(struct l3vpn_config),
  .startup =		PROTOCOL_STARTUP_CONNECTOR,
  .postconfig =		l3vpn_postconfig,
  .init =		l3vpn_init,
  .start =		l3vpn_start,
  .shutdown =		l3vpn_shutdown,
  .reconfigure =	l3vpn_reconfigure,
  .copy_config = 	l3vpn_copy_config,
};

void
l3vpn_build(void)
{
  proto_build(&proto_l3vpn);
}
