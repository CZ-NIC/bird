/*
 *	BIRD -- BGP/MPLS Ethernet Virtual Private Networks (EVPN)
 *
 *	(c) 2023--2026 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2023--2026 CZ.NIC z.s.p.o.
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
 * - MAC mobility community handling
 * - Review preference handling
 * - MPLS encapsulation mode
 */

#undef LOCAL_DEBUG

#include <stdlib.h>

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/mpls.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/data.h"
#include "lib/pubsub.h"
#include "lib/string.h"
#include "sysdep/unix/krt.h"

#include "evpn.h"

#include "proto/bgp/bgp.h"

static struct ea_class *ea_bgp_next_hop,
		       *ea_bgp_ext_community,
		       *ea_bgp_pmsi_tunnel,
		       *ea_bgp_mpls_label_stack;

#define EC_ENCAP		0x030cU


static struct evpn_vlan *evpn_find_vlan_by_tag(struct evpn_proto *p, u32 tag);
static struct evpn_vlan *evpn_find_vlan_by_vid(struct evpn_proto *p, u32 vid);

#define EVPN_ROOT_VLAN(P) \
  ( &(struct evpn_vlan){ .tag = (P)->tagX, .vni = (P)->vni, .vid = (P)->vid } )

#define evpn_get_vlan_by_tag(P,TAG) \
  ( evpn_find_vlan_by_tag((P), (TAG)) ?: EVPN_ROOT_VLAN(P) )

#define evpn_get_vlan_by_vid(P,VID) \
  ( evpn_find_vlan_by_vid((P), (VID)) ?: EVPN_ROOT_VLAN(P) )


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

static struct adata *
evpn_encap_ext_comms(struct evpn_proto *p)
{
  size_t len = list_length(&p->encaps) * (2 * sizeof(u32));
  struct adata *ad = lp_alloc_adata(tmp_linpool, len);

  int pos = 0;
  WALK_LIST_(struct evpn_encap, encap, p->encaps)
  {
    u32 hi = EC_ENCAP << 16;
    u32 lo = encap->type;
    ec_put(int_set_get_data(ad), pos, ec_generic(hi, lo));
    pos += 2;
  }

  return ad;
}

/*
 * Since only one type of encapsulation is currently supported, return first
 * (and only) encapsulation. If there were more encapsulation types, we would
 * have to choose one here.
 */
static inline struct evpn_encap *
evpn_get_encap(struct evpn_proto *p)
{
  ASSERT(list_length(&p->encaps) == 1);
  struct evpn_encap *encap = SKIP_BACK(struct evpn_encap, n, HEAD(p->encaps));

  return encap;
}

static void
evpn_announce_mac(struct evpn_proto *p, const net_addr_eth *n0, rte *new)
{
  struct channel *c = p->evpn_channel;
  struct evpn_vlan *v = evpn_get_vlan_by_vid(p, n0->vid);

  net_addr *n = alloca(sizeof(net_addr_evpn_mac));
  net_fill_evpn_mac(n, p->rd, v->tag, n0->mac);

  if (new)
  {
    rte e = {
      .src = p->p.main_source,
    };

    ea_set_attr_u32(&e.attrs, &ea_gen_source, 0, RTS_EVPN);
    ea_set_attr_u32(&e.attrs, &ea_gen_preference, 0, c->preference);

    ip_addr nh = evpn_get_encap(p)->router_addr;
    ea_set_attr_data(&e.attrs, ea_bgp_next_hop, BAF_TRANSITIVE, &nh, sizeof(nh));

    u32 label = v->vni;
    ea_set_attr_data(&e.attrs, ea_bgp_mpls_label_stack, 0, &label, sizeof(label));

    struct adata *ec = evpn_encap_ext_comms(p);
    struct adata *ad = evpn_export_targets(p, ec);
    ea_set_attr(&e.attrs, EA_LITERAL_DIRECT_ADATA(ea_bgp_ext_community, BAF_OPTIONAL | BAF_TRANSITIVE, ad));

    ea_set_attr_u32(&e.attrs, &ea_gen_mpls_label, 0, v->vni);

    rte_update(c, n, &e, p->p.main_source);
  }
  else
  {
    rte_update(c, n, NULL, p->p.main_source);
  }
}

static void
evpn_announce_imet(struct evpn_proto *p, struct evpn_vlan *v, int new)
{
  struct channel *c = p->evpn_channel;
  struct evpn_encap *encap = evpn_get_encap(p);

  /* We assume only one encapsulation */
  net_addr *n = alloca(sizeof(net_addr_evpn_imet));
  net_fill_evpn_imet(n, p->rd, v->tag, encap->router_addr);

  if (new)
  {
    rte e = {
      .src = p->p.main_source,
    };

    ea_set_attr_u32(&e.attrs, &ea_gen_source, 0, RTS_EVPN);
    ea_set_attr_u32(&e.attrs, &ea_gen_preference, 0, c->preference);

    ip_addr nh = encap->router_addr;
    ea_set_attr_data(&e.attrs, ea_bgp_next_hop, BAF_TRANSITIVE, &nh, sizeof(nh));

    struct adata *ec = evpn_encap_ext_comms(p);
    struct adata *ad = evpn_export_targets(p, ec);
    ea_set_attr(&e.attrs, EA_LITERAL_DIRECT_ADATA(ea_bgp_ext_community, BAF_OPTIONAL | BAF_TRANSITIVE, ad));

    ad = bgp_pmsi_new_ingress_replication(tmp_linpool, encap->router_addr, v->vni);
    ea_set_attr(&e.attrs, EA_LITERAL_DIRECT_ADATA(ea_bgp_pmsi_tunnel, BAF_OPTIONAL | BAF_TRANSITIVE, ad));

    rte_update(c, n, &e, p->p.main_source);
  }
  else
  {
    rte_update(c, n, NULL, p->p.main_source);
  }
}

static struct evpn_encap *
evpn_match_encap_by_ext_comms(struct evpn_proto *p, const struct adata *ad)
{
  bool has_any_encap = false;

  /* Find encapsulation communities */
  EC_SET_WALK(ec, ad)
  {
    uint type = ec >> 48;
    if (type != EC_ENCAP)
      continue;

    has_any_encap = true;

    /* Match encapsulation type */
    WALK_LIST_(struct evpn_encap, encap, p->encaps)
      if (encap->type == (ec & 0xff))
	return encap;
  }
  EC_SET_WALK_END;

  /* If there is any encapsulation, just not matching one, treat it as error */
  if (has_any_encap)
    return NULL;

  /* If there is no encapsulation, use default one */
  WALK_LIST_(struct evpn_encap, encap, p->encaps)
    if (encap->is_default)
      return encap;

  /* If there is no default encapsulation, treat it as error */
  return NULL;
}

#define BAD(msg, args...) \
  ({ log(L_ERR "%s: " msg, p->p.name, ## args); goto withdraw; })

static void
evpn_receive_mac(struct evpn_proto *p, const net_addr_evpn_mac *n0, rte *new)
{
  struct channel *c = p->eth_channel;
  struct rte_src *s = rt_get_source(&p->p, rd_to_u64(n0->rd));
  struct evpn_vlan *v = evpn_get_vlan_by_tag(p, n0->tag);

  net_addr_union nau;
  net_fill_eth(&nau.n, n0->mac, v->vid);

  if (new && rte_resolvable(new))
  {
    eattr *nh = ea_find(new->attrs, ea_bgp_next_hop);
    if (!nh)
      BAD("Missing NEXT_HOP attribute in %N", n0);

    eattr *ms = ea_find(new->attrs, ea_bgp_mpls_label_stack);
    if (!ms)
      BAD("Missing MPLS label stack in %N", n0);

    const struct adata *ad = ea_get_adata(new->attrs, ea_bgp_ext_community);
    struct evpn_encap *encap = evpn_match_encap_by_ext_comms(p, ad);

    if (!encap)
      BAD("No matching encapsulation found for %N", n0);

    rte e = {
      .src = s,
    };

    ea_set_attr_u32(&e.attrs, &ea_gen_source, 0, RTS_EVPN);
    ea_set_attr_u32(&e.attrs, &ea_gen_preference, 0, c->preference);

    struct nexthop_adata_mpls nam = {
      .nhad.nh.gw = *((ip_addr *) nh->u.ptr->data),
      .nhad.nh.iface = encap->tunnel_dev,
    };

    nam.nhad.nh.labels = MIN(ms->u.ptr->length / 4, MPLS_MAX_LABEL_STACK);
    memcpy(nam.nhad.nh.label, ms->u.ptr->data, nam.nhad.nh.labels * 4);

    nam.nhad.ad.length = (byte *) NEXTHOP_NEXT(&nam.nhad.nh) - nam.nhad.ad.data;
    ea_set_attr_data(&e.attrs, &ea_gen_nexthop, 0, nam.nhad.ad.data, nam.nhad.ad.length);

    /* Hack to handle src_vni in bridge code */
    ea_set_attr_u32(&e.attrs, &ea_gen_mpls_label, 0, v->vni);

    rte_update(c, &nau.n, &e, s);
  }
  else
  {
  withdraw:
    rte_update(c, &nau.n, NULL, s);
  }

  rt_unlock_source(s);
}

static void
evpn_receive_imet(struct evpn_proto *p, const net_addr_evpn_imet *n0, rte *new)
{
  struct channel *c = p->eth_channel;
  struct rte_src *s = rt_get_source(&p->p, rd_to_u64(n0->rd));
  struct evpn_vlan *v = evpn_get_vlan_by_tag(p, n0->tag);

  net_addr_union nau;
  net_fill_eth(&nau.n, MAC_NONE, v->vid);

  if (new && rte_resolvable(new))
  {
    eattr *pt = ea_find(new->attrs, ea_bgp_pmsi_tunnel);
    if (!pt)
      BAD("Missing PMSI_TUNNEL attribute in %N", n0);

    uint pmsi_type = bgp_pmsi_get_type(pt->u.ptr);
    if (pmsi_type != BGP_PMSI_TYPE_INGRESS_REPLICATION)
      BAD("Unsupported PMSI_TUNNEL type %u in %N", pmsi_type, n0);

    const struct adata *ad = ea_get_adata(new->attrs, ea_bgp_ext_community);
    struct evpn_encap *encap = evpn_match_encap_by_ext_comms(p, ad);

    if (!encap)
      BAD("No matching encapsulation found for %N", n0);

    rte e = {
      .src = s,
    };

    ea_set_attr_u32(&e.attrs, &ea_gen_source, 0, RTS_EVPN);
    ea_set_attr_u32(&e.attrs, &ea_gen_preference, 0, c->preference);

    struct nexthop_adata_mpls nam = {
      .nhad.nh.gw = bgp_pmsi_ir_get_endpoint(pt->u.ptr),
      .nhad.nh.iface = encap->tunnel_dev,
    };

    nam.nhad.nh.labels = 1;
    nam.nhad.nh.label[0] = bgp_pmsi_get_label(pt->u.ptr);

    nam.nhad.ad.length = (byte *) NEXTHOP_NEXT(&nam.nhad.nh) - nam.nhad.ad.data;
    ea_set_attr_data(&e.attrs, &ea_gen_nexthop, 0, nam.nhad.ad.data, nam.nhad.ad.length);

    /* Hack to handle src_vni in bridge code */
    ea_set_attr_u32(&e.attrs, &ea_gen_mpls_label, 0, v->vni);

    rte_update(c, &nau.n, &e, s);
  }
  else
  {
  withdraw:
    rte_update(c, &nau.n, NULL, s);
  }

  rt_unlock_source(s);
}

static void
evpn_rt_notify(struct proto *P, struct channel *c0 UNUSED, const net_addr *n, rte *new, const rte *old UNUSED)
{
  struct evpn_proto *p = (void *) P;

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
evpn_validate_iface_attrs(struct evpn_proto *p, const struct iface *i)
{
  if (!i->attrs)
    return 0;

  struct evpn_encap *encap = evpn_get_encap(p);

  if (encap->tunnel_dev != i)
    return 0;

  const eattr *ipa = ea_find(i->attrs, &ea_iface_vxlan_ip_addr);

  u32 type = ea_get_int(i->attrs, &ea_iface_type, IF_TYPE_UNDEF);
  u32 if_vni = ea_get_int(i->attrs, &ea_iface_vxlan_id, 0);

  if (type != IF_TYPE_VXLAN || !ipa)
    return 0;

  ip_addr rt_addr;
  ASSERT(sizeof(rt_addr) == ipa->u.ptr->length);
  memcpy(&rt_addr, ipa->u.ptr->data, ipa->u.ptr->length);

  struct evpn_config *cf = SKIP_BACK(struct evpn_config, c, p->p.cf);

  /*
   * VLANs -> if_vni must be 0
   * no VLAN, cf->vni defined -> if_vni must be 0 or cf->vni
   * no VLAN, cf->vni undefined -> if_vni can be anything (nonzero)
   */

  if ((cf->vni == U32_UNDEF) && (if_vni == 0))
  {
    log(L_ERR "%s: Unknown VNI", p->p.name);
    return 0;
  }

  u32 req_vni = EMPTY_LIST(cf->vlans) ? cf->vni : 0;
  if ((cf->vni != U32_UNDEF) && (if_vni != 0) && (if_vni != req_vni))
  {
    log(L_ERR "%s: VNI mismatch", p->p.name);
    return 0;
  }

  if ((cf->vni == U32_UNDEF) && (if_vni != 0))
    p->vni = if_vni;


  if (ipa_zero(encap->router_addr) && ipa_zero(rt_addr))
  {
    log(L_ERR "%s: Unknown router IP", p->p.name);
    return 0;
  }

  if (!ipa_zero(encap->router_addr) && !ipa_zero(rt_addr) && !ipa_equal(encap->router_addr, rt_addr))
  {
    log(L_ERR "%s: Router IP mismatch", p->p.name);
    return 0;
  }

  if (ipa_zero(encap->router_addr) && !ipa_zero(rt_addr))
    encap->router_addr = rt_addr;

  return 1;
}

static int
evpn_preexport(struct channel *C, rte *e)
{
  struct evpn_proto *p = (void *) C->proto;
  const net_addr *n = e->net;

  if (e->sender == C->in_req.hook)
    return -1;	/* Avoid local loops automatically */

  switch (n->type)
  {
  case NET_ETH:
  {
    u32 vid = ((const net_addr_eth *) n)->vid;

    if ((vid != p->vid) && !evpn_find_vlan_by_vid(p, vid))
      return -1;

    return 0;
  }

  case NET_EVPN:
  {
    u32 tag = ((const net_addr_evpn *) n)->tag;

    if (!evpn_import_targets(p, ea_get_adata(e->attrs, ea_bgp_ext_community)))
      return -1;

    if ((tag != p->tagX) && !evpn_find_vlan_by_tag(p, tag))
      return -1;

    return 0;
  }

  case NET_MPLS:
    return -1;

  default:
    bug("invalid type");
  }
}

static int
evpn_reload_routes(struct channel *C, struct rt_feeding_request *rfr)
{
  struct evpn_proto *p = (void *) C->proto;

  /* No partial reload implementation */
  if (rfr->prefilter.mode)
    return 0;

  /* route reload on one channel is just refeed on the other */
  switch (C->net_type)
  {
  case NET_ETH:
    rt_export_refeed(&p->evpn_channel->out_req, rfr);
    break;

  case NET_EVPN:
    rt_export_refeed(&p->eth_channel->out_req, rfr);
    break;

  case NET_MPLS:
    rt_export_refeed(&p->eth_channel->out_req, rfr);
    break;
  }

  return 1;
}

static void
evpn_feed_end(struct channel *C)
{
  struct evpn_proto *p = (void *) C->proto;

  switch (C->net_type)
  {
  case NET_ETH:
    if (p->evpn_refreshing)
    {
      rt_refresh_end(&p->evpn_channel->in_req);
      p->evpn_refreshing = false;
    }
    break;

  case NET_EVPN:
    if (p->eth_refreshing)
    {
      rt_refresh_end(&p->eth_channel->in_req);
      p->eth_refreshing = false;
    }
    break;

  case NET_MPLS:
    break;
  }
}

static inline u32
evpn_metric(const rte *e)
{
  struct eattr *ea = ea_find(e->attrs, &ea_gen_igp_metric) ?: ea_find(e->attrs, &ea_gen_local_metric);
  return ea ? MIN(ea->u.data, IGP_METRIC_UNKNOWN) : 0;
}

static int
evpn_rte_better(const rte *new, const rte *old)
{
  /* This is hack, we should have full BGP-style comparison */
  return evpn_metric(new) < evpn_metric(old);
}


/*
 *	EVPN encapsulations
 */

static struct evpn_encap *
evpn_new_encap(struct evpn_proto *p, const struct evpn_encap_config *ec)
{
  struct evpn_encap *e = mb_allocz(p->p.pool, sizeof(*e));

  *e = (struct evpn_encap) {
    .type        = ec->type,
    .tunnel_dev  = ec->tunnel_dev,
    .router_addr = ec->router_addr,
    .is_default  = ec->is_default,
  };

  add_tail(&p->encaps, &e->n);

  return e;
}

static inline int
evpn_reconfigure_encap(struct evpn_proto *p UNUSED, struct evpn_encap *e, struct evpn_encap_config *ec)
{
  if ((e->type != ec->type) ||
      (e->tunnel_dev != ec->tunnel_dev)	||
      (!ipa_zero(ec->router_addr) && !ipa_equal(e->router_addr, ec->router_addr)))
    return 0;

  return 1;
}

static int
evpn_reconfigure_encaps(struct evpn_proto *p, struct evpn_config *cf)
{
  ASSERT(list_length(&p->encaps) == 1);
  ASSERT(list_length(&cf->encaps) == 1);

  struct evpn_encap *e = evpn_get_encap(p);
  struct evpn_encap_config *ec = SKIP_BACK(struct evpn_encap_config, n, HEAD(cf->encaps));

  if (!e || !ec)
    return 0;

  return evpn_reconfigure_encap(p, e, ec);
}

static void
evpn_postconfig_encaps(struct evpn_config *cf)
{
  bool encap_types[EVPN_ENCAP_TYPE_MAX] = { 0 };
  bool has_encap = false;

  WALK_LIST_(struct evpn_encap_config, ec, cf->encaps)
  {
    if (encap_types[ec->type])
      cf_error("Only one encapsulation of each type is allowed");

    encap_types[ec->type] = true;
    has_encap = true;
  }

  if (!has_encap)
    cf_error("There must be at least one encapsulation");
}


/*
 *	EVPN VLANs
 */

#define VLAN_TAG_KEY(v)		v->tag
#define VLAN_TAG_NEXT(v)	v->next_tag
#define VLAN_TAG_EQ(v1,v2)	v1 == v2
#define VLAN_TAG_FN(v)		u32_hash(v)

#define VLAN_TAG_REHASH		evpn_tag_rehash
#define VLAN_TAG_PARAMS		/8, *2, 2, 2, 4, 24


#define VLAN_VID_KEY(v)		v->vid
#define VLAN_VID_NEXT(v)	v->next_vid
#define VLAN_VID_EQ(v1,v2)	v1 == v2
#define VLAN_VID_FN(v)		u32_hash(v)

#define VLAN_VID_REHASH		evpn_vid_rehash
#define VLAN_VID_PARAMS		/8, *2, 2, 2, 4, 16


HASH_DEFINE_REHASH_FN(VLAN_TAG, struct evpn_vlan)
HASH_DEFINE_REHASH_FN(VLAN_VID, struct evpn_vlan)


static struct evpn_vlan *
evpn_new_vlan(struct evpn_proto *p, struct evpn_vlan_config *cf, uint index)
{
  struct evpn_vlan *v = mb_allocz(p->p.pool, sizeof(struct evpn_vlan));

  v->tag = cf->id + index;
  v->vni = cf->vni + index;
  v->vid = cf->vid + index;

  if (!p->vlan_tag_hash.data)
    HASH_INIT(p->vlan_tag_hash, p->p.pool, 4);

  if (!p->vlan_vid_hash.data)
    HASH_INIT(p->vlan_vid_hash, p->p.pool, 4);

  add_tail(&p->vlans, &v->n);
  HASH_INSERT2(p->vlan_tag_hash, VLAN_TAG, p->p.pool, v);
  HASH_INSERT2(p->vlan_vid_hash, VLAN_VID, p->p.pool, v);

  return v;
}

static struct evpn_vlan *
evpn_find_vlan_by_tag(struct evpn_proto *p, u32 tag)
{
  return p->vlan_tag_hash.data ? HASH_FIND(p->vlan_tag_hash, VLAN_TAG, tag) : NULL;
}

static struct evpn_vlan *
evpn_find_vlan_by_vid(struct evpn_proto *p, u32 vid)
{
  return p->vlan_vid_hash.data ? HASH_FIND(p->vlan_vid_hash, VLAN_VID, vid) : NULL;
}

static void
evpn_remove_vlan(struct evpn_proto *p, struct evpn_vlan *v)
{
  rem_node(&v->n);
  HASH_REMOVE2(p->vlan_tag_hash, VLAN_TAG, p->p.pool, v);
  HASH_REMOVE2(p->vlan_vid_hash, VLAN_VID, p->p.pool, v);

  mb_free(v);
}

static void
evpn_publish_vlan_request(struct evpn_proto *p, struct vlan_request *req, bool update, int vlan_count)
{
  struct evpn_encap *encap = evpn_get_encap(p);

  /* Fill header */
  *req = (struct vlan_request) {
    .bridge = encap->tunnel_dev->master,
    .iface = encap->tunnel_dev,
    .owner = (uintptr_t) p,
    .update = update,
    .vlan_count = vlan_count,
  };

  TRACE(D_EVENTS, "VLAN %s published for %d VLANs on %s",
	(update ? "request" : "withdraw"), vlan_count, req->iface->name);

  ps_publish(p->vlan_pub, req, VLAN_REQUEST_LENGTH(vlan_count));
}

static void
evpn_request_vlan(struct evpn_proto *p, struct evpn_vlan *v, bool update)
{
  struct vlan_request *req = alloca(VLAN_REQUEST_LENGTH(1));

  req->vlans[0].vid = v->vid;
  req->vlans[0].vni = v->vni;

  evpn_publish_vlan_request(p, req, update, 1);
}

static void
evpn_request_vlans(struct evpn_proto *p)
{
  struct vlan_request *req = alloca(VLAN_REQUEST_LENGTH(32));

  int i = 0;
  WALK_LIST_(struct evpn_vlan, v, p->vlans)
  {
    req->vlans[i].vid = v->vid;
    req->vlans[i].vni = v->vni;
    i++;

    if (i == 32)
    {
      evpn_publish_vlan_request(p, req, true, i);
      i = 0;
    }
  }

  if (i > 0)
    evpn_publish_vlan_request(p, req, true, i);
}

static void
evpn_withdraw_vlans(struct evpn_proto *p)
{
  struct vlan_request req;
  evpn_publish_vlan_request(p, &req, false, 0);
}

static void
evpn_vlan_subscribe_hook(ps_publisher *pub)
{
  evpn_request_vlans(pub->data);
}

static inline int
evpn_reconfigure_vlan(struct evpn_proto *p UNUSED, struct evpn_vlan *v, struct evpn_vlan_config *cf, uint index)
{
  return
    (v->vni == cf->vni + index) &&
    (v->vid == cf->vid + index);
}

static int
evpn_reconfigure_vlans(struct evpn_proto *p, struct evpn_config *cf)
{
  list old_vlans;
  init_list(&old_vlans);
  add_tail_list(&old_vlans, &p->vlans);
  init_list(&p->vlans);
  int changed = 0;

  struct evpn_vlan_config *vc;
  WALK_LIST(vc, cf->vlans)
    for (uint i = 0; i < vc->range; i++)
    {
      struct evpn_vlan *v = evpn_find_vlan_by_tag(p, vc->id + i);

      if (v && evpn_reconfigure_vlan(p, v, vc, i))
      {
	rem_node(&v->n);
	add_tail(&p->vlans, &v->n);
	continue;
      }

      if (v)
      {
	evpn_request_vlan(p, v, false);
	evpn_remove_vlan(p, v);
      }

      v = evpn_new_vlan(p, vc, i);
      evpn_request_vlan(p, v, true);
      // evpn_announce_imet(p, v, 1);
      changed = 1;
    }

  struct evpn_vlan *v, *v2;
  WALK_LIST_DELSAFE(v, v2, old_vlans)
  {
    // evpn_announce_imet(p, v, 0);
    evpn_request_vlan(p, v, false);
    evpn_remove_vlan(p, v);
    changed = 1;
  }

  if (changed)
  {
    TRACE(D_EVENTS, "VLANs changed");

    /* Should not happend */
    if ((p->eth_channel->channel_state != CS_UP) ||
	(p->evpn_channel->channel_state != CS_UP))
      return 0;

    /*
     * We hard-reload channels by switching to CS_START and CS_UP, this resets
     * export maps so we do not get withdraws related to old exports, only
     * updates that are processed through the new VLAN mapping. On export,
     * rt_refresh_begin() / rt_refresh_end() is used for clean-up of old routes.
     *
     * Note: This is very fragile and expects that the channel manages to stop
     * exports synchronously.
     */

    rt_refresh_begin(&p->eth_channel->in_req);
    p->eth_refreshing = true;

    rt_refresh_begin(&p->evpn_channel->in_req);
    p->evpn_refreshing = true;

    channel_set_state(p->eth_channel, CS_PAUSE);
    channel_set_state(p->eth_channel, CS_UP);

    channel_set_state(p->evpn_channel, CS_PAUSE);
    channel_set_state(p->evpn_channel, CS_UP);

    WALK_LIST(v, p->vlans)
      evpn_announce_imet(p, v, 1);
  }

  return 1;
}


#define EVPN_VLAN_CONFIG_OPS(KEY) \
  evpn_vlan_config_get_##KEY, evpn_vlan_config_compare_by_##KEY

#define EVPN_DEFINE_VLAN_CONFIG_OPS(KEY)				\
									\
static u32								\
evpn_vlan_config_get_##KEY(const struct evpn_vlan_config *vc)		\
{ return vc->KEY; }							\
									\
static int								\
evpn_vlan_config_compare_by_##KEY(const void *vc1_, const void *vc2_)	\
{									\
  const struct evpn_vlan_config * const *vc1 = vc1_;			\
  const struct evpn_vlan_config * const *vc2 = vc2_;			\
  return uint_cmp((*vc1)->KEY, (*vc2)->KEY);				\
}

MACRO_FOREACH(EVPN_DEFINE_VLAN_CONFIG_OPS, id, vni, vid)

static void
evpn_check_intersections(struct evpn_vlan_config **vlans, int num_vlans, char *name,
			 u32 (*vlan_config_get) (const struct evpn_vlan_config *vc),
			 int (*vlan_config_compare) (const void *vc1_, const void *vc2_))
{
  qsort(vlans, num_vlans, sizeof(struct evpn_vlan_config *), vlan_config_compare);

  const struct evpn_vlan_config *o = NULL;
  uint max = 0;

  for (int i = 0; i < num_vlans; i++)
  {
    const struct evpn_vlan_config *v = vlans[i];
    uint lo = vlan_config_get(v);

    if (lo < max)
    {
      if ((o->range == 1) && (v->range == 1))
	cf_error("VLAN %s %u defined multiple times", name, lo);
      else
	cf_error("VLAN %s %u collision between vlan %u-%u and vlan %u-%u",
		 name, lo, o->id, o->id + o->range - 1, v->id, v->id + v->range - 1);
    }

    o = v;
    max = lo + v->range;
  }
}

static void
evpn_postconfig_vlans(struct evpn_config *cf)
{
  /* VLAN non-intersection check */

  int num_vlans = list_length(&cf->vlans);
  struct evpn_vlan_config **vlans = tmp_alloc(num_vlans * sizeof(struct evpn_vlan_config *));

  {
    int i = 0;
    struct evpn_vlan_config *vc;
    WALK_LIST(vc, cf->vlans)
      vlans[i++] = vc;
  }

  evpn_check_intersections(vlans, num_vlans, "tag", EVPN_VLAN_CONFIG_OPS(id));
  evpn_check_intersections(vlans, num_vlans, "VNI", EVPN_VLAN_CONFIG_OPS(vni));
  evpn_check_intersections(vlans, num_vlans, "VID", EVPN_VLAN_CONFIG_OPS(vid));
}


/*
 *	EVPN protocol glue
 */

static void evpn_started(struct evpn_proto *p, struct iface *i);
static int evpn_shutdown(struct proto *P);

static void
evpn_if_notify(struct proto *P, unsigned flags, struct iface *iface)
{
  struct evpn_proto *p = SKIP_BACK(struct evpn_proto, p, P);
  struct evpn_encap *encap = evpn_get_encap(p);

  if (flags & IF_IGNORE)
    return;

  if (iface != encap->tunnel_dev)
    return;

  if ((p->p.proto_state == PS_START) && (flags & IF_CHANGE_UP))
    evpn_started(p, iface);
  else if (flags & IF_CHANGE_DOWN)
    proto_notify_state(&p->p, evpn_shutdown(&p->p));
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

  /* When VLANs are configured, VNI cannot be learned */
  if ((cf->vni == U32_UNDEF) && !EMPTY_LIST(cf->vlans))
    cf->vni = 0;

  evpn_postconfig_encaps(cf);
  evpn_postconfig_vlans(cf);
}

struct rte_owner_class evpn_rte_owner_class = {
  .rte_better = evpn_rte_better,
};

static struct proto *
evpn_init(struct proto_config *CF)
{
  static bool bgp_attributes_resolved = false;
  if (!bgp_attributes_resolved)
  {
    ea_bgp_next_hop = ea_class_find_by_name("bgp_next_hop");
    ea_bgp_ext_community = ea_class_find_by_name("bgp_ext_community");
    ea_bgp_pmsi_tunnel = ea_class_find_by_name("bgp_pmsi_tunnel");
    ea_bgp_mpls_label_stack = ea_class_find_by_name("bgp_mpls_label_stack");
    bgp_attributes_resolved = true;
  }

  struct proto *P = proto_new(CF);
  struct evpn_proto *p = (void *) P;
  // struct evpn_config *cf = (void *) CF;

  proto_configure_channel(P, &p->eth_channel, proto_cf_find_channel(CF, NET_ETH));
  proto_configure_channel(P, &p->evpn_channel, proto_cf_find_channel(CF, NET_EVPN));
  proto_configure_mpls_channel(P, CF, RTS_EVPN);

  P->rt_notify = evpn_rt_notify;
  P->iface_sub.if_notify = evpn_if_notify;
  P->preexport = evpn_preexport;
  P->reload_routes = evpn_reload_routes;
  P->export_fed = evpn_feed_end;

  P->sources.class = &evpn_rte_owner_class;

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

  p->vni = cf->vni;
  p->vid = cf->vid;
  p->tagX = cf->tagX;

  init_list(&p->encaps);
  WALK_LIST_(struct evpn_encap_config, ec, cf->encaps)
    evpn_new_encap(p, ec);

  struct evpn_encap *encap = evpn_get_encap(p);
  p->vlan_pub = ps_publisher_new(p->p.pool, evpn_vlan_subscribe_hook, p);
  ps_attach_topic(p->vlan_pub, &vlan_requests, encap->tunnel_dev->master->name);

  init_list(&p->vlans);
  memset(&p->vlan_tag_hash, 0, sizeof(p->vlan_tag_hash));
  memset(&p->vlan_vid_hash, 0, sizeof(p->vlan_vid_hash));

  struct evpn_vlan_config *vc;
  WALK_LIST(vc, cf->vlans)
    for (uint i = 0; i < vc->range; i++)
      evpn_new_vlan(p, vc, i);

  evpn_request_vlans(p);

  evpn_prepare_import_targets(p);
  evpn_prepare_export_targets(p);

  /*

  // XXX ?
  if (P->vrf_set)
    P->mpls_map->vrf_iface = P->vrf;
  */

  /* Wait for VXLAN interfaces to be up */

  return PS_START;
}

static void
evpn_started(struct evpn_proto *p, struct iface *i)
{
  if (!evpn_validate_iface_attrs(p, i))
    return;

  proto_notify_state(&p->p, PS_UP);

  evpn_announce_imet(p, EVPN_ROOT_VLAN(p), 1);

  WALK_LIST_(struct evpn_vlan, v, p->vlans)
    evpn_announce_imet(p, v, 1);
}

static int
evpn_shutdown(struct proto *P)
{
  struct evpn_proto *p = (void *) P;

  evpn_withdraw_vlans(p);

  return PS_FLUSH;
}

static int
evpn_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct evpn_proto *p = (void *) P;
  struct evpn_config *cf = (void *) CF;

  if (!proto_configure_channel(P, &p->eth_channel, proto_cf_find_channel(CF, NET_ETH)) ||
      !proto_configure_channel(P, &p->evpn_channel, proto_cf_find_channel(CF, NET_EVPN)) ||
      !proto_configure_mpls_channel(P, CF, RTS_EVPN))
    return 0;

  if (!rd_equal(p->rd, cf->rd) ||
      ((cf->vni != U32_UNDEF) && (p->vni != cf->vni)) ||
      (p->vid != cf->vid))
    return 0;

  if (!evpn_reconfigure_encaps(p, cf))
    return 0;

  int import_changed = !same_tree(p->import_target, cf->import_target);
  int export_changed = !same_tree(p->export_target, cf->export_target);

  /* Update pointers to config structures */
  p->import_target = cf->import_target;
  p->export_target = cf->export_target;

  if (import_changed)
  {
    TRACE(D_EVENTS, "Import target changed");

    evpn_prepare_import_targets(p);

    if (p->evpn_channel->channel_state == CS_UP)
      channel_request_full_refeed(p->evpn_channel);
  }

  if (export_changed)
  {
    TRACE(D_EVENTS, "Export target changed");

    evpn_prepare_export_targets(p);

    if (p->eth_channel->channel_state == CS_UP)
      channel_request_full_refeed(p->eth_channel);
  }

  if (!evpn_reconfigure_vlans(p, cf))
    return 0;

  return 1;
}

static void
evpn_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct evpn_config *d = SKIP_BACK(struct evpn_config, c, dest);
  struct evpn_config *s = SKIP_BACK(struct evpn_config, c, src);

  cfg_copy_list(&d->encaps, &s->encaps, sizeof(struct evpn_encap_config));
  cfg_copy_list(&d->vlans, &s->vlans, sizeof(struct evpn_vlan_config));
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
