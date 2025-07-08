/*
 *	BIRD -- BGP/MPLS Ethernet Virtual Private Networks (EVPN)
 *
 *	(c) 2023 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2023 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/evpn/evpn.h"


CF_DEFINES

static struct evpn_encap_config *this_evpn_encap;
static struct evpn_vlan_config *this_evpn_vlan;

#define EVPN_CFG ((struct evpn_config *) this_proto)


CF_DECLS

CF_KEYWORDS(EVPN, ROUTE, IMPORT, EXPORT, TARGET, RD, DISTINGUISHER, TUNNEL, DEVICE, VNI, VID, VLAN, RANGE, ENCAPSULATION, VXLAN, ROUTER, DEFAULT)

%type <e> evpn_targets
%type <cc> evpn_channel_start evpn_channel


CF_GRAMMAR

proto: evpn_proto;


evpn_channel_start: net_type_base
{
  /* Redefining proto_channel to change default values */
  $$ = this_channel = channel_config_get(NULL, net_label[$1], $1, this_proto);
  if (!this_channel->copy)
  {
    this_channel->out_filter = FILTER_ACCEPT;
    this_channel->preference = ($1 == NET_ETH) ?
      DEF_PREF_L3VPN_IMPORT :
      DEF_PREF_L3VPN_EXPORT;
  }
};

evpn_channel: evpn_channel_start channel_opt_list channel_end;

evpn_proto_start: proto_start EVPN
{
  this_proto = proto_config_new(&proto_evpn, $1);
  init_list(&EVPN_CFG->encaps);
  init_list(&EVPN_CFG->vlans);
};


evpn_proto_item:
   proto_item
 | evpn_channel
 | mpls_channel
 | RD VPN_RD { EVPN_CFG->rd = $2; }
 | ROUTE DISTINGUISHER VPN_RD { EVPN_CFG->rd = $3; }
 | IMPORT TARGET evpn_targets { EVPN_CFG->import_target = $3; }
 | EXPORT TARGET evpn_targets { EVPN_CFG->export_target = $3; }
 | ROUTE TARGET evpn_targets { EVPN_CFG->import_target = EVPN_CFG->export_target = $3; }
 | VNI expr { EVPN_CFG->vni = $2; }
 | VID expr { EVPN_CFG->vid = $2; if ($2 > 4095) cf_error("VID must be in range 0-4095"); }
 | TAG expr { EVPN_CFG->tagX = $2; }
 | evpn_encap
 | evpn_vlan
 ;

evpn_proto_opts:
   /* empty */
 | evpn_proto_opts evpn_proto_item ';'
 ;

evpn_proto:
   evpn_proto_start proto_name '{' evpn_proto_opts '}';


evpn_targets:
   ec_item { f_tree_only_rt($1); $$ = $1; }
 | '[' ec_items ']' { f_tree_only_rt($2); $$ = build_tree($2, true); }
 ;


evpn_encap: evpn_encap_start evpn_encap_opt_list evpn_encap_end;

evpn_encap_start: ENCAPSULATION VXLAN
{
  this_evpn_encap = cfg_allocz(sizeof(struct evpn_encap_config));
  add_tail(&EVPN_CFG->encaps, &this_evpn_encap->n);

  this_evpn_encap->type        = EVPN_ENCAP_TYPE_VXLAN;
  this_evpn_encap->router_addr = IPA_NONE;
  this_evpn_encap->is_default  = false;
}

evpn_encap_opt:
   TUNNEL DEVICE  text { this_evpn_encap->tunnel_dev  = if_get_by_name($3); }
 | ROUTER ADDRESS ipa  { this_evpn_encap->router_addr = $3; }
 | DEFAULT bool { this_evpn_encap->is_default = $2; }
 ;

evpn_encap_opts:
   /* empty */
 | evpn_encap_opts evpn_encap_opt ';'
 ;

evpn_encap_opt_list:
   /* empty */
 | '{' evpn_encap_opts '}'
 ;

evpn_encap_end:
{
  this_evpn_encap = NULL;
}


evpn_vlan: evpn_vlan_start evpn_vlan_opt_list evpn_vlan_end;

evpn_vlan_start: VLAN expr
{
  this_evpn_vlan = cfg_allocz(sizeof(struct evpn_vlan_config));
  add_tail(&EVPN_CFG->vlans, &this_evpn_vlan->n);
  this_evpn_vlan->id = $2;
  this_evpn_vlan->range = 1;
  this_evpn_vlan->vni = U32_UNDEF;
  this_evpn_vlan->vid = U32_UNDEF;
}

evpn_vlan_opt:
   RANGE expr { this_evpn_vlan->range = $2; }
 | VNI expr { this_evpn_vlan->vni = $2; if ($2 > EVPN_VNI_MAX) cf_error("VNI must be less than 2^24"); }
 | VID expr { this_evpn_vlan->vid = $2; if ($2 > EVPN_VID_MAX) cf_error("VID must be less than 2^12"); }
 ;

evpn_vlan_opts:
   /* empty */
 | evpn_vlan_opts evpn_vlan_opt ';'
 ;

evpn_vlan_opt_list:
   /* empty */
 | '{' evpn_vlan_opts '}'
 ;

evpn_vlan_end:
{
  struct evpn_vlan_config *vc = this_evpn_vlan;

  if (vc->vni == U32_UNDEF)
    vc->vni = vc->id;

  if (vc->vid == U32_UNDEF)
    vc->vid = vc->id;

  if (((u64) vc->id + vc->range - 1) > EVPN_TAG_MAX)
    cf_error("Last tag in range must be less than 2^32");

  if (((u64) vc->vni + vc->range - 1) > EVPN_VNI_MAX)
    cf_error("Last VNI in range must be less than 2^24");

  if (((u64) vc->vid + vc->range - 1) > EVPN_VID_MAX)
    cf_error("Last VID in range must be less than 2^12");

  this_evpn_vlan = NULL;
}


CF_CODE

CF_END
