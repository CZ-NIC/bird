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

#define EVPN_CFG ((struct evpn_config *) this_proto)


CF_DECLS

CF_KEYWORDS(EVPN, ROUTE, IMPORT, EXPORT, TARGET, RD, DISTINGUISHER, TUNNEL, DEVICE, VNI, VID)

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
 | TUNNEL DEVICE text { EVPN_CFG->tunnel_dev = if_get_by_name($3); }
 | ROUTER ADDRESS ipa { EVPN_CFG->router_addr = $3; }
 | VNI expr { EVPN_CFG->vni = $2; }
 | VID expr { EVPN_CFG->vid = $2; if ($2 > 4095) cf_error("VID must be in range 0-4095"); }
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


CF_CODE

CF_END
