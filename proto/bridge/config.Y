/*
 *	BIRD -- Linux Bridge Interface
 *
 *	(c) 2023 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2023 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/bridge/bridge.h"


CF_DEFINES

#define KBR_CFG ((struct kbr_config *) this_proto)


CF_DECLS

CF_KEYWORDS(BRIDGE, BRIDGE, DEVICE, VLAN, FILTERING, SCAN, TIME, KBR_SOURCE)


CF_GRAMMAR

proto: kbr_proto;


kbr_proto_start: proto_start BRIDGE
{
  this_proto = proto_config_new(&proto_bridge, $1);
  this_proto->net_type = NET_ETH;

  KBR_CFG->scan_time = 60 S_;
};

kbr_proto_item:
   proto_item
 | proto_channel { $1->ra_mode = RA_ANY; }
 | BRIDGE DEVICE text { KBR_CFG->bridge_dev = if_get_by_name($3); }
 | VLAN FILTERING bool { KBR_CFG->vlan_filtering = $3; }
 | SCAN TIME expr_us { KBR_CFG->scan_time = $3; }
 ;

kbr_proto_opts:
   /* empty */
 | kbr_proto_opts kbr_proto_item ';'
 ;

kbr_proto:
   kbr_proto_start proto_name '{' kbr_proto_opts '}';


dynamic_attr: KBR_SOURCE { $$ = f_new_dynamic_attr(EAF_TYPE_INT, T_INT, EA_KBR_SOURCE); } ;

CF_CODE

CF_END
