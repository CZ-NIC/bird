/*
 *	BIRD -- Layer3 VPN Protocol Configuration
 *
 *	(c) 2011-2013 Yandex, LLC
 *      Author: Alexander V. Chernikov <melifaro@yandex-team.ru>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/l3vpn/l3vpn.h"

CF_DEFINES

#define L3VPN_CFG ((struct l3vpn_config *) this_proto)

CF_DECLS

CF_KEYWORDS(L3VPN, RD, LABEL, AUTO)

CF_GRAMMAR

CF_ADDTO(proto, l3vpn_proto l3vpn_proto_end '}' )

l3vpn_proto_start: proto_start L3VPN {
  this_proto = proto_config_new(&proto_l3vpn, $1);
};

l3vpn_proto:
   l3vpn_proto_start proto_name '{'
 | l3vpn_proto proto_item ';'
 | l3vpn_proto proto_channel ';' {
  switch (((struct channel_config *)$2)->net_type) {
    case NET_IP4:
    case NET_IP6:
      if (L3VPN_CFG->ip)
	cf_error("Multiple IP channels not supported");
      if (L3VPN_CFG->vpn &&
	  ((L3VPN_CFG->vpn->net_type == NET_VPN4 && ((struct channel_config *)$2)->net_type == NET_IP6)
	|| (L3VPN_CFG->vpn->net_type == NET_VPN6 && ((struct channel_config *)$2)->net_type == NET_IP4)))
	  cf_error("Mismatched IP/VPN families");

      L3VPN_CFG->ip = $2;
      break;
    case NET_VPN4:
    case NET_VPN6:
      if (L3VPN_CFG->vpn)
	cf_error("Multiple VPN channels not supported");

      if (L3VPN_CFG->ip &&
	  ((L3VPN_CFG->ip->net_type == NET_IP4 && ((struct channel_config *)$2)->net_type == NET_VPN6)
	|| (L3VPN_CFG->ip->net_type == NET_IP6 && ((struct channel_config *)$2)->net_type == NET_VPN4)))
	  cf_error("Mismatched IP/VPN families");

      L3VPN_CFG->vpn = $2;
      break;
    case NET_MPLS:
      if (L3VPN_CFG->mpls)
	cf_error("Multiple MPLS channels not supported");
      else
	L3VPN_CFG->mpls = $2;
      break;
    default:
      cf_error("Unsupported channel type");
  }
}
 | l3vpn_proto RD VPN_RD ';' { L3VPN_CFG->rd = $3; }
;
 
l3vpn_proto_end:
{
  if ((!L3VPN_CFG->ip) || (!L3VPN_CFG->vpn) || (!L3VPN_CFG->mpls))
    cf_error("Need all IP, VPN and MPLS channels configured.");
}


CF_CODE

CF_END
