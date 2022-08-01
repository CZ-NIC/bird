/*
 *	BIRD -- Statistics Protocol Configuration
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/snmp/snmp.h"

CF_DEFINES

#define SNMP_CFG ((struct snmp_config *) this_proto)
#define SNMP_CC ((struct snmp_channel_config *) this_channel)

CF_DECLS

CF_KEYWORDS(SNMP, TABLE, PROTOCOL, BPG)

%type <cc> snmp_channel_start

CF_GRAMMAR

proto: snmp_proto '}' { this_channel = NULL; }  ;

snmp_proto:
   snmp_proto_start '{'
 | snmp_proto proto_item ';'
 | snmp_proto snmp_proto_channel ';'
 | snmp_proto  ';'
 ;

snmp_proto_start: proto_start SNMP
{
  this_proto = proto_config_new(&proto_snmp, $1);
}

snmp_proto_channel: snmp_channel_start snmp_channel_opt_list channel_end ;

snmp_channel_start: net_type symbol
{
  this_channel = channel_config_get(&channel_snmp, $2->name, $1, this_proto);
}

snmp_channel_opt_list:
    /* empty */
  | '{' snmp_opts '}'
  ;

snmp_opts:
    /* empty */
  | snmp_opts channel_item ';'
  | snmp_opts snmp_opt ';'
  ;

snmp_opt:
    PROTOCOL BGP symbol {
      SNMP_CC->bgp = NULL;

      struct proto_config *pc;
      WALK_LIST(pc, this_proto->global->protos)
	if (!strcmp(pc->name, $3->name)
	    && pc->protocol == &proto_bgp)
	  SNMP_CC->bgp = (struct bgp_config *) pc;

      if (!SNMP_CC->bgp) cf_error("BGP protocol %s not found", $3);
    }
  ;

CF_CODE

CF_END
