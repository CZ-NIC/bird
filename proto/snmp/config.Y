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

CF_DECLS

CF_KEYWORDS(SNMP, PROTOCOL, BPG, LOCAL, AS, REMOTE, PORT)

CF_GRAMMAR

proto: snmp_proto '}' { this_channel = NULL; }  ;

snmp_proto:
   snmp_proto_start '{'
 | snmp_proto proto_item ';'
 | snmp_proto snmp_bgp_bond ';'
 | snmp_proto LOCAL PORT expr ';' { SNMP_CFG->local_port = $4; if (($4<1) ||
($4>65535)) cf_error("Invalid port number"); }
 | snmp_proto REMOTE PORT expr ';' { SNMP_CFG->remote_port = $4; if (($4<1) ||
($4>65545)) cf_error("Invalid port number"); }
 | snmp_proto LOCAL ipa ';' { SNMP_CFG->local_ip = $3; }
 | snmp_proto REMOTE ipa ';' { SNMP_CFG->remote_ip = $3; if(ipa_zero($3))
cf_error("Invalid remote ip address"); }
 | snmp_proto LOCAL AS expr ';' { if ($4<1 || $4>65535) cf_error("invalid local as");
  SNMP_CFG->local_as = $4; }
 ;

snmp_proto_start: proto_start SNMP
{
  this_proto = proto_config_new(&proto_snmp, $1);

  init_list(&SNMP_CFG->bgp_entries);

  SNMP_CFG->local_ip = IPA_NONE;
  SNMP_CFG->remote_ip = ipa_build4(127,0,0,1);
  SNMP_CFG->local_port = 0;
  SNMP_CFG->remote_port = 705;
  SNMP_CFG->local_as = 0;

  SNMP_CFG->timeout = 15;
}

proto_name ;


snmp_bgp_bond: BGP symbol
{
  struct snmp_bond *this_bond = cfg_alloc(sizeof(struct snmp_bond));
  this_bond->type = SNMP_BGP;

  struct proto_config *pc;
  WALK_LIST(pc, this_proto->global->protos)
    if (!strcmp(pc->name, $2->name) && pc->protocol == &proto_bgp
        && !ipa_zero(((struct bgp_proto *) pc)->remote_ip)) 
      this_bond->proto = pc;

  if (!this_bond->proto) cf_error("BGP protocol %s not found", $2->name);
  add_tail(&SNMP_CFG->bgp_entries, (node *) this_bond);
}

CF_CODE

CF_END
