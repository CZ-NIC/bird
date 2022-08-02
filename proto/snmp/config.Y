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

CF_GRAMMAR

proto: snmp_proto '}' { this_channel = NULL; }  ;

snmp_proto:
   snmp_proto_start '{'
 | snmp_proto proto_item ';'
 | snmp_proto snmp_bgp_bond ';'
 | snmp_proto  ';'
 ;

snmp_proto_start: proto_start SNMP
{
  this_proto = proto_config_new(&proto_snmp, $1);
  init_list(&SNMP_CFG->bgp_entries);
}

snmp_bgp_bond: BGP symbol
{
  struct snmp_bond *this_bond = cfg_alloc(sizeof(struct snmp_bond));
  this_bond->type = SNMP_BGP;

  struct proto_config *pc;
  WALK_LIST(pc, this_proto->global->protos)
    if (!strcmp(pc->name, $2->name) && pc->protocol == &proto_bgp)
      this_bond->proto = pc;

  if (!this_bond->proto) cf_error("BGP protocol %s not found", $2->name);
  add_tail(&SNMP_CFG->bgp_entries, (node *) this_bond);
}

CF_CODE

CF_END
