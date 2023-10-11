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
#include "proto/snmp/subagent.h"

CF_DEFINES

#define SNMP_CFG ((struct snmp_config *) this_proto)

struct snmp_bond *this_bond = NULL;

CF_DECLS

CF_KEYWORDS(SNMP, PROTOCOL, BPG, LOCAL, AS, REMOTE, ADDRESS, PORT, DESCRIPTION,
	    TIMEOUT, PRIORITY, CONTEXT, DEFAULT)

CF_GRAMMAR

proto: snmp_proto '}' { this_channel = NULL; }  ;

snmp_proto:
   snmp_proto_start '{'
 | snmp_proto proto_item ';'
 | snmp_proto snmp_bgp_bond ';'
 | snmp_proto LOCAL PORT expr ';' {
    if (($4 < 1) || ($4 > 65535)) cf_error("Invalid port number");
    SNMP_CFG->local_port = $4;
  }
 | snmp_proto REMOTE PORT expr ';' {
    if (($4 < 1) || ($4 > 65535)) cf_error("Invalid port number");
    SNMP_CFG->remote_port = $4;
  }
 | snmp_proto LOCAL ID ipa ';' { SNMP_CFG->bgp_local_id = $4; }
 | snmp_proto LOCAL ADDRESS ipa ';' { SNMP_CFG->local_ip = $4; }
 | snmp_proto REMOTE ADDRESS ipa ';' {
    if (ipa_zero($4)) cf_error("Invalid remote ip address");
    SNMP_CFG->remote_ip = $4;
  }
 | snmp_proto LOCAL AS expr ';' {
    if ($4 < 1 || $4 > 65535) cf_error("Invalid local AS");
    SNMP_CFG->bgp_local_as = $4;
  }
 | snmp_proto DESCRIPTION text ';' {
    if (strlen($3) > UINT32_MAX) cf_error("Description is too long");
    SNMP_CFG->description = $3;
  }
 | snmp_proto TIMEOUT expr ';' {
    if ($3 < 1 || $3 > 255) cf_error("Timeout must be in range 1-255");
    SNMP_CFG->timeout = $3;
  }
 | snmp_proto PRIORITY expr ';' {
    if ($3 > 255) cf_error("Registration priority must be in range 0-255");
    SNMP_CFG->priority = $3;
  }
 ;

snmp_proto_start: proto_start SNMP
{
  this_proto = proto_config_new(&proto_snmp, $1);

  init_list(&SNMP_CFG->bgp_entries);
  SNMP_CFG->bonds = 0;
  /* We always have the default context */
  SNMP_CFG->contexts = 1;

  SNMP_CFG->local_ip = IPA_NONE;
  SNMP_CFG->remote_ip = ipa_build4(127,0,0,1);
  SNMP_CFG->bgp_local_id = IPA_NONE;
  SNMP_CFG->local_port = 0;
  SNMP_CFG->remote_port = 705;
  SNMP_CFG->bgp_local_as = 0;

  SNMP_CFG->description = "bird";
  SNMP_CFG->timeout = 15;
  SNMP_CFG->priority = AGENTX_PRIORITY;
}

proto_name ;

snmp_context:
   /* empty */	  {
    if (!this_bond)
    {
      log(L_INFO "snmp_context no string alloc");
      this_bond = cfg_alloc(sizeof(struct snmp_bond));
    }

    this_bond->context = NULL;
  }
 | CONTEXT DEFAULT {
    if (!this_bond)
    {
      log(L_INFO "snmp_context CONTEXT DEFAULT alloc");
      this_bond = cfg_alloc(sizeof(struct snmp_bond));
    }
    this_bond->context = NULL;
  }
 | CONTEXT text {
    if(!this_bond)
    {
      log(L_INFO "snmp_context CONTEXT text alloc");
      this_bond = cfg_alloc(sizeof(struct snmp_bond));
    }
    this_bond->context = $2;
    SNMP_CFG->contexts++;
    log(L_INFO "storing context %s to bond at 0x%p", $2, this_bond);
  }
 ;

snmp_bgp_bond: BGP symbol snmp_context
{
  /* the snmp_context rule sets the correct value of this_bond */
  log(L_INFO "this_bond (at 0x%p) has value %s", this_bond,
    (this_bond->context) ? this_bond->context : "<no_val>");
  if (!this_bond)
  {
    log(L_INFO "snmp_bgp_bond BGP symbol ... alloc");
    this_bond = cfg_alloc(sizeof(struct snmp_bond));
    log(L_INFO "Unexpedted alloc in snmp_bgp_bond rule");
  }
  else
  {
    log(L_INFO, "working with this_bond (at 0x%p)", this_bond);
  }
  this_bond->type = SNMP_BGP;

  cf_assert_symbol($2, SYM_PROTO);
  this_bond->proto = $2->proto;

  if (!this_bond->proto) cf_error("BGP protocol %s not found", $2->name);
  add_tail(&SNMP_CFG->bgp_entries, &this_bond->n);
  SNMP_CFG->bonds++;

  this_bond = NULL;
}

CF_CODE

CF_END
