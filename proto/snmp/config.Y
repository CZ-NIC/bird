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

CF_DECLS

CF_KEYWORDS(SNMP, PROTOCOL, BGP, LOCAL, AS, REMOTE, ADDRESS, PORT, DESCRIPTION,
	    TIMEOUT, PRIORITY, CONTEXT, DEFAULT, MESSAGE)

CF_GRAMMAR

proto: snmp_proto ;

snmp_proto:
   snmp_proto_start proto_name '{' snmp_proto_opts '}' ;

snmp_proto_item:
   proto_item
 | snmp_bgp_bond
 /* | INTERFACE snmp_interface TODO */
 | LOCAL PORT expr {
    if (($3 < 1) || ($3 > 65535)) cf_error("Invalid port number");
    SNMP_CFG->local_port = $3;
  }
 | REMOTE PORT expr {
    if (($3 < 1) || ($3 > 65535)) cf_error("Invalid port number");
    SNMP_CFG->remote_port = $3;
  }
 | LOCAL ID IP4 { SNMP_CFG->bgp_local_id = $3; }
 | LOCAL ADDRESS IP4 { SNMP_CFG->local_ip = $3; }
 | REMOTE ADDRESS IP4 {
    if (ip4_zero($3)) cf_error("Invalid remote ip address");
    SNMP_CFG->remote_ip = $3;
  }
 | LOCAL AS expr {
    if ($3 < 1 || $3 > 65535) cf_error("Invalid local AS");
    SNMP_CFG->bgp_local_as = $3;
  }
 | SNMP DESCRIPTION text {
    if (strlen($3) > UINT32_MAX) cf_error("Description is too long");
    SNMP_CFG->description = $3;
  }
 | PRIORITY expr {
    if ($2 > 255) cf_error("Registration priority must be in range 0-255");
    SNMP_CFG->priority = $2;
  }
 | MESSAGE TIMEOUT expr_us {
    /* TODO */
    if ($3 TO_S > 255) log(L_WARN, "%s: msg", this_proto->name);
    if ($3 TO_S < 1) log(L_WARN, "%s: msg", this_proto->name);
    if (($3 TO_S) - (int)($3 TO_S) > 0) log(L_WARN, "%s: ", this_proto->name);
    SNMP_CFG->timeout = $3;
  }
/*
 | ERROR TIMEOUT expr_us {
    / * TODO * /
    SNMP_CFG->error_timeout = $3;
  }
*/
 | START DELAY TIME expr_us { SNMP_CFG->startup_delay = $4; }
 ;

snmp_proto_opts:
   /* empty */
 | snmp_proto_opts snmp_proto_item ';'
 ;

snmp_proto_start: proto_start SNMP
{
  this_proto = proto_config_new(&proto_snmp, $1);

  init_list(&SNMP_CFG->bgp_entries);
  SNMP_CFG->bonds = 0;

  SNMP_CFG->local_ip = IP4_NONE;
  SNMP_CFG->remote_ip = ip4_build(127,0,0,1);
  SNMP_CFG->bgp_local_id = IP4_NONE;
  SNMP_CFG->local_port = 0;
  SNMP_CFG->remote_port = 705;
  SNMP_CFG->bgp_local_as = 0;

  SNMP_CFG->description = "bird";
  SNMP_CFG->timeout = 15;
  SNMP_CFG->priority = AGENTX_PRIORITY;
}

snmp_bgp_bond: BGP symbol
{
  /* the snmp_context rule sets the correct value of this_bond */
  cf_assert_symbol($2, SYM_PROTO);

  if (!$2->proto) cf_error("BGP protocol %s not found", $2->name);

  cf_assert($2->proto->protocol == &proto_bgp,
    "SNMP BGP bond accepts only BGP protocols");

  struct bgp_config *bgp_config = SKIP_BACK(struct bgp_config, c, $2->proto);

  if (!ipa_is_ip4(bgp_config->remote_ip))
    cf_error("BGP4-MIB does not support IPv6 addresses.");

  struct snmp_bond *this_bond = cfg_alloc(sizeof(struct snmp_bond));
  this_bond->type = SNMP_BGP;
  this_bond->config = $2->proto;

  add_tail(&SNMP_CFG->bgp_entries, &this_bond->n);
  SNMP_CFG->bonds++;
}

CF_CODE

CF_END
