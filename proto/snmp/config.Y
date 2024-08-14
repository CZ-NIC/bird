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
	    TIMEOUT, PRIORITY, CONTEXT, DEFAULT, MESSAGE, VERBOSE)

CF_GRAMMAR

proto: snmp_proto ;

snmp_proto:
   snmp_proto_start proto_name '{' snmp_proto_opts '}' ;

snmp_proto_item:
   proto_item
 | snmp_bgp_bond
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
 | REMOTE ADDRESS DEFAULT {
    if (SNMP_CFG->trans_type != SNMP_TRANS_DEFAULT)
      cf_error("Duplicit option remote address");
  }
 | REMOTE ADDRESS ipa {
    if (SNMP_CFG->trans_type != SNMP_TRANS_DEFAULT)
      cf_error("Duplicit option remote address");

    SNMP_CFG->remote_ip = $3;
    SNMP_CFG->trans_type = SNMP_TRANS_TCP;
  }
 | REMOTE ADDRESS text {
    if (SNMP_CFG->trans_type != SNMP_TRANS_DEFAULT)
      cf_error("Duplicit option remote address");

    if (strcmp($3, agentx_master_addr)) {
      SNMP_CFG->remote_path = $3;
      SNMP_CFG->trans_type = SNMP_TRANS_UNIX;
    }
  }
 | LOCAL AS expr {
    if ($3 < 1 || $3 > UINT16_MAX) cf_error("Invalid local AS");
    SNMP_CFG->bgp_local_as = $3;
  }
 | SNMP DESCRIPTION text {
    if (strlen($3) > UINT16_MAX - 1) cf_error("Description is too long");
    SNMP_CFG->description = $3;
  }
 | PRIORITY expr {
    if ($2 > 255) cf_error("Registration priority must be in range 0-255");
    SNMP_CFG->priority = $2;
  }
 | MESSAGE TIMEOUT expr_us {
    /* TODO */
    if ($3 TO_S > 255 || $3 TO_S < 1)
      log(L_WARN "resolution of AgentX message timeout is from 1 to 255 s.");
    if (($3 TO_S) - (int)($3 TO_S) > 0)
      log(L_WARN "AgentX message timeout cannot use second fraction, "
	"will use rounded up value.");
    SNMP_CFG->timeout = $3;
  }
/*
 | ERROR TIMEOUT expr_us {
    / * TODO * /
    SNMP_CFG->error_timeout = $3;
  }
*/
 | START DELAY TIME expr_us { SNMP_CFG->startup_delay = $4; }
 | VERBOSE bool { SNMP_CFG->verbose = $2; }
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
  SNMP_CFG->remote_ip = IPA_NONE;
  SNMP_CFG->remote_path = agentx_master_addr;
  SNMP_CFG->trans_type = SNMP_TRANS_DEFAULT;
  SNMP_CFG->bgp_local_id = IP4_NONE;
  SNMP_CFG->local_port = 0;
  SNMP_CFG->remote_port = 705;
  SNMP_CFG->bgp_local_as = 0;
  SNMP_CFG->verbose = 0;

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
