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

CF_KEYWORDS(SNMP, PROTOCOL, LOCAL, AS, REMOTE, ADDRESS, PORT, DESCRIPTION,
	    TIMEOUT, PRIORITY, CONTEXT, DEFAULT, MESSAGE, VERBOSE, AGENTX,
	    SUBAGENT, MASTER, BGP4, MIB, REGISTRATION, PEER)

CF_GRAMMAR

proto: snmp_proto ;

snmp_proto:
   snmp_proto_start proto_name '{' snmp_proto_opts '}' ;

snmp_proto_item:
   proto_item
 | bgp4_mib
 | SOURCE ADDRESS ipa { SNMP_CFG->local_ip = $3; }
 | AGENTX MASTER ADDRESS DEFAULT {
    if (SNMP_CFG->trans_type != SNMP_TRANS_DEFAULT)
      cf_error("Duplicit option remote address");
  }
 | AGENTX MASTER ADDRESS text {
    if (SNMP_CFG->trans_type != SNMP_TRANS_DEFAULT)
      cf_error("Duplicit option remote address");

    if (strcmp($4, agentx_master_addr)) {
      SNMP_CFG->master_path = $4;
      SNMP_CFG->trans_type = SNMP_TRANS_UNIX;
    }
  }
 | AGENTX MASTER ADDRESS ipa {
    if (SNMP_CFG->trans_type != SNMP_TRANS_DEFAULT)
      cf_error("Duplicit option agentx master address");

    SNMP_CFG->master_ip = $4;
    SNMP_CFG->trans_type = SNMP_TRANS_TCP;
  }
 | AGENTX MASTER ADDRESS ipa PORT expr {
    if (SNMP_CFG->trans_type != SNMP_TRANS_DEFAULT)
      cf_error("Duplicit option agentx master address");

    if (($6 < 1) || ($6 > UINT16_MAX)) cf_error("Invalid port number");

    SNMP_CFG->master_ip = $4;
    SNMP_CFG->trans_type = SNMP_TRANS_TCP;
    SNMP_CFG->master_port = $6;
  }
 | SUBAGENT DESCRIPTION text {
    if (strlen($3) > UINT16_MAX - 1) cf_error("Description is too long");
    SNMP_CFG->description = $3;
  }
 | REGISTRATION PRIORITY expr {
    if ($3 > 255) cf_error("Registration priority must be in range 0-255");
    SNMP_CFG->priority = $3;
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
 | RETRY TIME expr_us {
    / * TODO * /
    SNMP_CFG->retry_timeout = $3;
  }
*/
 | START DELAY TIME expr_us { SNMP_CFG->startup_delay = $4; }
 | VERBOSE bool { SNMP_CFG->verbose = $2; }
 ;

bgp4_mib:
   MIB BGP4 '{' bgp4_mib_items '}'
 | BGP4 MIB '{' bgp4_mib_items '}'
 ;

bgp4_mib_items:
   bgp4_mib_items_opt bgp4_mib_as bgp4_mib_items_opt bgp4_mib_id bgp4_mib_items_opt
 ;

bgp4_mib_as:
  LOCAL AS expr ';' {
    if ($3 < 1 || $3 > UINT16_MAX) cf_error("Invalid local AS for BGP4-MIB");
    SNMP_CFG->bgp4_local_as = $3;
  }
  /* TODO add option to follow some bgp peer local as */
 ;

bgp4_mib_id:
   LOCAL ROUTER ID idval ';' { SNMP_CFG->bgp4_local_id = $4; }
  /* TODO add option to inherit global router id, or follow some bgp peer */
 ;

bgp4_mib_items_opt:
   /* empty */
 | bgp4_mib_items_opt bgp4_mib_peer ';'
 ;

bgp4_mib_peer: PEER symbol
{
  /* the snmp_context rule sets the correct value of this_bond */
  cf_assert_symbol($2, SYM_PROTO);

  if (!$2->proto) cf_error("BGP protocol %s not found", $2->name);

  cf_assert($2->proto->protocol == &proto_bgp,
    "SNMP BGP bond accepts only BGP protocols");

  struct snmp_bond *this_bond = cfg_alloc(sizeof(struct snmp_bond));
  this_bond->type = SNMP_BGP;
  this_bond->config = $2->proto;

  add_tail(&SNMP_CFG->bgp_entries, &this_bond->n);
  SNMP_CFG->bonds++;
}

snmp_proto_opts:
   /* empty */
 | snmp_proto_opts snmp_proto_item ';'
 ;

snmp_proto_start: proto_start SNMP
{
  this_proto = proto_config_new(&proto_snmp, $1);

  init_list(&SNMP_CFG->bgp_entries);
  SNMP_CFG->bonds = 0;

  SNMP_CFG->local_ip = IPA_NONE;
  SNMP_CFG->master_ip = IPA_NONE;
  SNMP_CFG->master_port = SNMP_PORT;
  SNMP_CFG->master_path = agentx_master_addr;
  SNMP_CFG->trans_type = SNMP_TRANS_DEFAULT;
  SNMP_CFG->bgp4_local_as = 0;
  SNMP_CFG->bgp4_local_id = 0;
  SNMP_CFG->verbose = 0;

  SNMP_CFG->description = "bird";
  SNMP_CFG->timeout = 15;
  SNMP_CFG->priority = AGENTX_PRIORITY;
}


CF_CODE

CF_END
