/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/rpki/rpki.h"

CF_DEFINES

#define RPKI_CFG ((struct rpki_config *) this_proto)

CF_DECLS

CF_KEYWORDS(RPKI, CACHE, SERVER, SERVERS)

CF_GRAMMAR

CF_ADDTO(proto, rpki_proto)

rpki_proto_start: proto_start RPKI {
     this_proto = proto_config_new(&proto_rpki, $1);
 }
 ;

rpki_proto_item:
   proto_item
 | CACHE SERVER ipa expr {
	RPKI_CFG->remote.ip = $3;
	RPKI_CFG->remote.port = $4;
 }
 ;

rpki_proto_opts:
   /* empty */
 | rpki_proto_opts rpki_proto_item ';'
 ;

rpki_proto:
   rpki_proto_start proto_name '{' rpki_proto_opts '}'

CF_CODE

CF_END
