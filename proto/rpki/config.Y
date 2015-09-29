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

static struct rpki_cache *this_rpki_cache;

CF_DECLS

CF_KEYWORDS(RPKI, CACHE, LIST, PREFERENCE)

CF_GRAMMAR

CF_ADDTO(proto, rpki_proto)

rpki_proto:
   rpki_proto_start proto_name '{' rpki_proto_opts '}' {
     if (RPKI_CFG->roa_table_cf == NULL)
     {
       cf_error("For the RPKI protocol must be specified a roa table");
     }
   }
 ;

rpki_proto_start:
   proto_start RPKI {
     this_proto = proto_config_new(&proto_rpki, $1);
     init_list(&RPKI_CFG->cache_list);
   }
 ;

rpki_proto_opts:
   /* empty */
 | rpki_proto_opts rpki_proto_item ';'
 ;

rpki_proto_item:
   proto_item
 | CACHE LIST '{' rpki_cache_list '}'
 | ROA TABLE roa_table_cf { RPKI_CFG->roa_table_cf = $3; }
 ;

rpki_cache_list:
   rpki_cache_list_item
 | rpki_cache_list ',' rpki_cache_list_item
 ;

rpki_cache_list_item:
   rpki_cache_init text rpki_cache_opts {
     this_rpki_cache->full_domain_name = $2;
     add_tail(&RPKI_CFG->cache_list, &this_rpki_cache->n);
   }
 | rpki_cache_init ipa rpki_cache_opts {
     this_rpki_cache->ip = $2;
     add_tail(&RPKI_CFG->cache_list, &this_rpki_cache->n);
   }
 ;

rpki_cache_init:
   /* empty */ { this_rpki_cache = rpki_new_cache(); }
 ;

rpki_cache_opts:
   /* empty */
 | rpki_cache_opts rpki_cache_opts_item ';'
 ;

rpki_cache_opts_item:
   PORT expr 		{ check_u16($2); bsnprintf(this_rpki_cache->port, RPKI_PORT_MAX_LENGTH_STR, "%u", (u16) $2); }
 | PREFERENCE expr	{ check_u8($2); this_rpki_cache->preference = $2; }
 ;

CF_CODE

CF_END
