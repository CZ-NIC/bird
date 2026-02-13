/*
 *	BIRD -- YANG-CBOR / CORECONF api
 *
 *	(c) 2026       Maria Matejka <mq@jmq.cz>
 *	(c) 2026       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "yang/yang.h"

CF_DEFINES

static struct yang_api_config *this_yang_api;
static struct yang_socket_config *this_yang_socket;

static uint yang_api_counter = 1;

CF_DECLS

CF_KEYWORDS(YANG, LISTEN, TCP, UDP, COAP, RESTRICTED, MODEL, CLI, MTU)

%type <s> yang_api_start
%type <yang_model> yang_model

CF_GRAMMAR

conf: yang_api ;

yang_api: yang_api_start {
     this_yang_api = cfg_allocz(sizeof *this_yang_api);
     this_yang_api->name = $1->name;
     $1->class = SYM_YANG_API;
     $1->api = this_yang_api;
   } '{' yang_api_opts '}' {
     if (!this_yang_api->params.model)
       cf_error("YANG API with no model");

     yang_api_config_add_tail(&new_config->yang, this_yang_api);
     this_yang_api->global = new_config;
     this_yang_api = NULL;
   }
;

yang_api_start:
   YANG /* empty */ { $$ = cf_default_name(new_config, "yang%d", &yang_api_counter); }
 | YANG symbol { $$ = $2; }
;

yang_api_opts: /* empty */ | yang_api_opts yang_api_opt ';' ;

yang_api_opt:
   LISTEN {
     this_yang_socket = cfg_allocz(sizeof *this_yang_socket);
     yang_socket_config_add_tail(&this_yang_api->listen, this_yang_socket);
   } yang_socket {
     WALK_TLIST(yang_socket_config, sc, &this_yang_api->listen)
       if ((sc != this_yang_socket) && (yang_socket_same(&sc->params, &this_yang_socket->params)))
	 cf_error("Duplicate socket configuration");
     this_yang_socket = NULL;
   }
 | MODEL yang_model	{ this_yang_api->params.model = $2; }
 | RESTRICTED bool	{ this_yang_api->params.restricted = $2; }
;

yang_model:
   CLI { $$ = YANG_MODEL_CLI; }
;

yang_socket:
   TCP COAP '{' yang_tcp_coap_socket '}'
 | UDP COAP '{' yang_udp_coap_socket '}' /* not implemented actually yet, placeholder */
;

yang_tcp_coap_socket: {
     this_yang_socket->params.kind = YANG_SOCKET_COAP_TCP;
     this_yang_socket->params.local_ip = ipa_build6(0, 0, 0, 1);
     this_yang_socket->params.port = 5683;
   } yang_tcp_coap_opts
;

yang_tcp_coap_opts: /* empty */
 | yang_tcp_coap_opts yang_tcp_coap_opt ';' ;

yang_tcp_coap_opt: yang_tcp_opt | yang_coap_opt ;

yang_tcp_opt: yang_tcpudp_opt ;


yang_udp_coap_socket: {
     this_yang_socket->params.kind = YANG_SOCKET_COAP_UDP;
     this_yang_socket->params.local_ip = ipa_build6(0, 0, 0, 1);
     this_yang_socket->params.port = 5683;
   } yang_udp_coap_opts
;

yang_udp_coap_opts: /* empty */
 | yang_udp_coap_opts yang_udp_coap_opt ';' ;

yang_udp_coap_opt: yang_udp_opt | yang_coap_opt ;

yang_udp_opt:
   yang_tcpudp_opt
 | MTU expr ';' {
     cf_error("mtu not yet supported");
   }
;


yang_tcpudp_opt:
   LOCAL ipa ';' {
     this_yang_socket->params.local_ip = $2;
   }
 | PORT expr ';' {
     this_yang_socket->params.port = $2;
   }
;

yang_coap_opt: ;

CF_CODE

CF_END
