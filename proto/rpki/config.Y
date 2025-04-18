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
#define RPKI_TR_TCP_CFG ((struct rpki_tr_tcp_config *) RPKI_CFG->tr_config.spec)
#define RPKI_TR_SSH_CFG ((struct rpki_tr_ssh_config *) RPKI_CFG->tr_config.spec)

static void
rpki_check_unused_hostname(void)
{
  if (RPKI_CFG->hostname != NULL)
    cf_error("Only one cache server per protocol allowed");
}

static void
rpki_check_unused_transport(void)
{
  if (RPKI_CFG->tr_config.spec != NULL)
    cf_error("At the most one transport per protocol allowed");
}

CF_DECLS

CF_KEYWORDS(RPKI, REMOTE, BIRD, PRIVATE, PUBLIC, KEY, TCP, SSH, TRANSPORT, USER,
	    RETRY, REFRESH, EXPIRE, KEEP, IGNORE, MAX, MIN, LENGTH, LOCAL, ADDRESS,
	    AUTHENTICATION, NONE, MD5, PASSWORD, VERSION)

%type <i> rpki_keep_interval

CF_GRAMMAR

proto: rpki_proto ;

rpki_proto_start: proto_start RPKI {
  this_proto = proto_config_new(&proto_rpki, $1);
  RPKI_CFG->retry_interval = RPKI_RETRY_INTERVAL;
  RPKI_CFG->refresh_interval = RPKI_REFRESH_INTERVAL;
  RPKI_CFG->expire_interval = RPKI_EXPIRE_INTERVAL;
  RPKI_CFG->min_version = 0;
  RPKI_CFG->max_version = RPKI_MAX_VERSION;
};

rpki_proto: rpki_proto_start proto_name '{' rpki_proto_opts '}' { rpki_check_config(RPKI_CFG); };

rpki_proto_opts:
   /* empty */
 | rpki_proto_opts rpki_proto_item ';'
 ;

rpki_proto_item:
   proto_item
 | proto_channel
 | REMOTE rpki_cache_addr
 | REMOTE rpki_cache_addr rpki_proto_item_port
 | rpki_proto_item_port
 | LOCAL ADDRESS ipa { RPKI_CFG->local_ip = $3; }
 | TRANSPORT rpki_transport
 | REFRESH rpki_keep_interval expr {
     if (rpki_check_refresh_interval($3))
       cf_error(rpki_check_refresh_interval($3));
     RPKI_CFG->refresh_interval = $3;
     RPKI_CFG->keep_refresh_interval = $2;
   }
 | RETRY rpki_keep_interval expr {
     if (rpki_check_retry_interval($3))
       cf_error(rpki_check_retry_interval($3));
     RPKI_CFG->retry_interval = $3;
     RPKI_CFG->keep_retry_interval = $2;
   }
 | EXPIRE rpki_keep_interval expr {
     if (rpki_check_expire_interval($3))
       cf_error(rpki_check_expire_interval($3));
     RPKI_CFG->expire_interval = $3;
     RPKI_CFG->keep_expire_interval = $2;
   }
 | IGNORE MAX LENGTH bool { RPKI_CFG->ignore_max_length = $4; }
 | MIN VERSION expr {
     if ($3 > RPKI_MAX_VERSION) cf_error("RPKI version %u unsupported, min version must be in range 0-%u", $3, RPKI_MAX_VERSION);
     RPKI_CFG->min_version = $3;
   }
 | MAX VERSION expr {
     if ($3 > RPKI_MAX_VERSION) cf_error("RPKI version %u unsupported, max version must be in range 0-%u", $3, RPKI_MAX_VERSION);
     RPKI_CFG->max_version = $3;
   }
 ;

rpki_keep_interval:
 /* empty */ { $$ = 0; }
 | KEEP { $$ = 1; }
 ;

rpki_proto_item_port: PORT expr { check_u16($2); RPKI_CFG->port = $2; };

rpki_cache_addr: text_or_ipa
{
  rpki_check_unused_hostname();
  if ($1.type == T_STRING)
    RPKI_CFG->hostname = $1.val.s;
  else if ($1.type == T_IP)
  {
    RPKI_CFG->ip = $1.val.ip;

    /* Ensure hostname is filled */
    char *hostname = cfg_allocz(INET6_ADDRSTRLEN + 1);
    bsnprintf(hostname, INET6_ADDRSTRLEN+1, "%I", RPKI_CFG->ip);
    RPKI_CFG->hostname = hostname;
  }
  else bug("Bad text_or_ipa");
};

rpki_transport:
   TCP rpki_transport_tcp_init rpki_transport_tcp_opts_list rpki_transport_tcp_check
 | SSH rpki_transport_ssh_init '{' rpki_transport_ssh_opts '}' rpki_transport_ssh_check
 ;

rpki_transport_tcp_init:
{
  rpki_check_unused_transport();
  RPKI_CFG->tr_config.spec = cfg_allocz(sizeof(struct rpki_tr_tcp_config));
  RPKI_CFG->tr_config.type = RPKI_TR_TCP;
};

rpki_transport_tcp_opts_list:
    /* empty */
  | '{' rpki_transport_tcp_opts '}'
  ;

rpki_transport_tcp_opts:
   /* empty */
 | rpki_transport_tcp_opts rpki_transport_tcp_item ';'
 ;

rpki_transport_tcp_item:
   AUTHENTICATION NONE	{ RPKI_TR_TCP_CFG->auth_type = RPKI_TCP_AUTH_NONE; }
 | AUTHENTICATION MD5	{ RPKI_TR_TCP_CFG->auth_type = RPKI_TCP_AUTH_MD5; }
 | PASSWORD text	{ RPKI_TR_TCP_CFG->password = $2; }
 ;

rpki_transport_tcp_check:
{
  if (!RPKI_TR_TCP_CFG->auth_type != !RPKI_TR_TCP_CFG->password)
    cf_error("Authentication and password options should be used together");
};

rpki_transport_ssh_init:
{
#if HAVE_LIBSSH
  rpki_check_unused_transport();
  RPKI_CFG->tr_config.spec = cfg_allocz(sizeof(struct rpki_tr_ssh_config));
  RPKI_CFG->tr_config.type = RPKI_TR_SSH;
#else
  cf_error("This build doesn't support SSH");
#endif
};

rpki_transport_ssh_opts:
   /* empty */
 | rpki_transport_ssh_opts rpki_transport_ssh_item ';'
 ;

rpki_transport_ssh_item:
   BIRD PRIVATE KEY text  { RPKI_TR_SSH_CFG->bird_private_key = $4; }
 | REMOTE PUBLIC KEY text { RPKI_TR_SSH_CFG->cache_public_key = $4; }
 | USER text              { RPKI_TR_SSH_CFG->user = $2; }
 ;

rpki_transport_ssh_check:
{
  if (RPKI_TR_SSH_CFG->user == NULL)
    cf_error("User must be set");
};

CF_CODE

CF_END
