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

static void
rpki_check_unused_hostname(void)
{
  if (RPKI_CFG->hostname != NULL)
    cf_error("Only one remote cache server per protocol allowed");
}

CF_DECLS

CF_KEYWORDS(RPKI, REMOTE, BIRD, PRIVATE, PUBLIC, KEY, SSH, ENCRYPTION, USER,
	    RETRY, REFRESH, EXPIRE, STATE, DIR)

CF_GRAMMAR

CF_ADDTO(proto, rpki_proto)

rpki_proto_start: proto_start RPKI {
  this_proto = proto_config_new(&proto_rpki, $1);
  RPKI_CFG->retry_interval = RPKI_DEFAULT_RETRY_INTERVAL;
  RPKI_CFG->refresh_interval = RPKI_DEFAULT_REFRESH_INTERVAL;
  RPKI_CFG->expire_interval = RPKI_DEFAULT_EXPIRE_INTERVAL;
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
 | SSH ENCRYPTION rpki_transport_ssh
 | REFRESH expr {
     if (rpki_check_refresh_interval($2))
       cf_error(rpki_check_refresh_interval($2));
     RPKI_CFG->refresh_interval = $2;
   }
 | RETRY expr {
     if (rpki_check_retry_interval($2))
       cf_error(rpki_check_retry_interval($2));
     RPKI_CFG->retry_interval = $2;
   }
 | EXPIRE expr {
     if (rpki_check_expire_interval($2))
       cf_error(rpki_check_expire_interval($2));
     RPKI_CFG->expire_interval = $2;
   }
 ;

rpki_transport_ssh:
   OFF { RPKI_CFG->ssh = NULL; }
 | rpki_transport_ssh_init '{' rpki_transport_ssh_opts '}' rpki_transport_ssh_check
 ;

rpki_proto_item_port: PORT expr { check_u16($2); RPKI_CFG->port = $2; };

rpki_cache_addr:
   text {
     rpki_check_unused_hostname();
     RPKI_CFG->hostname = $1;
   }
 | ipa {
     rpki_check_unused_hostname();
     RPKI_CFG->ip = $1;
     char *hostname = cfg_allocz(sizeof(INET6_ADDRSTRLEN+1));
     bsnprintf(hostname, INET6_ADDRSTRLEN+1, "%I", RPKI_CFG->ip);
     RPKI_CFG->hostname = hostname;
   }
 ;

rpki_transport_ssh_init:
{
  /* allow extending ssh configuration */
  if (RPKI_CFG->ssh == NULL)
    RPKI_CFG->ssh = cfg_allocz(sizeof(struct rpki_config_ssh));
};

rpki_transport_ssh_opts:
   /* empty */
 | rpki_transport_ssh_opts rpki_transport_ssh_item ';'
 ;

rpki_transport_ssh_item:
   BIRD PRIVATE KEY text { RPKI_CFG->ssh->bird_private_key = $4; }
 | REMOTE PUBLIC KEY text { RPKI_CFG->ssh->cache_public_key = $4; }
 | USER text { RPKI_CFG->ssh->user = $2; }
 ;

rpki_transport_ssh_check:
{
  if (RPKI_CFG->ssh->user == NULL)
    cf_error("User must be set");
};

CF_CODE

CF_END
