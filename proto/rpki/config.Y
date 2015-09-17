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

static struct rpki_cache_cfg *this_rpki_cache_cfg;

CF_DECLS

CF_KEYWORDS(RPKI, CACHE, LIST, PREFERENCE, BIRD, PRIVATE, PUBLIC, KEY, SSH, ENCRYPTION, USER)
CF_KEYWORDS(RETRY, REFRESH, EXPIRE)

CF_GRAMMAR

CF_ADDTO(proto, rpki_proto)

rpki_proto:
rpki_proto_start proto_name '{' rpki_proto_opts '}' rpki_proto_finish
;

rpki_proto_start:
proto_start RPKI {
  this_proto = proto_config_new(&proto_rpki, $1);
  init_list(&RPKI_CFG->cache_cfg_list);
}
;

rpki_proto_finish:
{
//  if (RPKI_CFG->roa_table_cf == NULL)
//    cf_error("For the RPKI protocol must be specified a roa table");
};

rpki_proto_opts:
/* empty */
| rpki_proto_opts rpki_proto_item ';'
;

rpki_proto_item:
proto_item
| CACHE rpki_cache
/* | ROA TABLE roa_table_cf { RPKI_CFG->roa_table_cf = $3; } */
;

rpki_cache:
rpki_cache_init rpki_cache_addr rpki_optional_cache_opts rpki_cache_finish {
  add_tail(&RPKI_CFG->cache_cfg_list, &this_rpki_cache_cfg->n);
}
;

rpki_cache_finish:
{
  if (this_rpki_cache_cfg->port == 0) /* empty? */
  {
    if (this_rpki_cache_cfg->ssh != NULL)
      this_rpki_cache_cfg->port = RPKI_DEFAULT_SSH_PORT;
    else
      this_rpki_cache_cfg->port = RPKI_DEFAULT_PORT;
  }
}
;

rpki_cache_init:
{
  this_rpki_cache_cfg = rpki_new_cache_cfg();
}
;

rpki_cache_addr:
text {
  this_rpki_cache_cfg->hostname = $1;
}
| ipa {
  this_rpki_cache_cfg->ip = $1;
  this_rpki_cache_cfg->hostname = cfg_allocz(sizeof(INET6_ADDRSTRLEN+1));
  bsnprintf(this_rpki_cache_cfg->hostname, INET6_ADDRSTRLEN+1, "%I", this_rpki_cache_cfg->ip);
}
;

rpki_optional_cache_opts:
/* empty */
| '{' rpki_cache_opts '}'
;

rpki_cache_opts:
 /* empty */
 | rpki_cache_opts rpki_cache_opts_item ';'
 ;

rpki_cache_opts_item:
 PORT expr {
  check_u16($2);
  this_rpki_cache_cfg->port = $2;
 }
 | PREFERENCE expr {
   if ($2 < 1 || $2 > 0xFF)
     cf_error("Value %d is out of range (1-255)", $2);
   this_rpki_cache_cfg->preference = $2;
 }
 | REFRESH expr { this_rpki_cache_cfg->refresh_interval = $2; }
 | RETRY   expr { this_rpki_cache_cfg->retry_interval = $2;   }
 | EXPIRE  expr { this_rpki_cache_cfg->expire_interval = $2;  }
 | SSH ENCRYPTION rpki_transport_ssh_init '{' rpki_transport_ssh_opts '}' rpki_transport_ssh_finish
 ;

rpki_transport_ssh_init:
{
  this_rpki_cache_cfg->ssh = cfg_allocz(sizeof(struct rpki_cache_ssh_cfg));
}
;

rpki_transport_ssh_opts:
/* empty */
| rpki_transport_ssh_opts rpki_transport_ssh_item ';'
;

rpki_transport_ssh_item:
BIRD PRIVATE KEY text {
  check_file_readability($4);
  this_rpki_cache_cfg->ssh->bird_private_key = $4;
}
| CACHE PUBLIC KEY text {
  check_file_readability($4);
  this_rpki_cache_cfg->ssh->cache_public_key = $4;
}
| USER text {
  this_rpki_cache_cfg->ssh->username = $2;
}
;

rpki_transport_ssh_finish:
{
#define RPKI_PARSE_CACHE_MISS_SSH_OPT(what) "Miss  '" what ";'  option in the %s protocol at cache server %s inside the ssh encryption block"

  if (!this_rpki_cache_cfg->ssh->username)
    cf_error(RPKI_PARSE_CACHE_MISS_SSH_OPT("user \"ssh_username\""), RPKI_CFG->c.name, this_rpki_cache_cfg->hostname);
}

CF_CODE

CF_END
