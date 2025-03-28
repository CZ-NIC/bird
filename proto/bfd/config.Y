/*
 *	BIRD -- Router Advertisement Configuration
 *
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/bfd/bfd.h"

CF_DEFINES

#define BFD_CFG ((struct bfd_config *) this_proto)
#define BFD_IFACE ((struct bfd_iface_config *) this_ipatt)
#define BFD_NEIGHBOR this_bfd_neighbor

static struct bfd_neighbor *this_bfd_neighbor;

extern struct bfd_config *bfd_cf;

CF_DECLS

CF_KEYWORDS(BFD, MIN, IDLE, RX, TX, INTERVAL, MULTIPLIER, PASSIVE, ADDRESS,
	INTERFACE, MULTIHOP, NEIGHBOR, DEV, ALL, LOCAL, AUTHENTICATION,
	NONE, SIMPLE, METICULOUS, KEYED, MD5, SHA1, IPV4, IPV6, DIRECT,
	STRICT, BIND, ZERO, UDP6, CHECKSUM, RX)

%type <iface> bfd_neigh_iface
%type <a> bfd_neigh_local
%type <i> bfd_neigh_multihop bfd_auth_type
%type <bssc> bfd_show_sessions_args

CF_GRAMMAR

proto: bfd_proto ;

bfd_proto_start: proto_start BFD
{
  this_proto = proto_config_new(&proto_bfd, $1);
  init_list(&BFD_CFG->patt_list);
  init_list(&BFD_CFG->neigh_list);
  BFD_CFG->accept_ipv4 = BFD_CFG->accept_ipv6 = 1;
  BFD_CFG->accept_direct = BFD_CFG->accept_multihop = 1;
};

bfd_proto_item:
   proto_item
 | ACCEPT bfd_accept
 | INTERFACE bfd_iface
 | MULTIHOP bfd_multihop
 | NEIGHBOR bfd_neighbor
 | STRICT BIND bool { BFD_CFG->strict_bind = $3; }
 | ZERO UDP6 CHECKSUM RX bool { BFD_CFG->zero_udp6_checksum_rx = $5; }
 ;

bfd_proto_opts:
   /* empty */
 | bfd_proto_opts bfd_proto_item ';'
 ;

bfd_proto:
   bfd_proto_start proto_name '{' bfd_proto_opts '}';


bfd_accept_item:
   IPV4			{ BFD_CFG->accept_ipv4 = 1;  BFD_CFG->accept_ipv6 = 0; }
 | IPV6 		{ BFD_CFG->accept_ipv4 = 0;  BFD_CFG->accept_ipv6 = 1; }
 | DIRECT		{ BFD_CFG->accept_direct = 1;  BFD_CFG->accept_multihop = 0; }
 | MULTIHOP		{ BFD_CFG->accept_direct = 0;  BFD_CFG->accept_multihop = 1; }
 ;

bfd_accept:
   {
     BFD_CFG->accept_ipv4 = BFD_CFG->accept_ipv6 = 1;
     BFD_CFG->accept_direct = BFD_CFG->accept_multihop = 1;
   }
 | bfd_accept bfd_accept_item


bfd_iface_start:
{
  this_ipatt = cfg_allocz(sizeof(struct bfd_iface_config));
  add_tail(&BFD_CFG->patt_list, NODE this_ipatt);
  init_list(&this_ipatt->ipn_list);

  BFD_IFACE->min_rx_int = BFD_DEFAULT_MIN_RX_INT;
  BFD_IFACE->min_tx_int = BFD_DEFAULT_MIN_TX_INT;
  BFD_IFACE->idle_tx_int = BFD_DEFAULT_IDLE_TX_INT;
  BFD_IFACE->multiplier = BFD_DEFAULT_MULTIPLIER;

  reset_passwords();
};

bfd_iface_finish:
{
  BFD_IFACE->passwords = get_passwords();

  if (!BFD_IFACE->auth_type != !BFD_IFACE->passwords)
    cf_warn("Authentication and password options should be used together");

  if (BFD_IFACE->passwords)
  {
    struct password_item *pass;
    WALK_LIST(pass, *BFD_IFACE->passwords)
    {
      if (pass->alg)
        cf_error("Password algorithm option not available in BFD protocol");

      pass->alg = bfd_auth_type_to_hash_alg[BFD_IFACE->auth_type];
    }
  }
};

bfd_iface_item:
   INTERVAL expr_us { BFD_IFACE->min_rx_int = BFD_IFACE->min_tx_int = $2; }
 | MIN RX INTERVAL expr_us { BFD_IFACE->min_rx_int = $4; }
 | MIN TX INTERVAL expr_us { BFD_IFACE->min_tx_int = $4; }
 | IDLE TX INTERVAL expr_us { BFD_IFACE->idle_tx_int = $4; }
 | MULTIPLIER expr { BFD_IFACE->multiplier = $2; }
 | PASSIVE bool { BFD_IFACE->passive = $2; }
 | AUTHENTICATION bfd_auth_type { BFD_IFACE->auth_type = $2; }
 | password_list {}
 ;

bfd_auth_type:
   NONE			 { $$ = BFD_AUTH_NONE; }
 | SIMPLE 		 { $$ = BFD_AUTH_SIMPLE; }
 | KEYED MD5		 { $$ = BFD_AUTH_KEYED_MD5; }
 | KEYED SHA1   	 { $$ = BFD_AUTH_KEYED_SHA1; }
 | METICULOUS KEYED MD5	 { $$ = BFD_AUTH_METICULOUS_KEYED_MD5; }
 | METICULOUS KEYED SHA1 { $$ = BFD_AUTH_METICULOUS_KEYED_SHA1; }
 ;

bfd_iface_opts:
   /* empty */
 | bfd_iface_opts bfd_iface_item ';'
 ;

bfd_iface_opt_list:
   /* empty */
 | '{' bfd_iface_opts '}'
 ;

bfd_iface:
  bfd_iface_start iface_patt_list_nopx bfd_iface_opt_list bfd_iface_finish;

bfd_multihop:
  bfd_iface_start bfd_iface_opt_list bfd_iface_finish
{ BFD_CFG->multihop = BFD_IFACE; };


bfd_neigh_iface:
   /* empty */ { $$ = NULL; }
 | '%' symbol { $$ = if_get_by_name($2->name); }
 | DEV text { $$ = if_get_by_name($2); }
 ;

bfd_neigh_local:
   /* empty */ { $$ = IPA_NONE; }
 | LOCAL ipa { $$ = $2; }
 ;

bfd_neigh_multihop:
   /* empty */ { $$ = 0; }
 | MULTIHOP bool { $$ = $2; }
 ;

bfd_neighbor: ipa bfd_neigh_iface bfd_neigh_local bfd_neigh_multihop
{
  this_bfd_neighbor = cfg_allocz(sizeof(struct bfd_neighbor));
  add_tail(&BFD_CFG->neigh_list, NODE this_bfd_neighbor);

  BFD_NEIGHBOR->addr = $1;
  BFD_NEIGHBOR->local = $3;
  BFD_NEIGHBOR->iface = $2;
  BFD_NEIGHBOR->multihop = $4;

  if ($4 && $2)
    cf_error("Neighbor cannot set both interface and multihop");

  if ($4 && ipa_zero($3))
    cf_error("Multihop neighbor requires specified local address");
};


/* BFD options */

bfd_item:
   INTERVAL expr_us { this_bfd_opts->min_rx_int = this_bfd_opts->min_tx_int = $2; }
 | MIN RX INTERVAL expr_us { this_bfd_opts->min_rx_int = $4; }
 | MIN TX INTERVAL expr_us { this_bfd_opts->min_tx_int = $4; }
 | IDLE TX INTERVAL expr_us { this_bfd_opts->idle_tx_int = $4; }
 | MULTIPLIER expr { this_bfd_opts->multiplier = $2; }
 | PASSIVE bool { this_bfd_opts->passive = $2; this_bfd_opts->passive_set = 1; }
 | GRACEFUL { this_bfd_opts->mode = BGP_BFD_GRACEFUL; }
 | AUTHENTICATION bfd_auth_type { this_bfd_opts->auth_type = $2; }
 | password_list {}
 ;

bfd_items:
   /* empty */
 | bfd_items bfd_item ';'
 ;

bfd_opts_start:
{ reset_passwords(); } ;

bfd_opts_end:
{
  this_bfd_opts->passwords = get_passwords();

  if (!this_bfd_opts->auth_type != !this_bfd_opts->passwords)
    cf_warn("Authentication and password options should be used together");

  if (this_bfd_opts->passwords)
  {
    struct password_item *pass;
    WALK_LIST(pass, *this_bfd_opts->passwords)
    {
      if (pass->alg)
        cf_error("Password algorithm option not available in BFD protocol");

      pass->alg = bfd_auth_type_to_hash_alg[this_bfd_opts->auth_type];
    }
  }
};

bfd_opts:
  '{' bfd_opts_start bfd_items '}' bfd_opts_end;


CF_CLI_HELP(SHOW BFD, ..., [[Show information about BFD protocol]]);

CF_CLI_HELP(SHOW BFD SESSIONS, ..., [[Show information about BFD sessions]]);
CF_CLI(SHOW BFD SESSIONS, bfd_show_sessions_args, [<name>] [address <ip|prefix>] [(interface|dev) \"<name>\"] [ipv4|ipv6] [direct|multihop] [all], [[Show information about BFD sessions]])
{ PROTO_WALK_CMD($4->name, &proto_bfd, p) bfd_show_sessions(p, $4); };

CF_CLI_OPT(SHOW BFD SESSIONS ADDRESS, <ip>|<prefix>)
CF_CLI_OPT(SHOW BFD SESSIONS INTERFACE, \"<name>\")
CF_CLI_OPT(SHOW BFD SESSIONS DEV, \"<name>\")
CF_CLI_OPT(SHOW BFD SESSIONS ALL)
CF_CLI_OPT(SHOW BFD SESSIONS IPV4)
CF_CLI_OPT(SHOW BFD SESSIONS IPV6)
CF_CLI_OPT(SHOW BFD SESSIONS DIRECT)
CF_CLI_OPT(SHOW BFD SESSIONS MULTIHOP)

bfd_show_sessions_args:
   /* empty */ { $$ = cfg_allocz(sizeof(struct bfd_show_sessions_cmd)); }
 | bfd_show_sessions_args CF_SYM_KNOWN { cf_assert_symbol($2, SYM_PROTO); $$->name = $2; }
 | bfd_show_sessions_args ADDRESS net_or_ipa { net_copy(&($$->address), &($3)); }
 | bfd_show_sessions_args INTERFACE text { $$->iface = if_get_by_name($3); }
 | bfd_show_sessions_args DEV text { $$->iface = if_get_by_name($3); }
 | bfd_show_sessions_args ALL { $$->verbose = 1; }
 | bfd_show_sessions_args IPV4 { $$->ipv4 = 1; if ($$->ipv6) cf_error("Options 'ipv4' and 'ipv6' are mutually exclusive"); }
 | bfd_show_sessions_args IPV6 { $$->ipv6 = 1; if ($$->ipv4) cf_error("Options 'ipv4' and 'ipv6' are mutually exclusive"); }
 | bfd_show_sessions_args DIRECT { $$->direct = 1; if ($$->multihop) cf_error("Options 'direct' and 'multihop' are mutually exclusive"); }
 | bfd_show_sessions_args MULTIHOP { $$->multihop = 1; if ($$->direct) cf_error("Options 'direct' and 'multihop' are mutually exclusive"); }
 ;


CF_CODE

CF_END
