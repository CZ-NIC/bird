/*
 *	BIRD -- Core Configuration
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *      (c) 2004       Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "nest/rt-dev.h"
#include "nest/password.h"
#include "nest/cmds.h"
#include "nest/mpls.h"
#include "lib/lists.h"
#include "lib/mac.h"

CF_DEFINES

static struct rtable_config *this_table;
static struct proto_config *this_proto;
static struct channel_config *this_channel;
static struct iface_patt *this_ipatt;
static struct iface_patt_node *this_ipn;
/* static struct roa_table_config *this_roa_table; */
static list *this_p_list;
static struct password_item *this_p_item;
static int password_id;
static struct bfd_options *this_bfd_opts;

static void
iface_patt_check(void)
{
  struct iface_patt_node *pn;

  WALK_LIST(pn, this_ipatt->ipn_list)
    if (!pn->pattern || pn->prefix.type)
      cf_error("Interface name/mask expected, not IP prefix");
}

static inline void
init_password_list(void)
{
   if (!this_p_list) {
      this_p_list = cfg_allocz(sizeof(list));
      init_list(this_p_list);
      password_id = 1;
   }
}

static inline void
init_password(const void *key, uint length, uint id)
{
   this_p_item = cfg_allocz(sizeof (struct password_item));
   this_p_item->password = key;
   this_p_item->length = length;
   this_p_item->genfrom = 0;
   this_p_item->gento = TIME_INFINITY;
   this_p_item->accfrom = 0;
   this_p_item->accto = TIME_INFINITY;
   this_p_item->id = id;
   this_p_item->alg = ALG_UNDEFINED;
   add_tail(this_p_list, &this_p_item->n);
}

static inline void
reset_passwords(void)
{
  this_p_list = NULL;
}

static inline list *
get_passwords(void)
{
  list *rv = this_p_list;
  this_p_list = NULL;
  return rv;
}

static inline void
init_bfd_opts(struct bfd_options **opts)
{
  cf_check_bfd(1);

  if (! *opts)
    *opts = bfd_new_options();
}

static inline void
open_bfd_opts(struct bfd_options **opts)
{
  init_bfd_opts(opts);
  this_bfd_opts = *opts;
}

static inline void
close_bfd_opts(void)
{
  this_bfd_opts = NULL;
}

static void
proto_postconfig(void)
{
  CALL(this_proto->protocol->postconfig, this_proto);
  this_channel = NULL;
  this_proto = NULL;
}

static void
channel_reload_out_done_main(void *_prr)
{
  struct proto_reload_request *prr = _prr;
  ASSERT_THE_BIRD_LOCKED;

  rfree(prr->trie->lp);
}

static inline void
proto_call_cmd_reload(struct proto_spec ps, int dir, const struct f_trie *trie)
{
  struct proto_reload_request *prr = cfg_alloc(sizeof *prr);
  *prr = (struct proto_reload_request) {
    .trie = trie,
    .dir = dir,
    .counter = 1,
  };
  if (trie)
  {
    /* CLI linpool is moved to trie, because trie is need for longer time
     * than the linpool would exist in CLI. The linpool is freed in channel_reload_out_done_main.
     */
    ASSERT_DIE(this_cli->parser_pool == prr->trie->lp);
    rmove(this_cli->parser_pool, &root_pool);
    this_cli->parser_pool = lp_new(this_cli->pool);
    prr->ev = (event) {
      .data = prr,
      .hook = channel_reload_out_done_main,
    };
  }

  proto_apply_cmd(ps, proto_cmd_reload, 1, (uintptr_t) prr);
  /* This function used reference to this trie, so it is freed here as well as in protocols*/
  if (trie)
    if (atomic_fetch_sub_explicit(&prr->counter, 1, memory_order_acq_rel) == 1)
      ev_send_loop(&main_birdloop, &prr->ev);
}

#define DIRECT_CFG ((struct rt_dev_config *) this_proto)

CF_DECLS

CF_KEYWORDS(ROUTER, ID, HOSTNAME, PROTOCOL, TEMPLATE, PREFERENCE, DISABLED, DEBUG, ALL, OFF, DIRECT, PIPE)
CF_KEYWORDS(INTERFACE, IMPORT, EXPORT, FILTER, NONE, VRF, DEFAULT, TABLE, TABLES, STATES, ROUTES, FILTERS)
CF_KEYWORDS(IPV4, IPV6, VPN4, VPN6, ROA4, ROA6, FLOW4, FLOW6, SADR, MPLS)
CF_KEYWORDS(RECEIVE, LIMIT, ACTION, WARN, BLOCK, RESTART, DISABLE, KEEP, FILTERED, RPKI)
CF_KEYWORDS(PASSWORD, KEY, FROM, PASSIVE, TO, ID, EVENTS, PACKETS, PROTOCOLS, CHANNELS, INTERFACES)
CF_KEYWORDS(ALGORITHM, KEYED, HMAC, MD5, SHA1, SHA256, SHA384, SHA512, BLAKE2S128, BLAKE2S256, BLAKE2B256, BLAKE2B512)
CF_KEYWORDS(PRIMARY, STATS, COUNT, FOR, IN, COMMANDS, PREEXPORT, NOEXPORT, EXPORTED, GENERATE)
CF_KEYWORDS(BGP, PASSWORDS, DESCRIPTION)
CF_KEYWORDS(RELOAD, IN, OUT, MRTDUMP, MESSAGES, RESTRICT, MEMORY, CLASS, DSCP, PARTIAL)
CF_KEYWORDS(TIMEFORMAT, ISO, SHORT, LONG, ROUTE, PROTOCOL, BASE, LOG, S, MS, US)
CF_KEYWORDS(GRACEFUL, RESTART, WAIT, MAX, AS)
CF_KEYWORDS(MIN, IDLE, RX, TX, INTERVAL, MULTIPLIER, PASSIVE)
CF_KEYWORDS(CHECK, LINK)
CF_KEYWORDS(CORK, SORTED, TRIE, MIN, MAX, ROA, DIGEST, ROUTE, REFRESH, SETTLE, TIME, GC, THRESHOLD, PERIOD)
CF_KEYWORDS(MPLS_LABEL, MPLS_POLICY, MPLS_CLASS)

/* For r_args_channel */
CF_KEYWORDS(IPV4, IPV4_MC, IPV4_MPLS, IPV6, IPV6_MC, IPV6_MPLS, IPV6_SADR, VPN4, VPN4_MC, VPN4_MPLS, VPN6, VPN6_MC, VPN6_MPLS, ROA4, ROA6, FLOW4, FLOW6, MPLS, PRI, SEC)

CF_ENUM(T_ENUM_RTS, RTS_, STATIC, INHERIT, DEVICE, STATIC_DEVICE, REDIRECT,
	RIP, OSPF, OSPF_IA, OSPF_EXT1, OSPF_EXT2, BGP, PIPE, BABEL, RPKI, L3VPN,
	AGGREGATED)
CF_ENUM(T_ENUM_SCOPE, SCOPE_, HOST, LINK, SITE, ORGANIZATION, UNIVERSE, UNDEFINED)
CF_ENUM(T_ENUM_RTD, RTD_, UNICAST, BLACKHOLE, UNREACHABLE, PROHIBIT)
CF_ENUM(T_ENUM_ROA, ROA_, UNKNOWN, VALID, INVALID)
CF_ENUM_PX(T_ENUM_AF, AF_, AFI_, IPV4, IPV6)
CF_ENUM(T_ENUM_MPLS_POLICY, MPLS_POLICY_, NONE, STATIC, PREFIX, AGGREGATE, VRF)

%type <i32> idval
%type <f> imexport
%type <r> rtable
%type <s> optproto
%type <ra> r_args
%type <sd> sym_args
%type <i> proto_start debug_mask debug_list debug_flag mrtdump_mask mrtdump_list mrtdump_flag export_mode limit_action net_type net_type_base tos password_algorithm
%type <ps> proto_patt proto_patt2
%type <cc> channel_start proto_channel
%type <cl> limit_spec
%type <net> r_args_for_val
%type <net_ptr> r_args_for
%type <t> channel_sym
%type <c> channel_arg
%type <const_trie> partial_opt

CF_GRAMMAR

/* Setting of router ID */

conf: rtrid ;

rtrid:
   ROUTER ID idval ';' { new_config->router_id = $3; }
 | ROUTER ID FROM iface_patt ';' { new_config->router_id_from = this_ipatt; }
 ;

idval:
   NUM { $$ = $1; }
 | '(' term ')' { $$ = cf_eval_int($2); }
 | IP4 { $$ = ip4_to_u32($1); }
 | CF_SYM_KNOWN {
     if ($1->class == (SYM_CONSTANT | T_INT) || $1->class == (SYM_CONSTANT | T_QUAD))
       $$ = SYM_VAL($1).i;
     else if (($1->class == (SYM_CONSTANT | T_IP)) && ipa_is_ip4(SYM_VAL($1).ip))
       $$ = ipa_to_u32(SYM_VAL($1).ip);
     else
       cf_error("Number or IPv4 address constant expected");
   }
 ;

conf: hostname_override ;

hostname_override: HOSTNAME text ';' { new_config->hostname = $2; } ;

conf: gr_opts ;

gr_opts: GRACEFUL RESTART WAIT expr ';' { new_config->gr_wait = $4; } ;


/* Network types (for tables, channels) */

net_type_base:
   IPV4 { $$ = NET_IP4; }
 | IPV6 { $$ = NET_IP6; }
 | IPV6 SADR { $$ = NET_IP6_SADR; }
 | VPN4 { $$ = NET_VPN4; }
 | VPN6 { $$ = NET_VPN6; }
 | ROA4 { $$ = NET_ROA4; }
 | ROA6 { $$ = NET_ROA6; }
 | FLOW4{ $$ = NET_FLOW4; }
 | FLOW6{ $$ = NET_FLOW6; }
 ;

net_type:
   net_type_base
 | MPLS { $$ = NET_MPLS; }
 ;

CF_ENUM(T_ENUM_NETTYPE, NET_, IP4, IP6, VPN4, VPN6, ROA4, ROA6, FLOW4, FLOW6, IP6_SADR, MPLS)


/* Creation of routing tables */

conf: table ;

table: table_start table_sorted table_opt_list ;

table_start: net_type TABLE symbol {
   this_table = rt_new_table($3, $1);
   }
 ;

table_sorted:
   /* empty */
 | SORTED { this_table->sorted = 1; }
 ;

table_opt:
   SORTED bool { this_table->sorted = $2; }
 | DEBUG debug_mask { this_table->debug = $2; }
 | TRIE bool {
     if (!net_val_match(this_table->addr_type, NB_IP | NB_VPN | NB_ROA | NB_IP6_SADR))
       cf_error("Trie option not supported for %s table", net_label[this_table->addr_type]);
     this_table->trie_used = $2;
   }
 | GC THRESHOLD expr { this_table->gc_threshold = $3; }
 | GC PERIOD expr_us { this_table->gc_period = (uint) $3; if ($3 > 3600 S_) cf_error("GC period must be at most 3600 s"); }
 | CORK THRESHOLD expr expr {
     if ($3 > $4) cf_error("Cork low threshold must be lower than the high threshold.");
     this_table->cork_threshold.low = $3;
     this_table->cork_threshold.high = $4; }
 | EXPORT SETTLE TIME settle { this_table->export_settle = $4; }
 | ROUTE REFRESH EXPORT SETTLE TIME settle { this_table->export_rr_settle = $6; }
 | DIGEST SETTLE TIME settle { this_table->digest_settle = $4; }
 ;

table_opts:
   /* empty */
 | table_opts table_opt ';'
 ;

table_opt_list:
   /* empty */
 | '{' table_opts '}'
 ;


/* Definition of protocols */

conf: proto { proto_postconfig(); } ;

proto_start:
   PROTOCOL { $$ = SYM_PROTO; }
 | TEMPLATE { $$ = SYM_TEMPLATE; }
 ;

proto_name:
   /* EMPTY */ {
     struct symbol *s = cf_default_name(new_config, this_proto->protocol->template, &this_proto->protocol->name_counter);
     s->class = this_proto->class;
     s->proto = this_proto;
     this_proto->name = s->name;
     }
 | symbol {
     cf_define_symbol(new_config, $1, this_proto->class, proto, this_proto);
     this_proto->name = $1->name;
   }
 | FROM CF_SYM_KNOWN {
     if (($2->class != SYM_TEMPLATE) && ($2->class != SYM_PROTO)) cf_error("Template or protocol name expected");

     struct symbol *s = cf_default_name(new_config, this_proto->protocol->template, &this_proto->protocol->name_counter);
     s->class = this_proto->class;
     s->proto = this_proto;
     this_proto->name = s->name;

     proto_copy_config(this_proto, $2->proto);
   }
 | symbol FROM CF_SYM_KNOWN {
     if (($3->class != SYM_TEMPLATE) && ($3->class != SYM_PROTO)) cf_error("Template or protocol name expected");

     cf_define_symbol(new_config, $1, this_proto->class, proto, this_proto);
     this_proto->name = $1->name;

     proto_copy_config(this_proto, $3->proto);
   }
 ;

proto_item:
   /* EMPTY */
 | DISABLED bool { this_proto->disabled = $2; }
 | DEBUG debug_mask { this_proto->debug = $2; }
 | MRTDUMP mrtdump_mask { this_proto->mrtdump = $2; }
 | ROUTER ID idval { this_proto->router_id = $3; }
 | DESCRIPTION text { this_proto->dsc = $2; }
 | VRF text { this_proto->vrf = if_get_by_name($2); }
 | VRF DEFAULT { this_proto->vrf = &default_vrf; }
 ;


channel_start: net_type_base
{
  $$ = this_channel = channel_config_get(NULL, net_label[$1], $1, this_proto);
};

channel_item_:
   TABLE rtable {
     if (this_channel->net_type && ($2->addr_type != this_channel->net_type))
       cf_error("Incompatible table type");
     this_channel->table = $2;
   }
 | IMPORT imexport { this_channel->in_filter = $2; }
 | EXPORT IN net_any imexport {
     if (this_channel->net_type && ($3->type != this_channel->net_type))
       cf_error("Incompatible export prefilter type");
     this_channel->out_subprefix = $3;
     this_channel->out_filter = $4;
   }
 | EXPORT imexport { this_channel->out_filter = $2; }
 | RECEIVE LIMIT limit_spec { this_channel->rx_limit = $3; }
 | IMPORT LIMIT limit_spec { this_channel->in_limit = $3; }
 | EXPORT LIMIT limit_spec { this_channel->out_limit = $3; }
 | PREFERENCE expr { this_channel->preference = $2; check_u16($2); }
 | IMPORT KEEP FILTERED bool {
     if ($4)
       this_channel->in_keep |= RIK_REJECTED;
     else if ((this_channel->in_keep & RIK_PREFILTER) == RIK_PREFILTER)
       cf_error("Import keep filtered is implied by the import table.");
     else
       this_channel->in_keep &= ~RIK_REJECTED;
   }
 | RPKI RELOAD bool { this_channel->rpki_reload = $3; }
 ;

/* To avoid grammar collision in Pipe protocol */
channel_item:
   channel_item_
 | DEBUG debug_mask { this_channel->debug = $2; }
 ;

channel_opts:
   /* empty */
 | channel_opts channel_item ';'
 ;

channel_opt_list:
   /* empty */
 | '{' channel_opts '}'
 ;

channel_end:
{
  if (!this_channel->table)
    cf_error("Routing table not specified");

  this_channel = NULL;
};

proto_channel: channel_start channel_opt_list channel_end;


rtable: CF_SYM_KNOWN {
  cf_assert_symbol($1, SYM_TABLE);
  if (!$1->table) rt_new_default_table($1);
  $$ = $1->table;
} ;

imexport:
   FILTER filter { $$ = $2; }
 | where_filter
 | ALL { $$ = FILTER_ACCEPT; }
 | NONE { $$ = FILTER_REJECT; }
 ;

limit_action:
   /* default */ { $$ = PLA_DISABLE; }
 | ACTION WARN { $$ = PLA_WARN; }
 | ACTION BLOCK { $$ = PLA_BLOCK; }
 | ACTION RESTART { $$ = PLA_RESTART; }
 | ACTION DISABLE { $$ = PLA_DISABLE; }
 ;

limit_spec:
   expr limit_action { $$ = (struct channel_limit){ .limit = $1, $$.action = $2 }; }
 | OFF { $$ = (struct channel_limit){}; }
 ;


conf: debug_default ;

debug_default:
   DEBUG PROTOCOLS debug_mask { new_config->proto_default_debug = $3; }
 | DEBUG CHANNELS debug_mask { new_config->channel_default_debug = $3; }
 | DEBUG TABLES debug_mask { new_config->table_default_debug = $3; }
 | DEBUG COMMANDS expr { new_config->cli_debug = $3; }
 | DEBUG SHOW ROUTE debug_mask { new_config->show_route_debug = $4; }
 ;

/* MRTDUMP PROTOCOLS is in systep/unix/config.Y */

conf: timeformat_base ;

timeformat_which:
   ROUTE { $$ = &new_config->tf_route; }
 | PROTOCOL { $$ = &new_config->tf_proto; }
 | BASE { $$ = &new_config->tf_base; }
 | LOG { $$ = &new_config->tf_log; }
 ;

timeformat_spec:
   timeformat_which TEXT { *$1 = (struct timeformat){$2, NULL, 0}; }
 | timeformat_which TEXT expr TEXT { *$1 = (struct timeformat){$2, $4, (s64) $3 S_}; }
 | timeformat_which ISO SHORT    { *$1 = TM_ISO_SHORT_S; }
 | timeformat_which ISO SHORT MS { *$1 = TM_ISO_SHORT_MS; }
 | timeformat_which ISO SHORT US { *$1 = TM_ISO_SHORT_US; }
 | timeformat_which ISO LONG    { *$1 = TM_ISO_LONG_S; }
 | timeformat_which ISO LONG MS { *$1 = TM_ISO_LONG_MS; }
 | timeformat_which ISO LONG US { *$1 = TM_ISO_LONG_US; }
 ;

timeformat_base:
   TIMEFORMAT timeformat_spec ';'
 ;

/* Interface patterns */

iface_patt_node_init:
   /* EMPTY */ {
     struct iface_patt_node *ipn = cfg_allocz(sizeof(struct iface_patt_node));
     add_tail(&this_ipatt->ipn_list, NODE ipn);
     this_ipn = ipn;
   }
 ;

iface_patt_node_body:
   TEXT { this_ipn->pattern = $1; /* this_ipn->prefix stays zero */ }
 | opttext net_or_ipa { this_ipn->pattern = $1; this_ipn->prefix = $2; }
 ;

iface_negate:
       { this_ipn->positive = 1; }
 | '-' { this_ipn->positive = 0; }
 ;

iface_patt_node:
   iface_patt_node_init iface_negate iface_patt_node_body
 ;


iface_patt_list:
   iface_patt_node
 | iface_patt_list ',' iface_patt_node
 ;

/* For name/mask-only iface patterns */
iface_patt_list_nopx: iface_patt_list { iface_patt_check(); }

iface_patt_init: {
   /* Generic this_ipatt init */
   this_ipatt = cfg_allocz(sizeof(struct iface_patt));
   init_list(&this_ipatt->ipn_list);
 }
 ;

iface_patt:
   iface_patt_init iface_patt_list
 ;

tos:
   CLASS expr { $$ = $2 & 0xfc;        if ($2 > 255) cf_error("TX class must be in range 0-255"); }
 | DSCP expr  { $$ = ($2 & 0x3f) << 2; if ($2 > 63)  cf_error("TX DSCP must be in range 0-63"); }
 ;

/* Direct device route protocol */

proto: dev_proto '}' ;

dev_proto_start: proto_start DIRECT {
     this_proto = proto_config_new(&proto_device, $1);
     init_list(&DIRECT_CFG->iface_list);
     this_proto->late_if_feed = 1;
   }
 ;

dev_proto:
   dev_proto_start proto_name '{'
 | dev_proto proto_item ';'
 | dev_proto proto_channel ';'
 | dev_proto dev_iface_patt ';'
 | dev_proto CHECK LINK bool ';' { DIRECT_CFG->check_link = $4; }
 ;

dev_iface_init:
   /* EMPTY */ {
     this_ipatt = cfg_allocz(sizeof(struct iface_patt));
     add_tail(&DIRECT_CFG->iface_list, NODE this_ipatt);
     init_list(&this_ipatt->ipn_list);
   }
 ;

dev_iface_patt:
   INTERFACE dev_iface_init iface_patt_list
 ;

/* Debug flags */

debug_mask:
   ALL { $$ = ~0; }
 | OFF { $$ = 0; }
 | '{' debug_list '}' { $$ = $2; }
 ;

debug_list:
   debug_flag
 | debug_list ',' debug_flag { $$ = $1 | $3; }
 ;

debug_flag:
   STATES	{ $$ = D_STATES; }
 | ROUTES	{ $$ = D_ROUTES; }
 | FILTERS	{ $$ = D_FILTERS; }
 | INTERFACES	{ $$ = D_IFACES; }
 | EVENTS	{ $$ = D_EVENTS; }
 | PACKETS	{ $$ = D_PACKETS; }
 ;

/* MRTDump flags */

mrtdump_mask:
   ALL { $$ = ~0; }
 | OFF { $$ = 0; }
 | '{' mrtdump_list '}' { $$ = $2; }
 ;

mrtdump_list:
   mrtdump_flag
 | mrtdump_list ',' mrtdump_flag { $$ = $1 | $3; }
 ;

mrtdump_flag:
   STATES	{ $$ = MD_STATES; }
 | MESSAGES	{ $$ = MD_MESSAGES; }
 ;

/* Password lists */

password_list:
   password_list_body
;

password_list_body:
   PASSWORDS '{' password_items '}'
 | password_item
;

password_items:
    /* empty */
  | password_item ';' password_items
;

password_item:
    password_item_begin '{' password_item_params '}' password_item_end
  | password_item_begin password_item_end
;

pass_key: PASSWORD | KEY;

password_item_begin: pass_key bytestring_text
{
  init_password_list();
  if ($2.type == T_BYTESTRING)
    init_password($2.val.bs->data, $2.val.bs->length, password_id++);
  else if ($2.type == T_STRING)
    init_password($2.val.s, strlen($2.val.s), password_id++);
  else bug("Bad bytestring_text");
};

password_item_params:
   /* empty */ { }
 | GENERATE FROM time ';' password_item_params { this_p_item->genfrom = $3; }
 | GENERATE TO time ';' password_item_params { this_p_item->gento = $3; }
 | ACCEPT FROM time ';' password_item_params { this_p_item->accfrom = $3; }
 | ACCEPT TO time ';' password_item_params { this_p_item->accto = $3; }
 | FROM time ';' password_item_params { this_p_item->genfrom = this_p_item->accfrom = $2; }
 | TO time ';' password_item_params { this_p_item->gento = this_p_item->accto = $2; }
 | ID expr ';' password_item_params { this_p_item->id = $2; if ($2 > 255) cf_error("Password ID must be in range 0-255"); }
 | ALGORITHM password_algorithm ';' password_item_params { this_p_item->alg = $2; }
 ;

password_algorithm:
   KEYED MD5	{ $$ = ALG_MD5; }
 | KEYED SHA1	{ $$ = ALG_SHA1; }
 | KEYED SHA256	{ $$ = ALG_SHA256; }
 | KEYED SHA384	{ $$ = ALG_SHA384; }
 | KEYED SHA512	{ $$ = ALG_SHA512; }
 | HMAC MD5	{ $$ = ALG_HMAC_MD5; }
 | HMAC SHA1	{ $$ = ALG_HMAC_SHA1; }
 | HMAC SHA256	{ $$ = ALG_HMAC_SHA256; }
 | HMAC SHA384	{ $$ = ALG_HMAC_SHA384; }
 | HMAC SHA512	{ $$ = ALG_HMAC_SHA512; }
 | BLAKE2S128	{ $$ = ALG_BLAKE2S_128; }
 | BLAKE2S256	{ $$ = ALG_BLAKE2S_256; }
 | BLAKE2B256	{ $$ = ALG_BLAKE2B_256; }
 | BLAKE2B512	{ $$ = ALG_BLAKE2B_512; }
 ;

password_item_end:
{
  password_validate_length(this_p_item);
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
 ;

bfd_items:
   /* empty */
 | bfd_items bfd_item ';'
 ;

bfd_opts:
   '{' bfd_items '}'
 ;

/* Core commands */
CF_CLI_HELP(SHOW, ..., [[Show status information]])

CF_CLI(SHOW STATUS,,, [[Show router status]])
{ cmd_show_status(); } ;

CF_CLI(SHOW MEMORY,,, [[Show memory usage]])
{ cmd_show_memory(); } ;

CF_CLI(SHOW PROTOCOLS, proto_patt2, [<protocol> | \"<pattern>\"], [[Show routing protocols]])
{ proto_apply_cmd_no_lock($3, proto_cmd_show, 0, (union cmd_arg){.verbose  = 0}); } ;

CF_CLI(SHOW PROTOCOLS ALL, proto_patt2, [<protocol> | \"<pattern>\"], [[Show routing protocol details]])
{ proto_apply_cmd_no_lock($4, proto_cmd_show, 0, (union cmd_arg){.verbose  = 1}); } ;

optproto:
   CF_SYM_KNOWN { cf_assert_symbol($1, SYM_PROTO); $$ = $1; }
 | /* empty */ { $$ = NULL; }
 ;

CF_CLI(SHOW INTERFACES,,, [[Show network interfaces]])
{ if_show(); } ;

CF_CLI(SHOW INTERFACES SUMMARY,,, [[Show summary of network interfaces]])
{ if_show_summary(); } ;

CF_CLI_HELP(SHOW ROUTE, ..., [[Show routing table]])
CF_CLI(SHOW ROUTE, r_args, [[[<prefix>|for <prefix>|for <ip>|in <prefix>] [table <t>] [(import|export) table <p>.<c>] [filter <f>|where <cond>] [all] [primary] [filtered] [(export|preexport|noexport) <p>] [protocol <p>] [stats|count]]], [[Show routing table]])
{ rt_show($3); } ;

CF_CLI_OPT(SHOW ROUTE FOR, <ip>|<prefix>)
CF_CLI_OPT(SHOW ROUTE IN, <prefix>)
CF_CLI_OPT(SHOW ROUTE TABLE, <t>)
CF_CLI_OPT(SHOW ROUTE FILTER, <f>)
CF_CLI_OPT(SHOW ROUTE WHERE, <cond>)
CF_CLI_OPT(SHOW ROUTE ALL)
CF_CLI_OPT(SHOW ROUTE PRIMARY)
CF_CLI_OPT(SHOW ROUTE FILTERED)
CF_CLI_OPT(SHOW ROUTE IMPORT, <p>[.<c>])
CF_CLI_OPT(SHOW ROUTE EXPORT, <p>[.<c>])
CF_CLI_OPT(SHOW ROUTE EXPORTED, <p>[.<c>])
CF_CLI_OPT(SHOW ROUTE PREEXPORT, <p>[.<c>])
CF_CLI_OPT(SHOW ROUTE NOEXPORT, <p>[.<c>])
CF_CLI_OPT(SHOW ROUTE PROTOCOL, <p>)
CF_CLI_OPT(SHOW ROUTE STATS)
CF_CLI_OPT(SHOW ROUTE COUNT)

r_args:
   /* empty */ {
     $$ = cfg_allocz(sizeof(struct rt_show_data));
     init_list(&($$->tables));
     $$->filter = FILTER_ACCEPT;
     OBSREF_SET($$->running_on_config, this_cli->main_config);
     $$->cli = this_cli;
     $$->tf_route = this_cli->main_config->tf_route;
   }
 | r_args net_any {
     $$ = $1;
     if ($$->addr) cf_error("Only one prefix expected");
     $$->addr = $2;
     $$->addr_mode = TE_ADDR_EQUAL;
   }
 | r_args FOR r_args_for {
     $$ = $1;
     if ($$->addr) cf_error("Only one prefix expected");
     $$->addr = $3;
     $$->addr_mode = TE_ADDR_FOR;
   }
 | r_args IN net_any {
     $$ = $1;
     if ($$->addr) cf_error("Only one prefix expected");
     if (!net_type_match($3, NB_IP)) cf_error("Only IP networks accepted for 'in' argument");
     $$->addr = $3;
     $$->addr_mode = TE_ADDR_IN;
   }
| r_args TABLE CF_SYM_KNOWN {
     cf_assert_symbol($3, SYM_TABLE);
     if (!$3->table) cf_error("Table %s not configured", $3->name);
     $$ = $1;
     rt_show_add_table($$, $3->table->table);
     $$->tables_defined_by = RSD_TDB_DIRECT;
   }
 | r_args TABLE ALL {
     struct rtable_config *t;
     $$ = $1;
     WALK_LIST(t, this_cli->main_config->tables)
       rt_show_add_table($$, t->table);
     $$->tables_defined_by = RSD_TDB_ALL;
   }
 | r_args IMPORT TABLE channel_arg {
     if (!($4->in_keep & RIK_PREFILTER)) cf_error("No import table in channel %s.%s", $4->proto->name, $4->name);
     struct rt_show_data_rtable *rsdr = rt_show_add_table($$, $4->table);
     rsdr->name = "import";
     rsdr->prefilter = $4;
     $$->tables_defined_by = RSD_TDB_DIRECT;
   }
 | r_args EXPORT TABLE channel_arg {
     if (!($4->out_table)) cf_error("No export table in channel %s.%s", $4->proto->name, $4->name);
     struct rt_show_data_rtable *rsdr = rt_show_add_exporter($$, $4->out_table);
     rsdr->name = "export";
     $$->tables_defined_by = RSD_TDB_DIRECT;
   }
 | r_args FILTER filter {
     $$ = $1;
     if ($$->filter != FILTER_ACCEPT) cf_error("Filter specified twice");
     $$->filter = $3;
   }
 | r_args where_filter {
     $$ = $1;
     if ($$->filter != FILTER_ACCEPT) cf_error("Filter specified twice");
     $$->filter = $2;
   }
 | r_args ALL {
     $$ = $1;
     $$->verbose = 1;
   }
 | r_args PRIMARY {
     $$ = $1;
     $$->primary_only = 1;
   }
 | r_args FILTERED {
     $$ = $1;
     $$->filtered = 1;
   }
 | r_args export_mode CF_SYM_KNOWN {
     cf_assert_symbol($3, SYM_PROTO);
     struct proto_config *c = (struct proto_config *) $3->proto;
     $$ = $1;
     if ($$->export_mode) cf_error("Export specified twice");
     if (!c->proto) cf_error("%s is not a protocol", $3->name);
     $$->export_mode = $2;
     $$->export_protocol = c->proto;
     $$->tables_defined_by = RSD_TDB_INDIRECT;
   }
 | r_args export_mode channel_arg {
     $$ = $1;
     if ($$->export_mode) cf_error("Export specified twice");
     $$->export_mode = $2;
     $$->export_channel = $3;
     $$->tables_defined_by = RSD_TDB_INDIRECT;
   }
 | r_args PROTOCOL CF_SYM_KNOWN {
     cf_assert_symbol($3, SYM_PROTO);
     struct proto_config *c = (struct proto_config *) $3->proto;
     $$ = $1;
     if ($$->show_protocol) cf_error("Protocol specified twice");
     if (!c->proto) cf_error("%s is not a protocol", $3->name);
     $$->show_protocol = c->proto;
     $$->tables_defined_by = RSD_TDB_INDIRECT;
   }
 | r_args STATS {
     $$ = $1;
     $$->stats = 1;
   }
 | r_args COUNT {
     $$ = $1;
     $$->stats = 2;
   }
 ;

r_args_for:
  r_args_for_val {
    $$ = cfg_alloc($1.length);
    net_copy($$, &$1);
  }
 | net_vpn4_
 | net_vpn6_
 | net_ip6_sadr_
 | VPN_RD IP4 {
    $$ = cfg_alloc(sizeof(net_addr_vpn4));
    net_fill_vpn4($$, $2, IP4_MAX_PREFIX_LENGTH, $1);
  }
 | VPN_RD IP6 {
    $$ = cfg_alloc(sizeof(net_addr_vpn6));
    net_fill_vpn6($$, $2, IP6_MAX_PREFIX_LENGTH, $1);
  }
 | IP6 FROM IP6 {
    $$ = cfg_alloc(sizeof(net_addr_ip6_sadr));
    net_fill_ip6_sadr($$, $1, IP6_MAX_PREFIX_LENGTH, $3, IP6_MAX_PREFIX_LENGTH);
  }
 | CF_SYM_KNOWN {
     if ($1->class == (SYM_CONSTANT | T_IP))
     {
       $$ = cfg_alloc(ipa_is_ip4(SYM_VAL($1).ip) ? sizeof(net_addr_ip4) : sizeof(net_addr_ip6));
       net_fill_ip_host($$, SYM_VAL($1).ip);
     }
     else if (($1->class == (SYM_CONSTANT | T_NET)) && net_type_match(SYM_VAL($1).net, NB_IP | NB_VPN))
       $$ = (net_addr *) SYM_VAL($1).net; /* Avoid const warning */
     else
       cf_error("IP address or network constant expected");
   }
 ;

r_args_for_val:
   net_ip4_
 | net_ip6_
 | IP4 { net_fill_ip4(&($$), $1, IP4_MAX_PREFIX_LENGTH); }
 | IP6 { net_fill_ip6(&($$), $1, IP6_MAX_PREFIX_LENGTH); }

export_mode:
   PREEXPORT	{ $$ = RSEM_PREEXPORT; }
 | EXPORT	{ $$ = RSEM_EXPORT; }
 | NOEXPORT	{ $$ = RSEM_NOEXPORT; }
 | EXPORTED	{ $$ = RSEM_EXPORTED; }
 ;

/* This is ugly hack */
channel_sym:
   IPV4		{ $$ = "ipv4"; }
 | IPV4_MC	{ $$ = "ipv4-mc"; }
 | IPV4_MPLS	{ $$ = "ipv4-mpls"; }
 | IPV6		{ $$ = "ipv6"; }
 | IPV6_MC	{ $$ = "ipv6-mc"; }
 | IPV6_MPLS	{ $$ = "ipv6-mpls"; }
 | IPV6_SADR	{ $$ = "ipv6-sadr"; }
 | VPN4		{ $$ = "vpn4"; }
 | VPN4_MC	{ $$ = "vpn4-mc"; }
 | VPN4_MPLS	{ $$ = "vpn4-mpls"; }
 | VPN6		{ $$ = "vpn6"; }
 | VPN6_MC	{ $$ = "vpn6-mc"; }
 | VPN6_MPLS	{ $$ = "vpn6-mpls"; }
 | ROA4		{ $$ = "roa4"; }
 | ROA6		{ $$ = "roa6"; }
 | FLOW4	{ $$ = "flow4"; }
 | FLOW6	{ $$ = "flow6"; }
 | MPLS		{ $$ = "mpls"; }
 | PRI		{ $$ = "pri"; }
 | SEC		{ $$ = "sec"; }
 ;

channel_arg:
   CF_SYM_KNOWN '.' channel_sym {
     cf_assert_symbol($1, SYM_PROTO);
     struct proto *p =  $1->proto->proto;
     if (!p) cf_error("%s is not a protocol", $1->name);
     $$ = proto_find_channel_by_name(p, $3);
     if (!$$) cf_error("Channel %s.%s not found", $1->name, $3);
   }
 ;

CF_CLI_HELP(SHOW SYMBOLS, ..., [[Show all known symbolic names]])
CF_CLI(SHOW SYMBOLS, sym_args, [table|filter|function|protocol|template|<symbol>], [[Show all known symbolic names]])
{ cmd_show_symbols($3); } ;

CF_CLI_OPT(SHOW SYMBOLS TABLE)
CF_CLI_OPT(SHOW SYMBOLS FILTER)
CF_CLI_OPT(SHOW SYMBOLS FUNCTION)
CF_CLI_OPT(SHOW SYMBOLS PROTOCOL)
CF_CLI_OPT(SHOW SYMBOLS TEMPLATE)

sym_args:
   /* empty */ {
     $$ = cfg_allocz(sizeof(struct sym_show_data));
     $$->config = this_cli->main_config;
   }
 | sym_args TABLE { $$ = $1; $$->type = SYM_TABLE; }
 | sym_args FILTER { $$ = $1; $$->type = SYM_FILTER; }
 | sym_args FUNCTION { $$ = $1; $$->type = SYM_FUNCTION; }
 | sym_args PROTOCOL { $$ = $1; $$->type = SYM_PROTO; }
 | sym_args TEMPLATE { $$ = $1; $$->type = SYM_TEMPLATE; }
 | sym_args CF_SYM_KNOWN { $$ = $1; $$->sym = $2; }
 ;


CF_CLI_HELP(DUMP, ..., [[Dump debugging information]])
CF_CLI(DUMP RESOURCES,,, [[Dump all allocated resource]])
{ rdump(&root_pool, 0); cli_msg(0, ""); } ;
CF_CLI(DUMP SOCKETS,,, [[Dump open sockets]])
{ sk_dump_all(); cli_msg(0, ""); } ;
CF_CLI(DUMP EVENTS,,, [[Dump event log]])
{ io_log_dump(); cli_msg(0, ""); } ;
CF_CLI(DUMP INTERFACES,,, [[Dump interface information]])
{ if_dump_all(); cli_msg(0, ""); } ;
CF_CLI(DUMP NEIGHBORS,,, [[Dump neighbor cache]])
{ neigh_dump_all(); cli_msg(0, ""); } ;
CF_CLI(DUMP ATTRIBUTES,,, [[Dump attribute cache]])
{ ea_dump_all(); cli_msg(0, ""); } ;
CF_CLI(DUMP ROUTES,,, [[Dump routes]])
{ rt_dump_all(); cli_msg(0, ""); } ;
CF_CLI(DUMP TABLES,,, [[Dump table connections]])
{ rt_dump_hooks_all(); cli_msg(0, ""); } ;
CF_CLI(DUMP PROTOCOLS,,, [[Dump protocol information]])
{ protos_dump_all(); cli_msg(0, ""); } ;
CF_CLI(DUMP FILTER ALL,,, [[Dump all filters in linearized form]])
{ filters_dump_all(); cli_msg(0, ""); } ;

CF_CLI(EVAL, term, <expr>, [[Evaluate an expression]])
{ cmd_eval(f_linearize($2, 1)); } ;

partial_opt:
  PARTIAL term {
    struct f_val val;
    if (f_eval(f_linearize($2, 1), &val) > F_RETURN) cf_error("Runtime error");
    if (val.type != T_PREFIX_SET) cf_error("Partial spec must be prefix set");
    $$ = val.val.ti;
  }
  | /* empty */ { $$ = NULL; }
  ;

CF_CLI(DISABLE, proto_patt opttext, (<protocol> | \"<pattern>\" | all) [message], [[Disable protocol]])
{ proto_apply_cmd($2, proto_cmd_disable, 1, (uintptr_t) $3); } ;
CF_CLI(ENABLE, proto_patt opttext, (<protocol> | \"<pattern>\" | all) [message], [[Enable protocol]])
{ proto_apply_cmd($2, proto_cmd_enable, 1, (uintptr_t) $3); } ;
CF_CLI(RESTART, proto_patt opttext, (<protocol> | \"<pattern>\" | all) [message], [[Restart protocol]])
{ proto_apply_cmd($2, proto_cmd_restart, 1, (uintptr_t) $3); } ;
CF_CLI(RELOAD FILTERS, proto_patt partial_opt, (<protocol> | \"<pattern>\" | all) [partial <prefix set>], [[Reload protocol filters]])
{ proto_call_cmd_reload($3, CMD_RELOAD, $4); } ;
CF_CLI(RELOAD FILTERS IN, proto_patt partial_opt, <protocol> | \"<pattern>\" | all, [[Reload protocol filters (just imported routes)]])
{ proto_call_cmd_reload($4, CMD_RELOAD_IN, $5); } ;
CF_CLI(RELOAD FILTERS OUT, proto_patt partial_opt, <protocol> | \"<pattern>\" | all, [[Reload protocol filters (just exported routes)]])
{ proto_call_cmd_reload($4, CMD_RELOAD_OUT, $5); } ;

CF_CLI_HELP(DEBUG, ..., [[Control protocol debugging via BIRD logs]])
CF_CLI(DEBUG, debug_args, (<protocol> | <channel> | \"<pattern>\" | all) (all | off | { states|routes|filters|interfaces|events|packets [, ...] }), [[Control protocol debugging via BIRD logs]])
{ /* Done in debug_args */  };

CF_CLI_OPT(DEBUG ALL)
CF_CLI_OPT(DEBUG OFF)
CF_CLI_OPT(DEBUG STATES)
CF_CLI_OPT(DEBUG ROUTES)
CF_CLI_OPT(DEBUG FILTERS)
CF_CLI_OPT(DEBUG INTERFACES)
CF_CLI_OPT(DEBUG EVENTS)
CF_CLI_OPT(DEBUG PACKETS)

debug_args:
   proto_patt debug_mask { proto_apply_cmd($1, proto_cmd_debug, 1, $2);  }
 | channel_arg debug_mask { channel_cmd_debug($1, $2); }
 ;

CF_CLI_HELP(MRTDUMP, ..., [[Control protocol debugging via MRTdump files]])
CF_CLI(MRTDUMP, proto_patt mrtdump_mask, (<protocol> | \"<pattern>\" | all) (all | off | { states|messages [, ...] }), [[Control protocol debugging via MRTdump format]])
{ proto_apply_cmd($2, proto_cmd_mrtdump, 1, $3); } ;

CF_CLI(RESTRICT,,,[[Restrict current CLI session to safe commands]])
{ this_cli->restricted = 1; cli_msg(16, "Access restricted"); } ;

proto_patt:
   CF_SYM_KNOWN { cf_assert_symbol($1, SYM_PROTO); $$.ptr = $1; $$.patt = 0; }
 | ALL  { $$.ptr = NULL; $$.patt = 1; }
 | TEXT { $$.ptr = $1; $$.patt = 1; }
 ;

proto_patt2:
   CF_SYM_KNOWN { cf_assert_symbol($1, SYM_PROTO); $$.ptr = $1; $$.patt = 0; }
 |      { $$.ptr = NULL; $$.patt = 1; }
 | TEXT { $$.ptr = $1; $$.patt = 1; }
 ;

CF_CODE

CF_END
