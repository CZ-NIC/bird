/*
 *	BIRD -- Configuration Parser Top
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#define PARSER 1

#include "nest/bird.h"
#include "conf/conf.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/timer.h"
#include "lib/string.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/route.h"
#include "nest/bfd.h"
#include "nest/cli.h"
#include "filter/filter.h"

/* FIXME: Turn on YYERROR_VERBOSE and work around lots of bison bugs? */

CF_DEFINES

static void
check_u16(uint val)
{
  if (val > 0xFFFF)
    cf_error("Value %u out of range (0-65535)", val);
}

#define cf_assert(cond, ...) do { if (!(cond)) cf_error(__VA_ARGS__); } while (0)
static inline void cf_assert_symbol(const struct symbol *sym, uint class) {
  switch (class) {
    case SYM_PROTO: cf_assert(sym->class == SYM_PROTO, "Protocol name required"); break;
    case SYM_TEMPLATE: cf_assert(sym->class == SYM_TEMPLATE, "Protocol template name required"); break;
    case SYM_FUNCTION: cf_assert(sym->class == SYM_FUNCTION, "Function name required"); break;
    case SYM_FILTER: cf_assert(sym->class == SYM_FILTER, "Filter name required"); break;
    case SYM_TABLE: cf_assert(sym->class == SYM_TABLE, "Table name required"); break;
    case SYM_ATTRIBUTE: cf_assert(sym->class == SYM_ATTRIBUTE, "Custom attribute name required"); break;
    case SYM_MPLS_DOMAIN: cf_assert(sym->class == SYM_MPLS_DOMAIN, "MPLS domain name required"); break;
    case SYM_MPLS_RANGE: cf_assert(sym->class == SYM_MPLS_RANGE, "MPLS range name required"); break;
    case SYM_VARIABLE: cf_assert((sym->class & ~0xff) == SYM_VARIABLE, "Variable name required"); break;
    case SYM_CONSTANT: cf_assert((sym->class & ~0xff) == SYM_CONSTANT, "Constant name required"); break;
    default: bug("This shall not happen");
  }
}

static inline const char *
cf_type_name(enum f_type type)
{
  /* There is already f_type_name(), but this uses names more suited
     to configuration error messages */
  switch (type)
  {
  case T_INT:		return "Number";
  case T_BOOL:		return "Boolean";
  case T_IP:		return "IP address";
  case T_NET:		return "Network";
  case T_STRING:	return "String";
  case T_BYTESTRING:	return "Bytestring";
  default:		return "???";
  }
}

static inline void
cf_assert_type(const struct f_val val, enum f_type type)
{
  if (val.type != type)
    cf_error("%s expected", cf_type_name(type));
}


CF_DECLS

%union {
  uint i;
  u32 i32;
  u64 i64;
  vpn_rd rd;
  ip_addr a;
  ip4_addr ip4;
  ip6_addr ip6;
  net_addr net;
  net_addr *net_ptr;
  struct symbol *s;
  struct keyword *kw;
  const char *t;
  struct rtable_config *r;
  struct channel_config *cc;
  struct channel *c;
  struct f_inst *x;
  struct {
    struct f_inst *begin, *end;
  } xp;
  enum filter_return fret;
  enum ec_subtype ecs;
  struct f_dynamic_attr fda;
  struct f_static_attr fsa;
  struct f_lval flv;
  struct f_line *fl;
  struct f_arg *fa;
  const struct filter *f;
  struct f_tree *e;
  struct f_trie *trie;
  struct f_val v;
  struct password_item *p;
  struct rt_show_data *ra;
  struct sym_show_data *sd;
  struct lsadb_show_data *ld;
  struct mrt_dump_data *md;
  struct mpls_show_ranges_cmd *msrc;
  struct bfd_show_sessions_cmd *bssc;
  struct iface *iface;
  void *g;
  btime time;
  struct f_prefix px;
  struct proto_spec ps;
  struct channel_limit cl;
  struct timeformat tf;
  struct timeformat *tfp;
  mpls_label_stack *mls;
  const struct adata *bs;
  struct aggr_item_node *ai;
}

%token END CLI_MARKER INVALID_TOKEN ELSECOL DDOT
%token GEQ LEQ NEQ AND OR IMP PP
%token PO PC
%token <i> NUM ENUM_TOKEN
%token <ip4> IP4
%token <ip6> IP6
%token <rd> VPN_RD
%token <s> CF_SYM_KNOWN CF_SYM_UNDEFINED CF_SYM_METHOD_BARE CF_SYM_METHOD_ARGS
%token <t> TEXT
%token <bs> BYTETEXT
%type <iface> ipa_scope

%type <i> expr bool pxlen4
%type <i32> idval
%type <time> expr_us time
%type <a> ipa
%type <net> net_ip4_ net_ip4 net_ip6_ net_ip6 net_ip_ net_ip net_or_ipa
%type <net_ptr> net_ net_any net_vpn4_ net_vpn6_ net_vpn_ net_roa4_ net_roa6_ net_roa_ net_ip6_sadr_ net_mpls_ net_aspa_
%type <mls> label_stack_start label_stack

%type <t> text opttext
%type <bs> bytestring
%type <s> symbol symbol_known

%type <v> conf_expr bytestring_expr text_or_ipa bytestring_or_text

%nonassoc PREFIX_DUMMY
%left AND OR
%nonassoc '=' '<' '>' '~' GEQ LEQ NEQ NMA IMP PO PC
%left '+' '-' PP
%left '*' '/' '%'
%left '!'
%nonassoc '.'

%start config

/* See r_args */
%expect 2

CF_KEYWORDS(DEFINE, ON, OFF, YES, NO, S, MS, US, PORT, VPN, MPLS, FROM, MAX, AS)

CF_GRAMMAR

/*
 * There are several basic configuration datatypes
 * (regular parser rule name, raw lexer token name):
 *  - bool (bool)
 *  - number (expr, NUM)
 *  - string (text, TEXT)
 *  - bytestring (bytestring, BYTETEXT)
 *  - IP address (ipa, IP4/IP6)
 *  - Network address (net_*)
 *
 * Regular parser grammar rules for these datatypes should include lexer token,
 * symbol (to resolve constants) and term (to evaluate expression). But that
 * makes them uncomposable, as e.g. 'text | ipa' leads to parser conflict.
 * Therefore, we have rules like text_or_ipa that combines more lexer tokens.
 *
 * In general, configuration grammar should use regular parser rules for these
 * datatypes and avoid raw lexer tokens. When raw lexer tokens must be used,
 * 'conf_expr' grammar rule should be added to handle constants and expressions.
 */

/* Basic config file structure */

config: conf_entries END { return 0; }
 | CLI_MARKER cli_cmd { return 0; }
 ;

conf_entries:
   /* EMPTY */
 | conf_entries conf
 ;

conf: ';' ;


/* Constant expressions */

conf: definition ;

definition:
   DEFINE symbol '=' term ';' {
     struct f_val *val = cfg_allocz(sizeof(struct f_val));
     *val = cf_eval($4, T_VOID);
     cf_define_symbol(new_config, $2, SYM_CONSTANT | val->type, val, val);
   }
 ;

conf_expr:
   symbol_known {
     /* If the symbol is not a constant, we pass empty f_val and fail later on type check */
     $$ = (($1->class & ~0xff) == SYM_CONSTANT) ? *$1->val : (struct f_val) {};
   }
 | '(' term ')' { $$ = cf_eval($2, T_VOID); }
 ;

symbol: CF_SYM_UNDEFINED | CF_SYM_KNOWN | KEYWORD ;
symbol_known: CF_SYM_KNOWN ;


/* Numbers */

expr:
   NUM
 | conf_expr { cf_assert_type($1, T_INT); $$ = $1.val.i; }
 ;

expr_us:
   expr S  { $$ = $1 S_; }
 | expr MS { $$ = $1 MS_; }
 | expr US { $$ = $1 US_; }
 ;


/* Switches */

bool:
   ON { $$ = 1; }
 | YES { $$ = 1; }
 | TRUE { $$ = 1; }
 | OFF { $$ = 0; }
 | NO { $$ = 0; }
 | FALSE { $$ = 0; }
 | /* Silence means agreement */ { $$ = 1; }
 | NUM { $$ = !!$1; cf_warn("Number argument for switch option deprecated"); }
 | conf_expr {
     if (($1.type != T_BOOL) && ($1.type != T_INT))
       cf_error("Switch value expected");

     if ($1.type == T_INT)
       cf_warn("Number argument for switch option deprecated");

     $$ = !!$1.val.i;
   }
 ;


/* Addresses */

ipa:
   IP4 { $$ = ipa_from_ip4($1); }
 | IP6 { $$ = ipa_from_ip6($1); }
 | conf_expr { cf_assert_type($1, T_IP); $$ = $1.val.ip; }
 ;

ipa_scope:
   /* empty */ { $$ = NULL; }
 | '%' symbol { $$ = if_get_by_name($2->name); }
 ;


/* Networks - internal */

pxlen4:
   '/' NUM {
     if ($2 > IP4_MAX_PREFIX_LENGTH) cf_error("Invalid prefix length %u", $2);
     $$ = $2;
   }
 ;

net_ip4_: IP4 pxlen4
{
  net_fill_ip4(&($$), $1, $2);

  net_addr_ip4 *n = (void *) &($$);
  if (!net_validate_ip4(n))
    cf_error("Invalid IPv4 prefix %I4/%d, maybe you wanted %I4/%d",
	     n->prefix, n->pxlen, ip4_and(n->prefix, ip4_mkmask(n->pxlen)), n->pxlen);
};

net_ip6_: IP6 '/' NUM
{
  if ($3 > IP6_MAX_PREFIX_LENGTH)
    cf_error("Invalid prefix length %u", $3);

  net_fill_ip6(&($$), $1, $3);

  net_addr_ip6 *n = (void *) &($$);
  if (!net_validate_ip6(n))
    cf_error("Invalid IPv6 prefix %I6/%d, maybe you wanted %I6/%d",
	     n->prefix, n->pxlen, ip6_and(n->prefix, ip6_mkmask(n->pxlen)), n->pxlen);
};

net_ip6_sadr_: IP6 '/' NUM FROM IP6 '/' NUM
{
  if ($3 > IP6_MAX_PREFIX_LENGTH)
    cf_error("Invalid prefix length %u", $3);

  if ($7 > IP6_MAX_PREFIX_LENGTH)
    cf_error("Invalid prefix length %u", $7);

  $$ = cfg_alloc(sizeof(net_addr_ip6_sadr));
  net_fill_ip6_sadr($$, $1, $3, $5, $7);

  net_addr_ip6_sadr *n = (void *) $$;
  if (!net_validate_ip6_sadr(n))
    cf_error("Invalid SADR IPv6 prefix %I6/%d from %I6/%d, maybe you wanted %I6/%d from %I6/%d",
	     n->dst_prefix, n->dst_pxlen, n->src_prefix, n->src_pxlen,
	     ip6_and(n->dst_prefix, ip6_mkmask(n->dst_pxlen)), n->dst_pxlen,
	     ip6_and(n->src_prefix, ip6_mkmask(n->src_pxlen)), n->src_pxlen);
};

net_vpn4_: VPN_RD net_ip4_
{
  $$ = cfg_alloc(sizeof(net_addr_vpn4));
  net_fill_vpn4($$, net4_prefix(&$2), net4_pxlen(&$2), $1);
}

net_vpn6_: VPN_RD net_ip6_
{
  $$ = cfg_alloc(sizeof(net_addr_vpn6));
  net_fill_vpn6($$, net6_prefix(&$2), net6_pxlen(&$2), $1);
}

net_roa4_: net_ip4_ MAX expr AS expr
{
  $$ = cfg_alloc(sizeof(net_addr_roa4));
  net_fill_roa4($$, net4_prefix(&$1), net4_pxlen(&$1), $3, $5);
  if ($3 < net4_pxlen(&$1) || $3 > IP4_MAX_PREFIX_LENGTH)
    cf_error("Invalid max prefix length %u", $3);
};

net_roa6_: net_ip6_ MAX expr AS expr
{
  $$ = cfg_alloc(sizeof(net_addr_roa6));
  net_fill_roa6($$, net6_prefix(&$1), net6_pxlen(&$1), $3, $5);
  if ($3 < net6_pxlen(&$1) || $3 > IP6_MAX_PREFIX_LENGTH)
    cf_error("Invalid max prefix length %u", $3);
};

net_mpls_: MPLS expr
{
  $$ = cfg_alloc(sizeof(net_addr_mpls));
  net_fill_mpls($$, $2);
}

net_aspa_: ASPA expr
{
  $$ = cfg_alloc(sizeof(net_addr_aspa));
  net_fill_aspa($$, $2);
}

net_ip_: net_ip4_ | net_ip6_ ;
net_vpn_: net_vpn4_ | net_vpn6_ ;
net_roa_: net_roa4_ | net_roa6_ ;

net_:
   net_ip_ { $$ = cfg_alloc($1.length); net_copy($$, &($1)); }
 | net_vpn_
 | net_roa_
 | net_flow_
 | net_ip6_sadr_
 | net_mpls_
 | net_aspa_
 ;


/* Networks - regular */

net_ip4:
   net_ip4_
 | conf_expr {
     if (($1.type != T_NET) || ($1.val.net->type != NET_IP4))
       cf_error("IPv4 network expected");
     $$ = * $1.val.net;
   }
 ;

net_ip6:
   net_ip6_
 | conf_expr {
     if (($1.type != T_NET) || ($1.val.net->type != NET_IP6))
       cf_error("IPv6 network expected");
     $$ = * $1.val.net;
   }
 ;

net_ip:
   net_ip_
 | conf_expr {
     if (($1.type != T_NET) || !net_is_ip($1.val.net))
       cf_error("IP network expected");
     $$ = * $1.val.net;
   }
 ;

net_any:
   net_
 | CF_SYM_KNOWN {
     if ($1->class != (SYM_CONSTANT | T_NET))
       cf_error("Network expected");
     $$ = (net_addr *) SYM_VAL($1).net; /* Avoid const warning */
   }
 ;

label_stack_start: expr
{
  $$ = cfg_allocz(sizeof(mpls_label_stack));
  $$->len = 1;
  $$->stack[0] = $1;
};

label_stack:
    label_stack_start
  | label_stack '/' expr {
    if ($1->len >= MPLS_MAX_LABEL_STACK)
      cf_error("Too many labels in stack");
    $1->stack[$1->len++] = $3;
    $$ = $1;
  }
;


/* Strings */

text:
   TEXT
 | conf_expr { cf_assert_type($1, T_STRING); $$ = $1.val.s; }
 ;

opttext:
    TEXT
 | /* empty */ { $$ = NULL; }
 ;

time:
   text {
     $$ = tm_parse_time($1);
     if (!$$)
       cf_error("Invalid date/time");
   }
 ;


/* Bytestrings */

bytestring:
   BYTETEXT
 | bytestring_expr { cf_assert_type($1, T_BYTESTRING); $$ = $1.val.bs; }
 ;

bytestring_expr:
   conf_expr
 | term_bs { $$ = cf_eval($1, T_VOID); }
 ;


/* Mixed ones */

/* number | IPv4 -> number */
idval:
   NUM { $$ = $1; }
 | IP4 { $$ = ip4_to_u32($1); }
 | conf_expr {
     if (($1.type == T_INT) || ($1.type == T_QUAD))
       $$ = $1.val.i;
     else if (($1.type == T_IP) && ipa_is_ip4($1.val.ip))
       $$ = ipa_to_u32($1.val.ip);
     else
       cf_error("Number or IPv4 address expected");
   }
 ;

/* net | ipa -> net */
net_or_ipa:
   net_ip4_
 | net_ip6_
 | IP4 { net_fill_ip4(&($$), $1, IP4_MAX_PREFIX_LENGTH); }
 | IP6 { net_fill_ip6(&($$), $1, IP6_MAX_PREFIX_LENGTH); }
 | conf_expr {
     if ($1.type == T_IP)
       net_fill_ip_host(&($$), $1.val.ip);
     else if (($1.type == T_NET) && net_is_ip($1.val.net))
       $$ = * $1.val.net;
     else
       cf_error("IP address/prefix expected");
   }
 ;

/* text | ipa -> f_val */
text_or_ipa:
   TEXT { $$.type = T_STRING; $$.val.s = $1; }
 | IP4 { $$.type = T_IP; $$.val.ip = ipa_from_ip4($1); }
 | IP6 { $$.type = T_IP; $$.val.ip = ipa_from_ip6($1); }
 | conf_expr {
     if (($1.type != T_STRING) && ($1.type != T_IP))
       cf_error("String or IP address expected");
     $$ = $1;
   }
 ;

/* bytestring | text -> f_val */
bytestring_or_text:
   BYTETEXT { $$.type = T_BYTESTRING; $$.val.bs = $1; }
 | TEXT { $$.type = T_STRING; $$.val.s = $1; }
 | bytestring_expr {
     if (($1.type != T_BYTESTRING) && ($1.type != T_STRING))
       cf_error("Bytestring or string expected");
     $$ = $1;
   }
 ;


CF_CODE

CF_END
