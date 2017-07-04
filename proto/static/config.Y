/*
 *	BIRD -- Static Protocol Configuration
 *
 *	(c) 1998--1999 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/static/static.h"

CF_DEFINES

#define STATIC_CFG ((struct static_config *) this_proto)
static struct static_route *this_srt, *this_snh;
static struct f_inst **this_srt_last_cmd;

static struct static_route *
static_nexthop_new(void)
{
  struct static_route *nh = this_srt;

  if (this_snh)
  {
    /* Additional next hop */
    nh = cfg_allocz(sizeof(struct static_route));
    nh->net = this_srt->net;
    this_snh->mp_next = nh;
  }

  nh->dest = RTD_UNICAST;
  nh->mp_head = this_srt;
  return nh;
};

static void
static_route_start(net_addr *n)
{
  this_srt = cfg_allocz(sizeof(struct static_route));
  add_tail(&STATIC_CFG->routes, &this_srt->n);
  this_srt->net = n;
  this_srt_last_cmd = &(this_srt->cmds);
  this_srt->mp_next = NULL;
  this_snh = NULL;
}

static void
static_route_finish(void)
{
  if (net_type_match(this_srt->net, NB_DEST) == !this_srt->dest)
    cf_error("Unexpected or missing nexthop/type");
}

static void
static_flow_action(u64 ec)
{
  NEW_F_VAL;

  val->type = T_EC; val->val.ec = ec;
  struct f_inst *fic = f_new_inst();
  fic->code = 'C'; fic->a1.p = val;
  *this_srt_last_cmd = f_generate_complex(
    P('C','a'), 'a',
    f_new_dynamic_attr(EAF_TYPE_EC_SET, T_ECLIST, EA_CODE(EAP_BGP, BA_EXT_COMMUNITY)),
    fic
  );
  this_srt_last_cmd = &((*this_srt_last_cmd)->next);
}

CF_DECLS

%type <fl> float_rate

CF_KEYWORDS(STATIC, ROUTE, VIA, DROP, REJECT, PROHIBIT, PREFERENCE, CHECK, LINK)
CF_KEYWORDS(WEIGHT, RECURSIVE, IGP, TABLE, BLACKHOLE, UNREACHABLE, BFD, MPLS)
CF_KEYWORDS(RATE, SAMPLE, LAST, DSCP)
CF_KEYWORDS_CS(mBps, mbps, Bps, bps, kBps, kbps, MBps, Mbps, GBps, Gbps, TBps, Tbps)


CF_GRAMMAR

CF_ADDTO(proto, static_proto '}')

static_proto_start: proto_start STATIC
{
  this_proto = proto_config_new(&proto_static, $1);
  init_list(&STATIC_CFG->routes);
};

static_proto:
   static_proto_start proto_name '{'
 | static_proto proto_item ';'
 | static_proto proto_channel ';' { this_proto->net_type = $2->net_type; }
 | static_proto CHECK LINK bool ';' { STATIC_CFG->check_link = $4; }
 | static_proto IGP TABLE rtable ';' {
    if ($4->addr_type == NET_IP4)
      STATIC_CFG->igp_table_ip4 = $4;
    else if ($4->addr_type == NET_IP6)
      STATIC_CFG->igp_table_ip6 = $4;
    else
      cf_error("Incompatible IGP table type");
   }
 | static_proto stat_route stat_route_opt_list ';' { static_route_finish(); }
 ;

stat_nexthop:
    VIA ipa ipa_scope {
      this_snh = static_nexthop_new();
      this_snh->via = $2;
      this_snh->iface = $3;
    }
  | VIA TEXT {
      this_snh = static_nexthop_new();
      this_snh->via = IPA_NONE;
      this_snh->iface = if_get_by_name($2);
    }
  | stat_nexthop MPLS label_stack {
    this_snh->mls = $3;
  }
  | stat_nexthop WEIGHT expr {
    this_snh->weight = $3 - 1;
    if (($3<1) || ($3>256)) cf_error("Weight must be in range 1-256");
  }
  | stat_nexthop BFD bool {
    this_snh->use_bfd = $3; cf_check_bfd($3);
  }
;

stat_nexthops:
    stat_nexthop
  | stat_nexthops stat_nexthop
;

stat_route0: ROUTE net_any {
     if (net_type_match($2, NB_FLOW))
       cf_error("Flowspec rules are not routes. Apologize!");
     static_route_start($2);
  }
 ;

stat_route:
   stat_route0 stat_nexthops
 | stat_route0 RECURSIVE ipa {
      this_srt->dest = RTDX_RECURSIVE;
      this_srt->via = $3;
   }
 | stat_route0 RECURSIVE ipa MPLS label_stack {
      this_srt->dest = RTDX_RECURSIVE;
      this_srt->via = $3;
      this_srt->mls = $5;
   }
 | stat_route0			{ this_srt->dest = RTD_NONE; }
 | stat_route0 DROP		{ this_srt->dest = RTD_BLACKHOLE; }
 | stat_route0 REJECT		{ this_srt->dest = RTD_UNREACHABLE; }
 | stat_route0 BLACKHOLE	{ this_srt->dest = RTD_BLACKHOLE; }
 | stat_route0 UNREACHABLE	{ this_srt->dest = RTD_UNREACHABLE; }
 | stat_route0 PROHIBIT		{ this_srt->dest = RTD_PROHIBIT; }
 | net_flow_ { static_route_start($1); } flowspec_action 
 ;

stat_route_item:
   cmd { *this_srt_last_cmd = $1; this_srt_last_cmd = &($1->next); }
 ;

stat_route_opts:
   /* empty */
 | stat_route_opts stat_route_item
 ;

stat_route_opt_list:
   /* empty */
 | '{' stat_route_opts '}'
 ;

flowspec_action: ACTION '{' flowspec_action0 '}' ;

flowspec_action0:
  /* empty */
 | flowspec_action0 RATE float_rate ';' { static_flow_action(flow_action_encode_byterate(0, $3)); }
 | flowspec_action0 SAMPLE ';' { static_flow_action(flow_action_encode_sample()); }
 | flowspec_action0 LAST ';' { static_flow_action(flow_action_encode_last()); }
 | flowspec_action0 RT cnum ',' cnum ';' { static_flow_action(flow_action_encode_redirect($3, $5)); }
 | flowspec_action0 DSCP NUM ';' { static_flow_action(flow_action_encode_dscp($3)); }
;

float_rate:
   NUM mBps { $$ = $1 / 1000.0; }
 | NUM mbps { $$ = $1 / 8000.0; }
 | NUM Bps { $$ = $1; }
 | NUM bps { $$ = $1 / 8.0; }
 | NUM kBps { $$ = 1000.0 * $1; }
 | NUM kbps { $$ = 1000.0 * $1 / 8.0; }
 | NUM MBps { $$ = 1000000.0 * $1; }
 | NUM Mbps { $$ = 1000000.0 * $1 / 8.0; }
 | NUM GBps { $$ = 1000000000.0 * $1; }
 | NUM Gbps { $$ = 1000000000.0 * $1 / 8.0; }
 | NUM TBps { $$ = 1000000000000.0 * $1; }
 | NUM Tbps { $$ = 1000000000000.0 * $1 / 8.0; }
;

CF_CLI(SHOW STATIC, optsym, [<name>], [[Show details of static protocol]])
{ static_show(proto_get_named($3, &proto_static)); } ;

CF_CODE

CF_END
