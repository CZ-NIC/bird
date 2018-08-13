/*
 *	BIRD -- Static Protocol Configuration
 *
 *	(c) 1998--1999 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/static/static.h"

CF_CTX

struct static_route *this_srt, *this_snh;
struct f_inst **this_srt_last_cmd;

CF_DEFINES

#define STATIC_CFG ((struct static_config *) ctx->this_proto)

static struct static_route *
static_nexthop_new(struct cf_context *ctx)
{
  struct static_route *nh = ctx->this_srt;

  if (ctx->this_snh)
  {
    /* Additional next hop */
    nh = cfg_allocz(sizeof(struct static_route));
    nh->net = ctx->this_srt->net;
    ctx->this_snh->mp_next = nh;
  }

  nh->dest = RTD_UNICAST;
  nh->mp_head = ctx->this_srt;
  return nh;
};

static void
static_route_finish(struct cf_context *ctx)
{
  if (net_type_match(ctx->this_srt->net, NB_DEST) == !ctx->this_srt->dest)
    cf_error(ctx, "Unexpected or missing nexthop/type");
}

CF_DECLS

CF_KEYWORDS(STATIC, ROUTE, VIA, DROP, REJECT, PROHIBIT, PREFERENCE, CHECK, LINK)
CF_KEYWORDS(ONLINK, WEIGHT, RECURSIVE, IGP, TABLE, BLACKHOLE, UNREACHABLE, BFD, MPLS)


CF_GRAMMAR

proto: static_proto '}' ;

static_proto_start: proto_start STATIC
{
  ctx->this_proto = proto_config_new(ctx, &proto_static, $1);
  init_list(&STATIC_CFG->routes);
};

static_proto:
   static_proto_start proto_name '{'
 | static_proto proto_item ';'
 | static_proto proto_channel ';' { ctx->this_proto->net_type = $2->net_type; }
 | static_proto CHECK LINK bool ';' { STATIC_CFG->check_link = $4; }
 | static_proto IGP TABLE rtable ';' {
    if ($4->addr_type == NET_IP4)
      STATIC_CFG->igp_table_ip4 = $4;
    else if ($4->addr_type == NET_IP6)
      STATIC_CFG->igp_table_ip6 = $4;
    else
      cf_error(ctx, "Incompatible IGP table type");
   }
 | static_proto stat_route stat_route_opt_list ';' { static_route_finish(ctx); }
 ;

stat_nexthop:
    VIA ipa ipa_scope {
      ctx->this_snh = static_nexthop_new(ctx);
      ctx->this_snh->via = $2;
      ctx->this_snh->iface = $3;
    }
  | VIA TEXT {
      ctx->this_snh = static_nexthop_new(ctx);
      ctx->this_snh->via = IPA_NONE;
      ctx->this_snh->iface = if_get_by_name($2);
    }
  | stat_nexthop MPLS label_stack {
    ctx->this_snh->mls = $3;
  }
  | stat_nexthop ONLINK bool {
    ctx->this_snh->onlink = $3;
  }
  | stat_nexthop WEIGHT expr {
    ctx->this_snh->weight = $3 - 1;
    if (($3<1) || ($3>256)) cf_error(ctx, "Weight must be in range 1-256");
  }
  | stat_nexthop BFD bool {
    ctx->this_snh->use_bfd = $3; BFD_CHECK($3);
  }
;

stat_nexthops:
    stat_nexthop
  | stat_nexthops stat_nexthop
;

stat_route0: ROUTE net_any {
     ctx->this_srt = cfg_allocz(sizeof(struct static_route));
     add_tail(&STATIC_CFG->routes, &ctx->this_srt->n);
     ctx->this_srt->net = $2;
     ctx->this_srt_last_cmd = &(ctx->this_srt->cmds);
     ctx->this_srt->mp_next = NULL;
     ctx->this_snh = NULL;
  }
 ;

stat_route:
   stat_route0 stat_nexthops
 | stat_route0 RECURSIVE ipa {
      ctx->this_srt->dest = RTDX_RECURSIVE;
      ctx->this_srt->via = $3;
   }
 | stat_route0 RECURSIVE ipa MPLS label_stack {
      ctx->this_srt->dest = RTDX_RECURSIVE;
      ctx->this_srt->via = $3;
      ctx->this_srt->mls = $5;
   }
 | stat_route0			{ ctx->this_srt->dest = RTD_NONE; }
 | stat_route0 DROP		{ ctx->this_srt->dest = RTD_BLACKHOLE; }
 | stat_route0 REJECT		{ ctx->this_srt->dest = RTD_UNREACHABLE; }
 | stat_route0 BLACKHOLE	{ ctx->this_srt->dest = RTD_BLACKHOLE; }
 | stat_route0 UNREACHABLE	{ ctx->this_srt->dest = RTD_UNREACHABLE; }
 | stat_route0 PROHIBIT		{ ctx->this_srt->dest = RTD_PROHIBIT; }
 ;

stat_route_item:
   cmd { *ctx->this_srt_last_cmd = $1; ctx->this_srt_last_cmd = &($1->next); }
 ;

stat_route_opts:
   /* empty */
 | stat_route_opts stat_route_item
 ;

stat_route_opt_list:
   /* empty */
 | '{' stat_route_opts '}'
 ;


CF_CLI(SHOW STATIC, optsym, [<name>], [[Show details of static protocol]])
{ static_show(proto_get_named(ctx, $3, &proto_static)); } ;

CF_CODE

CF_END
