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
static struct static_route *this_srt, *last_srt;
static struct f_inst **this_srt_last_cmd;

static void
static_route_finish(void)
{ }

CF_DECLS

CF_KEYWORDS(STATIC, ROUTE, VIA, DROP, REJECT, PROHIBIT, PREFERENCE, CHECK, LINK)
CF_KEYWORDS(WEIGHT, RECURSIVE, IGP, TABLE, BLACKHOLE, UNREACHABLE, BFD, MPLS)


CF_GRAMMAR

CF_ADDTO(proto, static_proto '}')

static_proto_start: proto_start STATIC
{
  this_proto = proto_config_new(&proto_static, $1);
  static_init_config(STATIC_CFG);
};

static_proto:
   static_proto_start proto_name '{'
 | static_proto proto_item ';'
 | static_proto proto_channel ';' { this_proto->net_type = $2->net_type; }
 | static_proto CHECK LINK bool ';' { STATIC_CFG->check_link = $4; }
 | static_proto IGP TABLE rtable ';' { STATIC_CFG->igp_table = $4; }
 | static_proto stat_route stat_route_opt_list ';' { static_route_finish(); }
 ;

stat_nexthop_via: VIA
{
  if (last_srt)
  {
    last_srt = (last_srt->mp_next = cfg_allocz(sizeof(struct static_route)));
    last_srt->net = this_srt->net;
  }
  else
  {
    last_srt = this_srt;
    rem_node(&this_srt->n);
  }

  last_srt->mp_head = this_srt;
  last_srt->dest = RTD_UNICAST;
};

stat_nexthop_ident:
    stat_nexthop_via ipa ipa_scope {
      last_srt->via = $2;
      last_srt->iface = $3;
      add_tail(&STATIC_CFG->neigh_routes, &last_srt->n);
    }
  | stat_nexthop_via TEXT {
      last_srt->via = IPA_NONE;
      last_srt->if_name = $2;
      add_tail(&STATIC_CFG->iface_routes, &last_srt->n);
    }
  | stat_nexthop_ident MPLS label_stack {
    last_srt->label_count = $3[0];
    last_srt->label_stack = &($3[1]);
  }
  | stat_nexthop_ident WEIGHT expr {
    last_srt->weight = $3 - 1;
    if (($3<1) || ($3>256)) cf_error("Weight must be in range 1-256");
  }
  | stat_nexthop_ident BFD bool { last_srt->use_bfd = $3; cf_check_bfd($3); }
;

stat_nexthop:
    stat_nexthop_ident
  | stat_nexthop stat_nexthop_ident
;

stat_route0: ROUTE net_any {
     this_srt = cfg_allocz(sizeof(struct static_route));
     add_tail(&STATIC_CFG->other_routes, &this_srt->n);
     this_srt->net = $2;
     this_srt_last_cmd = &(this_srt->cmds);
     this_srt->mp_next = NULL;
     last_srt = NULL;
  }
 ;

stat_route:
   stat_route0 stat_nexthop
 | stat_route0 RECURSIVE ipa {
      this_srt->dest = RTDX_RECURSIVE;
      this_srt->via = $3;
   }
 | stat_route0 RECURSIVE ipa MPLS label_stack {
      this_srt->dest = RTDX_RECURSIVE;
      this_srt->via = $3;
      this_srt->label_count = $5[0];
      this_srt->label_stack = &($5[1]);
   }
 | stat_route0 DROP		{ this_srt->dest = RTD_BLACKHOLE; }
 | stat_route0 REJECT		{ this_srt->dest = RTD_UNREACHABLE; }
 | stat_route0 BLACKHOLE	{ this_srt->dest = RTD_BLACKHOLE; }
 | stat_route0 UNREACHABLE	{ this_srt->dest = RTD_UNREACHABLE; }
 | stat_route0 PROHIBIT		{ this_srt->dest = RTD_PROHIBIT; }
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


CF_CLI(SHOW STATIC, optsym, [<name>], [[Show details of static protocol]])
{ static_show(proto_get_named($3, &proto_static)); } ;

CF_CODE

CF_END
