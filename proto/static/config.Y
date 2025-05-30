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
static struct f_inst *this_srt_cmds, *this_srt_last_cmd;
static uint this_srt_aspa_max;

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
static_route_finish(void)
{
  if (net_type_match(this_srt->net, NB_DEST) == !this_srt->dest)
    cf_error("Unexpected or missing nexthop/type");

  this_srt->cmds = f_linearize(this_srt_cmds, 0);
}

CF_DECLS

CF_KEYWORDS(STATIC, ROUTE, VIA, DROP, REJECT, PROHIBIT, PREFERENCE, CHECK, LINK, DEV)
CF_KEYWORDS(ONLINK, WEIGHT, RECURSIVE, IGP, TABLE, BLACKHOLE, UNREACHABLE, BFD, MPLS)
CF_KEYWORDS(TRANSIT, PROVIDERS)


CF_GRAMMAR

proto: static_proto '}' ;

static_proto_start: proto_start STATIC
{
  this_proto = proto_config_new(&proto_static, $1);
  init_list(&STATIC_CFG->routes);
};

static_proto:
   static_proto_start proto_name '{'
 | static_proto proto_item ';'
 | static_proto proto_channel ';' { this_proto->net_type = $2->net_type; }
 | static_proto mpls_channel ';'
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
    VIA text_or_ipa {
      this_snh = static_nexthop_new();
      if ($2.type == T_IP)
        this_snh->via = $2.val.ip;
      else if ($2.type == T_STRING)
        this_snh->iface = if_get_by_name($2.val.s);
    } ipa_scope {
      if ($2.type == T_IP)
        this_snh->iface = $4;
      else if ($4)
        cf_error("syntax error, unexpected '%'");
    }
  | stat_nexthop DEV text {
      this_snh->iface = if_get_by_name($3);
    }
  | stat_nexthop MPLS label_stack {
    this_snh->mls = $3;
  }
  | stat_nexthop ONLINK bool {
    this_snh->onlink = $3;
    if (this_snh->use_bfd && this_snh->onlink)
      cf_error("Options 'bfd' and 'onlink' cannot be combined");
  }
  | stat_nexthop WEIGHT expr {
    this_snh->weight = $3 - 1;
    if (($3<1) || ($3>256)) cf_error("Weight must be in range 1-256");
  }
  | stat_nexthop BFD bool {
    this_snh->use_bfd = $3; cf_check_bfd($3);
    if (this_snh->use_bfd && this_snh->onlink)
      cf_error("Options 'bfd' and 'onlink' cannot be combined");
  }
;

stat_nexthops:
    stat_nexthop
  | stat_nexthops stat_nexthop
;

stat_mpls:
   /* empty */
 | MPLS expr { this_srt->mpls_label = $2; if ($2 >= MPLS_MAX_LABEL) cf_error("MPLS label must be less than 2^20"); }
 ;

stat_route0: ROUTE net_any {
     this_srt = cfg_allocz(sizeof(struct static_route));
     add_tail(&STATIC_CFG->routes, &this_srt->n);
     this_srt->net = $2;
     this_srt->mpls_label = (uint) -1;
     this_srt_cmds = NULL;
     this_srt_last_cmd = NULL;
     this_srt->mp_next = NULL;
     this_snh = NULL;
  } stat_mpls
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
 | stat_route0 PROVIDERS {
    if (this_srt->net->type != NET_ASPA) cf_error("Provider settings available only for ASPA");
    this_srt->aspa = cfg_alloc(sizeof (adata) + (this_srt_aspa_max = 8) * sizeof (u32));
    this_srt->aspa->length = 0;
   } stat_aspa_providers
 | stat_route0 TRANSIT {
    if (this_srt->net->type != NET_ASPA) cf_error("Transit settings available only for ASPA");
    /* Allocate an explicit zero */
    this_srt->aspa = cfg_alloc(sizeof (adata) + sizeof (u32));
    this_srt->aspa->length = sizeof(u32);
    ((u32 *) this_srt->aspa->data)[0] = 0;
   }
 ;

stat_aspa_provider: expr {
  if (this_srt->aspa->length == this_srt_aspa_max * sizeof(u32))
  {
    adata *new = cfg_alloc(sizeof (adata) + (this_srt_aspa_max * 2) * sizeof (u32));
    memcpy(new, this_srt->aspa, this_srt->aspa->length + sizeof(adata));
    this_srt->aspa = new;
    this_srt_aspa_max *= 2;
  }

  ((u32 *) this_srt->aspa->data)[this_srt->aspa->length / sizeof(u32)] = $1;
  this_srt->aspa->length += sizeof(u32);
}

stat_aspa_providers: stat_aspa_provider | stat_aspa_providers ',' stat_aspa_provider ;

stat_route_item:
   cmd {
     if (this_srt_last_cmd)
       this_srt_last_cmd->next = $1;
     else
       this_srt_cmds = $1;
     this_srt_last_cmd = $1;
   }
 ;

stat_route_opts:
   /* empty */
 | stat_route_opts stat_route_item
 ;

stat_route_opt_list:
   /* empty */
 | '{' stat_route_opts '}'
 ;


CF_CLI(SHOW STATIC, optproto, [<name>], [[Show details of static protocol]])
{ PROTO_WALK_CMD($3, &proto_static, p) static_show(p); } ;

CF_CODE

CF_END
