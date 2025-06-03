/*
 *	BIRD -- Multi-Threaded Routing Toolkit (MRT) Protocol
 *
 *	(c) 2017--2018 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2017--2018 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/mrt/mrt.h"

CF_DEFINES

#define MRT_CFG ((struct mrt_config *) this_proto)
#define MRT_BGP_CC ((struct bgp_channel_config *) this_channel)

CF_DECLS

CF_KEYWORDS(MRT, TABLE, FILTER, FILENAME, PERIOD, ALWAYS, ADD, PATH, DUMP, TO, MRTLOAD,
            IPV4, IPV6, MULTICAST, MPLS, VPN4, VPN6, FLOW4, FLOW6, HUUU)

%type <md> mrt_dump_args


CF_GRAMMAR

proto: mrt_proto
     | mrtload_proto
     ;

mrt_proto_start: proto_start MRT
{
  this_proto = proto_config_new(&proto_mrt, $1);
};

mrtload_proto_start: proto_start MRTLOAD
{
  this_proto = proto_config_new(&proto_mrt, $1);
};

mrt_proto_item:
   proto_item
 | TABLE rtable		{ MRT_CFG->table_cf = $2; }
 | TABLE TEXT		{ MRT_CFG->table_expr = $2; }
 | FILTER filter	{ MRT_CFG->filter = $2; }
 | where_filter		{ MRT_CFG->filter = $1; }
 | FILENAME text	{ MRT_CFG->filename = $2; }
 | PERIOD expr		{ MRT_CFG->period = $2; }
 | ALWAYS ADD PATH bool	{ MRT_CFG->always_add_path = $4; }
 ;


mrt_proto_opts:
   /* empty */
 | mrt_proto_opts mrt_proto_item ';'
 ;

mrt_load_proto_item:
   proto_item
 | TABLE rtable		{ MRT_CFG->table_cf = $2; }
 /* | TABLE TEXT		{ MRT_CFG->table_expr = $2; } moved */
 /*| FILTER filter	{ MRT_CFG->filter = $2; }  //TODO?
 | where_filter		{ MRT_CFG->filter = $1; } */
 | FILENAME text	{ MRT_CFG->filename = $2; }
 ;



mrt_get_table:
   /* empty */
 | TABLE rtable ';' {
    MRT_CFG->table_cf = $2;
    log("table_cf %x", $2);
    if ($2->addr_type == NET_IP4){
      BGP_CC->igp_table_ip4 = $2;
      log("BGP_CC->igp_table_ip4");}
    else if ($2->addr_type == NET_IP6){
      BGP_CC->igp_table_ip6 = $2;
      log("BGP_CC->igp_table_ip4");}
    else
      cf_error("Mismatched IGP table type");
    }
 ;

mrt_tab:
   /* empty */
 | '{' mrt_get_table '}'

mgt_get_bgp_channel: bgp_afi
{
  log("%x", $1);
  const struct bgp_af_desc *desc = bgp_get_af_desc($1);

  if (!desc)
    cf_error("Unknown AFI/SAFI");

  this_channel = channel_config_get(&channel_bgp, desc->name, desc->net, this_proto);
  MRT_CFG->channel_cf = MRT_BGP_CC;

  /* New channel */
  if (!MRT_BGP_CC->desc)
  {
    MRT_BGP_CC->c.in_filter = FILTER_UNDEF;
    MRT_BGP_CC->c.out_filter = FILTER_UNDEF;
    MRT_BGP_CC->c.ra_mode = RA_UNDEF;
    MRT_BGP_CC->afi = $1;
    MRT_BGP_CC->desc = desc;
    MRT_BGP_CC->next_hop_keep = 0xff; /* undefined */
    MRT_BGP_CC->gr_able = 0xff;	/* undefined */
    MRT_BGP_CC->llgr_able = 0xff;	/* undefined */
    MRT_BGP_CC->llgr_time = ~0U;	/* undefined */
    MRT_BGP_CC->min_llgr_time = ~0U; /* undefined */
    MRT_BGP_CC->max_llgr_time = ~0U; /* undefined */
    MRT_BGP_CC->aigp = 0xff;	/* undefined */
  }
};


mrt_load_proto_opts:
   /* empty */
 | mrt_load_proto_opts mgt_get_bgp_channel mrt_tab ';'
 | mrt_load_proto_opts mrt_load_proto_item ';'
 ;


mrt_proto:
   mrt_proto_start proto_name '{' mrt_proto_opts '}' { mrt_check_config(this_proto); };

mrtload_proto:
   mrtload_proto_start proto_name '{' mrt_load_proto_opts '}' { mrt_load_check_config(this_proto, MRT_BGP_CC); };


CF_CLI_HELP(MRT DUMP, [table <name>|\"<pattern>\"] [to \"<file>\"] [filter <filter>|where <where filter>] , [[Save MRT Table Dump into a file]])
CF_CLI(MRT DUMP, mrt_dump_args, [table <name>|\"<pattern>\"] [to \"<file>\"] [filter <filter>|where <where filter>], [[Save mrt table dump v2 of table name <t> right now]])
{ mrt_dump_cmd($3); } ;

CF_CLI_OPT(MRT DUMP TABLE, <name>|\"<pattern>\")
CF_CLI_OPT(MRT DUMP TO, \"<file>\")
CF_CLI_OPT(MRT DUMP FILTER, <filter>)
CF_CLI_OPT(MRT DUMP WHERE, <where filter>)

mrt_dump_args:
   /* empty */ { $$ = cfg_allocz(sizeof(struct mrt_dump_data)); }
 | mrt_dump_args TABLE rtable	{ $$ = $1; $$->table_ptr = $3->table; }
 | mrt_dump_args TABLE TEXT	{ $$ = $1; $$->table_expr = $3; }
 | mrt_dump_args FILTER filter	{ $$ = $1; $$->filter = $3; }
 | mrt_dump_args where_filter	{ $$ = $1; $$->filter = $2; }
 | mrt_dump_args TO text 	{ $$ = $1; $$->filename = $3; }
 ;


CF_CODE

CF_END
