
CF_HDR

#include "proto/mrt/mrt_load.h"

CF_DEFINES

#define MRTLOAD_CFG ((struct mrtload_config *) this_proto)
#define MRT_BGP_CC ((struct bgp_channel_config *) this_channel)

CF_DECLS

CF_KEYWORDS(TABLE, FILTER, FILENAME, ADD, MRTLOAD, TIME, REPLAY,
            IPV4, IPV6, MULTICAST, MPLS, VPN4, VPN6, FLOW4, FLOW6)


CF_GRAMMAR

proto: mrtload_proto;

mrtload_proto_start: proto_start MRTLOAD
{
  this_proto = proto_config_new(&proto_mrtload, $1);
  BGP_RT_CFG = &MRTLOAD_CFG->rte_class;
};


mrtload_proto_item:
   proto_item
 | TABLE rtable		{ MRTLOAD_CFG->table_cf = $2; }
 | FILENAME text	{ MRTLOAD_CFG->filename = $2; }
 | TIME REPLAY expr	{ MRTLOAD_CFG->time_replay = $3; }
 ;



mrt_get_table:
   /* empty */
 | TABLE rtable ';' {
    MRTLOAD_CFG->table_cf = $2;
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

mrtload_tab:
   /* empty */
 | '{' mrt_get_table '}'

mrt_get_bgp_channel: bgp_afi
{
  log("%x", $1);
  const struct bgp_af_desc *desc = bgp_get_af_desc($1);

  if (!desc)
    cf_error("Unknown AFI/SAFI");

  this_channel = channel_config_get(&channel_mrtload, desc->name, desc->net, this_proto);
  MRTLOAD_CFG->channel_cf = MRT_BGP_CC;

  /* New channel */
  if (!MRT_BGP_CC->desc)
  {
    MRT_BGP_CC->c.in_filter = FILTER_ACCEPT;
    MRT_BGP_CC->c.out_filter = FILTER_REJECT;
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


mrtload_proto_opts:
   /* empty */
 | mrtload_proto_opts mrt_get_bgp_channel mrtload_tab ';'
 | mrtload_proto_opts mrtload_proto_item ';'
 | mrtload_proto_opts bgp_attr_for_route
 ;


mrtload_proto:
   mrtload_proto_start proto_name '{' mrtload_proto_opts '}' { mrtload_check_config(this_proto, MRT_BGP_CC); };


CF_CODE

CF_END
