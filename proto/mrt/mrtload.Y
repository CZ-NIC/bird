
CF_HDR

#include "proto/mrt/mrtload.h"

CF_DEFINES

#define MRTLOAD_CFG ((struct mrtload_config *) this_proto)
#define MRTLOAD_BGP_CC ((struct bgp_channel_config *) this_channel)

CF_DECLS

CF_KEYWORDS(TABLE, FILTER, FILENAME, ADD, MRTLOAD, TIME, REPLAY, ACCELERATE,
            IPV4, IPV6, MULTICAST, MPLS, VPN4, VPN6, FLOW4, FLOW6)


CF_GRAMMAR

proto: mrtload_proto ;

mrtload_proto_start: proto_start MRTLOAD
{
  this_proto = proto_config_new(&proto_mrtload, $1);
  BGP_RT_CFG = &MRTLOAD_CFG->rte_class;
};


mrt_channel_start: bgp_afi
{
  const struct bgp_af_desc *desc = bgp_get_af_desc($1);
  log("hereee in afiiiii");

  if (!desc)
    cf_error("Unknown AFI/SAFI");

  this_channel = channel_config_get(&channel_mrtload, desc->name, desc->net, this_proto);
  MRTLOAD_CFG->channel_cf = MRTLOAD_BGP_CC;
  log("this channel %x %x", this_channel, MRTLOAD_BGP_CC);

  /* New channel */
  if (!MRTLOAD_BGP_CC->desc)
  {
    MRTLOAD_BGP_CC->c.in_filter = FILTER_ACCEPT;
    MRTLOAD_BGP_CC->c.out_filter = FILTER_REJECT;
    MRTLOAD_BGP_CC->c.ra_mode = RA_UNDEF;
    MRTLOAD_BGP_CC->afi = $1;
    MRTLOAD_BGP_CC->desc = desc;
    MRTLOAD_BGP_CC->next_hop_keep = 0xff; /* undefined */
    MRTLOAD_BGP_CC->gr_able = 0xff;	/* undefined */
    MRTLOAD_BGP_CC->llgr_able = 0xff;	/* undefined */
    MRTLOAD_BGP_CC->llgr_time = ~0U;	/* undefined */
    MRTLOAD_BGP_CC->min_llgr_time = ~0U; /* undefined */
    MRTLOAD_BGP_CC->max_llgr_time = ~0U; /* undefined */
    MRTLOAD_BGP_CC->aigp = 0xff;	/* undefined */
  }
};

mrt_channel_item:
 /* empty */
 | channel_item ';'
 ;

mrt_proto_channel: mrt_channel_start //mrt_channel_item;

mrtload_proto_opts:
   /* empty */
 | mrtload_proto_opts mrtload_proto_item ';'
 ;

 mrtload_proto_item:
   proto_item
 | FILENAME text	{ MRTLOAD_CFG->filename = $2; log("file %s", $2);}
 | REPLAY ACCELERATE expr	{ MRTLOAD_CFG->replay_accel = $3; }
 | TABLE rtable {
    MRTLOAD_CFG->table_cf = $2;
    log("table_cf %x, MRTLOAD_BGP_CC %x", $2, MRTLOAD_BGP_CC);
    if ($2->addr_type == NET_IP4){
      MRTLOAD_BGP_CC->igp_table_ip4 = $2;
      log("MRTLOAD_BGP_CC->igp_table_ip4");}
    else if ($2->addr_type == NET_IP6){
      MRTLOAD_BGP_CC->igp_table_ip6 = $2;
      log("MRTLOAD_BGP_CC->igp_table_ip6");}
    else
      cf_error("Mismatched IGP table type");
    }
 ;


mrtload_proto:
  mrtload_proto_start proto_name '{' mrt_proto_channel ';' mrtload_proto_opts '}' { 
    mrtload_check_config(this_proto, MRTLOAD_BGP_CC);
  };


CF_CODE

CF_END
