/*
 *	BIRD -- Border Gateway Protocol Configuration
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/bgp/bgp.h"

CF_DEFINES

#define BGP_CFG ((struct bgp_config *) this_proto)
#define BGP_CC ((struct bgp_channel_config *) this_channel)

CF_DECLS

CF_KEYWORDS(BGP, LOCAL, NEIGHBOR, AS, HOLD, TIME, CONNECT, RETRY, KEEPALIVE,
	MULTIHOP, STARTUP, VIA, NEXT, HOP, SELF, DEFAULT, PATH, METRIC, ERROR,
	START, DELAY, FORGET, WAIT, ENABLE, DISABLE, AFTER, BGP_PATH,
	BGP_LOCAL_PREF, BGP_MED, BGP_ORIGIN, BGP_NEXT_HOP, BGP_ATOMIC_AGGR,
	BGP_AGGREGATOR, BGP_COMMUNITY, BGP_EXT_COMMUNITY, BGP_LARGE_COMMUNITY,
	SOURCE, ADDRESS, PASSWORD, RR, RS, CLIENT, CLUSTER, ID, AS4, ADVERTISE,
	IPV4, CAPABILITIES, LIMIT, PASSIVE, PREFER, OLDER, MISSING, LLADDR,
	DROP, IGNORE, ENHANCED, ROUTE, REFRESH, INTERPRET, COMMUNITIES, BGP_ORIGINATOR_ID,
	BGP_CLUSTER_LIST, IGP, TABLE, GATEWAY, DIRECT, RECURSIVE, MED, TTL,
	SECURITY, DETERMINISTIC, SECONDARY, ALLOW, BFD, ADD, PATHS, RX, TX,
	GRACEFUL, RESTART, AWARE, CHECK, LINK, PORT, EXTENDED, MESSAGES, SETKEY,
	STRICT, BIND, CONFEDERATION, MEMBER, MULTICAST, FLOW4, FLOW6, LONG,
	LIVED, STALE, IMPORT, IBGP, EBGP, MANDATORY, INTERNAL, EXTERNAL, SETS,
	DYNAMIC, RANGE, NAME, DIGITS, BGP_AIGP, AIGP, ORIGINATE, COST, ENFORCE,
	FIRST, FREE, VALIDATE, BASE, ROLE, ROLES, PEER, PROVIDER, CUSTOMER,
	RS_SERVER, RS_CLIENT, REQUIRE, BGP_OTC, GLOBAL)

%type <i> bgp_nh
%type <i32> bgp_afi

CF_KEYWORDS(CEASE, PREFIX, LIMIT, HIT, ADMINISTRATIVE, SHUTDOWN, RESET, PEER,
	CONFIGURATION, CHANGE, DECONFIGURED, CONNECTION, REJECTED, COLLISION,
	OUT, OF, RESOURCES)

%type<i> bgp_cease_mask bgp_cease_list bgp_cease_flag bgp_role_name

CF_GRAMMAR

proto: bgp_proto '}'  ;

bgp_proto_start: proto_start BGP {
     this_proto = proto_config_new(&proto_bgp, $1);
     BGP_CFG->local_port = BGP_PORT;
     BGP_CFG->remote_port = BGP_PORT;
     BGP_CFG->multihop = -1;	/* undefined */
     BGP_CFG->hold_time = 240;
     BGP_CFG->initial_hold_time = 240;
     BGP_CFG->compare_path_lengths = 1;
     BGP_CFG->igp_metric = 1;
     BGP_CFG->connect_delay_time = 5;
     BGP_CFG->connect_retry_time = 120;
     BGP_CFG->error_amnesia_time = 300;
     BGP_CFG->error_delay_time_min = 60;
     BGP_CFG->error_delay_time_max = 300;
     BGP_CFG->enable_refresh = 1;
     BGP_CFG->enable_enhanced_refresh = 1;
     BGP_CFG->enable_as4 = 1;
     BGP_CFG->enable_hostname = 0;
     BGP_CFG->capabilities = 2;
     BGP_CFG->interpret_communities = 1;
     BGP_CFG->allow_as_sets = 1;
     BGP_CFG->default_local_pref = 100;
     BGP_CFG->gr_mode = BGP_GR_AWARE;
     BGP_CFG->gr_time = 120;
     BGP_CFG->llgr_mode = -1;
     BGP_CFG->llgr_time = 3600;
     BGP_CFG->setkey = 1;
     BGP_CFG->local_role = BGP_ROLE_UNDEFINED;
     BGP_CFG->dynamic_name = "dynbgp";
     BGP_CFG->check_link = -1;
   }
 ;

bgp_loc_opts:
   /* empty */
 | bgp_loc_opts PORT expr { BGP_CFG->local_port = $3; if (($3<1) || ($3>65535)) cf_error("Invalid port number"); }
 | bgp_loc_opts AS expr { BGP_CFG->local_as = $3; }
 ;

bgp_nbr_opts:
   /* empty */
 | bgp_nbr_opts PORT expr { BGP_CFG->remote_port = $3; if (($3<1) || ($3>65535)) cf_error("Invalid port number"); }
 | bgp_nbr_opts AS expr { BGP_CFG->remote_as = $3; }
 | bgp_nbr_opts INTERNAL { BGP_CFG->peer_type = BGP_PT_INTERNAL; }
 | bgp_nbr_opts EXTERNAL { BGP_CFG->peer_type = BGP_PT_EXTERNAL; }
 ;

bgp_cease_mask:
   /* true -> all except connection collision */
   bool { $$ = $1 ? ~(1 << 7) : 0; }
 | '{' bgp_cease_list '}' { $$ = $2; }
 ;

bgp_cease_list:
   bgp_cease_flag
 | bgp_cease_list ',' bgp_cease_flag { $$ = $1 | $3; }
 ;

bgp_cease_flag:
   CEASE			{ $$ = 1 << 0; }
 | PREFIX LIMIT HIT		{ $$ = 1 << 1; }
 | ADMINISTRATIVE SHUTDOWN	{ $$ = 1 << 2; }
 | PEER DECONFIGURED		{ $$ = 1 << 3; }
 | ADMINISTRATIVE RESET		{ $$ = 1 << 4; }
 | CONNECTION REJECTED		{ $$ = 1 << 5; }
 | CONFIGURATION CHANGE		{ $$ = 1 << 6; }
 | CONNECTION COLLISION		{ $$ = 1 << 7; }
 | OUT OF RESOURCES		{ $$ = 1 << 8; }
 ;

bgp_role_name:
   PEER      { $$ = BGP_ROLE_PEER; }
 | PROVIDER  { $$ = BGP_ROLE_PROVIDER; }
 | CUSTOMER  { $$ = BGP_ROLE_CUSTOMER; }
 | RS_SERVER { $$ = BGP_ROLE_RS_SERVER; }
 | RS_CLIENT { $$ = BGP_ROLE_RS_CLIENT; }
 ;

bgp_proto:
   bgp_proto_start proto_name '{'
 | bgp_proto proto_item ';'
 | bgp_proto bgp_proto_channel ';'
 | bgp_proto mpls_channel ';'
 | bgp_proto LOCAL bgp_loc_opts ';'
 | bgp_proto LOCAL ipa ipa_scope bgp_loc_opts ';' {
     BGP_CFG->local_ip = $3;
     if ($4) BGP_CFG->iface = $4;
   }
 | bgp_proto NEIGHBOR bgp_nbr_opts ';'
 | bgp_proto NEIGHBOR ipa ipa_scope bgp_nbr_opts ';' {
     if (ipa_nonzero(BGP_CFG->remote_ip) || BGP_CFG->remote_range)
       cf_error("Only one neighbor per BGP instance is allowed");
     BGP_CFG->remote_ip = $3;
     if ($4) BGP_CFG->iface = $4;
   }
 | bgp_proto NEIGHBOR RANGE net_ip bgp_nbr_opts ';' {
     if (ipa_nonzero(BGP_CFG->remote_ip) || BGP_CFG->remote_range)
       cf_error("Only one neighbor per BGP instance is allowed");
     net_addr *n = cfg_alloc($4.length);
     net_copy(n, &($4));
     BGP_CFG->remote_range = n;
   }
 | bgp_proto INTERFACE TEXT ';' { BGP_CFG->iface = if_get_by_name($3); }
 | bgp_proto RR CLUSTER ID idval ';' { BGP_CFG->rr_cluster_id = $5; }
 | bgp_proto RR CLIENT bool ';' { BGP_CFG->rr_client = $4; }
 | bgp_proto RS CLIENT bool ';' { BGP_CFG->rs_client = $4; }
 | bgp_proto CONFEDERATION expr ';' { BGP_CFG->confederation = $3; }
 | bgp_proto CONFEDERATION MEMBER bool ';' { BGP_CFG->confederation_member = $4; }
 | bgp_proto HOLD TIME expr ';' { BGP_CFG->hold_time = $4; if (($4 && $4<3) || ($4>65535)) cf_error("Hold time must be in range 3-65535 or zero"); }
 | bgp_proto MIN HOLD TIME expr ';' { BGP_CFG->min_hold_time = $5; }
 | bgp_proto STARTUP HOLD TIME expr ';' { BGP_CFG->initial_hold_time = $5; }
 | bgp_proto DIRECT ';' { BGP_CFG->multihop = 0; }
 | bgp_proto MULTIHOP ';' { BGP_CFG->multihop = 64; }
 | bgp_proto MULTIHOP expr ';' { BGP_CFG->multihop = $3; if (($3<1) || ($3>255)) cf_error("Multihop must be in range 1-255"); }
 | bgp_proto DYNAMIC NAME text ';' {
     if (strchr($4, '%')) cf_error("Forbidden character '%%' in dynamic name");
     if (strlen($4) > (SYM_MAX_LEN - 16)) cf_error("Dynamic name too long");
     BGP_CFG->dynamic_name = $4;
   }
 | bgp_proto DYNAMIC NAME DIGITS expr ';' { BGP_CFG->dynamic_name_digits = $5; if ($5>10) cf_error("Dynamic name digits must be at most 10"); }
 | bgp_proto STRICT BIND bool ';' { BGP_CFG->strict_bind = $4; }
 | bgp_proto FREE BIND bool ';' { BGP_CFG->free_bind = $4; }
 | bgp_proto PATH METRIC bool ';' { BGP_CFG->compare_path_lengths = $4; }
 | bgp_proto MED METRIC bool ';' { BGP_CFG->med_metric = $4; }
 | bgp_proto IGP METRIC bool ';' { BGP_CFG->igp_metric = $4; }
 | bgp_proto PREFER OLDER bool ';' { BGP_CFG->prefer_older = $4; }
 | bgp_proto DETERMINISTIC MED bool ';' { BGP_CFG->deterministic_med = $4; }
 | bgp_proto DEFAULT BGP_MED expr ';' { BGP_CFG->default_med = $4; }
 | bgp_proto DEFAULT BGP_LOCAL_PREF expr ';' { BGP_CFG->default_local_pref = $4; }
 | bgp_proto SOURCE ADDRESS ipa ';' { BGP_CFG->local_ip = $4; }
 | bgp_proto START DELAY TIME expr ';' { BGP_CFG->connect_delay_time = $5; cf_warn("%s: Start delay time option is deprecated, use connect delay time", this_proto->name); }
 | bgp_proto CONNECT DELAY TIME expr ';' { BGP_CFG->connect_delay_time = $5; }
 | bgp_proto CONNECT RETRY TIME expr ';' { BGP_CFG->connect_retry_time = $5; }
 | bgp_proto KEEPALIVE TIME expr ';' { BGP_CFG->keepalive_time = $4; if (($4<1) || ($4>65535)) cf_error("Keepalive time must be in range 1-65535"); }
 | bgp_proto MIN KEEPALIVE TIME expr ';' { BGP_CFG->min_keepalive_time = $5; }
 | bgp_proto ERROR FORGET TIME expr ';' { BGP_CFG->error_amnesia_time = $5; }
 | bgp_proto ERROR WAIT TIME expr ',' expr ';' { BGP_CFG->error_delay_time_min = $5; BGP_CFG->error_delay_time_max = $7; }
 | bgp_proto DISABLE AFTER ERROR bool ';' { BGP_CFG->disable_after_error = $5; }
 | bgp_proto DISABLE AFTER CEASE bgp_cease_mask ';' { BGP_CFG->disable_after_cease = $5; }
 | bgp_proto ENABLE ROUTE REFRESH bool ';' { BGP_CFG->enable_refresh = $5; }
 | bgp_proto ENABLE ENHANCED ROUTE REFRESH bool ';' { BGP_CFG->enable_enhanced_refresh = $6; }
 | bgp_proto ENABLE AS4 bool ';' { BGP_CFG->enable_as4 = $4; }
 | bgp_proto ENABLE EXTENDED MESSAGES bool ';' { BGP_CFG->enable_extended_messages = $5; }
 | bgp_proto ADVERTISE HOSTNAME bool ';' { BGP_CFG->enable_hostname = $4; }
 | bgp_proto CAPABILITIES bool ';' { BGP_CFG->capabilities = $3; }
 | bgp_proto PASSWORD text ';' { BGP_CFG->password = $3; }
 | bgp_proto SETKEY bool ';' { BGP_CFG->setkey = $3; }
 | bgp_proto PASSIVE bool ';' { BGP_CFG->passive = $3; }
 | bgp_proto INTERPRET COMMUNITIES bool ';' { BGP_CFG->interpret_communities = $4; }
 | bgp_proto ALLOW LOCAL AS ';' { BGP_CFG->allow_local_as = -1; }
 | bgp_proto ALLOW LOCAL AS expr ';' { BGP_CFG->allow_local_as = $5; }
 | bgp_proto ALLOW BGP_LOCAL_PREF bool ';' { BGP_CFG->allow_local_pref = $4; }
 | bgp_proto ALLOW BGP_MED bool ';' { BGP_CFG->allow_med = $4; }
 | bgp_proto ALLOW AS SETS bool ';' { BGP_CFG->allow_as_sets = $5; }
 | bgp_proto GRACEFUL RESTART bool ';' { BGP_CFG->gr_mode = $4; }
 | bgp_proto GRACEFUL RESTART AWARE ';' { BGP_CFG->gr_mode = BGP_GR_AWARE; }
 | bgp_proto GRACEFUL RESTART TIME expr ';' { BGP_CFG->gr_time = $5; }
 | bgp_proto LONG LIVED GRACEFUL RESTART bool ';' { BGP_CFG->llgr_mode = $6; }
 | bgp_proto LONG LIVED GRACEFUL RESTART AWARE ';' { BGP_CFG->llgr_mode = BGP_LLGR_AWARE; }
 | bgp_proto LONG LIVED STALE TIME expr ';' { BGP_CFG->llgr_time = $6; }
 | bgp_proto TTL SECURITY bool ';' { BGP_CFG->ttl_security = $4; }
 | bgp_proto CHECK LINK bool ';' { BGP_CFG->check_link = $4; }
 | bgp_proto BFD bool ';' { if ($3) init_bfd_opts(&BGP_CFG->bfd); else BGP_CFG->bfd = NULL; }
 | bgp_proto BFD GRACEFUL ';' { init_bfd_opts(&BGP_CFG->bfd); BGP_CFG->bfd->mode = BGP_BFD_GRACEFUL; }
 | bgp_proto BFD { open_bfd_opts(&BGP_CFG->bfd); } bfd_opts { close_bfd_opts(); } ';'
 | bgp_proto ENFORCE FIRST AS bool ';' { BGP_CFG->enforce_first_as = $5; }
 | bgp_proto LOCAL ROLE bgp_role_name ';' { BGP_CFG->local_role = $4; }
 | bgp_proto REQUIRE ROLES bool ';' { BGP_CFG->require_roles = $4; }
 ;

bgp_afi:
   IPV4			{ $$ = BGP_AF_IPV4; }
 | IPV6			{ $$ = BGP_AF_IPV6; }
 | IPV4 MULTICAST	{ $$ = BGP_AF_IPV4_MC; }
 | IPV6 MULTICAST	{ $$ = BGP_AF_IPV6_MC; }
 | IPV4 MPLS		{ $$ = BGP_AF_IPV4_MPLS; }
 | IPV6 MPLS		{ $$ = BGP_AF_IPV6_MPLS; }
 | VPN4 MPLS		{ $$ = BGP_AF_VPN4_MPLS; }
 | VPN6 MPLS		{ $$ = BGP_AF_VPN6_MPLS; }
 | VPN4 MULTICAST	{ $$ = BGP_AF_VPN4_MC; }
 | VPN6 MULTICAST	{ $$ = BGP_AF_VPN6_MC; }
 | FLOW4		{ $$ = BGP_AF_FLOW4; }
 | FLOW6		{ $$ = BGP_AF_FLOW6; }
 ;

bgp_channel_start: bgp_afi
{
  const struct bgp_af_desc *desc = bgp_get_af_desc($1);

  if (!desc)
    cf_error("Unknown AFI/SAFI");

  this_channel = channel_config_get(&channel_bgp, desc->name, desc->net, this_proto);

  /* New channel */
  if (!BGP_CC->desc)
  {
    BGP_CC->c.in_filter = FILTER_UNDEF;
    BGP_CC->c.out_filter = FILTER_UNDEF;
    BGP_CC->c.ra_mode = RA_UNDEF;
    BGP_CC->afi = $1;
    BGP_CC->desc = desc;
    BGP_CC->next_hop_keep = 0xff; /* undefined */
    BGP_CC->gr_able = 0xff;	/* undefined */
    BGP_CC->llgr_able = 0xff;	/* undefined */
    BGP_CC->llgr_time = ~0U;	/* undefined */
    BGP_CC->aigp = 0xff;	/* undefined */
  }
};

bgp_nh:
   bool { $$ = $1; }
 | IBGP { $$ = NH_IBGP; }
 | EBGP { $$ = NH_EBGP; }

bgp_lladdr: SELF | DROP | IGNORE;

bgp_channel_item:
   channel_item
 | NEXT HOP ADDRESS ipa { BGP_CC->next_hop_addr = $4; }
 | NEXT HOP SELF bgp_nh { BGP_CC->next_hop_self = $4; }
 | NEXT HOP KEEP bgp_nh { BGP_CC->next_hop_keep = $4; }
 | NEXT HOP PREFER GLOBAL { BGP_CC->next_hop_prefer = NHP_GLOBAL; }
 | MANDATORY bool { BGP_CC->mandatory = $2; }
 | MISSING LLADDR bgp_lladdr { cf_warn("%s.%s: Missing lladdr option is deprecated and ignored, remove it", this_proto->name, this_channel->name); }
 | GATEWAY DIRECT { BGP_CC->gw_mode = GW_DIRECT; }
 | GATEWAY RECURSIVE { BGP_CC->gw_mode = GW_RECURSIVE; }
 | SECONDARY bool { BGP_CC->secondary = $2; }
 | VALIDATE bool {
    BGP_CC->validate = $2;
    if (BGP_SAFI(BGP_CC->afi) != BGP_SAFI_FLOW)
      cf_error("Validate option limited to flowspec channels");
   }
 | GRACEFUL RESTART bool { BGP_CC->gr_able = $3; }
 | LONG LIVED GRACEFUL RESTART bool { BGP_CC->llgr_able = $5; }
 | LONG LIVED STALE TIME expr { BGP_CC->llgr_time = $5; }
 | EXTENDED NEXT HOP bool { BGP_CC->ext_next_hop = $4; }
 | ADD PATHS RX { BGP_CC->add_path = BGP_ADD_PATH_RX; }
 | ADD PATHS TX { BGP_CC->add_path = BGP_ADD_PATH_TX; }
 | ADD PATHS bool { BGP_CC->add_path = $3 ? BGP_ADD_PATH_FULL : 0; }
 | IMPORT TABLE bool { BGP_CC->import_table = $3; }
 | EXPORT TABLE bool { BGP_CC->export_table = $3; }
 | AIGP bool { BGP_CC->aigp = $2; BGP_CC->aigp_originate = 0; }
 | AIGP ORIGINATE { BGP_CC->aigp = 1; BGP_CC->aigp_originate = 1; }
 | COST expr { BGP_CC->cost = $2; if ($2 < 1) cf_error("Cost must be positive"); }
 | IGP TABLE rtable {
    if (BGP_CC->desc->no_igp)
      cf_error("IGP table not allowed here");

    if ($3->addr_type == NET_IP4)
      BGP_CC->igp_table_ip4 = $3;
    else if ($3->addr_type == NET_IP6)
      BGP_CC->igp_table_ip6 = $3;
    else
      cf_error("Mismatched IGP table type");
   }
 | BASE TABLE rtable {
    if (BGP_SAFI(BGP_CC->afi) != BGP_SAFI_FLOW)
      cf_error("Base table option limited to flowspec channels");

    if (((BGP_CC->afi == BGP_AF_FLOW4) && ($3->addr_type == NET_IP4)) ||
        ((BGP_CC->afi == BGP_AF_FLOW6) && ($3->addr_type == NET_IP6)))
      BGP_CC->base_table = $3;
    else
      cf_error("Mismatched base table type");
   }
 ;

bgp_channel_opts:
   /* empty */
 | bgp_channel_opts bgp_channel_item ';'
 ;

bgp_channel_opt_list:
   /* empty */
 | '{' bgp_channel_opts '}'
 ;

bgp_channel_end:
{
  if (!this_channel->table)
    cf_error("Routing table not specified");

  this_channel = NULL;
};

bgp_proto_channel: bgp_channel_start bgp_channel_opt_list bgp_channel_end;


dynamic_attr: BGP_ORIGIN
	{ $$ = f_new_dynamic_attr(EAF_TYPE_INT, T_ENUM_BGP_ORIGIN, EA_CODE(PROTOCOL_BGP, BA_ORIGIN)); } ;
dynamic_attr: BGP_PATH
	{ $$ = f_new_dynamic_attr(EAF_TYPE_AS_PATH, T_PATH, EA_CODE(PROTOCOL_BGP, BA_AS_PATH)); } ;
dynamic_attr: BGP_NEXT_HOP
	{ $$ = f_new_dynamic_attr(EAF_TYPE_IP_ADDRESS, T_IP, EA_CODE(PROTOCOL_BGP, BA_NEXT_HOP)); } ;
dynamic_attr: BGP_MED
	{ $$ = f_new_dynamic_attr(EAF_TYPE_INT, T_INT, EA_CODE(PROTOCOL_BGP, BA_MULTI_EXIT_DISC)); } ;
dynamic_attr: BGP_LOCAL_PREF
	{ $$ = f_new_dynamic_attr(EAF_TYPE_INT, T_INT, EA_CODE(PROTOCOL_BGP, BA_LOCAL_PREF)); } ;
dynamic_attr: BGP_ATOMIC_AGGR
	{ $$ = f_new_dynamic_attr(EAF_TYPE_OPAQUE, T_ENUM_EMPTY, EA_CODE(PROTOCOL_BGP, BA_ATOMIC_AGGR)); } ;
dynamic_attr: BGP_AGGREGATOR
	{ $$ = f_new_dynamic_attr(EAF_TYPE_OPAQUE, T_ENUM_EMPTY, EA_CODE(PROTOCOL_BGP, BA_AGGREGATOR)); } ;
dynamic_attr: BGP_COMMUNITY
	{ $$ = f_new_dynamic_attr(EAF_TYPE_INT_SET, T_CLIST, EA_CODE(PROTOCOL_BGP, BA_COMMUNITY)); } ;
dynamic_attr: BGP_ORIGINATOR_ID
	{ $$ = f_new_dynamic_attr(EAF_TYPE_ROUTER_ID, T_QUAD, EA_CODE(PROTOCOL_BGP, BA_ORIGINATOR_ID)); } ;
dynamic_attr: BGP_CLUSTER_LIST
	{ $$ = f_new_dynamic_attr(EAF_TYPE_INT_SET, T_CLIST, EA_CODE(PROTOCOL_BGP, BA_CLUSTER_LIST)); } ;
dynamic_attr: BGP_EXT_COMMUNITY
	{ $$ = f_new_dynamic_attr(EAF_TYPE_EC_SET, T_ECLIST, EA_CODE(PROTOCOL_BGP, BA_EXT_COMMUNITY)); } ;
dynamic_attr: BGP_AIGP
	{ $$ = f_new_dynamic_attr(EAF_TYPE_OPAQUE, T_ENUM_EMPTY, EA_CODE(PROTOCOL_BGP, BA_AIGP)); } ;
dynamic_attr: BGP_LARGE_COMMUNITY
	{ $$ = f_new_dynamic_attr(EAF_TYPE_LC_SET, T_LCLIST, EA_CODE(PROTOCOL_BGP, BA_LARGE_COMMUNITY)); } ;
dynamic_attr: BGP_OTC
	{ $$ = f_new_dynamic_attr(EAF_TYPE_INT, T_INT, EA_CODE(PROTOCOL_BGP, BA_ONLY_TO_CUSTOMER)); } ;

custom_attr: ATTRIBUTE BGP expr type symbol ';' {
  if ($3 > 255 || $3 < 1)
    cf_error("Invalid attribute number (Given %i, must be 1-255)", $3);
  if ($4 != T_BYTESTRING)
    cf_error("Attribute type must be bytestring, not %s", f_type_name($4));
  if (bgp_attr_name($3))
    cf_error("Attribute BGP.%d already known as %s", $3, bgp_attr_name($3));

  struct f_dynamic_attr *a = cfg_alloc(sizeof(struct f_dynamic_attr));
  *a = f_new_dynamic_attr(f_type_attr($4), T_BYTESTRING, EA_CODE(PROTOCOL_BGP, $3));
  a->flags = BAF_TRANSITIVE | BAF_OPTIONAL;
  cf_define_symbol(new_config, $5, SYM_ATTRIBUTE, attribute, a);
};

CF_ENUM(T_ENUM_BGP_ORIGIN, ORIGIN_, IGP, EGP, INCOMPLETE)

CF_CODE

CF_END
