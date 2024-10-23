/*
 *	BIRD -- The Border Gateway Protocol
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *	(c) 2008--2016 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2008--2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_BGP_H_
#define _BIRD_BGP_H_

#include <stdint.h>
#include "nest/bird.h"
#include "nest/route.h"
#include "nest/bfd.h"
//#include "lib/lists.h"
#include "lib/hash.h"
#include "lib/socket.h"

struct eattr;


/* Address families */

#define BGP_AFI_IPV4		1
#define BGP_AFI_IPV6		2

#define BGP_SAFI_UNICAST	1
#define BGP_SAFI_MULTICAST	2
#define BGP_SAFI_MPLS		4
#define BGP_SAFI_MPLS_VPN	128
#define BGP_SAFI_VPN_MULTICAST	129
#define BGP_SAFI_FLOW		133

/* Internal AF codes */

#define BGP_AF(A, B)		(((u32)(A) << 16) | (u32)(B))
#define BGP_AFI(A)		((u32)(A) >> 16)
#define BGP_SAFI(A)		((u32)(A) & 0xFFFF)

#define BGP_AF_IPV4		BGP_AF( BGP_AFI_IPV4, BGP_SAFI_UNICAST )
#define BGP_AF_IPV6		BGP_AF( BGP_AFI_IPV6, BGP_SAFI_UNICAST )
#define BGP_AF_IPV4_MC		BGP_AF( BGP_AFI_IPV4, BGP_SAFI_MULTICAST )
#define BGP_AF_IPV6_MC		BGP_AF( BGP_AFI_IPV6, BGP_SAFI_MULTICAST )
#define BGP_AF_IPV4_MPLS	BGP_AF( BGP_AFI_IPV4, BGP_SAFI_MPLS )
#define BGP_AF_IPV6_MPLS	BGP_AF( BGP_AFI_IPV6, BGP_SAFI_MPLS )
#define BGP_AF_VPN4_MPLS	BGP_AF( BGP_AFI_IPV4, BGP_SAFI_MPLS_VPN )
#define BGP_AF_VPN6_MPLS	BGP_AF( BGP_AFI_IPV6, BGP_SAFI_MPLS_VPN )
#define BGP_AF_VPN4_MC		BGP_AF( BGP_AFI_IPV4, BGP_SAFI_VPN_MULTICAST )
#define BGP_AF_VPN6_MC		BGP_AF( BGP_AFI_IPV6, BGP_SAFI_VPN_MULTICAST )
#define BGP_AF_FLOW4		BGP_AF( BGP_AFI_IPV4, BGP_SAFI_FLOW )
#define BGP_AF_FLOW6		BGP_AF( BGP_AFI_IPV6, BGP_SAFI_FLOW )


struct bgp_write_state;
struct bgp_parse_state;
struct bgp_export_state;
struct bgp_bucket;

struct bgp_af_desc {
  u32 afi;
  u32 net;
  u8 mpls;
  u8 no_igp;
  const char *name;
  uint (*encode_nlri)(struct bgp_write_state *s, struct bgp_bucket *buck, byte *buf, uint size);
  void (*decode_nlri)(struct bgp_parse_state *s, byte *pos, uint len, ea_list *a);
  void (*update_next_hop)(struct bgp_export_state *s, eattr *nh, ea_list **to);
  uint (*encode_next_hop)(struct bgp_write_state *s, eattr *nh, byte *buf, uint size);
  void (*decode_next_hop)(struct bgp_parse_state *s, byte *pos, uint len, ea_list **to);
};


struct bgp_config {
  struct proto_config c;
  u32 local_as, remote_as;
  ip_addr local_ip;			/* Source address to use */
  ip_addr remote_ip;
  struct iface *iface;			/* Interface for link-local addresses */
  u16 local_port;			/* Local listening port */
  u16 remote_port; 			/* Neighbor destination port */
  int peer_type;			/* Internal or external BGP (BGP_PT_*, optional) */
  int multihop;				/* Number of hops if multihop */
  int strict_bind;			/* Bind listening socket to local address */
  int free_bind;			/* Bind listening socket with SKF_FREEBIND */
  int ttl_security;			/* Enable TTL security [RFC 5082] */
  int compare_path_lengths;		/* Use path lengths when selecting best route */
  int med_metric;			/* Compare MULTI_EXIT_DISC even between routes from differen ASes */
  int igp_metric;			/* Use IGP metrics when selecting best route */
  int prefer_older;			/* Prefer older routes according to RFC 5004 */
  int deterministic_med;		/* Use more complicated algo to have strict RFC 4271 MED comparison */
  u32 default_local_pref;		/* Default value for LOCAL_PREF attribute */
  u32 default_med;			/* Default value for MULTI_EXIT_DISC attribute */
  int capabilities;			/* Enable capability handshake [RFC 5492] */
  int enable_refresh;			/* Enable local support for route refresh [RFC 2918] */
  int enable_enhanced_refresh;		/* Enable local support for enhanced route refresh [RFC 7313] */
  int enable_as4;			/* Enable local support for 4B AS numbers [RFC 6793] */
  int enable_extended_messages;		/* Enable local support for extended messages [RFC 8654] */
  int enable_hostname;			/* Enable local support for hostname [draft] */
  u32 rr_cluster_id;			/* Route reflector cluster ID, if different from local ID */
  int rr_client;			/* Whether neighbor is RR client of me */
  int rs_client;			/* Whether neighbor is RS client of me */
  u32 confederation;			/* Confederation ID, or zero if confeds not active */
  int confederation_member;		/* Whether neighbor AS is member of our confederation */
  int passive;				/* Do not initiate outgoing connection */
  int interpret_communities;		/* Hardwired handling of well-known communities */
  int allow_local_as;			/* Allow that number of local ASNs in incoming AS_PATHs */
  int allow_local_pref;			/* Allow LOCAL_PREF in EBGP sessions */
  int allow_med;			/* Allow BGP_MED in EBGP sessions */
  int allow_as_sets;			/* Allow AS_SETs in incoming AS_PATHs */
  int enforce_first_as;			/* Enable check for neighbor AS as first AS in AS_PATH */
  int gr_mode;				/* Graceful restart mode (BGP_GR_*) */
  int llgr_mode;			/* Long-lived graceful restart mode (BGP_LLGR_*) */
  int setkey;				/* Set MD5 password to system SA/SP database */
  u8  local_role;			/* Set peering role with neighbor [RFC 9234] */
  int require_roles;			/* Require configured roles on both sides */
  int send_hold_time;
  int disable_rx;			/* Stop reading messages after handshake (for simulating error) */
  /* Times below are in seconds */
  unsigned gr_time;			/* Graceful restart timeout */
  unsigned llgr_time;			/* Long-lived graceful restart stale time */
  unsigned connect_delay_time;		/* Minimum delay between connect attempts */
  unsigned connect_retry_time;		/* Timeout for connect attempts */
  unsigned hold_time;
  unsigned min_hold_time;		/* Minimum accepted hold time */
  unsigned initial_hold_time;
  unsigned keepalive_time;
  unsigned min_keepalive_time;		/* Minimum accepted keepalive time */
  unsigned error_amnesia_time;		/* Errors are forgotten after */
  unsigned error_delay_time_min;	/* Time to wait after an error is detected */
  unsigned error_delay_time_max;
  unsigned disable_after_error;		/* Disable the protocol when error is detected */
  u32 disable_after_cease;		/* Disable it when cease is received, bitfield */

  const char *password;			/* Password used for MD5 authentication */
  net_addr *remote_range;		/* Allowed neighbor range for dynamic BGP */
  const char *dynamic_name;		/* Name pattern for dynamic BGP */
  int dynamic_name_digits;		/* Minimum number of digits for dynamic names */
  int check_link;			/* Use iface link state for liveness detection */
  int require_refresh;			/* Require remote support for route refresh [RFC 2918] */
  int require_enhanced_refresh;		/* Require remote support for enhanced route refresh [RFC 7313] */
  int require_as4;			/* Require remote support for 4B AS numbers [RFC 6793] */
  int require_extended_messages;	/* Require remote support for extended messages [RFC 8654] */
  int require_hostname;			/* Require remote support for hostname [draft] */
  int require_gr;			/* Require remote support for graceful restart [RFC 4724] */
  int require_llgr;			/* Require remote support for long-lived graceful restart [draft] */
  struct bfd_options *bfd;		/* Use BFD for liveness detection */
};

struct bgp_channel_config {
  struct channel_config c;

  u32 afi;
  const struct bgp_af_desc *desc;

  ip_addr next_hop_addr;		/* Local address for NEXT_HOP attribute */
  u8 next_hop_self;			/* Always set next hop to local IP address (NH_*) */
  u8 next_hop_keep;			/* Do not modify next hop attribute (NH_*) */
  u8 next_hop_prefer;			/* Prefer global or link-local next hop (NHP_*) */
  u8 mandatory;				/* Channel is mandatory in capability negotiation */
  u8 gw_mode;				/* How we compute route gateway from next_hop attr, see GW_* */
  u8 secondary;				/* Accept also non-best routes (i.e. RA_ACCEPTED) */
  u8 validate;				/* Validate Flowspec per RFC 8955 (6) */
  u8 gr_able;				/* Allow full graceful restart for the channel */
  u8 llgr_able;				/* Allow full long-lived GR for the channel */
  uint llgr_time;			/* Long-lived graceful restart stale time */
  u8 ext_next_hop;			/* Allow both IPv4 and IPv6 next hops */
  u8 require_ext_next_hop;		/* Require remote support of IPv4 NLRI with IPv6 next hops [RFC 8950] */
  u8 add_path;				/* Use ADD-PATH extension [RFC 7911] */
  u8 require_add_path;			/* Require remote support of ADD-PATH extension [RFC 7911] */
  u8 aigp;				/* AIGP is allowed on this session */
  u8 aigp_originate;			/* AIGP is originated automatically */
  u32 cost;				/* IGP cost for direct next hops */
  u8 import_table;			/* Use c.in_table as Adj-RIB-In */
  u8 export_table;			/* Keep Adj-RIB-Out and export it */

  struct settle_config ptx_exporter_settle;    /* Settle timer for export dumps */

  struct rtable_config *igp_table_ip4;	/* Table for recursive IPv4 next hop lookups */
  struct rtable_config *igp_table_ip6;	/* Table for recursive IPv6 next hop lookups */
  struct rtable_config *base_table;	/* Base table for Flowspec validation */
};

#define BGP_PT_INTERNAL		1
#define BGP_PT_EXTERNAL		2

#define BGP_ROLE_UNDEFINED 	255
#define BGP_ROLE_PROVIDER 	0
#define BGP_ROLE_RS_SERVER 	1
#define BGP_ROLE_RS_CLIENT 	2
#define BGP_ROLE_CUSTOMER 	3
#define BGP_ROLE_PEER 		4

#define NH_NO			0
#define NH_ALL			1
#define NH_IBGP			2
#define NH_EBGP			3

#define MLL_SELF		1
#define MLL_DROP		2
#define MLL_IGNORE		3

#define GW_DIRECT		1
#define GW_RECURSIVE		2

#define NHP_GLOBAL		1
#define NHP_LOCAL		2

#define BGP_ADD_PATH_RX		1
#define BGP_ADD_PATH_TX		2
#define BGP_ADD_PATH_FULL	3

#define BGP_GR_ABLE		1
#define BGP_GR_AWARE		2

/* For GR capability common flags */
#define BGP_GRF_RESTART 0x80

/* For GR capability per-AF flags */
#define BGP_GRF_FORWARDING 0x80

#define BGP_LLGR_ABLE		1
#define BGP_LLGR_AWARE		2

#define BGP_LLGRF_FORWARDING 0x80

#define BGP_GRS_NONE		0	/* No GR  */
#define BGP_GRS_ACTIVE		1	/* Graceful restart per RFC 4724 */
#define BGP_GRS_LLGR		2	/* Long-lived GR phase (stale timer active) */

#define BGP_BFD_GRACEFUL	2	/* BFD down triggers graceful restart */

/* rte->pflags */
#define BGP_REF_SUPPRESSED	0x1	/* Used for deterministic MED comparison */

struct bgp_af_caps {
  u32 afi;
  u8 ready;				/* Multiprotocol capability, RFC 4760 */
  u8 gr_able;				/* Graceful restart support, RFC 4724 */
  u8 gr_af_flags;			/* Graceful restart per-AF flags */
  u8 llgr_able;				/* Long-lived GR, RFC draft */
  u32 llgr_time;			/* Long-lived GR stale time */
  u8 llgr_flags;			/* Long-lived GR per-AF flags */
  u8 ext_next_hop;			/* Extended IPv6 next hop,   RFC 8950 */
  u8 add_path;				/* Multiple paths support,   RFC 7911 */
};

struct bgp_caps {
  u32 as4_number;			/* Announced ASN */

  u8 as4_support;			/* Four-octet AS capability, RFC 6793 */
  u8 ext_messages;			/* Extended message length,  RFC 8654 */
  u8 route_refresh;			/* Route refresh capability, RFC 2918 */
  u8 enhanced_refresh;			/* Enhanced route refresh,   RFC 7313 */
  u8 role;				/* BGP role capability,      RFC 9234 */

  u8 gr_aware;				/* Graceful restart capability, RFC 4724 */
  u8 gr_flags;				/* Graceful restart flags */
  u16 gr_time;				/* Graceful restart time in seconds */

  u8 llgr_aware;			/* Long-lived GR capability, RFC draft */
  u8 any_ext_next_hop;			/* Bitwise OR of per-AF ext_next_hop */
  u8 any_add_path;			/* Bitwise OR of per-AF add_path */

  const char *hostname;			/* Hostname, RFC draft */

  u16 af_count;				/* Number of af_data items */
  u16 length;				/* Length of capabilities in OPEN msg */

  struct bgp_af_caps af_data[0];	/* Per-AF capability data */
};

#define WALK_AF_CAPS(caps,ac) \
  for (ac = caps->af_data; ac < &caps->af_data[caps->af_count]; ac++)


struct bgp_socket {
  node n;				/* Node in global bgp_sockets */
  list requests;			/* Listen requests */
  sock *sk;				/* Real listening socket */
};

struct bgp_stats {
  uint rx_messages, tx_messages;
  uint rx_updates, tx_updates;
  u64  rx_bytes, tx_bytes;

  uint fsm_established_transitions;
};

struct bgp_conn {
  struct bgp_proto *bgp;
  struct birdsock *sk;
  u8 state;                            /* State of connection state machine */
  u8 as4_session;			/* Session uses 4B AS numbers in AS_PATH (both sides support it) */
  u8 ext_messages;			/* Session uses extended message length */
  u32 received_as;			/* ASN received in OPEN message */

  byte *local_open_msg;			/* Saved OPEN messages (no header) */
  byte *remote_open_msg;
  uint local_open_length;
  uint remote_open_length;

  struct bgp_caps *local_caps;
  struct bgp_caps *remote_caps;
  timer *connect_timer;
  timer *hold_timer;
  timer *keepalive_timer;
  timer *send_hold_timer;
  u32 packets_to_send;			/* Bitmap of packet types to be sent */
  u32 channels_to_send;			/* Bitmap of channels with packets to be sent */
  u8 last_channel;			/* Channel used last time for TX */
  u8 last_channel_count;		/* Number of times the last channel was used in succession */
  int notify_code, notify_subcode, notify_size;
  byte *notify_data;

  uint hold_time, keepalive_time, send_hold_time;	/* Times calculated from my and neighbor's requirements */
};

struct bgp_conn_sk_ea {
  ip_addr saddr;
  ip_addr daddr;
  int sport;
  int dport;
};

struct closing_bgp {
  int err_class;
  int err_code;
  int err_subcode;
  int length;
  byte data[0];
};

struct bgp_listen_request {
  node n;				/* Node in bgp_socket / pending list */
  struct bgp_socket *sock;		/* Assigned socket */
  ip_addr addr;
  struct iface *iface;
  struct iface *vrf;
  uint port;
  uint flags;
};

struct bgp_proto {
  struct proto p;
  const struct bgp_config *cf;		/* Shortcut to BGP configuration */
  ip_addr local_ip, remote_ip;
  u32 local_as, remote_as;
  u32 public_as;			/* Externally visible ASN (local_as or confederation id) */
  u32 local_id;				/* BGP identifier of this router */
  u32 remote_id;			/* BGP identifier of the neighbor */
  u32 rr_cluster_id;			/* Route reflector cluster ID */
  u8 is_internal;			/* Internal BGP session (local_as == remote_as) */
  u8 is_interior;			/* Internal or intra-confederation BGP session */
  u8 as4_session;			/* Session uses 4B AS numbers in AS_PATH (both sides support it) */
  u8 rr_client;				/* Whether neighbor is RR client of me */
  u8 rs_client;				/* Whether neighbor is RS client of me */
  u8 ipv4;				/* Use IPv4 connection, i.e. remote_ip is IPv4 */
  u8 passive;				/* Do not initiate outgoing connection */
  u8 route_refresh;			/* Route refresh allowed to send [RFC 2918] */
  u8 enhanced_refresh;			/* Enhanced refresh is negotiated [RFC 7313] */
  u8 gr_ready;				/* Neighbor could do graceful restart */
  u8 llgr_ready;			/* Neighbor could do Long-lived GR, implies gr_ready */
  u8 gr_active_num;			/* Neighbor is doing GR, number of active channels */
  u8 channel_count;			/* Number of active channels */
  u8 summary_add_path_rx;		/* Summary state of ADD_PATH RX w.r.t active channels */
  u32 *afi_map;				/* Map channel index -> AFI */
  struct bgp_channel **channel_map;	/* Map channel index -> channel */
  struct bgp_conn *conn;		/* Connection we have established */
  struct bgp_conn outgoing_conn;	/* Outgoing connection we're working with */
  struct bgp_conn incoming_conn;	/* Incoming connection we have neither accepted nor rejected yet */
  struct object_lock *lock;		/* Lock for neighbor connection */
  struct neighbor *neigh;		/* Neighbor entry corresponding to remote ip, NULL if multihop */
  struct bgp_listen_request listen;	/* Shared listening socket */
  struct bfd_request *bfd_req;		/* BFD request, if BFD is used */
  struct birdsock *postponed_sk;	/* Postponed incoming socket for dynamic BGP */
  struct rt_uncork_callback uncork;	/* Uncork hook */
  struct bgp_stats stats;		/* BGP statistics */
  btime last_established;		/* Last time of enter/leave of established state */
  btime last_rx_update;			/* Last time of RX update */
  ip_addr link_addr;			/* Link-local version of local_ip */
  event *event;				/* Event for respawning and shutting process */
  timer *startup_timer;			/* Timer used to delay protocol startup due to previous errors (startup_delay) */
  timer *gr_timer;			/* Timer waiting for reestablishment after graceful restart */
  int dynamic_name_counter;		/* Counter for dynamic BGP names */
  uint startup_delay;			/* Delay (in seconds) of protocol startup due to previous errors */
  btime last_proto_error;		/* Time of last error that leads to protocol stop */
  u8 last_error_class; 			/* Error class of last error */
  u32 last_error_code;			/* Error code of last error. BGP protocol errors
					   are encoded as (bgp_err_code << 16 | bgp_err_subcode) */
};

#define bgp_ea_state(p)  _Generic((p), \
    struct bgp_proto *: (p)->p.ea_state, \
    ea_list *: (p))

struct bgp_channel {
  struct channel c;

  /* Rest are BGP specific data */
  struct bgp_channel_config *cf;

  u32 afi;
  u32 index;
  const struct bgp_af_desc *desc;

  rtable *igp_table_ip4;		/* Table for recursive IPv4 next hop lookups */
  rtable *igp_table_ip6;		/* Table for recursive IPv6 next hop lookups */
  rtable *base_table;			/* Base table for Flowspec validation */

  /* Rest are zeroed when down */
  pool *pool;

  union bgp_ptx *tx;			/* TX encapsulation */

  ip_addr next_hop_addr;		/* Local address for NEXT_HOP attribute */
  ip_addr link_addr;			/* Link-local version of next_hop_addr */

  u32 packets_to_send;			/* Bitmap of packet types to be sent */

  u8 tx_keep;				/* Keep prefixes to be sent */

  u8 ext_next_hop;			/* Session allows both IPv4 and IPv6 next hops */

  u8 gr_ready;				/* Neighbor could do GR on this AF */
  u8 gr_active;				/* Neighbor is doing GR (BGP_GRS_*) */

  timer *stale_timer;			/* Long-lived stale timer for LLGR */
  u32 stale_time;			/* Stored LLGR stale time from last session */
  struct rt_export_feeder stale_feed;	/* Feeder request for stale route modification */
  event stale_event;			/* Feeder event for stale route modification */

  u8 add_path_rx;			/* Session expects receive of ADD-PATH extended NLRI */
  u8 add_path_tx;			/* Session expects transmit of ADD-PATH extended NLRI */

  u8 feed_state;			/* Feed state (TX) for EoR, RR packets, see BFS_* */
  u8 load_state;			/* Load state (RX) for EoR, RR packets, see BFS_* */
};

struct bgp_ptx_private {
#define BGP_PTX_PUBLIC \
  DOMAIN(rtable) lock;			/* Domain to be locked for prefix access */ \
  struct rt_exporter exporter;		/* Table-like exporter for ptx */ \
  struct bgp_channel *c;		/* Backlink to the channel */ \

  struct { BGP_PTX_PUBLIC; };
  struct bgp_ptx_private **locked_at;

  pool *pool;				/* Resource pool for TX related allocations */

  HASH(struct bgp_bucket) bucket_hash;	/* Hash table of route buckets */
  struct bgp_bucket *withdraw_bucket;	/* Withdrawn routes */
  list bucket_queue;			/* Queue of buckets to send (struct bgp_bucket) */

  HASH(struct bgp_prefix) prefix_hash;	/* Hash table of pending prefices */

  slab *prefix_slab;			/* Slab holding prefix nodes */
  slab *bucket_slab;			/* Slab holding buckets to send */

  char bmp;                            /* This is a fake ptx for BMP encoding */
};

typedef union bgp_ptx {
  struct { BGP_PTX_PUBLIC; };
  struct bgp_ptx_private priv;
} bgp_ptx;

LOBJ_UNLOCK_CLEANUP(bgp_ptx, rtable);
#define BGP_PTX_LOCK(_c, _tx)  LOBJ_LOCK(_c, _tx, bgp_ptx, rtable)
#define BGP_PTX_PUB(_tx)	SKIP_BACK(union bgp_ptx, priv, (_tx))

struct bgp_prefix {
  node buck_node;			/* Node in per-bucket list */
  struct bgp_prefix *next;		/* Node in prefix hash */
  struct bgp_bucket *last;		/* Last bucket sent with this prefix */
  struct bgp_bucket *cur;		/* Current bucket (cur == last) if no update is required */
  btime lastmod;			/* Last modification of this prefix */
  struct rte_src *src;			/* Path ID encoded as rte_src */
  struct netindex *ni;			/* Shared with the table */
};

struct bgp_bucket {
  node send_node;			/* Node in send queue */
  struct bgp_bucket *next;		/* Node in bucket hash table */
  list prefixes;			/* Prefixes to send in this bucket (struct bgp_prefix) */
  u32 hash;				/* Hash over extended attributes */
  u32 px_uc:31;				/* How many prefixes are linking this bucket */
  u32 bmp:1;				/* Temporary bucket for BMP encoding */
  ea_list eattrs[0];			/* Per-bucket extended attributes */
};

struct bgp_export_state {
  struct bgp_proto *proto;
  struct bgp_channel *channel;
  struct linpool *pool;

  struct bgp_proto *src;
  rte *route;
  int mpls;

  u32 attrs_seen[1];
  uint err_reject;
  uint local_next_hop;
};

struct bgp_write_state {
  struct bgp_proto *proto;
  struct bgp_ptx_private *ptx;
  struct linpool *pool;

  int mp_reach;
  int as4_session;
  int add_path;
  int mpls;
  int ignore_non_bgp_attrs;

  eattr *mp_next_hop;
  const adata *mpls_labels;
};

struct bgp_parse_state {
  struct bgp_proto *proto;
  struct bgp_channel *channel;
  struct linpool *pool;

  int as4_session;
  int add_path;
  int mpls;
  int reach_nlri_step;

  u32 attrs_seen[256/32];

  u32 mp_reach_af;
  u32 mp_unreach_af;

  uint attr_len;
  uint ip_reach_len;
  uint ip_unreach_len;
  uint ip_next_hop_len;
  uint mp_reach_len;
  uint mp_unreach_len;
  uint mp_next_hop_len;

  byte *attrs;
  byte *ip_reach_nlri;
  byte *ip_unreach_nlri;
  byte *ip_next_hop_data;
  byte *mp_reach_nlri;
  byte *mp_unreach_nlri;
  byte *mp_next_hop_data;

  uint err_withdraw;
  uint err_subcode;
  jmp_buf err_jmpbuf;

  /* Cached state for bgp_rte_update() */
  u32 last_id;
  struct rte_src *last_src;
};

#define BGP_PORT		179
#define BGP_VERSION		4
#define BGP_HEADER_LENGTH	19
#define BGP_HDR_MARKER_LENGTH	16
#define BGP_MAX_MESSAGE_LENGTH	4096
#define BGP_MAX_EXT_MSG_LENGTH	65535
#define BGP_RX_BUFFER_SIZE	4096
#define BGP_TX_BUFFER_SIZE	4096
#define BGP_RX_BUFFER_EXT_SIZE	65535
#define BGP_TX_BUFFER_EXT_SIZE	65535

#define BGP_CF_WALK_CHANNELS(P,C) WALK_LIST(C, P->c.channels) if (C->c.class == &channel_bgp)
#define BGP_WALK_CHANNELS(P,C) WALK_LIST(C, P->p.channels) if (C->c.class == &channel_bgp)

#define BGP_MSG_HDR_MARKER_SIZE	16
#define BGP_MSG_HDR_MARKER_POS	0
#define BGP_MSG_HDR_LENGTH_SIZE	2
#define BGP_MSG_HDR_LENGTH_POS	BGP_MSG_HDR_MARKER_SIZE
#define BGP_MSG_HDR_TYPE_SIZE	1
#define BGP_MSG_HDR_TYPE_POS	(BGP_MSG_HDR_MARKER_SIZE + BGP_MSG_HDR_LENGTH_SIZE)

static inline int bgp_channel_is_ipv4(struct bgp_channel *c)
{ return BGP_AFI(c->afi) == BGP_AFI_IPV4; }

static inline int bgp_channel_is_ipv6(struct bgp_channel *c)
{ return BGP_AFI(c->afi) == BGP_AFI_IPV6; }

static inline int bgp_cc_is_ipv4(struct bgp_channel_config *c)
{ return BGP_AFI(c->afi) == BGP_AFI_IPV4; }

static inline int bgp_cc_is_ipv6(struct bgp_channel_config *c)
{ return BGP_AFI(c->afi) == BGP_AFI_IPV6; }

static inline int bgp_channel_is_role_applicable(struct bgp_channel *c)
{ return (c->afi == BGP_AF_IPV4 || c->afi == BGP_AF_IPV6); }

static inline int bgp_cc_is_role_applicable(struct bgp_channel_config *c)
{ return (c->afi == BGP_AF_IPV4 || c->afi == BGP_AF_IPV6); }

static inline uint bgp_max_packet_length(struct bgp_conn *conn)
{ return conn->ext_messages ? BGP_MAX_EXT_MSG_LENGTH : BGP_MAX_MESSAGE_LENGTH; }

static inline void
bgp_parse_error(struct bgp_parse_state *s, uint subcode)
{
  s->err_subcode = subcode;
  longjmp(s->err_jmpbuf, 1);
}


void bgp_start_timer(struct bgp_proto *p, timer *t, uint value);
void bgp_check_config(struct bgp_config *c);
void bgp_error(struct bgp_conn *c, unsigned code, unsigned subcode, byte *data, int len);
void bgp_close_conn(struct bgp_conn *c);
void bgp_update_startup_delay(struct bgp_proto *p);
void bgp_conn_enter_openconfirm_state(struct bgp_conn *conn);
void bgp_conn_enter_established_state(struct bgp_conn *conn);
void bgp_conn_enter_close_state(struct bgp_conn *conn);
void bgp_conn_enter_idle_state(struct bgp_conn *conn);
void broke_bgp_listening(struct channel *C);
void bgp_handle_graceful_restart(struct bgp_proto *p);
void bgp_graceful_restart_done(struct bgp_channel *c);
void bgp_refresh_begin(struct bgp_channel *c);
void bgp_refresh_end(struct bgp_channel *c);
void bgp_store_error(struct bgp_proto *p, struct bgp_conn *c, u8 class, u32 code);
void bgp_stop(struct bgp_proto *p, int subcode, byte *data, uint len);
const char *bgp_format_role_name(u8 role);

void bgp_reload_in(struct proto *P, uintptr_t, int);
void bgp_reload_out(struct proto *P, uintptr_t, int);

static inline int
rte_resolvable(const rte *rt)
{
  eattr *nhea = ea_find(rt->attrs, &ea_gen_nexthop);
  if (!nhea)
    return 0;

  struct nexthop_adata *nhad = (void *) nhea->u.ptr;
  return NEXTHOP_IS_REACHABLE(nhad) || (nhad->dest != RTD_UNREACHABLE);
}

extern struct rte_owner_class bgp_rte_owner_class;

#ifdef LOCAL_DEBUG
#define BGP_FORCE_DEBUG 1
#else
#define BGP_FORCE_DEBUG 0
#endif
#define BGP_TRACE(flags, msg, args...) do { if ((p->p.debug & flags) || BGP_FORCE_DEBUG) \
	log(L_TRACE "%s: " msg, p->p.name , ## args ); } while(0)

#define BGP_TRACE_RL(rl, flags, msg, args...) do { if ((p->p.debug & flags) || BGP_FORCE_DEBUG) \
	log_rl(rl, L_TRACE "%s: " msg, p->p.name , ## args ); } while(0)


/* attrs.c */

eattr *
bgp_find_attr(ea_list *attrs, uint code);

int bgp_state_to_eattr(struct proto *P, struct ea_list *state);
void bgp_set_attr_u32(ea_list **to, uint code, uint flags, u32 val);
void bgp_set_attr_ptr(ea_list **to, uint code, uint flags, const struct adata *ad);
void bgp_set_attr_data(ea_list **to, uint code, uint flags, void *data, uint len);
void bgp_unset_attr(ea_list **to, uint code);

int bgp_encode_mp_reach_mrt(struct bgp_write_state *s, eattr *a, byte *buf, uint size);

const char * bgp_attr_name(uint code);
int bgp_encode_attrs(struct bgp_write_state *s, ea_list *attrs, byte *buf, byte *end);
ea_list * bgp_decode_attrs(struct bgp_parse_state *s, byte *data, uint len);
void bgp_finish_attrs(struct bgp_parse_state *s, ea_list **to);

void bgp_setup_out_table(struct bgp_channel *c);

void bgp_init_pending_tx(struct bgp_channel *c);
void bgp_free_pending_tx(struct bgp_channel *c);
void bgp_tx_resend(struct bgp_proto *p, struct bgp_channel *c);

void bgp_withdraw_bucket(struct bgp_ptx_private *c, struct bgp_bucket *b);
int bgp_done_bucket(struct bgp_ptx_private *c, struct bgp_bucket *b);

void bgp_done_prefix(struct bgp_ptx_private *c, struct bgp_prefix *px, struct bgp_bucket *buck);

int bgp_rte_better(const rte *, const rte *);
int bgp_rte_mergable(const rte *pri, const rte *sec);
int bgp_rte_recalculate(struct rtable_private *table, net *net, struct rte_storage *new, struct rte_storage *old, struct rte_storage *old_best);
void bgp_rte_modify_stale(void *bgp_channel);
u32 bgp_rte_igp_metric(const rte *);
void bgp_rt_notify(struct proto *P, struct channel *C, const net_addr *n, rte *new, const rte *old);
int bgp_preexport(struct channel *, struct rte *);
void bgp_get_route_info(const rte *, byte *);
int bgp_total_aigp_metric_(const rte *e, u64 *metric, const struct adata **ad);

static inline struct bgp_proto *bgp_rte_proto(const rte *rte)
{
  return (rte->src->owner->class == &bgp_rte_owner_class) ?
    SKIP_BACK(struct bgp_proto, p.sources, rte->src->owner) : NULL;
}

byte * bgp_bmp_encode_rte(ea_list *c, struct bgp_proto *bgp_p, byte *buf, const struct rte *new);

#define BGP_AIGP_METRIC		1
#define BGP_AIGP_MAX		U64(0xffffffffffffffff)

static inline u64
bgp_total_aigp_metric(const rte *e)
{
  u64 metric = BGP_AIGP_MAX;
  const struct adata *ad;

  bgp_total_aigp_metric_(e, &metric, &ad);
  return metric;
}

/* bgp protocol journal attributes */
extern struct ea_class ea_bgp_rem_id, ea_bgp_rem_as, ea_bgp_loc_as, ea_bgp_rem_ip, ea_bgp_peer_type, ea_bgp_afi,
      ea_bgp_in_conn_local_open_msg, ea_bgp_out_conn_local_open_msg, ea_bgp_in_conn_remote_open_msg,
      ea_bgp_out_conn_remote_open_msg, ea_bgp_close_bmp, ea_bgp_close_bmp_set, ea_bgp_as4_session,
      ea_bgp_state_startup, ea_bgp_in_conn_state, ea_bgp_out_conn_state,
      ea_bgp_in_conn_sk, ea_bgp_out_conn_sk, ea_bgp_as4_out_conn, ea_bgp_as4_in_conn;

/* Extended state attributes */
extern struct ea_class
	      ea_bgp_state_startup;

void bgp_register_attrs(void);
struct ea_class *bgp_find_ea_class_by_id(uint id);


/* packets.c */

void bgp_dump_state_change(struct bgp_conn *conn, uint old, uint new);
void bgp_prepare_capabilities(struct bgp_conn *conn);
int bgp_check_capabilities(struct bgp_conn *conn);
const struct bgp_af_desc *bgp_get_af_desc(u32 afi);
const struct bgp_af_caps *bgp_find_af_caps(struct bgp_caps *caps, u32 afi);
void bgp_schedule_packet(struct bgp_conn *conn, struct bgp_channel *c, int type);
void bgp_tx(struct birdsock *sk);
int bgp_rx(struct birdsock *sk, uint size);
void bgp_do_uncork(callback *);
const char * bgp_error_dsc(unsigned code, unsigned subcode);
void bgp_log_error(struct bgp_proto *p, u8 class, char *msg, unsigned code, unsigned subcode, byte *data, unsigned len);

void bgp_update_next_hop(struct bgp_export_state *s, eattr *a, ea_list **to);
byte *bgp_create_end_mark_(struct bgp_channel *c, byte *buf);
byte *bgp_create_end_mark_ea_(ea_list *c, byte *buf);


/* Packet types */

#define PKT_OPEN		0x01
#define PKT_UPDATE		0x02
#define PKT_NOTIFICATION	0x03
#define PKT_KEEPALIVE		0x04
#define PKT_ROUTE_REFRESH	0x05	/* [RFC2918] */
#define PKT_BEGIN_REFRESH	0x1e	/* Dummy type for BoRR packet [RFC7313] */
#define PKT_SCHEDULE_CLOSE	0x1f	/* Used internally to schedule socket close */

/* Attributes */

#define BAF_OPTIONAL		0x80
#define BAF_TRANSITIVE		0x40
#define BAF_PARTIAL		0x20
#define BAF_EXT_LEN		0x10

#define BAF_DECODE_FLAGS	0x0100	/* Private flag - attribute flags are handled by the decode hook */

enum bgp_attr_id {
  BA_ORIGIN		= 0x01,	/* RFC 4271 */		/* WM */
  BA_AS_PATH		= 0x02,				/* WM */
  BA_NEXT_HOP		= 0x03,				/* WM */
  BA_MULTI_EXIT_DISC	= 0x04,				/* ON */
  BA_LOCAL_PREF		= 0x05,				/* WD */
  BA_ATOMIC_AGGR	= 0x06,				/* WD */
  BA_AGGREGATOR		= 0x07,				/* OT */
  BA_COMMUNITY		= 0x08,	/* RFC 1997 */		/* OT */
  BA_ORIGINATOR_ID	= 0x09,	/* RFC 4456 */		/* ON */
  BA_CLUSTER_LIST	= 0x0a,	/* RFC 4456 */		/* ON */
  BA_MP_REACH_NLRI	= 0x0e,	/* RFC 4760 */
  BA_MP_UNREACH_NLRI	= 0x0f,	/* RFC 4760 */
  BA_EXT_COMMUNITY	= 0x10,	/* RFC 4360 */
  BA_AS4_PATH		= 0x11,	/* RFC 6793 */
  BA_AS4_AGGREGATOR	= 0x12,	/* RFC 6793 */
  BA_AIGP		= 0x1a,	/* RFC 7311 */
  BA_LARGE_COMMUNITY	= 0x20,	/* RFC 8092 */
#define BA_ONLY_TO_CUSTOMER	0x23	/* RFC 9234 */

/* Bird's private internal BGP attributes */
  BA_MPLS_LABEL_STACK	= 0x100, /* MPLS label stack transfer attribute */

/* Maximum */
  BGP_ATTR_MAX,
};

/* BGP connection states */

#define BS_IDLE			0
#define BS_CONNECT		1	/* Attempting to connect */
#define BS_ACTIVE		2	/* Waiting for connection retry & listening */
#define BS_OPENSENT		3
#define BS_OPENCONFIRM		4
#define BS_ESTABLISHED		5
#define BS_CLOSE		6	/* Used during transition to BS_IDLE */

#define BS_MAX			7

/* BGP start states
 *
 * Used in PS_START for fine-grained specification of starting state.
 *
 * When BGP protocol is started by core, it goes to BSS_PREPARE. When BGP
 * protocol done what is neccessary to start itself (like acquiring the lock),
 * it goes to BSS_CONNECT.
 */

#define BSS_PREPARE		0	/* Used before ordinary BGP started, i. e. waiting for lock */
#define BSS_DELAY		1	/* Startup delay due to previous errors */
#define BSS_CONNECT		2	/* Ordinary BGP connecting */

#define bgp_start_state(p)	ea_get_int(bgp_ea_state(p), &ea_bgp_state_startup, BSS_PREPARE)
#define bgp_set_start_state(p, val)	do {		\
  ea_list *L = bgp_ea_state(p);				\
  ea_set_attr_u32(&L, &ea_bgp_state_startup, 0, val);	\
  proto_announce_state(&p->p, L);			\
} while (0)


/* BGP feed states (TX)
 *
 * RFC 4724 specifies that an initial feed should end with End-of-RIB mark.
 *
 * RFC 7313 specifies that a route refresh should be demarcated by BoRR and EoRR packets.
 *
 * These states (stored in c->feed_state) are used to keep track of these
 * requirements. When such feed is started, BFS_LOADING / BFS_REFRESHING is
 * set. When it ended, BFS_LOADED / BFS_REFRESHED is set to schedule End-of-RIB
 * or EoRR packet. When the packet is sent, the state returned to BFS_NONE.
 *
 * Note that when a non-demarcated feed (e.g. plain RFC 4271 initial load
 * without End-of-RIB or plain RFC 2918 route refresh without BoRR/EoRR
 * demarcation) is active, BFS_NONE is set.
 *
 * BFS_NONE, BFS_LOADING and BFS_REFRESHING are also used as load states (RX)
 * with correspondent semantics (-, expecting End-of-RIB, expecting EoRR).
 */

#define BFS_NONE		0	/* No feed or original non-demarcated feed */
#define BFS_LOADING		1	/* Initial feed active, End-of-RIB planned */
#define BFS_LOADED		2	/* Loading done, End-of-RIB marker scheduled */
#define BFS_REFRESHING		3	/* Route refresh (introduced by BoRR) active */
#define BFS_REFRESHED		4	/* Refresh done, EoRR packet scheduled */


/* Error classes */

#define BE_NONE			0
#define BE_MISC			1	/* Miscellaneous error */
#define BE_SOCKET		2	/* Socket error */
#define BE_BGP_RX		3	/* BGP protocol error notification received */
#define BE_BGP_TX		4	/* BGP protocol error notification sent */
#define BE_AUTO_DOWN		5	/* Automatic shutdown */
#define BE_MAN_DOWN		6	/* Manual shutdown */

/* Misc error codes */

#define BEM_NEIGHBOR_LOST	1
#define BEM_INVALID_NEXT_HOP	2
#define BEM_INVALID_MD5		3	/* MD5 authentication kernel request failed (possibly not supported) */
#define BEM_NO_SOCKET		4
#define BEM_LINK_DOWN		5
#define BEM_BFD_DOWN		6
#define BEM_GRACEFUL_RESTART	7

/* Automatic shutdown error codes */

#define BEA_ROUTE_LIMIT_EXCEEDED 1

/* Well-known communities */

#define BGP_COMM_NO_EXPORT		0xffffff01	/* Don't export outside local AS / confed. */
#define BGP_COMM_NO_ADVERTISE		0xffffff02	/* Don't export at all */
#define BGP_COMM_NO_EXPORT_SUBCONFED	0xffffff03	/* NO_EXPORT even in local confederation */

#define BGP_COMM_LLGR_STALE		0xffff0006	/* Route is stale according to LLGR */
#define BGP_COMM_NO_LLGR		0xffff0007	/* Do not treat the route according to LLGR */

/* Origins */

#define ORIGIN_IGP		0
#define ORIGIN_EGP		1
#define ORIGIN_INCOMPLETE	2


#endif
