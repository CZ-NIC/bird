/*
 *	BIRD -- The Babel protocol
 *
 *	Copyright (c) 2015--2016 Toke Hoiland-Jorgensen
 * 	(c) 2016--2017 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2016--2017 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	This file contains the data structures used by Babel.
 */

#ifndef _BIRD_BABEL_H_
#define _BIRD_BABEL_H_

#include "nest/bird.h"
#include "nest/cli.h"
#include "nest/iface.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/locks.h"
#include "nest/password.h"
#include "lib/resource.h"
#include "lib/lists.h"
#include "lib/socket.h"
#include "lib/string.h"
#include "lib/timer.h"

#define EA_BABEL_METRIC		EA_CODE(PROTOCOL_BABEL, 0)
#define EA_BABEL_ROUTER_ID	EA_CODE(PROTOCOL_BABEL, 1)
#define EA_BABEL_SEQNO		EA_CODE(PROTOCOL_BABEL, 2)

#define BABEL_MAGIC		42
#define BABEL_VERSION		2
#define BABEL_PORT		6696
#define BABEL_INFINITY		0xFFFF


#define BABEL_HELLO_INTERVAL_WIRED	(4 S_)	/* Default hello intervals in seconds */
#define BABEL_HELLO_INTERVAL_WIRELESS	(4 S_)
#define BABEL_HELLO_LIMIT		12
#define BABEL_UPDATE_INTERVAL_FACTOR	4
#define BABEL_IHU_INTERVAL_FACTOR	3
#define BABEL_HOLD_TIME_FACTOR		4	/* How long we keep unreachable route relative to update interval */
#define BABEL_IHU_EXPIRY_FACTOR(X)	((btime)(X)*7/2)	/* 3.5 */
#define BABEL_HELLO_EXPIRY_FACTOR(X)	((btime)(X)*3/2)	/* 1.5 */
#define BABEL_ROUTE_EXPIRY_FACTOR(X)	((btime)(X)*7/2)	/* 3.5 */
#define BABEL_ROUTE_REFRESH_FACTOR(X)	((btime)(X)*5/2)	/* 2.5 */
#define BABEL_SEQNO_REQUEST_RETRY	4
#define BABEL_SEQNO_REQUEST_EXPIRY	(2 S_)
#define BABEL_SEQNO_FORWARD_EXPIRY	(10 S_)
#define BABEL_SEQNO_DUP_SUPPRESS_TIME	(1 S_)
#define BABEL_GARBAGE_INTERVAL		(300 S_)
#define BABEL_RXCOST_WIRED		96
#define BABEL_RXCOST_WIRELESS		256
#define BABEL_RXCOST_RTT		96
#define BABEL_INITIAL_HOP_COUNT		255
#define BABEL_MAX_SEND_INTERVAL		5	/* Unused ? */
#define BABEL_INITIAL_NEIGHBOR_TIMEOUT	(60 S_)

#define BABEL_RTT_MAX_VALUE		(600 S_)
#define BABEL_RTT_MIN			(10 MS_)
#define BABEL_RTT_MAX			(120 MS_)
#define BABEL_RTT_DECAY			42

/* Max interval that will not overflow when carried as 16-bit centiseconds */
#define BABEL_TIME_UNITS		10000	/* On-wire times are counted in centiseconds */
#define BABEL_MIN_INTERVAL		(0x0001 * BABEL_TIME_UNITS)
#define BABEL_MAX_INTERVAL		(0xFFFF * BABEL_TIME_UNITS)

#define BABEL_OVERHEAD		(IP6_HEADER_LENGTH+UDP_HEADER_LENGTH)
#define BABEL_MIN_MTU		(512 + BABEL_OVERHEAD)

#define BABEL_AUTH_NONE			0
#define BABEL_AUTH_MAC			1

#define BABEL_AUTH_NONCE_LEN		10	/* we send 80 bit nonces */
#define BABEL_AUTH_MAX_NONCE_LEN	192	/* max allowed by spec */
#define BABEL_AUTH_INDEX_LEN		32	/* max size in spec */
#define BABEL_AUTH_CHALLENGE_TIMEOUT	(30 S_)
#define BABEL_AUTH_CHALLENGE_INTERVAL	(300 MS_) /* used for both challenges and replies */

enum babel_tlv_type {
  BABEL_TLV_PAD1		= 0,
  BABEL_TLV_PADN		= 1,
  BABEL_TLV_ACK_REQ		= 2,
  BABEL_TLV_ACK			= 3,
  BABEL_TLV_HELLO		= 4,
  BABEL_TLV_IHU 		= 5,
  BABEL_TLV_ROUTER_ID		= 6,
  BABEL_TLV_NEXT_HOP		= 7,
  BABEL_TLV_UPDATE		= 8,
  BABEL_TLV_ROUTE_REQUEST	= 9,
  BABEL_TLV_SEQNO_REQUEST	= 10,
  BABEL_TLV_MAC			= 16,
  BABEL_TLV_PC			= 17,
  BABEL_TLV_CHALLENGE_REQUEST	= 18,
  BABEL_TLV_CHALLENGE_REPLY	= 19,
  BABEL_TLV_MAX
};

enum babel_subtlv_type {
  BABEL_SUBTLV_PAD1		= 0,
  BABEL_SUBTLV_PADN		= 1,
  BABEL_SUBTLV_DIVERSITY	= 2, /* we don't support this */
  BABEL_SUBTLV_TIMESTAMP	= 3,

  /* Mandatory subtlvs */
  BABEL_SUBTLV_SOURCE_PREFIX    = 128,
};

enum babel_iface_type {
  /* In practice, UNDEF and WIRED give equivalent behaviour */
  BABEL_IFACE_TYPE_UNDEF	= 0,
  BABEL_IFACE_TYPE_WIRED	= 1,
  BABEL_IFACE_TYPE_WIRELESS	= 2,
  BABEL_IFACE_TYPE_TUNNEL	= 3,
  BABEL_IFACE_TYPE_MAX
};

enum babel_next_hop_prefer {
  BABEL_NHP_NATIVE		= 0,
  BABEL_NHP_IP6			= 1,
};

enum babel_ae_type {
  BABEL_AE_WILDCARD		= 0,
  BABEL_AE_IP4			= 1,
  BABEL_AE_IP6			= 2,
  BABEL_AE_IP6_LL		= 3,
  BABEL_AE_IP4_VIA_IP6		= 4,
  BABEL_AE_MAX
};


struct babel_config {
  struct proto_config c;
  list iface_list;			/* List of iface configs (struct babel_iface_config) */
  uint hold_time;			/* Time to hold stale entries and unreachable routes */
  u8 randomize_router_id;

  struct channel_config *ip4_channel;
  struct channel_config *ip6_channel;
};

struct babel_iface_config {
  struct iface_patt i;

  u16 rxcost;
  u8 type;
  u8 limit;				/* Minimum number of Hellos to keep link up */
  u8 check_link;
  uint port;
  uint hello_interval;			/* Hello interval, in us */
  uint ihu_interval;			/* IHU interval, in us */
  uint update_interval;			/* Update interval, in us */

  btime rtt_min;			/* rtt above which to start penalising metric */
  btime rtt_max;			/* max rtt metric penalty applied above this */
  u16 rtt_cost;			/* metric penalty to apply at rtt_max */
  u16 rtt_decay;			/* decay of neighbour RTT (units of 1/256) */
  u8  rtt_send;			/* whether to send timestamps on this interface */

  u16 rx_buffer;			/* RX buffer size, 0 for MTU */
  u16 tx_length;			/* TX packet length limit (including headers), 0 for MTU */
  int tx_tos;
  int tx_priority;

  ip_addr next_hop_ip4;
  ip_addr next_hop_ip6;
  u8 next_hop_prefer;			/* Prefer native or IPv6 nexthop */
  u8 ext_next_hop;			/* Enable IPv4 via IPv6 */

  u8 auth_type;				/* Authentication type (BABEL_AUTH_*) */
  u8 auth_permissive;			/* Don't drop packets failing auth check */
  uint mac_num_keys;			/* Number of configured HMAC keys */
  uint mac_total_len;			/* Total digest length for all configured keys */
  list *passwords;			/* Passwords for authentication */
};

struct babel_proto {
  struct proto p;
  timer *timer;
  struct fib ip4_rtable;
  struct fib ip6_rtable;

  struct channel *ip4_channel;
  struct channel *ip6_channel;

  list interfaces;			/* Interfaces we really know about (struct babel_iface) */
  u64 router_id;
  u16 update_seqno;			/* To be increased on request */
  u8 update_seqno_inc;			/* Request for update_seqno increase */
  u8 triggered;				/* For triggering global updates */

  slab *route_slab;
  slab *source_slab;
  slab *msg_slab;
  slab *seqno_slab;

  struct tbf log_pkt_tbf;		/* TBF for packet messages */
};

struct babel_iface {
  node n;

  struct babel_proto *proto;
  struct iface *iface;

  struct babel_iface_config *cf;

  u8 up;

  pool *pool;
  char *ifname;
  sock *sk;
  ip_addr addr;
  ip_addr next_hop_ip4;
  ip_addr next_hop_ip6;
  int tx_length;
  list neigh_list;			/* List of neighbors seen on this iface (struct babel_neighbor) */
  list msg_queue;

  u16 hello_seqno;			/* To be increased on each hello */

  u32 auth_pc;
  int auth_tx_overhead;
  u8 auth_index[BABEL_AUTH_INDEX_LEN];

  btime next_hello;
  btime next_regular;
  btime next_triggered;
  btime want_triggered;

  timer *timer;
  event *send_event;
};

struct babel_neighbor {
  node n;
  struct babel_iface *ifa;

  ip_addr addr;
  u16 rxcost;				/* Sent in last IHU */
  u16 txcost;				/* Received in last IHU */
  u16 cost;				/* Computed neighbor cost */
  s8 ihu_cnt;				/* IHU countdown, 0 to send it */
  u8 hello_cnt;
  u16 hello_map;
  u16 next_hello_seqno;
  uint last_hello_int;

  u32 last_tstamp;
  btime last_tstamp_rcvd;
  btime srtt;

  u32 auth_pc_unicast;
  u32 auth_pc_multicast;
  u8 auth_passed;
  u8 auth_index_len;
  u8 auth_index[BABEL_AUTH_INDEX_LEN];
  u8 auth_nonce[BABEL_AUTH_NONCE_LEN];
  btime auth_nonce_expiry;
  btime auth_next_challenge;
  btime auth_next_challenge_reply;

  /* expiry timers */
  btime hello_expiry;
  btime ihu_expiry;
  btime init_expiry;

  list routes;				/* Routes this neighbour has sent us (struct babel_route) */
};

struct babel_source {
  node n;

  u64 router_id;
  u16 seqno;
  u16 metric;
  btime expires;
};

struct babel_route {
  node n;
  node neigh_route;
  struct babel_entry    *e;
  struct babel_neighbor *neigh;

  u8 feasible;
  u16 seqno;
  u16 metric;
  u16 advert_metric;
  u64 router_id;
  ip_addr next_hop;
  btime refresh_time;
  btime expires;
};

struct babel_seqno_request {
  node n;
  u64 router_id;
  u16 seqno;
  u8 forwarded;
  u8 hop_count;
  u8 count;
  btime expires;
  btime dup_suppress_time;
};

struct babel_entry {
  struct babel_route *selected;

  list routes;				/* Routes for this prefix (struct babel_route) */
  list sources;				/* Source entries for this prefix (struct babel_source). */
  list requests;

  u8 valid;				/* Entry validity state (BABEL_ENTRY_*) */
  u8 unreachable;			/* Unreachable route is announced */
  u16 seqno;				/* Outgoing seqno */
  u16 metric;				/* Outgoing metric */
  u64 router_id;			/* Outgoing router ID */
  btime updated;			/* Last change of outgoing rte, for triggered updates */

  struct fib_node n;
};

#define BABEL_ENTRY_DUMMY	0	/* No outgoing route */
#define BABEL_ENTRY_VALID	1	/* Valid outgoing route */
#define BABEL_ENTRY_STALE	2	/* Stale outgoing route, waiting for GC */


/*
 *	Internal TLV messages
 */

struct babel_msg_ack_req {
  u8 type;
  u16 nonce;
  uint interval;
  ip_addr sender;
};

struct babel_msg_ack {
  u8 type;
  u16 nonce;
};

struct babel_msg_hello {
  u8 type;
  u16 seqno;
  uint interval;
  ip_addr sender;
  u32 tstamp;
  btime pkt_received;
};

struct babel_msg_ihu {
  u8 type;
  u8 ae;
  u16 rxcost;
  uint interval;
  ip_addr addr;
  ip_addr sender;
  u32 tstamp;
  u32 tstamp_rcvd;
  btime pkt_received;
};

struct babel_msg_update {
  u8 type;
  u8 wildcard;
  uint interval;
  u16 seqno;
  u16 metric;
  u64 router_id;
  union {
    net_addr net;
    net_addr_ip6_sadr net_sadr;
  };
  ip_addr next_hop;
  ip_addr sender;
};

struct babel_msg_route_request {
  u8 type;
  u8 full;
  union {
    net_addr net;
    net_addr_ip6_sadr net_sadr;
  };
};

struct babel_msg_seqno_request {
  u8 type;
  u8 hop_count;
  u16 seqno;
  u64 router_id;
  union {
    net_addr net;
    net_addr_ip6_sadr net_sadr;
  };
  ip_addr sender;
};

struct babel_msg_challenge {
  u8 type;
  u8 nonce_len;
  u8 *nonce;
};

union babel_msg {
  u8 type;
  struct babel_msg_ack_req ack_req;
  struct babel_msg_ack ack;
  struct babel_msg_hello hello;
  struct babel_msg_ihu ihu;
  struct babel_msg_update update;
  struct babel_msg_route_request route_request;
  struct babel_msg_seqno_request seqno_request;
  struct babel_msg_challenge challenge;
};

struct babel_msg_node {
  node n;
  union babel_msg msg;
};

/* only used for auth checking, so not a part of union above */
struct babel_msg_auth {
  ip_addr sender;
  u32 pc;
  u8 pc_seen;
  u8 index_len;
  u8 *index;
  u8 challenge_reply_seen;
  u8 challenge_reply[BABEL_AUTH_NONCE_LEN];
  u8 challenge_seen;
  u8 challenge_len;
  u8 challenge[BABEL_AUTH_MAX_NONCE_LEN];
  u8 unicast;
};

static inline int babel_sadr_enabled(struct babel_proto *p)
{ return p->ip6_rtable.addr_type == NET_IP6_SADR; }

/* babel.c */
void babel_handle_ack_req(union babel_msg *msg, struct babel_iface *ifa);
void babel_handle_ack(union babel_msg *msg, struct babel_iface *ifa);
void babel_handle_hello(union babel_msg *msg, struct babel_iface *ifa);
void babel_handle_ihu(union babel_msg *msg, struct babel_iface *ifa);
void babel_handle_router_id(union babel_msg *msg, struct babel_iface *ifa);
void babel_handle_update(union babel_msg *msg, struct babel_iface *ifa);
void babel_handle_route_request(union babel_msg *msg, struct babel_iface *ifa);
void babel_handle_seqno_request(union babel_msg *msg, struct babel_iface *ifa);

void babel_show_interfaces(struct proto *P, const char *iff);
void babel_show_neighbors(struct proto *P, const char *iff);
void babel_show_entries(struct proto *P);
void babel_show_routes(struct proto *P);

void babel_auth_reset_index(struct babel_iface *ifa);
int babel_auth_check_pc(struct babel_iface *ifa, struct babel_msg_auth *msg);

/* packets.c */
void babel_enqueue(union babel_msg *msg, struct babel_iface *ifa);
void babel_send_unicast(union babel_msg *msg, struct babel_iface *ifa, ip_addr dest);
int babel_open_socket(struct babel_iface *ifa);
void babel_send_queue(void *arg);
void babel_auth_set_tx_overhead(struct babel_iface *ifa);


#endif
