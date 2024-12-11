/*
 *	BIRD -- The BGP Monitoring Protocol (BMP)
 *
 *	(c) 2020 Akamai Technologies, Inc. (Pawel Maslanka, pmaslank@akamai.com)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_BMP_H_
#define _BIRD_BMP_H_

#include "nest/bird.h"
#include "nest/protocol.h"
#include "lib/lists.h"
#include "lib/tlists.h"
#include "nest/route.h"
#include "lib/event.h"
#include "lib/hash.h"
#include "lib/socket.h"
#include "proto/bgp/bgp.h"

// Max length of MIB-II description object
#define MIB_II_STR_LEN 255

// Total size of Common Header
#define BMP_COMMON_HDR_SIZE 6

/* BMP Per-Peer Header [RFC 7854 - Section 4.2] */
// Total size of Per-Peer Header
#define BMP_PER_PEER_HDR_SIZE 42

// Maximum length of BMP message altogether
#define BMP_MSGBUF_LEN (BGP_MAX_EXT_MSG_LENGTH + BMP_PER_PEER_HDR_SIZE + BMP_COMMON_HDR_SIZE + 1)

// The following fields of this structure controls whether there will be put
// specific routes into Route Monitoring message and send to BMP collector
struct monitoring_rib {
  bool in_pre_policy;  // Monitoring pre-policy Adj-Rib-In
  bool in_post_policy; // Monitoring post-policy Adj-Rib-In
  bool local;          // Monitoring Local Rib
};

struct bmp_config {
  struct proto_config c;
  const char *sys_descr;              // sysDescr MIB-II [RFC1213] object
  const char *sys_name;               // sysName MIB-II [RFC1213] object
  ip_addr local_addr;                 // Local IP address
  ip_addr station_ip;                 // Monitoring station address
  u16 station_port;                   // Monitoring station TCP port
  bool monitoring_rib_in_pre_policy;  // Route monitoring pre-policy Adj-Rib-In
  bool monitoring_rib_in_post_policy;  // Route monitoring post-policy Adj-Rib-In
  uint tx_pending_limit;	      // Maximum on pending TX buffer count
};

struct bmp_proto {
  struct proto p;                  // Parent proto
  const struct bmp_config *cf;     // Shortcut to BMP configuration

  HASH(struct bmp_peer) peer_map;
  HASH(struct bmp_stream) stream_map;
  HASH(struct bmp_table) table_map;

  sock *sk;                        // TCP connection
  event *tx_ev;                    // TX event
  event *update_ev;                // Update event
  char sys_descr[MIB_II_STR_LEN];  // sysDescr MIB-II [RFC1213] object
  char sys_name[MIB_II_STR_LEN];   // sysName MIB-II [RFC1213] object
  ip_addr local_addr;              // Source local IP address
  ip_addr station_ip;              // Monitoring station IP address
  u16 station_port;                // Monitoring station TCP port
  struct monitoring_rib monitoring_rib;
  // Below fields are for internal use
  struct bmp_tx_buffer *tx_pending;// This buffer waits for socket to flush
  struct bmp_tx_buffer *tx_last;   // This buffer is the last to flush 
  uint tx_pending_count;	   // How many buffers waiting for flush
  uint tx_pending_limit;	   // Maximum on buffer count
  u64 tx_sent;			   // Amount of data sent
  u64 tx_sent_total;		   // Amount of data sent accumulated over reconnections
  event *tx_overflow_event;	   // Too many buffers waiting for flush
  timer *connect_retry_timer;      // Timer for retrying connection to the BMP collector
  bool started;                    // Flag that stores running status of BMP instance
  int sock_err;                    // Last socket error code

  struct lfjour_recipient proto_state_reader; // Reader of protocol states
  event proto_state_changed;
  byte msgbuf[BMP_MSGBUF_LEN];     // Buffer for preparing the messages before sending them out
};

struct bmp_stream {
  TLIST_NODE(bmp_peer_stream, struct bmp_stream) peer_node;
  TLIST_NODE(bmp_table_stream, struct bmp_stream) table_node;
  bool sync;
  bool shutting_down;
  struct bmp_stream *next;
  struct bmp_stream_info {
    u32 channel_id;
    ea_list *channel_state;
    const char *channel_name;
    u32 afi;
    enum bmp_stream_policy {
      BMP_STREAM_PRE_POLICY = 1,
      BMP_STREAM_POST_POLICY,
    } mode;
  } info;
};

#define TLIST_PREFIX bmp_peer_stream
#define TLIST_TYPE struct bmp_stream
#define TLIST_ITEM peer_node
#define TLIST_WANT_ADD_TAIL

#include "lib/tlists.h"

#define TLIST_PREFIX bmp_table_stream
#define TLIST_TYPE struct bmp_stream
#define TLIST_ITEM table_node
#define TLIST_WANT_ADD_TAIL

#include "lib/tlists.h"

struct bmp_peer {
  struct bmp_peer *next;
  struct bmp_peer_info {
    u32 proto_id;
    ea_list *proto_state;
    const char *proto_name;
  } info;
  TLIST_LIST(bmp_peer_stream) streams;
};

struct bmp_table {
  struct bmp_table *next;
  struct bmp_proto *p;
  rtable *table;
  struct rt_export_request out_req;
  event event;
  TLIST_LIST(bmp_table_stream) streams;
};

#endif /* _BIRD_BMP_H_ */
