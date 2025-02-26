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
#include "nest/route.h"
#include "lib/event.h"
#include "lib/hash.h"
#include "lib/socket.h"
#include "proto/bgp/bgp.h"
#include "proto/bmp/map.h"

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

/* Forward declarations */
struct bgp_proto;
struct bmp_proto;

struct bmp_proto {
  struct proto p;                  // Parent proto
  const struct bmp_config *cf;     // Shortcut to BMP configuration
  node bmp_node;                   // Node in bmp_proto_list

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
  // struct bmp_peer_map bgp_peers;   // Stores 'bgp_proto' structure per BGP peer
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
  byte msgbuf[BMP_MSGBUF_LEN];     // Buffer for preparing the messages before sending them out
};

struct bmp_peer {
  struct bgp_proto *bgp;
  struct bmp_peer *next;
  list streams;
};

struct bmp_stream {
  node n;
  struct bgp_proto *bgp;
  u32 key;
  bool sync;
  struct bmp_stream *next;
  struct bmp_table *table;
  struct bgp_channel *sender;
};

struct bmp_table {
  struct rtable *table;
  struct bmp_table *next;
  struct channel *channel;
  u32 uc;
};


#ifdef CONFIG_BMP

/**
 * bmp_peer_up - send notification that BGP peer connection is established
 */
void
bmp_peer_up(struct bgp_proto *bgp,
	    const byte *tx_open_msg, uint tx_open_length,
	    const byte *rx_open_msg, uint rx_open_length);

/**
 * bmp_peer_down - send notification that BGP peer connection is not in
 * established state
 */
void
bmp_peer_down(const struct bgp_proto *bgp, int err_class, int code, int subcode, const byte *data, int length);


#else /* BMP build disabled */

static inline void bmp_peer_up(struct bgp_proto *bgp UNUSED, const byte *tx_open_msg UNUSED, uint tx_open_length UNUSED, const byte *rx_open_msg UNUSED, uint rx_open_length UNUSED) { }
static inline void bmp_peer_down(const struct bgp_proto *bgp UNUSED, const int err_class UNUSED, int code UNUSED, int subcode UNUSED, const byte *data UNUSED, int length UNUSED) { }

#endif /* CONFIG_BMP */

#endif /* _BIRD_BMP_H_ */
