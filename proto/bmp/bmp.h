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
#include "proto/bmp/map.h"

#include <stdbool.h>

// Max length of MIB-II description object
#define MIB_II_STR_LEN 255

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
  pool *buffer_mpool;              // Memory pool used for BMP buffer allocations
  pool *map_mem_pool;              // Memory pool used for BMP map allocations
  pool *tx_mem_pool;               // Memory pool used for packet allocations designated to BMP collector
  pool *update_msg_mem_pool;       // Memory pool used for BPG UPDATE MSG allocations
  list tx_queue;                   // Stores queued packets going to be sent
  timer *connect_retry_timer;      // Timer for retrying connection to the BMP collector
  list update_msg_queue;           // Stores all composed BGP UPDATE MSGs
  bool started;                    // Flag that stores running status of BMP instance
  int sock_err;                    // Last socket error code
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
