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

enum bmp_peer_down {
  // Value of packet size of 'pkt_size' argument of bmp_peer_down() function
  // used for pointing out that there was not any packet to pass
  BMP_PEER_DOWN_NULL_PKT_SIZE = 0
};

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
  ip_addr station_ip;                 // Monitoring station address
  u16 station_port;                   // Monitoring station TCP port
  bool disabled;                      // Manually disabled
  bool monitoring_rib_in_pre_policy;  // Route monitoring pre-policy Adj-Rib-In
  bool monitoring_rib_in_post_policy; // Route monitoring post-policy Adj-Rib-In
  bool monitoring_rib_local;          // Route monitoring Local Rib
};

/* Forward declarations */
struct bgp_proto;
struct bmp_proto;

struct bmp_conn {
  struct bmp_proto *bmp;
  struct birdsock *sk;
  event *tx_ev;
};

// Stores sent and received BGP OPEN MSGs
struct bmp_peer_open_msg {
  struct bmp_peer_map tx_msg;
  struct bmp_peer_map rx_msg;
};

// Keeps necessary information during composing BGP UPDATE MSG which is going
// to be sent to the BMP collector
struct rt_table_info {
  list update_msg_queue;         // Stores all composed BGP UPDATE MSGs
  size_t update_msg_size;        // Size of all BGP UPDATE MSGs
  struct timeval update_begin_time; // Keeps timestamp of starting BGP UPDATE MSGs composing
  bool update_in_progress;       // Holds information whether composing process is still in progress
};

struct bmp_proto {
  struct proto p;                  // Parent proto
  const struct bmp_config *cf;     // Shortcut to BMP configuration
  struct bmp_conn *conn;           // Connection we have established
  char sys_descr[MIB_II_STR_LEN];  // sysDescr MIB-II [RFC1213] object
  char sys_name[MIB_II_STR_LEN];   // sysName MIB-II [RFC1213] object
  ip_addr station_ip;              // Monitoring station IP address
  u16 station_port;                // Monitoring station TCP port
  bool disabled;                   // Manually disabled
  struct monitoring_rib monitoring_rib;
  // Below fields are for internal use
  int station_socket;              // Socket associated with the BMP collector
  struct bmp_peer_map bgp_peers;   // Stores 'bgp_proto' structure per BGP peer
  struct bmp_peer_open_msg peer_open_msg; // Stores sent and received BGP OPEN MSG per BGP peer
  pool *buffer_mpool;              // Memory pool used for BMP buffer allocations
  pool *map_mem_pool;              // Memory pool used for BMP map allocations
  pool *tx_mem_pool;               // Memory pool used for packet allocations designated to BMP collector
  pool *update_msg_mem_pool;       // Memory pool used for BPG UPDATE MSG allocations
  list tx_queue;                   // Stores queued packets going to be sent
  timer *connect_retry_timer;      // Timer for retrying connection to the BMP collector
  struct rt_table_info rt_table_in_pre_policy; // Pre-policy route import table
  bool station_connected;          // Flag that stores connection status with BMP station
  bool started;                    // Flag that stores running status of BMP instance
};

/**
 * bmp_put_sent_bgp_open_msg - save sent BGP OPEN msg packet in BMP implementation.
 * NOTE: If there has been passed sent and received BGP OPEN MSGs to the BMP
 *       implementation, then there is going to be send BMP Peer Up Notification
 *       message to the BMP collector.
 */
void
bmp_put_sent_bgp_open_msg(const struct bgp_proto *bgp, const byte* pkt,
  const size_t pkt_size);

/**
 * bmp_put_recv_bgp_open_msg - save received BGP OPEN msg packet in BMP implementation.
 * NOTE: If there has been passed sent and received BGP OPEN MSGs to the BMP
 *       implementation, then there is going to be send BMP Peer Up Notification
 *       message to the BMP collector.
 */
void
bmp_put_recv_bgp_open_msg(const struct bgp_proto *bgp, const byte* pkt,
  const size_t pkt_size);

/**
 * The following 4 functions create BMP Route Monitoring message based on
 * pre-policy Adj-RIB-In. Composing Route Monitoring message consist of few
 * stages. First of all call bmp_route_monitor_update_in_pre_begin() in order
 * to start composing message. As a second step, call
 * bmp_route_monitor_put_update_in_pre_msg() in order to save BGP UPDATE msg.
 * As a third step call bmp_route_monitor_update_in_pre_commit() in order to
 * send BMP Route Monitoring message to the BMP collector. As a last step,
 * call bmp_route_monitor_update_in_pre_end() in order to release resources.
 */
void
bmp_route_monitor_update_in_pre_begin(void);

void
bmp_route_monitor_put_update_in_pre_msg(const byte *data, const size_t data_size);

void
bmp_route_monitor_update_in_pre_commit(const struct bgp_proto *bgp);

void
bmp_route_monitor_update_in_pre_end(void);

/**
 * bmp_peer_down - send notification that BGP peer connection is not in
 * established state
 */
void
bmp_peer_down(const struct bgp_proto *bgp, const int err_class, const byte *pkt,
  size_t pkt_size);

#endif	/* _BIRD_BMP_H_ */
