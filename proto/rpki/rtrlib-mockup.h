/*
 *	BIRD -- RTRLib Headers mockup
 *
 *	(c) 2015 CZ.NIC
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *
 * RTRlib is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 *
 * RTRlib is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RTRlib; see the file COPYING.LESSER.
 *
 * INET group, Hamburg University of Applied Sciences,
 * CST group, Freie Universitaet Berlin
 * Website: http://rpki.realmv6.org/
 *
 */

#ifndef _BIRD_RTRLIB_MOCKUP_H_
#define _BIRD_RTRLIB_MOCKUP_H_

#include <stdbool.h>

/**
 * @brief A transport socket datastructure.
 *
 * @param socket A pointer to a technology specific socket.
 * @param open_fp Pointer to a function that establishes the socket connection.
 * @param close_fp Pointer to a function that closes the socket.
 * @param free_fp Pointer to a function that frees all memory allocated with this socket.
 * @param send_fp Pointer to a function that sends data through this socket.
 * @param recv_fp Pointer to a function that receives data from this socket.
 */
struct tr_socket {
    void *socket;
    void *open_fp;	/* voided for mockuping */
    void *close_fp;	/* voided for mockuping */
    void *free_fp;	/* voided for mockuping */
    void *send_fp;	/* voided for mockuping */
    void *recv_fp;	/* voided for mockuping */
    void *ident_fp;	/* voided for mockuping */
};

/**
 * @brief States of the RTR socket.
 */
enum rtr_socket_state {
    /** Socket is establishing the transport connection. */
    RTR_CONNECTING,

    /** Connection is established, socket is waiting for a Serial Notify or expiration of the refresh_interval timer */
    RTR_ESTABLISHED,

    /** Resetting RTR connection. */
    RTR_RESET,

    /** Receiving validation records from the RTR server.  */
    RTR_SYNC,

    /** Reconnect without any waiting period */
    RTR_FAST_RECONNECT,

    /** No validation records are available on the RTR server. */
    RTR_ERROR_NO_DATA_AVAIL,

    /** Server was unable to answer the last serial or reset query. */
    RTR_ERROR_NO_INCR_UPDATE_AVAIL,

    /** Fatal protocol error occurred. */
    RTR_ERROR_FATAL,

    /** Error on the transport socket occurred. */
    RTR_ERROR_TRANSPORT,

    /** RTR Socket is stopped. */
    RTR_SHUTDOWN,
};

/**
 * @brief A RTR socket.
 * @param tr_socket Pointer to an initialized tr_socket that will be used to communicate with the RTR server.
 * @param refresh_interval Time period in seconds. Tells the router how long to wait before next attempting to poll the cache, using a Serial Query or
 * Reset Query PDU.
 * @param last_update Timestamp of the last validation record update. Is 0 if the pfx_table doesn't stores any
 * validation reords from this rtr_socket.
 * @param expire_interval Time period in seconds. Received records are deleted if the client was unable to refresh data for this time period.
 * If 0 is specified, the expire_interval is twice the refresh_interval.
 * @param retry_interval Time period in seconds between a faild quary and the next attempt.
 * @param state Current state of the socket.
 * @param session_id session_id of the RTR session.
 * @param request_session_id True, if the rtr_client have to request a new none from the server.
 * @param serial_number Last serial number of the obtained validation records.
 * @param pfx_table pfx_table that stores the validation records obtained from the connected rtr server.
 * @param connection_state_fp A callback function that is executed when the state of the socket changes.
 * @param connection_state_fp_param Parameter that is passed to the connection_state_fp callback.
 */
struct rtr_socket {
  struct tr_socket *tr_socket;
  unsigned int refresh_interval;
  time_t last_update;
  unsigned int expire_interval;
  unsigned int retry_interval;
  enum rtr_socket_state state;
  uint32_t session_id;
  bool request_session_id;
  uint32_t serial_number;
  void *pfx_table;				/* voided for mockuping */
  pthread_t thread_id;
  void *connection_state_fp;			/* voided for mockuping */
  void *connection_state_fp_param;
  unsigned int version;
  void *spki_table;				/* voided for mockuping */
};

/**
 * @brief  A tr_tcp_config struct holds configuration for a TCP connection.
 * @param host Hostname or IP address to connect to.
 * @param port Port to connect to.
 * @param bindaddr Hostname or IP address to connect from. NULL for
 *		   determination by OS.
 * to use the source address of the system's default route to the server
 */
struct tr_tcp_config {
    char *host;
    char *port;
    char *bindaddr;
};

/**
 * @brief Status of a rtr_mgr_group.
 */
enum rtr_mgr_status {
    /** RTR sockets are disconnected */
    RTR_MGR_CLOSED,

    /** RTR sockets trying to establish a connection. */
    RTR_MGR_CONNECTING,

    /** All RTR sockets of the group are synchronized with the rtr servers. */
    RTR_MGR_ESTABLISHED,

    /** Error occured on at least one RTR socket. */
    RTR_MGR_ERROR,
};

/**
 * @brief A set of RTR sockets.
 * @param sockets Array of rtr_socket pointer. The tr_socket element of the rtr_socket must be associated with an initialized transport socket.
 * @param sockets_len Number of elements in the sockets array.
 * @param preference The preference value of this group. Groups with lower preference values are preferred.
 * @param status Status of the group.
 */
struct rtr_mgr_group {
    struct rtr_socket **sockets;
    unsigned int sockets_len;
    uint8_t preference;
    enum rtr_mgr_status status;
};

struct rtr_mgr_config {
    struct rtr_mgr_group *groups;
    unsigned int len;
    /* some items deleted */
};


/**
 * @brief Version of the IP protocol.
 */
enum rtr_ip_version {
    RTRLIB_IPV4,
    RTRLIB_IPV6
};

/**
 * @brief Struct storing an IPv4 address in host byte order.
 * @param addr The IPv4 address.
 */
struct ipv4_addr {
    uint32_t addr;
};

/**
 * @brief Struct holding an IPv6 address in host byte order.
 * @param addr The IPv6 address.
 */
struct ipv6_addr {
    uint32_t addr[4];
};

/**
 * @brief The rtr_ip_addr struct stores a IPv4 or IPv6 address in host byte order.
 * @param ver Specifies the type of the stored address.
 * @param u Union holding a ipv4_addr or ipv6_addr.
 */
struct rtr_ip_addr {
    enum rtr_ip_version ver;
    union {
        struct ipv4_addr addr4;
        struct ipv6_addr addr6;
    } u;
};

/**
 * @brief pfx_record.
 * @param asn Origin AS number.
 * @param prefix IP prefix.
 * @param min_len Minimum prefix length.
 * @param max_len Maximum prefix length.
 * @param socket_id unique id of the rtr_socket that received this record.
 */
struct pfx_record {
    uint32_t asn;
    struct rtr_ip_addr prefix;
    uint8_t min_len;
    uint8_t max_len;
    const struct rtr_socket *socket;
};

#endif /* _BIRD_RTRLIB_MOCKUP_H_ */
