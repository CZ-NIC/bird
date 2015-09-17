/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file was part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * @defgroup mod_tcp_transport_h TCP transport socket
 * @ingroup mod_transport_h
 * @brief An implementation of the TCP protocol for the RTR transport.
 * See @ref mod_transport_h "transport interface" for a list of supported operations.
 *
 * @{
 */

#ifndef RTR_TCP_TRANSPORT_H
#define RTR_TCP_TRANSPORT_H
#include "transport.h"
#include "nest/bird.h"
#include "lib/ip.h"

/**
 * @brief  A tr_tcp_config struct holds configuration for a TCP connection.
 * @param host Hostname or IP address to connect to.
 * @param port Port to connect to.
 * @param bindaddr Hostname or IP address to connect from. NULL for
 *		   determination by OS.
 * to use the source address of the system's default route to the server
 */
struct tr_tcp_config {
  ip_addr ip;  char *host;	/* at least one of @ip or @host must be defined */
  uint port;
  char *bindaddr;		/* TODO: NEED THIS? */
};

struct tr_tcp_socket {
  struct rpki_cache *cache;
  struct tr_tcp_config config;
  char *ident;
};

/**
 * @brief Initializes the tr_socket struct for a TCP connection.
 * @param[in] config TCP configuration for the connection.
 * @param[out] socket Initialized transport socket.
 * @returns TR_SUCCESS On success.
 * @returns TR_ERROR On error.
 */
int tr_tcp_init(struct rpki_cache *cache);
#endif
/* @} */
