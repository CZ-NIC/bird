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
 * @defgroup mod_transport_h Transport sockets
 * @brief The RTR transport sockets implement the communication channel
 * (e.g., SSH, TCP, TCP-AO) between an RTR server and client.
 * @details Before using the transport socket, a tr_socket must be
 * initialized based on a protocol-dependent init function (e.g.,
 * tr_tcp_init()).\n
 * The tr_* functions call the corresponding function pointers, which are
 * passed in the tr_socket struct, and forward the remaining arguments.
 *
 * @{
 */

#ifndef RTR_TRANSPORT_H
#define RTR_TRANSPORT_H
#include <time.h>

/**
 * @brief The return values for tr_ functions.
 */
enum tr_rtvals {
  /** @brief Operation was successfull. */
  TR_SUCCESS = 0,

  /** Error occured. */
  TR_ERROR = -1,

  /** No data is available on the socket. */
  TR_WOULDBLOCK = -2,

  /** Call was interrupted from a signal */
  TR_INTR = -3,

  /** Connection closed */
  TR_CLOSED = -4
};

struct tr_socket;

/**
 * @brief A transport socket datastructure.
 *
 * @param socket A pointer to a technology specific socket.
 * @param open_fp Pointer to a function that establishes the socket connection.
 * @param close_fp Pointer to a function that closes the socket.
 * @param free_fp Pointer to a function that frees all memory allocated with this socket.
 */
struct tr_socket {
  void *socket;
  int  (*open_fp)(void *socket) ;
  void (*close_fp)(void *socket) ;
  void (*free_fp)(struct tr_socket *tr_sock);
  const char *(*ident_fp)(void *socket);
};

/**
 * @brief Establish the connection.
 * @param[in] socket Socket that will be used.
 * @return TR_SUCCESS On success.
 * @return TR_ERROR On error.
 */
int tr_open(struct tr_socket *socket);

/**
 * @brief Close the socket connection.
 * @param[in] socket Socket that will be closed.
 */
void tr_close(struct tr_socket *socket);

/**
 * @brief Deallocates all memory that the passed socket uses.
 * Socket have to be closed before.
 * @param[in] socket which will be freed.
 */
void tr_free(struct tr_socket *socket);

/**
 * Returns an identifier for the socket endpoint, eg host:port.
 * @param[in] socket
 * return Pointer to a \0 terminated String
 * return NULL on error
 */
const char *tr_ident(struct tr_socket *socket);

#endif
/* @} */
