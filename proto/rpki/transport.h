/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *	(c) 2015 Pavel Tvrdik <pawel.tvrdik@gmail.com>
 *
 *	This file was a part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/*
 * The RPKI transport sockets implement the communication channel
 * (e.g., SSH, TCP, TCP-AO) between an RPKI server and client.
 *
 * Before using the transport socket, a tr_socket must be
 * initialized based on a protocol-dependent init function (e.g.,
 * rpki_tr_tcp_init()).
 *
 * The rpki_tr_* functions call the corresponding function pointers, which are
 * passed in the rpki_tr_sock structure, and forward the remaining arguments.
 */

#ifndef _BIRD_RPKI_TRANSPORT_H_
#define _BIRD_RPKI_TRANSPORT_H_

#include <time.h>

/* The return values for rpki_tr_ functions */
enum rpki_tr_rtvals {
  RPKI_TR_SUCCESS 		= 0,	/* Operation was successful */
  RPKI_TR_ERROR 		= -1,	/* Error occurred */
  RPKI_TR_WOULDBLOCK 		= -2,	/* No data is available on the socket */
  RPKI_TR_INTR 			= -3,	/* Call was interrupted from a signal */
  RPKI_TR_CLOSED 		= -4	/* Connection closed */
};

/* A transport socket structure */
struct rpki_tr_sock {
  sock *sk;				/* Standard BIRD socket */
  struct rpki_cache *cache;		/* Cache server */
  int (*open_fp)(struct rpki_tr_sock *);	  /* Function that establishes the socket connection */
  const char *(*ident_fp)(struct rpki_tr_sock *); /* Function that returns an identifier for the socket endpoint */
  const char *ident;			/* Internal. Use ident_fp() hook instead of this pointer */
};

int rpki_tr_open(struct rpki_tr_sock *tr);
void rpki_tr_close(struct rpki_tr_sock *tr);
const char *rpki_tr_ident(struct rpki_tr_sock *tr);

/* Types of supported transports */
enum rpki_tr_type {
  RPKI_TR_TCP,				/* Unprotected transport over TCP */
#if HAVE_LIBSSH
  RPKI_TR_SSH,				/* Protected transport by SSHv2 connection */
#endif
};

/* Common configure structure for transports */
struct rpki_tr_config {
  enum rpki_tr_type type;		/* RPKI_TR_TCP or RPKI_TR_SSH */
  const void *spec;			/* Specific transport configuration, i.e. rpki_tr_tcp_config or rpki_tr_ssh_config */
};

struct rpki_tr_tcp_config {
  /* No internal configuration data */
};

struct rpki_tr_ssh_config {
  const char *bird_private_key;		/* Filepath to the BIRD server private key */
  const char *cache_public_key;		/* Filepath to the public key of cache server, can be file known_hosts */
  const char *user;			/* Username for SSH connection */
};

/* ssh_transport.c */
void rpki_tr_ssh_init(struct rpki_tr_sock *tr);

/* tcp_transport.c */
void rpki_tr_tcp_init(struct rpki_tr_sock *tr);

#endif /* _BIRD_RPKI_TRANSPORT_H_ */
