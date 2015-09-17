/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file was part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "rpki.h"
#include "transport.h"

inline int tr_open(struct tr_socket *socket)
{
  return socket->open_fp(socket->socket);
}

inline void tr_close(struct tr_socket *socket)
{
  socket->close_fp(socket->socket);
}

inline void tr_free(struct tr_socket *socket)
{
  socket->free_fp(socket);
}

inline const char *tr_ident(struct tr_socket *socket)
{
  return socket->ident_fp(socket->socket);
}
