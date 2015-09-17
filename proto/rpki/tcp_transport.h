/*
 *	BIRD -- An implementation of the TCP protocol for the RPKI protocol transport
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file was a part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_RPKI_TCP_TRANSPORT_H_
#define _BIRD_RPKI_TCP_TRANSPORT_H_

#include "transport.h"

struct rpki_tr_tcp {
  const char *ident;
};

void rpki_tr_tcp_init(struct rpki_tr_sock *tr);

#endif
