/*
 *	BIRD -- An implementation of the SSH protocol for the RPKI transport
 *
 *	This transport implementation uses libssh (http://www.libssh.org/)
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file was a part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_RPKI_SSH_TRANSPORT_H_
#define _BIRD_RPKI_SSH_TRANSPORT_H_

#include "transport.h"

struct rpki_tr_ssh {
  const char *ident;
};

void rpki_tr_ssh_init(struct rpki_tr_sock *tr);

#endif
