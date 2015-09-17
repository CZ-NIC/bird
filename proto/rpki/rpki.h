/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_RPKI_H_
#define _BIRD_RPKI_H_

#include "nest/bird.h"
#include "nest/protocol.h"

struct cache_server {
  ip_addr ip;
  u16 port;
};

struct rpki_config {
  struct proto_config c;
  struct cache_server remote;
};

struct rpki_proto {
  struct proto p;
};


#endif /* _BIRD_RPKI_H_ */
