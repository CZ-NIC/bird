/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_RPKI_H_
#define _BIRD_RPKI_H_

#include "rtrlib/rtrlib.h"

#include "nest/bird.h"
#include "nest/protocol.h"

#define RPKI_PORT "8282"
#define RPKI_PORT_MAX_LENGTH_STR 6

#define RPKI_TRACE(rpki, msg, args...) 					\
  do { 									\
    if (rpki->p.debug)							\
      log(L_TRACE "%s: " msg, rpki->p.name , ## args ); 		\
  } while(0)

struct rpki_cache {
  node n;		/* in struct rpki_config.cache_list */
  ip_addr ip;
  char *full_domain_name;
  char port[RPKI_PORT_MAX_LENGTH_STR]; /* the highest port is "65535" */
  u8 preference;

  /* below are private variables */

  struct rtr_socket rtr_tcp;
  struct tr_socket tr_tcp;
  struct tr_tcp_config tcp_config;
  char ip_buf[INET6_ADDRSTRLEN];
};

struct rpki_config {
  struct proto_config c;
  list cache_list; 	/* (struct rpki_cache *) */
};

struct rpki_proto {
  struct proto p;
  struct rtr_mgr_config *rtr_conf;
  struct rtr_mgr_group *rtr_groups;
  uint rtr_groups_len;
};

struct rpki_cache *rpki_new_cache(void);

#endif /* _BIRD_RPKI_H_ */
