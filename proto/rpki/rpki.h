/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	Using RTRLib: http://rpki.realmv6.org/
 *
 *	(c) 2015 CZ.NIC
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_RPKI_H_
#define _BIRD_RPKI_H_

#include <pthread.h>

#include "nest/bird.h"
#include "nest/protocol.h"
#include "lib/socket.h"
#include "proto/rpki/rtrlib-mockup.h"


#define RPKI_PORT "8282"
#define RPKI_PORT_MAX_LENGTH_STR 6
#define RPKI_LIBRTR_DEFAULT "librtr.so"

#define RPKI_DEFAULT_CACHE_PREFERENCE 0xff	/* the least preference */

#define RPKI_LOG(log_level, p, msg, args...) 				\
  do { 									\
    log(log_level "%s: " msg, p->p.name , ## args); 			\
  } while(0)
#define RPKI_TRACE(p, msg, args...) 					\
  do {									\
    if (p->p.debug)							\
      RPKI_LOG(L_TRACE, p, msg, ## args);				\
  } while(0)
#define RPKI_ERROR(p, msg, args...) RPKI_LOG(L_ERR, p, msg, ## args);
#define RPKI_DIE(p, msg, args...) 					\
    do {								\
      RPKI_LOG(L_FATAL, p, msg, ## args);				\
      exit(1);								\
    } while(0)


struct rpki_cache {
  node n;		/* in struct rpki_config.cache_list */
  char *host;		/* full domain name or ip address */
  char port[RPKI_PORT_MAX_LENGTH_STR]; /* the highest port is "65535" */
  u8 preference;	/* the most prioritized are the lowest numbers, starts with 1 */
  struct rtr_socket *rtr_tcp;
  char *ip_buf;
};

struct rpki_config {
  struct proto_config c;
  list cache_list; 	/* struct rpki_cache * */
  struct roa_table_config *roa_table_cf;
};

struct rpki_proto {
  struct proto p;
  node rpki_node;	/* in rpki_proto_list */

  struct rpki_config *cf;
  struct rtr_mgr_config *rtr_conf;
  struct rtr_mgr_group *rtr_groups;
  struct rtr_socket **rtr_sockets;
  uint rtr_sockets_len;

  sock *notify_read_sk;
  sock *notify_write_sk;
  list notify_list;
  pthread_mutex_t notify_lock;
};

struct rpki_cache *rpki_new_cache(void);


static inline void rpki_lock_notify(struct rpki_proto *p) { pthread_mutex_lock(&p->notify_lock); }
static inline void rpki_unlock_notify(struct rpki_proto *p) { pthread_mutex_unlock(&p->notify_lock); }

void rpki_init_all(void);
char *rpki_load_rtrlib(void);

#endif /* _BIRD_RPKI_H_ */
