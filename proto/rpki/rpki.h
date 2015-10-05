/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
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
#define RPKI_RX_BUFFER_EXT_SIZE 0xffff
#define RPKI_TX_BUFFER_EXT_SIZE 0xffff
#define RPKI_RTRLIB_PATH "/usr/local/lib64/librtr.so"

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
  ip_addr ip;
  char *full_domain_name;
  char port[RPKI_PORT_MAX_LENGTH_STR]; /* TODO change to u16 */
  u8 preference;

  /* below are private variables */

  struct rtr_socket rtr_tcp;
  struct tr_socket tr_tcp;
  struct tr_tcp_config tcp_config;
  char ip_buf[INET6_ADDRSTRLEN];
  char port_buf[RPKI_PORT_MAX_LENGTH_STR]; /* the highest port is "65535" */
};

struct rpki_config {
  struct proto_config c;
  list cache_list; 	/* (struct rpki_cache *) */
  struct roa_table_config *roa_table_cf;
  const char *rtrlib_path;
};

struct rpki_proto {
  struct proto p;
  node rpki_node;
  struct rpki_config *cf;
  struct rtr_mgr_config *rtr_conf;
  struct rtr_mgr_group *rtr_groups;
  struct rtr_socket **rtr_sockets;
  uint rtr_sockets_len;

  sock *notify_read_sk;
  sock *notify_write_sk;
  list notify_list;
  pthread_spinlock_t notify_lock;
};

struct rpki_cache *rpki_new_cache(void);

static inline void rpki_lock_sessions(struct rpki_proto *p) { pthread_spin_lock(&p->notify_lock); }
static inline void rpki_unlock_sessions(struct rpki_proto *p) { pthread_spin_unlock(&p->notify_lock); }

void rpki_init_all(void);

#endif /* _BIRD_RPKI_H_ */
