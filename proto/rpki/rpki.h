/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	Using RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_RPKI_H_
#define _BIRD_RPKI_H_

#include "nest/bird.h"
#include "nest/route.h"
#include "lib/socket.h"
#include "lib/ip.h"

#include "ssh_transport.h"
#include "tcp_transport.h"
#include "rtr.h"
#include "packets.h"

#define RPKI_DEFAULT_PORT 		8282
#define RPKI_DEFAULT_SSH_PORT 		22
#define RPKI_DEFAULT_RETRY_INTERVAL	30
#define RPKI_DEFAULT_REFRESH_INTERVAL	600
#define RPKI_DEFAULT_EXPIRE_INTERVAL	1200
#define RPKI_DEFAULT_CACHE_PREFERENCE 	1	/* The most important priority */

/*
 * 		+-------------------------------------------+
 * 		v					    |
 * 	RTR_MGR_CLOSED <--> RTR_MGR_CONNECTING --> RTR_MGR_ESTABLISHED <--> RTR_MGR_ERROR
 * 		^		    |					      ^   |
 * 		|		    +-----------------------------------------+   |
 * 		|								  |
 * 		+-----------------------------------------------------------------+
 */
enum rtr_mgr_status {
  /* RTR sockets are disconnected */
  RTR_MGR_CLOSED,

  /* RTR sockets trying to establish a connection. */
  RTR_MGR_CONNECTING,

  /* All RTR sockets of the group are synchronized with the rtr servers. */
  RTR_MGR_ESTABLISHED,

  /* Error occured on at least one RTR socket. */
  RTR_MGR_ERROR,
};

struct rpki_cache_ssh_cfg {
  char *bird_private_key;		/* Filepath to the BIRD server private key */
  char *cache_public_key;		/* Filepath to the public key of cache server, can be file known_hosts */
  char *username;			/* Username for SSH connection */
};

/* Used in parsing of configuration file */
struct rpki_cache_cfg {
  node n;
  char *hostname;			/* Full domain name of cache server or NULL */
  ip_addr ip;				/* IP address of cache server or IPA_NONE */
  u16 port;				/* Port of cache server */
  u8 preference;			/* Preference: the most prioritized are the lowest numbers and starts with 1 */
  uint refresh_interval;		/* Time interval (in seconds) for refreshing ROA from server */
  uint expire_interval;			/* Time interval (in seconds) */
  uint retry_interval;			/* Time interval (in seconds) for an unreachable server */
  struct rpki_cache_ssh_cfg *ssh;	/* SSH configuration or NULL */
};

struct rpki_cache {
  node n;
  struct rpki_proto *p;
  struct rpki_cache_cfg *cfg;
  struct rpki_cache_group *group;
  struct rtr_socket *rtr_socket;	/* RTRlib's socket data structure */
  sock *sk;				/* BIRD's socket data structure */
  timer *retry_timer;			/* Timer for Cache server */
  timer *refresh_timer;			/* Timer for Cache server */
  timer *expire_timer;			/* Timer for Cache server */
  u32 cache_id;				/* For purge ROAs learned only from this cache */
};

struct rpki_cache_group {
  node n;
  u8 preference;			/* Preference: the most prioritized are the lowest numbers and starts with 1 */
  list cache_list;			/* List of cache servers (struct rpki_cache) * */
  enum rtr_mgr_status status;
};

struct rpki_config {
  struct proto_config c;
  list cache_cfg_list;			/* Unordered list of cache servers configurations (struct rpki_cache_cfg) */
  struct roa_table_config *roa_table_cf;/* The ROA table for routes importing from cache servers */
};

struct rpki_proto {
  struct proto p;
  struct rpki_config *cf;
  list group_list;			/* Sorted list of cache groups (struct rpki_cache_group) */
  timer *timer;				/* Main timer */
};

void rpki_init_all(void);
struct rpki_cache_cfg *rpki_new_cache_cfg(void);
void rpki_init_all(void);
void rpki_close_connection(struct rpki_cache *cache);
int  rpki_open_connection(struct rpki_cache *cache);
const char *get_cache_ident(struct rpki_cache *cache);
void rpki_relax_groups(struct rpki_proto *p);
void rpki_print_groups(struct rpki_proto *p);

#define RPKI_LOG(log_level, rpki, msg, args...) 			\
    do { 								\
      log(log_level "%s: " msg, (rpki)->p.name , ## args); 		\
    } while(0)

#if defined(LOCAL_DEBUG) || defined(GLOBAL_DEBUG)
#define CACHE_DBG(cache,msg,args...) 					\
    do { 								\
      RPKI_LOG(L_DEBUG, (cache)->p, "%s: %s() " msg, get_cache_ident(cache),__func__, ## args);	\
    } while(0)
#else
#define CACHE_DBG(cache,msg,args...) do { } while(0)
#endif

#define RPKI_TRACE(level,rpki,msg,args...) 				\
    do {								\
      if ((rpki)->p.debug & level)					\
        RPKI_LOG(L_TRACE, rpki, msg, ## args);				\
    } while(0)

#define CACHE_TRACE(level,cache,msg,args...)				\
    do {								\
      if ((cache)->p->p.debug & level)					\
        RPKI_LOG(L_TRACE, (cache)->p, "%s: " msg, get_cache_ident(cache), ## args);	\
    } while(0)

#define RPKI_WARN(p, msg, args...) RPKI_LOG(L_WARN, p, msg, ## args);

#endif /* _BIRD_RPKI_H_ */
