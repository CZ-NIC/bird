/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *	(c) 2015 Pavel Tvrdik <pawel.tvrdik@gmail.com>
 *
 *	Using RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_RPKI_H_
#define _BIRD_RPKI_H_

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "lib/socket.h"
#include "lib/ip.h"

#include "transport.h"
#include "packets.h"

#define RPKI_TCP_PORT		323
#define RPKI_SSH_PORT		22
#define RPKI_RETRY_INTERVAL	600
#define RPKI_REFRESH_INTERVAL	3600
#define RPKI_EXPIRE_INTERVAL	7200

#define RPKI_VERSION_0		0
#define RPKI_VERSION_1		1
#define RPKI_MAX_VERSION 	RPKI_VERSION_1


/*
 * 	RPKI Cache
 */

enum rpki_cache_state {
  RPKI_CS_CONNECTING, 			/* Socket is establishing the transport connection. */
  RPKI_CS_ESTABLISHED,			/* Connection is established, socket is waiting for a Serial Notify or expiration of the refresh_interval timer */
  RPKI_CS_RESET,			/* Resetting RTR connection. */
  RPKI_CS_SYNC_START,			/* Sending a Serial/Reset Query PDU and expecting a Cache Response PDU */
  RPKI_CS_SYNC_RUNNING,			/* Receiving validation records from the RTR server. A state between Cache Response PDU and End of Data PDU */
  RPKI_CS_FAST_RECONNECT,		/* Reconnect without any waiting period */
  RPKI_CS_NO_INCR_UPDATE_AVAIL, 	/* Server is unable to answer the last Serial Query and sent Cache Reset. */
  RPKI_CS_ERROR_NO_DATA_AVAIL,		/* Server is unable to answer either a Serial Query or a Reset Query because it has no useful data available at this time. */
  RPKI_CS_ERROR_FATAL,			/* Fatal protocol error occurred. */
  RPKI_CS_ERROR_TRANSPORT,		/* Error on the transport socket occurred. */
  RPKI_CS_SHUTDOWN,			/* RTR Socket is stopped. */
};

struct rpki_cache {
  pool *pool;				/* Pool containing cache objects */
  struct rpki_proto *p;

  struct rpki_tr_sock *tr_sock;		/* Transport specific socket */
  enum rpki_cache_state state;		/* RPKI_CS_* */
  u32 session_id;
  u8 request_session_id;		/* 1: have to request new session id; 0: we have already received session id */
  u32 serial_num;			/* Serial number denotes the logical version of data from cache server */
  u8 version;				/* Protocol version */
  btime last_update;			/* Last successful synchronization with cache server */
  btime last_rx_prefix;			/* Last received prefix PDU */

  /* Intervals can be changed by cache server on the fly */
  u32 refresh_interval;			/* Actual refresh interval (in seconds) */
  u32 retry_interval;
  u32 expire_interval;
  timer *retry_timer;			/* Retry timer event */
  timer *refresh_timer;			/* Refresh timer event */
  timer *expire_timer;			/* Expire timer event */
};

const char *rpki_get_cache_ident(struct rpki_cache *cache);
const char *rpki_cache_state_to_str(enum rpki_cache_state state);


/*
 * 	Routes handling
 */

void rpki_table_add_roa(struct rpki_cache *cache, struct channel *channel, const net_addr_union *pfxr);
void rpki_table_remove_roa(struct rpki_cache *cache, struct channel *channel, const net_addr_union *pfxr);


/*
 *	RPKI Protocol Logic
 */

void rpki_cache_change_state(struct rpki_cache *cache, const enum rpki_cache_state new_state);


/*
 * 	RPKI Timer Events
 */

const char *rpki_check_refresh_interval(uint seconds);
const char *rpki_check_retry_interval(uint seconds);
const char *rpki_check_expire_interval(uint seconds);


/*
 * 	RPKI Protocol Configuration
 */

struct rpki_proto {
  struct proto p;
  struct rpki_cache *cache;

  struct channel *roa4_channel;
  struct channel *roa6_channel;
  u8 refresh_channels;			/* For non-incremental updates using rt_refresh_begin(), rt_refresh_end() */
};

struct rpki_config {
  struct proto_config c;
  const char *hostname;			/* Full domain name or stringified IP address of cache server */
  ip_addr ip;				/* IP address of cache server or IPA_NONE */
  u16 port;				/* Port number of cache server */
  struct rpki_tr_config tr_config;	/* Specific transport configuration structure */
  u32 refresh_interval;			/* Time interval (in seconds) for periodical downloading data from cache server */
  u32 retry_interval;			/* Time interval (in seconds) for an unreachable server */
  u32 expire_interval;			/* Maximal lifetime (in seconds) of ROAs without any successful refreshment */
  u8 keep_refresh_interval:1;		/* Do not overwrite refresh interval by cache server update */
  u8 keep_retry_interval:1;		/* Do not overwrite retry interval by cache server update */
  u8 keep_expire_interval:1;		/* Do not overwrite expire interval by cache server update */
  u8 ignore_max_length:1;		/* Ignore received max length and use MAX_PREFIX_LENGTH instead */
};

void rpki_check_config(struct rpki_config *cf);


/*
 *	Logger
 */

#define RPKI_LOG(log_level, rpki, msg, args...) 			\
    do { 								\
      log(log_level "%s: " msg, (rpki)->p.name , ## args); 		\
    } while(0)

#if defined(LOCAL_DEBUG) || defined(GLOBAL_DEBUG)
#define CACHE_DBG(cache,msg,args...) 					\
    do { 								\
      RPKI_LOG(L_DEBUG, (cache)->p, "%s [%s] %s " msg, rpki_get_cache_ident(cache), rpki_cache_state_to_str((cache)->state), __func__, ## args); \
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
        RPKI_LOG(L_TRACE, (cache)->p, msg, ## args); 			\
    } while(0)

#define RPKI_WARN(p, msg, args...) RPKI_LOG(L_WARN, p, msg, ## args);

#endif /* _BIRD_RPKI_H_ */
