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
#include "nest/protocol.h"
#include "lib/socket.h"
#include "lib/ip.h"

#include "ssh_transport.h"
#include "tcp_transport.h"
#include "packets.h"

#define RPKI_PORT			323
#define RPKI_SSH_PORT			22
#define RPKI_DEFAULT_RETRY_INTERVAL	600
#define RPKI_DEFAULT_REFRESH_INTERVAL	3600
#define RPKI_DEFAULT_EXPIRE_INTERVAL	7200

#define RPKI_VERSION_0			0
#define RPKI_VERSION_1			1
#define RPKI_MIN_VERSION 		0
#define RPKI_MAX_VERSION 		1

/*
 * Used in parsing of configuration file
 */

struct rpki_config_ssh {
  const char *bird_private_key;		/* Filepath to the BIRD server private key */
  const char *cache_public_key;		/* Filepath to the public key of cache server, can be file known_hosts */
  const char *user;			/* Username for SSH connection */
};

/*
 * Cache server
 */

enum rpki_cache_state {
    RPKI_CS_CONNECTING, 		/* Socket is establishing the transport connection. */
    RPKI_CS_ESTABLISHED,     		/* Connection is established, socket is waiting for a Serial Notify or expiration of the refresh_interval timer */
    RPKI_CS_RESET,			/* Resetting RTR connection. */
    RPKI_CS_SYNC,			/* Receiving validation records from the RTR server. */
    RPKI_CS_FAST_RECONNECT,		/* Reconnect without any waiting period */
    RPKI_CS_ERROR_NO_DATA_AVAIL,	/* No validation records are available on the RTR server. */
    RPKI_CS_ERROR_NO_INCR_UPDATE_AVAIL, /* Server was unable to answer the last serial or reset query. */
    RPKI_CS_ERROR_FATAL,		/* Fatal protocol error occurred. */
    RPKI_CS_ERROR_TRANSPORT,		/* Error on the transport socket occurred. */
    RPKI_CS_SHUTDOWN,			/* RTR Socket is stopped. */
};

/* return values */
enum rpki_rtvals {
    RPKI_SUCCESS = 0,
    RPKI_ERROR = -1
};

struct rpki_cache {
  pool *pool;				/* Pool containing cache objects */
  struct rpki_proto *p;

  struct channel *roa4_channel;
  struct channel *roa6_channel;
  u8 refresh_channels;			/* For non-incremental updates using rt_refresh_begin(), rt_refresh_end() */

  struct rpki_tr_sock *tr_sock;		/* Transport specific socket */
  enum rpki_cache_state state;		/* RPKI_CS_* */
  u32 session_id;
  u8 request_session_id;		/* 1 => have to request new session id; 0 => we have already session id */
  u32 serial_number;
  uint version;				/* Protocol version */
  bird_clock_t last_update;		/* Last successful synchronization with cache server */

  /* Intervals can be changed by remote cache server on the fly */
  uint refresh_interval;
  uint expire_interval;
  uint retry_interval;
  timer *retry_timer;
  timer *refresh_timer;
  timer *expire_timer;
};

/*
 * Rest of RPKI
 */

struct rpki_config {
  struct proto_config c;
  const char *hostname;			/* Full domain name of remote cache server */
  ip_addr ip;				/* IP address of cache server or IPA_NONE */
  u16 port;				/* Port of cache server */
  uint refresh_interval;		/* Time interval (in seconds) for refreshing ROA from server */
  uint expire_interval;			/* Time interval (in seconds) */
  uint retry_interval;			/* Time interval (in seconds) for an unreachable server */
  struct rpki_config_ssh *ssh;		/* SSH configuration or NULL */
};

struct rpki_proto {
  struct proto p;
  struct rpki_cache *cache;
};

const char *rpki_get_cache_ident(struct rpki_cache *cache);

void rpki_check_config(struct rpki_config *cf);
const char *rpki_check_refresh_interval(uint seconds);
const char *rpki_check_retry_interval(uint seconds);
const char *rpki_check_expire_interval(uint seconds);

void rpki_schedule_next_refresh(struct rpki_cache *cache);
void rpki_schedule_next_retry(struct rpki_cache *cache);
void rpki_schedule_next_expire_check(struct rpki_cache *cache);

void rpki_cache_change_state(struct rpki_cache *cache, const enum rpki_cache_state new_state);

/*
 * Debug/log outputs
 */

#define RPKI_LOG(log_level, rpki, msg, args...) 			\
    do { 								\
      log(log_level "%s: " msg, (rpki)->p.name , ## args); 		\
    } while(0)

#if defined(LOCAL_DEBUG) || defined(GLOBAL_DEBUG)
#define CACHE_DBG(cache,msg,args...) 					\
    do { 								\
      RPKI_LOG(L_DEBUG, (cache)->p, "%s: %s: " msg, rpki_get_cache_ident(cache), __func__, ## args);	\
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
        RPKI_LOG(L_TRACE, (cache)->p, "%s: " msg, rpki_get_cache_ident(cache), ## args);	\
    } while(0)

#define RPKI_WARN(p, msg, args...) RPKI_LOG(L_WARN, p, msg, ## args);

#endif /* _BIRD_RPKI_H_ */
