/*
 *	BIRD -- YANG-CBOR / CORECONF api
 *
 *	(c) 2026       Maria Matejka <mq@jmq.cz>
 *	(c) 2026       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_YANG_API_H_
#define _BIRD_YANG_API_H_

#include "lib/birdlib.h"
#include "lib/tlists.h"
#include "lib/ip.h"
#include "lib/coap.h"
#include "nest/locks.h"

/* YANG Model Selection */
enum yang_model {
  YANG_MODEL_CLI = 1,		/* Use BIRD CLI 1:1 model */
};

/* YANG session runtime structure */
struct yang_session {
  struct yang_socket *socket;
  struct birdsock *sock;
  union {
    struct coap_session coap;
  };
  bool error_sent;
};

/* YANG socket parameters */
struct yang_socket_params {
  enum yang_socket_kind {
    YANG_SOCKET_COAP_TCP = 1,	/* Regular CoAP over TCP */
    YANG_SOCKET_COAP_UDP = 2,	/* Regular CoAP over UDP */
  } kind;
  u16 port;			/* TCP/UDP port */
  ip_addr local_ip;		/* Local IP to listen */
};

bool yang_socket_same(const struct yang_socket_params *a, const struct yang_socket_params *b);

/* YANG socket configuration */
#define TLIST_PREFIX yang_socket_config
#define TLIST_TYPE struct yang_socket_config
#define TLIST_ITEM n
#define TLIST_WANT_ADD_TAIL
#define TLIST_WANT_WALK

struct yang_socket_config {
  TLIST_DEFAULT_NODE;
  struct yang_socket *socket;
  struct yang_socket_params params;
};

#include "lib/tlists.h"

/* YANG socket runtime structure */
#define TLIST_PREFIX yang_socket
#define TLIST_TYPE struct yang_socket
#define TLIST_ITEM n
#define TLIST_WANT_ADD_TAIL
#define TLIST_WANT_WALK

struct yang_socket {
  TLIST_DEFAULT_NODE;
  struct yang_socket_config *config;
  struct yang_socket_params params;
  struct object_lock *olock;
  struct birdsock *sock;			/* Listening socket */
};

#include "lib/tlists.h"


/* YANG API parameters */
struct yang_api_params {
  enum yang_model model;
  bool restricted;
};

/* YANG API configuration */
#define TLIST_PREFIX yang_api_config
#define TLIST_TYPE struct yang_api_config
#define TLIST_ITEM n
#define TLIST_WANT_ADD_TAIL
#define TLIST_WANT_WALK

struct yang_api_config {
  TLIST_DEFAULT_NODE;
  const char *name;
  struct yang_api *api;
  struct config *global;
  struct yang_api_params params;
  TLIST_LIST(yang_socket_config) listen;	/* All sockets pointed to this API */
};

#include "lib/tlists.h"

/* YANG API runtime structure */
#define TLIST_PREFIX yang_api
#define TLIST_TYPE struct yang_api
#define TLIST_ITEM n
#define TLIST_WANT_ADD_TAIL
#define TLIST_WANT_WALK

struct yang_api {
  TLIST_DEFAULT_NODE;
  const char *name;
  pool *pool;
  struct yang_api_config *config;
  struct yang_api_params params;
  TLIST_LIST(yang_socket) listen;
};

#include "lib/tlists.h"

/* YANG API routines */

struct config;
void yang_commit(struct config *, struct config *);
void yang_init(void);

#endif /* _BIRD_YANG_API_H_ */
