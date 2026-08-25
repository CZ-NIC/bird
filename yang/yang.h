/*
 *	BIRD -- YANG-CBOR / CORECONF ap/
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
#include "lib/cbor.h"
#include "lib/coap.h"
#include "nest/locks.h"

/* YANG Model Selection */
enum yang_model {
  YANG_MODEL_CLI = 1,		/* Use BIRD CLI 1:1 model */
  YANG_MODEL__MAX,
};

enum coreconf_state {
   CC_COAP_HEADER,
   CC_CHECK_HEADER,
   CC_YL_SEND,
   CC_CREATE_SUBSCRIPTION,
   CC_OP,
   CC_RPC_ACTION,
   CC_DONE,
   CC_ERROR,
};

extern const char *coreconf_state_names[];
enum resource_type {
   UNKNOWN_RESOURCE = 0,
   CORECONF_DATASTORE = 1,
   CORECONF_YANG_LIB,
   CORECONF_EVENT_STREAM,
   CORECONF_RPC_ACTION,
   CORECONF_DATA_NODE, // used only in /.well-known/core
   CORE_WELL_KNOWN,
};

/* YANG session runtime structure */
struct yang_session {
  struct yang_socket *socket;
  struct birdsock *sock;
  struct coap_session coap;
  struct cbor_parser_context *cbor;
  struct cbor_writer cbor_writer;
  struct coap_tx_opt_fixed {
    u32 len;
    enum coap_option_id type;
    char buf[2048];
  } cbor_b;
  //char *write_buffer;
  //uint write_buff_len;
  bool error_sent;
  const struct yang_url_node **url;
  bool (*endpoint)(struct yang_session *);
  uint url_pos;
  u64 sid_stack[16];
  u16 accept;
  u16 cont_format; /* CoAP Content-Format option. */
  int sid_pos;
  enum yang_parser_state {
    YANG_PS_VALUE = 0,
    YANG_PS_RELATIVE_SID = 1,
    YANG_PS_ABSOLUTE_SID = 2,
  } sid_state;
  enum coreconf_state coreconf_state;
  enum resource_type resource_type;
  enum resource_type core_query; // used as storage for ? queries on /.well-known/core
  bool core_report_all; // we report full /.well-known/core for unknown queries
  linpool *parse_stack;
  linpool *gen_stack;

  struct uytc_rpc_data *rpc;
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

/* YANG API URL Tree */

struct yang_url_node {
  bool (*endpoint)(struct yang_session *);
  const char *stem;
  const enum resource_type resource_type;
  const struct yang_url_node *children[];
};

extern const struct yang_url_node *yang_url_tree[YANG_MODEL__MAX];

/* YANG API routines */

struct config;
void yang_commit(struct config *, struct config *);
void yang_init(void);

enum yang_proc_state yang_common_coap_endpoint(struct yang_session *se);

/* pre-UYTC gen junk */
enum uytc_rpc_state {
  RPC_BEGIN,
  RPC_ID,
  RPC_BODY,
  RPC_PARSING,
  RPC_PROC,
  RPC_GEN,
  RPC_DONE,
};

struct coreconf_error {
  u64 error_tag_sid;
  u64 error_app_tag_sid;
  void *data_node;
  const char *msg;
};

struct uytc_rpc_data {
  enum uytc_rpc_state state;
  void *in_data;
  void *out_data;
  enum yang_proc_state (*in_fn)(struct yang_session *se, void **in_data);
  bool (*rpc)(void *in_data, void **out_data); // return false on error
  enum yang_proc_state (*out_fn)(struct yang_session *se, void *out_data);
};

enum show_status_state {
  STATUS_BEGIN,
  STATUS_WRITER_READY,
  STATUS_MAP,
  STATUS_SID,
  STATUS_MAP2,
  STATUS_SID2,
  STATUS_CLOSE,
  STATUS_CLOSE2,
  STATUS_DONE,
};

struct rpc_show_status {
  enum show_status_state state;
};

struct rpc_show_status_out {
  struct rpc_show_status status;
  char *curr;
  char data[2048];
};

extern pool *yang_pool;

#endif /* _BIRD_YANG_API_H_ */
