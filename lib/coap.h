/*
 *	BIRD -- Minimalist CoAP Module for CoAP over reliable connections 
 *
 *	(c) 2026 CZ.NIC
 *	(c) 2026 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _LIB_COAP_H_
#define _LIB_COAP_H_

#include "lib/birdlib.h"
#include "lib/tlists.h"
#include "lib/resource.h"

/*
 * RFC-specified constants
 */

/* Underlay transport */
enum coap_transport_type {
  COAP_TRANSPORT_UDP = 1,	/* RFC 7252 */
  COAP_TRANSPORT_TCP = 2,	/* RFC 8323 */
  COAP_TRANSPORT_WEBSOCKET = 3,	/* RFC 8323 */
} PACKED;

/* RFC 7252: Message types for CoAP over UDP */
enum coap_udp_msg_type {
  COAP_TYPE_CONFIRMABLE = 0,
  COAP_TYPE_NONCONFIRMABLE = 1,
  COAP_TYPE_ACK = 2,
  COAP_TYPE_RESET = 3,
} PACKED;

/* Message class; 3 bits */
enum coap_msg_class {
  COAP_CLS_REQUEST		= 0,		/* RFC 7252 */
  COAP_CLS_RESPONSE		= 2 << 5,	/* RFC 7252 */
  COAP_CLS_CLIENT_ERROR		= 4 << 5,	/* RFC 7252 */
  COAP_CLS_SERVER_ERROR		= 5 << 5,	/* RFC 7252 */
  COAP_CLS_STREAM_CONTROL	= 7 << 5,	/* RFC 8323 */
  COAP_CLS__MASK		= 7 << 5,	/* Bitmask to extract just the class */
} PACKED;

/* Full message code for COAP_CLS_REQUEST */
enum coap_msg_code {
  COAP_REQ_EMPTY			= COAP_CLS_REQUEST | 0,		/* RFC 7252 */
  COAP_REQ_GET				= COAP_CLS_REQUEST | 1,		/* RFC 7252 */
  COAP_REQ_POST				= COAP_CLS_REQUEST | 2,		/* RFC 7252 */
  COAP_REQ_PUT				= COAP_CLS_REQUEST | 3,		/* RFC 7252 */
  COAP_REQ_DELETE			= COAP_CLS_REQUEST | 4,		/* RFC 7252 */

  COAP_RESP_CREATED			= COAP_CLS_RESPONSE | 1,	/* RFC 7252 */
  COAP_RESP_DELETED			= COAP_CLS_RESPONSE | 2,	/* RFC 7252 */
  COAP_RESP_VALID			= COAP_CLS_RESPONSE | 3,	/* RFC 7252 */
  COAP_RESP_CHANGED			= COAP_CLS_RESPONSE | 4,	/* RFC 7252 */
  COAP_RESP_CONTENT			= COAP_CLS_RESPONSE | 5,	/* RFC 7252 */

  COAP_CERR_BAD_REQUEST			= COAP_CLS_CLIENT_ERROR | 0,	/* RFC 7252 */
  COAP_CERR_UNAUTHORIZED		= COAP_CLS_CLIENT_ERROR | 1,	/* RFC 7252 */
  COAP_CERR_BAD_OPTION			= COAP_CLS_CLIENT_ERROR | 2,	/* RFC 7252 */
  COAP_CERR_FORBIDDEN			= COAP_CLS_CLIENT_ERROR | 3,	/* RFC 7252 */
  COAP_CERR_NOT_FOUND			= COAP_CLS_CLIENT_ERROR | 4,	/* RFC 7252 */
  COAP_CERR_METHOD_NOT_ALLOWED		= COAP_CLS_CLIENT_ERROR | 5,	/* RFC 7252 */
  COAP_CERR_NOT_ACCEPTABLE		= COAP_CLS_CLIENT_ERROR | 6,	/* RFC 7252 */
  COAP_CERR_PRECONDITION_FAILED		= COAP_CLS_CLIENT_ERROR | 12,	/* RFC 7252 */
  COAP_CERR_REQUEST_ENTITY_TOO_LARGE	= COAP_CLS_CLIENT_ERROR | 13,	/* RFC 7252 */
  COAP_CERR_UNSUPPORTED_CONTENT_FORMAT	= COAP_CLS_CLIENT_ERROR | 15,	/* RFC 7252 */
  COAP_CERR_IMA_TEAPOT			= COAP_CLS_CLIENT_ERROR | 18,	/* RFC 2324 per analogiam */

  COAP_SERR_INTERNAL_SERVER_ERROR	= COAP_CLS_SERVER_ERROR | 0,	/* RFC 7252 */
  COAP_SERR_NOT_IMPLEMENTED		= COAP_CLS_SERVER_ERROR | 1,	/* RFC 7252 */
  COAP_SERR_BAD_GATEWAY			= COAP_CLS_SERVER_ERROR | 2,	/* RFC 7252 */
  COAP_SERR_SERVICE_UNAVAILABLE		= COAP_CLS_SERVER_ERROR | 3,	/* RFC 7252 */
  COAP_SERR_GATEWAY_TIMEOUT		= COAP_CLS_SERVER_ERROR | 4,	/* RFC 7252 */
  COAP_SERR_PROXYING_NOT_SUPPORTED	= COAP_CLS_SERVER_ERROR | 5,	/* RFC 7252 */

  COAP_SCO_CSM				= COAP_CLS_STREAM_CONTROL | 1,	/* RFC 8323 */
  COAP_SCO_PING				= COAP_CLS_STREAM_CONTROL | 2,	/* RFC 8323 */
  COAP_SCO_PONG				= COAP_CLS_STREAM_CONTROL | 3,	/* RFC 8323 */
  COAP_SCO_RELEASE			= COAP_CLS_STREAM_CONTROL | 4,	/* RFC 8323 */
  COAP_SCO_ABORT			= COAP_CLS_STREAM_CONTROL | 5,	/* RFC 8323 */
} PACKED;

enum coap_option_flags {
  COAP_OPT_F_CRITICAL			= 1,
  COAP_OPT_F_UNSAFE_TO_FWD		= 2,
  COAP_OPT_F_NOCACHEKEY			= 28,
};

enum coap_option_id {
					/* +---+---+---+---+--------+--------+ */
					/* | C | U | N | R | Format | Length | */
					/* +---+---+---+---+--------+--------+ */
  COAP_OPT_IF_MATCH		= 1,	/* | x |   |   | x | opaque | 0-8    | */
  COAP_OPT_URI_HOST		= 3,	/* | x | x | - |   | string | 1-255  | */
  COAP_OPT_ETAG			= 4,	/* |   |   |   | x | opaque | 1-8    | */
  COAP_OPT_IF_NONE_MATCH	= 5,	/* | x |   |   |   | empty  | 0      | */
  COAP_OPT_URI_PORT		= 7,	/* | x | x | - |   | uint   | 0-2    | */
  COAP_OPT_LOCATION_PATH	= 8,	/* |   |   |   | x | string | 0-255  | */
  COAP_OPT_URI_PATH		= 11,	/* | x | x | - | x | string | 0-255  | */
  COAP_OPT_CONTENT_FORMAT	= 12,	/* |   |   |   |   | uint   | 0-2    | */
  COAP_OPT_MAX_AGE		= 14,	/* |   | x | - |   | uint   | 0-4    | */
  COAP_OPT_URI_QUERY		= 15,	/* | x | x | - | x | string | 0-255  | */
  COAP_OPT_ACCEPT		= 17,	/* | x |   |   |   | uint   | 0-2    | */
  COAP_OPT_LOCATION_QUERY	= 20,	/* |   |   |   | x | string | 0-255  | */
  COAP_OPT_PROXY_URI		= 35,	/* | x | x | - |   | string | 1-1034 | */
  COAP_OPT_PROXY_SCHEME		= 39,	/* | x | x | - |   | string | 1-255  | */
  COAP_OPT_SIZE1		= 60,	/* |   |   | x |   | uint   | 0-4    | */
					/* +---+---+---+---+--------+--------+ */

  COAP_OPT_MAX_MSG_SIZE		= 2,	/* RFC 8323, COAP_SCO_CSM */
  COAP_OPT_BLOCKWISE		= 4,	/* RFC 8323, COAP_SCO_CSM */
  COAP_OPT_CUSTODY		= 2,	/* RFC 8323, COAP_SCO_PING + COAP_SCO_PONG */
  COAP_OPT_ALTERNATIVE_ADDR	= 2,	/* RFC 8323, COAP_SCO_RELEASE */
  COAP_OPT_HOLDOFF		= 4,	/* RFC 8323, COAP_SCO_RELEASE */
  COAP_OPT_BAD_CSM		= 2,	/* RFC 8323, COAP_SCO_ABORT */
} PACKED;

enum coap_parse_state {
  COAP_PS_EMPTY = 0,			/* Nothing parsed */
  COAP_PS_HEADER,			/* Header parsed */
  COAP_PS_OPTION_PARTIAL,		/* Part of an option is available */
  COAP_PS_OPTION_COMPLETE,		/* Option is complete */
  COAP_PS_PAYLOAD_PARTIAL,		/* Part of the payload is available */
  COAP_PS_PAYLOAD_COMPLETE,		/* Payload is complete */

  COAP_PSM_NONE = 0x40,			/* More data needed (generic) */
  COAP_PSM_CODE,			/* Missing code byte */
  COAP_PSM_ELEN,			/* Missing extended length bytes */
  COAP_PSM_TOKEN,			/* Missing token bytes */
  COAP_PSM_OPTION_NONE,			/* Missing option bytes (generic) */
  COAP_PSM_OPTION_DL,			/* Missing option DL byte */
  COAP_PSM_OPTION_PRE_LEN,		/* Option delta loaded, length needed */
  COAP_PSM_OPTION_DELTA,		/* Expected more option delta bytes */
  COAP_PSM_OPTION_LEN,			/* Expected more option length bytes */
  COAP_PS__MORE_MAX,

#define COAP_PS_MORE COAP_PSM_NONE ... COAP_PS__MORE_MAX 

  COAP_PSE_NONE = 0x80,			/* Error (generic) */
  COAP_PSE_TRUNCATED,			/* Message too short */
  COAP_PSE_INVALID_VERSION,		/* Unsupported CoAP version */
  COAP_PSE_INVALID_TOKLEN,		/* Token too long: check token_len */
  COAP_PSE_UNKNOWN_CLASS,		/* Message class not supported */
  COAP_PSE_FAKE_PAYLOAD_MARKER,		/* Payload marker anticipation failed */
  COAP_PSE_RESERVED_OPTION_LEN,		/* Reserved option length */
  COAP_PSE_NEED_RESET,			/* Parser needs a reset */

  COAP_PS__ERROR_MAX,
#define COAP_PS_ERROR COAP_PSE_NONE ... COAP_PS__ERROR_MAX
} PACKED;

/* CoAP low-level parser context */
struct coap_parse_context {
  enum coap_parse_state state;	/* Parser state machine state */

  enum coap_udp_msg_type type;	/* Type of the UDP message being parsed. UDP only. */
  u16 msg_id;			/* UDP Message ID. */
  u8 version;			/* CoAP version. Must be 1 by RFC 7252. UDP only. */

  enum coap_msg_class class;	/* Message class from the code byte */
  enum coap_msg_code code;	/* Full message code */

  u8 token_len;			/* Token actual byte length (may be zero) */
  u8 token_len_missing;		/* How many bytes we still need to load */
  u8 token[8];			/* Token value, opaque bytes */

  u8 option_dlbyte;		/* The DL byte of the option currently being loaded */

  u32 load_len;			/* Byte length of a value being loaded */
  u32 load_len_missing;		/* How many bytes we still need */

  u64 common_len;		/* Message length minus transport-specific header length, minus already parsed options */

  u32 option_delta;		/* Loaded option delta */
  u32 option_type;		/* Current option type */
  u32 option_len;		/* Current option value length */

  u32 option_chunk_offset;	/* How far is the option chunk */
  u32 option_chunk_len;		/* How long is the option chunk */
  const char *option_value;	/* Current option value chunk */

  u64 payload_chunk_offset;	/* How far is the chunk */
  u64 payload_chunk_len;	/* How long is the chunk */
  u64 payload_total_len;	/* Total chunk length; ~0 if unknown */
  const char *payload;		/* Payload chunk data */

  uint data_len;		/* Received data length */
  uint data_ptr;		/* Where we are in the received data */
  const char *data;		/* Received data to be parsed */
  s64 data_option_offset;	/* Relative to current data, where is the start of the options? */
};

#if 0
/* CoAP Endpoint identification */
struct coap_endpoint_ident {
  ip_addr remote;		/* UDP, TCP */
  u16 port;			/* UDP, TCP */
};

/* Messages recently received */
struct coap_seen_msg {
  u16 msg_id;
  enum coap_msg_type type;
  u8 code;
  btime expires;
};
#endif

/* CoAP session and endpoint parameters */
struct coap_params {
  btime ack_timeout;		/* RFC 7252, Sec. 4.2: How long to wait for ACK */
  u64 ack_random_factor;	/* RFC 7252, Sec. 4.2: Randomizer factor (* 2<<16) for ack_timeout */
  btime default_leisure;	/* RFC 7252, Sec. 8.2: Default wait time limit for multicast responses */
  uint max_retransmit;		/* RFC 7252, Sec. 4.2: Maximum number of retransmissions of confirmable msgs */
  uint nstart;			/* RFC 7252, Sec. 4.7: Limit on outstanding messages */
  uint probing_bps;		/* RFC 7252, Sec. 4.7: ??! */
  uint max_endpoints;		/* Implementation: Maximum number of remote endpoints served at once */
};

/* Frame preparation block */
struct coap_tx_frame {
  u8 code;				/* Option code to be sent */

  enum coap_udp_msg_type type;		/* Type of the UDP message being sent. UDP only. */
  u16 msg_id;				/* UDP Message ID. */
  u8 version;				/* CoAP version. Must be 1 by RFC 7252. UDP only. */

  u8 toklen;				/* Token length to be sent */
  char token[8];			/* The token */

  uint optcnt;				/* Option count */
  struct coap_tx_option *opt[];		/* Options, zero-type for payload */
};

/* Option preparation block */
struct coap_tx_option {
  u32 len;				/* Option length */
  enum coap_option_id type;		/* Option type */
  char data[];				/* The data */
};

#define COAP_TX_OPTION_GENERIC(_type, _len) ({ \
    struct coap_tx_option *_opt = alloca(_len + sizeof *_opt); \
    _opt->len = _len; \
    _opt->type = _type; \
    _opt; })

#define COAP_TX_OPTION_INT(_type, _value) ({ \
    typeof(_value) _val = _value; \
    struct coap_tx_option *_opt = COAP_TX_OPTION_GENERIC(_type, sizeof _val); \
    _Generic((_val), u8: put_u8, u16: put_u16, u32: put_u32)(_opt->data, _val); \
    _opt; })

#define COAP_TX_OPTION_VPRINTF(_type, _fmt, _vargs) ({ \
    char _buf[1024]; int _len = bvsnprintf(_buf, sizeof _buf, _fmt, _vargs); \
    if (_len < 0) log(L_ERR "Too long string at %s:%d", __FILE__, __LINE__); \
    struct coap_tx_option *_opt = COAP_TX_OPTION_GENERIC(_type, _len); \
    memcpy(_opt->data, _buf, _len); \
    _opt; })

#define COAP_TX_FRAME(_code, ...) ({ \
    struct { struct coap_tx_frame f; struct coap_tx_option *opt[MACRO_COUNT(__VA_ARGS__)]; } _frm = { \
    .f.code = _code, .f.optcnt = ARRAY_SIZE(_frm.opt), .opt = { __VA_ARGS__ }}; &_frm.f; })

#define TLIST_PREFIX coap_tx
#define TLIST_TYPE struct coap_tx
#define TLIST_ITEM n
#define TLIST_WANT_ADD_TAIL
#define TLIST_WANT_WALK
struct coap_tx {
  TLIST_DEFAULT_NODE;
  buffer buf;
};

#include "lib/tlists.h"

/* One CoAP session */
struct coap_session {
  enum coap_transport_type transport;	/* Transport type */
  bool blockwise_rx;			/* Blockwise transfers allowed */
  u32 max_msg_size;			/* Maximum message size */
  u32 max_msg_size_rx;			/* Received maximum message size info */

  struct coap_parse_context parser;	/* Frame parser */

  TLIST_LIST(coap_tx) tx_queue;		/* Send queue */
  struct coap_tx *tx_pending;		/* TX block in progress */

  bool flush_and_close;			/* Closing, do not accept more data to send */

  pool *tx_pool;			/* Pool to allocate TX frames from */
  struct birdsock *sock;		/* Socket to act on */
};

/* Receiving data from UDP */
void coap_udp_rx(struct coap_session *s, const char *data, uint len);
enum coap_parse_state coap_udp_parse(struct coap_session *s);

/* Receiving data from TCP */
void coap_tcp_rx(struct coap_session *s, const char *data, uint len);
enum coap_parse_state coap_tcp_parse(struct coap_session *s);

/* Common RX processing */
bool coap_process(struct coap_session *s);

/* Send a completely prepared frame */
void coap_tx_send(struct coap_session *s, const struct coap_tx_frame *f);
void coap_tx_send_simple(struct coap_session *s, enum coap_msg_code, ...);

/* Prepare the header and a payload buffer, and commit */
void coap_tx_header(struct coap_session *s, const struct coap_tx_frame *f, TLIST_LIST(coap_tx) *queue);
struct coap_tx *coap_tx_extend(struct coap_session *s, TLIST_LIST(coap_tx) *queue);
void coap_tx_commit(struct coap_session *s, TLIST_LIST(coap_tx) *queue);

/* Generic errors */
void coap_bad_request(struct coap_session *s, const char *fmt, ...);

/* Send-data sent */
void coap_tx_flush(struct coap_session *s, struct birdsock *sk);
void coap_tx_written(struct coap_session *s, struct birdsock *sk);

#endif /* _LIB_COAP_H_ */
