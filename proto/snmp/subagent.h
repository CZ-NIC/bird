#ifndef _BIRD_SNMP_SUBAGENT_H_
#define _BIRD_SNMP_SUBAGENT_H_

#include "nest/bird.h"
#include "snmp.h"

void snmp_start_subagent(struct snmp_proto *p);
void snmp_stop_subagent(struct snmp_proto *p);

#define AGENTX_INTEGER		  2
#define AGENTX_OCTET_STRING	  4
#define AGENTX_NULL		  5
#define AGENTX_OBJECT_ID	  6
#define AGENTX_IP_ADDRESS	 64
#define AGENTX_COUNTER_32	 65
#define AGENTX_GAUGE_32		 66
#define AGENTX_TIME_TICKS	 67
#define AGENTX_OPAQUE		 68
#define AGENTX_COUNTER_64	 70
#define AGENTX_NO_SUCH_OBJECT	128
#define AGENTX_NO_SUCH_INSTANCE 129
#define AGENTX_END_OF_MIB_VIEW	130

#define AGENTX_PRIORITY		127
#define MAX_STR 0xFFFFFFFF

#define PASTE_HEADER_(buf, v, t, f, s)		      \
  memset(buf, 0, sizeof(struct agentx_header));	      \
  struct agentx_header *h = (void *) buf;	      \
  log(L_INFO "value : %d", (void *) h == buf? 1:0);   \
  h->version = v;				      \
  h->type = t;	    				      \
  h->flags = f;		  			      \
  h->pad = 0;			  		      \
  ADVANCE(buf, s, sizeof(struct agentx_header));      \

#define PASTE_HEADER(buf, t, f, s)	PASTE_HEADER_(buf, AGENTX_VERSION, t, f, s)
#define U32_CPY(w, u) memcpy((w), (u), 4); ADVANCE((w), 4, 4);

struct agentx_header {
  u8 version;
  u8 type;
  u8 flags;
  u8 pad;
  u32 session_id;
  u32 transaction_id;
  u32 packet_id;
  u32 payload;   /* length of the packet without header */
};

#define AGENTX_HEADER_SIZE sizeof(struct agentx_header)

struct subid{
  u32 len;
  u32 ids[];
};

struct oid {
  u8 n_subid;
  u8 prefix;
  u8 include;
  u8 pad;
  struct subid subid;
};

struct agentx_varbind {
  u16 type;
  u16 pad;
  /* oid part */
  struct oid name;
};

struct agentx_search_range {
  struct oid start;
  struct oid end;
};

struct agentx_response {
  struct agentx_header h;
  u32 uptime;
  u16 err;
  u16 index;
};

#define AGENTX_VERSION		      1

enum agentx_pdu {
  AGENTX_OPEN_PDU		=  1,
  AGENTX_CLOSE_PDU		=  2,
  AGENTX_REGISTER_PDU		=  3,
  AGENTX_UNREGISTER_PDU		=  4,
  AGENTX_GET_PDU		=  5,
  AGENTX_GET_NEXT_PDU		=  6,
  AGENTX_GET_BULK_PDU		=  7,
  AGENTX_TEST_SET_PDU		=  8,
  AGENTX_COMMIT_SET_PDU		=  9,
  AGENTX_UNDO_SET_PDU		= 10,
  AGENTX_CLEANUP_SET_PDU	= 11,
  AGENTX_NOTIFY_PDU		= 12,
  AGENTX_PING_PDU		= 13,
  AGENTX_INDEX_ALLOCATE_PDU     = 14,
  AGENTX_INDEX_DEALLOCATE_PDU   = 15,
  AGENTX_ADD_AGENT_CAPS_PDU     = 16,
  AGENTX_REMOVE_AGENT_CAPS_PDU  = 17,
  AGENTX_RESPONSE_PDU		= 18,
} PACKED;

#define AGENTX_FLAGS_MASK          0x1F

enum agentx_flags {
  AGENTX_FLAG_INSTANCE_REGISTRATION = 0x01,
  AGENTX_FLAG_NEW_INDEX		    = 0x02,
  AGENTX_FLAG_ANY_INDEX		    = 0x04,
  AGENTX_NON_DEFAULT_CONTEXT	    = 0x08,
  AGENTX_NETWORK_BYTE_ORDER	    = 0x10,
} PACKED;

/* CLOSE_PDU close reasons */
enum agentx_close_reasons {
  AGENTX_CLOSE_OTHER	      = 1,
  AGENTX_CLOSE_PARSE_ERROR    = 2,
  AGENTX_CLOSE_PROTOCOL_ERROR = 3,
  AGENTX_CLOSE_TIMEOUTS	      = 4,
  AGENTX_CLOSE_SHUTDOWN	      = 5,
  AGENTX_CLOSE_BY_MANAGER     = 6,
} PACKED;


/* RESPONSE_PDU - result error */
enum agentx_response_err {
  AGENTX_RES_NO_ERROR	  	  =   0,
  AGENTX_RES_OPEN_FAILED	  = 256,
  AGENTX_RES_NOT_OPEN		  = 257,
  AGENTX_RES_INDEX_WRONG_TYPE	  = 258,
  AGENTX_RES_INDEX_ALREADY_ALLOC  = 259,
  AGENTX_RES_INDEX_NONE_AVAIL	  = 260,
  AGENTX_RES_NOT_ALLOCATED	  = 261,
  AGENTX_RES_UNSUPPORTED_CONTEXT  = 262,
  AGENTX_RES_DUPLICATE_REGISTR	  = 263,
  AGENTX_RES_UNKNOWN_REGISTR	  = 264,
  AGENTX_RES_UNKNOWN_AGENT_CAPS	  = 265,
  AGENTX_RES_PARSE_ERROR	  = 266,
  AGENTX_RES_REQUEST_DENIED	  = 267,
  AGENTX_RES_PROCESSING_ERR	  = 268,
} PACKED;

int snmp_rx(sock *sk, uint size);
#endif
