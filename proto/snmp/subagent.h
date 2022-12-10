#ifndef _BIRD_SNMP_SUBAGENT_H_
#define _BIRD_SNMP_SUBAGENT_H_

#include "nest/bird.h"
#include "snmp.h"

void snmp_start_subagent(struct snmp_proto *p);
void snmp_stop_subagent(struct snmp_proto *p);
void snmp_ping(struct snmp_proto *p);

#define AGENTX_VERSION              1

#define SNMP_STATE_START 0
#define SNMP_STATE_BGP 1
#define SNMP_STATE_INVALID 2

#define SNMP_MIB_2        1           /* last of oid .1.3.6.1.2.1     */
#define SNMP_OSPF_MIB    14	      /* part of oid .1.3.6.1.2.1.14  */
#define SNMP_BGP4_MIB    15	      /* part of oid .1.3.6.1.2.1.15  */
#define SNMP_OSPFv3_MIB 192	      /* part of oid .1.3.6.1.2.1.192 */

enum SNMP_CLASSES {
  SNMP_CLASS_INVALID = 0,
  SNMP_CLASS_BGP = 1,
  SNMP_CLASS_OSPF,
  SNMP_CLASS_END,
};

#define BGP4_VERSIONS 0x10

enum agentx_type {
  AGENTX_INTEGER	    =   2,
  AGENTX_OCTET_STRING	    =   4,
  AGENTX_NULL		    =   5,
  AGENTX_OBJECT_ID	    =   6,
  AGENTX_IP_ADDRESS	    =  64,
  AGENTX_COUNTER_32	    =  65,
  AGENTX_GAUGE_32	    =  66,
  AGENTX_TIME_TICKS	    =  67,
  AGENTX_OPAQUE		    =  68,
  AGENTX_COUNTER_64	    =  70,
  AGENTX_NO_SUCH_OBJECT	    = 128,
  AGENTX_NO_SUCH_INSTANCE   = 129,
  AGENTX_END_OF_MIB_VIEW    = 130,
} PACKED;

#define AGENTX_ADMIN_STOP   1
#define AGENTX_ADMIN_START  2

#define AGENTX_PRIORITY		127
#define MAX_STR 0xFFFFFFFF

#define SNMP_NATIVE

#ifdef SNMP_NATIVE
#define STORE(v,c) (v) = (u32) (c)
#define STORE_16(v,c) (v) = (u16) (c)
#define STORE_PTR(v,c) *((u32 *) (v)) = (u32) (c)
#define SNMP_UPDATE(h,l) \
  STORE((h)->payload, l)

#else
#define STORE(v, c) put_u32(&v, c)
#define STORE_16(v,c) put_u32(&v, c)
#define STORE_PTR(v,c) put_u32(v, c)
#define SNMP_UPDATE(h,l) \
  STORE(h->payload, l)
#endif

/* storing byte (u8) is always the same */
#define SNMP_HEADER_(h, v, t, f)  \
  put_u8(&h->version, v);	  \
  put_u8(&h->type, t);		  \
  put_u8(&h->flags, f);		  \
  put_u8(&h->pad, 0);

#ifdef SNMP_NATIVE
#define SNMP_HEADER(h,t,f)    SNMP_HEADER_(h, AGENTX_VERSION, t, f)
#else
#define SNMP_HEADER(h,t,f) \
  SNMP_HEADER_(h, AGENTX_VERSION, t, f | SNMP_NETWORK_BYTE_ORDER)
#endif

#define SNMP_B_HEADER(h, t) SNMP_HEADER(h, t, AGENTX_FLAG_BLANK)

#define SNMP_SESSION(h, p)			\
  STORE(h->session_id, p->session_id);		\
  STORE(h->transaction_id, p->transaction_id);	\
  p->transaction_id++;				\
  STORE(h->packet_id, p->packet_id);

#define SNMP_CREATE(b, t, n)  \
  n = (void *) (b);	      \
  memset(n, 0, sizeof(t));    \
  (b) += sizeof(t);

#define LOAD(v, bo) ((bo) ? get_u32(&v) : (u32) (v))
#define LOAD_16(v, bo) ((bo) ? get_u16(&v) : (u16) (v))
#define LOAD_PTR(v, bo) ((bo) ? get_u32(v) : (u32) *(v))

#define LOAD_STR(p, b, s, l, bo)    \
  l = LOAD(*((u32 *) b), bo);	    \
  log(L_INFO "LOAD_STR(), %p %u", p->p.pool, l + 1); \
  s = mb_allocz(p->p.pool, l + 1);  \
  memcpy(s, b, l);		    \
  b += snmp_str_size(s);

#define SNMP_LOAD_CONTEXT(p, h, b, s, l)      \
  if (h->flags & AGENTX_NON_DEFAULT_CONTEXT)  \
    { log(L_INFO "encountered non-default context"); \
    LOAD_STR(p, b, s, l, h->flags & AGENTX_NETWORK_BYTE_ORDER); }

#define SNMP_COPY_OID(b, o) \
  memcpy(b, o, snmp_oid_size(o));   \
  b += snmp_oid_size(o);

#define SNMP_COPY_VB(b, s, e)	\
  memcpy(b, s, 4);		\
  b += 4;			\
  SNMP_COPY_OID(b, &s->name)	\
  SNMP_COPY_OID(b, e)

#define BGP_DATA_(varbind, type_, packet, offset) \
  (varbind)->type = type_;		  \
  packet += offset;

#define BGP_DATA(varbind, type_, packet) BGP_DATA_(varbind, type_, packet, 4)

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

struct oid {
  u8 n_subid;
  u8 prefix;
  u8 include;
  u8 pad;
  u32 ids[];
};

struct agentx_varbind {
  u16 type;
  u16 pad;
  /* oid part */
  struct oid name;
};

/* this does not work */
struct agentx_search_range {
  struct oid start;
  struct oid end;
};

struct agentx_getbulk {
  u16 non_repeaters;
  u16 max_repetitions;
};

struct agentx_response {
  struct agentx_header h;
  u32 uptime;
  u16 err;
  u16 index;
};

struct agentx_close_pdu {
  struct agentx_header h;
  u8 reason;
};

struct agentx_un_register_pdu {
  struct agentx_header h;
  u8 timeout;
  u8 priority;
  u8 range_subid;
  u8 padd;
};

struct agentx_bulk_state {
  struct agentx_getbulk getbulk;
  u16 index;
  u16 repetition;
  byte* packet;
  u16 failed;
};

struct snmp_error {
  struct oid *oid;
  uint type;
};

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
  AGENTX_FLAG_BLANK		    = 0x00,
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
  AGENTX_RES_NO_ERROR		    =   0,
  /* TEST_SET_PDU response errors */
  AGENTX_RES_GEN_ERROR		    =   5,
  AGENTX_RES_NO_ACCESS		    =   6,
  AGENTX_RES_WRONG_TYPE		    =   7,
  AGENTX_RES_WRONG_LENGTH	    =   8,
  AGENTX_RES_WRONG_ENCODING	    =   9,
  AGENTX_RES_WRONG_VALUE	    =  10,
  AGENTX_RES_NO_CREATION	    =  11,
  AGENTX_RES_INCONSISTENT_VALUE	    =  12,
  AGENTX_RES_RESOURCE_UNAVAILABLE   =  13,
  AGENTX_RES_NOT_WRITEABLE	    =  17,
  AGENTX_RES_INCONSISTENT_NAME	    =  18,
  /* end of TEST_SET_PDU resonse errs */
  AGENTX_RES_OPEN_FAILED	    = 256,
  AGENTX_RES_NOT_OPEN		    = 257,
  AGENTX_RES_INDEX_WRONG_TYPE	    = 258,
  AGENTX_RES_INDEX_ALREADY_ALLOC    = 259,
  AGENTX_RES_INDEX_NONE_AVAIL	    = 260,
  AGENTX_RES_NOT_ALLOCATED	    = 261,
  AGENTX_RES_UNSUPPORTED_CONTEXT    = 262,
  AGENTX_RES_DUPLICATE_REGISTR	    = 263,
  AGENTX_RES_UNKNOWN_REGISTR	    = 264,
  AGENTX_RES_UNKNOWN_AGENT_CAPS	    = 265,
  AGENTX_RES_PARSE_ERROR	    = 266,
  AGENTX_RES_REQUEST_DENIED	    = 267,
  AGENTX_RES_PROCESSING_ERR	    = 268,
} PACKED;

int snmp_rx(sock *sk, uint size);

// debug wrapper
#define snmp_log(...) log(L_INFO "snmp " __VA_ARGS__)

#endif
