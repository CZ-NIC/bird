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

#define SNMP_ISO	  1	      /* last of oid .1		      */
#define SNMP_ORG	  3	      /* last of oid .1.3	      */
#define SNMP_DOD	  6	      /* last of oid .1.3.6	      */
#define SNMP_INTERNET	  1	      /* last of oid .1.3.6.1	      */

#define SNMP_MGMT	  2	      /* last of oid .1.3.6.1.2	      */
#define SNMP_MIB_2	  1	      /* last of oid .1.3.6.1.2.1     */
#define SNMP_OSPF_MIB	 14	      /* part of oid .1.3.6.1.2.1.14  */
#define SNMP_BGP4_MIB	 15	      /* part of oid .1.3.6.1.2.1.15  */
#define SNMP_OSPFv3_MIB	192	      /* part of oid .1.3.6.1.2.1.192 */

extern u32 snmp_internet[4];

#define SNMP_DEFAULT_CONTEXT 0

enum SNMP_CLASSES {
  SNMP_CLASS_INVALID = 0,
  SNMP_CLASS_BGP = 1,
  SNMP_CLASS_OSPF,
  SNMP_CLASS_END,
};

#define BGP4_VERSIONS ((char[]) { 0x10 })

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

enum snmp_search_res {
  SNMP_SEARCH_OK	  = 0,
  SNMP_SEARCH_NO_OBJECT	  = 1,
  SNMP_SEARCH_NO_INSTANCE = 2,
  SNMP_SEARCH_END_OF_VIEW = 3,
};

#define AGENTX_ADMIN_STOP   1
#define AGENTX_ADMIN_START  2

#define AGENTX_PRIORITY		127

#define SNMP_REGISTER_TREE 0
#define SNMP_REGISTER_INSTANCE 1

#define SNMP_NATIVE

#ifdef SNMP_NATIVE
#define STORE_U32(dest, val)  ((dest) = (u32) (val))
#define STORE_U16(dest, val)  ((dest) = (u16) (val))
#define STORE_U8(dest, val)   ((dest) = (u8) (val))
#define STORE_PTR(ptr, val)   (*((u32 *) (ptr)) = (u32) (val))
#else
#define STORE_U32(dest, val)  put_u32(&(dest), (val))
#define STORE_U16(dest, val)  put_u16(&(dest), (val))
#define STORE_U8(dest, val)   put_u8(&(dest), (val))
#define STORE_PTR(ptr, val)   put_u32(ptr, val)
#endif

/* storing byte (u8) is always the same */
#define SNMP_HEADER_(h, v, t, f)  \
  put_u8(&h->version, v);	  \
  put_u8(&h->type, t);		  \
  put_u8(&h->flags, f);		  \
  put_u8(&h->pad, 0);		  \
  STORE_U32(h->payload, 0)

#ifdef SNMP_NATIVE
#define SNMP_HEADER(h,t,f)    SNMP_HEADER_(h, AGENTX_VERSION, t, f)
#else
#define SNMP_HEADER(h,t,f) \
  SNMP_HEADER_(h, AGENTX_VERSION, t, f | SNMP_NETWORK_BYTE_ORDER)
#endif

#define SNMP_BLANK_HEADER(h, t) SNMP_HEADER(h, t, AGENTX_FLAG_BLANK)

#define SNMP_SESSION(h, p) 		  				      \
  STORE_U32(h->session_id, p->session_id);				      \
  STORE_U32(h->transaction_id, p->transaction_id);			      \
  STORE_U32(h->packet_id, p->packet_id)

#define LOAD_U32(v, bo) ((bo) ? get_u32(&v) : (u32) (v))
#define LOAD_U16(v, bo) ((bo) ? get_u16(&v) : (u16) (v))
#define LOAD_PTR(v, bo) ((bo) ? get_u32(v) : *((u32 *) v))

#define LOAD_STR(/* byte * */buf, str, length, byte_ord)  ({		      \
  length = LOAD_PTR(buf, byte_ord);					      \
  length > 0 ? (str = buf + 4) : (str = NULL); })

#define COPY_STR(proto, buf, str, length, byte_order) ({		      \
  length = LOAD_PTR(buf, byte_order);					      \
  log(L_INFO "LOAD_STR(), %p %u", proto->pool, length + 1);		      \
  str = mb_alloc(proto->pool, length + 1);				      \
  memcpy(str, buf+4, length);						      \
  str[length] = '\0'; /* set term. char */				      \
  buf += 4 + snmp_str_size_from_len(length); })

#define SNMP_LOAD_CONTEXT(hdr, buf, cont, cont_len) ({			      \
  if ((hdr)->flags & AGENTX_NON_DEFAULT_CONTEXT)			      \
    LOAD_STR((buf), (cont), (cont_len),					      \
      (hdr)->flags & AGENTX_NETWORK_BYTE_ORDER); })

#define SNMP_COPY_CONTEXT(proto, hdr, buf, cont, cont_len) ({		      \
  cont = NULL; cont_len = 0;						      \
  if (hdr->flags & AGENTX_NON_DEFAULT_CONTEXT)				      \
    COPY_STR(proto, buf, cont, cont_len,				      \
	(hdr)->flags & AGENTX_NETWORK_BYTE_ORDER) })

#define SNMP_HAS_CONTEXT(hdr)						      \
  hdr->flags |= AGENTX_NON_DEFAULT_CONTEXT

#define SNMP_NON_DEFAULT_CONTEXT(hdr,pdu,contid) ({			      \
  if (contid) {								      \
    SNMP_HAS_CONTEXT(hdr);						      \
    snmp_put_str((c).buffer, (sc)->context);				      \
    ADVANCE((c).buffer, (c).size, snmp_str_size((sc)->context));	      \
  } })

#define SNMP_PUT_OID(buf, size, oid, byte_ord)				      \
  ({									      \
    struct agentx_varbind *vb = (void *) buf;				      \
    SNMP_FILL_VARBIND(vb, oid, byte_ord);				      \
  })

#define SNMP_FILL_VARBIND(vb, oid, byte_ord)				      \
  snmp_oid_copy(&(vb)->name, (oid), (byte_ord)), snmp_oid_size((oid))

#define SNMP_VB_DATA(varbind)						      \
  (((void *)(varbind)) + snmp_varbind_header_size(varbind))

#define SNMP_PDU_CONTEXT(sk) {						      \
    .buffer = sk->tpos,							      \
    .size = sk->tbuf + sk->tbsize - sk->tpos,				      \
    .error = AGENTX_RES_NO_ERROR,					      \
    .context = 0,							      \
  }

struct agentx_header {
  u8 version;
  u8 type;
  u8 flags;
  u8 pad;
  u32 session_id;	/* AgentX sessionID established by Open-PDU */
  u32 transaction_id;	/* last transactionID seen/used */
  u32 packet_id;	/* last packetID seen/used */
  u32 payload;		/* payload_length of the packet without header */
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
  u16 error;
  u16 index;
};

struct agentx_close_pdu {
  struct agentx_header h;
  u8 reason;
};

struct agentx_un_register_hdr {
  u8 timeout;
  u8 priority;
  u8 range_subid;
  u8 pad;
};

struct agentx_bulk_state {
  struct agentx_getbulk getbulk;
  u16 index;
  u16 repetition;
  u32 repeaters;
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

#define AGENTX_FLAGS (AGENTX_FLAG_INSTANCE_REGISTRATION			      \
  | AGENTX_FLAG_NEW_INDEX						      \
  | AGENTX_FLAG_ANY_INDEX						      \
  | AGENTX_NON_DEFAULT_CONTEXT						      \
  | AGENTX_NETWORK_BYTE_ORDER)

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
  /* response OK master <-> subagent */
  AGENTX_RES_NO_ERROR		    =   0,
  /* TEST_SET_PDU response errors (subagent -> master) */
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
  /* end of TEST_SET_PDU resonse errs (master -> subagent) */
  AGENTX_RES_OPEN_FAILED	    = 256,
  AGENTX_RES_NOT_OPEN		    = 257,
  AGENTX_RES_INDEX_WRONG_TYPE	    = 258,
  AGENTX_RES_INDEX_ALREADY_ALLOC    = 259,
  AGENTX_RES_INDEX_NONE_AVAIL	    = 260,
  AGENTX_RES_NOT_ALLOCATED	    = 261,
  AGENTX_RES_UNSUPPORTED_CONTEXT    = 262,
  AGENTX_RES_DUPLICATE_REGISTER	    = 263,
  AGENTX_RES_UNKNOWN_REGISTER	    = 264,
  AGENTX_RES_UNKNOWN_AGENT_CAPS	    = 265,
  AGENTX_RES_PARSE_ERROR	    = 266,
  AGENTX_RES_REQUEST_DENIED	    = 267,
  AGENTX_RES_PROCESSING_ERR	    = 268,
} PACKED;

/* SNMP PDU buffer info */
struct snmp_pdu {
  byte *buffer;			    /* pointer to buffer */
  uint size;			    /* unused space in buffer */
  uint context;			    /* context hash */
  int byte_ord;			    /* flag signaling NETWORK_BYTE_ORDER */
  enum agentx_response_err error;   /* storage for result of current action */
};

struct agentx_alloc_context {
  u8 is_instance; /* flag INSTANCE_REGISTRATION */
  u8 new_index;   /* flag NEW_INDEX */
  u8 any_index;	  /* flag ANY_INDEX */
  char *context;  /* context to allocate in */
  uint clen;	  /* length of context string */
};

int snmp_rx(sock *sk, uint size);
int snmp_rx_stop(sock *sk, uint size);
void snmp_down(struct snmp_proto *p);
void snmp_register(struct snmp_proto *p, struct oid *oid, uint index, uint len, u8 is_instance, uint contid);
void snmp_unregister(struct snmp_proto *p, struct oid *oid, uint index, uint len, uint contid);
void snmp_notify_pdu(struct snmp_proto *p, struct oid *oid, void *data, uint size, int include_uptime);

void snmp_manage_tbuf(struct snmp_proto *p, struct snmp_pdu *c);

struct oid *snmp_prefixize(struct snmp_proto *p, const struct oid *o, int byte_ord);
u8 snmp_get_mib_class(const struct oid *oid);


// debug wrapper
#define snmp_log(...) log(L_INFO "snmp " __VA_ARGS__)

#endif
