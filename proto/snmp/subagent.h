
#ifndef _BIRD_SNMP_SUBAGENT_H_
#define _BIRD_SNMP_SUBAGENT_H_

#include "nest/bird.h"
#include "snmp.h"
#include "lib/macro.h"

void snmp_start_subagent(struct snmp_proto *p);
void snmp_stop_subagent(struct snmp_proto *p);
void snmp_ping(struct snmp_proto *p);

#define AGENTX_VERSION              1

/* standard snmp internet prefix */
#define SNMP_ISO	  1	      /* last of oid .1		      */
#define SNMP_ORG	  3	      /* last of oid .1.3	      */
#define SNMP_DOD	  6	      /* last of oid .1.3.6	      */
#define SNMP_INTERNET	  1	      /* last of oid .1.3.6.1	      */

#define SNMP_MGMT	  2	      /* last of oid .1.3.6.1.2	      */
#define SNMP_MIB_2	  1	      /* last of oid .1.3.6.1.2.1     */
#define SNMP_SYSTEM	  1	      /* last of oid .1.3.6.1.2.1.1   */
#define SNMP_OSPF_MIB	 14	      /* last of oid .1.3.6.1.2.1.14  */
#define SNMP_BGP4_MIB	 15	      /* last of oid .1.3.6.1.2.1.15  */
#define SNMP_OSPFv3_MIB	192	      /* last of oid .1.3.6.1.2.1.192 */

/* sysUpTime */
#define SNMP_SYS_UP_TIME  3	      /* last of oid .1.3.6.1.2.1.1.3 */

/* snmpTrapOID */
#define SNMP_V2		  6	      /* last of oid .1.3.6.1.6		  */
#define SNMP_MODULES	  3	      /* last of oid .1.3.6.1.6.3	  */
#define SNMP_ALARM_NEXT_INDEX 1	      /* last of oid .1.3.6.1.6.3.1	  */
#define SNMP_MIB_OBJECTS  1	      /* last of oid .1.3.6.1.6.3.1.1	  */
#define SNMP_TRAP	  4	      /* last of oid .1.3.6.1.6.3.1.1.4	  */
#define SNMP_TRAP_OID	  1	      /* last of oid .1.3.6.1.6.3.1.1.4.1 */

extern const u32 snmp_internet[4];

#define SNMP_DEFAULT_CONTEXT 0

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

  AGENTX_INVALID	    =   0,
} PACKED;

enum snmp_search_res {
  SNMP_SEARCH_OK	  = 0,
  SNMP_SEARCH_NO_OBJECT	  = 1,
  SNMP_SEARCH_NO_INSTANCE = 2,
  SNMP_SEARCH_END_OF_VIEW = 3,
};


#define AGENTX_PRIORITY		127

#define SNMP_REGISTER_TREE 0
#define SNMP_REGISTER_INSTANCE 1

enum agentx_flags {
  AGENTX_FLAG_BLANK		    = 0x00,
  AGENTX_FLAG_INSTANCE_REGISTRATION = 0x01,
  AGENTX_FLAG_NEW_INDEX		    = 0x02,
  AGENTX_FLAG_ANY_INDEX		    = 0x04,
  AGENTX_NON_DEFAULT_CONTEXT	    = 0x08,
  AGENTX_NETWORK_BYTE_ORDER	    = 0x10,
} PACKED;

#define AGENTX_FLAGS_MASK (AGENTX_FLAG_INSTANCE_REGISTRATION		      \
  | AGENTX_FLAG_NEW_INDEX						      \
  | AGENTX_FLAG_ANY_INDEX						      \
  | AGENTX_NON_DEFAULT_CONTEXT						      \
  | AGENTX_NETWORK_BYTE_ORDER)

// TODO - make me compile time option
#define SNMP_NETWORK_BYTE_ORDER

#if !(defined(SNMP_NATIVE) || defined(SNMP_NETWORK_BYTE_ORDER))
# error "SNMP: currently support only native byte order or network byte order."
#endif

#if defined(SNMP_NATIVE) && defined(SNMP_NETWORK_BYTE_ORDER) && !defined(CPU_BIG_ENDIAN)
# error "SNMP: couldn't use both native byte order and network byte order " \
  "(big endian) on little endian machine."
#endif

#if (defined(SNMP_NATIVE) && defined(CPU_BIG_ENDIAN)) || defined(SNMP_NETWORK_BYTE_ORDER)
#define SNMP_BYTE_ORDER AGENTX_NETWORK_BYTE_ORDER
#else
#define SNMP_BYTE_ORDER 0
#endif

/* We recommend using STORE_U32 over VALUE_U32 when possible */
#ifdef SNMP_NATIVE
#define STORE_U32(dest, val)  ((u32) ((dest) = (u32) (val)))
#define STORE_U16(dest, val)  ((u16) ((dest) = (u16) (val)))
#define STORE_U8(dest, val)   ((u8) ((dest) = (u8) (val)))
#define STORE_PTR(ptr, val)   (*((u32 *) (ptr)) = (u32) (val))

#define VALUE_U32(val)	      ((u32) (val))
#define VALUE_U16(val)	      ((u16) (val))
#define VALUE_U8(val)	      ((u8) (val))

#define LOAD_U32(src)	      *((u32 *) &(src))
#define LOAD_U16(src)	      *((u16 *) &(src))
#define LOAD_U8(src)	      *((u8 *) &(src))
#define LOAD_PTR(ptr)	      *((u32 *) (ptr))
#endif

#if  defined(SNMP_NETWORK_BYTE_ORDER) && (!defined(SNMP_NATIVE) || defined(CPU_BIG_ENDIAN))
#define STORE_U32(dest, val)  put_u32(&(dest), (val))
#define STORE_U16(dest, val)  put_u16(&(dest), (val))
#define STORE_U8(dest, val)   put_u8(&(dest), (val))
#define STORE_PTR(ptr, val)   put_u32(ptr, val)

#define VALUE_U32(val)	      htonl(val)
#define VALUE_U16(val)	      htons(val)
#define VALUE_U8(val)	      ((u8) (val))


#define LOAD_U32(src)	      get_u32(&(src))
#define LOAD_U16(src)	      get_u16(&(src))
#define LOAD_U8(src)	      get_u8(&(src))
#define LOAD_PTR(src)	      get_u32(ptr)
#endif

struct agentx_header {
  u8 version;
  u8 type;
  u8 flags;
  u8 reserved;		/* always zero filled */
  u32 session_id;	/* AgentX sessionID established by Open-PDU */
  u32 transaction_id;	/* last transactionID seen/used */
  u32 packet_id;	/* last packetID seen/used */
  u32 payload;		/* payload_length of the packet without header */
};

#define AGENTX_HEADER_SIZE 20
STATIC_ASSERT(AGENTX_HEADER_SIZE == sizeof(struct agentx_header));

struct oid {
  u8 n_subid;
  u8 prefix;
  u8 include;
  u8 reserved;	/* always zero filled */
  u32 ids[];
};

#define STATIC_OID(sbids)						      \
  struct {								      \
    u8 n_subid;								      \
    u8 prefix;								      \
    u8 include;								      \
    u8 reserved;							      \
    u32 ids[sbids];							      \
  }

#define STATIC_OID_INITIALIZER(sbids, pref, ...)			      \
  {									      \
    .n_subid = sbids,							      \
    .prefix = pref,							      \
    .include = 0,							      \
    .reserved = 0,							      \
    .ids = { __VA_ARGS__ },						      \
  }

/* enforced by MIB tree, see mib_tree.h for more info */
#define OID_MAX_LEN 32

/*
 * AgentX VarBind -- Variable Binding
 * During the processing of the VarBind, the fields @type and @name are in cpu
 * native byte order. This should be fixed by running snmp_varbind_leave()
 * before VarBind control pointer abondonment or before packet transmission.
 * The data following the structure should always follow the packet byte order.
 */
struct agentx_varbind {
  u16 type;
  u16 reserved; /* always zero filled */
  /* oid part */
  struct oid name;
  /* AgentX variable binding data optionally here */
};

struct agentx_search_range {
  struct oid *start;
  struct oid *end;
};

/* AgentX Octet String */
struct agentx_octet_str {
  u32 length;
  byte data[0];
};

struct agentx_response {
  struct agentx_header h;
  u32 uptime;
  u16 error;
  u16 index;
};

STATIC_ASSERT(4 + 2 + 2 + AGENTX_HEADER_SIZE == sizeof(struct agentx_response));

struct agentx_open_pdu {
  struct agentx_header h;
  u8 timeout;
  u8 reserved1;	  /* reserved u24 */
  u16 reserved2;  /* whole u24 is always zero filled */
};

struct agentx_close_pdu {
  struct agentx_header h;
  u8 reason;
  u8 reserved1; /* reserved u24 */
  u16 reserved2; /* whole u24 is always zero filled */
};

struct agentx_un_register_hdr {
  u8 timeout;
  u8 priority;
  u8 range_subid;
  u8 reserved;	/* always zero filled */
};

struct agentx_getbulk {
  u16 non_repeaters;
  u16 max_repetitions;
};

struct agentx_bulk_state {
  struct agentx_getbulk getbulk;
  u16 index;
  u16 repetition;
  u32 repeaters;
  int has_any;	    /* flag is clear when all responses are EndOfMibView */
};

enum agentx_pdu_types {
  AGENTX_OPEN_PDU		=  1,	  /* agentx-Open-PDU */
  AGENTX_CLOSE_PDU		=  2,	  /* agentx-Close-PDU */
  AGENTX_REGISTER_PDU		=  3,	  /* agentx-Regiter-PDU */
  AGENTX_UNREGISTER_PDU		=  4,	  /* agentx-Unregister-PDU */
  AGENTX_GET_PDU		=  5,	  /* agentx-Get-PDU */
  AGENTX_GET_NEXT_PDU		=  6,	  /* agentx-GetNext-PDU */
  AGENTX_GET_BULK_PDU		=  7,	  /* agentx-GetBulk-PDU */
  AGENTX_TEST_SET_PDU		=  8,	  /* agentx-TestSet-PDU */
  AGENTX_COMMIT_SET_PDU		=  9,	  /* agentx-CommitSet-PDU */
  AGENTX_UNDO_SET_PDU		= 10,	  /* agentx-UndoSet-PDU */
  AGENTX_CLEANUP_SET_PDU	= 11,	  /* agentx-CleanupSet-PDU */
  AGENTX_NOTIFY_PDU		= 12,	  /* agentx-Notify-PDU */
  AGENTX_PING_PDU		= 13,	  /* agentx-Ping-PDU */
  AGENTX_INDEX_ALLOCATE_PDU     = 14,	  /* agentx-IndexAllocate-PDU */
  AGENTX_INDEX_DEALLOCATE_PDU   = 15,	  /* agentx-IndexDeallocate-PDU */
  AGENTX_ADD_AGENT_CAPS_PDU     = 16,	  /* agentx-AddAgentCaps-PDU */
  AGENTX_REMOVE_AGENT_CAPS_PDU  = 17,	  /* agentx-RemoveAgentCaps-PDU */
  AGENTX_RESPONSE_PDU		= 18,	  /* agentx-Response-PDU */
} PACKED;

/* agentx-Close-PDU close reasons */
enum agentx_close_reasons {
  AGENTX_CLOSE_OTHER	      = 1,
  AGENTX_CLOSE_PARSE_ERROR    = 2,
  AGENTX_CLOSE_PROTOCOL_ERROR = 3,
  AGENTX_CLOSE_TIMEOUTS	      = 4,
  AGENTX_CLOSE_SHUTDOWN	      = 5,
  AGENTX_CLOSE_BY_MANAGER     = 6,
} PACKED;


/* agentx-Response-PDU - result errors */
enum agentx_response_errs {
  /* response error to both Administrative and SNMP messages */
  AGENTX_RES_NO_ERROR		    =   0,	/* noAgentXError */
  /* response errors to SNMP messages */
  AGENTX_RES_GEN_ERROR		    =   5,	/* genError */
  AGENTX_RES_NO_ACCESS		    =   6,	/* noAccess */
  AGENTX_RES_WRONG_TYPE		    =   7,	/* wrongType */
  AGENTX_RES_WRONG_LENGTH	    =   8,	/* wrongLength */
  AGENTX_RES_WRONG_ENCODING	    =   9,	/* wrongEncoding */
  AGENTX_RES_WRONG_VALUE	    =  10,	/* wrongValue*/
  AGENTX_RES_NO_CREATION	    =  11,	/* noCreation */
  AGENTX_RES_INCONSISTENT_VALUE	    =  12,	/* inconsistentValue */
  AGENTX_RES_RESOURCE_UNAVAILABLE   =  13,	/* resourceUnavailable */
  AGENTX_RES_COMMIT_FAILED	    =  14,	/* commitFailed */
  AGENTX_RES_UNDO_FAILED	    =  15,	/* undoFailed */
  AGENTX_RES_NOT_WRITABLE	    =  17,	/* notWritable */
  AGENTX_RES_INCONSISTENT_NAME	    =  18,	/* inconsistentName */
  /* response error to Administrative messages */
  AGENTX_RES_OPEN_FAILED	    = 256,	/* openFailed */
  AGENTX_RES_NOT_OPEN		    = 257,	/* notOpen */
  AGENTX_RES_INDEX_WRONG_TYPE	    = 258,	/* indexWrongType */
  AGENTX_RES_INDEX_ALREADY_ALLOC    = 259,	/* indexAlreadyAlloc */
  AGENTX_RES_INDEX_NONE_AVAIL	    = 260,	/* indexNoneAvail */
  AGENTX_RES_NOT_ALLOCATED	    = 261,	/* notAllocated */
  AGENTX_RES_UNSUPPORTED_CONTEXT    = 262,	/* unsupportedContext */
  AGENTX_RES_DUPLICATE_REGISTER	    = 263,	/* duplicateRegister */
  AGENTX_RES_UNKNOWN_REGISTER	    = 264,	/* unknownRegister */
  AGENTX_RES_UNKNOWN_AGENT_CAPS	    = 265,	/* unknownAgentCaps */
  AGENTX_RES_PARSE_ERROR	    = 266,	/* parseError */
  AGENTX_RES_REQUEST_DENIED	    = 267,	/* requestDenied */
  AGENTX_RES_PROCESSING_ERR	    = 268,	/* processingError */
} PACKED;

/* SNMP PDU info */
struct snmp_pdu {
  struct snmp_proto *p;

  /* TX buffer */
  byte *buffer;			    /* pointer to buffer */
  uint size;			    /* unused space in buffer */

  /* Search Range */
  struct agentx_varbind *sr_vb_start; /* search range starting OID inside TX buffer (final storage) */
  const struct oid *sr_o_end;	      /* search range ending OID */

  /* Control */
  enum agentx_response_errs error;  /* storage for result of current action */
  u32 index;			    /* index on which the error was found */
};

struct snmp_packet_info {
  node n;
  u8 type; // enum type
  u32 session_id;
  u32 transaction_id;
  u32 packet_id;
  void *data;
};

int snmp_rx(sock *sk, uint size);
void snmp_tx(sock *sk);
int snmp_rx_stop(sock *sk, uint size);
void snmp_register(struct snmp_proto *p, struct oid *oid, uint index, uint len, u8 is_instance);
void snmp_unregister(struct snmp_proto *p, struct oid *oid, uint index, uint len);
void snmp_notify_pdu(struct snmp_proto *p, struct oid *oid, void *data, uint size, int include_uptime);

int snmp_tbuf_reserve(struct snmp_pdu *c, size_t bytes);

static inline int
snmp_is_active(const struct snmp_proto *p)
{
  /* Note: states in which we have opened socket */
  return p->state == SNMP_OPEN || p->state == SNMP_REGISTER ||
      p->state == SNMP_CONN;
}

struct agentx_varbind *snmp_vb_to_tx(struct snmp_pdu *c, const struct oid *oid);
u8 snmp_get_mib_class(const struct oid *oid);

void snmp_register_mibs(struct snmp_proto *p);

#endif
