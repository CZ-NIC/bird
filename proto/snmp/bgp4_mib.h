#ifndef _BIRD_SNMP_BGP4_MIB_H_
#define _BIRD_SNMP_BGP4_MIB_H_

#include "snmp.h"
#include "proto/bgp/bgp.h"
#include "subagent.h"

#define BGP4_MIB 15

/* peers attributes */
enum bgp4_mib_peer_entry_row {
  BGP4_MIB_PEER_IDENTIFIER	    =  1,
  BGP4_MIB_STATE		    =  2,
  BGP4_MIB_ADMIN_STATUS		    =  3,   /* in read-only mode */
  BGP4_MIB_NEGOTIATED_VERSION	    =  4,
  BGP4_MIB_LOCAL_ADDR		    =  5,
  BGP4_MIB_LOCAL_PORT		    =  6,
  BGP4_MIB_REMOTE_ADDR		    =  7,
  BGP4_MIB_REMOTE_PORT		    =  8,
  BGP4_MIB_REMOTE_AS		    =  9,
  BGP4_MIB_RX_UPDATES		    = 10,   /* in updates */
  BGP4_MIB_TX_UPDATES		    = 11,   /* out updates */
  BGP4_MIB_RX_MESSAGES		    = 12,   /* in total messages */
  BGP4_MIB_TX_MESSAGES		    = 13,   /* out total messages */
  BGP4_MIB_LAST_ERROR		    = 14,
  BGP4_MIB_FSM_TRANSITIONS	    = 15,   /* FSM established transitions */
  BGP4_MIB_FSM_ESTABLISHED_TIME	    = 16,
  BGP4_MIB_RETRY_INTERVAL	    = 17,
  BGP4_MIB_HOLD_TIME		    = 18,
  BGP4_MIB_KEEPALIVE		    = 19,
  BGP4_MIB_HOLD_TIME_CONFIGURED	    = 20,
  BGP4_MIB_KEEPALIVE_CONFIGURED	    = 21,
  BGP4_MIB_ORIGINATION_INTERVAL	    = 22,   /* UNSUPPORTED - 0 */
  BGP4_MIB_MIN_ROUTE_ADVERTISEMENT  = 23,   /* UNSUPPORTED - 0 */
  BGP4_MIB_IN_UPDATE_ELAPSED_TIME   = 24,
} PACKED;

/* version of BGP, here BGP-4 */
#define BGP4_VERSIONS ((char[]) { 0x10 }) /* OID bgp.bgpVersion */
/* for OID bgp.bgpPeerTable.bgpPeerEntry.bgpPeerNegotiatedVersion */
#define BGP4_MIB_NEGOTIATED_VER_VALUE 4
#define BGP4_MIB_NEGOTIATED_VER_NO_VALUE 0

u8 snmp_bgp_get_valid(u8 state);
u8 snmp_bgp_getnext_valid(u8 state);

void snmp_bgp4_register(struct snmp_proto *p);

enum snmp_search_res snmp_bgp_search(struct snmp_proto *p, struct agentx_varbind **vb_search, const struct oid *o_end, struct snmp_pdu *c);
enum snmp_search_res snmp_bgp_search2(struct snmp_proto *p, struct oid **searched, const struct oid *o_end, uint contid);
void snmp_bgp_fill(struct snmp_proto *p, struct agentx_varbind **vb, struct snmp_pdu *c);
//int snmp_bgp_testset(struct snmp_proto *p, const struct agentx_varbind *vb, void* tr, struct oid *oid, uint pkt_type);

void snmp_bgp_notify_established(struct snmp_proto *p, struct bgp_proto *bgp);
void snmp_bgp_notify_backward_trans(struct snmp_proto *p, struct bgp_proto *bgp);

enum bgp4_mib_rows {
  BGP4_MIB_VERSION    = 1,
  BGP4_MIB_LOCAL_AS   = 2,
  BGP4_MIB_PEER_TABLE = 3,    /* subtable */
  BGP4_MIB_IDENTIFIER = 4,    /* BGP4-MIB::bgpIdentifier local router id */
};

enum bgp4_mib_peer_table_rows {
  BGP4_MIB_PEER_ENTRY = 1,
};

enum bgp4_mib_linearized_states {
  BGP4_MIB_S_INVALID = 0, /* state invalid */
  BGP4_MIB_S_START = 1,
  BGP4_MIB_S_BGP,
  BGP4_MIB_S_VERSION,
  BGP4_MIB_S_LOCAL_AS,
  BGP4_MIB_S_PEER_TABLE,
  BGP4_MIB_S_PEER_ENTRY,
  BGP4_MIB_S_PEER_IDENTIFIER,
  BGP4_MIB_S_STATE,
  BGP4_MIB_S_ADMIN_STATUS,
  BGP4_MIB_S_NEGOTIATED_VERSION,
  BGP4_MIB_S_LOCAL_ADDR,
  BGP4_MIB_S_LOCAL_PORT,
  BGP4_MIB_S_REMOTE_ADDR,
  BGP4_MIB_S_REMOTE_PORT,
  BGP4_MIB_S_REMOTE_AS,
  BGP4_MIB_S_RX_UPDATES,
  BGP4_MIB_S_TX_UPDATES,
  BGP4_MIB_S_RX_MESSAGES,
  BGP4_MIB_S_TX_MESSAGES,
  BGP4_MIB_S_LAST_ERROR,
  BGP4_MIB_S_FSM_TRANSITIONS,
  BGP4_MIB_S_FSM_ESTABLISHED_TIME,
  BGP4_MIB_S_RETRY_INTERVAL,
  BGP4_MIB_S_HOLD_TIME,
  BGP4_MIB_S_KEEPALIVE,
  BGP4_MIB_S_HOLD_TIME_CONFIGURED,
  BGP4_MIB_S_KEEPALIVE_CONFIGURED,
  BGP4_MIB_S_ORIGINATION_INTERVAL,
  BGP4_MIB_S_MIN_ROUTE_ADVERTISEMENT,
  BGP4_MIB_S_IN_UPDATE_ELAPSED_TIME,
  BGP4_MIB_S_PEER_TABLE_END,
  BGP4_MIB_S_IDENTIFIER,	/* state local identification */
  BGP4_MIB_S_END,
  BGP4_MIB_S_NO_VALUE = 255,
} PACKED;

/* valid values for BGP4_MIB_STATE */
enum bgp4_mib_bgp_states {
  BGP4_MIB_IDLE = 1,
  BGP4_MIB_CONNECT = 2,
  BGP4_MIB_ACTIVE = 3,
  BGP4_MIB_OPENSENT = 4,
  BGP4_MIB_OPENCONFIRM = 5,
  BGP4_MIB_ESTABLISHED = 6,
};

STATIC_ASSERT(BGP4_MIB_IDLE == BS_IDLE + 1);
STATIC_ASSERT(BGP4_MIB_CONNECT == BS_CONNECT + 1);
STATIC_ASSERT(BGP4_MIB_ACTIVE == BS_ACTIVE + 1);
STATIC_ASSERT(BGP4_MIB_OPENSENT == BS_OPENSENT + 1);
STATIC_ASSERT(BGP4_MIB_OPENCONFIRM == BS_OPENCONFIRM + 1);
STATIC_ASSERT(BGP4_MIB_ESTABLISHED == BS_ESTABLISHED + 1);

/* Traps OID sub-identifiers */
#define BGP4_MIB_ESTABLISHED_NOTIFICATION 1
#define BGP4_MIB_BACKWARD_TRANS_NOTIFICATION 2

#endif
