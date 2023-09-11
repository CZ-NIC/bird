#ifndef _BIRD_SNMP_BGP_MIB_H_
#define _BIRD_SNMP_BGP_MIB_H_

#include "snmp.h"
#include "subagent.h"

/* peers attributes */
enum BGP4_MIB_PEER_TABLE {
  SNMP_BGP_IDENTIFIER		    =  1,
  SNMP_BGP_STATE		    =  2,
  SNMP_BGP_ADMIN_STATUS		    =  3,   /* in read-only mode */
  SNMP_BGP_NEGOTIATED_VERSION	    =  4,
  SNMP_BGP_LOCAL_ADDR		    =  5,
  SNMP_BGP_LOCAL_PORT		    =  6,
  SNMP_BGP_REMOTE_ADDR		    =  7,
  SNMP_BGP_REMOTE_PORT		    =  8,
  SNMP_BGP_REMOTE_AS		    =  9,
  SNMP_BGP_RX_UPDATES		    = 10,   /* in updates */
  SNMP_BGP_TX_UPDATES		    = 11,   /* out updates */
  SNMP_BGP_RX_MESSAGES		    = 12,   /* in total messages */
  SNMP_BGP_TX_MESSAGES		    = 13,   /* out total messages */
  SNMP_BGP_LAST_ERROR		    = 14,
  SNMP_BGP_FSM_TRANSITIONS	    = 15,   /* FSM established transitions */
  SNMP_BGP_FSM_ESTABLISHED_TIME	    = 16,
  SNMP_BGP_RETRY_INTERVAL	    = 17,
  SNMP_BGP_HOLD_TIME		    = 18,
  SNMP_BGP_KEEPALIVE		    = 19,
  SNMP_BGP_HOLD_TIME_CONFIGURED	    = 20,
  SNMP_BGP_KEEPALIVE_CONFIGURED	    = 21,
  SNMP_BGP_ORIGINATION_INTERVAL	    = 22,   /* UNSUPPORTED - 0 */
  SNMP_BGP_MIN_ROUTE_ADVERTISEMENT  = 23,   /* UNSUPPORTED - 0 */
  SNMP_BGP_IN_UPDATE_ELAPSED_TIME   = 24,
} PACKED;

/* version of BGP, here BGP-4 */
#define SNMP_BGP_NEGOTIATED_VER_VALUE 4
#define SNMP_BGP_NEGOTIATED_VER_NO_VALUE 0

struct oid;

void snmp_bgp_register(struct snmp_proto *p);

u8 snmp_bgp_get_valid(u8 state);
u8 snmp_bgp_getnext_valid(u8 state);

struct oid *snmp_bgp_search(struct snmp_proto *p, struct oid *o_start, struct oid *o_end, uint contid);
enum snmp_search_res snmp_bgp_search2(struct snmp_proto *p, struct oid **searched, const struct oid *o_end, uint contid);
void snmp_bgp_fill(struct snmp_proto *p, struct agentx_varbind *vb, struct snmp_pdu *c);

void snmp_bgp_notify_established(struct snmp_proto *p, struct bgp_proto *bgp);
void snmp_bgp_notify_backward_trans(struct snmp_proto *p, struct bgp_proto *bgp);

#define SNMP_BGP_VERSION    1
#define SNMP_BGP_LOCAL_AS   2
#define SNMP_BGP_PEER_TABLE 3
#define SNMP_BGP_PEER_ENTRY   1

/* BGP linearized state */
enum BGP_INTERNAL_STATES {
  BGP_INTERNAL_INVALID = 0,
  BGP_INTERNAL_START = 1,
  BGP_INTERNAL_BGP,
  BGP_INTERNAL_VERSION,
  BGP_INTERNAL_LOCAL_AS,
  BGP_INTERNAL_PEER_TABLE,
  BGP_INTERNAL_PEER_ENTRY,
  BGP_INTERNAL_IDENTIFIER,
  BGP_INTERNAL_STATE,
  BGP_INTERNAL_ADMIN_STATUS,
  BGP_INTERNAL_NEGOTIATED_VERSION,
  BGP_INTERNAL_LOCAL_ADDR,
  BGP_INTERNAL_LOCAL_PORT,
  BGP_INTERNAL_REMOTE_ADDR,
  BGP_INTERNAL_REMOTE_PORT,
  BGP_INTERNAL_REMOTE_AS,
  BGP_INTERNAL_RX_UPDATES,
  BGP_INTERNAL_TX_UPDATES,
  BGP_INTERNAL_RX_MESSAGES,
  BGP_INTERNAL_TX_MESSAGES,
  BGP_INTERNAL_LAST_ERROR,
  BGP_INTERNAL_FSM_TRANSITIONS,
  BGP_INTERNAL_FSM_ESTABLISHED_TIME,
  BGP_INTERNAL_RETRY_INTERVAL,
  BGP_INTERNAL_HOLD_TIME,
  BGP_INTERNAL_KEEPALIVE,
  BGP_INTERNAL_HOLD_TIME_CONFIGURED,
  BGP_INTERNAL_KEEPALIVE_CONFIGURED,
  BGP_INTERNAL_ORIGINATION_INTERVAL,
  BGP_INTERNAL_MIN_ROUTE_ADVERTISEMENT,
  BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME,
  BGP_INTERNAL_PEER_TABLE_END,
  BGP_INTERNAL_END,
  BGP_INTERNAL_NO_VALUE = 255,
} PACKED;

#define SNMP_BGP_LAST_ERROR(bgp_proto)					      \
  { bgp_proto->last_error_code & 0x00FF0000 >> 16,			      \
    bgp_proto->last_error_code & 0x000000FF };

#endif
