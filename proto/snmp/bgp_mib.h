#ifndef _BIRD_SNMP_BGP_MIB_H_
#define _BIRD_SNMP_BGP_MIB_H_

/* peers attributes */
enum BGP4_MIB {
  SNMP_BGP_IDENTIFIER		    =  1;
  SNMP_BGP_STATE		    =  2;
  SNMP_BGP_ADMIN_STATUS		    =  3;   /* in read-only mode */
  SNMP_BGP_VERSION		    =  4;
  SNMP_BGP_LOCAL_ADDR		    =  5;
  SNMP_BGP_LOCAL_PORT		    =  6;
  SNMP_BGP_REMOTE_ADDR		    =  7;
  SNMP_BGP_REMOTE_PORT		    =  8;
  SNMP_BGP_REMOTE_AS		    =  9;
  SNMP_BGP_RX_UPDATES		    = 10;   /* in updates */
  SNMP_BGP_TX_UPDATES		    = 11;   /* out updates */
  SNMP_BGP_RX_MESSAGES		    = 12;   /* in total messages */
  SNMP_BGP_TX_MESSAGES		    = 13;   /* out total messages */
  SNMP_BGP_LAST_ERROR		    = 14;
  SNMP_BGP_FSM_TRANSITIONS	    = 15;   /* FSM established transitions */
  SNMP_BGP_FSM_ESTABLISHED_TIME	    = 16;   /* UNSUPPORTED FSM established time */
  SNMP_BGP_RETRY_INTERVAL	    = 17;
  SNMP_BGP_HOLD_TIME		    = 18;
  SNMP_BGP_KEEPALIVE		    = 19;
  SNMP_BGP_HOLD_TIME_CONFIGURED	    = 20;
  SNMP_BGP_KEEPALIVE_CONFIGURED	    = 21;
  SNMP_BGP_ORIGINATION_INTERVAL	    = 22;   /* UNSUPPORTED 0 */
  SNMP_BGP_MIN_ROUTE_ADVERTISEMENT  = 23;   /* UNSUPPORTED 0*/
  SNMP_BGP_MIN_UPDATE_ELAPSED_TIME  = 24;   /* UNSUPPORTED */
} PACKED;

void snmp_init_bgp_table(void);
void snmp_del_bgp_table(void);

#endif
