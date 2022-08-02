#ifndef _BIRD_SNMP_BGP_MIB_H_
#define _BIRD_SNMP_BGP_MIB_H_

/* peers attributes */
#define SNMP_BGP_IDENTIFIER 1
#define SNMP_BGP_STATE 2
#define SNMP_BGP_ADMIN_STATUS 3		    /* in read-only mode */
#define SNMP_BGP_VERSION 4
#define SNMP_BGP_LOCAL_ADDR 5
#define SNMP_BGP_LOCAL_PORT 6
#define SNMP_BGP_REMOTE_ADDR 7
#define SNMP_BGP_REMOTE_PORT 8
#define SNMP_BGP_REMOTE_AS 9
#define SNMP_BGP_RX_UPDATES 10		    /* in updates */
#define SNMP_BGP_TX_UPDATES 11		    /* out updates */
#define SNMP_BGP_RX_MESSAGES 12		    /* in total messages */
#define SNMP_BGP_TX_MESSAGES 13		    /* out total messages */
#define SNMP_BGP_LAST_ERROR 14		    /* UNSUPPORTED */
#define SNMP_BGP_FSM_TRANSITIONS 15	    /* FSM established transitions */
#define SNMP_BGP_FSM_ESTABLISHED_TIME 16    /* UNSUPPORTED FSM established time */
#define SNMP_BGP_RETRY_INTERVAL 17		  
#define SNMP_BGP_HOLD_TIME 18		  
#define SNMP_BGP_KEEPALIVE 19		  
#define SNMP_BGP_HOLD_TIME_CONFIGURED 20	  
#define SNMP_BGP_KEEPALIVE_CONFIGURED 21  
#define SNMP_BGP_ORIGINATION_INTERVAL 22    /* UNSUPPORTED */
#define SNMP_BGP_MIN_ROUTE_ADVERTISEMENT 23 /* UNSUPPORTED */
#define SNMP_BGP_MIN_UPDATE_ELAPSED_TIME 24 /* UNSUPPORTED */

void snmp_init_bgp_table(void);
void snmp_del_bgp_table(void);

#endif
