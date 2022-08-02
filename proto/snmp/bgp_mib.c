/*
 *	BIRD -- Simple Network Management Protocol (SNMP)
 *        BGP4-MIB bgpPeerTable
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *      Parts of this file were auto-generated using mib2c
 *      using mib2c.create-dataset.conf
 */


#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/varbind_api.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

// fix conflicts
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "proto/snmp/bgp_mib.h"
#include "lib/birdlib.h"

static int
bgpPeerTable_handler(
  netsnmp_mib_handler               *handler, // contains void * for internal use
  netsnmp_handler_registration      *reginfo,
  netsnmp_agent_request_info        *reqinfo,
  netsnmp_request_info              *requests) {

  /* perform anything here that you need to do.  The requests have
     already been processed by the master table_dataset handler, but
     this gives you chance to act on the request in some other way
     if need be. */

  log(L_INFO " bgpPeerTable_handler()");
  // walk list of netsnmp_data_list
  for (netsnmp_data_list *l = reqinfo->agent_data;
       l; l->next)
  {
    log(L_INFO " name: %s,  poniter %p", l->name, l->data);
  }

  char buff[64];
  // walk list of netsnmp_variable_list VB
  for (netsnmp_variable_list *var = requests->requestvb;
       var; var->next_variable)
  {
    snprint_value(buff, 64, var->name, var->name_length, var);
    log(L_INFO "variable %s", buff);
    memset((void *) buff, 0, 64);
  }

  return SNMP_ERR_NOERROR;
}

void
snmp_init_bgp_table(void)
{
  const oid bgpPeerTable_oid[] = {1,3,6,1,2,1,15,3};
  netsnmp_table_data_set *table_set;

  /* create the table structure itself */
  table_set = netsnmp_create_table_data_set("bgpPeerTable");

  log(L_INFO "adding indexes to SNMP table bgpPeerTable");

  netsnmp_table_set_add_indexes(
    table_set,
    ASN_IPADDRESS,  /* index: bgpPeerRemoteAddr */
    0
  );

  log(L_INFO "adding column types to SNMP table bgpPeerTable");
  netsnmp_table_set_multi_add_default_row(
    table_set,
    SNMP_BGP_IDENTIFIER, ASN_IPADDRESS, 0, NULL, 0,
    SNMP_BGP_STATE, ASN_INTEGER, 0, NULL, 0,
    /* change to ASN_INTEGER, 1, NULL, 0, below to allow write */
    SNMP_BGP_ADMIN_STATUS, ASN_INTEGER, 0, NULL, 0,
    SNMP_BGP_VERSION, ASN_INTEGER, 0, NULL, 0,
    SNMP_BGP_LOCAL_ADDR, ASN_IPADDRESS, 0, NULL, 0,
    SNMP_BGP_LOCAL_PORT, ASN_INTEGER, 0, NULL, 0,
    SNMP_BGP_REMOTE_ADDR, ASN_IPADDRESS, 0, NULL, 0,
    SNMP_BGP_REMOTE_PORT, ASN_INTEGER, 0, NULL, 0,
    SNMP_BGP_REMOTE_AS, ASN_INTEGER, 0, NULL, 0,
    SNMP_BGP_RX_UPDATES, ASN_COUNTER, 0, NULL, 0,
    SNMP_BGP_TX_UPDATES, ASN_COUNTER, 0, NULL, 0,
    SNMP_BGP_RX_MESSAGES, ASN_COUNTER, 0, NULL, 0,
    SNMP_BGP_TX_MESSAGES, ASN_COUNTER, 0, NULL, 0,
    SNMP_BGP_LAST_ERROR, ASN_OCTET_STR, 0, NULL, 0,
    SNMP_BGP_FSM_TRANSITIONS, ASN_COUNTER, 0, NULL, 0,
    SNMP_BGP_FSM_ESTABLISHED_TIME, ASN_GAUGE, 0, NULL, 0,
    SNMP_BGP_RETRY_INTERVAL, ASN_INTEGER, 1, NULL, 0,
    SNMP_BGP_HOLD_TIME, ASN_INTEGER, 0, NULL, 0,
    SNMP_BGP_KEEPALIVE, ASN_INTEGER, 0, NULL, 0,
    SNMP_BGP_HOLD_TIME_CONFIGURED, ASN_INTEGER, 1, NULL, 0,
    SNMP_BGP_KEEPALIVE_CONFIGURED, ASN_INTEGER, 1, NULL, 0,
    SNMP_BGP_ORIGINATION_INTERVAL, ASN_INTEGER, 1, NULL, 0,
    SNMP_BGP_MIN_ROUTE_ADVERTISEMENT, ASN_INTEGER, 1, NULL, 0,
    SNMP_BGP_MIN_UPDATE_ELAPSED_TIME, ASN_GAUGE, 0, NULL, 0,
    0
  );

  /* registering the table with the master agent */
  /* note: if you don't need a subhandler to deal with any aspects
     of the request, change bgpPeerTable_handler to "NULL" */
  netsnmp_register_table_data_set(
    netsnmp_create_handler_registration(
      "bgpPeerTable", bgpPeerTable_handler,
      bgpPeerTable_oid,
      OID_LENGTH(bgpPeerTable_oid),
      HANDLER_CAN_RONLY
      // HANDLER_CAN_RWRITE
    ),
    table_set, NULL
  );
}

void
snmp_del_bgp_table(void)
{  
  // XXX really needed ?
  const oid bgpPeerTable_oid[] = {1,3,6,1,2,1,15,3};

  remove_tree_entry(bgpPeerTable_oid, OID_LENGTH(bgpPeerTable_oid));
}
