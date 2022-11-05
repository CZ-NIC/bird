/*
 *	BIRD -- Simple Network Management Protocol (SNMP) Unit tests
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"

#include "bgp_mib.h"
#include "subagent.h"
#include "snmp.h"

#define SNMP_EXPECTED(actual, expected) \
  bt_debug("%s  expected: %3u   actual: %3u\n", \
    #expected, expected, actual);

void
dump_oid(struct oid *oid)
{
  bt_debug(" OID DUMP: \n");
  bt_debug("  n_subid = %3u  prefix = %3u  include %s  --- \n",
    oid->n_subid, oid->prefix, (oid->include != 0) ? "yes" : "no" );

  for (int i = 0; i < oid->n_subid; i++)
    bt_debug(" %u:  %u\n", i + 1, oid->ids[i]);

  bt_debug(" OID DUMP END\n");
}

void
dump_bgp_state_values(void)
{
    // TODO XXX here
}


static void
test_oid(struct oid *oid, uint base_size)
{
  /* tests all states one by one */

  oid->n_subid = base_size + 2;
  oid->ids[0] = 1;
  oid->ids[1] = 15;  // BGP4-MIB::bgp
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_BGP);

  oid->n_subid = base_size + 3;
  oid->ids[2] = 1;   // BGP4-MIB::bgpVersion
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_VERSION);

  oid->ids[2] = 2;   // BGP4-MIB::bgpLocalAs
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_LOCAL_AS);

  oid->ids[2] = 3;   // BGP4-MIB::bgpPeerTable
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_PEER_TABLE);

  bt_debug("testing BGP4-MIB::bgpPeerEntry\n");
  oid->n_subid = base_size + 4;
  oid->ids[2] = 3;
  oid->ids[3] = 1;   // BGP4-MIB::bgpPeerEntry
  dump_oid(oid);
  SNMP_EXPECTED(snmp_bgp_state(oid), BGP_INTERNAL_PEER_ENTRY);
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_PEER_ENTRY);

  oid->n_subid = base_size + 5;
  oid->ids[2] = 3;
  oid->ids[3] = 1;
  oid->ids[4] = 1;    // BGP4-MIB::bgpPeerIdentifier
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_IDENTIFIER);

  oid->ids[4] = 2;    // BGP4-MIB::bgpPeerState
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_STATE);

  oid->ids[4] = 3;    // BGP4-MIB::bgpPeerAdminStatus
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_ADMIN_STATUS);
  
  oid->ids[4] = 4;    // BGP4-MIB::bgpPeerNegotiatedVersion
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_NEGOTIATED_VERSION);
  
  oid->ids[4] = 5;    // BGP4-MIB::bgpPeerLocalAddr
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_LOCAL_ADDR);
  
  oid->ids[4] = 6;    // BGP4-MIB::bgpPeerLocalPort
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_LOCAL_PORT);
  
  oid->ids[4] = 7;    // BGP4-MIB::bgpPeerRemoteAddr
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_REMOTE_ADDR);
  
  oid->ids[4] = 8;    // BGP4-MIB::bgpPeerRemotePort
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_REMOTE_PORT);
  
  oid->ids[4] = 9;    // BGP4-MIB::bgpPeerRemoteAs
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_REMOTE_AS);
  
  oid->ids[4] = 10;   // BGP4-MIB::bgpPeerInUpdates
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_RX_UPDATES);
  
  oid->ids[4] = 11;   // BGP4-MIB::bgpPeerOutUpdates
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_TX_UPDATES);
  
  oid->ids[4] = 12;   // BGP4-MIB::bgpPeerInTotalMessages
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_RX_MESSAGES);
  
  oid->ids[4] = 13;   // BGP4-MIB::bgpPeerOutTotalMessages
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_TX_MESSAGES);
  
  oid->ids[4] = 14;   // BGP4-MIB::bgpPeerLastError
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_LAST_ERROR);
  
  oid->ids[4] = 15;   // BGP4-MIB::bgpPeerFsmEstablishedTransitions
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_FSM_TRANSITIONS);
  
  oid->ids[4] = 16;   // BGP4-MIB::bgpPeerFsmEstablishedTime
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_FSM_ESTABLISHED_TIME);
  
  oid->ids[4] = 17;   // BGP4-MIB::bgpPeerConnectionRetryInterval
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_RETRY_INTERVAL);
  
  oid->ids[4] = 18;   // BGP4-MIB::bgpPeerHoldTime
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_HOLD_TIME);
  
  oid->ids[4] = 19;   // BGP4-MIB::bgpPeerKeepAlive
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_KEEPALIVE);
  
  oid->ids[4] = 20;   // BGP4-MIB::bgpPeerHoldTimeConfigured
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_HOLD_TIME_CONFIGURED);
  
  oid->ids[4] = 21;   // BGP4-MIB::bgpPeerKeepAliveConfigured
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_KEEPALIVE_CONFIGURED);
  
  oid->ids[4] = 22;   // BGP4-MIB::bgpPeerMinASOriginationInterval
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_ORIGINATION_INTERVAL);
  
  oid->ids[4] = 23;   // BGP4-MIB::bgpPeerMinRouteAdvertisementInverval
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_MIN_ROUTE_ADVERTISEMENT);

  oid->ids[4] = 24;   // BGP4-MIB::bgpPeerInUpdateElapsedTime
  bt_assert(snmp_bgp_state(oid) == BGP_INTERNAL_IN_UPDATE_ELAPSED_TIME);
}

static int
t_s_bgp_state(void)
{
  struct oid *oid = alloca(sizeof(struct oid) + 10 * sizeof(32));

  /* oid header */
  oid->n_subid = 0;
  oid->prefix = 2;
  oid->include = 0;
  oid->pad = 0;

  /* test all states with expected oid length */
  bt_debug("testing precise oids\n");
  test_oid(oid, 0);

  for (int i = 0; i < 10; i++)
    oid->ids[i] = (u32) bt_random();

  /* if this subid is too high it does not match the test case
   * in general test_oid() func
   */
  oid->ids[2] = 0;

  /* test all states with garbage ip */
  bt_debug("testing oids with random ip index\n");
  test_oid(oid, 4);

  /* test all states with invalid ip */
  bt_debug("testing oids with invalid ip index\n");
  /* zero the states that overlap */
  oid->ids[2] = 0;
  oid->ids[3] = 0;
  oid->ids[4] = 0;

  oid->ids[5] = 0;
  oid->ids[6] = 257;
  oid->ids[7] = 127;
  oid->ids[8] = 0xFFFF;
  test_oid(oid, 4);

  bt_debug("testing too long oids\n");
  bt_debug("not implemented\n");
  bt_debug("exiting\n");
  return 1;
}

int main(int argc, char **argv)
{
  bt_init(argc, argv);

  bt_test_suite(t_s_bgp_state, "Function snmp_bgp_state()");

  return bt_exit_value();
}
