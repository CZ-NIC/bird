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
#include "snmp_utils.h"

#define SNMP_EXPECTED(actual, expected) \
  bt_debug("%s  expected: %3u   actual: %3u\n", \
    #expected, expected, actual);

#ifdef CPU_BIG_ENDIAN
  #define BYTE_ORD 1
#else
  #define BYTE_ORD 0
#endif

#define OID_ALLOCATE(size) mb_alloc(&root_pool, sizeof(struct oid) + (size) * sizeof (u32))

#define OID_INIT(oid, n_subid_, prefix_, include_, arr_)      \
  (oid)->n_subid = (n_subid_);				      \
  (oid)->prefix = (prefix_);				      \
  (oid)->include = (include_);				      \
  memcpy((oid)->ids, (arr_), sizeof(arr_));		      \

void
test_fill(struct snmp_proto *p)
{
  ((struct proto *) p)->pool = &root_pool;
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
  snmp_oid_dump(oid);
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
t_s_is_oid_empty(void)
{
  bt_assert(snmp_is_oid_empty(NULL) == 0);

  struct oid *blank = mb_alloc(&root_pool, sizeof(struct oid));
  blank->n_subid = 0;
  blank->prefix = 0;
  blank->include = 0;

  bt_assert(snmp_is_oid_empty(blank) == 1);

  struct oid *prefixed = mb_alloc(&root_pool, sizeof(struct oid) + 3 * sizeof(u32));
  prefixed->n_subid = 3;
  prefixed->prefix = 100;
  prefixed->include = 1;

  u32 prefixed_arr[] = { ~((u32) 0), 0, 256 };
  memcpy(&prefixed->ids, prefixed_arr, sizeof(prefixed_arr) /
    sizeof(prefixed_arr[0]));

  bt_assert(snmp_is_oid_empty(prefixed) == 0);

  struct oid *to_prefix = mb_alloc(&root_pool, sizeof(struct oid) + 8 * sizeof(u32));
  to_prefix->n_subid = 8;
  to_prefix->prefix = 0;
  to_prefix->include = 1;

  u32 to_prefix_arr[] = {1, 3, 6, 1, 100, ~((u32) 0), 0, 256 };
  memcpy(&to_prefix->n_subid, to_prefix_arr, sizeof(to_prefix_arr) /
    sizeof(to_prefix_arr[0]));

  bt_assert(snmp_is_oid_empty(to_prefix) == 0);

  struct oid *unprefixable = mb_alloc(&root_pool, sizeof(struct oid) + 2 * sizeof(u32));
  unprefixable->n_subid = 2;
  unprefixable->prefix = 0;
  unprefixable->include = 0;

  u32 unpref[] = { 65535, 4 };
  memcpy(&unprefixable->ids, unpref, sizeof(unpref) / sizeof(unpref[0]));

  bt_assert(snmp_is_oid_empty(unprefixable) == 0);

  struct oid *unprefixable2 = mb_alloc(&root_pool, sizeof(struct oid) + 8 * sizeof(u32));
  unprefixable2->n_subid = 8;
  unprefixable2->prefix = 0;
  unprefixable2->include = 1;

  u32 unpref2[] = { 1, 3, 6, 2, 1, 2, 15, 6 };
  memcpy(&unprefixable2->ids, unpref2, sizeof(unpref2) / sizeof(unpref2[0]));

  bt_assert(snmp_is_oid_empty(unprefixable2) == 0);

  return 1;
}

static int
t_s_prefixize(void)
{
  struct oid *nulled = NULL;

  struct snmp_proto snmp_proto;

  test_fill(&snmp_proto);

  bt_debug("before seg fault\n");

  if (snmp_is_oid_empty(NULL))
    bt_debug("null oid is empty");
  else
    bt_debug("null oid is not empty");
  
  bt_debug("main cause\n");
  struct oid *tmp = snmp_prefixize(&snmp_proto, nulled, BYTE_ORD);
  bt_debug("after snmp_prefixize() call\n");
  bt_assert( NULL == tmp );

  bt_debug("after assert\n");
  struct oid *blank = mb_allocz(&root_pool, sizeof(struct oid));

  /* here the byte order should not matter */
  bt_assert(snmp_is_oid_empty(snmp_prefixize(&snmp_proto, blank, 1 - BYTE_ORD)) == 1);

  struct oid *prefixed = mb_alloc(&root_pool, sizeof(struct oid) + 3 * sizeof(u32));
  prefixed->n_subid = 3;
  prefixed->prefix = 100;
  prefixed->include = 1;

  u32 prefixed_arr[] = { ~((u32) 0), 0, 256 };
  memcpy(&prefixed->ids, prefixed_arr, sizeof(prefixed_arr) /
    sizeof(prefixed_arr[0]));

    bt_assert(memcmp(snmp_prefixize(&snmp_proto, prefixed, BYTE_ORD), prefixed, snmp_oid_size(prefixed)) == 0);

  struct oid *to_prefix = mb_alloc(&root_pool, sizeof(struct oid) + 8 * sizeof(u32));
  to_prefix->n_subid = 8;
  to_prefix->prefix = 0;
  to_prefix->include = 1;

  u32 to_prefix_arr[] = {1, 3, 6, 1, 100, ~((u32) 0), 0, 256 };
  memcpy(&to_prefix->n_subid, to_prefix_arr, sizeof(to_prefix_arr) /
    sizeof(to_prefix_arr[0]));

  bt_assert(memcmp(snmp_prefixize(&snmp_proto, to_prefix, BYTE_ORD), prefixed, snmp_oid_size(prefixed)) == 0);

  struct oid *unprefixable = mb_alloc(&root_pool, sizeof(struct oid) + 2 * sizeof(u32));
  unprefixable->n_subid = 2;
  unprefixable->prefix = 0;
  unprefixable->include = 0;

  u32 unpref[] = { 65535, 4 };
  memcpy(&unprefixable->ids, unpref, sizeof(unpref) / sizeof(unpref[0]));

  bt_assert(snmp_prefixize(&snmp_proto, unprefixable, BYTE_ORD) == NULL);

  struct oid *unprefixable2 = mb_alloc(&root_pool, sizeof(struct oid) + 8 * sizeof(u32));
  unprefixable2->n_subid = 8;
  unprefixable2->prefix = 0;
  unprefixable2->include = 1;

  u32 unpref2[] = { 1, 3, 6, 2, 1, 2, 15, 6 };
  memcpy(&unprefixable2->ids, unpref2, sizeof(unpref2) / sizeof(unpref2[0]));

  bt_assert(snmp_prefixize(&snmp_proto, unprefixable2, BYTE_ORD) == NULL);

  return 1;
}

static int
t_oid_compare(void)
{
  /* same length, no prefix */
  struct oid *l1 = OID_ALLOCATE(5);
  {
    u32 arr[] = { 1, 2, 3, 4, 5 };
    OID_INIT(l1, 5, 0, 1, arr);
  }


  struct oid *r1 = OID_ALLOCATE(5);
  {
    u32 arr[] = { 1, 2, 3, 4, 6 };
    OID_INIT(r1, 5, 0, 0, arr);
  }

  bt_assert(snmp_oid_compare(l1, r1) == -1);
  bt_assert(snmp_oid_compare(r1, l1) ==  1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  /* same results for prefixed oids */
  l1->prefix = 1;
  r1->prefix = 1;

  bt_assert(snmp_oid_compare(l1, r1) == -1);
  bt_assert(snmp_oid_compare(r1, l1) ==  1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  mb_free(l1);
  mb_free(r1);


  /* different length, no prefix */
  l1 = OID_ALLOCATE(4);
  {
    u32 arr[] = { 1, 2, 3, 4 };
    OID_INIT(l1, 4, 0, 0, arr);
  }

  r1 = OID_ALLOCATE(5);
  {
    u32 arr[] = { 1, 2, 3, 4, 1 };
    OID_INIT(l1, 5, 0, 1, arr);
  }

  bt_assert(snmp_oid_compare(l1, r1) == -1);
  bt_assert(snmp_oid_compare(r1, l1) ==  1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  /* same results for prefixed oids */
  l1->prefix = 3;
  r1->prefix = 3;

  bt_assert(snmp_oid_compare(l1, r1) == -1);
  bt_assert(snmp_oid_compare(r1, l1) ==  1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  mb_free(l1);
  mb_free(r1);


  /* inverse order different length, no prefix */  
  l1 = OID_ALLOCATE(4);
  {
    u32 arr[] = { 1, 2, 3, 5 };
    OID_INIT(l1, 4, 0, 0, arr);
  }

  r1 = OID_ALLOCATE(5);
  {
    u32 arr[] = { 1, 2, 3, 4, 1 };
    OID_INIT(r1, 5, 0, 0, arr);
  }

  bt_assert(snmp_oid_compare(l1, r1) ==  1);
  bt_assert(snmp_oid_compare(r1, l1) == -1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  /* same results for prefixed oids */
  l1->prefix = 254;
  r1->prefix = 254;

  bt_assert(snmp_oid_compare(l1, r1) ==  1);
  bt_assert(snmp_oid_compare(r1, l1) == -1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  mb_free(l1);
  mb_free(r1);


/* ==== MIXED PREFIXED / NON PREFIXED OID compare ==== */
  /* same length, mixed */
  l1 = OID_ALLOCATE(6);  /* OID .1.2.17.3.21.4 */
  {
    u32 arr[] = { 1, 2, 17, 3, 21, 4 };
    OID_INIT(l1, 6, 0, 1, arr);
  }

  r1 = OID_ALLOCATE(1);  /* OID .1.3.6.1.5.3 */
  {
    u32 arr[] = { 3 };
    OID_INIT(l1, 1, 5, 1, arr);
  }

  bt_assert(snmp_oid_compare(l1, r1) == -1);
  bt_assert(snmp_oid_compare(r1, l1) ==  1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  mb_free(l1);
  mb_free(r1);

  return 1;
}

static int
t_s_bgp_state(void)
{
  struct oid *oid = mb_alloc(&root_pool, sizeof(struct oid) + 10 * sizeof(u32));

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

  return 1;
}

int main(int argc, char **argv)
{
  bt_init(argc, argv);

  bt_test_suite(t_s_bgp_state, "Function snmp_bgp_state()");

  bt_test_suite(t_s_is_oid_empty, "Function snmp_is_oid_empty()");

  bt_test_suite(t_s_prefixize, "Function snmp_prefixize()");

  bt_test_suite(t_oid_compare, "Function snmp_oid_compare()");

  return bt_exit_value();
}
