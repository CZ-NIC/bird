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

/*
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/varbind_api.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
*/

// fix conflicts
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "bgp_mib.h"
#include "snmp.h"

void
snmp_bgp_register()
{}

static inline int
is_bgp_peer_entry(struct oid *o)
{
  if (o->ids[2] == BGP4_PEER_ENTRY &&
      o->ids[3] > 0 &&
      /* do not include bgpPeerInUpdatesElapsedTime
         and bgpPeerFsmEstablishedTime */
      o->ids[3] < SNMP_BGP_IN_UPDATE_ELAPSED_TIME &&
      o->ids[3] != SNMP_BGP_FSM_ESTABLISHED_TIME)
    return 1;
  else
    return 0;
}

int
snmp_bgp_is_supported(struct oid *o)
{
  if (o->prefix == 2 && o->ids[0] == 1)
  {
    if (o->ids[1] == BGP4_MIB_VERSION ||
        o->ids == BGP4_MIB_LOCAL_AS)
      return 1;
    else if (o->ids[1] == BGP4_PEER_TABLE)
      return is_bgp_peer_entry(o)
    else
      return 0;
  }
  else
    return 0;
}

