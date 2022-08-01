/*
 *	BIRD -- Simple Network Management Protocol (SNMP)
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SNMP_H_
#define _BIRD_SNPM_H_

#include "proto/bgp/bgp.h"

struct snmp_config {
  struct channel_config c;
};

struct snmp_proto {
  struct channel c;
  struct tbf rl_gen;
};

struct snmp_channel_config {
  struct channel_config c;
  struct bgp_config *bgp;
};

struct snmp_channel {
  struct channel c;
};

#endif
