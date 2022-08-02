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

#define SNMP_UNDEFINED	0
#define SNMP_BGP	1
#define SNMP_OSPF	2
#define SNMP_INVALID  255

struct snmp_bond {
  node n;
  struct proto_config *proto;
  u8 type;
};

struct snmp_config {
  struct channel_config c;
  list bgp_entries;
};

struct snmp_proto {
  struct channel c;
  struct tbf rl_gen;
};

struct snmp_channel_config {
  struct channel_config c;
  struct bgp_config *bgp;
  u8 type;
};

struct snmp_channel {
  struct channel c;
};

#endif
