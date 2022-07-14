/*
 *	BIRD -- Statistics Protocol
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_STATS_H_
#define _BIRD_STATS_H_

struct stats_config {
  struct proto_config c;
  const net_addr *in_subprefix;
  u8 max_generation;
};

struct stats_proto {
  struct proto p;
  struct channel *c;
  struct tbf rl_gen;
  u32 *counters;
};

#endif
