/*
 *	BIRD -- Table-to-Table Routing Protocol a.k.a Pipe
 *
 *	(c) 1999 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_STATS_H_
#define _BIRD_STATS_H_

struct stats_config {
  struct proto_config c;
  struct rtable_config *peer;		/* Table we're connected to */
  const net_addr *in_subprefix;
  u8 max_generation;
};

struct stats_proto {
  struct proto p;
  struct channel *pri;
  struct channel *sec;
  struct tbf rl_gen;
};

#endif
