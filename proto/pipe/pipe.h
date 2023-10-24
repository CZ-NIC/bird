/*
 *	BIRD -- Table-to-Table Routing Protocol a.k.a Pipe
 *
 *	(c) 1999 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_PIPE_H_
#define _BIRD_PIPE_H_

struct pipe_config {
  struct proto_config c;
  struct rtable_config *peer;		/* Table we're connected to */
  const net_addr *in_subprefix;
  u8 max_generation;
};

struct pipe_proto {
  struct proto p;
  struct channel *pri;
  struct channel *sec;
  uint pri_flags;
  uint sec_flags;
  struct tbf rl_gen;
};

#define PIPE_FL_RR_BEGIN_PENDING	1	/* Route refresh should start with the first route notified */

#endif

struct import_to_export_reload {
  struct channel_import_request *cir;	/* We can not free this struct before reload finishes. */
  struct channel_feeding_request cfr;	/* New request we actually need - import was changed to feed the other side. */
};
