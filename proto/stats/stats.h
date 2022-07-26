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
#include "lib/timer.h"

struct stats_channel;

struct stats_config {
  struct proto_config c;
};

struct stats_proto {
  struct proto p;
  struct stats_channel *c;
  struct tbf rl_gen;
};

struct stats_channel {
  struct channel c;
  pool *pool;                     /* copy of procotol pool */
  u32 _counter;			  /* internal counter */
  u32 counter;			  /* publicly accessible counter */
  struct settle_timer *settle_timer;
};

struct stats_channel_config {
  struct channel_config c;
  btime min_settle_time;              /* wait before notifying filters */
  btime max_settle_time;
};

/*
 * get_stats_counter() - extract last notified counter
 *   for specific stats channel if it runs
 *
 */
static inline int
get_stats_counter(struct symbol *sym)
{
  if (sym->ch_config->channel)
    return (int) ((struct stats_channel *) sym->ch_config->channel)->counter;
  else
    return 0;
}

#endif
