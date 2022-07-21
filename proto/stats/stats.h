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
  pool *pool;
  u8 max_generation;
  u32 *counters;
  u32 sum;
  timer *timer;
  btime settle;
};

struct stats_channel_config {
  struct channel_config c;
  u8 max_generation;
  btime settle;
};

static inline int
get_stats_sum(struct symbol *sym)
{
  if (sym->ch_config->channel)
    return (int) ((struct stats_channel *) sym->ch_config->channel)->sum;
  else
    return 0;
}

#endif
