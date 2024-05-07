/*
 *	BIRD -- Aggregator Pseudoprotocol
 *
 *	(c) 2023       Igor Putovny <igor.putovny@nic.cz>
 *	(c) 2023       Maria Matejka <mq@ucw.cz>
 *	(c) 2023       CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	This file contains the data structures used by Babel.
 */

#ifndef _BIRD_AGGREGATOR_H_
#define _BIRD_AGGREGATOR_H_

#include "nest/bird.h"
#include "nest/protocol.h"
#include "lib/hash.h"

struct aggregator_config {
  struct proto_config c;
  struct channel_config *src, *dst;
  const struct f_line *aggr_on;
  const struct f_line *premerge;
  const struct f_line *merge_by;
  uint aggr_on_count;
  u8 aggr_on_net;
};

struct aggregator_route {
  struct aggregator_route *next_hash;
  struct aggregator_route *next_rte;
  struct aggregator_bucket *bucket;
  struct rte rte;
};

struct aggregator_bucket {
  struct aggregator_bucket *next_hash;
  struct aggregator_route *rte;		/* Pointer to struct aggregator_route.rte */
  struct rte_src *last_src;		/* Which src we announced the bucket last with */
  u32 count;
  u32 hash;
  struct f_val aggr_data[0];
};

struct aggregator_proto {
  struct proto p;
  struct channel *src, *dst;

  /* Buckets by aggregator rule */
  HASH(struct aggregator_bucket) buckets;
  slab *bucket_slab;

  /* Routes by net and src */
  HASH(struct aggregator_route) routes;
  slab *route_slab;

  /* Aggregator rule */
  const struct f_line *aggr_on;
  uint aggr_on_count;
  u8 aggr_on_net;

  /* Merge filter */
  const struct f_line *premerge;
  const struct f_line *merge_by;
  event reload_buckets;
};

#endif
