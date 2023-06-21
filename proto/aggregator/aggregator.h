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
  uint aggr_on_count;
  uint aggr_on_da_count;
  struct aggr_item *aggr_on;
  const struct f_line *merge_by;
};

struct aggregator_route {
  struct aggregator_route *next_hash;
  struct aggregator_bucket *bucket;
  struct rte rte;
};

struct aggregator_bucket {
  struct aggregator_bucket *next_hash;
  struct rte *rte;			/* Pointer to struct aggregator_route.rte */
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
  uint aggr_on_count;
  uint aggr_on_da_count;
  struct aggr_item *aggr_on;

  /* Merge filter */
  const struct f_line *merge_by;
  event reload_buckets;
};

enum aggr_item_type {
  AGGR_ITEM_TERM,
  AGGR_ITEM_STATIC_ATTR,
  AGGR_ITEM_DYNAMIC_ATTR,
};

struct aggr_item {
  enum aggr_item_type type;
  union {
    struct f_static_attr sa;
    struct f_dynamic_attr da;
    const struct f_line *line;
  };
};

struct aggr_item_node {
  const struct aggr_item_node *next;
  struct aggr_item i;
};

#endif
