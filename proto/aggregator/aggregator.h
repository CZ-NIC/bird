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
#include "lib/settle.h"

#define MAX_POTENTIAL_BUCKETS_COUNT 16

struct aggregator_config {
  struct proto_config c;
  struct channel_config *src, *dst;
  uint aggr_on_count;
  uint aggr_on_da_count;
  struct aggr_item *aggr_on;
  int net_present;
  const struct f_line *merge_by;
  struct settle_config aggr_timer_cf;
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
  int net_present;

  /* Merge filter */
  const struct f_line *merge_by;
  event reload_buckets;

  /* Aggregation trie */
  uint addr_type;
  slab *trie_slab;
  struct trie_node *root;
  struct settle_config aggr_timer_cf;
  struct settle aggr_timer;
  int before_count;
  int after_count;
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

struct trie_node {
  struct trie_node *parent;
  struct trie_node *child[2];
  struct aggregator_bucket *bucket;
  struct aggregator_bucket *potential_buckets[MAX_POTENTIAL_BUCKETS_COUNT];
  int potential_buckets_count;
  int depth;
};

#endif
