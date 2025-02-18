/*
 *	BIRD -- Aggregator Pseudoprotocol
 *
 *	(c) 2023--2024 Igor Putovny <igor.putovny@nic.cz>
 *	(c) 2023--2024 Maria Matejka <mq@ucw.cz>
 *	(c) 2024       CZ.NIC z.s.p.o.
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

#define BUCKET_LIST_INIT_SIZE         16
#define POTENTIAL_BUCKETS_BITMAP_SIZE 8
#define MAX_POTENTIAL_BUCKETS_COUNT   ((int)(sizeof(u32) * 8 * POTENTIAL_BUCKETS_BITMAP_SIZE))

#define IP4_WITHDRAWAL_LIMIT 100
#define IP6_WITHDRAWAL_LIMIT 200

enum aggregation_mode {
  NET_AGGR, PREFIX_AGGR,
};

struct aggregator_config {
  struct proto_config c;
  struct channel_config *src, *dst;
  enum aggregation_mode aggr_mode;
  uint aggr_on_count;
  uint aggr_on_da_count;
  struct aggr_item *aggr_on;
  const struct f_line *merge_by;
  int logging;
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
  u32 id;
  struct f_val aggr_data[0];
};

/* Structure containing information needed for route withdrawal */
struct rte_withdrawal_item {
  struct rte_withdrawal_item *next;
  struct aggregator_bucket *bucket;
  struct net_addr addr;
};

struct aggregator_proto {
  struct proto p;
  struct channel *src, *dst;
  enum aggregation_mode aggr_mode;

  /* Buckets by aggregator rule */
  HASH(struct aggregator_bucket) buckets;
  linpool *bucket_pool;

  /* Routes by net and src */
  HASH(struct aggregator_route) routes;
  linpool *route_pool;

  /* Aggregator rule */
  uint aggr_on_count;
  uint aggr_on_da_count;
  struct aggr_item *aggr_on;

  /* Merge filter */
  const struct f_line *merge_by;
  event reload_buckets;

  /* Aggregation trie */
  uint addr_type;
  linpool *trie_pool;
  struct trie_node *root;
  int logging;

  /* List of bucket pointers */
  struct aggregator_bucket **bucket_list;
  size_t bucket_list_size;
  size_t bucket_list_count;

  struct hmap bucket_id_map;

  linpool *rte_withdrawal_pool;
  struct rte_withdrawal_item *rte_withdrawal_stack;
  int rte_withdrawal_count;
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

enum fib_status {
  UNASSIGNED_STATUS,
  IN_FIB,
  NON_FIB,
};

enum prefix_origin {
  FILLER,
  ORIGINAL,
  AGGREGATED,
};

struct trie_node {
  struct trie_node *parent;
  struct trie_node *child[2];
  struct trie_node *ancestor;
  struct aggregator_bucket *original_bucket;
  struct aggregator_bucket *selected_bucket;
  enum fib_status status;
  enum prefix_origin px_origin;
  u32 potential_buckets[POTENTIAL_BUCKETS_BITMAP_SIZE];
  int potential_buckets_count;
  int depth;
};

#endif
