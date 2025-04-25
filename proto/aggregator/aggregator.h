/*
 *	BIRD -- Aggregator Pseudoprotocol
 *
 *	(c) 2023--2025 Igor Putovny <igor.putovny@nic.cz>
 *	(c) 2023--2025 Maria Matejka <mq@ucw.cz>
 *	(c) 2025       CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_AGGREGATOR_H_
#define _BIRD_AGGREGATOR_H_

#include "nest/bird.h"
#include "nest/protocol.h"
#include "lib/hash.h"

#define BUCKET_LIST_INIT_SIZE              16
#define POTENTIAL_BUCKETS_BITMAP_INIT_SIZE  8

#define IP4_WITHDRAWAL_MAX_EXPECTED_LIMIT 100
#define IP6_WITHDRAWAL_MAX_EXPECTED_LIMIT 200

enum aggregation_mode {
  NET_AGGR, PREFIX_AGGR,
};

struct aggregator_config {
  struct proto_config c;
  struct channel_config *src, *dst;
  struct aggr_item *aggr_on;
  u32 aggr_on_count;
  u32 aggr_on_da_count;
  const struct f_line *merge_by;
  enum aggregation_mode aggr_mode;
  bool logging;
};

struct aggregator_route {
  struct aggregator_route *next_hash;
  struct aggregator_bucket *bucket;
  struct rte rte;
};

struct aggregator_bucket {
  struct aggregator_bucket *next_hash;
  struct rte *rte;                      /* Pointer to struct aggregator_route.rte */
  struct rte_src *last_src;             /* Which src we announced the bucket last with */
  u32 count;
  u32 hash;
  u32 id;
  struct f_val aggr_data[];
};

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
  struct linpool *bucket_pool;

  /* Routes by net and src */
  HASH(struct aggregator_route) routes;
  struct linpool *route_pool;

  /* Bucket IDs and count */
  struct hmap bucket_id_map;
  int buckets_count;

  /* Aggregator rule */
  struct aggr_item *aggr_on;
  u32 aggr_on_count;
  u32 aggr_on_da_count;

  /* Merge filter */
  const struct f_line *merge_by;
  event reload_buckets;

  /* Aggregation trie */
  struct trie_node *root;
  struct slab *trie_slab;
  u32 addr_type;
  int bitmap_size;
  bool initial_feed;
  bool logging;

  /* Array of bucket pointers */
  struct aggregator_bucket **bucket_list;
  uint bucket_list_size;

  /* Route withdrawal */
  struct rte_withdrawal_item *rte_withdrawal_stack;
  struct linpool *rte_withdrawal_pool;
  int rte_withdrawal_count;

  /* This may be requested as a dump target */
  struct dump_request_target dump_request_target;
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
  UNASSIGNED_FIB,
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
  int potential_buckets_count;
  int depth;
  u32 potential_buckets[];
};

void aggregator_aggregate(struct aggregator_proto *p);
void aggregator_recompute(struct aggregator_proto *p, struct aggregator_route *old, struct aggregator_route *new);
void aggregator_bucket_update(struct aggregator_proto *p, struct aggregator_bucket *bucket, const struct net_addr *addr);

struct trie_node *aggregator_root_init(struct aggregator_bucket *bucket, struct slab *trie_slab);

void aggregator_trie_dump(struct dump_request *dreq);

#endif
