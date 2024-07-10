/*
 *	BIRD Internet Routing Daemon -- Route aggregation
 *
 *	(c) 2023--2023 Igor Putovny <igor.putovny@nic.cz>
 *	(c) 2023       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Route aggregation
 *
 * This is an implementation of route aggregation functionality.
 * It enables user to specify a set of route attributes in the configuarion file
 * and then, for a given destination (net), aggregate routes with the same
 * values of these attributes into a single multi-path route.
 *
 * Structure &channel contains pointer to aggregation list which is represented
 * by &aggr_list_linearized. In rt_notify_aggregated(), attributes from this
 * list are evaluated for every route of a given net and results are stored
 * in &rte_val_list which contains pointer to this route and array of &f_val.
 * Array of pointers to &rte_val_list entries is sorted using
 * sort_rte_val_list(). For comparison of &f_val structures, val_compare()
 * is used. Comparator function is written so that sorting is stable. If all
 * attributes have the same values, routes are compared by their global IDs.
 *
 * After sorting, &rte_val_list entries containing equivalent routes will be
 * adjacent to each other. Function process_rte_list() iterates through these
 * entries to identify sequences of equivalent routes. New route will be
 * created for each such sequence, even if only from a single route.
 * Only attributes from the aggreagation list will be set for the new route.
 * New &rta is created and prepare_rta() is used to copy static and dynamic
 * attributes to new &rta from &rta of the original route. New route is created
 * by create_merged_rte() from new &rta and exported to the routing table.
 */

#undef LOCAL_DEBUG

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "nest/bird.h"
#include "nest/iface.h"
#include "filter/filter.h"
#include "proto/aggregator/aggregator.h"
#include "lib/settle.h"

#include <stdlib.h>
#include <assert.h>

extern linpool *rte_update_pool;

static inline int
is_leaf(const struct trie_node *node)
{
  assert(node != NULL);
  return !node->child[0] && !node->child[1];
}

/*
 * Allocate new node in protocol linpool
 */
static inline struct trie_node *
create_new_node(linpool *trie_pool)
{
  struct trie_node *node = lp_allocz(trie_pool, sizeof(*node));
  return node;
}

/*
 * Mark appropriate child of parent node as NULL
 */
static inline void
remove_node(struct trie_node *node)
{
  assert(node != NULL);
  assert(node->child[0] == NULL && node->child[1] == NULL);

  if (!node->parent)
    ;
  else
  {
    if (node->parent->child[0] == node)
      node->parent->child[0] = NULL;
    else if (node->parent->child[1] == node)
      node->parent->child[1] = NULL;
    else
      bug("Invalid child pointer");
  }
}

/*
 * Insert prefix in @addr to prefix trie with beginning at @root and assign @bucket to this prefix
 */
static void
trie_insert_prefix_ip4(const struct net_addr_ip4 *addr, struct trie_node *const root, struct aggregator_bucket *bucket, linpool *trie_pool)
{
  assert(addr != NULL);
  assert(bucket != NULL);
  assert(root != NULL);
  assert(trie_pool != NULL);

  struct trie_node *node = root;

  for (u32 i = 0; i < addr->pxlen; i++)
  {
    u32 bit = ip4_getbit(addr->prefix, i);

    if (!node->child[bit])
    {
      struct trie_node *new = create_new_node(trie_pool);
      new->parent = node;
      node->child[bit] = new;
      new->depth = new->parent->depth + 1;
    }

    node = node->child[bit];
  }

  /* Assign bucket to the last node */
  node->bucket = bucket;
}

static void
trie_insert_prefix_ip6(const struct net_addr_ip6 *addr, struct trie_node * const root, struct aggregator_bucket *bucket, linpool *trie_pool)
{
  assert(addr != NULL);
  assert(bucket != NULL);
  assert(root != NULL);
  assert(trie_pool != NULL);

  struct trie_node *node = root;

  for (u32 i = 0; i < addr->pxlen; i++)
  {
    u32 bit = ip6_getbit(addr->prefix, i);

    if (!node->child[bit])
    {
      struct trie_node *new = create_new_node(trie_pool);
      new->parent = node;
      node->child[bit] = new;
      new->depth = new->parent->depth + 1;
    }

    node = node->child[bit];
  }

  /* Assign bucket to the last node */
  node->bucket = bucket;
}

/*
 * Return first non-null bucket of the closest ancestor of @node
 */
static struct aggregator_bucket *
get_ancestor_bucket(const struct trie_node *node)
{
  /* Defined for other than root nodes */
  while (1)
  {
    if (!node->parent)
      return node->bucket;

    if (node->parent->bucket)
      return node->parent->bucket;

    node = node->parent;
  }
}

/*
 * First pass of Optimal Route Table Construction (ORTC) algorithm
 */
static void
first_pass(struct trie_node *node, linpool *trie_pool)
{
  assert(node != NULL);
  assert(trie_pool != NULL);

  if (is_leaf(node))
  {
    assert(node->bucket != NULL);
    assert(node->potential_buckets_count == 0);
    node->potential_buckets[node->potential_buckets_count++] = node->bucket;
    return;
  }

  /* Root node */
  if (!node->parent)
    assert(node->bucket != NULL);

  /* Initialize bucket from the nearest ancestor that has a bucket */
  if (!node->bucket)
    node->bucket = node->parent->bucket;

  for (int i = 0; i < 2; i++)
  {
    if (!node->child[i])
    {
      struct trie_node *new = create_new_node(trie_pool);
      new->parent = node;
      new->bucket = node->bucket;
      new->depth = node->depth + 1;
      node->child[i] = new;
    }
  }

  if (node->child[0])
    first_pass(node->child[0], trie_pool);

  if (node->child[1])
    first_pass(node->child[1], trie_pool);

  /* Discard bucket information in internal nodes */
  node->bucket = NULL;
}

static void
first_pass_after_check_helper(const struct trie_node *node)
{
  for (int i = 0; i < node->potential_buckets_count; i++)
  {
    for (int j = i + 1; j < node->potential_buckets_count; j++)
    {
      assert(node->potential_buckets[i] != node->potential_buckets[j]);
    }
  }
}

static void
first_pass_after_check(const struct trie_node *node)
{
  first_pass_after_check_helper(node);

  if (node->child[0])
  {
    first_pass_after_check_helper(node->child[0]);
  }

  if (node->child[1])
  {
    first_pass_after_check_helper(node->child[1]);
  }
}

/*
 * Compare buckets by linear ordering on pointers
 */
static int
aggregator_bucket_compare(const struct aggregator_bucket *a, const struct aggregator_bucket *b)
{
  assert(a != NULL);
  assert(b != NULL);

  if ((uintptr_t)a < (uintptr_t)b)
    return -1;

  if ((uintptr_t)a > (uintptr_t)b)
    return 1;

  return 0;
}

static int
aggregator_bucket_compare_wrapper(const void *a, const void *b)
{
  assert(a != NULL);
  assert(b != NULL);

  const struct aggregator_bucket *fst = *(struct aggregator_bucket **)a;
  const struct aggregator_bucket *snd = *(struct aggregator_bucket **)b;

  return aggregator_bucket_compare(fst, snd);
}

/*
 * Compute union of two sets of potential buckets in @left and @right and put result in @node
 */
static void
compute_buckets_union(struct trie_node *node, const struct trie_node *left, const struct trie_node *right)
{
  assert(left  != NULL);
  assert(right != NULL);
  assert(node  != NULL);

  struct aggregator_bucket *input_buckets[MAX_POTENTIAL_BUCKETS_COUNT * 2] = { 0 };
  const int input_count = left->potential_buckets_count + right->potential_buckets_count;

  memcpy(input_buckets, left->potential_buckets, sizeof(input_buckets[0]) * left->potential_buckets_count);
  memcpy(&input_buckets[left->potential_buckets_count], right->potential_buckets, sizeof(input_buckets[0]) * right->potential_buckets_count);
  qsort(input_buckets, input_count, sizeof(input_buckets[0]), aggregator_bucket_compare_wrapper);

  struct aggregator_bucket *output_buckets[ARRAY_SIZE(input_buckets)] = { 0 };
  int output_count = 0;

  for (int i = 0; i < input_count; i++)
  {
    /*
     * Don't copy element if it's the same as the last inserted element
     * to avoid duplicates
     */
    if (output_count != 0 && output_buckets[output_count - 1] == input_buckets[i])
      continue;

    output_buckets[output_count++] = input_buckets[i];
  }

  // strictly greater
  for (int i = 1; i < output_count; i++)
    assert(output_buckets[i - 1] < output_buckets[i]);

  // duplicates
  for (int i = 0; i < output_count; i++)
    for (int j = i + 1; j < output_count; j++)
      assert(output_buckets[i] != output_buckets[j]);

  node->potential_buckets_count = output_count < MAX_POTENTIAL_BUCKETS_COUNT ? output_count : MAX_POTENTIAL_BUCKETS_COUNT;
  memcpy(node->potential_buckets, output_buckets, sizeof(node->potential_buckets[0]) * node->potential_buckets_count);
}

/*
 * Compute intersection of two sets of potential buckets in @left and @right and put result in @node
 */
static void
compute_buckets_intersection(struct trie_node *node, const struct trie_node *left, const struct trie_node *right)
{
  assert(left  != NULL);
  assert(right != NULL);
  assert(node  != NULL);

  struct aggregator_bucket *fst[MAX_POTENTIAL_BUCKETS_COUNT] = { 0 };
  struct aggregator_bucket *snd[MAX_POTENTIAL_BUCKETS_COUNT] = { 0 };

  memcpy(fst, left->potential_buckets,  sizeof(fst[0]) * left->potential_buckets_count);
  memcpy(snd, right->potential_buckets, sizeof(snd[0]) * right->potential_buckets_count);

  qsort(fst, left->potential_buckets_count,  sizeof(fst[0]), aggregator_bucket_compare_wrapper);
  qsort(snd, right->potential_buckets_count, sizeof(snd[0]), aggregator_bucket_compare_wrapper);

  struct aggregator_bucket *output[ARRAY_SIZE(fst) + ARRAY_SIZE(snd)] = { 0 };
  int output_count = 0;

  int i = 0;
  int j = 0;

  while (i < left->potential_buckets_count && j < right->potential_buckets_count)
  {
    int res = aggregator_bucket_compare(fst[i], snd[j]);

    if (res == 0)
    {
      output[output_count++] = fst[i];
      i++;
      j++;
    }
    else if (res == -1)
      i++;
    else if (res == 1)
      j++;
    else
      bug("Impossible");
  }

  // strictly greater
  for (int k = 1; k < output_count; k++)
    assert(output[k - 1] < output[k]);

  // duplicates
  for (int k = 0; k < output_count; k++)
    for (int l = k + 1; l < output_count; l++)
      assert(output[k] != output[l]);

  node->potential_buckets_count = output_count < MAX_POTENTIAL_BUCKETS_COUNT ? output_count : MAX_POTENTIAL_BUCKETS_COUNT;
  memcpy(node->potential_buckets, output, sizeof(node->potential_buckets[0]) * node->potential_buckets_count);
}

/*
 * Check if sets of potential buckets of two nodes are disjoint
 */
static int
bucket_sets_are_disjoint(const struct trie_node *left, const struct trie_node *right)
{
  assert(left != NULL);
  assert(right != NULL);

  if (left->potential_buckets_count == 0 || right->potential_buckets_count == 0)
  {
    log("Buckets are disjoint");
    return 1;
  }

  int i = 0;
  int j = 0;

  while (i < left->potential_buckets_count && j < right->potential_buckets_count)
  {
    int res = aggregator_bucket_compare(left->potential_buckets[i], right->potential_buckets[j]);

    if (res == 0)
      return 0;
    else if (res == -1)
      i++;
    else if (res == 1)
      j++;
    else
      bug("Impossible");
  }

  return 1;
}

/*
 * Second pass of Optimal Route Table Construction (ORTC) algorithm
 */
static void
second_pass(struct trie_node *node)
{
  assert(node != NULL);
  assert(node->potential_buckets_count <= MAX_POTENTIAL_BUCKETS_COUNT);

  if (is_leaf(node))
  {
    assert(node->potential_buckets_count == 1);
    assert(node->potential_buckets[0] != NULL);
    assert(node->potential_buckets[0] == node->bucket);
    return;
  }

  /* Internal node */
  assert(node->potential_buckets_count == 0);

  struct trie_node * const left = node->child[0];
  struct trie_node * const right = node->child[1];

  assert(left != NULL);
  assert(right != NULL);

  /* Postorder traversal */
  second_pass(left);
  second_pass(right);

  // duplicates
  for (int i = 0; i < left->potential_buckets_count; i++)
    for (int j = i + 1; j < left->potential_buckets_count; j++)
      assert(left->potential_buckets[i] != left->potential_buckets[j]);

  for (int i = 0; i < right->potential_buckets_count; i++)
    for (int j = i + 1; j < right->potential_buckets_count; j++)
      assert(right->potential_buckets[i] != right->potential_buckets[j]);

  /*
   * If there are no common buckets among children's buckets, parent's
   * buckets are computed as union of its children's buckets.
   * Otherwise, parent's buckets are computed as intersection of its
   * children's buckets.
   */
  if (bucket_sets_are_disjoint(left, right))
    compute_buckets_union(node, left, right);
  else
    compute_buckets_intersection(node, left, right);
}

/*
 * Check if @bucket is one of potential buckets in @node
 */
static int
is_bucket_potential(const struct trie_node *node, const struct aggregator_bucket *bucket)
{
  for (int i = 0; i < node->potential_buckets_count; i++)
    if (node->potential_buckets[i] == bucket)
      return 1;

  return 0;
}

static void
remove_potential_buckets(struct trie_node *node)
{
  for (int i = 0; i < node->potential_buckets_count; i++)
    node->potential_buckets[i] = NULL;

  node->potential_buckets_count = 0;
}

/*
 * Third pass of Optimal Route Table Construction (ORTC) algorithm
 */
static void
third_pass(struct trie_node *node)
{
  assert(node != NULL);
  assert(node->potential_buckets_count <= MAX_POTENTIAL_BUCKETS_COUNT);

  /* Root is assigned any of its potential buckets */
  if (!node->parent)
  {
    assert(node->potential_buckets_count > 0);
    assert(node->potential_buckets[0] != NULL);
    node->bucket = node->potential_buckets[0];
  }
  else
  {
    // Internal nodes should not have a bucket since it was deleted during first pass
    if (!is_leaf(node))
      assert(node->bucket == NULL);

    const struct aggregator_bucket *inherited_bucket = get_ancestor_bucket(node);

    /*
     * If bucket inherited from ancestor is one of potential buckets of this node,
     * then this node doesn't need bucket because it inherits one.
     */
    if (is_bucket_potential(node, inherited_bucket))
    {
      node->bucket = NULL;
      remove_potential_buckets(node);
    }
    else
    {
      assert(node->potential_buckets_count > 0);
      node->bucket = node->potential_buckets[0];
    }
  }

  /* Preorder traversal */
  if (node->child[0])
    third_pass(node->child[0]);

  if (node->child[1])
    third_pass(node->child[1]);

  /* Leaves with no assigned bucket are removed */
  if (!node->bucket && is_leaf(node))
    remove_node(node);
}

static void
get_trie_prefix_count_helper(const struct trie_node *node, int *count)
{
  if (is_leaf(node))
  {
    *count += 1;
    return;
  }

  if (node->child[0])
    get_trie_prefix_count_helper(node->child[0], count);
 
  if (node->child[1])
    get_trie_prefix_count_helper(node->child[1], count);
}

static int
get_trie_prefix_count(const struct trie_node *node)
{
  int count = 0;
  get_trie_prefix_count_helper(node, &count);

  return count;
}

static void
get_trie_depth_helper(const struct trie_node *node, int *result, int depth)
{
  if (is_leaf(node))
  {
    if (depth > *result)
      *result = depth;

    return;
  }

  if (node->child[0])
    get_trie_depth_helper(node->child[0], result, depth + 1);

  if (node->child[1])
    get_trie_depth_helper(node->child[1], result, depth + 1);
}

static int
get_trie_depth(const struct trie_node *node)
{
  int result = 0;
  get_trie_depth_helper(node, &result, 0);

  return result;
}

static void
print_prefixes_ip4_helper(const struct trie_node *node, struct net_addr_ip4 *addr, int depth)
{
  assert(node != NULL);

  if (is_leaf(node))
  {
    log("%N -> %p", addr, node->bucket);
    return;
  }

  if (node->bucket)
  {
    log("%N -> %p", addr, node->bucket);
  }

  if (node->child[0])
  {
    ip4_clrbit(&addr->prefix, depth);
    addr->pxlen = depth + 1;
    print_prefixes_ip4_helper(node->child[0], addr, depth + 1);
  }

  if (node->child[1])
  {
    ip4_setbit(&addr->prefix, depth);
    addr->pxlen = depth + 1;
    print_prefixes_ip4_helper(node->child[1], addr, depth + 1);
    ip4_clrbit(&addr->prefix, depth);
  }
}

static void
print_prefixes_ip6_helper(const struct trie_node *node, struct net_addr_ip6 *addr, int depth)
{
  assert(node != NULL);

  if (is_leaf(node))
  {
    log("%N -> %p", addr, node->bucket);
    return;
  }

  if (node->bucket)
  {
    log("%N -> %p", addr, node->bucket);
  }

  if (node->child[0])
  {
    ip6_clrbit(&addr->prefix, depth);
    addr->pxlen = depth + 1;
    print_prefixes_ip6_helper(node->child[0], addr, depth + 1);
  }

  if (node->child[1])
  {
    ip6_setbit(&addr->prefix, depth);
    addr->pxlen = depth + 1;
    print_prefixes_ip6_helper(node->child[1], addr, depth + 1);
    ip6_clrbit(&addr->prefix, depth);
  }
}

static void
print_prefixes(const struct trie_node *node, int type)
{
  if (type == NET_IP4)
  {
    struct net_addr_ip4 addr = { 0 };
    net_fill_ip4((net_addr *)&addr, IP4_NONE, 0);
    print_prefixes_ip4_helper(node, &addr, 0);
  }
  else if (type == NET_IP6)
  {
    struct net_addr_ip6 addr = { 0 };
    net_fill_ip6((net_addr *)&addr, IP6_NONE, 0);
    print_prefixes_ip6_helper(node, &addr, 0);
  }
}

static void aggregator_bucket_update(struct aggregator_proto *p, struct aggregator_bucket *bucket, struct network *net);

/*
 * Create route for aggregated prefix
 */
static void
create_route_ip4(struct aggregator_proto *p, struct aggregator_bucket *bucket, const struct net_addr_ip4 *addr)
{
  struct {
    struct network net;
    union net_addr_union u;
  } net_placeholder;

  assert(addr->type == NET_IP4);
  net_copy_ip4((struct net_addr_ip4 *)&net_placeholder.net.n.addr, addr);
  aggregator_bucket_update(p, bucket, &net_placeholder.net);
}

static void
create_route_ip6(struct aggregator_proto *p, struct aggregator_bucket *bucket, const struct net_addr_ip6 *addr)
{
  struct {
    struct network n;
    union net_addr_union u;
  } net_placeholder;

  assert(addr->type == NET_IP6);
  net_copy_ip6((struct net_addr_ip6 *)&net_placeholder.n.n.addr, addr);
  aggregator_bucket_update(p, bucket, &net_placeholder.n);
}

static void
collect_prefixes_ip4_helper(struct aggregator_proto *p, struct net_addr_ip4 *addr, const struct trie_node *node, int *count, int depth)
{
  assert(node != NULL);

  if (is_leaf(node))
  {
    assert(node->bucket != NULL);
    create_route_ip4(p, node->bucket, addr);
    *count += 1;
    p->leaves++;
    return;
  }

  /* Internal node with assigned bucket */
  if (node->bucket)
  {
    create_route_ip4(p, node->bucket, addr);
    *count += 1;
    p->internal_nodes++;
  }

  if (node->child[0])
  {
    ip4_clrbit(&addr->prefix, depth);
    addr->pxlen = depth + 1;
    collect_prefixes_ip4_helper(p, addr, node->child[0], count, depth + 1);
  }

  if (node->child[1])
  {
    ip4_setbit(&addr->prefix, depth);
    addr->pxlen = depth + 1;
    collect_prefixes_ip4_helper(p, addr, node->child[1], count, depth + 1);
    ip4_clrbit(&addr->prefix, depth);
  }
}

static void
collect_prefixes_ip6_helper(struct aggregator_proto *p, struct net_addr_ip6 *addr, const struct trie_node *node, int *count, int depth)
{
  assert(node != NULL);

  if (is_leaf(node))
  {
    assert(node->bucket != NULL);
    create_route_ip6(p, node->bucket, addr);
    *count += 1;
    p->leaves++;
    return;
  }

  /* Internal node with assigned bucket */
  if (node->bucket)
  {
    create_route_ip6(p, node->bucket, addr);
    *count += 1;
    p->internal_nodes++;
  }

  if (node->child[0])
  {
    ip6_clrbit(&addr->prefix, depth);
    addr->pxlen = depth + 1;
    collect_prefixes_ip6_helper(p, addr, node->child[0], count, depth + 1);
  }

  if (node->child[1])
  {
    ip6_setbit(&addr->prefix, depth);
    addr->pxlen = depth + 1;
    collect_prefixes_ip6_helper(p, addr, node->child[1], count, depth + 1);
    ip6_clrbit(&addr->prefix, depth);
  }
}

static void
collect_prefixes(struct aggregator_proto *p)
{
  int count = 0;

  if (p->addr_type == NET_IP4)
  {
    struct net_addr_ip4 addr = { 0 };
    net_fill_ip4((net_addr *)&addr, IP4_NONE, 0);
    collect_prefixes_ip4_helper(p, &addr, p->root, &count, 0);
  }
  else if (p->addr_type == NET_IP6)
  {
    struct net_addr_ip6 addr = { 0 };
    net_fill_ip6((net_addr *)&addr, IP6_NONE, 0);
    collect_prefixes_ip6_helper(p, &addr, p->root, &count, 0);
  }
  else
    bug("Invalid NET type");

  p->after_count = count;
}

static void
construct_trie(struct aggregator_proto *p)
{
  HASH_WALK(p->buckets, next_hash, bucket)
  {
    for (const struct rte *rte = bucket->rte; rte; rte = rte->next)
    {
      union net_addr_union *uptr = (net_addr_union *)rte->net->n.addr;
      assert(uptr->n.type == NET_IP4 || uptr->n.type == NET_IP6);

      if (uptr->n.type == NET_IP4)
      {
        const struct net_addr_ip4 *addr = &uptr->ip4;
        trie_insert_prefix_ip4(addr, p->root, bucket, p->trie_pool);
        log("INSERT %N", addr);
        p->before_count++;
      }
      else if (uptr->n.type == NET_IP6)
      {
        const struct net_addr_ip6 *addr = &uptr->ip6;
        trie_insert_prefix_ip6(addr, p->root, bucket, p->trie_pool);
        log("INSERT %N", addr);
        p->before_count++;
      }
      else
        bug("Invalid NET type");
    }
  }
  HASH_WALK_END;
}

/*
 * Run Optimal Routing Table Constructor (ORTC) algorithm
 */
static void
calculate_trie(struct aggregator_proto *p)
{
  assert(p->addr_type == NET_IP4 || p->addr_type == NET_IP6);

  log("====PREFIXES BEFORE ====");

  log("====FIRST PASS====");
  first_pass(p->root, p->trie_pool);
  first_pass_after_check(p->root);
  print_prefixes(p->root, p->addr_type);

  second_pass(p->root);
  log("====SECOND PASS====");
  print_prefixes(p->root, p->addr_type);

  third_pass(p->root);
  log("====THIRD PASS====");
  print_prefixes(p->root, p->addr_type);

}

static void
run_aggregation(struct aggregator_proto *p)
{
  assert(p->root != NULL);
  log("==== AGGREGATION START ====");

  construct_trie(p);
  calculate_trie(p);
  collect_prefixes(p);

  log("%d prefixes before aggregation", p->before_count);
  log("%d prefixes after aggregation", p->after_count);
  log("%d internal nodes with bucket", p->internal_nodes);
  log("%d leaves with bucket", p->leaves);
  log("==== AGGREGATION DONE ====");
}

static void
flush_aggregator(struct aggregator_proto *p)
{
  lp_flush(p->bucket_pool);
  lp_flush(p->route_pool);
  lp_flush(p->trie_pool);
}

static void
request_feed_on_settle_timer(struct settle *s)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, s->tm.data);

  assert(PREFIX_AGGR == p->aggr_mode);
  log("Request feed on settle timer: aggr mode is PREFIX_AGGR");
  assert(p->root == NULL);

  log("Request feed on settle timer: requesting feed on src channel");
  channel_request_feeding(p->src);
}

static void trie_init(struct aggregator_proto *p);

static void
aggregate_on_feed_end(struct channel *C)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, C->proto);

  assert(PREFIX_AGGR == p->aggr_mode);
  assert(p->root == NULL);

  if (C == p->src)
  {
    trie_init(p);
    run_aggregation(p);
    flush_aggregator(p);

    p->root = NULL;
    p->before_count = 0;
    p->after_count = 0;
    p->internal_nodes = 0;
    p->leaves = 0;

    if (p->first_run)
      p->first_run = 0;
  }
}

/*
 * Set static attribute in @rta from static attribute in @old according to @sa.
 */
static void
rta_set_static_attr(struct rta *rta, const struct rta *old, struct f_static_attr sa)
{
  switch (sa.sa_code)
  {
    case SA_NET:
      break;

    case SA_FROM:
      rta->from = old->from;
      break;

    case SA_GW:
      rta->dest = RTD_UNICAST;
      rta->nh.gw = old->nh.gw;
      rta->nh.iface = old->nh.iface;
      rta->nh.next = NULL;
      rta->hostentry = NULL;
      rta->nh.labels = 0;
      break;

    case SA_SCOPE:
      rta->scope = old->scope;
      break;

    case SA_DEST:
      rta->dest = old->dest;
      rta->nh.gw = IPA_NONE;
      rta->nh.iface = NULL;
      rta->nh.next = NULL;
      rta->hostentry = NULL;
      rta->nh.labels = 0;
      break;

    case SA_IFNAME:
      rta->dest = RTD_UNICAST;
      rta->nh.gw = IPA_NONE;
      rta->nh.iface = old->nh.iface;
      rta->nh.next = NULL;
      rta->hostentry = NULL;
      rta->nh.labels = 0;
      break;

    case SA_GW_MPLS:
      rta->nh.labels = old->nh.labels;
      memcpy(&rta->nh.label, &old->nh.label, sizeof(u32) * old->nh.labels);
      break;

    case SA_WEIGHT:
      rta->nh.weight = old->nh.weight;
      break;

    case SA_PREF:
      rta->pref = old->pref;
      break;

    default:
      bug("Invalid static attribute access (%u/%u)", sa.f_type, sa.sa_code);
  }
}

/*
 * Compare list of &f_val entries.
 * @count: number of &f_val entries
 */
static int
same_val_list(const struct f_val *v1, const struct f_val *v2, uint len)
{
  for (uint i = 0; i < len; i++)
    if (!val_same(&v1[i], &v2[i]))
      return 0;

  return 1;
}

/*
 * Create and export new merged route
 */
static void
aggregator_bucket_update(struct aggregator_proto *p, struct aggregator_bucket *bucket, struct network *net)
{
  /* Empty bucket */
  if (!bucket->rte)
  {
    rte_update2(p->dst, net->n.addr, NULL, bucket->last_src);
    bucket->last_src = NULL;
    return;
  }

  /* Allocate RTA and EA list */
  struct rta *rta = allocz(rta_size(bucket->rte->attrs));
  rta->dest = RTD_UNREACHABLE;
  rta->source = RTS_AGGREGATED;
  rta->scope = SCOPE_UNIVERSE;

  struct ea_list *eal = allocz(sizeof(*eal) + sizeof(struct eattr) * p->aggr_on_da_count);
  eal->next = NULL;
  eal->count = 0;
  rta->eattrs = eal;

  /* Seed the attributes from aggregator rule */
  for (uint i = 0; i < p->aggr_on_count; i++)
  {
    if (p->aggr_on[i].type == AGGR_ITEM_DYNAMIC_ATTR)
    {
      u32 ea_code = p->aggr_on[i].da.ea_code;
      const struct eattr *e = ea_find(bucket->rte->attrs->eattrs, ea_code);

      if (e)
        eal->attrs[eal->count++] = *e;
    }
    else if (p->aggr_on[i].type == AGGR_ITEM_STATIC_ATTR)
      rta_set_static_attr(rta, bucket->rte->attrs, p->aggr_on[i].sa);
  }

  struct rte *new = rte_get_temp(rta, p->p.main_source);
  new->net = net;

  log("=============== CREATE MERGED ROUTE ===============");
  log("New route created: id = %d, protocol: %s", new->src->global_id, new->src->proto->name);
  log("===================================================");

  /* merge filter needs one argument called "routes" */
  struct f_val val = {
    .type = T_ROUTES_BLOCK,
    .val.rte = bucket->rte,
  };

  /* Actually run the filter */
  enum filter_return fret = f_eval_rte(p->merge_by, &new, rte_update_pool, 1, &val, 0);

  /* Src must be stored now, rte_update2() may return new */
  struct rte_src *new_src = new ? new->src : NULL;

  /* Finally import the route */
  switch (fret)
  {
    /* Pass the route to the protocol */
    case F_ACCEPT:
      rte_update2(p->dst, net->n.addr, new, bucket->last_src ?: new->src);
      break;

    /* Something bad happened */
    default:
      ASSERT_DIE(fret == F_ERROR);
      /* fall through */

    /* We actually don't want this route */
    case F_REJECT:
      if (bucket->last_src)
	rte_update2(p->dst, net->n.addr, NULL, bucket->last_src);
      break;
  }

  /* Switch source lock for bucket->last_src */
  if (bucket->last_src != new_src)
  {
    if (new_src)
      rt_lock_source(new_src);
    if (bucket->last_src)
      rt_unlock_source(bucket->last_src);

    bucket->last_src = new_src;
  }
}

/*
 * Reload all the buckets on reconfiguration if merge filter has changed.
 * TODO: make this splitted
 */
static void
aggregator_reload_buckets(void *data)
{
  struct aggregator_proto *p = data;

  HASH_WALK(p->buckets, next_hash, b)
    if (b->rte)
    {
      aggregator_bucket_update(p, b, b->rte->net);
      lp_flush(rte_update_pool);
    }
  HASH_WALK_END;
}


/*
 * Evaluate static attribute of @rt1 according to @sa
 * and store result in @pos.
 */
static void
eval_static_attr(const struct rte *rt1, struct f_static_attr sa, struct f_val *pos)
{
  const struct rta *rta = rt1->attrs;

#define RESULT(_type, value, result)    \
  do {                                  \
    pos->type = _type;                  \
    pos->val.value = result;            \
  } while (0)

  switch (sa.sa_code)
  {
    case SA_NET:	RESULT(sa.f_type, net, rt1->net->n.addr); break;
    case SA_FROM:       RESULT(sa.f_type, ip, rta->from); break;
    case SA_GW:	        RESULT(sa.f_type, ip, rta->nh.gw); break;
    case SA_PROTO:	    RESULT(sa.f_type, s, rt1->src->proto->name); break;
    case SA_SOURCE:	    RESULT(sa.f_type, i, rta->source); break;
    case SA_SCOPE:	    RESULT(sa.f_type, i, rta->scope); break;
    case SA_DEST:	    RESULT(sa.f_type, i, rta->dest); break;
    case SA_IFNAME:	    RESULT(sa.f_type, s, rta->nh.iface ? rta->nh.iface->name : ""); break;
    case SA_IFINDEX:	RESULT(sa.f_type, i, rta->nh.iface ? rta->nh.iface->index : 0); break;
    case SA_WEIGHT:	    RESULT(sa.f_type, i, rta->nh.weight + 1); break;
    case SA_PREF:	    RESULT(sa.f_type, i, rta->pref); break;
    case SA_GW_MPLS:    RESULT(sa.f_type, i, rta->nh.labels ? rta->nh.label[0] : MPLS_NULL); break;
    default:
      bug("Invalid static attribute access (%u/%u)", sa.f_type, sa.sa_code);
  }

#undef RESULT
}

/*
 * Evaluate dynamic attribute of @rt1 according to @da
 * and store result in @pos.
 */
static void
eval_dynamic_attr(const struct rte *rt1, struct f_dynamic_attr da, struct f_val *pos)
{
  const struct rta *rta = rt1->attrs;
  const struct eattr *e = ea_find(rta->eattrs, da.ea_code);

#define RESULT(_type, value, result)    \
  do {                                  \
    pos->type = _type;                  \
    pos->val.value = result;            \
  } while (0)

#define RESULT_VOID         \
  do {                      \
    pos->type = T_VOID;     \
  } while (0)

  if (!e)
  {
    /* A special case: undefined as_path looks like empty as_path */
    if (da.type == EAF_TYPE_AS_PATH)
    {
      RESULT(T_PATH, ad, &null_adata);
      return;
    }

    /* The same special case for int_set */
    if (da.type == EAF_TYPE_INT_SET)
    {
      RESULT(T_CLIST, ad, &null_adata);
      return;
    }

    /* The same special case for ec_set */
    if (da.type == EAF_TYPE_EC_SET)
    {
      RESULT(T_ECLIST, ad, &null_adata);
      return;
    }

    /* The same special case for lc_set */
    if (da.type == EAF_TYPE_LC_SET)
    {
      RESULT(T_LCLIST, ad, &null_adata);
      return;
    }

    /* Undefined value */
    RESULT_VOID;
    return;
  }

  switch (e->type & EAF_TYPE_MASK)
  {
    case EAF_TYPE_INT:
      RESULT(da.f_type, i, e->u.data);
      break;
    case EAF_TYPE_ROUTER_ID:
      RESULT(T_QUAD, i, e->u.data);
      break;
    case EAF_TYPE_OPAQUE:
      RESULT(T_ENUM_EMPTY, i, 0);
      break;
    case EAF_TYPE_IP_ADDRESS:
      RESULT(T_IP, ip, *((ip_addr *) e->u.ptr->data));
      break;
    case EAF_TYPE_AS_PATH:
      RESULT(T_PATH, ad, e->u.ptr);
      break;
    case EAF_TYPE_BITFIELD:
      RESULT(T_BOOL, i, !!(e->u.data & (1u << da.bit)));
      break;
    case EAF_TYPE_INT_SET:
      RESULT(T_CLIST, ad, e->u.ptr);
      break;
    case EAF_TYPE_EC_SET:
      RESULT(T_ECLIST, ad, e->u.ptr);
      break;
    case EAF_TYPE_LC_SET:
      RESULT(T_LCLIST, ad, e->u.ptr);
      break;
    default:
      bug("Unknown dynamic attribute type");
  }

#undef RESULT
#undef RESULT_VOID
}

static inline u32 aggr_route_hash(const rte *e)
{
  struct {
    net *net;
    struct rte_src *src;
  } obj = {
    .net = e->net,
    .src = e->src,
  };

  return mem_hash(&obj, sizeof obj);
}

#define AGGR_RTE_KEY(n)			(&(n)->rte)
#define AGGR_RTE_NEXT(n)		((n)->next_hash)
#define AGGR_RTE_EQ(a,b)		(((a)->src == (b)->src) && ((a)->net == (b)->net))
#define AGGR_RTE_FN(_n)			aggr_route_hash(_n)
#define AGGR_RTE_ORDER			4 /* Initial */

#define AGGR_RTE_REHASH			aggr_rte_rehash
#define AGGR_RTE_PARAMS			/8, *2, 2, 2, 4, 24

HASH_DEFINE_REHASH_FN(AGGR_RTE, struct aggregator_route);


#define AGGR_BUCK_KEY(n)		(n)
#define AGGR_BUCK_NEXT(n)		((n)->next_hash)
#define AGGR_BUCK_EQ(a,b)		(((a)->hash == (b)->hash) && (same_val_list((a)->aggr_data, (b)->aggr_data, p->aggr_on_count)))
#define AGGR_BUCK_FN(n)			((n)->hash)
#define AGGR_BUCK_ORDER			4 /* Initial */

#define AGGR_BUCK_REHASH		aggr_buck_rehash
#define AGGR_BUCK_PARAMS		/8, *2, 2, 2, 4, 24

HASH_DEFINE_REHASH_FN(AGGR_BUCK, struct aggregator_bucket);


#define AGGR_DATA_MEMSIZE	(sizeof(struct f_val) * p->aggr_on_count)

static void
aggregator_rt_notify(struct proto *P, struct channel *src_ch, net *net, rte *new, rte *old)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, P);
  ASSERT_DIE(src_ch == p->src);
  struct aggregator_bucket *new_bucket = NULL, *old_bucket = NULL;
  struct aggregator_route *old_route = NULL;

  /* Ignore all updates if protocol is not up */
  if (p->p.proto_state != PS_UP)
    return;

  if (PREFIX_AGGR == p->aggr_mode)
  {
    assert(p->root == NULL);

    /*
     * Don't kick settle timer during initial feed. That would cause
     * cyclic calls to rt_notify() without receiving any new updates.
     */
    if (!p->first_run)
    {
      log("rt notify: kick");
      settle_kick(&p->notify_settle);
    }
  }

  /* Find the objects for the old route */
  if (old)
    old_route = HASH_FIND(p->routes, AGGR_RTE, old);

  if (old_route)
    old_bucket = old_route->bucket;

  /* Find the bucket for the new route */
  if (new)
  {
    /* Routes are identical, do nothing */
    if (old_route && rte_same(&old_route->rte, new))
      return;

    /* Evaluate route attributes. */
    struct aggregator_bucket *tmp_bucket = lp_allocz(p->bucket_pool, sizeof(*tmp_bucket));

    for (uint val_idx = 0; val_idx < p->aggr_on_count; val_idx++)
    {
      int type = p->aggr_on[val_idx].type;

      switch (type)
      {
        case AGGR_ITEM_TERM: {
          const struct f_line *line = p->aggr_on[val_idx].line;
          struct rte *rt1 = new;
          enum filter_return fret = f_eval_rte(line, &new, rte_update_pool, 0, NULL, &tmp_bucket->aggr_data[val_idx]);

          if (rt1 != new)
          {
            rte_free(rt1);
            log(L_WARN "Aggregator rule modifies the route, reverting");
          }

          if (fret > F_RETURN)
            log(L_WARN "%s.%s: Wrong number of items left on stack after evaluation of aggregation list", rt1->src->proto->name, rt1->sender);

          break;
        }

        case AGGR_ITEM_STATIC_ATTR: {
          struct f_val *pos = &tmp_bucket->aggr_data[val_idx];
          eval_static_attr(new, p->aggr_on[val_idx].sa, pos);
          break;
        }

        case AGGR_ITEM_DYNAMIC_ATTR: {
          struct f_val *pos = &tmp_bucket->aggr_data[val_idx];
          eval_dynamic_attr(new, p->aggr_on[val_idx].da, pos);
          break;
        }

        default:
          break;
      }
    }

    /* Compute the hash */
    u64 haux;
    mem_hash_init(&haux);
    for (uint i = 0; i < p->aggr_on_count; i++)
    {
      mem_hash_mix_num(&haux, tmp_bucket->aggr_data[i].type);

#define MX(k) mem_hash_mix(&haux, &IT(k), sizeof IT(k));
#define IT(k) tmp_bucket->aggr_data[i].val.k

      switch (tmp_bucket->aggr_data[i].type)
      {
	case T_VOID:
	  break;
	case T_INT:
	case T_BOOL:
	case T_PAIR:
	case T_QUAD:
	case T_ENUM:
	  MX(i);
	  break;
	case T_EC:
	case T_RD:
	  MX(ec);
	  break;
	case T_LC:
	  MX(lc);
	  break;
	case T_IP:
	  MX(ip);
	  break;
	case T_NET:
	  mem_hash_mix_num(&haux, net_hash(IT(net)));
	  break;
	case T_STRING:
	  mem_hash_mix_str(&haux, IT(s));
	  break;
	case T_PATH_MASK:
	  mem_hash_mix(&haux, IT(path_mask), sizeof(*IT(path_mask)) + IT(path_mask)->len * sizeof (IT(path_mask)->item));
	  break;
	case T_PATH:
	case T_CLIST:
	case T_ECLIST:
	case T_LCLIST:
	  mem_hash_mix(&haux, IT(ad)->data, IT(ad)->length);
	  break;
	case T_PATH_MASK_ITEM:
	case T_ROUTE:
	case T_ROUTES_BLOCK:
	  bug("Invalid type %s in hashing", f_type_name(tmp_bucket->aggr_data[i].type));
	case T_SET:
	  MX(t);
	  break;
	case T_PREFIX_SET:
	  MX(ti);
	  break;
      }
    }

    tmp_bucket->hash = mem_hash_value(&haux);

    /* Find the existing bucket */
    if (new_bucket = HASH_FIND(p->buckets, AGGR_BUCK, tmp_bucket))
      ;
    else
    {
      new_bucket = tmp_bucket;
      HASH_INSERT2(p->buckets, AGGR_BUCK, p->p.pool, new_bucket);
    }

    /* Store the route attributes */
    if (rta_is_cached(new->attrs))
      rta_clone(new->attrs);
    else
      new->attrs = rta_lookup(new->attrs);

    log("new rte: %p, net: %p, src: %p, hash: %x", new, new->net, new->src, aggr_route_hash(new));

    /* Insert the new route into the bucket */
    struct aggregator_route *arte = lp_allocz(p->route_pool, sizeof(*arte));
    *arte = (struct aggregator_route) {
      .bucket = new_bucket,
      .rte = *new,
    };
    arte->rte.next = new_bucket->rte,
    new_bucket->rte = &arte->rte;
    new_bucket->count++;
    HASH_INSERT2(p->routes, AGGR_RTE, p->p.pool, arte);
    log("Inserting rte: %p, arte: %p, net: %p, src: %p, hash: %x", &arte->rte, arte, arte->rte.net, arte->rte.src, aggr_route_hash(&arte->rte));
  }

  /* Remove the old route from its bucket */
  if (old_bucket)
  {
    for (struct rte **k = &old_bucket->rte; *k; k = &(*k)->next)
      if (*k == &old_route->rte)
      {
	*k = (*k)->next;
	break;
      }

    old_bucket->count--;
    HASH_REMOVE2(p->routes, AGGR_RTE, p->p.pool, old_route);
    rta_free(old_route->rte.attrs);
  }

  /* Aggregation within nets allows incremental updates */
  if (NET_AGGR == p->aggr_mode)
  {
    /* Announce changes */
    if (old_bucket)
      aggregator_bucket_update(p, old_bucket, net);

    if (new_bucket && (new_bucket != old_bucket))
      aggregator_bucket_update(p, new_bucket, net);
  }

  /* Cleanup the old bucket if empty */
  if (old_bucket && (!old_bucket->rte || !old_bucket->count))
  {
    ASSERT_DIE(!old_bucket->rte && !old_bucket->count);
    HASH_REMOVE2(p->buckets, AGGR_BUCK, p->p.pool, old_bucket);
  }
}

static int
aggregator_preexport(struct channel *C, struct rte *new)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, C->proto);
  /* Reject our own routes */
  if (new->sender == p->dst)
    return -1;

  /* Disallow aggregating already aggregated routes */
  if (new->attrs->source == RTS_AGGREGATED)
  {
    log(L_ERR "Multiple aggregations of the same route not supported in BIRD 2.");
    return -1;
  }

  return 0;
}

static void
aggregator_postconfig(struct proto_config *CF)
{
  struct aggregator_config *cf = SKIP_BACK(struct aggregator_config, c, CF);

  if (!cf->dst->table)
    cf_error("Source table not specified");

  if (!cf->src->table)
    cf_error("Destination table not specified");

  if (cf->dst->table->addr_type != cf->src->table->addr_type)
    cf_error("Both tables must be of the same type");

  cf->dst->in_filter = cf->src->in_filter;

  cf->src->in_filter = FILTER_REJECT;
  cf->dst->out_filter = FILTER_REJECT;

  cf->dst->debug = cf->src->debug;
}

static struct proto *
aggregator_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, P);
  struct aggregator_config *cf = SKIP_BACK(struct aggregator_config, c, CF);

  proto_configure_channel(P, &p->src, cf->src);
  proto_configure_channel(P, &p->dst, cf->dst);

  p->aggr_mode = cf->aggr_mode;
  p->aggr_on_count = cf->aggr_on_count;
  p->aggr_on_da_count = cf->aggr_on_da_count;
  p->aggr_on = cf->aggr_on;
  p->merge_by = cf->merge_by;
  p->notify_settle_cf = cf->notify_settle_cf;

  P->rt_notify = aggregator_rt_notify;
  P->preexport = aggregator_preexport;
  P->feed_end = aggregate_on_feed_end;

  return P;
}

/*
 * Initialize hash table and create default route
 */
static void
trie_init(struct aggregator_proto *p)
{
  /*
   * Hash tables are initialized in aggregator_start() before the first run.
   * They are initialized here for all subsequent runs.
   */
  if (!p->first_run)
  {
    HASH_INIT(p->buckets, p->p.pool, AGGR_BUCK_ORDER);
    HASH_INIT(p->routes, p->p.pool, AGGR_RTE_ORDER);

    p->reload_buckets = (event) {
      .hook = aggregator_reload_buckets,
      .data = p,
    };
  }

  p->root = create_new_node(p->trie_pool);
  p->root->depth = 1;

  struct network *default_net = NULL;

  if (p->addr_type == NET_IP4)
  {
    default_net = mb_allocz(p->p.pool, sizeof(*default_net) + sizeof(struct net_addr_ip4));
    net_fill_ip4(default_net->n.addr, IP4_NONE, 0);
    log("Creating net %p for default route %N", default_net, default_net->n.addr);
  }
  else if (p->addr_type == NET_IP6)
  {
    default_net = mb_allocz(p->p.pool, sizeof(*default_net) + sizeof(struct net_addr_ip6));
    net_fill_ip6(default_net->n.addr, IP6_NONE, 0);
    log("Creating net %p for default route %N", default_net, default_net->n.addr);
  }

  /* Create route attributes with zero nexthop */
  struct rta rta = { 0 };

  /* Allocate bucket for root node */
  struct aggregator_bucket *new_bucket = lp_allocz(p->bucket_pool, sizeof(*new_bucket));
  u64 haux = 0;
  mem_hash_init(&haux);
  new_bucket->hash = mem_hash_value(&haux);

  struct aggregator_route *arte = lp_allocz(p->route_pool, sizeof(*arte));

  *arte = (struct aggregator_route) {
    .bucket = new_bucket,
    .rte = { .attrs = rta_lookup(&rta) },
  };

  arte->rte.next = new_bucket->rte;
  new_bucket->rte = &arte->rte;
  new_bucket->count++;

  arte->rte.net = default_net;
  default_net->routes = &arte->rte;

  HASH_INSERT2(p->routes, AGGR_RTE, p->p.pool, arte);
  HASH_INSERT2(p->buckets, AGGR_BUCK, p->p.pool, new_bucket);

  /* Assign default route to the root */
  p->root->bucket = new_bucket;
}

static int
aggregator_start(struct proto *P)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, P);

  assert(p->bucket_pool == NULL);
  assert(p->route_pool == NULL);
  assert(p->trie_pool == NULL);

  p->addr_type = p->src->table->addr_type;

  p->bucket_pool = lp_new(P->pool);
  HASH_INIT(p->buckets, P->pool, AGGR_BUCK_ORDER);

  p->route_pool = lp_new(P->pool);
  HASH_INIT(p->routes, P->pool, AGGR_RTE_ORDER);

  p->reload_buckets = (event) {
    .hook = aggregator_reload_buckets,
    .data = p,
  };

  if (PREFIX_AGGR == p->aggr_mode)
  {
    assert(p->trie_pool == NULL);
    p->trie_pool = lp_new(P->pool);
    settle_init(&p->notify_settle, &p->notify_settle_cf, request_feed_on_settle_timer, p);
  }

  p->first_run = 1;

  return PS_UP;
}

static int
aggregator_shutdown(struct proto *P)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, P);

  settle_cancel(&p->notify_settle);

  assert(p->root == NULL);
  flush_aggregator(p);

  return PS_DOWN;
}

static void
aggregator_cleanup(struct proto *P)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, P);

  assert(!tm_active(&p->notify_settle.tm));

  /*
   * Linpools will be freed with other protocol resources but pointers
   * have to be erased because protocol may be started again
   */
  p->bucket_pool = NULL;
  p->route_pool = NULL;
  p->trie_pool = NULL;

  assert(p->root == NULL);
  p->root = NULL;
  p->first_run = 1;

  p->before_count = 0;
  p->after_count = 0;
  p->internal_nodes = 0;
  p->leaves = 0;
}

static int
aggregator_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, P);
  struct aggregator_config *cf = SKIP_BACK(struct aggregator_config, c, CF);

  TRACE(D_EVENTS, "Reconfiguring");

  /* Compare timer configuration */
  if (cf->notify_settle_cf.min != p->notify_settle_cf.min || cf->notify_settle_cf.max != p->notify_settle_cf.max)
    return 0;

  /* Compare numeric values (shortcut) */
  if (cf->aggr_on_count != p->aggr_on_count)
    return 0;

  if (cf->aggr_on_da_count != p->aggr_on_da_count)
    return 0;

  /* Compare aggregator rule */
  for (uint i = 0; i < p->aggr_on_count; i++)
    switch (cf->aggr_on[i].type)
    {
      case AGGR_ITEM_TERM:
	if (!f_same(cf->aggr_on[i].line, p->aggr_on[i].line))
	  return 0;
	break;
      case AGGR_ITEM_STATIC_ATTR:
	if (memcmp(&cf->aggr_on[i].sa, &p->aggr_on[i].sa, sizeof(struct f_static_attr)) != 0)
	  return 0;
	break;
      case AGGR_ITEM_DYNAMIC_ATTR:
	if (memcmp(&cf->aggr_on[i].da, &p->aggr_on[i].da, sizeof(struct f_dynamic_attr)) != 0)
	  return 0;
	break;
      default:
	bug("Broken aggregator rule");
    }

  /* Compare merge filter */
  if (!f_same(cf->merge_by, p->merge_by))
    ev_schedule(&p->reload_buckets);

  p->aggr_on = cf->aggr_on;
  p->merge_by = cf->merge_by;

  return 1;
}

static void
aggregator_get_status(struct proto *P, byte *buf)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, P);

  if (p->p.proto_state == PS_DOWN)
    buf[0] = 0;
  else
  {
    if (PREFIX_AGGR == p->aggr_mode)
      strcpy(buf, "prefix aggregation");
    else
      strcpy(buf, "net aggregation");
  }
}

struct protocol proto_aggregator = {
  .name =		"Aggregator",
  .template =		"aggregator%d",
  .class =		PROTOCOL_AGGREGATOR,
  .preference =		1,
  .channel_mask =	NB_ANY,
  .proto_size =		sizeof(struct aggregator_proto),
  .config_size =	sizeof(struct aggregator_config),
  .postconfig =		aggregator_postconfig,
  .init =		aggregator_init,
  .start =		aggregator_start,
  .shutdown =		aggregator_shutdown,
  .cleanup =           aggregator_cleanup,
  .reconfigure =	aggregator_reconfigure,
  .get_status =        aggregator_get_status,
};

void
aggregator_build(void)
{
  proto_build(&proto_aggregator);
}
