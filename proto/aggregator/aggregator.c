/*
 *	BIRD Internet Routing Daemon -- Route aggregation
 *
 *	(c) 2023--2024 Igor Putovny <igor.putovny@nic.cz>
 *	(c) 2024       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Aggregator protocol
 *
 * The purpose of the aggregator protocol is to aggregate routes based on
 * user-specified set of route attributes. It can be used for aggregating
 * routes for a given destination (net) or for aggregating prefixes.
 *
 * Aggregation of routes for networks means that for each destination, routes
 * with the same values of attributes will be aggregated into a single
 * multi-path route. Aggregation is performed by inserting routes into a hash
 * table based on values of their attributes and egenrating new routes from
 * the routes in th same bucket. Buckets are represented by @aggregator_bucket,
 * which contains linked list of @aggregator_route.
 *
 * Aggregation of prefixes aggregates a given set of prefixes into another set
 * of prefixes. It offers a reduction in number of prefixes without changing
 * the routing semantics.
 *
 * Prefix aggregation implements the ORTC (Optimal Route Table Construction)
 * algorithm. This algorithm uses a binary tree representation of the routing
 * table. An edge from the parent node to its left child represents bit 0, and
 * an edge from the parent node to its right child represents bit 1 as the
 * prefix is traversed from the most to the least significant bit. Leaf node
 * of every prefix contains pointer to @aggregator_bucket where the route for
 * this prefix belongs.
 *
 * ORTC algorithm consists of three passes through the trie.
 *
 * The first pass adds new nodes to the trie so that every node has either two
 * or zero children. During this pass, routing information is propagated to the
 * leaves.
 *
 * The second pass finds the most prevalent buckets by pushing information from
 * the leaves up towards the root. Each node is assigned a set of potential
 * buckets. If there are any common buckets among the node's children, they
 * are carried to the parent node. Otherwise, all of children's buckets are
 * carried to the parent node.
 *
 * The third pass moves down the tree, selecting a bucket for the prefix and
 * removing redundant routes. The node inherits a bucket from the closest
 * ancestor node that has a bucket (except for the root node). If the inherited
 * bucket is a member of the node's set of potential buckets, then the node
 * does not need a bucket. Otherwise, the node does need a bucket and any of
 * its potential buckets can be chosen. All leaves which have not been assigned
 * a bucket are removed.
 *
 * The algorithm works on the assumption that there is a default route, that is,
 * the null prefix at the root node has a bucket. This route is created before
 * the aggregation starts.
 *
 * Incorporation of incremental updates of routes has not been implemented yet.
 * The whole trie is rebuilt and aggregation runs all over again when enough
 * updates are collected. To achieve this, the aggregator uses a settle timer
 * configured with two intervals, @min and @max. User can specify these
 * intervals in the configuration file. After receiving an update, settle timer
 * is kicked. If no update is received for interval @min or if @max interval is
 * exceeded, timer triggers and refeed of the source channel is requested. When
 * the refeed ends, all prefixes are inserted into the trie and aggregation
 * algorithm proceeds.
 *
 * Memory for the aggregator is allocated from three linpools: one for buckets,
 * one for routes and one for trie used in prefix aggregation. Obviously, trie
 * linpool is allocated only when aggregating prefixes. Linpools are flushed
 * after prefix aggregation is finished, thus destroying all data structures
 * used.
 *
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

static int total_nodes;
static int prefix_nodes;
static int imaginary_nodes;
static int additional_nodes;
static int removed_nodes;
static int one_child_nodes_1;
static int one_child_nodes_2;

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
  total_nodes++;
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

  removed_nodes++;
}

/*
 * Mark bucket with ID @id as present in bitmap of potential buckets in @node
 */
static inline void
node_insert_potential_bucket(struct trie_node *node, u32 id)
{
  assert(node->potential_buckets_count < MAX_POTENTIAL_BUCKETS_COUNT);

  if (BIT32R_TEST(node->potential_buckets, id))
    return;

  BIT32R_SET(node->potential_buckets, id);
  node->potential_buckets_count++;
}

/*
 * Return pointer to bucket with ID @id.
 * Protocol contains list of pointers to all buckets. Every pointer
 * lies at position equal to bucket ID to enable fast lookup.
 */
static inline struct aggregator_bucket *
get_bucket_ptr(const struct aggregator_proto *p, u32 id)
{
  ASSERT_DIE(id < p->bucket_list_size);
  ASSERT_DIE(p->bucket_list[id] != NULL);
  ASSERT_DIE(p->bucket_list[id]->id == id);
  return p->bucket_list[id];
}

static inline int
popcount32(u32 x)
{
  static const u32 m1  = 0x55555555;
  static const u32 m2  = 0x33333333;
  static const u32 m4  = 0x0f0f0f0f;
  static const u32 m8  = 0x00ff00ff;
  static const u32 m16 = 0x0000ffff;

  x = (x & m1)  + ((x >> 1)  &  m1);
  x = (x & m2)  + ((x >> 2)  &  m2);
  x = (x & m4)  + ((x >> 4)  &  m4);
  x = (x & m8)  + ((x >> 8)  &  m8);
  x = (x & m16) + ((x >> 16) & m16);

  return (int)x;
}

/*
 * If sets of potential buckets in @left and @right have non-empty intersection
 * (computed as bitwise AND), save it to the target bucket. Otherwise compute
 * their union as bitwise OR.
 */
static void
process_potential_buckets(struct trie_node *target, const struct trie_node *left, const struct trie_node *right)
{
  assert(target != NULL);
  assert(left != NULL);
  assert(right != NULL);

  int has_intersection = 0;
  int bucket_count = 0;

  for (int i = 0; i < POTENTIAL_BUCKETS_BITMAP_SIZE; i++)
  {
    has_intersection |= !!(target->potential_buckets[i] = left->potential_buckets[i] & right->potential_buckets[i]);
    bucket_count += popcount32(target->potential_buckets[i]);
  }

  if (!has_intersection)
  {
    bucket_count = 0;

    for (int i = 0; i < POTENTIAL_BUCKETS_BITMAP_SIZE; i++)
    {
      target->potential_buckets[i] = left->potential_buckets[i] | right->potential_buckets[i];
      bucket_count += popcount32(target->potential_buckets[i]);
    }
  }

  /* Update number of potential buckets */
  target->potential_buckets_count = bucket_count;
}

/*
 * Insert @bucket to bucket list in @p to position @bucket-ID
 */
static void
proto_insert_bucket(struct aggregator_proto *p, struct aggregator_bucket *bucket)
{
  if (!p->bucket_list)
  {
    p->bucket_list_size = BUCKET_LIST_INIT_SIZE;
    p->bucket_list = mb_allocz(p->p.pool, sizeof(p->bucket_list[0]) * p->bucket_list_size);
  }

  /* Don't do anything if bucket is already in the list */
  if (bucket->id < p->bucket_list_size && p->bucket_list[bucket->id])
    return;

  const size_t old_size = p->bucket_list_size;

  /* Reallocate if more space is needed because of bucket ID */
  if (bucket->id >= p->bucket_list_size)
  {
    while (bucket->id >= p->bucket_list_size)
      p->bucket_list_size *= 2;

    assert(old_size < p->bucket_list_size);

    p->bucket_list = mb_realloc(p->bucket_list, sizeof(p->bucket_list[0]) * p->bucket_list_size);
    memset(&p->bucket_list[old_size], 0, sizeof(p->bucket_list[0]) * (p->bucket_list_size - old_size));
  }

  assert(bucket->id < p->bucket_list_size);
  assert(p->bucket_list[bucket->id] == NULL);

  p->bucket_list[bucket->id] = bucket;
  p->bucket_list_count++;
}

/*
 * Insert prefix in @addr to prefix trie with beginning at @root and assign @bucket to this prefix
 */
static void
trie_insert_prefix_ip4(struct trie_node * const root, const struct net_addr_ip4 *addr, struct aggregator_bucket *bucket, linpool *trie_pool)
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
      prefix_nodes++;
    }

    node = node->child[bit];
  }

  /* Assign bucket to the last node */
  node->bucket = bucket;
}

static void
trie_insert_prefix_ip6(struct trie_node * const root, const struct net_addr_ip6 *addr, struct aggregator_bucket *bucket, linpool *trie_pool)
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
      prefix_nodes++;
    }

    node = node->child[bit];
  }

  /* Assign bucket to the last node */
  node->bucket = bucket;
}

/*
 * Assign unique ID to all buckets
 */
static void
assign_bucket_id(struct aggregator_proto *p, struct aggregator_bucket *bucket)
{
  assert(p != NULL);
  assert(bucket != NULL);
  assert(bucket->id == 0);

  bucket->id = hmap_first_zero(&p->bucket_id_map);
  hmap_set(&p->bucket_id_map, bucket->id);
}

/*
 * First pass of Optimal Route Table Construction (ORTC) algorithm
 */
static void
first_pass(struct trie_node *node)
{
  assert(node != NULL);

  if (is_leaf(node))
  {
    assert(node->bucket != NULL);
    assert(node->potential_buckets_count == 0);
    node_insert_potential_bucket(node, node->bucket->id);
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
      imaginary_nodes++;
  }

  if (node->child[0])
    first_pass(node->child[0]);

  if (node->child[1])
    first_pass(node->child[1]);
}

/*
 * Second pass of Optimal Route Table Construction (ORTC) algorithm
 */
static void
second_pass(struct aggregator_proto *p, struct trie_node *node)
{
  assert(node != NULL);
  assert(node->potential_buckets_count <= MAX_POTENTIAL_BUCKETS_COUNT);

  if (is_leaf(node))
  {
    assert(node->potential_buckets_count == 1);

    /* The only potential bucket so far is the assigned bucket of the current node */
    assert(BIT32R_TEST(node->potential_buckets, node->bucket->id));
    assert(get_bucket_ptr(p, node->bucket->id) == node->bucket);
    return;
  }

  /* Internal node */
  assert(node->potential_buckets_count == 0);

  struct trie_node *left  = node->child[0];
  struct trie_node *right = node->child[1];

  /* Postorder traversal */
  if (left)
    second_pass(p, left);

  if (right)
    second_pass(p, right);

  assert(node->bucket != NULL);

  /* Imaginary node if this was a complete binary tree */
  struct trie_node imaginary_node = {
    .parent = node,
  };

  /*
   * Imaginary node is used only for computing sets of potential buckets
   * of its parent node.
   */
  node_insert_potential_bucket(&imaginary_node, node->bucket->id);

  /* Nodes with exactly one child */
  if ((left && !right) || (!left && right))
  {
    if (left && !right)
      right = &imaginary_node;
    else if (!left && right)
      left = &imaginary_node;
    else
      bug("Node does not have only one child");

    one_child_nodes_1++;
  }

  assert(left != NULL && right != NULL);

  /*
   * If there are no common buckets among children's buckets, parent's
   * buckets are computed as union of its children's buckets.
   * Otherwise, parent's buckets are computed as intersection of its
   * children's buckets.
   */
  process_potential_buckets(node, left, right);
}

/*
 * Check if @bucket is one of potential buckets in @node
 */
static int
is_bucket_potential(const struct trie_node *node, const struct aggregator_bucket *bucket)
{
  ASSERT_DIE(bucket->id < MAX_POTENTIAL_BUCKETS_COUNT);
  return BIT32R_TEST(node->potential_buckets, bucket->id);
}

static void
remove_potential_buckets(struct trie_node *node)
{
  node->potential_buckets_count = 0;
  memset(node->potential_buckets, 0, sizeof(node->potential_buckets));
}

static void
third_pass_helper(struct aggregator_proto *p, struct trie_node *node)
{
  assert(node != NULL);
  assert(node->potential_buckets_count <= MAX_POTENTIAL_BUCKETS_COUNT);

  /* Bucket inherited from the closest ancestor with a non-null bucket */
  const struct aggregator_bucket *inherited_bucket = node->parent->ancestor->bucket;
  assert(inherited_bucket != NULL);

  /* Save bucket of the current node before it is (potentially) deleted in the next step */
  struct aggregator_bucket * const current_node_bucket = node->bucket;
  assert(current_node_bucket != NULL);

  /*
   * If bucket inherited from ancestor is one of potential buckets of this node,
   * then this node doesn't need a bucket because it inherits one.
   */
  if (is_bucket_potential(node, inherited_bucket))
  {
    node->bucket = NULL;
    remove_potential_buckets(node);
  }
  else
  {
    assert(node->potential_buckets_count > 0);

    /* Assign bucket with the lowest ID to the node */
    for (u32 i = 0; i < MAX_POTENTIAL_BUCKETS_COUNT; i++)
    {
      if (BIT32R_TEST(node->potential_buckets, i))
      {
        node->bucket = get_bucket_ptr(p, i);
        assert(node->bucket != NULL);
        assert(node->bucket->id == i);
        break;
      }
    }
  }

  /*
   * Node with a bucket is the closest ancestor for all his descendants.
   * Otherwise, it must refer to the closest ancestor of its parent.
   */
  node->ancestor = node->bucket ? node : node->parent->ancestor;
  assert(node->ancestor != NULL);
  assert(node->ancestor->bucket != NULL);

  const struct trie_node * const left  = node->child[0];
  const struct trie_node * const right = node->child[1];

  /* Nodes with exactly one child */
  if ((left && !right) || (!left && right))
  {
    /*
     * Imaginary node that would have been added in the first pass.
     * This node inherits bucket from its parent (current node).
     */
    struct trie_node imaginary_node = {
      .parent = node,
      .bucket = current_node_bucket,
      .depth = node->depth + 1,
    };

    node_insert_potential_bucket(&imaginary_node, current_node_bucket->id);

    /*
     * If the current node (parent of the imaginary node) has a bucket,
     * then the imaginary node inherits this bucket.
     * Otherwise it inherits bucket from the closest ancestor with
     * a non-null bucket.
     */
    const struct aggregator_bucket * const imaginary_node_inherited_bucket = node->bucket ? node->bucket : inherited_bucket;

    /*
     * Nodes that would have been added during first pass are not removed only
     * if they have a bucket. And they have a bucket only if their potential
     * bucket is different from the bucket they inherit from their ancestor.
     * If this condition is met, we need to allocate these nodes and
     * connect them to the trie.
     */
    if (!is_bucket_potential(&imaginary_node, imaginary_node_inherited_bucket))
    {
      struct trie_node *new = create_new_node(p->trie_pool);
      *new = imaginary_node;

      if (left && !right)
        node->child[1] = new;
      else if (!left && right)
        node->child[0] = new;
      else
        bug("Node does not have only one child");

      additional_nodes++;
    }

    one_child_nodes_2++;
  }

  /* Preorder traversal */
  if (node->child[0])
    third_pass_helper(p, node->child[0]);

  if (node->child[1])
    third_pass_helper(p, node->child[1]);

  /* Leaves with no assigned bucket are removed */
  if (!node->bucket && is_leaf(node))
    remove_node(node);
}

/*
 * Third pass of Optimal Route Table Construction (ORTC) algorithm
 */
static void
third_pass(struct aggregator_proto *p, struct trie_node *root)
{
  assert(root != NULL);
  assert(root->potential_buckets_count <= MAX_POTENTIAL_BUCKETS_COUNT);
  assert(root->potential_buckets_count > 0);

  /* Assign bucket with the lowest ID to root */
  for (u32 i = 0; i < MAX_POTENTIAL_BUCKETS_COUNT; i++)
  {
    if (BIT32R_TEST(root->potential_buckets, i))
    {
      root->bucket = get_bucket_ptr(p, i);
      assert(root->bucket != NULL);
      assert(root->bucket->id == i);
      break;
    }
  }

  /* The closest ancestor of the root node with a non-null bucket is the root itself */
  root->ancestor = root;

  if (root->child[0])
    third_pass_helper(p, root->child[0]);

  if (root->child[1])
    third_pass_helper(p, root->child[1]);
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
get_trie_node_count_helper(const struct trie_node *node, int *count)
{
  *count += 1;

  if (node->child[0])
    get_trie_node_count_helper(node->child[0], count);

  if (node->child[1])
    get_trie_node_count_helper(node->child[1], count);
}

static int
get_trie_node_count(const struct trie_node *root)
{
  int count = 0;
  get_trie_node_count_helper(root, &count);
  return count;
}

static void
print_prefixes_ip4_helper(struct net_addr_ip4 *addr, const struct trie_node *node, int depth)
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
    print_prefixes_ip4_helper(addr, node->child[0], depth + 1);
  }

  if (node->child[1])
  {
    ip4_setbit(&addr->prefix, depth);
    addr->pxlen = depth + 1;
    print_prefixes_ip4_helper(addr, node->child[1], depth + 1);
    ip4_clrbit(&addr->prefix, depth);
  }
}

static void
print_prefixes_ip6_helper(struct net_addr_ip6 *addr, const struct trie_node *node, int depth)
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
    print_prefixes_ip6_helper(addr, node->child[0], depth + 1);
  }

  if (node->child[1])
  {
    ip6_setbit(&addr->prefix, depth);
    addr->pxlen = depth + 1;
    print_prefixes_ip6_helper(addr, node->child[1], depth + 1);
    ip6_clrbit(&addr->prefix, depth);
  }
}

static void
print_prefixes(const struct trie_node *node, int type)
{
  if (NET_IP4 == type)
  {
    struct net_addr_ip4 addr = { 0 };
    net_fill_ip4((net_addr *)&addr, IP4_NONE, 0);
    print_prefixes_ip4_helper(&addr, node, 0);
  }
  else if (NET_IP6 == type)
  {
    struct net_addr_ip6 addr = { 0 };
    net_fill_ip6((net_addr *)&addr, IP6_NONE, 0);
    print_prefixes_ip6_helper(&addr, node, 0);
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

  if (NET_IP4 == p->addr_type)
  {
    struct net_addr_ip4 addr = { 0 };
    net_fill_ip4((net_addr *)&addr, IP4_NONE, 0);
    collect_prefixes_ip4_helper(p, &addr, p->root, &count, 0);
  }
  else if (NET_IP6 == p->addr_type)
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

      if (NET_IP4 == uptr->n.type)
      {
        const struct net_addr_ip4 *addr = &uptr->ip4;
        trie_insert_prefix_ip4(p->root, addr, bucket, p->trie_pool);
        p->before_count++;

        if (p->logging)
          log("Insert %N", addr);
      }
      else if (NET_IP6 == uptr->n.type)
      {
        const struct net_addr_ip6 *addr = &uptr->ip6;
        trie_insert_prefix_ip6(p->root, addr, bucket, p->trie_pool);
        p->before_count++;

        if (p->logging)
          log("Insert %N", addr);
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

  if (p->logging)
  {
    log("==== PREFIXES BEFORE ====");
    print_prefixes(p->root, p->addr_type);
  }

  times_update(&main_timeloop);
  log("==== FIRST PASS ====");
  first_pass(p->root);
  times_update(&main_timeloop);
  log("==== FIRST PASS DONE ====");

  if (p->logging)
  {
    log("==== FIRST PASS ====");
    print_prefixes(p->root, p->addr_type);
  }

  times_update(&main_timeloop);
  log("==== SECOND PASS ====");
  second_pass(p, p->root);
  times_update(&main_timeloop);
  log("==== SECOND PASS DONE");

  if (p->logging)
  {
    log("==== SECOND PASS ====");
    print_prefixes(p->root, p->addr_type);
  }

  times_update(&main_timeloop);
  log("==== THIRD PASS ====");
  third_pass(p, p->root);
  times_update(&main_timeloop);
  log("==== THIRD PASS DONE ====");

  if (p->logging)
  {
    log("==== THIRD PASS ====");
    print_prefixes(p->root, p->addr_type);
  }

}

static void
run_aggregation(struct aggregator_proto *p)
{
  assert(p->root != NULL);

  times_update(&main_timeloop);

  log("---- AGGREGATION START ----");

  times_update(&main_timeloop);
  log("==== BUILDING TRIE ====");
  construct_trie(p);
  times_update(&main_timeloop);
  log("==== BUILDING TRIE DONE  ====");

  calculate_trie(p);

  times_update(&main_timeloop);
  log("==== COLLECTING PREFIXES ====");
  collect_prefixes(p);
  times_update(&main_timeloop);
  log("==== COLLECTING PREFIXES DONE ====");

  times_update(&main_timeloop);

  log("%d prefixes before aggregation", p->before_count);
  log("%d prefixes after aggregation", p->after_count);
  log("%d internal nodes with bucket", p->internal_nodes);
  log("%d leaves with bucket", p->leaves);

  log("");
  log("%d nodes in total", total_nodes);
  log("%d prefix nodes", prefix_nodes);
  log("%d imaginary nodes", imaginary_nodes);
  log("%d nodes added in the third pass", additional_nodes);
  log("%d nodes removed", removed_nodes);
  log("%d nodes left", get_trie_node_count(p->root));
  log("%d one-child nodes in the second pass", one_child_nodes_1);
  log("%d one-child nodes in the third  pass", one_child_nodes_2);

  total_nodes = prefix_nodes = imaginary_nodes = additional_nodes = removed_nodes = one_child_nodes_1 = one_child_nodes_2 = 0;
  log("---- AGGREGATION DONE ----");
}

static void
flush_aggregator(struct aggregator_proto *p)
{
  lp_flush(p->bucket_pool);
  lp_flush(p->route_pool);
  lp_flush(p->trie_pool);

  memset(p->bucket_list, 0, p->bucket_list_size);
}

static void
request_feed_on_settle_timer(struct settle *s)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, s->tm.data);

  assert(PREFIX_AGGR == p->aggr_mode);
  assert(p->root == NULL);

  times_update(&main_timeloop);
  log("==== FEED START ====");
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
    times_update(&main_timeloop);
    log("==== FEED END ====");

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

  if (p->logging)
  {
    log("=============== CREATE MERGED ROUTE ===============");
    log("New route created: id = %d, protocol: %s", new->src->global_id, new->src->proto->name);
    log("===================================================");
  }

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
      settle_kick(&p->notify_settle);
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
    struct aggregator_bucket *tmp_bucket = allocz(sizeof(*tmp_bucket) + sizeof(tmp_bucket->aggr_data[0]) * p->aggr_on_count);
    assert(tmp_bucket->id == 0);

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
      new_bucket = lp_allocz(p->bucket_pool, sizeof(*new_bucket) + sizeof(new_bucket->aggr_data[0]) * p->aggr_on_count);
      memcpy(new_bucket, tmp_bucket, sizeof(*new_bucket) + sizeof(new_bucket->aggr_data[0]) * p->aggr_on_count);
      HASH_INSERT2(p->buckets, AGGR_BUCK, p->p.pool, new_bucket);

      assign_bucket_id(p, new_bucket);
      proto_insert_bucket(p, new_bucket);
    }

    /* Store the route attributes */
    if (rta_is_cached(new->attrs))
      rta_clone(new->attrs);
    else
      new->attrs = rta_lookup(new->attrs);

    if (p->logging)
      log("New rte: %p, net: %p, src: %p, hash: %x", new, new->net, new->src, aggr_route_hash(new));

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

    if (p->logging)
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
  p->logging = cf->logging;
  p->bucket_list = NULL;
  p->bucket_list_size = 0;
  p->bucket_list_count = 0;

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

    if (p->logging)
      log("Creating net %p for default route %N", default_net, default_net->n.addr);
  }
  else if (p->addr_type == NET_IP6)
  {
    default_net = mb_allocz(p->p.pool, sizeof(*default_net) + sizeof(struct net_addr_ip6));
    net_fill_ip6(default_net->n.addr, IP6_NONE, 0);

    if (p->logging)
      log("Creating net %p for default route %N", default_net, default_net->n.addr);
  }

  /* Create route attributes with zero nexthop */
  struct rta rta = { 0 };

  /* Allocate bucket for root node */
  struct aggregator_bucket *new_bucket = lp_allocz(p->bucket_pool, sizeof(*new_bucket));
  assert(new_bucket->id == 0);
  u64 haux = 0;
  mem_hash_init(&haux);
  new_bucket->hash = mem_hash_value(&haux);

  /* Assign ID to root node */
  assign_bucket_id(p, new_bucket);
  proto_insert_bucket(p, new_bucket);
  assert(get_bucket_ptr(p, new_bucket->id) == new_bucket);

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

  hmap_init(&p->bucket_id_map, p->p.pool, 1024);
  hmap_set(&p->bucket_id_map, 0);       /* 0 is default value, do not use it as ID */

  p->first_run = 1;

  times_update(&main_timeloop);
  log("==== FEED START ====");

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

  p->bucket_list = NULL;
  p->bucket_list_size = 0;
  p->bucket_list_count = 0;

  p->bucket_id_map = (struct hmap) { 0 };
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
