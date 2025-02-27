/*
 *	BIRD Internet Routing Daemon -- Prefix aggregation
 *
 *	(c) 2023--2025 Igor Putovny <igor.putovny@nic.cz>
 *	(c) 2025       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Aggregator protocol trie
 *
 * Prefix aggregation implements the ORTC (Optimal Route Table Construction)
 * algorithm. This algorithm uses a binary tree representation of the routing
 * table. An edge from the parent node to its left child represents bit 0, and
 * an edge from the parent node to its right child represents bit 1 as the
 * prefix is traversed from the most to the least significant bit. Last node
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
 * The third pass moves down the trie while deciding which prefixes will be
 * exported to the FIB. The node inherits a bucket from the closest ancestor
 * that has a bucket. If the inherited bucket is one of potential buckets of
 * this node, then this node does not need a bucket and its prefix will not
 * be in FIB. Otherwise the node does need a bucket and any of its potential
 * buckets can be chosen. We always choose the bucket with the lowest ID.
 *
 * The algorithm works with the assumption that there is a default route,
 * that is, the null prefix at the root node has a bucket.
 *
 * Aggregator is capable of processing incremental updates. After receiving
 * an update, which can be either announce or withdraw, corresponding node
 * is found in the trie and its original bucket is updated.
 * The trie now needs to be recomputed to reflect this update. We go from
 * updated node upwards until we find its closest IN_FIB ancestor.
 * This is the prefix node that covers an address space which is affected
 * by received update. The whole subtree rooted at this node is deaggregated,
 * which means deleting all information computed by aggregation algorithm.
 * This is followed by second pass which propagates potential buckets from
 * the leaves upwards. Merging of sets of potential buckets continues upwards
 * until the node's set is not changed by this operation. Finally, third pass
 * runs from this node, finishing the aggregation. During third pass, changes in
 * prefix FIB status are detected and routes are exported or removed from the
 * routing table accordingly. All new routes are exported immmediately, however,
 * all routes that are to be withdrawed are pushed on the stack and removed
 * after recomputing the trie.
 *
 * From a practical point of view, our implementation differs a little bit from
 * the algorithm as it was described in the original paper.
 * During first pass, the trie is normalized by adding new nodes so that every
 * node has either zero or two children. We do not add these nodes to save both
 * time and memory. Another difference is that the propagation of original
 * buckets, which was previously done in the first pass, is now done in the
 * second pass, saving one traversal through the trie.
 */

#undef LOCAL_DEBUG

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "nest/bird.h"
#include "nest/iface.h"
#include "filter/filter.h"
#include "proto/aggregator/aggregator.h"

#include <stdlib.h>
#include <assert.h>

static const char *px_origin_str[] = {
  [FILLER]     = "filler",
  [ORIGINAL]   = "original",
  [AGGREGATED] = "aggregated",
};

static const u32 ipa_shift[] = {
  [NET_IP4] = IP6_MAX_PREFIX_LENGTH - IP4_MAX_PREFIX_LENGTH,
  [NET_IP6] = 0,
};

/*
 * Allocate new node in protocol linpool
 */
struct trie_node *
aggregator_create_new_node(linpool *trie_pool)
{
  struct trie_node *node = lp_allocz(trie_pool, sizeof(*node));
  return node;
}

static inline int
aggregator_is_leaf(const struct trie_node *node)
{
  ASSERT_DIE(node != NULL);
  return !node->child[0] && !node->child[1];
}

/*
 * Unlink node from the trie by setting appropriate child of parent node to NULL
 */
static inline void
aggregator_remove_node(struct trie_node *node)
{
  ASSERT_DIE(node != NULL);
  ASSERT_DIE(node->child[0] == NULL && node->child[1] == NULL);

  if (!node->parent)
    ;
  else
  {
    if (node->parent->child[0] == node)
      node->parent->child[0] = NULL;
    else if (node->parent->child[1] == node)
      node->parent->child[1] = NULL;
    else
      bug("Corrupted memory (node is not its parent's child)");
  }

  memset(node, 0, sizeof(*node));
}

/*
 * Insert @bucket to the set of potential buckets in @node
 */
static inline void
aggregator_node_add_potential_bucket(struct trie_node *node, const struct aggregator_bucket *bucket)
{
  ASSERT_DIE(node->potential_buckets_count < MAX_POTENTIAL_BUCKETS_COUNT);

  /*
  if (BIT32R_TEST(node->potential_buckets, bucket->id))
    return;

  BIT32R_SET(node->potential_buckets, bucket->id);
  node->potential_buckets_count++;
  */

  /*
   * If the bit is set, the result of TEST is 1 and is subtracted from
   * the bucket count, decreasing it by one.
   * Second statement has no effect since the bit is already set.
   * Third statement increases count by one, returning it to its previous
   * value. Nothing changed.
   *
   * If the bit is not set, the result of TEST is 0 and subtracting it
   * from the total count doesn't change its value.
   * Second statement sets the bit and third statement increases count by one.
   * Bit is now set and the total count was increased by one.
   */
  node->potential_buckets_count -= BIT32R_TEST(node->potential_buckets, bucket->id);
  BIT32R_SET(node->potential_buckets, bucket->id);
  node->potential_buckets_count++;
}

/*
 * Check if @bucket is one of potential buckets of @node
 */
static inline int
aggregator_is_bucket_potential(const struct trie_node *node, const struct aggregator_bucket *bucket)
{
  ASSERT_DIE(node != NULL);
  ASSERT_DIE(bucket != NULL);

  ASSERT_DIE(bucket->id < MAX_POTENTIAL_BUCKETS_COUNT);
  return BIT32R_TEST(node->potential_buckets, bucket->id);
}

/*
 * Return pointer to bucket with ID @id.
 * Protocol contains list of pointers to all buckets. Every pointer
 * lies at position equal to bucket ID to enable fast lookup.
 */
static inline struct aggregator_bucket *
aggregator_get_bucket_from_id(const struct aggregator_proto *p, u32 id)
{
  ASSERT_DIE(id < p->bucket_list_size);
  ASSERT_DIE(p->bucket_list[id] != NULL);
  ASSERT_DIE(p->bucket_list[id]->id == id);
  return p->bucket_list[id];
}

/*
 * Select bucket with the lowest ID from the set of node's potential buckets
 */
static inline struct aggregator_bucket *
aggregator_select_lowest_id_bucket(const struct aggregator_proto *p, const struct trie_node *node)
{
  ASSERT_DIE(p != NULL);
  ASSERT_DIE(node != NULL);

  for (u32 i = 0; i < MAX_POTENTIAL_BUCKETS_COUNT; i++)
  {
    if (BIT32R_TEST(node->potential_buckets, i))
    {
      struct aggregator_bucket *bucket = aggregator_get_bucket_from_id(p, i);
      ASSERT_DIE(bucket != NULL);
      ASSERT_DIE(bucket->id == i);
      return bucket;
    }
  }

  bug("No potential buckets to choose from");
}

/*
 * @target: node we are computing set of potential buckets for
 * @left, @right: left and right children of @target
 *
 * If sets of potential buckets in @left and @right have non-empty intersection,
 * computed as bitwise AND, save it to the target bucket. Otherwise compute
 * their union as bitwise OR. Return whether the set of potential buckets in the
 * target node has changed.
 */
static int
aggregator_merge_potential_buckets(struct trie_node *target, const struct trie_node *left, const struct trie_node *right)
{
  ASSERT_DIE(target != NULL);
  ASSERT_DIE(left != NULL);
  ASSERT_DIE(right != NULL);

  int has_intersection = 0;
  int has_changed = 0;
  int buckets_count = 0;

  u32 old[ARRAY_SIZE(target->potential_buckets)] = { 0 };

  for (int i = 0; i < POTENTIAL_BUCKETS_BITMAP_SIZE; i++)
  {
    /* Save current bitmap values */
    old[i] = target->potential_buckets[i];

    /* Compute intersection */
    has_intersection |= !!(target->potential_buckets[i] = left->potential_buckets[i] & right->potential_buckets[i]);
    buckets_count += u32_popcount(target->potential_buckets[i]);

    /*
     * If old and new values are different, the result of their XOR will be
     * non-zero, thus @changed will be set to non-zero - true, as well.
     */
    has_changed |= !!(old[i] ^ target->potential_buckets[i]);
  }

  /* Sets have an empty intersection, compute their union instead */
  if (!has_intersection)
  {
    buckets_count = 0;
    has_changed = 0;

    for (int i = 0; i < POTENTIAL_BUCKETS_BITMAP_SIZE; i++)
    {
      target->potential_buckets[i] = left->potential_buckets[i] | right->potential_buckets[i];
      buckets_count += u32_popcount(target->potential_buckets[i]);
      has_changed |= !!(old[i] ^ target->potential_buckets[i]);
    }
  }

  /* Update number of potential buckets */
  target->potential_buckets_count = buckets_count;

  return has_changed;
}

static void
aggregator_print_prefixes_helper(const struct trie_node *node, ip_addr *prefix, u32 pxlen, u32 type)
{
  ASSERT_DIE(node != NULL);
  ASSERT_DIE(prefix != NULL);

  if (node->status == IN_FIB)
  {
    struct net_addr addr = { 0 };
    net_fill_ipa(&addr, *prefix, pxlen);
    log("%N selected bucket: %u", &addr, node->selected_bucket->id);
  }

  if (node->child[0])
  {
    ASSERT_DIE((u32)node->depth == pxlen);
    ipa_clrbit(prefix, node->depth + ipa_shift[type]);
    aggregator_print_prefixes_helper(node->child[0], prefix, pxlen + 1, type);
  }

  if (node->child[1])
  {
    ASSERT_DIE((u32)node->depth == pxlen);
    ipa_setbit(prefix, node->depth + ipa_shift[type]);
    aggregator_print_prefixes_helper(node->child[1], prefix, pxlen + 1, type);
    ipa_clrbit(prefix, node->depth + ipa_shift[type]);
  }
}

static void
aggregator_print_prefixes(const struct trie_node *node, u32 type)
{
  ASSERT_DIE(node != NULL);

  ip_addr prefix = (type == NET_IP4) ? ipa_from_ip4(IP4_NONE) : ipa_from_ip6(IP6_NONE);
  aggregator_print_prefixes_helper(node, &prefix, 0, type);
}

static void
aggregator_dump_trie_helper(const struct aggregator_proto *p, const struct trie_node *node, ip_addr *prefix, u32 pxlen, struct buffer *buf)
{
  ASSERT_DIE(p != NULL);
  ASSERT_DIE(node != NULL);
  ASSERT_DIE(prefix != NULL);

  memset(buf->start, 0, buf->pos - buf->start);
  buf->pos = buf->start;

  struct net_addr addr = { 0 };
  net_fill_ipa(&addr, *prefix, pxlen);

  buffer_print(buf, "%*s%s%N ", 2 * node->depth, "", (node->status == IN_FIB) ? "@" : " ", &addr);

  if (node->original_bucket)
    buffer_print(buf, "[%u] ", node->original_bucket->id);
  else
    buffer_print(buf, "[] ");

  buffer_print(buf, "{");

  int j = 0;

  for (size_t i = 0; i < MAX_POTENTIAL_BUCKETS_COUNT; i++)
  {
    if (BIT32R_TEST(node->potential_buckets, i))
    {
      buffer_print(buf, "%u", i);
      j++;

      if (j < node->potential_buckets_count)
        buffer_print(buf, ", ");
    }
  }

  buffer_print(buf, "}");

  if (node->selected_bucket)
    buffer_print(buf, " -> [[%u]]", node->selected_bucket->id);

  buffer_print(buf, " %p %s", node, px_origin_str[node->px_origin]);
  log("%s", buf->start);

  if (node->child[0])
  {
    ASSERT_DIE((u32)node->depth == pxlen);
    ipa_clrbit(prefix, node->depth + ipa_shift[p->addr_type]);
    aggregator_dump_trie_helper(p, node->child[0], prefix, pxlen + 1, buf);
  }

  if (node->child[1])
  {
    ASSERT_DIE((u32)node->depth == pxlen);
    ipa_setbit(prefix, node->depth + ipa_shift[p->addr_type]);
    aggregator_dump_trie_helper(p, node->child[1], prefix, pxlen + 1, buf);
    ipa_clrbit(prefix, node->depth + ipa_shift[p->addr_type]);
  }
}

static void
aggregator_dump_trie(const struct aggregator_proto *p)
{
  ip_addr prefix = (p->addr_type == NET_IP4) ? ipa_from_ip4(IP4_NONE) : ipa_from_ip6(IP6_NONE);

  struct buffer buf = { 0 };
  LOG_BUFFER_INIT(buf);

  log("==== TRIE BEGIN ====");
  aggregator_dump_trie_helper(p, p->root, &prefix, 0, &buf);
  log("==== TRIE   END ====");
}

static inline void
aggregator_create_route(struct aggregator_proto *p, ip_addr prefix, u32 pxlen, struct aggregator_bucket *bucket)
{
  struct net_addr addr = { 0 };
  net_fill_ipa(&addr, prefix, pxlen);

  struct network *n = allocz(sizeof(*n) + sizeof(struct net_addr));
  net_copy(n->n.addr, &addr);

  aggregator_bucket_update(p, bucket, n);
}

/*
 * Prepare to withdraw route for @prefix
 */
static void
aggregator_prepare_rte_withdrawal(struct aggregator_proto *p, ip_addr prefix, u32 pxlen, struct aggregator_bucket *bucket)
{
  ASSERT_DIE(p != NULL);
  ASSERT_DIE(bucket != NULL);

  struct net_addr addr = { 0 };
  net_fill_ipa(&addr, prefix, pxlen);

  struct rte_withdrawal_item *node = lp_allocz(p->rte_withdrawal_pool, sizeof(*node));

  *node = (struct rte_withdrawal_item) {
    .next = p->rte_withdrawal_stack,
    .bucket = bucket,
  };

  net_copy(&node->addr, &addr);

  p->rte_withdrawal_stack = node;
  p->rte_withdrawal_count++;

  ASSERT_DIE(p->rte_withdrawal_stack != NULL);
}

/*
 * Insert @prefix to the trie and assign @bucket to this prefix. If the prefix
 * is already in the trie, update its bucket to @bucket and return updated node.
 */
static struct trie_node *
aggregator_trie_insert_prefix(struct aggregator_proto *p, ip_addr prefix, u32 pxlen, struct aggregator_bucket *bucket)
{
  ASSERT_DIE(p != NULL);
  ASSERT_DIE(bucket != NULL);

  struct trie_node *node = p->root;

  for (u32 i = 0; i < pxlen; i++)
  {
    u32 bit = ipa_getbit(prefix, i + ipa_shift[p->addr_type]);

    if (!node->child[bit])
    {
      struct trie_node *new = aggregator_create_new_node(p->trie_pool);

      *new = (struct trie_node) {
        .parent = node,
        .status = NON_FIB,
        .px_origin = FILLER,
        .depth = node->depth + 1,
      };

      node->child[bit] = new;
    }

    node = node->child[bit];
  }

  /* Assign bucket to the last node */
  node->original_bucket = bucket;
  node->px_origin = ORIGINAL;

  return node;
}

/*
 * Remove @prefix from the trie and return the last affected node
 */
static struct trie_node *
aggregator_trie_remove_prefix(struct aggregator_proto *p, ip_addr prefix, u32 pxlen)
{
  struct trie_node *node = p->root;

  for (u32 i = 0; i < pxlen; i++)
  {
    u32 bit = ipa_getbit(prefix, i + ipa_shift[p->addr_type]);
    node = node->child[bit];
    ASSERT_DIE(node != NULL);
  }

  ASSERT_DIE(node->px_origin == ORIGINAL);
  ASSERT_DIE((u32)node->depth == pxlen);

  node->px_origin = FILLER;
  node->ancestor = NULL;
  node->original_bucket = NULL;
  node->potential_buckets_count = 0;
  memset(node->potential_buckets, 0, sizeof(node->potential_buckets));

  return node;
}

/*
 * Find prefix corresponding to the position of @target node in the trie
 * and save result into @prefix and @pxlen.
 */
static void
aggregator_find_subtree_prefix(const struct trie_node *target, ip_addr *prefix, u32 *pxlen, u32 type)
{
  ASSERT_DIE(target != NULL);
  ASSERT_DIE(prefix != NULL);
  ASSERT_DIE(pxlen != NULL);

  int path[IP6_MAX_PREFIX_LENGTH] = { 0 };
  int pos = 0;
  u32 len = 0;

  const struct trie_node *node = target;
  const struct trie_node *parent = node->parent;

  /* Ascend to the root node */
  while (parent)
  {
    if (node == parent->child[0])
      path[pos++] = 0;
    else if (node == parent->child[1])
      path[pos++] = 1;
    else
      bug("Corrupted memory (node is not its parent's child)");

    ASSERT_DIE(pos < IP6_MAX_PREFIX_LENGTH);
    node = parent;
    parent = node->parent;
  }

  ASSERT_DIE(node->parent == NULL);

  /* Descend to the target node */
  for (int i = pos - 1; i >= 0; i--)
  {
    if (path[i] == 0)
      ipa_clrbit(prefix, node->depth + ipa_shift[type]);
    else
      ipa_setbit(prefix, node->depth + ipa_shift[type]);

    node = node->child[path[i]];
    len++;
    ASSERT_DIE((u32)node->depth == len);
  }

  ASSERT_DIE(node == target);
  *pxlen = len;
}

/*
 * Second pass of Optimal Route Table Construction (ORTC) algorithm
 */
static void
aggregator_second_pass(struct trie_node *node)
{
  ASSERT_DIE(node != NULL);
  ASSERT_DIE(node->potential_buckets_count <= MAX_POTENTIAL_BUCKETS_COUNT);

  if (aggregator_is_leaf(node))
  {
    ASSERT_DIE(node->original_bucket != NULL);
    ASSERT_DIE(node->potential_buckets_count == 0);
    aggregator_node_add_potential_bucket(node, node->original_bucket);
    return;
  }

  /* Propagate original buckets */
  if (!node->original_bucket)
    node->original_bucket = node->parent->original_bucket;

  /* Internal node */
  ASSERT_DIE(node->potential_buckets_count == 0);

  struct trie_node *left  = node->child[0];
  struct trie_node *right = node->child[1];

  /* Postorder traversal */
  if (left)
    aggregator_second_pass(left);

  if (right)
    aggregator_second_pass(right);

  ASSERT_DIE(node->original_bucket != NULL);

  /* Imaginary node if this was a complete binary tree */
  struct trie_node imaginary_node = {
    .parent = node,
  };

  /*
   * Imaginary node is used only for computing sets of potential buckets
   * of its parent node. It inherits parent's potential bucket.
   */
  aggregator_node_add_potential_bucket(&imaginary_node, node->original_bucket);

  /* Nodes with exactly one child */
  if ((left && !right) || (!left && right))
  {
    if (left && !right)
      right = &imaginary_node;
    else
      left = &imaginary_node;
  }

  ASSERT_DIE(left != NULL && right != NULL);

  /*
   * If there are no common buckets among children's buckets, parent's
   * buckets are computed as union of its children's buckets.
   * Otherwise, parent's buckets are computed as intersection of its
   * children's buckets.
   */
  aggregator_merge_potential_buckets(node, left, right);
}

static void
aggregator_third_pass_helper(struct aggregator_proto *p, struct trie_node *node, ip_addr *prefix, u32 pxlen)
{
  ASSERT_DIE(node != NULL);
  ASSERT_DIE(node->potential_buckets_count <= MAX_POTENTIAL_BUCKETS_COUNT);

  ASSERT_DIE(node->original_bucket != NULL);
  ASSERT_DIE(node->parent->ancestor != NULL);
  ASSERT_DIE(node->parent->ancestor->selected_bucket != NULL);

  /* Bucket inherited from the closest ancestor with a non-null selected bucket */
  const struct aggregator_bucket * const inherited_bucket = node->parent->ancestor->selected_bucket;

  /*
   * If the bucket inherited from the ancestor is one of the potential buckets
   * of this node, then this node doesn't need a bucket because it inherits
   * one, and is not needed in FIB.
   */
  if (aggregator_is_bucket_potential(node, inherited_bucket))
  {
    /*
     * Prefix status is changing from IN_FIB to NON_FIB, thus its route
     * must be removed from the routing table.
     */
    if (node->status == IN_FIB)
    {
      ASSERT_DIE(node->selected_bucket != NULL);
      aggregator_prepare_rte_withdrawal(p, *prefix, pxlen, node->selected_bucket);
    }

    node->selected_bucket = NULL;
    node->status = NON_FIB;
    node->ancestor = node->parent->ancestor;

    /*
     * We have to keep information whether this prefix was original to enable
     * processing of incremental updates. If it's not original, then it is
     * a filler because it's not going to FIB.
     */
    node->px_origin = (node->px_origin == ORIGINAL) ? ORIGINAL : FILLER;
  }
  else
  {
    ASSERT_DIE(node->potential_buckets_count > 0);

    /* Assign bucket with the lowest ID to the node */
    node->selected_bucket = aggregator_select_lowest_id_bucket(p, node);
    ASSERT_DIE(node->selected_bucket != NULL);

    /*
     * Prefix status is changing from NON_FIB or UNASSIGNED (at newly created nodes)
     * to IN_FIB, thus its route is exported to the routing table.
     */
    if (node->status != IN_FIB)
      aggregator_create_route(p, *prefix, pxlen, node->selected_bucket);

    /*
     * Keep information whether this prefix was original. If not, then its origin
     * is changed to aggregated, because algorithm decided it's going to FIB.
     */
    node->px_origin = (node->px_origin == ORIGINAL) ? ORIGINAL : AGGREGATED;
    node->status = IN_FIB;
    node->ancestor = node;
  }

  ASSERT_DIE((node->selected_bucket != NULL && node->status == IN_FIB) || (node->selected_bucket == NULL && node->status == NON_FIB));
  ASSERT_DIE(node->ancestor != NULL);
  ASSERT_DIE(node->ancestor->original_bucket != NULL);
  ASSERT_DIE(node->ancestor->selected_bucket != NULL);

  const struct trie_node * const left  = node->child[0];
  const struct trie_node * const right = node->child[1];

  /* Nodes with only one child */
  if ((left && !right) || (!left && right))
  {
    /*
     * Imaginary node that would have been added during first pass.
     * This node inherits bucket from its parent (current node).
     */
    struct trie_node imaginary_node = {
      .parent = node,
      .original_bucket = node->original_bucket,
      .px_origin = AGGREGATED,
      .depth = node->depth + 1,
    };

    aggregator_node_add_potential_bucket(&imaginary_node, node->original_bucket);

    /*
     * If the current node (parent of the imaginary node) has a bucket,
     * then the imaginary node inherits this bucket.
     * Otherwise it inherits bucket from the closest ancestor with
     * a non-null bucket.
     */
    const struct aggregator_bucket * const imaginary_node_inherited_bucket = node->selected_bucket ? node->selected_bucket : inherited_bucket;

    /*
     * Original algorithm would normalize the trie during first pass, so that
     * every node has either zero or two children. We skip this step to save
     * both time and memory.
     * On the other hand, nodes may be removed from the trie during third pass,
     * if they do not have bucket on their own and inherit one from their
     * ancestors instead (and thus are not needed in FIB).
     * Nodes get bucket if the bucket inherited from their ancestors is NOT
     * one of their potential buckets. In this case, we need to add these nodes
     * to the trie.
     */
    if (!aggregator_is_bucket_potential(&imaginary_node, imaginary_node_inherited_bucket))
    {
      struct trie_node *new = aggregator_create_new_node(p->trie_pool);
      *new = imaginary_node;

      /* Connect new node to the trie */
      if (left && !right)
        node->child[1] = new;
      else
        node->child[0] = new;
    }
  }

  /* Preorder traversal */
  if (node->child[0])
  {
    ASSERT_DIE((u32)node->depth == pxlen);
    ipa_clrbit(prefix, node->depth + ipa_shift[p->addr_type]);
    aggregator_third_pass_helper(p, node->child[0], prefix, pxlen + 1);
  }

  if (node->child[1])
  {
    ASSERT_DIE((u32)node->depth == pxlen);
    ipa_setbit(prefix, node->depth + ipa_shift[p->addr_type]);
    aggregator_third_pass_helper(p, node->child[1], prefix, pxlen + 1);
    ipa_clrbit(prefix, node->depth + ipa_shift[p->addr_type]);
  }

  if (node->status == NON_FIB && aggregator_is_leaf(node))
    ASSERT_DIE(node->selected_bucket == NULL);
}

/*
 * Third pass of Optimal Route Table Construction (ORTC) algorithm
 */
static void
aggregator_third_pass(struct aggregator_proto *p, struct trie_node *node)
{
  ASSERT_DIE(node != NULL);
  ASSERT_DIE(node->potential_buckets_count <= MAX_POTENTIAL_BUCKETS_COUNT);
  ASSERT_DIE(node->potential_buckets_count > 0);

  ip_addr prefix = (p->addr_type == NET_IP4) ? ipa_from_ip4(IP4_NONE) : ipa_from_ip6(IP6_NONE);
  u32 pxlen = 0;

  /*
   * If third pass runs on a subtree and not the whole trie,
   * find prefix that covers this subtree.
   */
  aggregator_find_subtree_prefix(node, &prefix, &pxlen, p->addr_type);

  ASSERT_DIE(node->selected_bucket == NULL);

  /* Select bucket with the lowest ID */
  node->selected_bucket = aggregator_select_lowest_id_bucket(p, node);
  ASSERT_DIE(node->selected_bucket != NULL);

  /*
   * Export new route if node status is changing from NON_FIB
   * or UNASSIGNED to IN_FIB.
   */
  if (node->status != IN_FIB)
    aggregator_create_route(p, prefix, pxlen, node->selected_bucket);

  /* The closest ancestor of the IN_FIB node with a non-null bucket is the node itself */
  node->ancestor = node;
  node->status = IN_FIB;
  node->px_origin = (node->px_origin == ORIGINAL) ? ORIGINAL : AGGREGATED;

  if (node->child[0])
  {
    ASSERT_DIE((u32)node->depth == pxlen);
    ipa_clrbit(&prefix, node->depth + ipa_shift[p->addr_type]);
    aggregator_third_pass_helper(p, node->child[0], &prefix, pxlen + 1);
  }

  if (node->child[1])
  {
    ASSERT_DIE((u32)node->depth == pxlen);
    ipa_setbit(&prefix, node->depth + ipa_shift[p->addr_type]);
    aggregator_third_pass_helper(p, node->child[1], &prefix, pxlen + 1);
    ipa_clrbit(&prefix, node->depth + ipa_shift[p->addr_type]);
  }
}

static void
check_trie_after_aggregation(const struct trie_node *node)
{
  ASSERT_DIE(node != NULL);
  ASSERT_DIE(node->ancestor != NULL);

  if (node->status == IN_FIB)
  {
    ASSERT_DIE(node->px_origin == ORIGINAL || node->px_origin == AGGREGATED);
    ASSERT_DIE(node->selected_bucket != NULL);
    ASSERT_DIE(node->ancestor != NULL);
    ASSERT_DIE(node->ancestor == node);
  }
  else if (node->status == NON_FIB)
  {
    ASSERT_DIE(node->px_origin == ORIGINAL || node->px_origin == FILLER);
    ASSERT_DIE(node->selected_bucket == NULL);
    ASSERT_DIE(node->ancestor != NULL);
    ASSERT_DIE(node->ancestor != node);
    ASSERT_DIE(node->ancestor == node->parent->ancestor);
  }
  else
    bug("Unknown node status");

  if (node->child[0])
    check_trie_after_aggregation(node->child[0]);

  if (node->child[1])
    check_trie_after_aggregation(node->child[1]);
}

/*
 * Delete all information computed by aggregation algorithm in the subtree
 * rooted at @node and propagate original buckets in the subtree.
 */
static void
aggregator_deaggregate(struct trie_node *node)
{
  ASSERT_DIE(node != NULL);

  /* Delete results computed by aggregation algorithm */
  node->ancestor = NULL;
  node->potential_buckets_count = 0;
  memset(node->potential_buckets, 0, sizeof(node->potential_buckets));

  /*
   * Original prefixes already have their original bucket set,
   * others inherit it from their parents.
   */
  if (node->px_origin != ORIGINAL)
  {
    node->original_bucket = node->parent->original_bucket;
    node->px_origin = FILLER;
  }

  ASSERT_DIE(node->original_bucket != NULL);

  if (node->child[0])
    aggregator_deaggregate(node->child[0]);

  if (node->child[1])
    aggregator_deaggregate(node->child[1]);
}

/*
 * Merge sets of potential buckets of node's children going from @node upwards.
 * Stop when the node's set doesn't change and return the last updated node.
 */
static struct trie_node *
aggregator_merge_buckets_above(struct trie_node *node)
{
  ASSERT_DIE(node != NULL);

  struct trie_node *parent = node->parent;

  while (parent)
  {
    const struct trie_node *left  = parent->child[0];
    const struct trie_node *right = parent->child[1];
    ASSERT_DIE(left == node || right == node);

    struct trie_node imaginary_node = { 0 };
    aggregator_node_add_potential_bucket(&imaginary_node, parent->original_bucket);

    /* Nodes with only one child */
    if (left && !right)
      right = &imaginary_node;
    else if (!left && right)
      left = &imaginary_node;

    ASSERT_DIE(left != NULL && right != NULL);

    /* The parent's set wasn't affected by merging, stop here */
    if (aggregator_merge_potential_buckets(parent, left, right) == 0)
      return node;

    node = parent;
    parent = node->parent;
  }

  return node;
}

/*
 * Incorporate announcement of new prefix into the trie
 */
void
aggregator_update_prefix(struct aggregator_proto *p, struct aggregator_route *old UNUSED, struct aggregator_route *new)
{
  ASSERT_DIE(p != NULL);
  ASSERT_DIE(new != NULL);

  const struct net_addr *addr = new->rte.net->n.addr;

  const ip_addr prefix = net_prefix(addr);
  const u32 pxlen = net_pxlen(addr);

  struct trie_node * const updated_node = aggregator_trie_insert_prefix(p, prefix, pxlen, new->bucket);
  ASSERT_DIE(updated_node != NULL);
  ASSERT_DIE(updated_node->original_bucket != NULL);
  ASSERT_DIE(updated_node->status == NON_FIB);
  ASSERT_DIE(updated_node->px_origin == ORIGINAL);

  struct trie_node *node = updated_node;

  /*
   * Find the closest IN_FIB ancestor of the updated node and deaggregate
   * the whole subtree rooted at this node. Since updated node has IN_FIB
   * status, we need to find node which is different from this node.
   * Then aggregate it once again, this time with incorporated update.
   */
  while (1)
  {
    if (node->status == IN_FIB && node != updated_node)
      break;

    node = node->parent;
  }

  aggregator_deaggregate(node);
  aggregator_second_pass(node);
  struct trie_node *highest_node = aggregator_merge_buckets_above(node);
  ASSERT_DIE(highest_node != NULL);
  aggregator_third_pass(p, highest_node);

  check_trie_after_aggregation(p->root);
}

/*
 * Incorporate prefix withdrawal to the trie
 */
void
aggregator_withdraw_prefix(struct aggregator_proto *p, struct aggregator_route *old)
{
  ASSERT_DIE(p != NULL);
  ASSERT_DIE(old != NULL);

  const struct net_addr *addr = old->rte.net->n.addr;

  const ip_addr prefix = net_prefix(addr);
  const u32 pxlen = net_pxlen(addr);

  struct trie_node * const updated_node = aggregator_trie_remove_prefix(p, prefix, pxlen);
  ASSERT_DIE(updated_node != NULL);

  struct trie_node *node = updated_node;

  /*
   * Find the closest IN_FIB ancestor of the updated node and deaggregate
   * the whole subtree rooted at this node. Since updated node does not have
   * IN_FIB status, the next node with this status will be its ancestor we are
   * seeking. Then aggregate it again, this time with incorporated update.
   */
  while (1)
  {
    if (node->status == IN_FIB)
      break;

    node = node->parent;
  }

  aggregator_deaggregate(node);
  aggregator_second_pass(node);
  struct trie_node *highest_node = aggregator_merge_buckets_above(node);
  ASSERT_DIE(highest_node != NULL);
  aggregator_third_pass(p, highest_node);

  check_trie_after_aggregation(p->root);
}

static void
aggregator_construct_trie(struct aggregator_proto *p)
{
  HASH_WALK(p->buckets, next_hash, bucket)
  {
    for (const struct rte *rte = bucket->rte; rte; rte = rte->next)
    {
      const struct net_addr *addr = rte->net->n.addr;

      const ip_addr prefix = net_prefix(addr);
      const u32 pxlen = net_pxlen(addr);

      aggregator_trie_insert_prefix(p, prefix, pxlen, bucket);
    }
  }
  HASH_WALK_END;
}

/*
 * Run Optimal Routing Table Constructor (ORTC) algorithm
 */
static void
aggregator_calculate_trie(struct aggregator_proto *p)
{
  ASSERT_DIE(p->addr_type == NET_IP4 || p->addr_type == NET_IP6);

  aggregator_second_pass(p->root);
  aggregator_third_pass(p, p->root);

  check_trie_after_aggregation(p->root);
}

void
aggregator_aggregate(struct aggregator_proto *p)
{
  ASSERT_DIE(p->root != NULL);

  aggregator_construct_trie(p);
  aggregator_calculate_trie(p);
}
