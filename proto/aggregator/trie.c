/*
 *  BIRD Internet Routing Daemon -- Prefix aggregation
 *
 *  (c) 2023--2025 Igor Putovny <igor.putovny@nic.cz>
 *  (c) 2025       CZ.NIC, z.s.p.o.
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Aggregator protocol trie
 *
 * Prefix aggregation implements the ORTC (Optimal Route Table Construction)
 * algorithm [1].
 *
 * This algorithm uses a binary tree representation of the routing table.
 * An edge from the parent node to its left child represents bit 0, and
 * an edge from the parent node to its right child represents bit 1 as the
 * prefix is traversed from the most to the least significant bit. Last node
 * of every prefix contains original bucket where the route for this prefix
 * belongs.
 *
 * Prefixes are therefore represented as a path through the trie, beginning at
 * the root node. The last node on this path is called prefix node.
 *
 *** The Original Algorithm ***
 *
 * ORTC algorithm as described in the original paper consists of three passes
 * through the trie. (This is not exactly how this is implemented here.)
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
 * exported to the FIB. The node inherits a bucket from its closest ancestor
 * that has a bucket. If the inherited bucket is one of potential buckets of
 * this node, then this node does not need a bucket and its prefix will not
 * be in FIB. Otherwise the node does need a bucket and any of its potential
 * buckets can be chosen. We always choose the bucket with the lowest ID.
 * This prefix will go to the FIB.
 *
 * Algorithm works with the assumption that there is a default route.
 *
 *** Our Implementation ***
 *
 * Description of this implementation follows.
 *
 * Routes are put in the hash table based on their attributes.
 * Route attributes are represented as buckets. All routes with the same set of
 * attributes matched by the "aggregate on" config clause are put in the same
 * bucket.
 *
 * The trie contains three different kinds of nodes: original, aggregated and
 * fillers.
 *
 * - Original nodes represent prefixes from the original (import) routing table.
 * - Aggregated nodes represent prefixes that do not exist in the original table
 *   but do exist in the aggregated (export) table.
 * - Filler nodes exist neither in original or aggregated table, they represent
 *   prefixes "on the way" to the original or aggregated nodes.
 *
 * Each node has a FIB status flag signalling whether this prefix was exported
 * to the FIB (IN_FIB) or not (NON_FIB). It is clear that IN_FIB nodes can be
 * either original or aggregated, whereas NON_FIB nodes can be either original
 * or fillers.
 *
 * Every node contains pointer to its closest IN_FIB ancestor. If the node is
 * IN_FIB, the ancestor pointer points to itself.
 *
 * After every aggregation, following invariants are always satisfied:
 *
 *   1. All nodes have original bucket set.
 *   2. All nodes have the IN_FIB ancestor pointer set.
 *   3. If a node is IN_FIB, then
 *        a) its selected bucket must not be null,
 *        b) its ancestor pointer must point to itself,
 *        c) it must be ORIGINAL or AGGREGATED.
 *   4. If a node is NON_FIB, then
 *        a) its selected bucket must be null,
 *        b) its ancestor pointer must point to the closest IN_FIB ancestor,
 *        c) it must be ORIGINAL or FILLER.
 *
 * Our implementation differs from the algorithm as described in the original
 * paper in several aspects:
 *
 * - We do not normalize the trie by adding new nodes. This way, nodes may
 *   have one child (not only zero or two).
 * - The first pass is merged with the second pass. These two passes together
 *   are named propagate_and_merge().
 * - The third pass is called group_prefixes().
 *
 * The Aggregator is capable of processing incremental updates in the following
 * way. After receiving an update, which can be either announce or withdraw:
 *
 *    1. The corresponding node is found in the trie and its original bucket
 *       is updated. The trie now needs to be recomputed to reflect this update.
 *    2. The trie is traversed from the updated node upwards until its closest
 *       IN_FIB ancestor is found. This is the prefix node that covers an
 *       address space which is directly affected by the received update.
 *    3. The propagate_and_merge() pass is started for the subtree rooted in
 *       the node found in the previous step. This pass propagates buckets
 *       eligible for selection from the leaves upwards.
 *    4. Merging of sets of eligible buckets may leak from the subtree upwards
 *       by computing a different eligible bucket set for the node selected in
 *       step 2. In this case, we continue upwards until the computed set is
 *       equal to previous one.
 *    5. From the last node changed in the last step, the group_prefixes()
 *       is started downwards.
 *    6. When this function decides to change IN_FIB status or exchange the
 *       selected bucket, either route update is done immediately, or route
 *       retraction is scheduled for later to avoid short-term misroutings.
 *
 * References:
 *
 * [1] R. P. Draves, C. King, S. Venkatachary and B. D. Zill. Constructing
 *     Optimal IP Routing Tables. In Proceedings of IEEE INFOCOM, volume 1,
 *     pages 88-97, 1999.
 * [2] Z. A. Uzmi, M. Nebel, A. Tariq, S. Jawad, R. Chen, A. Shaikh, J. Wang,
 *     P. Francis. Practical and Near-Optimal FIB Aggregation using SMALTA.
 *     In Proceedings of CoNEXT, 2011.
 * [3] Y. Liu, B. Zhang, L. Wang. FIFA: Fast Incremental FIB Aggregation.
 *     In Proceedings of IEEE INFOCOM, 2013.
 * [4] Y. Liu, X. Zhao, K. Nam, L. Wang, B. Zhang. Incremental Forwarding
 *     Table Aggregation. In Proceedings of IEEE GLOBECOM, 2010.
 * [5] X. Zhao, Y. Liu, L. Wang, B. Zhang. On the Aggregatability of Router
 *     Forwarding Tables. In Proceedings of IEEE INFOCOM, 2010.
 *
 */

#undef LOCAL_DEBUG

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "nest/bird.h"
#include "filter/filter.h"
#include "proto/aggregator/aggregator.h"

/* Only u32 is allowed to use in bitmap because of use of BIT32 macros */
STATIC_ASSERT(sizeof(((struct trie_node *)0)->potential_buckets[0]) == sizeof(u32));

static const char *px_origin_str[] = {
  [FILLER]     = "filler",
  [ORIGINAL]   = "original",
  [AGGREGATED] = "aggregated",
};

/*
 * We use ip6_addr (under its alias ip_addr) to contain both IPv4 and IPv6
 * addresses. When using bitwise operations on these addresses, we have to
 * add offset of 96 in case of IPv4 address, because IPv4 address is stored
 * in the lowest 32 bits of ip6_addr, whereas IPv6 occupies all 128 bits.
 */
static const u32 ipa_shift[] = {
  [NET_IP4] = IP6_MAX_PREFIX_LENGTH - IP4_MAX_PREFIX_LENGTH,
  [NET_IP6] = 0,
};

/*
 * Allocate and initialize root node
 */
struct trie_node *
aggregator_root_init(struct aggregator_bucket *bucket, struct slab *trie_slab)
{
  struct trie_node *root = sl_allocz(trie_slab);

  *root = (struct trie_node) {
    .original_bucket = bucket,
    .status = NON_FIB,
    .px_origin = ORIGINAL,
    .depth = 0,
  };

  return root;
}

/*
 * Unlink node from the trie by setting appropriate child of parent node to NULL
 * and free memory.
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
    {
      node->parent->child[0] = NULL;
      ASSERT_DIE(node->parent->child[1] != node);
    }
    else if (node->parent->child[1] == node)
    {
      node->parent->child[1] = NULL;
      ASSERT_DIE(node->parent->child[0] != node);
    }
    else
      bug("Corrupted memory (node is not its parent's child)");
  }

  sl_free(node);
}

/*
 * Insert @bucket_id to the set of potential buckets in @node
 */
static inline void
aggregator_node_add_potential_bucket(struct trie_node *node, u32 bucket_id)
{
  if (BIT32R_TEST(node->potential_buckets, bucket_id))
    return;

  BIT32R_SET(node->potential_buckets, bucket_id);
  node->potential_buckets_count++;
}

/*
 * Check if @bucket is one of potential buckets of @node
 */
static inline int
aggregator_is_bucket_potential(const struct trie_node *node, u32 id, int bitmap_size)
{
  ASSERT_DIE(node != NULL);

  ASSERT_DIE(id < (sizeof(node->potential_buckets[0]) * bitmap_size * 8));
  return BIT32R_TEST(node->potential_buckets, id);
}

/*
 * Return pointer to bucket with ID @id.
 * Protocol contains list of pointers to all buckets. Every pointer
 * lies at position equal to bucket ID to enable fast lookup.
 */
static inline struct aggregator_bucket *
aggregator_get_bucket_from_id(const struct aggregator_proto *p, u32 id)
{
  ASSERT_DIE(id < p->bucket_map_size);
  ASSERT_DIE(p->bucket_map[id] != NULL);
  ASSERT_DIE(p->bucket_map[id]->id == id);
  return p->bucket_map[id];
}

/*
 * Select bucket with the lowest ID from the set of node's potential buckets
 */
static inline struct aggregator_bucket *
aggregator_select_lowest_id_bucket(const struct aggregator_proto *p, const struct trie_node *node)
{
  ASSERT_DIE(p != NULL);
  ASSERT_DIE(node != NULL);

  for (int i = 0; i < p->bitmap_size; i++)
  {
    if (node->potential_buckets[i] == 0)
      continue;

    /*
     * Use CLZ -- Count Leading Zeroes to find first set bit.
     * Compute its position from the beginning of the array.
     */
    u32 id = u32_clz(node->potential_buckets[i]) + i * 32;

    /* We would love if this got optimized out */
    ASSERT_DIE(BIT32R_TEST(node->potential_buckets, id));

    struct aggregator_bucket *bucket = aggregator_get_bucket_from_id(p, id);
    ASSERT_DIE(bucket != NULL);
    ASSERT_DIE(bucket->id == id);

    return bucket;
  }

  bug("No potential buckets to choose from");
}

/*
 * @target: node we are computing set of potential buckets for
 * @left, @right: left and right children of @target
 *
 * The resulting set is an intersection of sets of @left and @right. If this
 * intersection is empty, resulting set is an union of @left and @right sets.
 *
 * Returns: whether the set of potential buckets in the target node has changed.
 */
static bool
aggregator_merge_potential_buckets(struct trie_node *target, const struct trie_node *left, const struct trie_node *right, int bitmap_size)
{
  ASSERT_DIE(target != NULL);
  ASSERT_DIE(left != NULL);
  ASSERT_DIE(right != NULL);

  bool has_intersection = false;
  bool has_changed = false;

  u32 *before = allocz(sizeof(*before) * bitmap_size);

  target->potential_buckets_count = 0;

  /* First we try to compute intersection. If it exists, we want to keep it. */
  for (int i = 0; i < bitmap_size; i++)
  {
    /* Save current bitmap values */
    before[i] = target->potential_buckets[i];

    /* Compute intersection */
    target->potential_buckets[i] = left->potential_buckets[i] & right->potential_buckets[i];
    target->potential_buckets_count += u32_popcount(target->potential_buckets[i]);

    if (target->potential_buckets[i] != 0)
      has_intersection = true;

    if (before[i] != target->potential_buckets[i])
      has_changed = true;
  }

  /* Intersection found */
  if (has_intersection)
    return has_changed;

  /* Sets have an empty intersection, compute their union instead */
  target->potential_buckets_count = 0;
  has_changed = false;

  for (int i = 0; i < bitmap_size; i++)
  {
    target->potential_buckets[i] = left->potential_buckets[i] | right->potential_buckets[i];
    target->potential_buckets_count += u32_popcount(target->potential_buckets[i]);

    if (before[i] != target->potential_buckets[i])
      has_changed = true;
  }

  return has_changed;
}

/*
 * Dump aggregation trie
 */
static void
aggregator_trie_dump_helper(const struct aggregator_proto *p, const struct trie_node *node, ip_addr *prefix, u32 pxlen, struct buffer *buf, struct dump_request *dreq)
{
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

  for (int i = 0, j = 0; i < p->bitmap_size; i++)
  {
    if (node->potential_buckets[i] == 0)
      continue;

    u32 item = node->potential_buckets[i];

    while (item != 0)
    {
      /* Find first set bit (CLZ -- Count Leading Zeroes) */
      int bitpos = u32_clz(item);

      /* Compute ID as offset from the beginning of array */
      u32 id = i * 32 + (u32)bitpos;

      buffer_print(buf, "%u", id);
      j++;

      if (j < node->potential_buckets_count)
        buffer_print(buf, ", ");

      /* Clear first set bit and continue */
      u32 mask = 1U << (32 - bitpos - 1);
      item &= ~mask;
    }
  }

  buffer_print(buf, "}");

  if (node->selected_bucket)
    buffer_print(buf, " -> [[%u]]", node->selected_bucket->id);

  buffer_print(buf, " %p %s", node, px_origin_str[node->px_origin]);
  RDUMP("%s\n", buf->start);

  if (node->child[0])
  {
    ASSERT_DIE((u32)node->depth == pxlen);
    ip6_clrbit(prefix, node->depth + ipa_shift[p->addr_type]);
    aggregator_trie_dump_helper(p, node->child[0], prefix, pxlen + 1, buf, dreq);
  }

  if (node->child[1])
  {
    ASSERT_DIE((u32)node->depth == pxlen);
    ip6_setbit(prefix, node->depth + ipa_shift[p->addr_type]);
    aggregator_trie_dump_helper(p, node->child[1], prefix, pxlen + 1, buf, dreq);
    ip6_clrbit(prefix, node->depth + ipa_shift[p->addr_type]);
  }
}

void
aggregator_trie_dump(struct dump_request *dreq)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, dump_request_target, dreq->target);

  ip_addr prefix = (p->addr_type == NET_IP4) ? ipa_from_ip4(IP4_NONE) : ipa_from_ip6(IP6_NONE);

  struct buffer buf = { 0 };
  LOG_BUFFER_INIT(buf);

  RDUMP("======== TRIE BEGIN ========\n");
  aggregator_trie_dump_helper(p, p->root, &prefix, 0, &buf, dreq);
  RDUMP("======== TRIE   END ========\n");
}

static inline void
aggregator_create_route(struct aggregator_proto *p, ip_addr prefix, u32 pxlen, struct aggregator_bucket *bucket)
{
  struct net_addr addr = { 0 };
  net_fill_ipa(&addr, prefix, pxlen);

  /* TODO: Proč sem vlastně předáváme struct network? Mělo by nám stačit net_addr. */
  aggregator_bucket_update(p, bucket, &addr);
}

/*
 * Prepare to withdraw route for @prefix
 */
static void
aggregator_prepare_rte_withdrawal(struct aggregator_proto *p, ip_addr prefix, u32 pxlen, struct aggregator_bucket *bucket)
{
  ASSERT_DIE(p != NULL);
  ASSERT_DIE(bucket != NULL);

  /* Allocate the item */
  struct rte_withdrawal_item *item = lp_allocz(p->rte_withdrawal_pool, sizeof(*item));

  /* Fill in net and bucket */
  net_fill_ipa(&item->addr, prefix, pxlen);
  item->bucket = bucket;

  /* Push item onto stack */
  item->next = p->rte_withdrawal_stack;
  p->rte_withdrawal_stack = item;
  p->rte_withdrawal_count++;
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
    u32 bit = ip6_getbit(prefix, i + ipa_shift[p->addr_type]);

    /* Add filler nodes onto the path to the actual prefix node */
    if (!node->child[bit])
    {
      struct trie_node *new = sl_allocz(p->trie_slab);

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
    u32 bit = ip6_getbit(prefix, i + ipa_shift[p->addr_type]);
    node = node->child[bit];
    ASSERT_DIE(node != NULL);
  }

  ASSERT_DIE(node->px_origin == ORIGINAL);
  ASSERT_DIE((u32)node->depth == pxlen);

  /*
   * Even though this function is called to remove prefix from the trie, we
   * can only change its origin from original to filler. Node itself cannot be
   * removed just yet. If it was removed, we would lose information about the
   * input data which are used by the algorithm. This information is essential
   * for correctly recomputing the trie. If the algorithm decides the node is
   * no longer needed, it will be removed later.
   */
  node->px_origin = FILLER;
  node->ancestor = NULL;
  node->original_bucket = NULL;
  node->potential_buckets_count = 0;
  memset(node->potential_buckets, 0, sizeof(node->potential_buckets[0]) * p->bitmap_size);

  return node;
}

/*
 * Find prefix corresponding to the position of @target node in the trie
 * and save result into @prefix and @pxlen.
 */
static void
aggregator_find_subtree_prefix(const struct trie_node *target, ip_addr *prefix, u32 *pxlen, u32 addr_type)
{
  ASSERT_DIE(target != NULL);
  ASSERT_DIE(prefix != NULL);
  ASSERT_DIE(pxlen != NULL);

  const struct trie_node *node = target;
  const struct trie_node *parent = node->parent;

  u32 len = 0;

  /* Ascend to the root node */
  while (parent)
  {
    if (node == node->parent->child[0])
      ip6_clrbit(prefix, node->depth + ipa_shift[addr_type] - 1);
    else if (node == node->parent->child[1])
      ip6_setbit(prefix, node->depth + ipa_shift[addr_type] - 1);
    else
      bug("Corrupted memory (node is not its parent's child)");

    node = parent;
    parent = node->parent;
    len++;
  }

  /* Descend back to target node */
  for (u32 i = 0; i < len; i++)
  {
    u32 bit = ip6_getbit(*prefix, node->depth + ipa_shift[addr_type]);
    node = node->child[bit];
    ASSERT_DIE(node != NULL);
  }

  ASSERT_DIE(node == target);
  *pxlen = len;
}

/*
 * First and second pass of Optimal Route Table Construction (ORTC) algorithm
 *
 * This function is called after the trie is changed. This function is called
 * recursively.
 *
 * First, this function propagates original bucket information from the node's
 * parent to the current one. (This is basically the first pass in the original
 * algorithm.)
 *
 * Then this function calls itself to its children.
 *
 * After the recursion returns, sets of potential buckets from the children are
 * merged to form the potential_buckets bitmap of the current node.
 *
 * With this, the function both propagates changes down and up during one pass.
 *
 * The argument is the node from which to descend.
 * @node: node from which to descend
 */
static void
aggregator_propagate_and_merge(struct trie_node *node, int bitmap_size)
{
  ASSERT_DIE(node != NULL);
  ASSERT_DIE(node->status != UNASSIGNED_FIB);
  ASSERT_DIE(node->potential_buckets_count <= (int)(bitmap_size * sizeof(node->potential_buckets[0]) * 8));

  if (node->px_origin == ORIGINAL)
    ASSERT_DIE(node->original_bucket != NULL);
  else
  {
    /* Non-original node needs to get the original bucket from its parent. */
    ASSERT_DIE(node->parent->original_bucket != NULL);
    node->original_bucket = node->parent->original_bucket;

    /*
     * This node will be recalculated anyway, therefore for now we indicate
     * by FILLER that the trie state is not consistent with the routes
     * in the target routing table.
     */
    node->px_origin = FILLER;
  }

  /* Get children for traversal */
  struct trie_node *left  = node->child[0];
  struct trie_node *right = node->child[1];

  /* Special case for leaf nodes */
  if (!left && !right)
  {
    /* Reset the bucket bitmap to cleanup possible old bucket information */
    node->potential_buckets_count = 0;
    memset(node->potential_buckets, 0, sizeof(node->potential_buckets[0]) * bitmap_size);

    /*
     * For the leaf node, by definition, the only bucket in the bitmap is the
     * original bucket.
     */
    ASSERT_DIE(node->original_bucket->id < (bitmap_size * sizeof(node->potential_buckets[0]) * 8));
    aggregator_node_add_potential_bucket(node, node->original_bucket->id);

    /* No children, no further work. Done! */
    return;
  }

  /*
   * Prepare an imaginary node in case some children are missing. This node's
   * potential buckets is just this node's original bucket and nothing else.
   * This fixes the (kinda) missing first pass when comparing our algorithm
   * to the original one.
   */
  struct trie_node *imaginary_node = allocz(sizeof(*imaginary_node) + sizeof(imaginary_node->potential_buckets[0]) * bitmap_size);

  ASSERT_DIE(node->original_bucket->id < (bitmap_size * sizeof(imaginary_node->potential_buckets[0]) * 8));
  aggregator_node_add_potential_bucket(imaginary_node, node->original_bucket->id);

  /* Process children */
  if (left)
    aggregator_propagate_and_merge(left, bitmap_size);
  else
    left = imaginary_node;

  if (right)
    aggregator_propagate_and_merge(right, bitmap_size);
  else
    right = imaginary_node;

  /* Merge sets of potential buckets */
  aggregator_merge_potential_buckets(node, left, right, bitmap_size);
}

/*
 * @inherited_bucket: selected bucket of the closest ancestor of the target node
 * which is in FIB and thus has a non-null bucket
 *
 * Process nodes that have only one child during grouping of prefixes and add
 * new nodes if necessary.
 *
 * Because our implementation doesn't normalize the trie (by adding new nodes
 * so that every node has either two or zero children) during first stage of
 * aggregation, we need to decide if these missing nodes are indeed needed in
 * the trie.
 */
static void
aggregator_process_one_child_nodes(struct trie_node *node, const struct aggregator_bucket *inherited_bucket, struct slab *trie_slab, int bitmap_size)
{
  ASSERT_DIE(node != NULL);

  const size_t node_size = sizeof(*node) + sizeof(node->potential_buckets[0]) * bitmap_size;

  /* Imaginary node that would have been added during normalization of the trie */
  struct trie_node *imaginary_node = allocz(node_size);

  *imaginary_node = (struct trie_node) {
    .parent = node,
    .original_bucket = node->original_bucket,
    .status = NON_FIB,
    .px_origin = AGGREGATED,
    .depth = node->depth + 1,
  };

  /* Imaginary node inherits bucket from its parent - current node */
  ASSERT_DIE(node->original_bucket->id < (bitmap_size * sizeof(node->potential_buckets[0]) * 8));
  aggregator_node_add_potential_bucket(imaginary_node, node->original_bucket->id);

  /*
   * If the current node (parent of the imaginary node) has a bucket, then
   * the imaginary node inherits this bucket. Otherwise it inherits bucket
   * from the closest ancestor which is IN_FIB and thus has a non-null bucket.
   */
  const struct aggregator_bucket * const imaginary_node_inherited_bucket = (node->status == IN_FIB)
                                                                         ? node->selected_bucket
                                                                         : inherited_bucket;

  ASSERT_DIE(imaginary_node_inherited_bucket != NULL);

  /*
   * Since this implementation doesn't normalize the trie during first stage
   * of aggregation, we need to know if these nodes are needed in the trie.
   * These nodes are simulated by @imaginary_node. If the bucket that imaginary
   * node inherits from its IN_FIB ancestor is NOT one of its potential buckets,
   * imaginary node needs to be added to the trie because it's not covered
   * by its ancestor.
   */
  if (!aggregator_is_bucket_potential(imaginary_node, imaginary_node_inherited_bucket->id, bitmap_size))
  {
    /* Allocate new node and copy imaginary node into it */
    struct trie_node *new = sl_allocz(trie_slab);
    memcpy(new, imaginary_node, node_size);

    const struct trie_node * const left  = node->child[0];
    const struct trie_node * const right = node->child[1];

    /* Connect new node to the trie */
    if (left && !right)
      node->child[1] = new;
    else
      node->child[0] = new;
  }
}

/*
 * Export prefix of the current node to FIB and set node status to IN_FIB
 */
static void
aggregator_export_node_prefix(struct aggregator_proto *p, struct trie_node *node, ip_addr prefix, u32 pxlen)
{
  ASSERT_DIE(node->potential_buckets_count > 0);

  /* Save old bucket before assigning new */
  struct aggregator_bucket * const old_bucket = node->selected_bucket;

  /* Select bucket with the lowest ID */
  node->selected_bucket = aggregator_select_lowest_id_bucket(p, node);

  /* Node status is changing from NON_FIB to IN_FIB, export its route */
  if (node->status != IN_FIB)
  {
    aggregator_create_route(p, prefix, pxlen, node->selected_bucket);
  }
  else /* Prefix is already in FIB */
  {
    ASSERT_DIE(old_bucket != NULL);

    /* Node's bucket has changed, remove old route and export new */
    if (old_bucket && old_bucket != node->selected_bucket)
    {
      aggregator_prepare_rte_withdrawal(p, prefix, pxlen, old_bucket);
      aggregator_create_route(p, prefix, pxlen, node->selected_bucket);
    }
  }

  node->status = IN_FIB;
  node->ancestor = node;

  /* Original prefix stays original, otherwise it becomes aggregated */
  node->px_origin = (node->px_origin == ORIGINAL) ? ORIGINAL : AGGREGATED;
}

/*
 * Remove prefix of the current node from FIB and set node status to NON_FIB
 */
static void
aggregator_withdraw_node_prefix(struct aggregator_proto *p, struct trie_node *node, ip_addr prefix, u32 pxlen)
{
  /* Node status is changing from IN_FIB to NON_FIB, withdraw its route */
  if (node->status == IN_FIB)
  {
    ASSERT_DIE(node->selected_bucket != NULL);
    aggregator_prepare_rte_withdrawal(p, prefix, pxlen, node->selected_bucket);
  }

  node->selected_bucket = NULL;
  node->status = NON_FIB;
  node->ancestor = node->parent->ancestor;

  /*
   * Original prefix stays original, otherwise it was aggregated and becomes
   * a filler.
   */
  node->px_origin = (node->px_origin == ORIGINAL) ? ORIGINAL : FILLER;
}

/*
 * This functions moves from the target node downwards to the leaves and
 * decides which prefixes are the result of the aggregation and will be
 * exported to the FIB.
 * Each node (except root node) is covered by one of its ancestors. We can say
 * that each node "inherits" selected bucket from one of its ancestors. If this
 * inherited bucket is one of the node's potential buckets, then this prefix
 * will not go to the FIB, because its address space is already covered by some
 * shorter prefix. However, if enherited bucket is not one of the node's
 * potential bucket, then a bucket for this node is chosen from its set and the
 * prefix is exported to the FIB.
 */
static void
aggregator_group_prefixes_helper(struct aggregator_proto *p, struct trie_node *node, ip_addr *prefix, u32 pxlen)
{
  ASSERT_DIE(node != NULL);
  ASSERT_DIE(node->status != UNASSIGNED_FIB);
  ASSERT_DIE(node->potential_buckets_count <= (int)(p->bitmap_size * sizeof(node->potential_buckets[0]) * 8));

  ASSERT_DIE(node->original_bucket != NULL);
  ASSERT_DIE(node->parent->ancestor != NULL);
  ASSERT_DIE(node->parent->ancestor->selected_bucket != NULL);

  /* Bucket inherited from the closest ancestor with a non-null selected bucket */
  const struct aggregator_bucket * const inherited_bucket = node->parent->ancestor->selected_bucket;

  /*
   * If the bucket inherited from the ancestor is one of potential buckets
   * of the current node, then this node doesn't need a bucket because it
   * inherits one, and its prefix is thus not needed in FIB.
   */
  if (aggregator_is_bucket_potential(node, inherited_bucket->id, p->bitmap_size))
    aggregator_withdraw_node_prefix(p, node, *prefix, pxlen);
  else
    aggregator_export_node_prefix(p, node, *prefix, pxlen);

  ASSERT_DIE((node->selected_bucket != NULL && node->status == IN_FIB) || (node->selected_bucket == NULL && node->status == NON_FIB));
  ASSERT_DIE(node->ancestor != NULL);
  ASSERT_DIE(node->ancestor->original_bucket != NULL);
  ASSERT_DIE(node->ancestor->selected_bucket != NULL);

  const struct trie_node * const left  = node->child[0];
  const struct trie_node * const right = node->child[1];

  /* Process nodes with only one child */
  if ((left && !right) || (!left && right))
    aggregator_process_one_child_nodes(node, inherited_bucket, p->trie_slab, p->bitmap_size);

  /* Preorder traversal */
  if (node->child[0]) /* TODO: nestačí tady left a right? Takhle to vypadá, že se left a right pod rukama můžou přepsat. */
  {
    ASSERT_DIE((u32)node->depth == pxlen);
    ip6_clrbit(prefix, node->depth + ipa_shift[p->addr_type]);
    aggregator_group_prefixes_helper(p, node->child[0], prefix, pxlen + 1);
  }

  if (node->child[1])
  {
    ASSERT_DIE((u32)node->depth == pxlen);
    ip6_setbit(prefix, node->depth + ipa_shift[p->addr_type]);
    aggregator_group_prefixes_helper(p, node->child[1], prefix, pxlen + 1);
    ip6_clrbit(prefix, node->depth + ipa_shift[p->addr_type]);
  }

  /* Prune the trie */
  if (node->status == NON_FIB && node->px_origin != ORIGINAL && !node->child[0] && !node->child[1])
  {
    ASSERT_DIE(node->selected_bucket == NULL);
    aggregator_remove_node(node);
  }
}

/*
 * Third pass of Optimal Route Table Construction (ORTC) algorithm
 *
 * This functions represents final stage of aggregation. It decides which
 * prefixes will be exported into FIB. In that case, it selects bucket for
 * the target node from the set of its potential buckets and creates new
 * route for this prefix. Recursively group prefixes in the subtree rooted
 * at @node.
 */
static void
aggregator_group_prefixes(struct aggregator_proto *p, struct trie_node *node)
{
  ASSERT_DIE(node != NULL);
  ASSERT_DIE(node->potential_buckets_count > 0);
  ASSERT_DIE(node->potential_buckets_count <= (int)(p->bitmap_size * sizeof(node->potential_buckets[0]) * 8));

  ip_addr prefix = (p->addr_type == NET_IP4) ? ipa_from_ip4(IP4_NONE) : ipa_from_ip6(IP6_NONE);
  u32 pxlen = 0;

  /*
   * If this function runs on a subtree and not the whole trie,
   * find prefix that covers this subtree.
   */
  aggregator_find_subtree_prefix(node, &prefix, &pxlen, p->addr_type);

  /* Export prefix of the current node */
  aggregator_export_node_prefix(p, node, prefix, pxlen);

  if (node->child[0])
  {
    ASSERT_DIE((u32)node->depth == pxlen);
    ip6_clrbit(&prefix, node->depth + ipa_shift[p->addr_type]);
    aggregator_group_prefixes_helper(p, node->child[0], &prefix, pxlen + 1);
  }

  if (node->child[1])
  {
    ASSERT_DIE((u32)node->depth == pxlen);
    ip6_setbit(&prefix, node->depth + ipa_shift[p->addr_type]);
    aggregator_group_prefixes_helper(p, node->child[1], &prefix, pxlen + 1);
    ip6_clrbit(&prefix, node->depth + ipa_shift[p->addr_type]);
  }
}

/*
 * Check trie consistency and invariants
 */
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
 * Merge sets of potential buckets of node's children going from @node upwards.
 * Stop when the node's set doesn't change and return the last updated node.
 */
static struct trie_node *
aggregator_merge_buckets_above(struct trie_node *node, int bitmap_size)
{
  ASSERT_DIE(node != NULL);

  struct trie_node *parent = node->parent;

  while (parent)
  {
    const struct trie_node *left  = parent->child[0];
    const struct trie_node *right = parent->child[1];
    ASSERT_DIE(left == node || right == node);

    struct trie_node *imaginary_node = allocz(sizeof(*imaginary_node) + sizeof(imaginary_node->potential_buckets[0]) * bitmap_size);

    ASSERT_DIE(parent->original_bucket->id < (bitmap_size * sizeof(imaginary_node->potential_buckets[0]) * 8));
    aggregator_node_add_potential_bucket(imaginary_node, parent->original_bucket->id);

    /* Nodes with only one child */
    if (left && !right)
      right = imaginary_node;
    else if (!left && right)
      left = imaginary_node;

    ASSERT_DIE(left != NULL && right != NULL);

    /* The parent's set didn't change by merging, stop here */
    if (!aggregator_merge_potential_buckets(parent, left, right, bitmap_size))
      return node;

    node = parent;
    parent = node->parent;
  }

  return node;
}

static void
aggregator_construct_trie(struct aggregator_proto *p)
{
  HASH_WALK(p->buckets, next_hash, bucket)
  {
    for (const struct rte *rte = bucket->rte; rte; rte = rte->next)
    {
      const struct net_addr *addr = rte->net->n.addr;

      ip_addr prefix = net_prefix(addr);
      u32 pxlen = net_pxlen(addr);

      aggregator_trie_insert_prefix(p, prefix, pxlen, bucket);
    }
  }
  HASH_WALK_END;
}

/*
 * Run Optimal Routing Table Constructor (ORTC) algorithm
 */
static void
aggregator_compute_trie(struct aggregator_proto *p)
{
  ASSERT_DIE(p->addr_type == NET_IP4 || p->addr_type == NET_IP6);

  aggregator_propagate_and_merge(p->root, p->bitmap_size);
  aggregator_group_prefixes(p, p->root);

  check_trie_after_aggregation(p->root);
}

void
aggregator_aggregate(struct aggregator_proto *p)
{
  ASSERT_DIE(p->root != NULL);

  aggregator_construct_trie(p);
  aggregator_compute_trie(p);
}

/*
 * Incorporate prefix change into the trie and reaggregate
 */
void
aggregator_recompute(struct aggregator_proto *p, struct aggregator_route *old, struct aggregator_route *new)
{
  struct trie_node *updated_node = NULL;

  /* Withdraw */
  if (old && !new)
  {
    const struct net_addr *addr = old->rte.net->n.addr;

    ip_addr prefix = net_prefix(addr);
    u32 pxlen = net_pxlen(addr);

    updated_node = aggregator_trie_remove_prefix(p, prefix, pxlen);
    ASSERT_DIE(updated_node != NULL);
  }
  else /* Announce or update */
  {
    const struct net_addr *addr = new->rte.net->n.addr;

    ip_addr prefix = net_prefix(addr);
    u32 pxlen = net_pxlen(addr);

    updated_node = aggregator_trie_insert_prefix(p, prefix, pxlen, new->bucket);

    ASSERT_DIE(updated_node != NULL);
    ASSERT_DIE(updated_node->px_origin == ORIGINAL);
    ASSERT_DIE(updated_node->original_bucket != NULL);
  }

  struct trie_node *ancestor = updated_node;

  /* Find the closest IN_FIB ancestor of the updated node */
  while (ancestor = ancestor->parent)
  {
    ASSERT_DIE(ancestor != updated_node);

    /* Stop when IN_FIB ancestor is found or when we cannot continue further */
    if (ancestor->status == IN_FIB || !ancestor->parent)
      break;
  }

  ASSERT_DIE(ancestor != NULL);
  ASSERT_DIE(ancestor != updated_node);
  ASSERT_DIE(ancestor->status == IN_FIB);

  /* Reaggregate trie with incorporated update */
  aggregator_propagate_and_merge(ancestor, p->bitmap_size);

  /* Merge buckets upwards until they change, return last updated node */
  struct trie_node *highest_node = aggregator_merge_buckets_above(ancestor, p->bitmap_size);
  ASSERT_DIE(highest_node != NULL);

  aggregator_group_prefixes(p, highest_node);
  check_trie_after_aggregation(highest_node);
}
