#include "mib_tree.h"
#include "snmp_utils.h"

#ifdef allocz
#undef allocz
#endif

#define alloc(size) mb_alloc(p, size)
#define allocz(size) mb_allocz(p, size)
#define free(ptr) mb_free(ptr)
#define realloc(ptr, newsize) mib_mb_realloc(p, ptr, newsize)

/*
 * mib_mb_realloc - fix mb_realloc for NULL
 * @p: pool to use for NULL pointers
 * @ptr: old pointer to be reallocated
 * @size: new size of allocated memory block
 *
 * The mb_realloc() does not work with NULL as ptr.
 */
static inline void *
mib_mb_realloc(pool *p, void *ptr, unsigned size)
{
  if (!ptr)
    return mb_alloc(p, size);

  return mb_realloc(ptr, size);
}

/*
 * mib_tree_init - Initialize a MIB tree
 * @p: allocation source pool
 * @t: pointer to a tree being initialized
 *
 * By default the standard SNMP internet prefix (.1.3.6.1) is inserted into the
 * tree.
 */
void
mib_tree_init(pool *p, struct mib_tree *t)
{
  struct mib_node *node = &t->root;
  node->c.id = 0;
  node->c.flags = 0;
  node->children = NULL;
  node->child_len = 0;

  struct oid *oid = tmp_alloc(
    snmp_oid_size_from_len((uint) ARRAY_SIZE(snmp_internet)));
  oid->n_subid =  ARRAY_SIZE(snmp_internet);
  oid->prefix = 0;
  oid->include =  0;
  oid->reserved = 0;

  for (size_t i = 0; i < ARRAY_SIZE(snmp_internet); i++)
    oid->ids[i] = snmp_internet[i];

  (void) mib_tree_add(p, t, oid, 0);
}

int
mib_tree_hint(pool *p, struct mib_tree *t, const struct oid *oid, uint size)
{
  mib_node_u *node = mib_tree_add(p, t, oid, 0);
  if (!node || mib_node_is_leaf(node))
    return 0;

  struct mib_node *inner = &node->inner;
  if (inner->child_len >= size + 1)
    return 1;

  u32 old_len = inner->child_len;
  inner->child_len = size + 1;
  inner->children = realloc(inner->children,
    inner->child_len * sizeof(mib_node_u *));

  for (u32 i = old_len; i < inner->child_len; i++)
    inner->children[i] = NULL;
  return 1;
}


// TODO: This function does not work with leaf nodes inside the snmp_internet prefix
// area
// Return NULL of failure, valid mib_node_u pointer otherwise

/*
 * mib_tree_add - Insert a new node to the tree
 * @p: allocation source pool
 * @t: MIB tree to insert to
 * @oid: identification of inserted node.
 * @is_leaf: flag signaling that inserted OID should be leaf node.
 *
 * Reinsertion only return already valid node pointer, no allocations are done
 * in this case. Return pointer to node in the MIB tree @t or NULL if the
 * requested insertion is invalid. Insertion is invalid if we want to insert
 * node below a leaf or insert a leaf in place taken by normal node.
 *
 */
mib_node_u *
mib_tree_add(pool *p, struct mib_tree *t, const struct oid *oid, int is_leaf)
{
  struct mib_walk_state walk;
  mib_node_u *node;

  /* The empty prefix is associated with the root tree node */
  if (snmp_is_oid_empty(oid) && !is_leaf)
    return (mib_node_u *) &t->root;
  else if (snmp_is_oid_empty(oid))
    return NULL;

  mib_tree_walk_init(&walk, t);
  node = mib_tree_find(t, &walk, oid);
  ASSERT(walk.id_pos <= oid->n_subid + 1);

  if (node)
  {
    if (mib_node_is_leaf(node) == is_leaf)
      return node;

    /* we are trying to insert a leaf node in place of inner node,
     * or vice versa */
    return NULL;
  }

  ASSERT(walk.id_pos < oid->n_subid + 1);

  node = walk.stack[walk.stack_pos - 1];
  /* we encounter leaf node before end of OID's id path */
  if (mib_node_is_leaf(node))
    return NULL;

  struct mib_node *node_inner = &node->inner;
  if (snmp_oid_is_prefixed(oid) &&
      walk.stack_pos <= ARRAY_SIZE(snmp_internet) + 1)
  {
    ASSUME(walk.stack_pos && walk.stack[0] == (mib_node_u *) &t->root);

    for (u32 id = walk.stack_pos - 1; id < ARRAY_SIZE(snmp_internet); id++)
    {
      if (snmp_internet[id] >= node_inner->child_len)
      {
	u32 old_len = node_inner->child_len;
	node_inner->child_len = snmp_internet[id] + 1;
	node_inner->children = realloc(node_inner->children,
	  node_inner->child_len * sizeof(mib_node_u *));

	for (u32 i = old_len; i < node_inner->child_len; i++)
	  node_inner->children[i] = NULL;
      }

      node = allocz(sizeof(struct mib_node));
      /* assign child into a parent's children array */
      node_inner->children[snmp_internet[id]] = node;
      node_inner = &node->inner;
      node_inner->c.id = snmp_internet[id];
      /* node_inner's fields c.flags, child_len, children defaults to zero or
       * NULL respectively */
      walk.stack[walk.stack_pos++] = node;
    }

    if (walk.stack_pos == ARRAY_SIZE(snmp_internet) + 1)
    {
      u32 old_len = node_inner->child_len;
      node_inner->child_len = MAX(old_len, (u32) oid->prefix + 1);
      node_inner->children = realloc(node_inner->children,
	node_inner->child_len * sizeof(mib_node_u *));

      for (u32 i = old_len; i < node_inner->child_len; i++)
	node_inner->children[i] = NULL;

      if (is_leaf && !oid->n_subid)
      {
	node = allocz(sizeof(struct mib_leaf));
	node->empty.flags = MIB_TREE_LEAF;
      }
      else
      {
	node = allocz(sizeof(struct mib_node));
	node->empty.flags = 0;
      }

      node->empty.id = oid->prefix;
      /* add node into the parent's children array */
      node_inner->children[oid->prefix] = node;
      node_inner = &node->inner;
      walk.stack[walk.stack_pos++] = node;
    }
  }

  /* snmp_internet + 2 = empty + snmp_internet + prefix */
  if (snmp_oid_is_prefixed(oid) &&
      walk.stack_pos == ARRAY_SIZE(snmp_internet) + 2 &&
      oid->n_subid == 0 &&
      mib_node_is_leaf(node) == is_leaf)
    return node;

  if (mib_node_is_leaf(node))
    return node;

  u8 subids = oid->n_subid;
  u32 old_len = node_inner->child_len;
  u32 child_id = oid->ids[walk.id_pos];
  node_inner->child_len = MAX(old_len, child_id + 1);
  node_inner->children = realloc(node_inner->children,
    node_inner->child_len * sizeof(mib_node_u *));

  for (u32 i = old_len; i < node_inner->child_len; i++)
    node_inner->children[i] = NULL;

  struct mib_node *parent;
  /* break to loop before last node in the oid */
  for (; walk.id_pos < subids - 1;)
  {
    parent = node_inner;
    node_inner = allocz(sizeof(struct mib_node));

    parent->children[child_id] = (mib_node_u *) node_inner;
    node_inner->c.id = child_id;

    child_id = oid->ids[++walk.id_pos];

    node_inner->child_len = child_id + 1;
    node_inner->children = allocz(node_inner->child_len * sizeof(mib_node_u *));
  }

  parent = node_inner;
  mib_node_u *last;
  if (is_leaf)
  {
    last = allocz(sizeof(struct mib_leaf));
    struct mib_leaf *leaf = &last->leaf;

    parent->children[child_id] = (mib_node_u *) leaf;
    leaf->c.id = child_id;

    leaf->c.flags = MIB_TREE_LEAF;
  }
  else
  {
    last = allocz(sizeof(struct mib_node));
    node_inner = &last->inner;

    parent->children[child_id] = (mib_node_u *) node_inner;
    node_inner->c.id = child_id;
    /* fields c.flags, child_len and children are set by zeroed allocz() */
  }

  return last;
}

/*
 * mib_tree_delete - delete a MIB subtree
 * @t: MIB tree
 * @walk: MIB tree walk state that specify the subtree
 *
 * Return number of nodes deleted in the subtree. It is possible to delete an empty
 * prefix which leads to deletion of all nodes inside the MIB tree. Note that
 * the empty prefix (tree root) node itself could be deleted therefore 0 may be
 * returned in case of empty prefix deletion.
 */
int
mib_tree_delete(struct mib_tree *t, struct mib_walk_state *walk)
{
  int deleted = 0;
  if (!t)
    return 0;

  /* (walk->stack_pos < 2) It is impossible to delete root node */
  if (!walk || walk->stack_pos == 0)
    return 0;

  if (walk->stack_pos == 1)
  {
    for (u32 child = 0; child < t->root.child_len; child++)
    {
      if (!t->root.children[child])
	continue;

      walk->stack_pos = 2;
      walk->stack[0] = (mib_node_u*) &t->root;
      walk->stack[1] = t->root.children[child];

      deleted += mib_tree_delete(t, walk);
    }

    return deleted;
  }

  struct mib_node *parent = &walk->stack[walk->stack_pos - 2]->inner;
  mib_node_u *node = walk->stack[walk->stack_pos - 1];

  struct mib_walk_state delete = {
    .id_pos = walk->id_pos,
    .stack_pos = 2,
    .stack = {
      (mib_node_u *) parent,
      node,
      NULL,
    },
  };

  u32 last_id = 0;
  while (delete.stack_pos > 1)
  {
continue_while:	  /* like outer continue, but skip always true condition */
    parent = (struct mib_node *) delete.stack[delete.stack_pos - 2];

    if (mib_node_is_leaf(node))
    {
      /* Free leaf node */
      last_id = node->leaf.c.id;
      parent->children[last_id] = NULL;
      delete.stack[--delete.stack_pos] = NULL;
      free(node);
      deleted++;
      node = delete.stack[delete.stack_pos - 1];
      continue;	  /* here, we couldn't skip the while condition */
    }

    struct mib_node *node_inner = &node->inner;
    mib_node_u *child = NULL;
    for (u32 id = last_id; id < node_inner->child_len; id++)
    {
      /* Recursively traverse child nodes */
      child = node_inner->children[id];

      if (!child)
	continue;

      last_id = 0;
      delete.stack[delete.stack_pos++] = child;
      parent = node_inner;
      node = child;
      goto continue_while;    /* outer continue */
    }

    /* Free inner node without any children */
    last_id = node_inner->c.id;
    parent->children[last_id] = NULL;
    delete.stack[--delete.stack_pos] = NULL;
    free(node_inner->children);
    free(node_inner);
    deleted++;
    node = (mib_node_u *) parent;

    /* skip check for deleted node in loop over children */
    last_id++;
  }

  /* delete the node from original stack */
  walk->stack[--walk->stack_pos] = NULL;

  node = walk->stack[walk->stack_pos - 1];
  struct mib_node *node_inner = &node->inner;
  u32 id;
  for (id = 0; id < node_inner->child_len; id++)
  {
    if (node_inner->children[id] != NULL)
      break;
  }

  if (id == node_inner->child_len)
  {
    /* all the children are NULL */
    free(node_inner->children);
    node_inner->children = NULL;
    node_inner->child_len = 0;
  }

  return deleted;
}

/*
 * mib_tree_remove - delete a MIB subtree
 * @t: MIB tree
 * @oid: object identifier specifying the subtree
 *
 * This is a convenience wrapper around mib_tree_delete(). The mib_tree_remove()
 * finds the corresponding node and deletes it. Return 0 if the OID was not
 * found. Otherwise return number of deleted nodes (see mib_tree_delete() for
 * more details).
 */
int
mib_tree_remove(struct mib_tree *t, const struct oid *oid)
{
  struct mib_walk_state walk = { };
  mib_node_u *node = mib_tree_find(t, &walk, oid);

  if (!node)
    return 0;

  return mib_tree_delete(t, &walk);
}

/*
 * mib_tree_find - Find a OID node in MIB tree
 * @t: searched tree
 * @walk: output search state
 * @oid: searched node identification
 *
 * Return valid pointer to node in MIB tree or NULL. The search state @walk is
 * always updated and contains the longest possible prefix of @oid present
 * inside the tree @t. The @walk must not be NULL and must be blank (only
 * initialized).
 */
mib_node_u *
mib_tree_find(const struct mib_tree *t, struct mib_walk_state *walk, const struct oid *oid)
{
  ASSERT(t && walk);

  if (!oid || snmp_is_oid_empty(oid))
  {
    walk->stack_pos = 1;
    walk->stack[0] = (mib_node_u *) &t->root;
    return (snmp_is_oid_empty(oid)) ? (mib_node_u *) &t->root : NULL;
  }

  mib_node_u *node;
  struct mib_node *node_inner;

  /* the OID id index to use */
  u8 oid_pos = walk->id_pos;

  if (walk->stack_pos > 0)
    node = walk->stack[walk->stack_pos - 1];
  else
    node = walk->stack[walk->stack_pos++] = (mib_node_u *) &t->root;

  if (mib_node_is_leaf(node))
  {
    /* In any of cases below we did not move in the tree therefore the
     * walk->id_pos is left untouched. */
    if (snmp_oid_is_prefixed(oid) &&
	oid->n_subid + ARRAY_SIZE(snmp_internet) + 1 == walk->id_pos)
      return node;

    else if (snmp_oid_is_prefixed(oid) &&
	oid->n_subid + ARRAY_SIZE(snmp_internet) + 1 > walk->id_pos)
      return NULL;

    else if (!snmp_oid_is_prefixed(oid) && oid->n_subid + 1 == walk->id_pos)
      return node;
  }

  node_inner = &node->inner;
  ASSERT(node); /* node may be leaf if OID is not in tree t */

  /* Handling of prefixed OID */
  if (snmp_oid_is_prefixed(oid) && walk->stack_pos < 6)
  {
    /* The movement inside implicit SNMP internet and following prefix is not
     * projected to walk->id_pos. */
    uint i = (uint) walk->stack_pos - 1;
    /* walking the snmp_internet prefix itself */
    for (; i < ARRAY_SIZE(snmp_internet); i++)
    {
      if (node_inner->child_len <= snmp_internet[i])
	return NULL;

      node = node_inner->children[snmp_internet[i]];
      node_inner = &node->inner;

      if (!node)
	return NULL;

      ASSERT(node->empty.id == snmp_internet[i]);
      walk->stack[walk->stack_pos++] = node;

      if (mib_node_is_leaf(node))
	return NULL;
    }

    /* walking the prefix continuation (OID field oid->prefix) */
    u8 prefix = oid->prefix;
    if (node_inner->child_len <= prefix)
      return NULL;

    node = node_inner->children[prefix];
    node_inner = &node->inner;

    if (!node)
      return NULL;

    ASSERT(node->empty.id == prefix);
    walk->stack[walk->stack_pos++] = node;

    if (mib_node_is_leaf(node) && oid->n_subid > 0)
      return NULL;
  }

  u8 subids = oid->n_subid;
  if (subids == 0)
    return (node == (mib_node_u *) &t->root) ? NULL : node;

  /* loop for all OID's ids except the last one */
  for (; oid_pos < subids - 1 && walk->stack_pos < MIB_WALK_STACK_SIZE + 1; oid_pos++)
  {
    u32 id = oid->ids[oid_pos];
    if (node_inner->child_len <= id)
    {
      /* The walk->id_pos points after the last accepted OID id.
       * This is correct because we did not find the last OID in the tree. */
      walk->id_pos = oid_pos;
      return NULL;
    }

    node = node_inner->children[id];
    node_inner = &node->inner;

    if (!node)
    {
      /* Same as above, the last node is not valid therefore the walk->is_pos
       * points after the last accepted OID id. */
      walk->id_pos = oid_pos;
      return NULL;
    }

    ASSERT(node->empty.id == id);
    walk->stack[walk->stack_pos++] = node;

    if (mib_node_is_leaf(node))
    {
      /* We need to increment the oid_pos because the walk->is_pos suppose the
       * pointer after the last valid OID id. */
      walk->id_pos = ++oid_pos;
      return NULL;
    }
  }

  walk->id_pos = oid_pos;
  u32 last_id = oid->ids[oid_pos];
  if (node_inner->child_len <= last_id ||
      walk->stack_pos >= MIB_WALK_STACK_SIZE + 1)
    return NULL;

  node = node_inner->children[last_id];
  node_inner = &node->inner;

  if (!node)
    return NULL;

  /* here, the check of node being a leaf is intentionally omitted
   * because we may need to search for a inner node */
  ASSERT(node->empty.id == last_id);

  /* We need to increment the oid_pos because the walk->is_pos suppose the
   * pointer after the last valid OID id. */
  walk->id_pos = ++oid_pos;
  return walk->stack[walk->stack_pos++] = node;
}

void
mib_tree_walk_init(struct mib_walk_state *walk, const struct mib_tree *t)
{
  walk->id_pos = 0;
  walk->stack_pos = (t != NULL) ? 1 : 0;
  memset(&walk->stack, 0, sizeof(walk->stack));

  if (t != NULL)
    walk->stack[0] = (mib_node_u *) &t->root;
}

static inline int
walk_is_prefixable(const struct mib_walk_state *walk)
{
  /* empty prefix and oid->prefix (+2) */
  if (walk->stack_pos < ARRAY_SIZE(snmp_internet) + 2)
    return 0;

  for (uint i = 0; i < ARRAY_SIZE(snmp_internet); i++)
  {
    if (walk->stack[i + 1]->empty.id != snmp_internet[i])
      return 0;
  }

  u32 id = walk->stack[ARRAY_SIZE(snmp_internet) + 1]->empty.id;
  return id > 0 && id <= UINT8_MAX;
}

int
mib_tree_walk_to_oid(const struct mib_walk_state *walk, struct oid *result, u32 subids)
{
  ASSERT(walk && result);

  /* the stack_pos point after last valid index, and the first is always empty
   * prefix */
  if (walk->stack_pos <= 1)
  {
    /* create a null valued OID; sets all n_subid, prefix, include and reserved */
    memset(result, 0, sizeof(struct oid));
    return 0;
  }

  u32 index;
  if (walk_is_prefixable(walk))
  {
    if (walk->stack_pos - 2 > subids - (ARRAY_SIZE(snmp_internet) + 1))
      return 1;

    /* skip empty prefix, whole snmp_internet .1.3.6.1 and oid->prefix */
    index = 2 + ARRAY_SIZE(snmp_internet);
    result->n_subid = walk->stack_pos - (ARRAY_SIZE(snmp_internet) + 2);
    result->prefix = \
      walk->stack[ARRAY_SIZE(snmp_internet) + 1]->empty.id;
  }
  else
  {
    if (walk->stack_pos - 2 > subids)
      return 1;

    index = 1;	/* skip empty prefix */
    result->n_subid = walk->stack_pos - 1;
    result->prefix = 0;
  }

  result->include = 0;
  result->reserved = 0;

  u32 i = 0;
  /* the index could point after last stack array element */
  for (; index < walk->stack_pos && index < MIB_WALK_STACK_SIZE; index++)
    result->ids[i++] = walk->stack[index]->empty.id;

  return 0;
}

/*
 * return -1 if walk_oid < oid
 * return 0 if walk_oid == oid
 * return +1 if walk_oid > oid
 *
 */
// TODO tests, doc string
int
mib_tree_walk_oid_compare(const struct mib_walk_state *walk, const struct oid *oid)
{
  /* code is very similar to snmp_oid_compare() */
  if (!walk->stack_pos)
    return -1;

  uint walk_idx = 1;
  u8 walk_subids = walk->stack_pos;	  /* left_subids */
  u8 oid_subids = oid->n_subid;  /* right_subids */

  const u8 oid_prefix = oid->prefix;

  if (oid_prefix != 0)
  {
    for (; walk_idx < walk_subids && walk_idx < ARRAY_SIZE(snmp_internet) + 1; walk_idx++)
    {
      u32 id = walk->stack[walk_idx]->empty.id;
      if (id < snmp_internet[walk_idx - 1])
	return -1;
      else if (id > snmp_internet[walk_idx - 1])
	return 1;
    }

    if (walk_idx == walk_subids)
      return 1;

    const u8 walk_prefix = walk->stack[walk_idx++]->empty.id;
    if (walk_prefix < oid_prefix)
      return -1;
    else if (walk_prefix > oid_prefix)
      return 1;
  }

  uint i = 0;
  for (; i < oid_subids && walk_idx < walk_subids; i++, walk_idx++)
  {
    u32 walk_id = walk->stack[walk_idx]->empty.id;
    u32 oid_id = oid->ids[i];
    if (walk_id < oid_id)
      return -1;
    else if (walk_id > oid_id)
      return 1;
  }

  if (walk_idx == walk_subids && i == oid_subids)
    return 0;
  else if (walk_idx == walk_subids)
    return -1;
  else /* if (i == oid_subids) */
    return 1;
}



/**
 * mib_tree_walk_is_oid_descendant - check if OID is in walk subtree
 * @walk: MIB tree walk state
 * @oid: OID to use
 *
 * Return 0 if @walk specify same path in MIB tree as @oid, return +1 if @oid is
 * in @walk subtree, return -1 otherwise.
 */
int
mib_tree_walk_is_oid_descendant(const struct mib_walk_state *walk, const struct oid *oid)
{
  /* walk stack index skipped zero prefix and OID subidentifier index */
  u32 i = 1, j = 0;

  if (!walk->stack_pos && snmp_is_oid_empty(oid))
    return 0;

  if (snmp_oid_is_prefixed(oid))
  {
    for (; i < MIN(walk->stack_pos - 1, ARRAY_SIZE(snmp_internet) + 1); i++)
    {
      if (walk->stack[i]->empty.id != snmp_internet[i - 1])
	return -1;
    }

    if (i == walk->stack_pos)
      return +1;

    if (i < walk->stack_pos &&
	walk->stack[i]->empty.id != (u32) oid->prefix)
      return -1;

    i++;
  }

  u32 ids = oid->n_subid;
  for (; i < walk->stack_pos && j < ids; i++, j++)
  {
    if (walk->stack[i]->empty.id != oid->ids[j])
      return -1;
  }

  if (i < walk->stack_pos)
    return -1;
  else if (i == walk->stack_pos && j == ids)
    return 0;
  else if (i == walk->stack_pos)
    return +1;
  else
  {
    die("unreachable");
    return -1;
  }
}

mib_node_u *
mib_tree_walk_next(const struct mib_tree *t, struct mib_walk_state *walk)
{
  ASSERT(t && walk);

  u32 next_id = 0;

  if (walk->stack_pos == 0)
    return NULL;

  mib_node_u *node = walk->stack[walk->stack_pos - 1];

  if (mib_node_is_leaf(node))
  {
    next_id = node->leaf.c.id + 1;
    walk->stack[--walk->stack_pos] = NULL;
    node = walk->stack[walk->stack_pos - 1];
  }

  while (walk->stack_pos > 0)
  {
    node = walk->stack[walk->stack_pos - 1];

    if (mib_node_is_leaf(node))
    {
      walk->stack[walk->stack_pos++] = node;
      return node;
    }

    struct mib_node *node_inner = &node->inner;
    for (u32 id = next_id; id < node_inner->child_len; id++)
    {
      mib_node_u *child = node_inner->children[id];

      if (!child)
	continue;

      walk->stack[walk->stack_pos++] = child;
      return child;
    }

    next_id = node_inner->c.id + 1;
    walk->stack[--walk->stack_pos] = NULL;
  }

  return NULL;
}

struct mib_leaf *
mib_tree_walk_next_leaf(const struct mib_tree *t, struct mib_walk_state *walk, u32 skip)
{
  (void)t;

  if (walk->stack_pos == 0)
    return NULL;

  u32 next_id = skip;
  mib_node_u *node = walk->stack[walk->stack_pos - 1];

  if (mib_node_is_leaf(node) && walk->stack_pos > 1)
  {
    next_id = node->leaf.c.id + 1;
    walk->stack[--walk->stack_pos] = NULL;
    node = walk->stack[walk->stack_pos - 1];
  }
  else if (mib_node_is_leaf(node))
  {
    /* walk->stack_pos == 1, so we NULL out the last stack field */
    walk->stack[--walk->stack_pos] = NULL;
    return NULL;
  }

  while (walk->stack_pos > 0)
  {
continue_while:
    node = walk->stack[walk->stack_pos - 1];

    if (mib_node_is_leaf(node))
      return (struct mib_leaf *) node;

    struct mib_node *node_inner = &node->inner;
    for (u32 id = next_id; id < node_inner->child_len; id++)
    {
      mib_node_u *child = node_inner->children[id];

      if (!child)
	continue;

      next_id = 0;
      walk->stack[walk->stack_pos++] = child;
      /* node is assign at the beginning of the while loop (from stack) */
      goto continue_while;
    }

    next_id = node->empty.id + 1;
    walk->stack[--walk->stack_pos] = NULL;
  }

  return NULL;
}

