#include "mib_tree.h"
#include "snmp_utils.h"

/* TODO does the code handle leafs correctly ?! */

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
  STORE_U8(oid->n_subid, ARRAY_SIZE(snmp_internet));
  STORE_U8(oid->prefix, 0);
  STORE_U8(oid->include, 0);
  STORE_U8(oid->reserved, 0);

  for (size_t i = 0; i < ARRAY_SIZE(snmp_internet); i++)
    STORE_U32(oid->ids[i], snmp_internet[i]);

  (void) mib_tree_add(p, t, oid, 0);

  /* WTF ??
  struct mib_walk_state walk = { };
  (void) mib_tree_find(t, &walk, oid);
*/
}


// This function does not work with leaf nodes inside the snmp_internet prefix
// area
// Return NULL of failure, valid mib_node_u pointer otherwise
mib_node_u *
mib_tree_add(pool *p, struct mib_tree *t, const struct oid *oid, int is_leaf)
{
  //ASSERT(snmp_oid_is_prefixed(oid) || !snmp_oid_is_prefixable(oid));
  struct mib_walk_state walk;
  mib_node_u *node;

  /* The empty prefix is associated with the root tree node */
  if (snmp_is_oid_empty(oid) && !is_leaf)
    return (mib_node_u *) &t->root;
  else if (snmp_is_oid_empty(oid))
    return NULL;

  mib_tree_walk_init(&walk);
  node = mib_tree_find(t, &walk, oid);
  ASSERT(walk.id_pos <= LOAD_U8(oid->n_subid) + 1);

  if (node)
  {
    if (mib_node_is_leaf(node) == is_leaf)
      return node;

    /* we are trying to insert a leaf node in place of inner node,
     * or vice versa */
    return NULL;
  }

  ASSERT(walk.id_pos < LOAD_U8(oid->n_subid) + 1);

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
      node_inner->child_len = MAX(old_len, (u32) LOAD_U8(oid->prefix) + 1);
      node_inner->children = realloc(node_inner->children,
	node_inner->child_len * sizeof(mib_node_u *));

      for (u32 i = old_len; i < node_inner->child_len; i++)
	node_inner->children[i] = NULL;

      if (is_leaf && !LOAD_U8(oid->n_subid))
      {
	node = allocz(sizeof(struct mib_leaf));
	node->empty.flags = MIB_TREE_LEAF;
      }
      else
      {
	node = allocz(sizeof(struct mib_node));
	node->empty.flags = 0;
      }

      node->empty.id = LOAD_U8(oid->prefix);
      /* add node into the parent's children array */
      node_inner->children[LOAD_U8(oid->prefix)] = node;
      node_inner = &node->inner;
      walk.stack[walk.stack_pos++] = node;
    }
  }

  /* snmp_internet + 2 = empty + snmp_internet + prefix */
  if (snmp_oid_is_prefixed(oid) &&
      walk.stack_pos == ARRAY_SIZE(snmp_internet) + 2 &&
      LOAD_U8(oid->n_subid) == 0 &&
      mib_node_is_leaf(node) == is_leaf)
    return node;

  if (mib_node_is_leaf(node))
    return node;

  u8 subids = LOAD_U8(oid->n_subid);
  u32 old_len = node_inner->child_len;
  u32 child_id = oid->ids[walk.id_pos];
  node_inner->child_len = MAX(old_len, LOAD_U32(child_id) + 1);
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

    child_id = LOAD_U32(oid->ids[++walk.id_pos]);

    node_inner->child_len = child_id + 1;
    node_inner->children = allocz(node_inner->child_len * sizeof(mib_node_u *));
    /*
    node_inner->child_len = (child_id == 0) ? 0 : child_id;
    node_inner->children = (child_id == 0) ? NULL
      : allocz(node_inner->child_len * sizeof(mib_node_u *));
    */
  }

  parent = node_inner;
  mib_node_u *last;
  if (is_leaf)
  {
    last = allocz(sizeof(struct mib_leaf));
    struct mib_leaf *leaf = &last->leaf;

    parent->children[child_id] = (mib_node_u *) leaf;
    leaf->c.id = child_id;

    //leaf->c.id = LOAD_U32(oid->ids[subids - 1]);
    leaf->c.flags = MIB_TREE_LEAF;
  }
  else
  {
    last = allocz(sizeof(struct mib_node));
    node_inner = &last->inner;

    parent->children[child_id] = (mib_node_u *) node_inner;
    node_inner->c.id = child_id;
    //node_inner->c.id = LOAD_U32(oid->ids[subids - 1]);
    /* fields c.flags, child_len and children are set by zeroed allocz() */
  }

  return last;
}

#if 0
// TODO merge functions mib_tree_add and mib_tree_insert into one with public iface

mib_node_u *
mib_tree_add(struct snmp_proto *p, struct mib_tree *t, const struct oid *oid, uint size, int is_leaf)
{
  struct mib_walk_state walk = { };
  mib_node_u *known = mib_tree_find(t, &walk, oid);

  if (known)
    return known;

  known = walk.stack[walk.stack_pos];

  // redundant ??, if not, would be returned from find
  if (walk.id_pos_abs == oid->n_subid)
    return known;

  if (walk.id_pos_rel < 0)

  if (walk.id_pos_abs < oid->n_subid && (u32) walk.id_pos_rel == known->id_len)
  {
    if (known->child_len >= oid->ids[walk.id_pos_abs]) // abs +1?
    {
      u32 old_len = known->child_len;
      known->child_len = oid->ids[walk.id_pos_abs] + 1;
      known->children = mb_realloc(known->children,
	  known->child_len * sizeof(struct mib_node *));

      for (uint i = old_len; i < known->child_len; i++)
	known->children[i] = NULL;
    }

    /* find would return it
    if (known->children[oid->ids[]])
      return known->children[oid->ids[]];
    */

    struct mib_node *node = mb_alloc(p->p.pool, sizeof(struct mib_node));
    node->id_len = oid->n_subid - walk.id_pos_abs;
    node->ids = mb_alloc(p->p.pool, node->id_len * sizeof(u32));
    node->flags = 0;
    node->children = NULL;
    node->child_len = 0;
    node->child_count = 0;

    known->child_count++;
    known->children[oid->ids[0]] = node;
    return node;
  }
  else if (walk.id_pos_abs < oid->n_subid)
  {
    /* We known that walk.id_pos_rel < known->id_len */
    struct mib_node *parent = mb_alloc(p->p.pool, sizeof(struct mib_node));
    parent->id_len = known->id_len - walk.id_pos_rel;
    parent->ids = mb_alloc(p->p.pool,
      parent->id_len * sizeof(struct mib_node *));
    memcpy(&parent->ids, &known->ids, parent->id_len * sizeof(struct mib_node *));
    u32 *ids = mb_alloc(p->p.pool,
      (known->id_len - walk.id_pos_rel) * sizeof(u32));
    memcpy(ids, &known->ids[parent->id_len],
      (known->id_len - parent->id_len) * sizeof(struct mib_node *));
    mb_free(known->ids);
    known->id_len = known->id_len - walk.id_pos_rel;
    known->ids = ids;
    parent->child_len = MAX(known->ids[0], oid->ids[walk.id_pos_abs]) + 1;
    parent->children = mb_allocz(p->p.pool,
      parent->child_len * sizeof(struct mib_node *));
    parent->children[known->ids[0]] = known;

    struct mib_node *child = mb_alloc(p->p.pool, sizeof(struct mib_node));
    child->id_len = oid->n_subid - walk.id_pos_abs - parent->id_len;
    child->ids = mb_alloc(p->p.pool,
      child->id_len * sizeof(struct mib_node *));
    memcpy(&child->ids, &oid->ids[oid->n_subid - child->id_len],
      child->id_len * sizeof(u32));
    // TODO test that we do not override the known
    parent->children[child->ids[0]] = child;

    return child;
  }
  else if (walk.id_pos_abs > oid->n_subid)
    die("unreachable");

  return NULL;
}
#endif

/*
int
mib_tree_insert(struct snmp_proto *p, struct mib_tree *t, struct oid *oid)
{
  ASSUME(oid);

  struct mib_walk_state walk = { };
  struct mib_node *node = mib_tree_find(t, &walk, oid);
  struct mib_leaf *leaf = NULL;

  if (!node)
  {
    node = walk.stack[walk.stack_pos];

    if (walk.id_pos_abs > oid->n_subid)
    {
    }
    else / * walk.id_pos_abs <= oid->n_subid * /
    {
      leaf = mb_alloc(p->p.pool, sizeof(struct mib_leaf));
      leaf->id_len = oid->n_subid - walk.id_pos_abs;
      leaf->ids = mb_alloc(p->p.pool, leaf->id_len * sizeof(struct mib_node *));
      memcpy(&leaf->ids, &oid->ids[oid->n_subid - leaf->id_len],
	leaf->id_len * sizeof(u32));
      leaf->flags = 0;
      leaf->children = NULL;
      leaf->child_len = 0;
      leaf->child_count = 0;
    }
  }
}
*/

#if 0
int
mib_tree_insert(struct snmp_proto *p, struct mib_tree *t, struct oid *oid, struct mib_leaf *leaf)
{
  ASSUME(oid);

  struct mib_walk_state walk = { };
  struct mib_node *node = mib_tree_find(t, &walk, oid);
  struct mib_node *leaf_node = &leaf->n;

  if (!node)
  {
    node = walk.stack[walk.stack_pos];

    // can this really happen ??
    if (walk.id_pos_abs > oid->n_subid)
    {
      struct mib_node *parent = mb_alloc(p->p.pool, sizeof(struct mib_node));
      parent->id_len = walk.id_pos_abs - oid->n_subid; // -1?
      parent->ids = mb_alloc(p->p.pool, parent->id_len * sizeof(u32));
      memcpy(&parent->ids, &node->ids, parent->id_len * sizeof(u32));
      u32 *ids = mb_alloc(p->p.pool,
	(node->id_len - parent->id_len) * sizeof(u32));
      node->id_len = node->id_len - parent->id_len;
      memcpy(ids, &node->ids[parent->id_len], node->id_len * sizeof(u32));
      mb_free(node->ids);
      node->ids = ids;

      parent->child_count = 2;
      parent->child_len = MAX(node->ids[0], oid->ids[walk.id_pos_abs]) + 1;
      parent->children = mb_allocz(p->p.pool,
	parent->child_len * sizeof(struct mib_node *));
      parent->children[node->ids[0]] = node;
      parent->children[leaf_node->ids[0]] = leaf_node;
      return 1;
    }
    else
    {
      mb_free(leaf_node->ids);
      leaf_node->id_len = oid->n_subid - walk.id_pos_abs;
      leaf_node->ids = mb_alloc(p->p.pool, leaf_node->id_len * sizeof(u32));
      return 1;
    }
  }

  if (mib_node_is_leaf(node))
  {
    struct mib_leaf *l = SKIP_BACK(struct mib_leaf, n, node);
    insert_node(&leaf->leafs, &l->leafs);
    return 1;
  }

  if (node->child_len > 0)
    return 0;

  // problem when node->id_len + (walk.id_pos_abs - walk.id_pos_rel) > oid->n_subid
  if (walk.id_pos_abs < oid->n_subid) // +-1??
  {
    leaf_node->id_len = node->id_len - walk.id_pos_abs;
    leaf_node->ids = mb_alloc(p->p.pool, leaf_node->id_len * sizeof(u32));
    memcpy(&leaf_node->ids, &oid->ids[walk.id_pos_abs], leaf_node->id_len * sizeof(u32));
    leaf_node->child_len = leaf_node->child_count = 0;
    leaf_node->children = NULL;
    return 1;
  }
  else
    return 0;
  return 1;
}
#endif

/*
int
mib_tree_remove(struct mib_tree *tree, struct oid *oid)
{
  struct mib_walk_state walk = { };
  struct mib_node *node = mib_tree_find(tree, &walk, oid);

  if (!node)
    return 0;

  mib_tree_delete(&walk);
  //mib_tree_delete(tree, &walk);
  return 1;
}
*/

int
mib_tree_remove(struct mib_tree *t, const struct oid *oid)
{
  struct mib_walk_state walk = { };
  mib_node_u *node = mib_tree_find(t, &walk, oid);

  if (!node)
    return 0;
  else
  {
    (void) mib_tree_delete(t, &walk);
    return 1;
  }
}

int
mib_tree_delete(struct mib_tree *t, struct mib_walk_state *walk)
{
  int deleted = 0;
  ASSUME(t);

  /* (walk->stack_pos < 2) It is impossible to delete root node */
  if (!walk || !walk->id_pos || walk->stack_pos < 2)
    return 0;

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

/* currently support only search with blank new walk state */
/* requires non-NULL walk */
/* TODO doc string, user should check if the node is not root (or at least be
 * aware of that */
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

  u8 oid_pos = walk->id_pos = 0;
  node = walk->stack[walk->stack_pos++] = (mib_node_u *) &t->root;

#if 0
  u8 oid_pos = walk->id_pos;

  if (walk->stack_pos > 0)
    node = walk->stack[walk->stack_pos];
  else
    node = walk->stack[walk->stack_pos++] = (mib_node_u *) &t->root;

  if (mib_node_is_leaf(node))
  {
    if (snmp_oid_is_prefixed(oid) && LOAD_U8(oid->n_subid) + ARRAY_SIZE(snmp_internet) + 1 == walk->id_pos)
      return node;

    else if (!snmp_oid_is_prefixed(oid) && LOAD_U8(oid->n_subid) + 1 == walk->id_pos)
      return node;

    /* it could hold that LOAD_U8(oid->n_subid) >= walk->id_pos */
    return NULL;
  }
#endif

  node_inner = &node->inner;
  ASSERT(node && !mib_node_is_leaf(node));

  /* Handling of prefixed OID */
  if (snmp_oid_is_prefixed(oid))
  {
    uint i;
    /* walking the snmp_internet prefix itself */
    for (i = 0; i < ARRAY_SIZE(snmp_internet); i++)
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
    u8 prefix = LOAD_U8(oid->prefix);
    if (node_inner->child_len <= prefix)
      return NULL;

    node = node_inner->children[prefix];
    node_inner = &node->inner;

    if (!node)
      return NULL;

    ASSERT(node->empty.id == prefix);
    walk->stack[walk->stack_pos++] = node;

    if (mib_node_is_leaf(node) && LOAD_U8(oid->n_subid) > 0)
      return NULL;
  }

  u8 subids = LOAD_U8(oid->n_subid);
  if (subids == 0)
    return (node == (mib_node_u *) &t->root) ? NULL : node;

  /* loop for all OID's ids except the last one */
  for (oid_pos = 0; oid_pos < subids - 1; oid_pos++) // remove oid_pos assignment
  {
    u32 id = LOAD_U32(oid->ids[oid_pos]);
    if (node_inner->child_len <= id)
    {
      walk->id_pos = oid_pos;
      return NULL;
    }

    node = node_inner->children[id];
    node_inner = &node->inner;

    if (!node)
    {
      walk->id_pos = oid_pos;
      return NULL;
    }

    ASSERT(node->empty.id == id);
    walk->stack[walk->stack_pos++] = node;

    if (mib_node_is_leaf(node))
    {
      walk->id_pos = ++oid_pos;
      return NULL;
    }
  }

  walk->id_pos = oid_pos;
  u32 last_id = LOAD_U32(oid->ids[oid_pos]);
  if (node_inner->child_len <= last_id)
    return NULL;

  node = node_inner->children[last_id];
  node_inner = &node->inner;

  if (!node)
    return NULL;

  /* here, the check of node being a leaf is intentionally omitted
   * because we may need to search for a inner node */
  ASSERT(node->empty.id == last_id);
  walk->id_pos = ++oid_pos;
  return walk->stack[walk->stack_pos++] = node;
}

void
mib_tree_walk_init(struct mib_walk_state *walk)
{
  walk->id_pos = 0;
  walk->stack_pos = 0;
  memset(&walk->stack, 0, sizeof(walk->stack));
}

/*
void
mib_node_free(mib_node_u *node)
{
  if (!mib_node_is_leaf(node))
  {
    struct mib_node *node_inner = &node->inner;
    node_inner->child_len = 0;
    free(node_inner->children);
    node_inner->children = NULL;
  }

  free(node);
}
*/

mib_node_u *
mib_tree_walk_next(struct mib_tree *t, struct mib_walk_state *walk)
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

#if 0
struct mib_node *
mib_tree_walk_next(struct mib_walk_state *walk)
{
  ASSUME(walk->stack[walk->stack_pos]);

  if (walk->stack_pos == 0 && walk->stack[0] &&
      walk->stack[0]->flags & (MIB_TREE_REG_ACK || MIB_TREE_REG_WAIT))
    return walk->stack[0];

  struct mib_node *node = walk->stack[walk->stack_pos];
  u32 id;

find_leaf:
  while (!mib_node_is_leaf(node))
  {
    for (id = 0; id < node->child_len; id++)
    {
      if (node->children[id])
      {
	node = node->children[id];
	walk->stack[++walk->stack_pos] = node;
	break;
      }
    }

    if (node->flags & (MIB_TREE_REG_ACK || MIB_TREE_REG_WAIT))
      return node;
  }

  id = node->ids[0];

  while (walk->stack_pos)
  {
    walk->stack[walk->stack_pos] = NULL;
    --walk->stack_pos;
    node = walk->stack[walk->stack_pos];

    if (id + 1 != node->child_len)
      break;
  }

  if (id + 1 == node->child_len)
    return walk->stack[0] = NULL;

  node = node->children[id + 1];
  walk->stack_pos++;
  walk->stack[walk->stack_pos] = node;
  goto find_leaf;
}
#endif


struct mib_leaf *
mib_tree_walk_next_leaf(struct mib_tree *t, struct mib_walk_state *walk)
{
  (void) t;

  if (walk->stack_pos == 0)
    return NULL;

  u32 next_id = 0;
  mib_node_u *node = walk->stack[walk->stack_pos - 1];

  if (mib_node_is_leaf(node) && walk->stack_pos > 1)
  {
    next_id = node->leaf.c.id + 1;
    walk->stack[--walk->stack_pos] = NULL;
    node = walk->stack[walk->stack_pos - 1]; // does it underflow ??
  }
  else if (mib_node_is_leaf(node))
  {
    /* walk->stack_pos == 1, so we NULL out the last stack field */
    walk->stack[--walk->stack_pos] = NULL;
    return NULL;
  }

  mib_node_u *parent = (walk->stack_pos <= 1) ? NULL :
     walk->stack[walk->stack_pos - 2];

  while (walk->stack_pos > 0)
  {
continue_while:
    node = walk->stack[walk->stack_pos - 1];

    if (mib_node_is_leaf(node))
    {
      walk->stack[walk->stack_pos++] = node;
      return (struct mib_leaf *) node;
    }

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

    while (walk->stack_pos > 1)	// endless loop here possible ??
    {
      parent = walk->stack[walk->stack_pos - 2];
      node = walk->stack[walk->stack_pos - 1];

      ASSUME(mib_node_is_leaf(node));
      if (node->leaf.c.id + 1 == parent->inner.child_len)
	walk->stack[--walk->stack_pos] = NULL;

      next_id = node->inner.c.id + 1;
    }
  }

  return NULL;
}

#if 0
struct mib_leaf *
mib_tree_next_leaf(struct mib_walk_state *walk)
{
  ASSUME(walk->stack[walk->stack_pos] &&
	 mib_node_is_leaf(walk->stack[walk->stack_pos]));

  struct mib_node *node = walk->stack[walk->stack_pos];
  u32 id;

  while (walk->stack_pos)
  {
    id = node->ids[0];
    walk->stack[walk->stack_pos] = NULL;
    --walk->stack_pos;
    node = walk->stack[walk->stack_pos];

    if (id + 1 != node->child_len)
      break;
  }

  if (id + 1 == node->child_len)
    return (struct mib_leaf *) (walk->stack[0] = NULL);

  id++;
  while (!mib_node_is_leaf(node))
  {
    for (; id < node->child_len && !node->children[id]; id++)
      ;

    node = node->children[id];
    walk->stack[++walk->stack_pos] = node;
    id = 0;
  }

  return (struct mib_leaf *) node;
}
#endif

