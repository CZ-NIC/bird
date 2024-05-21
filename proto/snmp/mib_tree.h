#ifndef _BIRD_SNMP_MIB_TREE_
#define _BIRD_SNMP_MIB_TREE_

#include "lib/resource.h"
#include "lib/lists.h"
#include "lib/birdlib.h"

#include "subagent.h"

#define MIB_TREE_NO_FLAGS 0x00
#define MIB_TREE_LEAF 0x01
#define MIB_TREE_HAS_HOOKS 0x02

typedef union mib_node_union mib_node_u;

struct mib_node_core {
  u32 id;
  u8 flags;
};

struct mib_node {
  struct mib_node_core c;
  mib_node_u **children;
  u32 child_len;
};

struct mib_leaf {
  struct mib_node_core c;
  enum snmp_search_res (*filler)(struct snmp_proto *p, struct snmp_pdu *c);
  //enum snmp_search_res (*filler)(struct snmp_proto_pdu *pc, struct agentx_varbind **vb);
  enum agentx_type type;
  int size;
};

union mib_node_union {
  struct mib_node_core empty;
  struct mib_node inner;
  struct mib_leaf leaf;
};

/*
 * The stack size include empty prefix (mib tree root).
 */
#define MIB_WALK_STACK_SIZE 33
STATIC_ASSERT(OID_MAX_LEN < MIB_WALK_STACK_SIZE);

/* walk state for MIB tree */
struct mib_walk_state {
  u8 id_pos;  /* points after last matching subid in OID */
  u32 stack_pos;  /* points after last valid stack node */
  mib_node_u *stack[MIB_WALK_STACK_SIZE];
};

struct mib_tree {
  struct mib_node root;
};

void mib_tree_init(pool *p, struct mib_tree *t);
// TODO: remove need for argument include_root
void mib_tree_walk_init(struct mib_walk_state *state, const struct mib_tree *t);
int mib_tree_walk_to_oid(const struct mib_walk_state *state, struct oid *result, u32 subids);

mib_node_u *mib_tree_add(pool *p, struct mib_tree *tree, const struct oid *oid, int is_leaf);
int mib_tree_remove(struct mib_tree *t, const struct oid *oid);
int mib_tree_delete(struct mib_tree *t, struct mib_walk_state *state);
mib_node_u *mib_tree_find(const struct mib_tree *tree, struct mib_walk_state *walk, const struct oid *oid);
mib_node_u *mib_tree_walk_next(const struct mib_tree *t, struct mib_walk_state *walk);
struct mib_leaf *mib_tree_walk_next_leaf(const struct mib_tree *t, struct mib_walk_state *walk);

static inline int
mib_node_is_leaf(const mib_node_u *node)
{
  ASSUME(node);
  return node->empty.flags & MIB_TREE_LEAF;
}

#endif

