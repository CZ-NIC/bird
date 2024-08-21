#ifndef _BIRD_SNMP_MIB_TREE_
#define _BIRD_SNMP_MIB_TREE_

#include "subagent.h"

#include "lib/resource.h"
#include "lib/lists.h"
#include "lib/birdlib.h"

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

struct mib_walk_state;

struct mib_leaf {
  struct mib_node_core c;

  /**
   * filler - hook for filling VarBind data value
   * @state: self referencing MIB tree walk state
   * @data: box holding destiantion VarBind and SNMP protocol instance
   *
   * If corresponding leaf node has filled in AgentX type and/or size, it is
   * guaranteed that PDU buffer have enough space. Hook mustn't be NULL.
   * If the leaf node has set valid type, the varbind type will be automatically
   * set by the snmp_walk_fill() servicing routine. If the field type is set to
   * AGENTX_INVALID, it is expected that filler() hook will also fill
   * the VarBind type.
   */
  enum snmp_search_res (*filler)(struct mib_walk_state *state, struct snmp_pdu *context);

  /**
   * call_next - signal multileaf
   * @state: self referencing MIB tree walk state
   * @data: box holding destination VarBind and SNMP protocol insntace
   *
   * MIB modules can implement subtrees by a single leaf node in MIB node tree.
   * When the tree is walked, the specific leaf node has to be returned multiple
   * times. The @call_next hook determines if we should move to next leaf node.
   * It is expected that call_next() hook may change the VarBind to be filled.
   *
   * Hook may be NULL meaning the leaf node is not multileaf/subtree.
   *
   */
  int (*call_next)(struct mib_walk_state *state, struct snmp_pdu *context);

  /**
   * type of produced VarBind, may be replaced in packet instanciation by
   * AGENTX_NO_SUCH_OBJECT, AGENTX_NO_SUCH_INSTANCE or AGENTX_END_OF_MIB_VIEW
   * The field is unspecified if equal to AGENTX_INVALID.
   */
  enum agentx_type type;

  /*
   * Specify upper bound of VarBind data size. If set to -1, all handling must
   * be done in filler() hook. In all other cases the filler() hook has
   * guaranteed that the space is available.
   */
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
void mib_tree_walk_init(struct mib_walk_state *state, const struct mib_tree *t);
int mib_tree_walk_to_oid(const struct mib_walk_state *state, struct oid *result, u32 subids);
int mib_tree_walk_oid_compare(const struct mib_walk_state *state, const struct oid *oid);

mib_node_u *mib_tree_add(pool *p, struct mib_tree *tree, const struct oid *oid, int is_leaf);
int mib_tree_remove(struct mib_tree *t, const struct oid *oid);
int mib_tree_delete(struct mib_tree *t, struct mib_walk_state *state);
mib_node_u *mib_tree_find(const struct mib_tree *tree, struct mib_walk_state *walk, const struct oid *oid);
mib_node_u *mib_tree_walk_next(const struct mib_tree *t, struct mib_walk_state *walk);
struct mib_leaf *mib_tree_walk_next_leaf(const struct mib_tree *t, struct mib_walk_state *walk, u32 skip);

int mib_tree_hint(pool *p, struct mib_tree *t, const struct oid *oid, uint size);
int mib_tree_walk_is_oid_descendant(const struct mib_walk_state *walk, const struct oid *oid);

static inline int
mib_node_is_leaf(const mib_node_u *node)
{
  ASSUME(node);
  return node->empty.flags & MIB_TREE_LEAF;
}

#endif

