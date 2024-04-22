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
  enum snmp_search_res (*filler)(struct snmp_proto_pdu *pc, struct agentx_varbind **vb);
  enum agentx_type type;
  int size;
};

union mib_node_union {
  struct mib_node_core empty;
  struct mib_node inner;
  struct mib_leaf leaf;
};

/*
cannonical names
  find
  walk_init
  walk_next
  init
  insert
  delete / remove
 */

/*
 * The stack size include empty prefix (mib tree root).
 */
#define MIB_WALK_STACK_SIZE 33
STATIC_ASSERT(OID_MAX_LEN < MIB_WALK_STACK_SIZE);

struct mib_walk_state {
  u8 id_pos;  /* points after last matching subid in OID */
  u32 stack_pos;  /* points after last valid stack node */
  mib_node_u *stack[MIB_WALK_STACK_SIZE];
};

struct mib_tree {
  struct mib_node root;
};

void mib_tree_init(pool *p, struct mib_tree *t);
void mib_tree_walk_init(struct mib_walk_state *state);
//void mib_node_free(mib_node_u *node);
//void mib_tree_free(struct mib_tree *tree);

mib_node_u *mib_tree_add(pool *p, struct mib_tree *tree, const struct oid *oid, int is_leaf);
int mib_tree_remove(struct mib_tree *t, const struct oid *oid);
int mib_tree_delete(struct mib_tree *t, struct mib_walk_state *state);
mib_node_u *mib_tree_find(const struct mib_tree *tree, struct mib_walk_state *walk, const struct oid *oid);
mib_node_u *mib_tree_next(struct mib_tree *tree, mib_node_u *end);

static inline int
mib_node_is_leaf(const mib_node_u *node)
{
  return node->empty.flags & MIB_TREE_LEAF;
}

/*
WALK OID ID POS !!!
assert on STACK SIZE overflow resp fix entering the too long OIDs

Enumerace divnych pripadu

OID { n_subid  0, prefix  0 } ids NULL
OID { n_subid  0, prefix  2 } ids NULL <- todle je divny
OID { n_subid  1, prefix  0 } ids { 1 }
OID { n_subid  2, prefix  0 } ids { 1, 31 }
OID { n_subid  3, prefix  0 } ids { 1, 30, 32 }
OID { n_subid  7, prefix  0 } ids { 1, 2, 3, 4, 5, 6, 7 }
OID { n_subid  1, prefix  4 } ids { 8 }
OID { n_subid  2, prefix 19 } ids { 3, 2 }
OID { n_subid  3, prefix  5 } ids { 3, 9, 1 }
OID { n_subid  4, prefix  2 } ids { 1, 15, 1, 2 } <- obecny priklad

hledani
odstraneni
odstraneni stromu/podstromu
nasledovnik
nasledovnik list
pridani do vrcholu do stromu

TODO
add
next
next leaf
find with non-empty walk state

je opravdu potreba mit v vsech funkcich argument stromu (struct mib_tree *t) ?
  >> walk, walk_init, next, next_leaf <<

otestovat neprefixovane OID v prefixovanem strome
a prefixove OID v neprefixovanem strome

TESTING TREES

s internet prefixem
  - jinak prazdny
  - jeden vrchol
  - dva vrcholy
  - 3, 4,
  - rand() vrcholu

  cesta, vidlicka, hrabe

bez internet prefixu
  - uplne prazdny
  - jediny vrchol (0, 1, 300, rand())
  - dva vrcholy
  - tri vrcholy
  - ctyri vrcholy
  - pet vrcholu jako v internet ale s prefixem = 300
  - rand() vrcholu rand() hodnot

  cesta vidlicka hrabe

 */

#endif

