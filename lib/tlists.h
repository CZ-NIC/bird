/*
 *	BIRD Library -- Typed Linked Lists
 *
 *	(c) 2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	Based roughly on Martin Mares' lib/lists.h but completely implemented as macros.
 */

#ifndef _BIRD_TLISTS_H_
#define _BIRD_TLISTS_H_

#define TNODE(t) struct tnode__##t
#define TNODE_DEF(t)
#define TLIST(t) union tlist__##t
#define TLIST_DEF(t) TNODE(t) { \
  TNODE(t) *next; \
  struct t *self; \
  TNODE(t) *prev; \
}; \
  TLIST(t) { \
  struct { \
    TNODE(t) head_node; \
    struct t *head_null_self; \
    TNODE(t) *tail; \
  }; \
  struct { \
    TNODE(t) *head; \
    struct t *tail_padding_self; \
    TNODE(t) tail_node; \
  }; \
}

#define INIT_TLIST(t, list) do { \
  memset(&(list), 0, sizeof(TLIST(t))); \
  list.head_node.next = &(list.tail_node); \
  list.tail_node.prev = &(list.head_node); \
} while (0)

#define EMPTY_TLIST(t, list) (!((list).head->next))

#define TNODE_VALID(t, n) ((n)->next)
#define WALK_TLIST(t, n, list) for (TNODE(t) *n = list.head; TNODE_VALID(t, n); n = n->next)
#define WALK_TLIST_DELSAFE(t, n, list) \
  for (TNODE(t) *n = list.head, *_n; _n = n->next; n = _n)

#define TADD_TAIL(t, list, node) do { \
  TNODE(t) *p = list.tail; \
  node.prev = p; \
  node.next = &(list.tail_node); \
  p->next = &(node); \
  list.tail = &(node); \
} while (0)

#define TREM_NODE(t, node) do { \
  TNODE(t) *p = node.prev, *n = node.next; \
  node.prev = node.next = NULL; \
  p->next = n; \
  n->prev = p; \
} while (0)

#endif
