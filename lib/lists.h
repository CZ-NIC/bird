/*
 *	BIRD Library -- Linked Lists
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LISTS_H_
#define _BIRD_LISTS_H_

#include "lib/birdlib.h"

/*
 * I admit the list structure is very tricky and also somewhat awkward,
 * but it's both efficient and easy to manipulate once one understands the
 * basic trick: The list head always contains two synthetic nodes which are
 * always present in the list: the head and the tail. But as the `next'
 * entry of the tail and the `prev' entry of the head are both NULL, the
 * nodes can overlap each other:
 *
 *     head    head_node.next
 *     null    head_node.prev  tail_node.next
 *     tail                    tail_node.prev
 */

typedef struct node {
  struct node *next, *prev;
} node;

typedef union list {			/* In fact two overlayed nodes */
  struct {				/* Head node */
    struct node head_node;
    void *head_padding;
  };
  struct {				/* Tail node */
    void *tail_padding;
    struct node tail_node;
  };
  struct {				/* Split to separate pointers */
    struct node *head;
    struct node *null;
    struct node *tail;
  };
} list;

#define NODE (node *)
#define HEAD(list) ((void *)((list).head))
#define TAIL(list) ((void *)((list).tail))
#define NODE_NEXT(n) ((void *)((NODE (n))->next))
#define NODE_VALID(n) ((NODE (n))->next)
#define WALK_LIST(n,list) for(n=HEAD(list); NODE_VALID(n); n=NODE_NEXT(n))
#define WALK_LIST2(n,nn,list,pos) \
  for(nn=(list).head; NODE_VALID(nn) && (n=SKIP_BACK(typeof(*n),pos,nn)); nn=nn->next)
#define WALK_LIST_DELSAFE(n,nxt,list) \
  for(n=HEAD(list); nxt=NODE_NEXT(n); n=(void *) nxt)
#define WALK_LIST2_DELSAFE(n,nn,nxt,list,pos) \
  for(nn=HEAD(list); (nxt=nn->next) && (n=SKIP_BACK(typeof(*n),pos,nn)); nn=nxt)

/* WALK_LIST_FIRST supposes that called code removes each processed node */
#define WALK_LIST_FIRST(n,list) \
     while(n=HEAD(list), (NODE (n))->next)
#define WALK_LIST_BACKWARDS(n,list) for(n=TAIL(list);(NODE (n))->prev; \
				n=(void *)((NODE (n))->prev))
#define WALK_LIST_BACKWARDS_DELSAFE(n,prv,list) \
     for(n=TAIL(list); prv=(void *)((NODE (n))->prev); n=(void *) prv)

#define EMPTY_LIST(list) (!(list).head->next)


#ifndef _BIRD_LISTS_C_
#define LIST_INLINE static inline
#include "lib/lists.c"
#undef LIST_INLINE

#else /* _BIRD_LISTS_C_ */
#define LIST_INLINE
void add_tail(list *, node *);
void add_head(list *, node *);
void rem_node(node *);
void move_list(list *dest, list *src);
void add_head_list(list *, list *);
void add_tail_list(list *, list *);
void init_list(list *);
void insert_node(node *, node *);
uint list_length(list *);
#endif

/* Typed lists */
#define TLIST_NODE(_type) struct { _type *next, *prev; } _tln
#define TLIST(_type) union { \
  struct { \
    union { \
      struct { _type *next, *prev; }; \
      _type node[0]; \
    } head_node; \
    void *head_padding; \
  }; \
  struct { \
    void *tail_padding; \
    union { \
      struct { _type *next, *prev; }; \
      _type node[0]; \
    } tail_node; \
  }; \
  struct { \
    _type *head, *null, *tail; \
  }; \
}

#define TNODE(n) (n)->node
#define THEAD(list) list.head
#define TTAIL(list) list.tail
#define TNODE_IN_LIST(n) (((n)->_tln.next) && ((n)->_tln.prev))

#define TLIST_NODE_TYPE(l) typeof(*(l.head))

#define TLIST_EMPTY(list) ((list)->head == ((list)->tail_node.node))

#define WALK_TLIST(n_, list) for (n_ = (list).head; n_->_tln.next; n_ = n_->_tln.next)
#define WALK_TLIST_DELSAFE(n_, list) for (typeof(n_) next_ = n_ = THEAD(list); next_ = n_->_tln.next; n_ = next_)

#define INIT_TLIST(list) do { \
  typeof(list) l_ = list; \
  l_->head = l_->tail_node.node; \
  l_->tail = l_->head_node.node; \
  l_->null = NULL; \
} while (0)

#define TADD_HEAD(list_, node_) do { \
  typeof(node_) n_ = node_; \
  typeof(list_) l_ = list_; \
  n_->_tln.next = l_->head; \
  n_->_tln.prev = l_->head_node.node; \
  l_->head->_tln.prev = n_; \
  l_->head = n_; \
} while (0)

#define TADD_TAIL(list_, node_) do { \
  typeof(node_) n_ = node_; \
  typeof(list_) l_ = list_; \
  n_->_tln.next = l_->tail_node.node; \
  n_->_tln.prev = l_->tail; \
  l_->tail->_tln.next = n_; \
  l_->tail = n_; \
} while (0)

#define TREM_NODE(node) do { \
  typeof(node) n_ = node; \
  n_->_tln.prev->_tln.next = n_->_tln.next; \
  n_->_tln.next->_tln.prev = n_->_tln.prev; \
  n_->_tln.prev = n_->_tln.next = NULL; \
} while (0)

#define TFIX_NODE(node) do { \
  typeof(node) n_ = node; \
  n_->_tln.next->_tln.prev = n_; \
  n_->_tln.prev->_tln.next = n_; \
 } while (0)

#endif
