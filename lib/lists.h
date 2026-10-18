/*
 *	BIRD Library -- Linked Lists
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LISTS_H_
#define _BIRD_LISTS_H_

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

#define STATIC_LIST_INIT(name)	name = { .head = &name.tail_node, .tail = &name.head_node, .null = NULL }

#define NODE (node *)
#define HEAD(list) ((void *)((list).head))
#define TAIL(list) ((void *)((list).tail))
#define NODE_NEXT(n) ((void *)((NODE (n))->next))
#define NODE_VALID(n) ((NODE (n))->next)
#define WALK_LIST(n,list) for(n=HEAD(list); NODE_VALID(n); n=NODE_NEXT(n))
#define WALK_LIST_(t,n,list) for(t *n=HEAD(list); NODE_VALID(n); n=NODE_NEXT(n))
#define WALK_LIST2(n,nn,list,pos) \
  for(nn=(list).head; NODE_VALID(nn) && (n=SKIP_BACK(typeof(*n),pos,nn)); nn=nn->next)
#define WALK_LIST_DELSAFE(n,nxt,list) \
  for(n=HEAD(list); nxt=NODE_NEXT(n); n=(void *) nxt)
#define WALK_LIST2_DELSAFE(n,nn,nxt,list,pos) \
  for(nn=HEAD(list); (nxt=nn->next) && (n=SKIP_BACK(typeof(*n),pos,nn)); nn=nxt)

/* WALK_LIST_FIRST supposes that called code removes each processed node */
#define WALK_LIST_FIRST(n,list) \
     while(n=HEAD(list), (NODE (n))->next)
#define WALK_LIST_FIRST2(n,pos,list) \
     while(n=SKIP_BACK(typeof(*n),pos,(list).head), (n)->pos.next)
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
void add_tail_list(list *, list *);
void init_list(list *);
void insert_node(node *, node *);
uint list_length(list *);
#endif


#define LIST(type)		LIST_(type, 0)
#define LIST2(type, pos)	LIST_(type, offsetof(type, pos))
#define LIST_(type, off)	struct { list list; type *node[0]; char offset[0][off]; }
#define LIST_TYPE(l)		typeof(*(l).node[0])
#define LIST_OFFSET(l)		sizeof(typeof((l).offset[0]))

#define LIST_IN(l)		(&(l).list)
#define NODE_IN(l, n)		({ TYPE_CHECK(LIST_TYPE(l) *, n); (node *) ((char *) (n) + LIST_OFFSET(l)); })
#define NODE_OUT(l, n)		({ TYPE_CHECK(node *, n); (LIST_TYPE(l) *) ((char *) (n) - LIST_OFFSET(l)); })

#define LIST_INIT(l, pos)						\
  ({									\
    STATIC_ASSERT(TYPE_EQUAL(MEMBER_TYPE(LIST_TYPE(l), pos), node));	\
    STATIC_ASSERT(LIST_OFFSET(l) == offsetof(LIST_TYPE(l), pos));	\
    init_list(LIST_IN(l));						\
  })

#define LIST_ADD_TAIL(l, n)		add_tail(LIST_IN(l), NODE_IN(l, n))
#define LIST_ADD_HEAD(l, n)		add_head(LIST_IN(l), NODE_IN(l, n))
#define LIST_INSERT(l, n, after)	insert_node(NODE_IN(l, n), NODE_IN(l, after))
#define LIST_REMOVE(l, n)		rem_node(NODE_IN(l, n))
#define LIST_LENGTH(l)			list_length(LIST_IN(l))
#define LIST_EMPTY(l)			(!(l).list.head->next)

#define LIST_FIRST(l) \
  ({ node *_nn = (l).list.head; _nn->next ? NODE_OUT(l, _nn) : NULL; })

#define LIST_NEXT(l, n) \
  ({ node *_nn = NODE_IN(l, n)->next; _nn->next ? NODE_OUT(l, _nn) : NULL; })

#define LIST_LAST(l) \
  ({ node *_nn = (l).list.tail; _nn->prev ? NODE_OUT(l, _nn) : NULL; })

#define LIST_PREV(l, n) \
  ({ node *_nn = NODE_IN(l, n)->prev; _nn->prev ? NODE_OUT(l, _nn) : NULL; })


#define LIST_EXTEND(l1, l2)				     		\
  ({									\
    STATIC_ASSERT(TYPE_EQUAL(LIST_TYPE(l1), LIST_TYPE(l2)));		\
    add_tail_list(LIST_IN(l1), LIST_IN(l2));				\
  })



#define LIST_WALK_(l, n) \
  for(node *_nn=(l).list.head; _nn->next && (n = NODE_OUT(l, _nn)); _nn=_nn->next)

#define LIST_WALK_DELSAFE_(l, n) \
  for(node *_nn=(l).list.head; _nn->next && (n = NODE_OUT(l, _nn)) && (_nn=_nn->next, 1); )

#define LIST_WALK_FIRST_(l, n) \
  for(node *_nn=(l).list.head; _nn->next && (n = NODE_OUT(l, _nn)); _nn=(l).list.head)

#define LIST_WALK_REVERSE_(l, n) \
  for(node *_nn=(l).list.tail; _nn->prev && (n = NODE_OUT(l, _nn)); _nn=_nn->prev)

#define LIST_WALK_REVERSE_DELSAFE_(l, n) \
  for(node *_nn=(l).list.tail; _nn->prev && (n = NODE_OUT(l, _nn)) && (_nn=_nn->prev, 1); )


#define LIST_WALK(l, n) \
  WITH(LIST_TYPE(l) *, n, NULL) LIST_WALK_(l, n)

#define LIST_WALK_DELSAFE(l, n) \
  WITH(LIST_TYPE(l) *, n, NULL) LIST_WALK_DELSAFE_(l, n)

#define LIST_WALK_FIRST(l, n) \
  WITH(LIST_TYPE(l) *, n, NULL) LIST_WALK_FIRST_(l, n)

#define LIST_WALK_REVERSE(l, n) \
  WITH(LIST_TYPE(l) *, n, NULL) LIST_WALK_REVERSE_(l, n)

#define LIST_WALK_REVERSE_DELSAFE(l, n) \
  WITH(LIST_TYPE(l) *, n, NULL) LIST_WALK_REVERSE_DELSAFE_(l, n)


#define LIST_WALK_REENTRANT(l, n) \
  for (n = LIST_FIRST(l); n; n = LIST_NEXT(l, n))

#define LIST_WALK_REVERSE_REENTRANT(l, n) \
  for (n = LIST_LAST(l); n; n = LIST_PREV(l, n))


#endif
