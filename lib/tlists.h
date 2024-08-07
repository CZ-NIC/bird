/*
 *	BIRD Library -- Typed Linked Lists
 *
 *	(c) 2022 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *
 *	This implementation of linked lists forces its members to be
 *	typed. On the other hand, it needs to be implemented as ugly macros to
 *	keep the needed genericity.
 *
 *	Usage:
 *	1. Include this file
 *	2. Define the node structure
 *	3. For every list type you need to define:
 *	  A. #define TLIST_PREFIX and other macros
 *	  B. Include this file once again
 *
 *	Macros to define:
 *	TLIST_PREFIX:		prefix to prepend to everything generated
 *	TLIST_TYPE:		the actual node type
 *	TLIST_ITEM:		where the tlist structure is
 *	TLIST_WANT_WALK:	if defined, generates a helper functions for list walking macros
 *	TLIST_WANT_ADD_HEAD:	if defined, TLIST_PREFIX_add_head() is generated to
 *				add an item to the beginning of the list
 *	TLIST_WANT_ADD_TAIL:	if defined, TLIST_PREFIX_add_tail() is generated to
 *				add an item to the end of the list
 *
 *	TLIST_PREFIX_rem_node() is generated always.
 *
 *	All these macros are #undef-ed by including this file.
 *
 *	Example:
 *
 *	#include "lib/tlists.h"
 *	
 *	struct foo {
 *	  ...
 *	  TLIST_NODE(bar, struct foo) baz;
 *	  ...
 *	};
 *
 *	#define TLIST_PREFIX  bar
 *	#define TLIST_TYPE    struct foo
 *	#define TLIST_ITEM    baz
 *
 *	#define TLIST_WANT_WALK
 *	#define TLIST_WANT_ADD_HEAD
 *
 *	#include "lib/tlists.h"
 *
 *	...
 *	(end of example)
 *
 */

#ifdef _BIRD_LIB_TLISTS_H_
# ifdef TLIST_PREFIX

/* Check for mandatory arguments */
#ifndef TLIST_TYPE
#error "TLIST_TYPE must be defined"
#endif
#ifndef TLIST_ITEM
#error "TLIST_ITEM must be defined"
#endif
#ifndef TLIST_PREFIX
#error "TLIST_PREFIX must be defined"
#endif

#define TLIST_NAME(x)	MACRO_CONCAT_AFTER(TLIST_PREFIX,_##x)
#ifndef TLIST_LIST_STRUCT
#define TLIST_LIST_STRUCT	struct TLIST_NAME(list)
#endif

#ifndef TLIST_DEFINED_BEFORE
TLIST_STRUCT_DEF(TLIST_PREFIX, TLIST_TYPE);
#endif

static inline TLIST_LIST_STRUCT * TLIST_NAME(enlisted)(TLIST_TYPE *node)
{
  return node->TLIST_ITEM.list;
}

#ifdef TLIST_WANT_WALK
static inline struct TLIST_NAME(node) * TLIST_NAME(node_get)(TLIST_TYPE *node)
{ return &(node->TLIST_ITEM); }
#endif

#if defined(TLIST_WANT_ADD_HEAD) || defined(TLIST_WANT_ADD_AFTER)
static inline void TLIST_NAME(add_head)(TLIST_LIST_STRUCT *list, TLIST_TYPE *node)
{
  ASSERT_DIE(!TLIST_NAME(enlisted)(node));
  node->TLIST_ITEM.list = list;

  if (node->TLIST_ITEM.next = list->first)
    list->first->TLIST_ITEM.prev = node;
  else
    list->last = node;

  list->first = node;
}
#endif

#ifdef TLIST_WANT_ADD_TAIL
static inline void TLIST_NAME(add_tail)(TLIST_LIST_STRUCT *list, TLIST_TYPE *node)
{
  ASSERT_DIE(!TLIST_NAME(enlisted)(node));
  node->TLIST_ITEM.list = list;

  if (node->TLIST_ITEM.prev = list->last)
    list->last->TLIST_ITEM.next = node;
  else
    list->first = node;

  list->last = node;
}
#endif

#ifdef TLIST_WANT_UPDATE_NODE
static inline void TLIST_NAME(update_node)(TLIST_LIST_STRUCT *list, TLIST_TYPE *node)
{
  ASSERT_DIE(TLIST_NAME(enlisted)(node) == list);

  if (node->TLIST_ITEM.prev)
    node->TLIST_ITEM.prev->TLIST_ITEM.next = node;
  else
    list->first = node;

  if (node->TLIST_ITEM.next)
    node->TLIST_ITEM.next->TLIST_ITEM.prev = node;
  else
    list->last = node;
}
#endif

#ifdef TLIST_WANT_ADD_AFTER
static inline void TLIST_NAME(add_after)(TLIST_LIST_STRUCT *list, TLIST_TYPE *node, TLIST_TYPE *after)
{
  ASSERT_DIE(!TLIST_NAME(enlisted)(node));

  /* Adding to beginning */
  if (!(node->TLIST_ITEM.prev = after))
    return TLIST_NAME(add_head)(list, node);

  /* OK, Adding after a real node */
  node->TLIST_ITEM.list = list;

  /* There is another node after the anchor */
  if (node->TLIST_ITEM.next = after->TLIST_ITEM.next)
    /* Link back */
    node->TLIST_ITEM.next->TLIST_ITEM.prev = node;
  else
    /* Or we are adding the last node */
    list->last = node;

  /* Link forward from "after" */
  after->TLIST_ITEM.next = node;
}
#endif


static inline void TLIST_NAME(rem_node)(TLIST_LIST_STRUCT *list, TLIST_TYPE *node)
{
  ASSERT_DIE(TLIST_NAME(enlisted)(node) == list);

  if (node->TLIST_ITEM.prev)
    node->TLIST_ITEM.prev->TLIST_ITEM.next = node->TLIST_ITEM.next;
  else
  {
    ASSERT_DIE(list->first == node);
    list->first = node->TLIST_ITEM.next;
  }

  if (node->TLIST_ITEM.next)
    node->TLIST_ITEM.next->TLIST_ITEM.prev = node->TLIST_ITEM.prev;
  else
  {
    ASSERT_DIE(list->last == node);
    list->last = node->TLIST_ITEM.prev;
  }

  node->TLIST_ITEM.next = node->TLIST_ITEM.prev = NULL;
  node->TLIST_ITEM.list = NULL;
}

#undef TLIST_PREFIX
#undef TLIST_NAME
#undef TLIST_LIST_STRUCT
#undef TLIST_TYPE
#undef TLIST_ITEM
#undef TLIST_WANT_ADD_HEAD
#undef TLIST_WANT_ADD_TAIL
#undef TLIST_WANT_UPDATE_NODE
#undef TLIST_DEFINED_BEFORE

# endif
#else
#define _BIRD_LIB_TLISTS_H_

#include "lib/macro.h"

#if defined(TLIST_NAME) || defined(TLIST_PREFIX)
#error "You should first include lib/tlists.h without requesting a TLIST"
#endif

#define TLIST_LIST(_name)		struct _name##_list
#define TLIST_STRUCT_DEF(_name, _type)	TLIST_LIST(_name) { _type *first, *last; }

#define TLIST_NODE_IN(_name, _type)	{ _type *next; _type *prev; TLIST_LIST(_name) *list; }
#define TLIST_NODE(_name, _type)	struct _name##_node TLIST_NODE_IN(_name, _type)
#define TLIST_DEFAULT_NODE		struct MACRO_CONCAT_AFTER(TLIST_PREFIX,_node) \
					TLIST_NODE_IN(TLIST_PREFIX,TLIST_TYPE) TLIST_ITEM


/* Use ->first and ->last to access HEAD and TAIL */
#define THEAD(_name, _list)  (_list)->first
#define TTAIL(_name, _list)  (_list)->last

/* Walkaround macros: simple and resilient to node removal */
#define WALK_TLIST(_name, _node, _list) \
  for (typeof((_list)->first) _node = (_list)->first; \
      _node; _node = _name##_node_get((_node))->next)

#define WALK_TLIST_DELSAFE(_name, _node, _list) \
  for (typeof((_list)->first) _node = (_list)->first, \
      _helper = _node ? _name##_node_get((_list)->first)->next : NULL; \
      _node; \
      (_node = _helper) ? (_helper = _name##_node_get(_helper)->next) : 0)

/* Empty check */
#define EMPTY_TLIST(_name, _list) (!(_list)->first)

/* List length */
#define TLIST_LENGTH(_name, _list)  ({ uint _len = 0; WALK_TLIST(_name, _, _list) _len++; _len; })

#endif

