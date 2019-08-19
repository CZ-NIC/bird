/*
 *	BIRD Library -- Linked Lists
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Linked lists
 *
 * The BIRD library provides a set of functions for operating on linked
 * lists. The lists are internally represented as standard doubly linked
 * lists with synthetic head and tail which makes all the basic operations
 * run in constant time and contain no extra end-of-list checks. Each list
 * is described by a &list structure, nodes can have any format as long
 * as they start with a &node structure. If you want your nodes to belong
 * to multiple lists at once, you can embed multiple &node structures in them
 * and use the SKIP_BACK() macro to calculate a pointer to the start of the
 * structure from a &node pointer, but beware of obscurity.
 *
 * There also exist safe linked lists (&slist, &snode and all functions
 * being prefixed with |s_|) which support asynchronous walking very
 * similar to that used in the &fib structure.
 */

#define _BIRD_LISTS_C_

#include "nest/bird.h"
#include "lib/lists.h"

LIST_INLINE int
check_list(list *l, node *n)
{
  if (!l)
  {
    ASSERT_DIE(n);
    ASSERT_DIE(n->prev);

    do { n = n->prev; } while (n->prev);

    l = SKIP_BACK(list, head_node, n);
  }

  int seen = 0;

  ASSERT_DIE(l->null == NULL);
  ASSERT_DIE(l->head != NULL);
  ASSERT_DIE(l->tail != NULL);

  node *prev = &l->head_node, *cur = l->head, *next = l->head->next;
  while (next)
  {
    if (cur == n)
      seen++;
    ASSERT_DIE(cur->prev == prev);
    prev = cur;
    cur = next;
    next = next->next;
  }

  ASSERT_DIE(cur == &(l->tail_node));
  ASSERT_DIE(!n || (seen == 1));

  return 1;
}

/**
 * add_tail - append a node to a list
 * @l: linked list
 * @n: list node
 *
 * add_tail() takes a node @n and appends it at the end of the list @l.
 */
LIST_INLINE void
add_tail(list *l, node *n)
{
  EXPENSIVE_CHECK(check_list(l, NULL));
  ASSUME(n->prev == NULL);
  ASSUME(n->next == NULL);

  node *z = l->tail;

  n->next = &l->tail_node;
  n->prev = z;
  z->next = n;
  l->tail = n;
}

/**
 * add_head - prepend a node to a list
 * @l: linked list
 * @n: list node
 *
 * add_head() takes a node @n and prepends it at the start of the list @l.
 */
LIST_INLINE void
add_head(list *l, node *n)
{
  EXPENSIVE_CHECK(check_list(l, NULL));
  ASSUME(n->prev == NULL);
  ASSUME(n->next == NULL);

  node *z = l->head;

  n->next = z;
  n->prev = &l->head_node;
  z->prev = n;
  l->head = n;
}

/**
 * insert_node - insert a node to a list
 * @n: a new list node
 * @after: a node of a list
 *
 * Inserts a node @n to a linked list after an already inserted
 * node @after.
 */
LIST_INLINE void
insert_node(node *n, node *after)
{
  EXPENSIVE_CHECK(check_list(l, after));
  ASSUME(n->prev == NULL);
  ASSUME(n->next == NULL);

  node *z = after->next;

  n->next = z;
  n->prev = after;
  after->next = n;
  z->prev = n;
}

/**
 * rem_node - remove a node from a list
 * @n: node to be removed
 *
 * Removes a node @n from the list it's linked in. Afterwards, node @n is cleared.
 */
LIST_INLINE void
rem_node(node *n)
{
  EXPENSIVE_CHECK(check_list(NULL, n));

  node *z = n->prev;
  node *x = n->next;

  z->next = x;
  x->prev = z;
  n->next = NULL;
  n->prev = NULL;
}

/**
 * update_node - update node after calling realloc on it
 * @n: node to be updated
 *
 * Fixes neighbor pointers.
 */
LIST_INLINE void
update_node(node *n)
{
  ASSUME(n->next->prev == n->prev->next);

  n->next->prev = n;
  n->prev->next = n;

  EXPENSIVE_CHECK(check_list(NULL, n));
}

/**
 * init_list - create an empty list
 * @l: list
 *
 * init_list() takes a &list structure and initializes its
 * fields, so that it represents an empty list.
 */
LIST_INLINE void
init_list(list *l)
{
  l->head = &l->tail_node;
  l->null = NULL;
  l->tail = &l->head_node;
}

/**
 * add_tail_list - concatenate two lists
 * @to: destination list
 * @l: source list
 *
 * This function appends all elements of the list @l to
 * the list @to in constant time.
 */
LIST_INLINE void
add_tail_list(list *to, list *l)
{
  EXPENSIVE_CHECK(check_list(to, NULL));
  EXPENSIVE_CHECK(check_list(l, NULL));

  node *p = to->tail;
  node *q = l->head;

  p->next = q;
  q->prev = p;
  q = l->tail;
  q->next = &to->tail_node;
  to->tail = q;

  EXPENSIVE_CHECK(check_list(to, NULL));
}

LIST_INLINE uint
list_length(list *l)
{
  uint len = 0;
  node *n;

  EXPENSIVE_CHECK(check_list(l, NULL));

  WALK_LIST(n, *l)
    len++;

  return len;
}
