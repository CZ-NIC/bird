/*
 *	BIRD Library -- Linked Lists Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/tlists.h"

#define TLIST_PREFIX tp
#define TLIST_TYPE struct test_node
#define TLIST_ITEM n
#define TLIST_WANT_ADD_HEAD
#define TLIST_WANT_ADD_TAIL
#define TLIST_WANT_ADD_AFTER
#define TLIST_WANT_UPDATE_NODE

struct test_node {
  TLIST_DEFAULT_NODE;
};

#include "lib/tlists.h"

#define MAX_NUM 1000

static struct test_node nodes[MAX_NUM];
static TLIST_LIST(tp) l;

static void
show_list(void)
{
  bt_debug("\n");
  bt_debug("list.first points to %p\n", l.first);
  bt_debug("list.last  points to %p\n", l.last);

  int i;
  for (i = 0; i < MAX_NUM; i++)
  {
    bt_debug("n[%3i] is at %p\n", i, &nodes[i]);
    bt_debug("  prev is at %p and point to %p\n", &(nodes[i].n.prev), nodes[i].n.prev);
    bt_debug("  next is at %p and point to %p\n", &(nodes[i].n.next), nodes[i].n.next);
  }
}

static int
is_filled_list_well_linked(void)
{
  int i;
  bt_assert(l.first == &nodes[0]);
  bt_assert(l.last == &nodes[MAX_NUM-1]);
  bt_assert(!nodes[0].n.prev);
  bt_assert(!nodes[MAX_NUM-1].n.next);

  for (i = 0; i < MAX_NUM; i++)
  {
    bt_assert(nodes[i].n.list == &l);

    if (i < (MAX_NUM-1))
      bt_assert(nodes[i].n.next == &nodes[i+1]);

    if (i > 0)
      bt_assert(nodes[i].n.prev == &nodes[i-1]);
  }

  return 1;
}

static int
is_empty_list_well_unlinked(void)
{
  int i;

  bt_assert(!l.first);
  bt_assert(!l.last);
  bt_assert(EMPTY_TLIST(tp, &l));

  for (i = 0; i < MAX_NUM; i++)
  {
    bt_assert(nodes[i].n.next == NULL);
    bt_assert(nodes[i].n.prev == NULL);
    bt_assert(nodes[i].n.list == NULL);
  }

  return 1;
}

static void
init_list__(TLIST_LIST(tp) *l, struct test_node nodes[])
{
  *l = (TLIST_LIST(tp)) {};

  int i;
  for (i = 0; i < MAX_NUM; i++)
  {
    nodes[i].n.next = NULL;
    nodes[i].n.prev = NULL;
    nodes[i].n.list = NULL;
  }
}

static void
init_list_(void)
{
  init_list__(&l, nodes);
}

static int
t_add_tail(void)
{
  int i;

  init_list_();
  for (i = 0; i < MAX_NUM; i++)
  {
    tp_add_tail(&l, &nodes[i]);
    bt_debug(".");
    bt_assert(l.last == &nodes[i]);
    bt_assert(l.first == &nodes[0]);

    bt_assert(nodes[i].n.list == &l);
    bt_assert(!nodes[i].n.next);

    if (i > 0)
    {
      bt_assert(nodes[i-1].n.next == &nodes[i]);
      bt_assert(nodes[i].n.prev == &nodes[i-1]);
    }
  }
  show_list();
  bt_assert(is_filled_list_well_linked());

  return 1;
}

static int
t_add_head(void)
{
  int i;

  init_list_();
  for (i = MAX_NUM-1; i >= 0; i--)
  {
    tp_add_head(&l, &nodes[i]);
    bt_debug(".");
    bt_assert(l.first == &nodes[i]);
    bt_assert(l.last == &nodes[MAX_NUM-1]);
    if (i < MAX_NUM-1)
    {
      bt_assert(nodes[i+1].n.prev == &nodes[i]);
      bt_assert(nodes[i].n.next == &nodes[i+1]);
    }
  }
  show_list();
  bt_assert(is_filled_list_well_linked());

  return 1;
}

static void
insert_node_(TLIST_LIST(tp) *l, struct test_node *n, struct test_node *after)
{
  tp_add_after(l, n, after);
  bt_debug(".");
}

static int
t_insert_node(void)
{
  int i;

  init_list_();

  // add first node
  insert_node_(&l, &nodes[0], NULL);

  // add odd nodes
  for (i = 2; i < MAX_NUM; i+=2)
    insert_node_(&l, &nodes[i], &nodes[i-2]);

  // add even nodes
  for (i = 1; i < MAX_NUM; i+=2)
    insert_node_(&l, &nodes[i], &nodes[i-1]);

  bt_debug("\n");
  bt_assert(is_filled_list_well_linked());

  return 1;
}

static void
fill_list2(TLIST_LIST(tp) *l, struct test_node nodes[])
{
  int i;
  for (i = 0; i < MAX_NUM; i++)
    tp_add_tail(l, &nodes[i]);
}

static void
fill_list(void)
{
  fill_list2(&l, nodes);
}

static int
t_remove_node(void)
{
  int i;

  init_list_();

  /* Fill & Remove & Check */
  fill_list();
  for (i = 0; i < MAX_NUM; i++)
    tp_rem_node(&l, &nodes[i]);
  bt_assert(is_empty_list_well_unlinked());

  /* Fill & Remove the half of nodes & Check & Remove the rest nodes & Check */
  fill_list();
  for (i = 0; i < MAX_NUM; i+=2)
    tp_rem_node(&l, &nodes[i]);

  int tail_node_index = (MAX_NUM % 2) ? MAX_NUM - 2 : MAX_NUM - 1;
  bt_assert(l.first == &nodes[1]);
  bt_assert(l.last == &nodes[tail_node_index]);
  bt_assert(!nodes[tail_node_index].n.next);

  for (i = 1; i < MAX_NUM; i+=2)
  {
    if (i > 1)
      bt_assert(nodes[i].n.prev == &nodes[i-2]);
    if (i < tail_node_index)
      bt_assert(nodes[i].n.next == &nodes[i+2]);
  }

  for (i = 1; i < MAX_NUM; i+=2)
    tp_rem_node(&l, &nodes[i]);
  bt_assert(is_empty_list_well_unlinked());

  return 1;
}

static int
t_update_node(void)
{
  struct test_node head, inside, tail;

  init_list_();
  fill_list();

  head = nodes[0];
  tp_update_node(&l, &head);
  bt_assert(l.first == &head);
  bt_assert(head.n.prev == NULL);
  bt_assert(head.n.next == &nodes[1]);
  bt_assert(nodes[1].n.prev == &head);

  inside = nodes[MAX_NUM/2];
  tp_update_node(&l, &inside);
  bt_assert(nodes[MAX_NUM/2-1].n.next == &inside);
  bt_assert(nodes[MAX_NUM/2+1].n.prev == &inside);
  bt_assert(inside.n.prev == &nodes[MAX_NUM/2-1]);
  bt_assert(inside.n.next == &nodes[MAX_NUM/2+1]);

  tail = nodes[MAX_NUM-1];
  tp_update_node(&l, &tail);
  bt_assert(l.last == &tail);
  bt_assert(tail.n.prev == &nodes[MAX_NUM-2]);
  bt_assert(tail.n.next == NULL);
  bt_assert(nodes[MAX_NUM-2].n.next == &tail);

  return 1;
}

#if 0
static int
t_add_tail_list(void)
{
  node nodes2[MAX_NUM];
  list l2;

  init_list__(&l, (node *) nodes);
  fill_list2(&l, (node *) nodes);

  init_list__(&l2, (node *) nodes2);
  fill_list2(&l2, (node *) nodes2);

  add_tail_list(&l, &l2);

  bt_assert(nodes[MAX_NUM-1].next == &nodes2[0]);
  bt_assert(nodes2[0].prev == &nodes[MAX_NUM-1]);
  bt_assert(l.tail == &nodes2[MAX_NUM-1]);

  return 1;
}
#endif

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_add_tail, "Adding nodes to tail of list");
  bt_test_suite(t_add_head, "Adding nodes to head of list");
  bt_test_suite(t_insert_node, "Inserting nodes to list");
  bt_test_suite(t_remove_node, "Removing nodes from list");
  bt_test_suite(t_update_node, "Updating nodes in list");
#if 0
  bt_test_suite(t_add_tail_list, "At the tail of a list adding the another list");
#endif

  return bt_exit_value();
}
