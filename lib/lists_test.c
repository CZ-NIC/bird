/*
 *	BIRD Library -- Linked Lists Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/lists.h"

#define MAX_NUM 1000

static node nodes[MAX_NUM];
static list l;

static void
show_list(void)
{
  bt_debug("\n");
  bt_debug("list.null is at %p and point to %p\n", &l.null, l.null);
  bt_debug("list.head is at %p and point to %p\n", &l.head, l.head);
  bt_debug("list.tail is at %p and point to %p\n", &l.tail, l.tail);

  int i;
  for (i = 0; i < MAX_NUM; i++)
  {
    bt_debug("n[%3i] is at %p\n", i, &nodes[i]);
    bt_debug("  prev is at %p and point to %p\n", &(nodes[i].prev), nodes[i].prev);
    bt_debug("  next is at %p and point to %p\n", &(nodes[i].next), nodes[i].next);
  }
}

static int
is_filled_list_well_linked(void)
{
  int i;
  bt_assert(l.head == &nodes[0]);
  bt_assert(l.tail == &nodes[MAX_NUM-1]);
  bt_assert((void *) nodes[0].prev == (void *) &l.head);
  bt_assert((void *) nodes[MAX_NUM-1].next == (void *) &l.null);

  for (i = 0; i < MAX_NUM; i++)
  {
    if (i < (MAX_NUM-1))
      bt_assert(nodes[i].next == &nodes[i+1]);

    if (i > 0)
      bt_assert(nodes[i].prev == &nodes[i-1]);
  }

  return 1;
}

static int
is_empty_list_well_unlinked(void)
{
  int i;

  bt_assert(l.head == NODE &l.null);
  bt_assert(l.tail == NODE &l.head);
  bt_assert(EMPTY_LIST(l));

  for (i = 0; i < MAX_NUM; i++)
  {
    bt_assert(nodes[i].next == NULL);
    bt_assert(nodes[i].prev == NULL);
  }

  return 1;
}

static void
init_list__(list *l, struct node nodes[])
{
  init_list(l);

  int i;
  for (i = 0; i < MAX_NUM; i++)
  {
    nodes[i].next = NULL;
    nodes[i].prev = NULL;
  }
}

static void
init_list_(void)
{
  init_list__(&l, (node *) nodes);
}

static int
t_add_tail(void)
{
  int i;

  init_list_();
  for (i = 0; i < MAX_NUM; i++)
  {
    add_tail(&l, &nodes[i]);
    bt_debug(".");
    bt_assert(l.tail == &nodes[i]);
    bt_assert(l.head == &nodes[0]);
    bt_assert((void *) nodes[i].next == (void *) &l.null);
    if (i > 0)
    {
      bt_assert(nodes[i-1].next == &nodes[i]);
      bt_assert(nodes[i].prev == &nodes[i-1]);
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
    add_head(&l, &nodes[i]);
    bt_debug(".");
    bt_assert(l.head == &nodes[i]);
    bt_assert(l.tail == &nodes[MAX_NUM-1]);
    if (i < MAX_NUM-1)
    {
      bt_assert(nodes[i+1].prev == &nodes[i]);
      bt_assert(nodes[i].next == &nodes[i+1]);
    }
  }
  show_list();
  bt_assert(is_filled_list_well_linked());

  return 1;
}

static void
insert_node_(node *n, node *after)
{
  insert_node(n, after);
  bt_debug(".");
}

static int
t_insert_node(void)
{
  int i;

  init_list_();

  // add first node
  insert_node_(&nodes[0], NODE &l.head);

  // add odd nodes
  for (i = 2; i < MAX_NUM; i+=2)
    insert_node_(&nodes[i], &nodes[i-2]);

  // add even nodes
  for (i = 1; i < MAX_NUM; i+=2)
    insert_node_(&nodes[i], &nodes[i-1]);

  bt_debug("\n");
  bt_assert(is_filled_list_well_linked());

  return 1;
}

static void
fill_list2(list *l, node nodes[])
{
  int i;
  for (i = 0; i < MAX_NUM; i++)
    add_tail(l, &nodes[i]);
}

static void
fill_list(void)
{
  fill_list2(&l, (node *) nodes);
}

static int
t_remove_node(void)
{
  int i;

  init_list_();

  /* Fill & Remove & Check */
  fill_list();
  for (i = 0; i < MAX_NUM; i++)
    rem_node(&nodes[i]);
  bt_assert(is_empty_list_well_unlinked());

  /* Fill & Remove the half of nodes & Check & Remove the rest nodes & Check */
  fill_list();
  for (i = 0; i < MAX_NUM; i+=2)
    rem_node(&nodes[i]);

  int tail_node_index = (MAX_NUM % 2) ? MAX_NUM - 2 : MAX_NUM - 1;
  bt_assert(l.head == &nodes[1]);
  bt_assert(l.tail == &nodes[tail_node_index]);
  bt_assert(nodes[tail_node_index].next == NODE &l.null);

  for (i = 1; i < MAX_NUM; i+=2)
  {
    if (i > 1)
      bt_assert(nodes[i].prev == &nodes[i-2]);
    if (i < tail_node_index)
      bt_assert(nodes[i].next == &nodes[i+2]);
  }

  for (i = 1; i < MAX_NUM; i+=2)
    rem_node(&nodes[i]);
  bt_assert(is_empty_list_well_unlinked());

  return 1;
}

static int
t_update_node(void)
{
  node head, inside, tail;

  init_list_();
  fill_list();

  head = nodes[0];
  update_node(&head);
  bt_assert(l.head == &head);
  bt_assert(head.prev == NODE &l.head);
  bt_assert(head.next == &nodes[1]);
  bt_assert(nodes[1].prev == &head);

  inside = nodes[MAX_NUM/2];
  update_node(&inside);
  bt_assert(nodes[MAX_NUM/2-1].next == &inside);
  bt_assert(nodes[MAX_NUM/2+1].prev == &inside);
  bt_assert(inside.prev == &nodes[MAX_NUM/2-1]);
  bt_assert(inside.next == &nodes[MAX_NUM/2+1]);

  tail = nodes[MAX_NUM-1];
  update_node(&tail);
  bt_assert(l.tail == &tail);
  bt_assert(tail.prev == &nodes[MAX_NUM-2]);
  bt_assert(tail.next == NODE &l.null);
  bt_assert(nodes[MAX_NUM-2].next == &tail);

  return 1;
}

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

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_add_tail, "Adding nodes to tail of list");
  bt_test_suite(t_add_head, "Adding nodes to head of list");
  bt_test_suite(t_insert_node, "Inserting nodes to list");
  bt_test_suite(t_remove_node, "Removing nodes from list");
  bt_test_suite(t_update_node, "Updating nodes in list");
  bt_test_suite(t_add_tail_list, "At the tail of a list adding the another list");

  return bt_exit_value();
}
