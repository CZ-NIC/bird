/*
 *	BIRD Library -- Safe Linked Lists Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"

#include "lib/slists.h"

#define MAX_NUM 1000

static snode nodes[MAX_NUM];
static slist lst;

static void
show_list(void)
{
  bt_debug("\n");
  bt_debug("list.null is at %p and point to %p \n", &lst.null, lst.null);
  bt_debug("list.head is at %p and point to %p \n", &lst.head, lst.head);
  bt_debug("list.tail is at %p and point to %p \n", &lst.tail, lst.tail);
  bt_debug("list.tail_readers is at %p and point to %p \n", &lst.tail_readers, lst.tail_readers);

  int i;
  for (i = 0; i < MAX_NUM; i++)
    bt_debug("n[%3i] is at %p, .prev (%p) points to %p, .next (%p) points to %p, .readers (%p) points to %p \n",
	     i, &nodes[i], &(nodes[i].prev), nodes[i].prev, &(nodes[i].next), nodes[i].next, &(nodes[i].readers), nodes[i].readers);
}

static int
is_filled_list_well_linked(void)
{
  int i;
  bt_assert(lst.head == &nodes[0]);
  bt_assert(lst.tail == &nodes[MAX_NUM-1]);
  bt_assert((void *) nodes[0].prev == (void *) &lst.head);
  bt_assert((void *) nodes[MAX_NUM-1].next == (void *) &lst.null);

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
  bt_assert(lst.head == SNODE &lst.null);
  bt_assert(lst.tail == SNODE &lst.head);

  bt_assert(EMPTY_SLIST(lst));

  return 1;
}

static void
init_list__(slist *l, struct snode nodes[])
{
  s_init_list(l);

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
  init_list__(&lst, nodes);
}

static int
t_add_tail(void)
{
  int i;

  init_list_();
  for (i = 0; i < MAX_NUM; i++)
  {
    s_add_tail(&lst, &nodes[i]);
    bt_debug(".");
    bt_assert(lst.tail == &nodes[i]);
    bt_assert(lst.head == &nodes[0]);
    bt_assert((void *) nodes[i].next == (void *) &lst.null);
    if (i > 0)
    {
      bt_assert(nodes[i-1].next == &nodes[i]);
      bt_assert(nodes[i].prev == &nodes[i-1]);
    }
  }

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
    s_add_head(&lst, &nodes[i]);
    bt_debug(".");
    bt_assert(lst.head == &nodes[i]);
    bt_assert(lst.tail == &nodes[MAX_NUM-1]);
    if (i < MAX_NUM-1)
    {
      bt_assert(nodes[i+1].prev == &nodes[i]);
      bt_assert(nodes[i].next == &nodes[i+1]);
    }
  }

  bt_assert(is_filled_list_well_linked());

  return 1;
}

static void
insert_node_(snode *n, snode *after)
{
  s_insert_node(n, after);
  bt_debug(".");
}

static int
t_insert_node(void)
{
  int i;

  init_list_();

  // add first node
  insert_node_(&nodes[0], SNODE &lst.head);

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
fill_list2(slist *l, snode nodes[])
{
  int i;
  for (i = 0; i < MAX_NUM; i++)
    s_add_tail(l, &nodes[i]);
}

static void
fill_list(void)
{
  fill_list2(&lst, SNODE nodes);
}


static int
t_remove_node(void)
{
  int i;

  init_list_();

  /* Fill & Remove & Check */
  fill_list();
  for (i = 0; i < MAX_NUM; i++)
    s_rem_node(&nodes[i]);
  bt_assert(is_empty_list_well_unlinked());

  /* Fill & Remove the half of nodes & Check & Remove the rest nodes & Check */
  fill_list();
  for (i = 0; i < MAX_NUM; i+=2)
    s_rem_node(&nodes[i]);

  int tail_node_index = (MAX_NUM % 2) ? MAX_NUM - 2 : MAX_NUM - 1;
  bt_assert(lst.head == &nodes[1]);
  bt_assert(lst.tail == &nodes[tail_node_index]);
  bt_assert(nodes[tail_node_index].next == SNODE &lst.null);

  for (i = 1; i < MAX_NUM; i+=2)
  {
    if (i > 1)
      bt_assert(nodes[i].prev == &nodes[i-2]);
    if (i < tail_node_index)
      bt_assert(nodes[i].next == &nodes[i+2]);
  }

  for (i = 1; i < MAX_NUM; i+=2)
    s_rem_node(&nodes[i]);
  bt_assert(is_empty_list_well_unlinked());

  return 1;
}

static int
t_add_tail_list(void)
{
  snode nodes2[MAX_NUM];
  slist l2;

  init_list__(&lst, SNODE &nodes);
  fill_list2(&lst, SNODE &nodes);

  init_list__(&l2, SNODE &nodes2);
  fill_list2(&l2, SNODE &nodes2);

  s_add_tail_list(&lst, &l2);

  bt_assert(nodes[MAX_NUM-1].next == &nodes2[0]);
  bt_assert(nodes2[0].prev == &nodes[MAX_NUM-1]);
  bt_assert(lst.tail == &nodes2[MAX_NUM-1]);

  return 1;
}

void
dump(const char *str, slist *a)
{
  snode *x;

  bt_debug("%s \n", str);
  for (x = SHEAD(*a); x; x = x->next)
  {
    siterator *i, *j;
    bt_debug("%p", x);
    j = (siterator *) x;
    for (i = x->readers; i; i = i->next)
    {
      if (i->prev != j)
	bt_debug(" ???");
      j = i;
      bt_debug(" [%p:%p]", i, i->node);
    }
    bt_debug("\n");
  }
  bt_debug("---\n");
}

static int
t_iterator_walk(void)
{
  snode *node;
  siterator iter;

  init_list_();
  fill_list();

  int k;
  int i = 0;

  show_list();

  s_init(&iter, &lst);
  WALK_SLIST(node, lst)
  {
    s_get(&iter);
    s_put(&iter, node);
    bt_debug("node->readers: %p, iter: %p, nodes[%d].readers: %p, node: %p, nodes[i]: %p, node->next: %p \n",
	     node->readers, &iter, i, nodes[i].readers, node, &(nodes[i]), node->next);
    bt_assert(node->readers == &iter);
    bt_assert(node->readers == nodes[i].readers);
    bt_assert(node == &(nodes[i]));
    for (k = 0; k < MAX_NUM; k++)
      if (k != i)
	bt_assert(nodes[k].readers == NULL);

    dump("",&lst);
    i++;
  }

  return 1;
}

static int
t_original(void)
{
  slist a, b;
  snode *x, *y;
  siterator i, j;

  s_init_list(&a);
  s_init_list(&b);
  x = xmalloc(sizeof(*x));
  s_add_tail(&a, x);
  x = xmalloc(sizeof(*x));
  s_add_tail(&a, x);
  x = xmalloc(sizeof(*x));
  s_add_tail(&a, x);
  dump("1", &a);

  s_init(&i, &a);
  s_init(&j, &a);
  dump("2", &a);

  x = s_get(&i);
  bt_debug("Got %p\n", x);
  dump("3", &a);

  s_put(&i, x->next);
  dump("4", &a);

  y = s_get(&j);
  while (y)
  {
    s_put(&j, y);
    dump("5*", &a);
    y = s_get(&j)->next;
  }

  dump("5 done", &a);

  s_rem_node(a.head->next);
  dump("6 (deletion)", &a);

  s_put(&i, s_get(&i)->next);
  dump("6 (relink)", &a);

  x = xmalloc(sizeof(*x));
  s_add_tail(&b, x);
  dump("7 (second list)", &b);

  s_add_tail_list(&b, &a);
  dump("8 (after merge)", &b);

  return 1;
}

static int
t_safe_del_walk(void)
{
  init_list_();
  fill_list();

  show_list();

  snode *node, *node_next;
  WALK_SLIST_DELSAFE(node,node_next, lst)
  {
    bt_debug("Will remove node %p \n", node);
    s_rem_node(SNODE node);
  }
  bt_assert(is_empty_list_well_unlinked());

  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_add_tail,		"Adding nodes to tail of list");
  bt_test_suite(t_add_head, 		"Adding nodes to head of list");
  bt_test_suite(t_insert_node, 	 	"Inserting nodes to list");
  bt_test_suite(t_remove_node,		"Removing nodes from list");
  bt_test_suite(t_add_tail_list,	"At the tail of a list adding the another list");
  bt_test_suite(t_iterator_walk,	"Iterator walk");
  bt_test_suite(t_safe_del_walk,	"WALK_SLIST_DELSAFE and s_rem_node all nodes");
  bt_test_suite(t_original, 		"The original BIRD test suit for SLIST");

  return bt_exit_value();
}
