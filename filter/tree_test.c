/*
 *	Filters: Utility Functions Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "filter/filter.h"

static struct f_tree *
new_tree(uint id)
{
  struct f_tree *tree = f_new_tree();
  tree->from.type  = tree->to.type  = T_INT;
  tree->from.val.i = tree->to.val.i = id;

  return tree;
}

static void
show_subtree(struct f_tree *node)
{
  if (!node)
    return;

  if (node->from.val.i == node->to.val.i)
    bt_debug("%u ", node->from.val.i);
  else
    bt_debug("%u..%u ", node->from.val.i, node->to.val.i);
  show_subtree(node->left);
  show_subtree(node->right);
}

static void
show_tree2(struct f_tree *root_node, const char *tree_name)
{
  bt_debug("%s: \n", tree_name);
  bt_debug("[ ");
  show_subtree(root_node);
  bt_debug("]\n\n");
}

#define show_tree(tree) show_tree2(tree, #tree);

static uint
get_nodes_count_in_full_tree(uint height)
{
  return (naive_pow(2, height+1) - 1);
}

static struct f_tree *
get_balanced_full_subtree(uint height, uint idx)
{
  struct f_tree *node = new_tree(idx);
  if (height > 0)
  {
    uint nodes_in_subtree = get_nodes_count_in_full_tree(--height);
    node->left  = get_balanced_full_subtree(height, idx - nodes_in_subtree/2 - 1);
    node->right = get_balanced_full_subtree(height, idx + nodes_in_subtree/2 + 1);
  }
  return node;
}

static struct f_tree *
get_balanced_full_tree(uint height)
{
  return get_balanced_full_subtree(height, get_nodes_count_in_full_tree(height)/2);
}

static struct f_tree *
get_degenerated_left_tree(uint nodes_count)
{
  struct f_tree **nodes = (struct f_tree **) malloc(nodes_count * sizeof(struct f_tree *));

  int i;
  for (i = nodes_count-1; i >= 0; i--)
  {
    nodes[i] = new_tree(i);
    if (i != nodes_count-1)
      nodes[i]->left = nodes[i+1];
  }

  struct f_tree *root_node = nodes[0];
  free(nodes);

  return root_node;
}

static struct f_tree *
get_random_degenerated_left_tree(uint nodes_count)
{
  struct f_tree *tree = get_degenerated_left_tree(nodes_count);

  size_t avaible_indexes_size = nodes_count * sizeof(byte);
  byte *avaible_indexes = malloc(avaible_indexes_size);
  bzero(avaible_indexes, avaible_indexes_size);

  struct f_tree *n;
  for (n = tree; n; n = n->left)
  {
    uint selected_idx;
    do {
      selected_idx = bt_random() % nodes_count;
    } while(avaible_indexes[selected_idx] != 0);

    avaible_indexes[selected_idx] = 1;
    n->from.type  = n->to.type  = T_INT;
    n->from.val.i = n->to.val.i = selected_idx;
  }

  free(avaible_indexes);
  return tree;
}

static struct f_tree *
get_balanced_tree_with_ranged_values(uint nodes_count)
{
  struct f_tree *tree = get_degenerated_left_tree(nodes_count);

  uint idx = 0;
  struct f_tree *n;
  for (n = tree; n; n = n->left)
  {
    n->from.type = n->to.type = T_INT;
    n->from.val.i = idx;
    idx += (uint)bt_random() / nodes_count;	/* (... / nodes_count) preventing overflow an uint idx */
    n->to.val.i = idx++;
  }

  return build_tree(tree);
}


static int
t_balancing(void)
{
  bt_bird_init_with_simple_configuration();

  uint height;
  for (height = 1; height < 13; height++)
  {
    uint nodes_count = get_nodes_count_in_full_tree(height);

    struct f_tree *simple_degenerated_tree = get_degenerated_left_tree(nodes_count);
    struct f_tree *expected_balanced_tree = get_balanced_full_tree(height);
    struct f_tree *balanced_tree_from_simple_degenerated = build_tree(simple_degenerated_tree);

    show_tree(simple_degenerated_tree);
    show_tree(expected_balanced_tree);
    show_tree(balanced_tree_from_simple_degenerated);

    bt_assert(same_tree(balanced_tree_from_simple_degenerated, expected_balanced_tree));
  }

  return BT_SUCCESS;
}

static int
t_balancing_random(void)
{
  bt_bird_init_with_simple_configuration();

  uint height;
  for (height = 1; height < 10; height++)
  {
    uint nodes_count = get_nodes_count_in_full_tree(height);

    struct f_tree *expected_balanced_tree = get_balanced_full_tree(height);

    uint i;
    for(i = 0; i < 10; i++)
    {
      struct f_tree *random_degenerated_tree = get_random_degenerated_left_tree(nodes_count);
      struct f_tree *balanced_tree_from_random_degenerated = build_tree(random_degenerated_tree);

      show_tree(random_degenerated_tree);
      show_tree(expected_balanced_tree);
      show_tree(balanced_tree_from_random_degenerated);

      bt_assert(same_tree(balanced_tree_from_random_degenerated, expected_balanced_tree));
    }
  }

  return BT_SUCCESS;
}

static int
t_find(void)
{
  bt_bird_init_with_simple_configuration();

  uint height;
  for (height = 1; height < 13; height++)
  {
    uint nodes_count = get_nodes_count_in_full_tree(height);

    struct f_tree *tree = get_balanced_full_tree(height);

    struct f_val looking_up_value = {
	.type = T_INT
    };
    for(looking_up_value.val.i = 0; looking_up_value.val.i < nodes_count; looking_up_value.val.i++)
    {
      struct f_tree *found_tree = find_tree(tree, looking_up_value);
      bt_assert((val_compare(looking_up_value, found_tree->from) == 0) && (val_compare(looking_up_value, found_tree->to) == 0));
    }
  }

  return BT_SUCCESS;
}

static uint
get_max_value_in_unbalanced_tree(struct f_tree *node, uint max)
{
  if (!node)
    return max;

  if (node->to.val.i > max)
    max = node->to.val.i;

  uint max_left  = get_max_value_in_unbalanced_tree(node->left, max);
  if (max_left > max)
    max = max_left;

  uint max_right = get_max_value_in_unbalanced_tree(node->right, max);
  if (max_right > max)
    max = max_right;

  return max;
}

static int
t_find_ranges(void)
{
  bt_bird_init_with_simple_configuration();

  uint height;
  for (height = 1; height < 10; height++)
  {
    uint nodes_count = get_nodes_count_in_full_tree(height);

    struct f_tree *tree = get_balanced_tree_with_ranged_values(nodes_count);
    uint max_value = get_max_value_in_unbalanced_tree(tree, 0);
    bt_debug("max_value: %u \n", max_value);

    struct f_val looking_up_value = {
	.type = T_INT
    };
    for(looking_up_value.val.i = 0; looking_up_value.val.i <= max_value; looking_up_value.val.i += ((uint)bt_random()/nodes_count))
    {
      struct f_tree *found_tree = find_tree(tree, looking_up_value);
      bt_debug("searching: %u \n", looking_up_value.val.i);
      bt_assert(
	  (val_compare(looking_up_value, found_tree->from) == 0) || (val_compare(looking_up_value, found_tree->to) == 0) ||
	 ((val_compare(looking_up_value, found_tree->from) == 1) && (val_compare(looking_up_value, found_tree->to) == -1))
      );
    }
  }

  return BT_SUCCESS;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_balancing, "Balancing strong unbalanced trees");
  bt_test_suite(t_balancing_random, "Balancing random unbalanced trees");
  bt_test_suite(t_find, "Finding values in trees");
  bt_test_suite(t_find_ranges, "Finding values in trees with random ranged values");

  return bt_end();
}
