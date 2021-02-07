/*
 *	Filters: utility functions
 *
 *	Copyright 1998 Pavel Machek <pavel@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/alloca.h"
#include "nest/bird.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/data.h"

/**
 * find_tree
 * @t: tree to search in
 * @val: value to find
 *
 * Search for given value in the tree. I relies on fact that sorted tree is populated
 * by &f_val structures (that can be compared by val_compare()). In each node of tree, 
 * either single value (then t->from==t->to) or range is present.
 *
 * Both set matching and |switch() { }| construction is implemented using this function,
 * thus both are as fast as they can be.
 */
const struct f_tree *
find_tree(const struct f_tree *t, const struct f_val *val)
{
  if (!t)
    return NULL;
  if ((val_compare(&(t->from), val) != 1) &&
      (val_compare(&(t->to), val) != -1))
    return t;
  if (val_compare(&(t->from), val) == -1)
    return find_tree(t->right, val);
  else
    return find_tree(t->left, val);
}

static struct f_tree *
build_tree_rec(struct f_tree **buf, int l, int h)
{
  struct f_tree *n;
  int pos;

  if (l >= h)
    return NULL;

  pos = (l+h)/2;
  n = buf[pos];
  n->left = build_tree_rec(buf, l, pos);
  n->right = build_tree_rec(buf, pos+1, h);
  return n;
}

static int 
tree_compare(const void *p1, const void *p2)
{
  return val_compare(&((* (struct f_tree **) p1)->from), &((* (struct f_tree **) p2)->from));
}

/**
 * build_tree
 * @from: degenerated tree (linked by @tree->left) to be transformed into form suitable for find_tree()
 *
 * Transforms degenerated tree into balanced tree.
 */
struct f_tree *
build_tree(struct f_tree *from)
{
  struct f_tree *tmp, *root;
  struct f_tree **buf;
  int len, i;

  if (from == NULL)
    return NULL;

  len = 0;
  for (tmp = from; tmp != NULL; tmp = tmp->left)
    len++;

  if (len <= 1024)
    buf = alloca(len * sizeof(struct f_tree *));
  else
    buf = xmalloc(len * sizeof(struct f_tree *));

  /* Convert a degenerated tree into an sorted array */
  i = 0;
  for (tmp = from; tmp != NULL; tmp = tmp->left)
    buf[i++] = tmp;

  qsort(buf, len, sizeof(struct f_tree *), tree_compare);

  root = build_tree_rec(buf, 0, len);

  if (len > 1024)
    xfree(buf);

  return root;
}

struct f_tree *
f_new_tree(void)
{
  struct f_tree *ret = cfg_allocz(sizeof(struct f_tree));
  return ret;
}

/**
 * same_tree
 * @t1: first tree to be compared
 * @t2: second one
 *
 * Compares two trees and returns 1 if they are same
 */
int
same_tree(const struct f_tree *t1, const struct f_tree *t2)
{
  if ((!!t1) != (!!t2))
    return 0;
  if (!t1)
    return 1;
  if (val_compare(&(t1->from), &(t2->from)))
    return 0;
  if (val_compare(&(t1->to), &(t2->to)))
    return 0;
  if (!same_tree(t1->left, t2->left))
    return 0;
  if (!same_tree(t1->right, t2->right))
    return 0;
  if (!f_same(t1->data, t2->data))
    return 0;
  return 1;
}


static void
tree_node_format(const struct f_tree *t, buffer *buf)
{
  if (t == NULL)
    return;

  tree_node_format(t->left, buf);

  val_format(&(t->from), buf);
  if (val_compare(&(t->from), &(t->to)) != 0)
  {
    buffer_puts(buf, "..");
    val_format(&(t->to), buf);
  }
  buffer_puts(buf, ", ");

  tree_node_format(t->right, buf);
}

void
tree_format(const struct f_tree *t, buffer *buf)
{
  buffer_puts(buf, "[");

  tree_node_format(t, buf);

  if (buf->pos == buf->end)
    return;

  /* Undo last separator */
  if (buf->pos[-1] != '[')
    buf->pos -= 2;

  buffer_puts(buf, "]");
}

void
tree_walk(const struct f_tree *t, void (*hook)(const struct f_tree *, void *), void *data)
{
  if (!t)
    return;

  tree_walk(t->left, hook, data);
  hook(t, data);
  tree_walk(t->right, hook, data);
}
