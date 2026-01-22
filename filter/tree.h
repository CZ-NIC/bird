/*
 *	BIRD Internet Routing Daemon -- Binary Search Trees
 *
 *	(c) 1998 Pavel Machek <pavel@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_FILTER_TREE_H_
#define _BIRD_FILTER_TREE_H_

#include "nest/bird.h"
#include "lib/types-enums.h"
#include "lib/types-union.h"

struct f_tree {
  struct f_tree *left, *right;
  struct f_val from, to;
  void *data;
};

struct f_tree *f_new_tree(void);
struct f_tree *build_tree(struct f_tree *, bool merge);
const struct f_tree *find_tree(const struct f_tree *t, const struct f_val *val);
const struct f_tree *find_tree_linear(const struct f_tree *t, const struct f_val *val);
int same_tree(const struct f_tree *t0, const struct f_tree *t2);
int tree_node_count(const struct f_tree *t);
void tree_format(const struct f_tree *t, buffer *buf);
void tree_walk(const struct f_tree *t, void (*hook)(const struct f_tree *, void *), void *data);

int clist_set_type(const struct f_tree *set, struct f_val *v);
static inline int eclist_set_type(const struct f_tree *set)
{ return !set || set->from.type == T_EC; }
static inline int lclist_set_type(const struct f_tree *set)
{ return !set || set->from.type == T_LC; }
static inline int path_set_type(const struct f_tree *set)
{ return !set || set->from.type == T_INT; }

int clist_match_set(const struct adata *clist, const struct f_tree *set);
int eclist_match_set(const struct adata *list, const struct f_tree *set);
int lclist_match_set(const struct adata *list, const struct f_tree *set);

#endif
