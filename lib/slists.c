/*
 *	BIRD Library -- Safe Linked Lists
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#define _BIRD_SLISTS_C_

#include "nest/bird.h"
#include "lib/slists.h"

static inline void
s_merge(snode *from, snode *to)
{
  siterator *f, *g;

  if (!(f = from->readers))
    return;
  if (!(g = to->readers))
    {
      /* Fast path */
      to->readers = f;
      f->prev = (siterator *) to;
    fixup:
      while (f && f->node)
	{
	  f->node = NULL;
	  f = f->next;
	}
      return;
    }
  /* Really merging */
  while (g->next)
    g = g->next;
  g->next = f;
  f->prev = g;
  goto fixup;
}

snode *
s_get(siterator *i)
{
  siterator *f, *g;
  snode *n;

  if (!(n = i->node))
    {
      /*
       * No node found. We have to walk the iterator list backwards
       * to find where are we linked.
       */
      f = i;
      while (!f->null)
	f = f->prev;
      n = (snode *) f;
    }
  f = i->prev;				/* Maybe the snode itself */
  g = i->next;
  f->next = g;
  if (g)
    g->prev = f;

  i->prev = NULL;
  i->next = NULL;
  return n;
}

void
s_put(siterator *i, snode *n)
{
  siterator *f;

  i->node = n;
  if (f = n->readers)
    f->prev = i;
  i->next = f;
  n->readers = i;
  i->prev = (siterator *) n;
  i->null = NULL;
}

void
s_add_tail(slist *l, snode *n)
{
  snode *z = l->tail;

  n->next = (snode *) &l->null;
  n->prev = z;
  z->next = n;
  l->tail = n;
  n->readers = NULL;
}

void
s_add_head(slist *l, snode *n)
{
  snode *z = l->head;

  n->next = z;
  n->prev = (snode *) &l->head;
  z->prev = n;
  l->head = n;
  n->readers = NULL;
}

void
s_insert_node(snode *n, snode *after)
{
  snode *z = after->next;

  n->next = z;
  n->prev = after;
  after->next = n;
  z->prev = n;
  n->readers = NULL;
}

void
s_rem_node(snode *n)
{
  snode *z = n->prev;
  snode *x = n->next;

  z->next = x;
  x->prev = z;
  s_merge(n, x);
}

void
s_init_list(slist *l)
{
  l->head = (snode *) &l->null;
  l->null = NULL;
  l->tail = (snode *) &l->head;
  l->tail_readers = NULL;
}

void
s_add_tail_list(slist *to, slist *l)
{
  snode *p = to->tail;
  snode *q = l->head;

  p->next = q;
  q->prev = p;
  q = l->tail;
  q->next = (snode *) &to->null;
  to->tail = q;
  s_merge((snode *) &l->null, (snode *) &to->null);
}
