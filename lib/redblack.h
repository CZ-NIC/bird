/*
 *	BIRD Internet Routing Daemon -- Red Black Tree
 *
 *	(c) 2018 Maria Matejka <mq@jmq.cz>
 *	(c) 2018 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_REDBLACK_H_
#define _BIRD_REDBLACK_H_

/* Assumption: The nodes are always residing on an even address.
 * We store the node blackness into the parent pointer LSB. */

/*
 * Typical use case:
 * struct mystruct {
 *   whatever;
 *   REDBLACK_NODE(struct mystruct, myprefix_);
 *   whatever;
 * };
 */

#define REDBLACK_NODE(type, name) type *name[3]

/* Color bit definition */
#define REDBLACK_BLACK	0
#define REDBLACK_RED	1

/* Parent pointer and color composition and resolution */
#define REDBLACK_PARENT_POINTER(name, what) (what)->name[0]
#define REDBLACK_PTR(type, pointer) ((type *) pointer)
#define REDBLACK_PTR_RED(type, pointer) REDBLACK_PTR(type, (((uintptr_t) (pointer)) | 1))
#define REDBLACK_PTR_BLACK(type, pointer) (pointer)
#define REDBLACK_PTR_COLOR(pointer) (((uintptr_t) (pointer)) & 1)
#define REDBLACK_NODE_COLOR(name, what) REDBLACK_PTR_COLOR(REDBLACK_PARENT_POINTER(name, what))
#define REDBLACK_PTR_COMPOSE(type, pointer, color) REDBLACK_PTR(type, (((uintptr_t) (pointer)) | (color)))
#define REDBLACK_PTR_PTR(type, pointer) REDBLACK_PTR(type, (((uintptr_t) (pointer)) & ~1))
#define REDBLACK_PARENT(type, name, what) REDBLACK_PTR_PTR(type, REDBLACK_PARENT_POINTER(name, what))
#define REDBLACK_SET_COLOR(type, name, what, color) \
  (REDBLACK_PARENT_POINTER(name, what) = REDBLACK_PTR_COMPOSE(type, REDBLACK_PARENT(type, name, what), color))

/* Left and right direction */
#define REDBLACK_LEFT	1
#define REDBLACK_RIGHT	2
#define REDBLACK_CHILD(name, what, where) (what)->name[where]
#define REDBLACK_CHILDREN(name, what) { (what)->name[REDBLACK_LEFT], (what)->name[REDBLACK_RIGHT] }
#define REDBLACK_LEFT_CHILD(name, what)  REDBLACK_CHILD(name, what, REDBLACK_LEFT)
#define REDBLACK_RIGHT_CHILD(name, what) REDBLACK_CHILD(name, what, REDBLACK_RIGHT)
#define REDBLACK_PARENT_SIDE(name, parent, child) ((REDBLACK_LEFT_CHILD(name, parent) == child) ? REDBLACK_LEFT : REDBLACK_RIGHT)


#define REDBLACK_DUMP(type, name, root, dumper) \
  do { \
    type *n = root; \
    int depth = 0, dir = 0; \
    while (n) { \
      switch (dir) { \
	case 0: if (REDBLACK_LEFT_CHILD(name, n)) { \
		  ASSERT(REDBLACK_PARENT(type, name, REDBLACK_LEFT_CHILD(name, n)) == n); \
		  n = REDBLACK_LEFT_CHILD(name, n); dir = 0; depth++; break; \
		} __attribute__((fallthrough)); \
	case 1: dumper(n, REDBLACK_NODE_COLOR(name, n), depth); \
		if (REDBLACK_RIGHT_CHILD(name, n)) { \
		  ASSERT(REDBLACK_PARENT(type, name, REDBLACK_RIGHT_CHILD(name, n)) == n); \
		  n = REDBLACK_RIGHT_CHILD(name, n); dir = 0; depth++; break; \
		} __attribute__((fallthrough)); \
	case 2: { \
		  type *p = REDBLACK_PARENT(type, name, n); \
		  if (p) dir = REDBLACK_PARENT_SIDE(name, p, n); \
		  n = p; \
		  depth--; \
		  break; \
		} \
      } \
    } \
  } while (0)

#define REDBLACK_MAX_REASONABLE_DEPTH 256
#define REDBLACK_CHECK(type, name, key, compare, root) do { \
  if (!root) \
    break; \
  type *prev = NULL; \
  struct redblack_check { \
    type *node; \
    int state; \
    int blackness[2]; \
  } stack[REDBLACK_MAX_REASONABLE_DEPTH] = { \
    {}, \
    { .node = root } \
  }; \
  int pos = 1; \
  while (pos > 0) { \
    switch (stack[pos].state) { \
      case 0: \
	if (REDBLACK_LEFT_CHILD(name, stack[pos].node)) { \
	  stack[pos+1] = (struct redblack_check) { .node = REDBLACK_LEFT_CHILD(name, stack[pos].node) }; \
	  ASSERT(compare(key(stack[pos+1].node), key(stack[pos].node)) < 0); \
	  pos++; \
	  continue; \
	} \
	stack[pos].state++; \
	__attribute__((fallthrough)); \
      case 1: \
	ASSERT(!prev || (compare(key(prev), key(stack[pos].node)) < 0)); \
	if (REDBLACK_RIGHT_CHILD(name, stack[pos].node)) { \
	  stack[pos+1] = (struct redblack_check) { .node = REDBLACK_RIGHT_CHILD(name, stack[pos].node) }; \
	  ASSERT(compare(key(stack[pos+1].node), key(stack[pos].node)) > 0); \
	  pos++; \
	  continue; \
	} \
	stack[pos].state++; \
	__attribute__((fallthrough)); \
      case 2: \
	ASSERT(stack[pos].blackness[0] == stack[pos].blackness[1]); \
	stack[pos-1].blackness[stack[pos-1].state] = stack[pos].blackness[0] + (REDBLACK_NODE_COLOR(name, stack[pos].node) == REDBLACK_BLACK); \
	pos--; \
	stack[pos].state++; \
    } \
  } \
/*  printf("Redblack check OK. Overall blackness: %d\n", stack[0].blackness[0]); */ \
} while(0)

#define REDBLACK_FIND_POINTER(name, key, compare, root, what, pointer) \
  for ( \
      int _cmp = !(pointer = &(root)); \
      (*pointer) && (_cmp = compare((what), key((*pointer)))); \
      pointer = &(REDBLACK_CHILD(name, (*pointer), ((_cmp < 0) ? 1 : 2))) \
      )

#define REDBLACK_FIND(type, name, key, compare, root, what) \
  ({ type **pointer; REDBLACK_FIND_POINTER(name, key, compare, root, what, pointer); *pointer; })

#define REDBLACK_FIRST(type, name, root) ({ \
    type *first = root; \
    if (first) \
      while (REDBLACK_LEFT_CHILD(name, first)) \
	first = REDBLACK_LEFT_CHILD(name, first); \
    first; \
})

#define REDBLACK_NEXT(type, name, node) ({ \
    type *where = node; \
    if (REDBLACK_RIGHT_CHILD(name, where)) { \
      where = REDBLACK_RIGHT_CHILD(name, where); \
      while (REDBLACK_LEFT_CHILD(name, where)) \
	where = REDBLACK_LEFT_CHILD(name, where); \
    } else \
      while (1) { \
	type *p = REDBLACK_PARENT(type, name, where); \
	int ps = p ? REDBLACK_PARENT_SIDE(name, p, where) : 0; \
	where = p; \
	if (ps == REDBLACK_RIGHT) \
	  continue; \
	break; \
      } \
    where; \
})


/* Low level tree manipulation */

/* Connect a node @ch to its new parent @p on side @side, setting color of @ch to @color */
#define REDBLACK_CONNECT_NODE_SET_COLOR(type, name, p, side, ch, color) \
  (ch ? (REDBLACK_PARENT_POINTER(name, (REDBLACK_CHILD(name, p, side) = ch)) = REDBLACK_PTR_COMPOSE(type, p, color)) \
   : (REDBLACK_CHILD(name, p, side) = NULL))

/* Connect a node @ch to its new parent @p on side @side, keeping its former color */
#define REDBLACK_CONNECT_NODE_KEEP_COLOR(type, name, p, side, ch) \
  REDBLACK_CONNECT_NODE_SET_COLOR(type, name, p, side, ch, REDBLACK_NODE_COLOR(name, ch))

/* Opposite side macros (left <=> right) */
#define REDBLACK_OPPOSITE(side) (3-(side))

/* Tree rotation in a given direction.
 * Left rotation:
 *
 *   (P)                 (C)
 *  /  XX               XX  \
 * (A)  (C)    --->   (P)   (D)    
 *      X \           / X
 *    (B) (D)       (A) (B)
 *
 * Right rotation is in the opposite direction.
 */
#define REDBLACK_ROTATE(type, name, root, p, side) do { \
  type *rp = p, \
  *rg = REDBLACK_PARENT(type, name, rp), \
  *rc = REDBLACK_CHILD(name, rp, REDBLACK_OPPOSITE(side)), \
  *rb = REDBLACK_CHILD(name, rc, side); \
  int rgs = rg ? REDBLACK_PARENT_SIDE(name, rg, rp) : 0; \
  REDBLACK_CONNECT_NODE_KEEP_COLOR(type, name, rc, side, rp); \
  REDBLACK_CONNECT_NODE_KEEP_COLOR(type, name, rp, REDBLACK_OPPOSITE(side), rb); \
  if (rgs) \
    REDBLACK_CONNECT_NODE_KEEP_COLOR(type, name, rg, rgs, rc); \
  else { \
    REDBLACK_PARENT_POINTER(name, rc) = NULL; \
    root = rc; \
  } \
} while (0)

#define REDBLACK_INSERT(type, name, key, compare, root, what) do { \
  type **where = &(root); \
  what->name[1] = what->name[2] = NULL; \
  REDBLACK_FIND_POINTER(name, key, compare, root, key(what), where) \
    REDBLACK_PARENT_POINTER(name, what) = REDBLACK_PTR_RED(type, *where); \
  ASSERT(!*where); \
  *where = what; \
  type *n = *where; \
  do { \
    if (((uintptr_t) REDBLACK_PARENT_POINTER(name, n)) == 1) \
      REDBLACK_PARENT_POINTER(name, n) = NULL; \
    if (REDBLACK_PARENT_POINTER(name, n) == NULL) \
      break; \
    type *p = REDBLACK_PARENT(type, name, n); \
    if (REDBLACK_NODE_COLOR(name, p) == REDBLACK_BLACK) \
      break; \
    type *g = REDBLACK_PARENT(type, name, p); \
    type *u = REDBLACK_CHILD(name, g, REDBLACK_OPPOSITE(REDBLACK_PARENT_SIDE(name, g, p))); \
    if (u && REDBLACK_NODE_COLOR(name, u) == REDBLACK_RED) { \
      REDBLACK_SET_COLOR(type, name, u, REDBLACK_BLACK); \
      REDBLACK_SET_COLOR(type, name, p, REDBLACK_BLACK); \
      REDBLACK_SET_COLOR(type, name, g, REDBLACK_RED); \
      n = g; \
      continue; \
    } \
    int gc = REDBLACK_PARENT_SIDE(name, g, p); \
    int pc = REDBLACK_PARENT_SIDE(name, p, n); \
    if (gc != pc) { \
      REDBLACK_ROTATE(type, name, root, p, gc); \
      REDBLACK_SET_COLOR(type, name, n, REDBLACK_BLACK); \
    } else \
      REDBLACK_SET_COLOR(type, name, p, REDBLACK_BLACK); \
    REDBLACK_ROTATE(type, name, root, g, REDBLACK_OPPOSITE(gc)); \
    REDBLACK_SET_COLOR(type, name, g, REDBLACK_RED); \
    break; \
  } while (1); \
} while (0)

#define REDBLACK_EXCHANGE(type, name, root, aa, bb) do { \
  type *a = aa, *b = bb; \
  type *ap = REDBLACK_PARENT(type, name, a), *al = REDBLACK_LEFT_CHILD(name, a), *ar = REDBLACK_RIGHT_CHILD(name, a); \
  type *bp = REDBLACK_PARENT(type, name, b), *bl = REDBLACK_LEFT_CHILD(name, b), *br = REDBLACK_RIGHT_CHILD(name, b); \
  int as = ap ? REDBLACK_PARENT_SIDE(name, ap, a) : 0, bs = bp ? REDBLACK_PARENT_SIDE(name, bp, b) : 0; \
  if ((ap != b) || (as != REDBLACK_LEFT)) \
    REDBLACK_CONNECT_NODE_KEEP_COLOR(type, name, a, REDBLACK_LEFT, bl); \
  if ((bp != a) || (bs != REDBLACK_LEFT)) \
    REDBLACK_CONNECT_NODE_KEEP_COLOR(type, name, b, REDBLACK_LEFT, al); \
  if ((ap != b) || (as != REDBLACK_RIGHT)) \
    REDBLACK_CONNECT_NODE_KEEP_COLOR(type, name, a, REDBLACK_RIGHT, br); \
  if ((bp != a) || (bs != REDBLACK_RIGHT)) \
    REDBLACK_CONNECT_NODE_KEEP_COLOR(type, name, b, REDBLACK_RIGHT, ar); \
  int ac = REDBLACK_NODE_COLOR(name, a), bc = REDBLACK_NODE_COLOR(name, b); \
  if (a == bp) \
    bp = b; \
  if (b == ap) \
    ap = a; \
  if (ap) \
    REDBLACK_CONNECT_NODE_SET_COLOR(type, name, ap, as, b, ac); \
  else { \
    REDBLACK_PARENT_POINTER(name, b) = NULL; \
    root = b; \
  } \
  if (bp) \
    REDBLACK_CONNECT_NODE_SET_COLOR(type, name, bp, bs, a, bc); \
  else { \
    REDBLACK_PARENT_POINTER(name, a) = NULL; \
    root = a; \
  } \
} while (0)

#define REDBLACK_DELETE(type, name, root, what_) do { \
  type *what = what_; \
  type *cl = REDBLACK_LEFT_CHILD(name, what); \
  type *cr = REDBLACK_RIGHT_CHILD(name, what); \
  if (cl && cr) { \
    type *s = cl; \
    while (REDBLACK_RIGHT_CHILD(name, s)) s = REDBLACK_RIGHT_CHILD(name, s); \
    REDBLACK_EXCHANGE(type, name, root, s, what); \
    cl = REDBLACK_LEFT_CHILD(name, what); \
    cr = REDBLACK_RIGHT_CHILD(name, what); \
  } \
  type *p = REDBLACK_PARENT(type, name, what); \
  if (REDBLACK_NODE_COLOR(name, what) == REDBLACK_RED) { \
    ASSERT((cl == NULL) && (cl == NULL)); \
    REDBLACK_CHILD(name, p, REDBLACK_PARENT_SIDE(name, p, what)) = NULL; \
    break; \
  } \
  /* The only child now must be red */ \
  int ps = REDBLACK_PARENT_SIDE(name, p, what); \
  if (cl) { \
    REDBLACK_CONNECT_NODE_SET_COLOR(type, name, p, ps, cl, REDBLACK_BLACK); \
    break; \
  } \
  if (cr) { \
    REDBLACK_CONNECT_NODE_SET_COLOR(type, name, p, ps, cr, REDBLACK_BLACK); \
    break; \
  } \
  type *drop = what; \
  while (1) { /* Invariant: what is black */ \
    if (what == root) { /* Case 1 */ \
      root = NULL; \
      break; \
    } \
    type *p = REDBLACK_PARENT(type, name, what); \
    int ws = REDBLACK_PARENT_SIDE(name, p, what); \
    type *s = REDBLACK_CHILD(name, p, REDBLACK_OPPOSITE(ws)); \
    /* Case 2 */ \
    if (s && (REDBLACK_NODE_COLOR(name, s) == REDBLACK_RED)) { /* Therefore p is black also in case 2 */ \
      REDBLACK_ROTATE(type, name, root, p, ws); \
      REDBLACK_SET_COLOR(type, name, p, REDBLACK_RED); \
      REDBLACK_SET_COLOR(type, name, s, REDBLACK_BLACK); \
      continue; \
    } \
    if (drop) drop = REDBLACK_CHILD(name, p, ws) = NULL; \
    type *sc[2] = REDBLACK_CHILDREN(name, s); \
    /* Case 3 & 4: sc[0] and sc[1] are both black; s is black from case 2 */ \
    if ((!sc[0] || REDBLACK_NODE_COLOR(name, sc[0]) == REDBLACK_BLACK) && \
	(!sc[1] || REDBLACK_NODE_COLOR(name, sc[1]) == REDBLACK_BLACK)) { \
      if (REDBLACK_NODE_COLOR(name, p) == REDBLACK_BLACK) { /* Case 3 */ \
	/* No red node nearby, pushing the change up the tree */ \
	REDBLACK_SET_COLOR(type, name, s, REDBLACK_RED); \
	what = p; \
	continue; \
      } else { /* Case 4: p is red */ \
	/* Moving the red down the other tree */ \
	REDBLACK_SET_COLOR(type, name, p, REDBLACK_BLACK); \
	REDBLACK_SET_COLOR(type, name, s, REDBLACK_RED); \
	break; \
      } \
    } \
    /* Now sc[0] or sc[1] must be red (one or both) */ \
    /* Case 5: the niece on the opposite side is black */ \
    int nop = (REDBLACK_OPPOSITE(ws) == REDBLACK_RIGHT); \
    if (!sc[nop] || (REDBLACK_NODE_COLOR(name, sc[nop]) == REDBLACK_BLACK)) { \
      REDBLACK_SET_COLOR(type, name, s, REDBLACK_RED); \
      REDBLACK_SET_COLOR(type, name, sc[1-nop], REDBLACK_BLACK); \
      REDBLACK_ROTATE(type, name, root, s, REDBLACK_OPPOSITE(ws)); \
      s = REDBLACK_CHILD(name, p, REDBLACK_OPPOSITE(ws)); \
      sc[0] = REDBLACK_LEFT_CHILD(name, s); \
      sc[1] = REDBLACK_RIGHT_CHILD(name, s); \
    } \
    /* Case 6: the niece on the opposite side is red */ \
    REDBLACK_ROTATE(type, name, root, p, ws); \
    REDBLACK_SET_COLOR(type, name, s, REDBLACK_NODE_COLOR(name, p)); \
    REDBLACK_SET_COLOR(type, name, p, REDBLACK_BLACK); \
    REDBLACK_SET_COLOR(type, name, sc[nop], REDBLACK_BLACK); \
    break; \
  } \
} while (0) 

#endif
