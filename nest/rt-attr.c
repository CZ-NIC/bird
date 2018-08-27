/*
 *	BIRD -- Route Attribute Cache
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Route attribute cache
 *
 * Each route entry carries a set of route attributes. Several of them
 * vary from route to route, but most attributes are usually common
 * for a large number of routes. To conserve memory, we've decided to
 * store only the varying ones directly in the &rte and hold the rest
 * in a special structure called &rta which is shared among all the
 * &rte's with these attributes.
 *
 * Each &rta contains all the static attributes of the route (i.e.,
 * those which are always present) as structure members and a list of
 * dynamic attributes represented by a linked list of &ea_list
 * structures, each of them consisting of an array of &eattr's containing
 * the individual attributes. An attribute can be specified more than once
 * in the &ea_list chain and in such case the first occurrence overrides
 * the others. This semantics is used especially when someone (for example
 * a filter) wishes to alter values of several dynamic attributes, but
 * it wants to preserve the original attribute lists maintained by
 * another module.
 *
 * Each &eattr contains an attribute identifier (split to protocol ID and
 * per-protocol attribute ID), protocol dependent flags, a type code (consisting
 * of several bit fields describing attribute characteristics) and either an
 * embedded 32-bit value or a pointer to a &adata structure holding attribute
 * contents.
 *
 * There exist two variants of &rta's -- cached and un-cached ones. Un-cached
 * &rta's can have arbitrarily complex structure of &ea_list's and they
 * can be modified by any module in the route processing chain. Cached
 * &rta's have their attribute lists normalized (that means at most one
 * &ea_list is present and its values are sorted in order to speed up
 * searching), they are stored in a hash table to make fast lookup possible
 * and they are provided with a use count to allow sharing.
 *
 * Routing tables always contain only cached &rta's.
 */

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/cli.h"
#include "nest/attrs.h"
#include "lib/alloca.h"
#include "lib/hash.h"
#include "lib/idm.h"
#include "lib/resource.h"
#include "lib/string.h"

#include <stddef.h>

const char * rta_dest_names[RTD_MAX] = {
  [RTD_NONE]		= "",
  [RTD_UNICAST]		= "unicast",
  [RTD_BLACKHOLE]	= "blackhole",
  [RTD_UNREACHABLE]	= "unreachable",
  [RTD_PROHIBIT]	= "prohibited",
};

pool *rta_pool;

static slab *rta_slab_[4];
static slab *nexthop_slab_[4];
static slab *rte_src_slab;

static struct idm src_ids;
#define SRC_ID_INIT_SIZE 4

/* rte source hash */

#define RSH_KEY(n)		n->proto, n->private_id
#define RSH_NEXT(n)		n->next
#define RSH_EQ(p1,n1,p2,n2)	p1 == p2 && n1 == n2
#define RSH_FN(p,n)		p->hash_key ^ u32_hash(n)

#define RSH_REHASH		rte_src_rehash
#define RSH_PARAMS		/2, *2, 1, 1, 8, 20
#define RSH_INIT_ORDER		6

static HASH(struct rte_src) src_hash;

static void
rte_src_init(void)
{
  rte_src_slab = sl_new(rta_pool, sizeof(struct rte_src));

  idm_init(&src_ids, rta_pool, SRC_ID_INIT_SIZE);

  HASH_INIT(src_hash, rta_pool, RSH_INIT_ORDER);
}


HASH_DEFINE_REHASH_FN(RSH, struct rte_src)

struct rte_src *
rt_find_source(struct proto *p, u32 id)
{
  return HASH_FIND(src_hash, RSH, p, id);
}

struct rte_src *
rt_get_source(struct proto *p, u32 id)
{
  struct rte_src *src = rt_find_source(p, id);

  if (src)
    return src;

  src = sl_alloc(rte_src_slab);
  src->proto = p;
  src->private_id = id;
  src->global_id = idm_alloc(&src_ids);
  src->uc = 0;

  HASH_INSERT2(src_hash, RSH, rta_pool, src);

  return src;
}

void
rt_prune_sources(void)
{
  HASH_WALK_FILTER(src_hash, next, src, sp)
  {
    if (src->uc == 0)
    {
      HASH_DO_REMOVE(src_hash, RSH, sp);
      idm_free(&src_ids, src->global_id);
      sl_free(rte_src_slab, src);
    }
  }
  HASH_WALK_FILTER_END;

  HASH_MAY_RESIZE_DOWN(src_hash, RSH, rta_pool);
}


/*
 *	Multipath Next Hop
 */

static inline u32
nexthop_hash(struct nexthop *x)
{
  u32 h = 0;
  for (; x; x = x->next)
  {
    h ^= ipa_hash(x->gw) ^ (h << 5) ^ (h >> 9);

    for (int i = 0; i < x->labels; i++)
      h ^= x->label[i] ^ (h << 6) ^ (h >> 7);
  }

  return h;
}

int
nexthop__same(struct nexthop *x, struct nexthop *y)
{
  for (; x && y; x = x->next, y = y->next)
  {
    if (!ipa_equal(x->gw, y->gw) || (x->iface != y->iface) ||
	(x->flags != y->flags) || (x->weight != y->weight) ||
	(x->labels != y->labels))
      return 0;

    for (int i = 0; i < x->labels; i++)
      if (x->label[i] != y->label[i])
	return 0;
  }

  return x == y;
}

static int
nexthop_compare_node(struct nexthop *x, struct nexthop *y)
{
  int r;

  if (!x)
    return 1;

  if (!y)
    return -1;

  /* Should we also compare flags ? */

  r = ((int) y->weight) - ((int) x->weight);
  if (r)
    return r;

  r = ipa_compare(x->gw, y->gw);
  if (r)
    return r;

  r = ((int) y->labels) - ((int) x->labels);
  if (r)
    return r;

  for (int i = 0; i < y->labels; i++)
  {
    r = ((int) y->label[i]) - ((int) x->label[i]);
    if (r)
      return r;
  }

  return ((int) x->iface->index) - ((int) y->iface->index);
}

static inline struct nexthop *
nexthop_copy_node(const struct nexthop *src, linpool *lp)
{
  struct nexthop *n = lp_alloc(lp, nexthop_size(src));

  memcpy(n, src, nexthop_size(src));
  n->next = NULL;

  return n;
}

/**
 * nexthop_merge - merge nexthop lists
 * @x: list 1
 * @y: list 2
 * @rx: reusability of list @x
 * @ry: reusability of list @y
 * @max: max number of nexthops
 * @lp: linpool for allocating nexthops
 *
 * The nexthop_merge() function takes two nexthop lists @x and @y and merges them,
 * eliminating possible duplicates. The input lists must be sorted and the
 * result is sorted too. The number of nexthops in result is limited by @max.
 * New nodes are allocated from linpool @lp.
 *
 * The arguments @rx and @ry specify whether corresponding input lists may be
 * consumed by the function (i.e. their nodes reused in the resulting list), in
 * that case the caller should not access these lists after that. To eliminate
 * issues with deallocation of these lists, the caller should use some form of
 * bulk deallocation (e.g. stack or linpool) to free these nodes when the
 * resulting list is no longer needed. When reusability is not set, the
 * corresponding lists are not modified nor linked from the resulting list.
 */
struct nexthop *
nexthop_merge(struct nexthop *x, struct nexthop *y, int rx, int ry, int max, linpool *lp)
{
  struct nexthop *root = NULL;
  struct nexthop **n = &root;

  while ((x || y) && max--)
  {
    int cmp = nexthop_compare_node(x, y);
    if (cmp < 0)
    {
      *n = rx ? x : nexthop_copy_node(x, lp);
      x = x->next;
    }
    else if (cmp > 0)
    {
      *n = ry ? y : nexthop_copy_node(y, lp);
      y = y->next;
    }
    else
    {
      *n = rx ? x : (ry ? y : nexthop_copy_node(x, lp));
      x = x->next;
      y = y->next;
    }
    n = &((*n)->next);
  }
  *n = NULL;

  return root;
}

void
nexthop_insert(struct nexthop **n, struct nexthop *x)
{
  for (; *n; n = &((*n)->next))
  {
    int cmp = nexthop_compare_node(*n, x);

    if (cmp < 0)
      continue;
    else if (cmp > 0)
      break;
    else
      return;
  }

  x->next = *n;
  *n = x;
}

int
nexthop_is_sorted(struct nexthop *x)
{
  for (; x && x->next; x = x->next)
    if (nexthop_compare_node(x, x->next) >= 0)
      return 0;

  return 1;
}

static inline slab *
nexthop_slab(struct nexthop *nh)
{
  return nexthop_slab_[MIN(nh->labels, 3)];
}

static struct nexthop *
nexthop_copy(struct nexthop *o)
{
  struct nexthop *first = NULL;
  struct nexthop **last = &first;

  for (; o; o = o->next)
    {
      struct nexthop *n = sl_alloc(nexthop_slab(o));
      n->gw = o->gw;
      n->iface = o->iface;
      n->next = NULL;
      n->weight = o->weight;
      n->labels = o->labels;
      for (int i=0; i<o->labels; i++)
	n->label[i] = o->label[i];

      *last = n;
      last = &(n->next);
    }

  return first;
}

static void
nexthop_free(struct nexthop *o)
{
  struct nexthop *n;

  while (o)
    {
      n = o->next;
      sl_free(nexthop_slab(o), o);
      o = n;
    }
}


/*
 *	Extended Attributes
 */

static inline eattr *
ea__find(ea_list *e, unsigned id)
{
  eattr *a;
  int l, r, m;

  while (e)
    {
      if (e->flags & EALF_BISECT)
	{
	  l = 0;
	  r = e->count - 1;
	  while (l <= r)
	    {
	      m = (l+r) / 2;
	      a = &e->attrs[m];
	      if (a->id == id)
		return a;
	      else if (a->id < id)
		l = m+1;
	      else
		r = m-1;
	    }
	}
      else
	for(m=0; m<e->count; m++)
	  if (e->attrs[m].id == id)
	    return &e->attrs[m];
      e = e->next;
    }
  return NULL;
}

/**
 * ea_find - find an extended attribute
 * @e: attribute list to search in
 * @id: attribute ID to search for
 *
 * Given an extended attribute list, ea_find() searches for a first
 * occurrence of an attribute with specified ID, returning either a pointer
 * to its &eattr structure or %NULL if no such attribute exists.
 */
eattr *
ea_find(ea_list *e, unsigned id)
{
  eattr *a = ea__find(e, id & EA_CODE_MASK);

  if (a && (a->type & EAF_TYPE_MASK) == EAF_TYPE_UNDEF &&
      !(id & EA_ALLOW_UNDEF))
    return NULL;
  return a;
}

/**
 * ea_walk - walk through extended attributes
 * @s: walk state structure
 * @id: start of attribute ID interval
 * @max: length of attribute ID interval
 *
 * Given an extended attribute list, ea_walk() walks through the list looking
 * for first occurrences of attributes with ID in specified interval from @id to
 * (@id + @max - 1), returning pointers to found &eattr structures, storing its
 * walk state in @s for subsequent calls.
 *
 * The function ea_walk() is supposed to be called in a loop, with initially
 * zeroed walk state structure @s with filled the initial extended attribute
 * list, returning one found attribute in each call or %NULL when no other
 * attribute exists. The extended attribute list or the arguments should not be
 * modified between calls. The maximum value of @max is 128.
 */
eattr *
ea_walk(struct ea_walk_state *s, uint id, uint max)
{
  ea_list *e = s->eattrs;
  eattr *a = s->ea;
  eattr *a_max;

  max = id + max;

  if (a)
    goto step;

  for (; e; e = e->next)
  {
    if (e->flags & EALF_BISECT)
    {
      int l, r, m;

      l = 0;
      r = e->count - 1;
      while (l < r)
      {
	m = (l+r) / 2;
	if (e->attrs[m].id < id)
	  l = m + 1;
	else
	  r = m;
      }
      a = e->attrs + l;
    }
    else
      a = e->attrs;

  step:
    a_max = e->attrs + e->count;
    for (; a < a_max; a++)
      if ((a->id >= id) && (a->id < max))
      {
	int n = a->id - id;

	if (BIT32_TEST(s->visited, n))
	  continue;

	BIT32_SET(s->visited, n);

	if ((a->type & EAF_TYPE_MASK) == EAF_TYPE_UNDEF)
	  continue;

	s->eattrs = e;
	s->ea = a;
	return a;
      }
      else if (e->flags & EALF_BISECT)
	break;
  }

  return NULL;
}

/**
 * ea_get_int - fetch an integer attribute
 * @e: attribute list
 * @id: attribute ID
 * @def: default value
 *
 * This function is a shortcut for retrieving a value of an integer attribute
 * by calling ea_find() to find the attribute, extracting its value or returning
 * a provided default if no such attribute is present.
 */
int
ea_get_int(ea_list *e, unsigned id, int def)
{
  eattr *a = ea_find(e, id);
  if (!a)
    return def;
  return a->u.data;
}

static inline void
ea_do_sort(ea_list *e)
{
  unsigned n = e->count;
  eattr *a = e->attrs;
  eattr *b = alloca(n * sizeof(eattr));
  unsigned s, ss;

  /* We need to use a stable sorting algorithm, hence mergesort */
  do
    {
      s = ss = 0;
      while (s < n)
	{
	  eattr *p, *q, *lo, *hi;
	  p = b;
	  ss = s;
	  *p++ = a[s++];
	  while (s < n && p[-1].id <= a[s].id)
	    *p++ = a[s++];
	  if (s < n)
	    {
	      q = p;
	      *p++ = a[s++];
	      while (s < n && p[-1].id <= a[s].id)
		*p++ = a[s++];
	      lo = b;
	      hi = q;
	      s = ss;
	      while (lo < q && hi < p)
		if (lo->id <= hi->id)
		  a[s++] = *lo++;
		else
		  a[s++] = *hi++;
	      while (lo < q)
		a[s++] = *lo++;
	      while (hi < p)
		a[s++] = *hi++;
	    }
	}
    }
  while (ss);
}

/**
 * In place discard duplicates, undefs and temporary attributes in sorted
 * ea_list. We use stable sort for this reason.
 **/
static inline void
ea_do_prune(ea_list *e)
{
  eattr *s, *d, *l, *s0;
  int i = 0;

  s = d = e->attrs;	    /* Beginning of the list. @s is source, @d is destination. */
  l = e->attrs + e->count;  /* End of the list */

  /* Walk from begin to end. */
  while (s < l)
    {
      s0 = s++;
      /* Find a consecutive block of the same attribute */
      while (s < l && s->id == s[-1].id)
	s++;

      /* Now s0 is the most recent version, s[-1] the oldest one */
      /* Drop undefs */
      if ((s0->type & EAF_TYPE_MASK) == EAF_TYPE_UNDEF)
	continue;

      /* Drop temporary attributes */
      if (s0->type & EAF_TEMP)
	continue;

      /* Copy the newest version to destination */
      *d = *s0;

      /* Preserve info whether it originated locally */
      d->type = (d->type & ~(EAF_ORIGINATED|EAF_FRESH)) | (s[-1].type & EAF_ORIGINATED);

      /* Next destination */
      d++;
      i++;
    }

  e->count = i;
}

/**
 * ea_sort - sort an attribute list
 * @e: list to be sorted
 *
 * This function takes a &ea_list chain and sorts the attributes
 * within each of its entries.
 *
 * If an attribute occurs multiple times in a single &ea_list,
 * ea_sort() leaves only the first (the only significant) occurrence.
 */
void
ea_sort(ea_list *e)
{
  while (e)
    {
      if (!(e->flags & EALF_SORTED))
	{
	  ea_do_sort(e);
	  ea_do_prune(e);
	  e->flags |= EALF_SORTED;
	}
      if (e->count > 5)
	e->flags |= EALF_BISECT;
      e = e->next;
    }
}

/**
 * ea_scan - estimate attribute list size
 * @e: attribute list
 *
 * This function calculates an upper bound of the size of
 * a given &ea_list after merging with ea_merge().
 */
unsigned
ea_scan(ea_list *e)
{
  unsigned cnt = 0;

  while (e)
    {
      cnt += e->count;
      e = e->next;
    }
  return sizeof(ea_list) + sizeof(eattr)*cnt;
}

/**
 * ea_merge - merge segments of an attribute list
 * @e: attribute list
 * @t: buffer to store the result to
 *
 * This function takes a possibly multi-segment attribute list
 * and merges all of its segments to one.
 *
 * The primary use of this function is for &ea_list normalization:
 * first call ea_scan() to determine how much memory will the result
 * take, then allocate a buffer (usually using alloca()), merge the
 * segments with ea_merge() and finally sort and prune the result
 * by calling ea_sort().
 */
void
ea_merge(ea_list *e, ea_list *t)
{
  eattr *d = t->attrs;

  t->flags = 0;
  t->count = 0;
  t->next = NULL;
  while (e)
    {
      memcpy(d, e->attrs, sizeof(eattr)*e->count);
      t->count += e->count;
      d += e->count;
      e = e->next;
    }
}

/**
 * ea_same - compare two &ea_list's
 * @x: attribute list
 * @y: attribute list
 *
 * ea_same() compares two normalized attribute lists @x and @y and returns
 * 1 if they contain the same attributes, 0 otherwise.
 */
int
ea_same(ea_list *x, ea_list *y)
{
  int c;

  if (!x || !y)
    return x == y;
  ASSERT(!x->next && !y->next);
  if (x->count != y->count)
    return 0;
  for(c=0; c<x->count; c++)
    {
      eattr *a = &x->attrs[c];
      eattr *b = &y->attrs[c];

      if (a->id != b->id ||
	  a->flags != b->flags ||
	  a->type != b->type ||
	  ((a->type & EAF_EMBEDDED) ? a->u.data != b->u.data : !adata_same(a->u.ptr, b->u.ptr)))
	return 0;
    }
  return 1;
}

static inline ea_list *
ea_list_copy(ea_list *o)
{
  ea_list *n;
  unsigned i, len;

  if (!o)
    return NULL;
  ASSERT(!o->next);
  len = sizeof(ea_list) + sizeof(eattr) * o->count;
  n = mb_alloc(rta_pool, len);
  memcpy(n, o, len);
  n->flags |= EALF_CACHED;
  for(i=0; i<o->count; i++)
    {
      eattr *a = &n->attrs[i];
      if (!(a->type & EAF_EMBEDDED))
	{
	  unsigned size = sizeof(struct adata) + a->u.ptr->length;
	  struct adata *d = mb_alloc(rta_pool, size);
	  memcpy(d, a->u.ptr, size);
	  a->u.ptr = d;
	}
    }
  return n;
}

static inline void
ea_free(ea_list *o)
{
  int i;

  if (o)
    {
      ASSERT(!o->next);
      for(i=0; i<o->count; i++)
	{
	  eattr *a = &o->attrs[i];
	  if (!(a->type & EAF_EMBEDDED))
	    mb_free(a->u.ptr);
	}
      mb_free(o);
    }
}

static int
get_generic_attr(eattr *a, byte **buf, int buflen UNUSED)
{
  if (a->id == EA_GEN_IGP_METRIC)
    {
      *buf += bsprintf(*buf, "igp_metric");
      return GA_NAME;
    }

  return GA_UNKNOWN;
}

void
ea_format_bitfield(struct eattr *a, byte *buf, int bufsize, const char **names, int min, int max)
{
  byte *bound = buf + bufsize - 32;
  u32 data = a->u.data;
  int i;

  for (i = min; i < max; i++)
    if ((data & (1u << i)) && names[i])
    {
      if (buf > bound)
      {
	strcpy(buf, " ...");
	return;
      }

      buf += bsprintf(buf, " %s", names[i]);
      data &= ~(1u << i);
    }

  if (data)
    bsprintf(buf, " %08x", data);

  return;
}

static inline void
opaque_format(struct adata *ad, byte *buf, uint size)
{
  byte *bound = buf + size - 10;
  uint i;

  for(i = 0; i < ad->length; i++)
    {
      if (buf > bound)
	{
	  strcpy(buf, " ...");
	  return;
	}
      if (i)
	*buf++ = ' ';

      buf += bsprintf(buf, "%02x", ad->data[i]);
    }

  *buf = 0;
  return;
}

static inline void
ea_show_int_set(struct cli *c, struct adata *ad, int way, byte *pos, byte *buf, byte *end)
{
  int i = int_set_format(ad, way, 0, pos, end - pos);
  cli_printf(c, -1012, "\t%s", buf);
  while (i)
    {
      i = int_set_format(ad, way, i, buf, end - buf - 1);
      cli_printf(c, -1012, "\t\t%s", buf);
    }
}

static inline void
ea_show_ec_set(struct cli *c, struct adata *ad, byte *pos, byte *buf, byte *end)
{
  int i = ec_set_format(ad, 0, pos, end - pos);
  cli_printf(c, -1012, "\t%s", buf);
  while (i)
    {
      i = ec_set_format(ad, i, buf, end - buf - 1);
      cli_printf(c, -1012, "\t\t%s", buf);
    }
}

static inline void
ea_show_lc_set(struct cli *c, struct adata *ad, byte *pos, byte *buf, byte *end)
{
  int i = lc_set_format(ad, 0, pos, end - pos);
  cli_printf(c, -1012, "\t%s", buf);
  while (i)
    {
      i = lc_set_format(ad, i, buf, end - buf - 1);
      cli_printf(c, -1012, "\t\t%s", buf);
    }
}

/**
 * ea_show - print an &eattr to CLI
 * @c: destination CLI
 * @e: attribute to be printed
 *
 * This function takes an extended attribute represented by its &eattr
 * structure and prints it to the CLI according to the type information.
 *
 * If the protocol defining the attribute provides its own
 * get_attr() hook, it's consulted first.
 */
void
ea_show(struct cli *c, eattr *e)
{
  struct protocol *p;
  int status = GA_UNKNOWN;
  struct adata *ad = (e->type & EAF_EMBEDDED) ? NULL : e->u.ptr;
  byte buf[CLI_MSG_SIZE];
  byte *pos = buf, *end = buf + sizeof(buf);

  if (p = class_to_protocol[EA_PROTO(e->id)])
    {
      pos += bsprintf(pos, "%s.", p->name);
      if (p->get_attr)
	status = p->get_attr(e, pos, end - pos);
      pos += strlen(pos);
    }
  else if (EA_PROTO(e->id))
    pos += bsprintf(pos, "%02x.", EA_PROTO(e->id));
  else
    status = get_generic_attr(e, &pos, end - pos);

  if (status < GA_NAME)
    pos += bsprintf(pos, "%02x", EA_ID(e->id));
  if (status < GA_FULL)
    {
      *pos++ = ':';
      *pos++ = ' ';
      switch (e->type & EAF_TYPE_MASK)
	{
	case EAF_TYPE_INT:
	  bsprintf(pos, "%u", e->u.data);
	  break;
	case EAF_TYPE_OPAQUE:
	  opaque_format(ad, pos, end - pos);
	  break;
	case EAF_TYPE_IP_ADDRESS:
	  bsprintf(pos, "%I", *(ip_addr *) ad->data);
	  break;
	case EAF_TYPE_ROUTER_ID:
	  bsprintf(pos, "%R", e->u.data);
	  break;
	case EAF_TYPE_AS_PATH:
	  as_path_format(ad, pos, end - pos);
	  break;
	case EAF_TYPE_BITFIELD:
	  bsprintf(pos, "%08x", e->u.data);
	  break;
	case EAF_TYPE_INT_SET:
	  ea_show_int_set(c, ad, 1, pos, buf, end);
	  return;
	case EAF_TYPE_EC_SET:
	  ea_show_ec_set(c, ad, pos, buf, end);
	  return;
	case EAF_TYPE_LC_SET:
	  ea_show_lc_set(c, ad, pos, buf, end);
	  return;
	case EAF_TYPE_UNDEF:
	default:
	  bsprintf(pos, "<type %02x>", e->type);
	}
    }
  cli_printf(c, -1012, "\t%s", buf);
}

/**
 * ea_dump - dump an extended attribute
 * @e: attribute to be dumped
 *
 * ea_dump() dumps contents of the extended attribute given to
 * the debug output.
 */
void
ea_dump(ea_list *e)
{
  int i;

  if (!e)
    {
      debug("NONE");
      return;
    }
  while (e)
    {
      debug("[%c%c%c]",
	    (e->flags & EALF_SORTED) ? 'S' : 's',
	    (e->flags & EALF_BISECT) ? 'B' : 'b',
	    (e->flags & EALF_CACHED) ? 'C' : 'c');
      for(i=0; i<e->count; i++)
	{
	  eattr *a = &e->attrs[i];
	  debug(" %02x:%02x.%02x", EA_PROTO(a->id), EA_ID(a->id), a->flags);
	  if (a->type & EAF_TEMP)
	    debug("T");
	  debug("=%c", "?iO?I?P???S?????" [a->type & EAF_TYPE_MASK]);
	  if (a->type & EAF_ORIGINATED)
	    debug("o");
	  if (a->type & EAF_EMBEDDED)
	    debug(":%08x", a->u.data);
	  else
	    {
	      int j, len = a->u.ptr->length;
	      debug("[%d]:", len);
	      for(j=0; j<len; j++)
		debug("%02x", a->u.ptr->data[j]);
	    }
	}
      if (e = e->next)
	debug(" | ");
    }
}

/**
 * ea_hash - calculate an &ea_list hash key
 * @e: attribute list
 *
 * ea_hash() takes an extended attribute list and calculated a hopefully
 * uniformly distributed hash value from its contents.
 */
inline uint
ea_hash(ea_list *e)
{
  const u64 mul = 0x68576150f3d6847;
  u64 h = 0xafcef24eda8b29;
  int i;

  if (e)			/* Assuming chain of length 1 */
    {
      for(i=0; i<e->count; i++)
	{
	  struct eattr *a = &e->attrs[i];
	  h ^= a->id; h *= mul;
	  if (a->type & EAF_EMBEDDED)
	    h ^= a->u.data;
	  else
	    {
	      struct adata *d = a->u.ptr;
	      h ^= mem_hash(d->data, d->length);
	    }
	  h *= mul;
	}
    }
  return (h >> 32) ^ (h & 0xffffffff);
}

/**
 * ea_append - concatenate &ea_list's
 * @to: destination list (can be %NULL)
 * @what: list to be appended (can be %NULL)
 *
 * This function appends the &ea_list @what at the end of
 * &ea_list @to and returns a pointer to the resulting list.
 */
ea_list *
ea_append(ea_list *to, ea_list *what)
{
  ea_list *res;

  if (!to)
    return what;
  res = to;
  while (to->next)
    to = to->next;
  to->next = what;
  return res;
}

/*
 *	rta's
 */

static uint rta_cache_count;
static uint rta_cache_size = 32;
static uint rta_cache_limit;
static uint rta_cache_mask;
static rta **rta_hash_table;

static void
rta_alloc_hash(void)
{
  rta_hash_table = mb_allocz(rta_pool, sizeof(rta *) * rta_cache_size);
  if (rta_cache_size < 32768)
    rta_cache_limit = rta_cache_size * 2;
  else
    rta_cache_limit = ~0;
  rta_cache_mask = rta_cache_size - 1;
}

static inline uint
rta_hash(rta *a)
{
  u64 h;
  mem_hash_init(&h);
#define MIX(f) mem_hash_mix(&h, &(a->f), sizeof(a->f));
  MIX(src);
  MIX(hostentry);
  MIX(from);
  MIX(igp_metric);
  MIX(source);
  MIX(scope);
  MIX(dest);
#undef MIX

  return mem_hash_value(&h) ^ nexthop_hash(&(a->nh)) ^ ea_hash(a->eattrs);
}

static inline int
rta_same(rta *x, rta *y)
{
  return (x->src == y->src &&
	  x->source == y->source &&
	  x->scope == y->scope &&
	  x->dest == y->dest &&
	  x->igp_metric == y->igp_metric &&
	  ipa_equal(x->from, y->from) &&
	  x->hostentry == y->hostentry &&
	  nexthop_same(&(x->nh), &(y->nh)) &&
	  ea_same(x->eattrs, y->eattrs));
}

static inline slab *
rta_slab(rta *a)
{
  return rta_slab_[a->nh.labels > 2 ? 3 : a->nh.labels];
}

static rta *
rta_copy(rta *o)
{
  rta *r = sl_alloc(rta_slab(o));

  memcpy(r, o, rta_size(o));
  r->uc = 1;
  r->nh.next = nexthop_copy(o->nh.next);
  r->eattrs = ea_list_copy(o->eattrs);
  return r;
}

static inline void
rta_insert(rta *r)
{
  uint h = r->hash_key & rta_cache_mask;
  r->next = rta_hash_table[h];
  if (r->next)
    r->next->pprev = &r->next;
  r->pprev = &rta_hash_table[h];
  rta_hash_table[h] = r;
}

static void
rta_rehash(void)
{
  uint ohs = rta_cache_size;
  uint h;
  rta *r, *n;
  rta **oht = rta_hash_table;

  rta_cache_size = 2*rta_cache_size;
  DBG("Rehashing rta cache from %d to %d entries.\n", ohs, rta_cache_size);
  rta_alloc_hash();
  for(h=0; h<ohs; h++)
    for(r=oht[h]; r; r=n)
      {
	n = r->next;
	rta_insert(r);
      }
  mb_free(oht);
}

/**
 * rta_lookup - look up a &rta in attribute cache
 * @o: a un-cached &rta
 *
 * rta_lookup() gets an un-cached &rta structure and returns its cached
 * counterpart. It starts with examining the attribute cache to see whether
 * there exists a matching entry. If such an entry exists, it's returned and
 * its use count is incremented, else a new entry is created with use count
 * set to 1.
 *
 * The extended attribute lists attached to the &rta are automatically
 * converted to the normalized form.
 */
rta *
rta_lookup(rta *o)
{
  rta *r;
  uint h;

  ASSERT(!(o->aflags & RTAF_CACHED));
  if (o->eattrs)
    ea_normalize(o->eattrs);

  h = rta_hash(o);
  for(r=rta_hash_table[h & rta_cache_mask]; r; r=r->next)
    if (r->hash_key == h && rta_same(r, o))
      return rta_clone(r);

  r = rta_copy(o);
  r->hash_key = h;
  r->aflags = RTAF_CACHED;
  rt_lock_source(r->src);
  rt_lock_hostentry(r->hostentry);
  rta_insert(r);

  if (++rta_cache_count > rta_cache_limit)
    rta_rehash();

  return r;
}

void
rta__free(rta *a)
{
  ASSERT(rta_cache_count && (a->aflags & RTAF_CACHED));
  rta_cache_count--;
  *a->pprev = a->next;
  if (a->next)
    a->next->pprev = a->pprev;
  rt_unlock_hostentry(a->hostentry);
  rt_unlock_source(a->src);
  if (a->nh.next)
    nexthop_free(a->nh.next);
  ea_free(a->eattrs);
  a->aflags = 0;		/* Poison the entry */
  sl_free(rta_slab(a), a);
}

rta *
rta_do_cow(rta *o, linpool *lp)
{
  rta *r = lp_alloc(lp, rta_size(o));
  memcpy(r, o, rta_size(o));
  for (struct nexthop **nhn = &(r->nh.next), *nho = o->nh.next; nho; nho = nho->next)
    {
      *nhn = lp_alloc(lp, nexthop_size(nho));
      memcpy(*nhn, nho, nexthop_size(nho));
      nhn = &((*nhn)->next);
    }
  r->aflags = 0;
  r->uc = 0;
  return r;
}

/**
 * rta_dump - dump route attributes
 * @a: attribute structure to dump
 *
 * This function takes a &rta and dumps its contents to the debug output.
 */
void
rta_dump(rta *a)
{
  static char *rts[] = { "RTS_DUMMY", "RTS_STATIC", "RTS_INHERIT", "RTS_DEVICE",
			 "RTS_STAT_DEV", "RTS_REDIR", "RTS_RIP",
			 "RTS_OSPF", "RTS_OSPF_IA", "RTS_OSPF_EXT1",
			 "RTS_OSPF_EXT2", "RTS_BGP", "RTS_PIPE", "RTS_BABEL" };
  static char *rtd[] = { "", " DEV", " HOLE", " UNREACH", " PROHIBIT" };

  debug("p=%s uc=%d %s %s%s h=%04x",
	a->src->proto->name, a->uc, rts[a->source], ip_scope_text(a->scope),
	rtd[a->dest], a->hash_key);
  if (!(a->aflags & RTAF_CACHED))
    debug(" !CACHED");
  debug(" <-%I", a->from);
  if (a->dest == RTD_UNICAST)
    for (struct nexthop *nh = &(a->nh); nh; nh = nh->next)
      {
	if (ipa_nonzero(nh->gw)) debug(" ->%I", nh->gw);
	if (nh->labels) debug(" L %d", nh->label[0]);
	for (int i=1; i<nh->labels; i++)
	  debug("/%d", nh->label[i]);
	debug(" [%s]", nh->iface ? nh->iface->name : "???");
      }
  if (a->eattrs)
    {
      debug(" EA: ");
      ea_dump(a->eattrs);
    }
}

/**
 * rta_dump_all - dump attribute cache
 *
 * This function dumps the whole contents of route attribute cache
 * to the debug output.
 */
void
rta_dump_all(void)
{
  rta *a;
  uint h;

  debug("Route attribute cache (%d entries, rehash at %d):\n", rta_cache_count, rta_cache_limit);
  for(h=0; h<rta_cache_size; h++)
    for(a=rta_hash_table[h]; a; a=a->next)
      {
	debug("%p ", a);
	rta_dump(a);
	debug("\n");
      }
  debug("\n");
}

void
rta_show(struct cli *c, rta *a)
{
  static char *src_names[] = { "dummy", "static", "inherit", "device", "static-device", "redirect",
			       "RIP", "OSPF", "OSPF-IA", "OSPF-E1", "OSPF-E2", "BGP", "pipe" };

  cli_printf(c, -1008, "\tType: %s %s", src_names[a->source], ip_scope_text(a->scope));

  for(ea_list *eal = a->eattrs; eal; eal=eal->next)
    for(int i=0; i<eal->count; i++)
      ea_show(c, &eal->attrs[i]);
}

/**
 * rta_init - initialize route attribute cache
 *
 * This function is called during initialization of the routing
 * table module to set up the internals of the attribute cache.
 */
void
rta_init(void)
{
  rta_pool = rp_new(&root_pool, "Attributes");

  rta_slab_[0] = sl_new(rta_pool, sizeof(rta));
  rta_slab_[1] = sl_new(rta_pool, sizeof(rta) + sizeof(u32));
  rta_slab_[2] = sl_new(rta_pool, sizeof(rta) + sizeof(u32)*2);
  rta_slab_[3] = sl_new(rta_pool, sizeof(rta) + sizeof(u32)*MPLS_MAX_LABEL_STACK);

  nexthop_slab_[0] = sl_new(rta_pool, sizeof(struct nexthop));
  nexthop_slab_[1] = sl_new(rta_pool, sizeof(struct nexthop) + sizeof(u32));
  nexthop_slab_[2] = sl_new(rta_pool, sizeof(struct nexthop) + sizeof(u32)*2);
  nexthop_slab_[3] = sl_new(rta_pool, sizeof(struct nexthop) + sizeof(u32)*MPLS_MAX_LABEL_STACK);

  rta_alloc_hash();
  rte_src_init();
}

/*
 *  Documentation for functions declared inline in route.h
 */
#if 0

/**
 * rta_clone - clone route attributes
 * @r: a &rta to be cloned
 *
 * rta_clone() takes a cached &rta and returns its identical cached
 * copy. Currently it works by just returning the original &rta with
 * its use count incremented.
 */
static inline rta *rta_clone(rta *r)
{ DUMMY; }

/**
 * rta_free - free route attributes
 * @r: a &rta to be freed
 *
 * If you stop using a &rta (for example when deleting a route which uses
 * it), you need to call rta_free() to notify the attribute cache the
 * attribute is no longer in use and can be freed if you were the last
 * user (which rta_free() tests by inspecting the use count).
 */
static inline void rta_free(rta *r)
{ DUMMY; }

#endif
