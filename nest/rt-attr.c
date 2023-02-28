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
#include "nest/rt.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/cli.h"
#include "lib/attrs.h"
#include "lib/alloca.h"
#include "lib/hash.h"
#include "lib/idm.h"
#include "lib/resource.h"
#include "lib/string.h"

#include <stddef.h>
#include <stdlib.h>

const adata null_adata;		/* adata of length 0 */

struct ea_class ea_gen_igp_metric = {
  .name = "igp_metric",
  .type = T_INT,
};

struct ea_class ea_gen_preference = {
  .name = "preference",
  .type = T_INT,
};

struct ea_class ea_gen_from = {
  .name = "from",
  .type = T_IP,
};

const char * const rta_src_names[RTS_MAX] = {
  [RTS_STATIC]		= "static",
  [RTS_INHERIT]		= "inherit",
  [RTS_DEVICE]		= "device",
  [RTS_STATIC_DEVICE]	= "static-device",
  [RTS_REDIRECT]	= "redirect",
  [RTS_RIP]		= "RIP",
  [RTS_OSPF]		= "OSPF",
  [RTS_OSPF_IA]		= "OSPF-IA",
  [RTS_OSPF_EXT1]	= "OSPF-E1",
  [RTS_OSPF_EXT2]	= "OSPF-E2",
  [RTS_BGP]		= "BGP",
  [RTS_PIPE]		= "pipe",
  [RTS_BABEL]		= "Babel",
  [RTS_RPKI]		= "RPKI",
};

static void
ea_gen_source_format(const eattr *a, byte *buf, uint size)
{
  if ((a->u.data >= RTS_MAX) || !rta_src_names[a->u.data])
    bsnprintf(buf, size, "unknown");
  else
    bsnprintf(buf, size, "%s", rta_src_names[a->u.data]);
}

struct ea_class ea_gen_source = {
  .name = "source",
  .type = T_ENUM_RTS,
  .readonly = 1,
  .format = ea_gen_source_format,
};

struct ea_class ea_gen_nexthop = {
  .name = "nexthop",
  .type = T_NEXTHOP_LIST,
};

/*
 * ea_set_hostentry() acquires hostentry from hostcache.
 * New hostentry has zero use count. Cached rta locks its
 * hostentry (increases its use count), uncached rta does not lock it.
 * Hostentry with zero use count is removed asynchronously
 * during host cache update, therefore it is safe to hold
 * such hostentry temporarily as long as you hold the table lock.
 *
 * There is no need to hold a lock for hostentry->dep table, because that table
 * contains routes responsible for that hostentry, and therefore is non-empty if
 * given hostentry has non-zero use count. If the hostentry has zero use count,
 * the entry is removed before dep is referenced.
 *
 * The protocol responsible for routes with recursive next hops should hold a
 * lock for a 'source' table governing that routes (argument tab),
 * because its routes reference hostentries related to the governing table.
 * When all such routes are
 * removed, rtas are immediately removed achieving zero uc. Then the 'source'
 * table lock could be immediately released, although hostentries may still
 * exist - they will be freed together with the 'source' table.
 */

  static void
ea_gen_hostentry_stored(const eattr *ea)
{
  struct hostentry_adata *had = (struct hostentry_adata *) ea->u.ptr;
  had->he->uc++;
}

static void
ea_gen_hostentry_freed(const eattr *ea)
{
  struct hostentry_adata *had = (struct hostentry_adata *) ea->u.ptr;
  had->he->uc--;
}

struct ea_class ea_gen_hostentry = {
  .name = "hostentry",
  .type = T_HOSTENTRY,
  .readonly = 1,
  .stored = ea_gen_hostentry_stored,
  .freed = ea_gen_hostentry_freed,
};

const char * rta_dest_names[RTD_MAX] = {
  [RTD_NONE]		= "",
  [RTD_UNICAST]		= "unicast",
  [RTD_BLACKHOLE]	= "blackhole",
  [RTD_UNREACHABLE]	= "unreachable",
  [RTD_PROHIBIT]	= "prohibited",
};

struct ea_class ea_gen_flowspec_valid = {
  .name = "flowspec_valid",
  .type = T_ENUM_FLOWSPEC_VALID,
  .readonly = 1,
};

const char * flowspec_valid_names[FLOWSPEC__MAX] = {
  [FLOWSPEC_UNKNOWN]	= "unknown",
  [FLOWSPEC_VALID]	= "",
  [FLOWSPEC_INVALID]	= "invalid",
};

DOMAIN(attrs) attrs_domain;

pool *rta_pool;

/* Assuming page size of 4096, these are magic values for slab allocation */
static const uint ea_slab_sizes[] = { 56, 112, 168, 288, 448, 800, 1344 };
static slab *ea_slab[ARRAY_SIZE(ea_slab_sizes)];

static slab *rte_src_slab;

static struct idm src_ids;
#define SRC_ID_INIT_SIZE 4

/* rte source hash */

#define RSH_KEY(n)		n->private_id
#define RSH_NEXT(n)		n->next
#define RSH_EQ(n1,n2)		n1 == n2
#define RSH_FN(n)		u32_hash(n)

#define RSH_REHASH		rte_src_rehash
#define RSH_PARAMS		/2, *2, 1, 1, 8, 20
#define RSH_INIT_ORDER		2
static struct rte_src **rte_src_global;
static uint rte_src_global_max = SRC_ID_INIT_SIZE;

static void
rte_src_init(void)
{
  rte_src_slab = sl_new(rta_pool, sizeof(struct rte_src));
  rte_src_global = mb_allocz(rta_pool, sizeof(struct rte_src *) * rte_src_global_max);

  idm_init(&src_ids, rta_pool, SRC_ID_INIT_SIZE);
}

HASH_DEFINE_REHASH_FN(RSH, struct rte_src)

static struct rte_src *
rt_find_source(struct rte_owner *p, u32 id)
{
  return HASH_FIND(p->hash, RSH, id);
}

struct rte_src *
rt_get_source_o(struct rte_owner *p, u32 id)
{
  if (p->stop)
    bug("Stopping route owner asked for another source.");

  struct rte_src *src = rt_find_source(p, id);

  if (src)
  {
    UNUSED u64 uc = atomic_fetch_add_explicit(&src->uc, 1, memory_order_acq_rel);
    return src;
  }

  RTA_LOCK;
  src = sl_allocz(rte_src_slab);
  src->owner = p;
  src->private_id = id;
  src->global_id = idm_alloc(&src_ids);

  atomic_store_explicit(&src->uc, 1, memory_order_release);
  p->uc++;

  HASH_INSERT2(p->hash, RSH, rta_pool, src);
  if (config->table_debug)
    log(L_TRACE "Allocated new rte_src for %s, ID %uL %uG, have %u sources now",
	p->name, src->private_id, src->global_id, p->uc);

  if (src->global_id >= rte_src_global_max)
  {
    rte_src_global = mb_realloc(rte_src_global, sizeof(struct rte_src *) * (rte_src_global_max *= 2));
    memset(&rte_src_global[rte_src_global_max / 2], 0,
	sizeof(struct rte_src *) * (rte_src_global_max / 2));
  }

  rte_src_global[src->global_id] = src;
  RTA_UNLOCK;

  return src;
}

struct rte_src *
rt_find_source_global(u32 id)
{
  if (id >= rte_src_global_max)
    return NULL;
  else
    return rte_src_global[id];
}

static inline void
rt_done_sources(struct rte_owner *o)
{
  ev_send(o->list, o->stop);
}

void
rt_prune_sources(void *data)
{
  struct rte_owner *o = data;

  HASH_WALK_FILTER(o->hash, next, src, sp)
  {
    u64 uc;
    while ((uc = atomic_load_explicit(&src->uc, memory_order_acquire)) >> RTE_SRC_PU_SHIFT)
      synchronize_rcu();

    if (uc == 0)
    {
      o->uc--;

      HASH_DO_REMOVE(o->hash, RSH, sp);

      RTA_LOCK;
      rte_src_global[src->global_id] = NULL;
      idm_free(&src_ids, src->global_id);
      sl_free(src);
      RTA_UNLOCK;
    }
  }
  HASH_WALK_FILTER_END;

  RTA_LOCK;
  HASH_MAY_RESIZE_DOWN(o->hash, RSH, rta_pool);

  if (o->stop && !o->uc)
  {
    rfree(o->prune);
    RTA_UNLOCK;

    if (config->table_debug)
      log(L_TRACE "All rte_src's for %s pruned, scheduling stop event", o->name);

    rt_done_sources(o);
  }
  else
    RTA_UNLOCK;
}

void
rt_init_sources(struct rte_owner *o, const char *name, event_list *list)
{
  RTA_LOCK;
  HASH_INIT(o->hash, rta_pool, RSH_INIT_ORDER);
  o->hash_key = random_u32();
  o->uc = 0;
  o->name = name;
  o->prune = ev_new_init(rta_pool, rt_prune_sources, o);
  o->stop = NULL;
  o->list = list;
  RTA_UNLOCK;
}

void
rt_destroy_sources(struct rte_owner *o, event *done)
{
  o->stop = done;

  if (!o->uc)
  {
    if (config->table_debug)
      log(L_TRACE "Source owner %s destroy requested. All rte_src's already pruned, scheduling stop event", o->name);

    RTA_LOCK;
    rfree(o->prune);
    RTA_UNLOCK;

    rt_done_sources(o);
  }
  else
    if (config->table_debug)
      log(L_TRACE "Source owner %s destroy requested. Remaining %u rte_src's to prune.", o->name, o->uc);
}

/*
 *	Multipath Next Hop
 */

static int
nexthop_compare_node(const struct nexthop *x, const struct nexthop *y)
{
  int r;
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

static int
nexthop_compare_qsort(const void *x, const void *y)
{
  return nexthop_compare_node( *(const struct nexthop **) x, *(const struct nexthop **) y );
}

/**
 * nexthop_merge - merge nexthop lists
 * @x: list 1
 * @y: list 2
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
struct nexthop_adata *
nexthop_merge(struct nexthop_adata *xin, struct nexthop_adata *yin, int max, linpool *lp)
{
  uint outlen = ADATA_SIZE(xin->ad.length) + ADATA_SIZE(yin->ad.length);
  struct nexthop_adata *out = lp_alloc(lp, outlen);
  out->ad.length = outlen - sizeof (struct adata);

  struct nexthop *x = &xin->nh, *y = &yin->nh, *cur = &out->nh;
  int xvalid, yvalid;

  while (max--)
  {
    xvalid = NEXTHOP_VALID(x, xin);
    yvalid = NEXTHOP_VALID(y, yin);

    if (!xvalid && !yvalid)
      break;

    ASSUME(NEXTHOP_VALID(cur, out));

    int cmp = !xvalid ? 1 : !yvalid ? -1 : nexthop_compare_node(x, y);

    if (cmp < 0)
    {
      ASSUME(NEXTHOP_VALID(x, xin));
      memcpy(cur, x, nexthop_size(x));
      x = NEXTHOP_NEXT(x);
    }
    else if (cmp > 0)
    {
      ASSUME(NEXTHOP_VALID(y, yin));
      memcpy(cur, y, nexthop_size(y));
      y = NEXTHOP_NEXT(y);
    }
    else
    {
      ASSUME(NEXTHOP_VALID(x, xin));
      memcpy(cur, x, nexthop_size(x));
      x = NEXTHOP_NEXT(x);

      ASSUME(NEXTHOP_VALID(y, yin));
      y = NEXTHOP_NEXT(y);
    }
    cur = NEXTHOP_NEXT(cur);
  }

  out->ad.length = (void *) cur - (void *) out->ad.data;

  return out;
}

struct nexthop_adata *
nexthop_sort(struct nexthop_adata *nhad, linpool *lp)
{
  /* Count the nexthops */
  uint cnt = 0;
  NEXTHOP_WALK(nh, nhad)
    cnt++;

  if (cnt <= 1)
    return nhad;

  /* Get pointers to them */
  struct nexthop **sptr = tmp_alloc(cnt * sizeof(struct nexthop *));

  uint i = 0;
  NEXTHOP_WALK(nh, nhad)
    sptr[i++] = nh;

  /* Sort the pointers */
  qsort(sptr, cnt, sizeof(struct nexthop *), nexthop_compare_qsort);

  /* Allocate the output */
  struct nexthop_adata *out = (struct nexthop_adata *) lp_alloc_adata(lp, nhad->ad.length);
  struct nexthop *dest = &out->nh;

  /* Deduplicate nexthops while storing them */
  for (uint i = 0; i < cnt; i++)
  {
    if (i && !nexthop_compare_node(sptr[i], sptr[i-1]))
      continue;

    memcpy(dest, sptr[i], NEXTHOP_SIZE(sptr[i]));
    dest = NEXTHOP_NEXT(dest);
  }

  out->ad.length = (void *) dest - (void *) out->ad.data;
  return out;
}

int
nexthop_is_sorted(struct nexthop_adata *nhad)
{
  struct nexthop *prev = NULL;
  NEXTHOP_WALK(nh, nhad)
  {
    if (prev && (nexthop_compare_node(prev, nh) >= 0))
      return 0;

    prev = nh;
  }

  return 1;
}

/*
 *	Extended Attributes
 */

#define EA_CLASS_INITIAL_MAX	128
static struct ea_class **ea_class_global = NULL;
static uint ea_class_max;
static struct idm ea_class_idm;

/* Config parser lex register function */
void ea_lex_register(struct ea_class *def);
void ea_lex_unregister(struct ea_class *def);

static void
ea_class_free(struct ea_class *cl)
{
  /* No more ea class references. Unregister the attribute. */
  idm_free(&ea_class_idm, cl->id);
  ea_class_global[cl->id] = NULL;
  if (!cl->hidden)
    ea_lex_unregister(cl);
}

static void
ea_class_ref_free(resource *r)
{
  struct ea_class_ref *ref = SKIP_BACK(struct ea_class_ref, r, r);
  if (!--ref->class->uc)
    ea_class_free(ref->class);
}

static void
ea_class_ref_dump(resource *r, unsigned indent UNUSED)
{
  struct ea_class_ref *ref = SKIP_BACK(struct ea_class_ref, r, r);
  debug("name \"%s\", type=%d\n", ref->class->name, ref->class->type);
}

static struct resclass ea_class_ref_class = {
  .name = "Attribute class reference",
  .size = sizeof(struct ea_class_ref),
  .free = ea_class_ref_free,
  .dump = ea_class_ref_dump,
  .lookup = NULL,
  .memsize = NULL,
};

static void
ea_class_init(void)
{
  ASSERT_DIE(ea_class_global == NULL);

  idm_init(&ea_class_idm, rta_pool, EA_CLASS_INITIAL_MAX);
  ea_class_global = mb_allocz(rta_pool,
      sizeof(*ea_class_global) * (ea_class_max = EA_CLASS_INITIAL_MAX));
}

static struct ea_class_ref *
ea_ref_class(pool *p, struct ea_class *def)
{
  def->uc++;
  struct ea_class_ref *ref = ralloc(p, &ea_class_ref_class);
  ref->class = def;
  return ref;
}

static struct ea_class_ref *
ea_register(pool *p, struct ea_class *def)
{
  def->id = idm_alloc(&ea_class_idm);

  ASSERT_DIE(ea_class_global);
  while (def->id >= ea_class_max)
    ea_class_global = mb_realloc(ea_class_global, sizeof(*ea_class_global) * (ea_class_max *= 2));

  ASSERT_DIE(def->id < ea_class_max);
  ea_class_global[def->id] = def;

  if (!def->hidden)
    ea_lex_register(def);

  return ea_ref_class(p, def);
}

struct ea_class_ref *
ea_register_alloc(pool *p, struct ea_class cl)
{
  struct ea_class *clp = ea_class_find_by_name(cl.name);
  if (clp && clp->type == cl.type)
    return ea_ref_class(p, clp);

  uint namelen = strlen(cl.name) + 1;

  struct {
    struct ea_class cl;
    char name[0];
  } *cla = mb_alloc(rta_pool, sizeof(struct ea_class) + namelen);
  cla->cl = cl;
  memcpy(cla->name, cl.name, namelen);
  cla->cl.name = cla->name;

  return ea_register(p, &cla->cl);
}

void
ea_register_init(struct ea_class *clp)
{
  ASSERT_DIE(!ea_class_find_by_name(clp->name));
  ea_register(&root_pool, clp);
}

struct ea_class *
ea_class_find_by_id(uint id)
{
  ASSERT_DIE(id < ea_class_max);
  ASSERT_DIE(ea_class_global[id]);
  return ea_class_global[id];
}

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
ea_find_by_id(ea_list *e, unsigned id)
{
  eattr *a = ea__find(e, id & EA_CODE_MASK);

  if (a && a->undef && !(id & EA_ALLOW_UNDEF))
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

	if (a->undef)
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
 * In place discard duplicates and undefs in sorted ea_list. We use stable sort
 * for this reason.
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
      /* Drop undefs unless this is a true overlay */
      if (s0->undef && (s[-1].undef || !e->next))
	continue;

      /* Copy the newest version to destination */
      *d = *s0;

      /* Preserve info whether it originated locally */
      d->originated = s[-1].originated;

      /* Not fresh any more, we prefer surstroemming */
      d->fresh = 0;

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
static void
ea_sort(ea_list *e)
{
  if (!(e->flags & EALF_SORTED))
  {
    ea_do_sort(e);
    ea_do_prune(e);
    e->flags |= EALF_SORTED;
  }

  if (e->count > 5)
    e->flags |= EALF_BISECT;
}

/**
 * ea_scan - estimate attribute list size
 * @e: attribute list
 *
 * This function calculates an upper bound of the size of
 * a given &ea_list after merging with ea_merge().
 */
static unsigned
ea_scan(const ea_list *e, int overlay)
{
  unsigned cnt = 0;

  while (e)
    {
      cnt += e->count;
      e = e->next;
      if (e && overlay && ea_is_cached(e))
	break;
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
static void
ea_merge(ea_list *e, ea_list *t, int overlay)
{
  eattr *d = t->attrs;

  t->flags = 0;
  t->count = 0;

  while (e)
    {
      memcpy(d, e->attrs, sizeof(eattr)*e->count);
      t->count += e->count;
      d += e->count;
      e = e->next;

      if (e && overlay && ea_is_cached(e))
	break;
    }

  t->next = e;
}

ea_list *
ea_normalize(ea_list *e, int overlay)
{
  ea_list *t = tmp_alloc(ea_scan(e, overlay));
  ea_merge(e, t, overlay);
  ea_sort(t);

  return t->count ? t : t->next;
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
  if (x->next != y->next)
    return 0;
  if (x->count != y->count)
    return 0;
  for(c=0; c<x->count; c++)
    {
      eattr *a = &x->attrs[c];
      eattr *b = &y->attrs[c];

      if (a->id != b->id ||
	  a->flags != b->flags ||
	  a->type != b->type ||
	  a->originated != b->originated ||
	  a->fresh != b->fresh ||
	  a->undef != b->undef ||
	  ((a->type & EAF_EMBEDDED) ? a->u.data != b->u.data : !adata_same(a->u.ptr, b->u.ptr)))
	return 0;
    }
  return 1;
}

uint
ea_list_size(ea_list *o)
{
  unsigned i, elen;

  ASSERT_DIE(o);
  elen = BIRD_CPU_ALIGN(sizeof(ea_list) + sizeof(eattr) * o->count);

  for(i=0; i<o->count; i++)
    {
      eattr *a = &o->attrs[i];
      if (!a->undef && !(a->type & EAF_EMBEDDED))
	elen += ADATA_SIZE(a->u.ptr->length);
    }

  return elen;
}

void
ea_list_copy(ea_list *n, ea_list *o, uint elen)
{
  uint adpos = sizeof(ea_list) + sizeof(eattr) * o->count;
  memcpy(n, o, adpos);
  adpos = BIRD_CPU_ALIGN(adpos);

  for(uint i=0; i<o->count; i++)
    {
      eattr *a = &n->attrs[i];
      if (!a->undef && !(a->type & EAF_EMBEDDED))
	{
	  unsigned size = ADATA_SIZE(a->u.ptr->length);
	  ASSERT_DIE(adpos + size <= elen);

	  struct adata *d = ((void *) n) + adpos;
	  memcpy(d, a->u.ptr, size);
	  a->u.ptr = d;

	  adpos += size;
	}
    }

  ASSERT_DIE(adpos == elen);
}

static void
ea_list_ref(ea_list *l)
{
  for(uint i=0; i<l->count; i++)
    {
      eattr *a = &l->attrs[i];
      ASSERT_DIE(a->id < ea_class_max);

      if (a->undef)
	continue;

      struct ea_class *cl = ea_class_global[a->id];
      ASSERT_DIE(cl && cl->uc);

      CALL(cl->stored, a);
      cl->uc++;
    }

  if (l->next)
  {
    ASSERT_DIE(ea_is_cached(l->next));
    ea_clone(l->next);
  }
}

static void ea_free_nested(ea_list *l);

static void
ea_list_unref(ea_list *l)
{
  for(uint i=0; i<l->count; i++)
    {
      eattr *a = &l->attrs[i];
      ASSERT_DIE(a->id < ea_class_max);

      if (a->undef)
	continue;

      struct ea_class *cl = ea_class_global[a->id];
      ASSERT_DIE(cl && cl->uc);

      CALL(cl->freed, a);
      if (!--cl->uc)
	ea_class_free(cl);
    }

  if (l->next)
    ea_free_nested(l->next);
}

void
ea_format_bitfield(const struct eattr *a, byte *buf, int bufsize, const char **names, int min, int max)
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
opaque_format(const struct adata *ad, byte *buf, uint size)
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
ea_show_int_set(struct cli *c, const char *name, const struct adata *ad, int way, byte *buf)
{
  int nlen = strlen(name);
  int i = int_set_format(ad, way, 0, buf, CLI_MSG_SIZE - nlen - 3);
  cli_printf(c, -1012, "\t%s: %s", name, buf);
  while (i)
    {
      i = int_set_format(ad, way, i, buf, CLI_MSG_SIZE - 1);
      cli_printf(c, -1012, "\t\t%s", buf);
    }
}

static inline void
ea_show_ec_set(struct cli *c, const char *name, const struct adata *ad, byte *buf)
{
  int nlen = strlen(name);
  int i = ec_set_format(ad, 0, buf, CLI_MSG_SIZE - nlen - 3);
  cli_printf(c, -1012, "\t%s: %s", name, buf);
  while (i)
    {
      i = ec_set_format(ad, i, buf, CLI_MSG_SIZE - 1);
      cli_printf(c, -1012, "\t\t%s", buf);
    }
}

static inline void
ea_show_lc_set(struct cli *c, const char *name, const struct adata *ad, byte *buf)
{
  int nlen = strlen(name);
  int i = lc_set_format(ad, 0, buf, CLI_MSG_SIZE - nlen - 3);
  cli_printf(c, -1012, "\t%s: %s", name, buf);
  while (i)
    {
      i = lc_set_format(ad, i, buf, CLI_MSG_SIZE - 1);
      cli_printf(c, -1012, "\t\t%s", buf);
    }
}

void
ea_show_nexthop_list(struct cli *c, struct nexthop_adata *nhad)
{
  if (!NEXTHOP_IS_REACHABLE(nhad))
    return;

  NEXTHOP_WALK(nh, nhad)
  {
    char mpls[MPLS_MAX_LABEL_STACK*12 + 5], *lsp = mpls;
    char *onlink = (nh->flags & RNF_ONLINK) ? " onlink" : "";
    char weight[16] = "";

    if (nh->labels)
    {
      lsp += bsprintf(lsp, " mpls %d", nh->label[0]);
      for (int i=1;i<nh->labels; i++)
	lsp += bsprintf(lsp, "/%d", nh->label[i]);
    }
    *lsp = '\0';

    if (!NEXTHOP_ONE(nhad))
      bsprintf(weight, " weight %d", nh->weight + 1);

    if (ipa_nonzero(nh->gw))
      if (nh->iface)
	cli_printf(c, -1007, "\tvia %I on %s%s%s%s",
	    nh->gw, nh->iface->name, mpls, onlink, weight);
      else
	cli_printf(c, -1007, "\tvia %I", nh->gw);
    else
      cli_printf(c, -1007, "\tdev %s%s%s",
	  nh->iface->name, mpls,  onlink, weight);
  }
}

void
ea_show_hostentry(const struct adata *ad, byte *buf, uint size)
{
  const struct hostentry_adata *had = (const struct hostentry_adata *) ad;

  if (ipa_nonzero(had->he->link) && !ipa_equal(had->he->link, had->he->addr))
    bsnprintf(buf, size, "via %I %I table %s", had->he->addr, had->he->link, had->he->tab->name);
  else
    bsnprintf(buf, size, "via %I table %s", had->he->addr, had->he->tab->name);
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
static void
ea_show(struct cli *c, const eattr *e)
{
  const struct adata *ad = (e->type & EAF_EMBEDDED) ? NULL : e->u.ptr;
  byte buf[CLI_MSG_SIZE];
  byte *pos = buf, *end = buf + sizeof(buf);

  ASSERT_DIE(e->id < ea_class_max);

  struct ea_class *cls = ea_class_global[e->id];
  ASSERT_DIE(cls);

  if (e->undef || cls->hidden)
    return;
  else if (cls->format)
    cls->format(e, buf, end - buf);
  else
    switch (e->type)
      {
	case T_INT:
	  if ((cls == &ea_gen_igp_metric) && e->u.data >= IGP_METRIC_UNKNOWN)
	    return;

	  bsprintf(pos, "%u", e->u.data);
	  break;
	case T_OPAQUE:
	  opaque_format(ad, pos, end - pos);
	  break;
	case T_IP:
	  bsprintf(pos, "%I", *(ip_addr *) ad->data);
	  break;
	case T_QUAD:
	  bsprintf(pos, "%R", e->u.data);
	  break;
	case T_PATH:
	  as_path_format(ad, pos, end - pos);
	  break;
	case T_CLIST:
	  ea_show_int_set(c, cls->name, ad, 1, buf);
	  return;
	case T_ECLIST:
	  ea_show_ec_set(c, cls->name, ad, buf);
	  return;
	case T_LCLIST:
	  ea_show_lc_set(c, cls->name, ad, buf);
	  return;
	case T_NEXTHOP_LIST:
	  ea_show_nexthop_list(c, (struct nexthop_adata *) e->u.ptr);
	  return;
	case T_HOSTENTRY:
	  ea_show_hostentry(ad, pos, end - pos);
	  break;
	default:
	  bsprintf(pos, "<type %02x>", e->type);
      }

  cli_printf(c, -1012, "\t%s: %s", cls->name, buf);
}

static void
nexthop_dump(const struct adata *ad)
{
  struct nexthop_adata *nhad = (struct nexthop_adata *) ad;

  debug(":");

  NEXTHOP_WALK(nh, nhad)
    {
      if (ipa_nonzero(nh->gw)) debug(" ->%I", nh->gw);
      if (nh->labels) debug(" L %d", nh->label[0]);
      for (int i=1; i<nh->labels; i++)
	debug("/%d", nh->label[i]);
      debug(" [%s]", nh->iface ? nh->iface->name : "???");
    }
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
      struct ea_storage *s = ea_is_cached(e) ? ea_get_storage(e) : NULL;
      debug("[%c%c%c] uc=%d h=%08x",
	    (e->flags & EALF_SORTED) ? 'S' : 's',
	    (e->flags & EALF_BISECT) ? 'B' : 'b',
	    (e->flags & EALF_CACHED) ? 'C' : 'c',
	    s ? s->uc : 0, s ? s->hash_key : 0);
      for(i=0; i<e->count; i++)
	{
	  eattr *a = &e->attrs[i];
	  debug(" %04x.%02x", a->id, a->flags);
	  debug("=%c",
	      "?iO?IRP???S??pE?"
	      "??L???N?????????"
	      "?o???r??????????" [a->type]);
	  if (a->originated)
	    debug("o");
	  if (a->type & EAF_EMBEDDED)
	    debug(":%08x", a->u.data);
	  else if (a->id == ea_gen_nexthop.id)
	    nexthop_dump(a->u.ptr);
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
      h ^= mem_hash(&e->next, sizeof(e->next));
      for(i=0; i<e->count; i++)
	{
	  struct eattr *a = &e->attrs[i];
	  h ^= a->id; h *= mul;
	  if (a->undef)
	    continue;
	  if (a->type & EAF_EMBEDDED)
	    h ^= a->u.data;
	  else
	    {
	      const struct adata *d = a->u.ptr;
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
static struct ea_storage **rta_hash_table;

static void
rta_alloc_hash(void)
{
  rta_hash_table = mb_allocz(rta_pool, sizeof(struct ea_storage *) * rta_cache_size);
  if (rta_cache_size < 32768)
    rta_cache_limit = rta_cache_size * 2;
  else
    rta_cache_limit = ~0;
  rta_cache_mask = rta_cache_size - 1;
}

static inline void
rta_insert(struct ea_storage *r)
{
  uint h = r->hash_key & rta_cache_mask;
  r->next_hash = rta_hash_table[h];
  if (r->next_hash)
    r->next_hash->pprev_hash = &r->next_hash;
  r->pprev_hash = &rta_hash_table[h];
  rta_hash_table[h] = r;
}

static void
rta_rehash(void)
{
  uint ohs = rta_cache_size;
  uint h;
  struct ea_storage *r, *n;
  struct ea_storage **oht = rta_hash_table;

  rta_cache_size = 2*rta_cache_size;
  DBG("Rehashing rta cache from %d to %d entries.\n", ohs, rta_cache_size);
  rta_alloc_hash();
  for(h=0; h<ohs; h++)
    for(r=oht[h]; r; r=n)
      {
	n = r->next_hash;
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
ea_list *
ea_lookup(ea_list *o, int overlay)
{
  struct ea_storage *r;
  uint h;

  ASSERT(!ea_is_cached(o));
  o = ea_normalize(o, overlay);
  h = ea_hash(o);

  RTA_LOCK;

  for(r=rta_hash_table[h & rta_cache_mask]; r; r=r->next_hash)
    if (r->hash_key == h && ea_same(r->l, o))
    {
      atomic_fetch_add_explicit(&r->uc, 1, memory_order_acq_rel);
      RTA_UNLOCK;
      return r->l;
    }

  uint elen = ea_list_size(o);
  uint sz = elen + sizeof(struct ea_storage);
  for (uint i=0; i<ARRAY_SIZE(ea_slab_sizes); i++)
    if (sz <= ea_slab_sizes[i])
    {
      r = sl_alloc(ea_slab[i]);
      break;
    }

  int huge = r ? 0 : EALF_HUGE;;
  if (huge)
    r = mb_alloc(rta_pool, sz);

  ea_list_copy(r->l, o, elen);
  ea_list_ref(r->l);

  r->l->flags |= EALF_CACHED | huge;
  r->hash_key = h;
  r->uc = 1;

  rta_insert(r);

  if (++rta_cache_count > rta_cache_limit)
    rta_rehash();

  RTA_UNLOCK;
  return r->l;
}

static void
ea_free_locked(struct ea_storage *a)
{
  /* Somebody has cloned this rta inbetween. This sometimes happens. */
  if (atomic_load_explicit(&a->uc, memory_order_acquire))
    return;

  ASSERT(rta_cache_count);
  rta_cache_count--;
  *a->pprev_hash = a->next_hash;
  if (a->next_hash)
    a->next_hash->pprev_hash = a->pprev_hash;

  ea_list_unref(a->l);
  if (a->l->flags & EALF_HUGE)
    mb_free(a);
  else
    sl_free(a);
}

static void
ea_free_nested(struct ea_list *l)
{
  struct ea_storage *r = ea_get_storage(l);
  if (1 == atomic_fetch_sub_explicit(&r->uc, 1, memory_order_acq_rel))
    ea_free_locked(r);
}

void
ea__free(struct ea_storage *a)
{
  RTA_LOCK;
  ea_free_locked(a);
  RTA_UNLOCK;
}

/**
 * rta_dump_all - dump attribute cache
 *
 * This function dumps the whole contents of route attribute cache
 * to the debug output.
 */
void
ea_dump_all(void)
{
  RTA_LOCK;

  debug("Route attribute cache (%d entries, rehash at %d):\n", rta_cache_count, rta_cache_limit);
  for (uint h=0; h < rta_cache_size; h++)
    for (struct ea_storage *a = rta_hash_table[h]; a; a = a->next_hash)
      {
	debug("%p ", a);
	ea_dump(a->l);
	debug("\n");
      }
  debug("\n");

  RTA_UNLOCK;
}

void
ea_show_list(struct cli *c, ea_list *eal)
{
  ea_list *n = ea_normalize(eal, 0);
  for (int i  =0; i < n->count; i++)
    ea_show(c, &n->attrs[i]);
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
  attrs_domain = DOMAIN_NEW(attrs, "Attributes");

  rta_pool = rp_new(&root_pool, "Attributes");

  for (uint i=0; i<ARRAY_SIZE(ea_slab_sizes); i++)
    ea_slab[i] = sl_new(rta_pool, ea_slab_sizes[i]);

  rta_alloc_hash();
  rte_src_init();
  ea_class_init();

  /* These attributes are required to be first for nice "show route" output */
  ea_register_init(&ea_gen_nexthop);
  ea_register_init(&ea_gen_hostentry);

  /* Other generic route attributes */
  ea_register_init(&ea_gen_preference);
  ea_register_init(&ea_gen_igp_metric);
  ea_register_init(&ea_gen_from);
  ea_register_init(&ea_gen_source);
  ea_register_init(&ea_gen_flowspec_valid);
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
