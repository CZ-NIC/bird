/*
 *	BIRD -- Route Attribute Cache
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2020--2025 Maria Matejka <mq@jmq.cz>
 *	(c) 2026       Katerina Kubecova <katerina.kubecova@nic.cz>
 *	(c) 2008--2026 CZ.NIC
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
#include "lib/attrs.h"
#include "lib/alloca.h"
#include "lib/hash.h"
#include "lib/idm.h"
#include "lib/resource.h"
#include "lib/string.h"
#include "lib/timer.h"

#include <stddef.h>
#include <stdlib.h>

const adata null_adata;		/* adata of length 0 */

struct ea_class ea_gen_igp_metric = {
  .name = "igp_metric",
  .type = T_INT,
};

struct ea_class ea_gen_local_metric = {
  .name = "local_metric",
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
  [RTS_PERF]		= "Perf",
  [RTS_L3VPN]		= "L3VPN",
  [RTS_AGGREGATED]	= "aggregated",
  [RTS_BRIDGE]		= "bridge",
  [RTS_EVPN]		= "EVPN",
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
  lfuc_lock(&had->he->uc);
}

static void
ea_gen_hostentry_freed(const eattr *ea)
{
  struct hostentry_adata *had = (struct hostentry_adata *) ea->u.ptr;
  lfuc_unlock(&had->he->uc, &had->he->owner->hcu_cb);
}

struct ea_class ea_gen_hostentry = {
  .name = "hostentry",
  .type = T_HOSTENTRY,
  .readonly = 1,
  .stored = ea_gen_hostentry_stored,
  .freed = ea_gen_hostentry_freed,
};

struct ea_class ea_gen_hostentry_version = {
  .name = "hostentry version",
  .type = T_INT,
  .readonly = 1,
  .hidden = 1,
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

static void
ea_gen_aspa_providers_format(const eattr *a, byte *buf, uint size)
{
  int_set_format(a->u.ad, ISF_NUMBERS, -1, buf, size - 5);
}

struct ea_class ea_gen_aspa_providers = {
  .name = "aspa_providers",
  .legacy_name = "aspa_providers",
  .type = T_CLIST,
  .format = ea_gen_aspa_providers_format,
};

DOMAIN(attrs) attrs_domain;

pool *rta_pool;

/* Assuming page size of 4096, these are magic values for slab allocation */
static const uint ea_slab_sizes[] = { 56, 112, 168, 288, 448, 800, 1344 };
static mslab *ea_slab[ARRAY_SIZE(ea_slab_sizes)];

static slab *rte_src_slab;

static struct idm src_ids;
#define SRC_ID_INIT_SIZE 4

/* rte source hash */

#define RSH_KEY(n)		n->private_id
#define RSH_NEXT(n)		n->next
#define RSH_EQ(n1,n2)		n1 == n2
#define RSH_FN(n)		u64_hash(n)

#define RSH_REHASH		rte_src_rehash
#define RSH_PARAMS		/2, *2, 1, 1, 8, 20
#define RSH_INIT_ORDER		2
static struct rte_src * _Atomic * _Atomic rte_src_global;
static _Atomic uint rte_src_global_max;

static void ea_rehash(void*);

static void
rte_src_init(void)
{
  rte_src_slab = sl_new(rta_pool, sizeof(struct rte_src));

  uint gmax = SRC_ID_INIT_SIZE * 32;
  struct rte_src * _Atomic *g = mb_alloc(rta_pool, sizeof(struct rte_src * _Atomic) * gmax);
  for (uint i = 0; i < gmax; i++)
    atomic_store_explicit(&g[i], NULL, memory_order_relaxed);

  atomic_store_explicit(&rte_src_global, g, memory_order_release);
  atomic_store_explicit(&rte_src_global_max, gmax, memory_order_release);

  idm_init(&src_ids, rta_pool, SRC_ID_INIT_SIZE);
}

HASH_DEFINE_REHASH_FN(RSH, struct rte_src)

static struct rte_src *
rt_find_source(struct rte_owner *p, u64 id)
{
  return HASH_FIND(p->hash, RSH, id);
}

struct rte_src *
rt_get_source_o(struct rte_owner *p, u64 id)
{
  if (p->stop)
    bug("Stopping route owner asked for another source.");

  ASSERT_DIE(birdloop_inside(p->prune.target));

  struct rte_src *src = rt_find_source(p, id);

  if (src)
  {
#ifdef RT_SOURCE_DEBUG
    log(L_INFO "Found source %uG", src->global_id);
#endif
    lfuc_lock_revive(&src->uc);
    return src;
  }

  RTA_LOCK;
  src = sl_allocz(rte_src_slab);
  src->owner = p;
  src->private_id = id;

  src->global_id = idm_alloc(&src_ids);

  lfuc_init(&src->uc);
  p->uc++;

  HASH_INSERT2(p->hash, RSH, rta_pool, src);
  if (p->debug & D_ROUTES)
    log(L_TRACE "%s: new rte_src ID %luL %uG, have %u sources now",
	p->name, src->private_id, src->global_id, p->uc);

  uint gm = atomic_load_explicit(&rte_src_global_max, memory_order_relaxed);
  struct rte_src * _Atomic * g = atomic_load_explicit(&rte_src_global, memory_order_relaxed);

  if (src->global_id >= gm)
  {
    /* Allocate new block */
    size_t old_len = sizeof(struct rte_src * _Atomic) * gm;
    struct rte_src * _Atomic * new_block = mb_alloc(rta_pool, old_len * 2);
    memcpy(new_block, g, old_len);

    for (uint i = 0; i < gm; i++)
      atomic_store_explicit(&new_block[gm+i], NULL, memory_order_relaxed);

    /* Update the pointer */
    atomic_store_explicit(&rte_src_global, new_block, memory_order_release);
    atomic_store_explicit(&rte_src_global_max, gm * 2, memory_order_release);

    /* Wait for readers */
    synchronize_rcu();

    /* Free the old block */
    mb_free(g);
    g = new_block;
  }

  atomic_store_explicit(&g[src->global_id], src, memory_order_release);
  RTA_UNLOCK;

  return src;
}

/**
 * Find a rte source by its global ID. Only available for existing and locked
 * sources stored by their ID. Checking for non-existent or foreign source is unsafe.
 *
 * @id: requested global ID
 *
 * Returns the found source or dies. Result of this function is guaranteed to
 * be a valid source as long as the caller owns it.
 */
struct rte_src *
rt_find_source_global(u32 id)
{
  rcu_read_lock();
  ASSERT_DIE(id < atomic_load_explicit(&rte_src_global_max, memory_order_acquire));

  struct rte_src * _Atomic * g = atomic_load_explicit(&rte_src_global, memory_order_acquire);
  struct rte_src *src = atomic_load_explicit(&g[id], memory_order_acquire);
  ASSERT_DIE(src);
  ASSERT_DIE(src->global_id == id);

  rcu_read_unlock();

  return src;
}

static inline void
rt_done_sources(struct rte_owner *o)
{
  RTA_LOCK;
  HASH_FREE(o->hash);
  RTA_UNLOCK;

  callback_activate(o->stop);
}

void
rt_prune_sources(callback *cb)
{
  SKIP_BACK_DECLARE(struct rte_owner, o, prune, cb);

  HASH_WALK_FILTER(o->hash, next, src, sp)
  {
    if (lfuc_finished(&src->uc))
    {
      o->uc--;

      if (o->debug & D_ROUTES)
	log(L_TRACE "%s: freed rte_src ID %luL %uG, have %u sources now",
	    o->name, src->private_id, src->global_id, o->uc);

      HASH_DO_REMOVE(o->hash, RSH, sp);

      RTA_LOCK;
      struct rte_src * _Atomic * g = atomic_load_explicit(&rte_src_global, memory_order_acquire);
      atomic_store_explicit(&g[src->global_id], NULL, memory_order_release);
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
    callback_cancel(&o->prune);
    RTA_UNLOCK;

    if (o->debug & D_EVENTS)
      log(L_TRACE "%s: all rte_src's pruned, scheduling stop event", o->name);

    rt_done_sources(o);
  }
  else
    RTA_UNLOCK;
}

void
rt_dump_sources(struct dump_request *dreq, struct rte_owner *o)
{
  RDUMP("\t%s: hord=%u, uc=%u, cnt=%u prune=%p, stop=%p\n",
      o->name, o->hash.order, o->uc, o->hash.count, o->prune, o->stop);
  RDUMP("\tget_route_info=%p, better=%p, mergable=%p, igp_metric=%p, recalculate=%p",
      o->class->get_route_info, o->class->rte_better, o->class->rte_mergable,
      o->class->rte_igp_metric, o->rte_recalculate);

  int splitting = 0;
  HASH_WALK(o->hash, next, src)
  {
    RDUMP("%c%c%uL %uG %luU",
	(splitting % 8) ? ',' : '\n',
	(splitting % 8) ? ' ' : '\t',
	src->private_id, src->global_id,
	atomic_load_explicit(&src->uc.uc, memory_order_relaxed));

    splitting++;
  }
  HASH_WALK_END;
  RDUMP("\n");
}

static struct rte_owner_class default_rte_owner_class;

void
rt_init_sources(struct rte_owner *o, const char *name, struct birdloop *loop)
{
  RTA_LOCK;
  HASH_INIT(o->hash, rta_pool, RSH_INIT_ORDER);
  o->hash_key = random_u32();
  o->uc = 0;
  o->name = name;
  callback_init(&o->prune, rt_prune_sources, loop);
  o->stop = NULL;
  if (!o->class)
    o->class = &default_rte_owner_class;
  RTA_UNLOCK;
  if (o->debug & D_EVENTS)
    log(L_TRACE "%s: initialized rte_src owner", o->name);
}

void
rt_destroy_sources(struct rte_owner *o, callback *done)
{
  o->stop = done;

  if (!o->uc)
  {
    if (o->debug & D_EVENTS)
      log(L_TRACE "%s: rte_src owner destroy requested, already clean, scheduling stop event", o->name);

    rt_done_sources(o);
  }
  else
    if (o->debug & D_EVENTS)
      log(L_TRACE "%s: rte_src owner destroy requested, remaining %u rte_src's to prune.", o->name, o->uc);
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

static void
ea_class_free(struct ea_class *cl)
{
  RTA_LOCK;

  /* No more ea class references. Unregister the attribute. */
  idm_free(&ea_class_idm, cl->id);
  ea_class_global[cl->id] = NULL;

  /* When we start supporting full protocol removal, we may need to call
   * ea_lex_unregister(cl), see where ea_lex_register() is called. */

  RTA_UNLOCK;
}

static void
ea_class_ref_free(resource *r)
{
  SKIP_BACK_DECLARE(struct ea_class_ref, ref, r, r);
  if (atomic_fetch_sub_explicit(&ref->class->uc, 1, memory_order_acquire) == 1)
    ea_class_free(ref->class);
}

static void
ea_class_ref_dump(struct dump_request *dreq, resource *r)
{
  SKIP_BACK_DECLARE(struct ea_class_ref, ref, r, r);
  RDUMP("name \"%s\", type=%d\n", ref->class->name, ref->class->type);
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

struct ea_class_ref *
ea_ref_class(pool *p, struct ea_class *def)
{
  atomic_fetch_add_explicit(&def->uc, 1, memory_order_acquire);
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
  {
    struct ea_class **ea_class_new = mb_allocz(rta_pool, sizeof(*ea_class_global) * (ea_class_max * 2));
    memcpy(ea_class_new, ea_class_global, sizeof(*ea_class_global) * ea_class_max);
    ea_class_max *= 2;
    struct ea_class **ea_class_old = ea_class_global;
    ea_class_global = ea_class_new;
    synchronize_rcu();

    mb_free(ea_class_old);
  }

  ASSERT_DIE(def->id < ea_class_max);
  ea_class_global[def->id] = def;

  return ea_ref_class(p, def);
}

struct ea_class_ref *
ea_register_alloc(pool *p, struct ea_class cl)
{
  struct ea_class_ref *ref;

  RTA_LOCK;
  struct ea_class *clp = ea_class_find_by_name(cl.name);
  if (clp && clp->type == cl.type)
  {
    ref = ea_ref_class(p, clp);
    RTA_UNLOCK;
    return ref;
  }

  uint namelen = strlen(cl.name) + 1;

  struct {
    struct ea_class cl;
    char name[0];
  } *cla = mb_alloc(rta_pool, sizeof(struct ea_class) + namelen);
  cla->cl = cl;
  memcpy(cla->name, cl.name, namelen);
  cla->cl.name = cla->name;

  ref = ea_register(p, &cla->cl);
  RTA_UNLOCK;
  return ref;
}

void
ea_register_init(struct ea_class *clp)
{
  RTA_LOCK;
  ASSERT_DIE(!ea_class_find_by_name(clp->name));

  struct ea_class *def = ea_register(&root_pool, clp)->class;

  if (!clp->hidden)
    ea_lex_register(def);

  RTA_UNLOCK;
}

struct ea_class *
ea_class_find_by_id(uint id)
{
  ASSERT_DIE(id < ea_class_max);
  rcu_read_lock();
  struct ea_class *ret = ea_class_global[id];
  rcu_read_unlock();
  ASSERT_DIE(ret);
  return ret;
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

static bool eattr_same_value(const eattr *a, const eattr *b);

/**
 * In place discard duplicates and undefs in sorted ea_list. We use stable sort
 * for this reason.
 **/
static inline void
ea_do_prune(ea_list *e)
{
  eattr *s, *d, *l, *s0;
  int i = 0;

#if 0
  debug("[[prune]] ");
  ea_dump(e);
  debug(" ----> ");
#endif

  /* Prepare underlay stepper */
  uint ulc = 0;
  for (ea_list *u = e->next; u; u = u->next)
    ulc++;

  struct { eattr *cur, *end; } uls[ulc];
  {
    ea_list *u = e->next;
    for (uint i = 0; i < ulc; i++)
    {
      ASSERT_DIE(u->flags & EALF_SORTED);
      uls[i].cur = u->attrs;
      uls[i].end = u->attrs + u->count;
      u = u->next;
      /* debug(" [[prev %d: %p to %p]] ", i, uls[i].cur, uls[i].end); */
    }
  }

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

      /* Find the attribute's underlay version */
      eattr *prev = NULL;
      for (uint i = 0; i < ulc; i++)
      {
	while ((uls[i].cur < uls[i].end) && (uls[i].cur->id < s0->id))
	{
	  uls[i].cur++;
	  /* debug(" [[prev %d: %p (%s/%d)]] ", i, uls[i].cur, ea_class_global[uls[i].cur->id]->name, uls[i].cur->id); */
	}

	if ((uls[i].cur >= uls[i].end) || (uls[i].cur->id > s0->id))
	  continue;

	prev = uls[i].cur;
	break;
      }

      /* Drop identicals */
      if (prev && eattr_same_value(s0, prev))
      {
	/* debug(" [[drop identical %s]] ", ea_class_global[s0->id]->name); */
	continue;
      }

      /* Drop undefs (identical undefs already dropped before) */
      if (!prev && s0->undef)
      {
	/* debug(" [[drop undef %s]] ", ea_class_global[s0->id]->name); */
	continue;
      }

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
ea_scan(const ea_list *e, u32 upto)
{
  unsigned cnt = 0;

  while (e)
    {
      cnt += e->count;
      e = e->next;
      if (e && BIT32_TEST(&upto, e->stored))
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
ea_merge(ea_list *e, ea_list *t, u32 upto)
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

      if (e && BIT32_TEST(&upto, e->stored))
	break;
    }

  t->next = e;
}

ea_list *
ea_normalize(ea_list *e, u32 upto)
{
#if 0
  debug("(normalize)");
  ea_dump(e);
  debug(" ----> ");
#endif
  ea_list *t = tmp_allocz(ea_scan(e, upto));
  ea_merge(e, t, upto);
  ea_sort(t);
#if 0
  ea_dump(t);
  debug("\n");
#endif

  return t;
}

static bool
eattr_same_value(const eattr *a, const eattr *b)
{
  if (
      a->id != b->id ||
      a->flags != b->flags ||
      a->type != b->type ||
      a->undef != b->undef
    )
    return 0;

  if (a->undef)
    return 1;

  if (a->type == T_PTR)
    return a->u.v_ptr == b->u.v_ptr;
  if (a->type & EAF_EMBEDDED)
    return a->u.data == b->u.data;
  else
    return adata_same(a->u.ptr, b->u.ptr);
}

static bool
eattr_same(const eattr *a, const eattr *b)
{
  return
    eattr_same_value(a, b) &&
    a->originated == b->originated &&
    a->fresh == b->fresh;
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
    if (!eattr_same(&x->attrs[c], &y->attrs[c]))
      return 0;
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

      rcu_read_lock();
      struct ea_class *cl = ea_class_global[a->id];
      ASSERT_DIE(cl && atomic_load_explicit(&cl->uc, memory_order_relaxed));
      rcu_read_unlock();

      CALL(cl->stored, a);
      atomic_fetch_add_explicit(&cl->uc, 1, memory_order_release);
    }

  if (l->next)
    ea_ref(l->next);
}

static void
ea_list_unref(ea_list *l)
{
  for(uint i=0; i<l->count; i++)
    {
      eattr *a = &l->attrs[i];
      ASSERT_DIE(a->id < ea_class_max);

      if (a->undef)
	continue;

      rcu_read_lock();
      struct ea_class *cl = ea_class_global[a->id];
      ASSERT_DIE(cl && atomic_load_explicit(&cl->uc, memory_order_relaxed));
      rcu_read_unlock();

      CALL(cl->freed, a);
      if (atomic_fetch_sub_explicit(&cl->uc, 1, memory_order_release) == 1)
	ea_class_free(cl);
    }

  if (l->next)
    ea_free_later(l->next);
}

void
ea_format_bitfield(const struct eattr *a, byte *buf, int bufsize, const char **names, int min, int max)
{
  byte *start = buf;
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

      buf += bsprintf(buf, "%s ", names[i]);
      data &= ~(1u << i);
    }

  if (data)
    bsprintf(buf, "%08x ", data);

  if (buf != start)
    buf--;

  *buf = 0;
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

  uint s = 0;

  if (ipa_nonzero(had->he->link) && !ipa_equal(had->he->link, had->he->addr))
    s = bsnprintf(buf, size, "via %I %I table %s", had->he->addr, had->he->link, had->he->owner->name);
  else
    s = bsnprintf(buf, size, "via %I table %s", had->he->addr, had->he->owner->name);

  uint lc = HOSTENTRY_LABEL_COUNT(had);
  if (!lc)
    return;

  s = bsnprintf((buf += s), (size -= s), " mpls");
  for (uint i=0; i < lc; i++)
    s = bsnprintf((buf += s), (size -= s), " %u", had->labels[i]);
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

  rcu_read_lock();
  struct ea_class *cls = ea_class_global[e->id];
  ASSERT_DIE(cls);
  rcu_read_unlock();

  if (e->undef || cls->hidden)
    return;

  const char *name = (c->v2attributes && !cls->conf) ? cls->legacy_name : cls->name;
  if (!name)
    return;

  if (cls->format)
    cls->format(e, buf, end - buf);
  else
    switch (e->type)
      {
	case T_INT:
	  if ((cls == &ea_gen_local_metric) && e->u.data >= IGP_METRIC_UNKNOWN)
	    bsprintf(pos, "unknown");
	  else
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
	  ea_show_int_set(c, name, ad, ISF_COMMUNITY_LIST, buf);
	  return;
	case T_ECLIST:
	  ea_show_ec_set(c, name, ad, buf);
	  return;
	case T_LCLIST:
	  ea_show_lc_set(c, name, ad, buf);
	  return;
	case T_STRING:
	  bsnprintf(pos, end - pos, "%s", (const char *) ad->data);
	  break;
	case T_NEXTHOP_LIST:
	  ea_show_nexthop_list(c, (struct nexthop_adata *) e->u.ptr);
	  return;
	case T_HOSTENTRY:
	  ea_show_hostentry(ad, pos, end - pos);
	  break;
	default:
	  bsprintf(pos, "<type %02x>", e->type);
      }

  cli_printf(c, -1012, "\t%s: %s", name, buf);
}

static void
nexthop_dump(struct dump_request *dreq, const struct adata *ad)
{
  struct nexthop_adata *nhad = (struct nexthop_adata *) ad;

  RDUMP(":");

  if (!NEXTHOP_IS_REACHABLE(nhad))
  {
    const char *name = rta_dest_name(nhad->dest);
    if (name)
      RDUMP(" %s", name);
    else
      RDUMP(" D%d", nhad->dest);
  }
  else NEXTHOP_WALK(nh, nhad)
    {
      if (ipa_nonzero(nh->gw)) RDUMP(" ->%I", nh->gw);
      if (nh->labels) RDUMP(" L %d", nh->label[0]);
      for (int i=1; i<nh->labels; i++)
	RDUMP("/%d", nh->label[i]);
      RDUMP(" [%s]", nh->iface ? nh->iface->name : "???");
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
ea_dump(struct dump_request *dreq, ea_list *e)
{
  int i;

  if (!e)
    {
      RDUMP("NONE");
      return;
    }
  while (e)
    {
      struct ea_storage *s = e->stored ? ea_get_storage(e) : NULL;
      RDUMP("[%c%c] overlay=%d uc=%d h=%08x",
	    (e->flags & EALF_SORTED) ? 'S' : 's',
	    (e->flags & EALF_BISECT) ? 'B' : 'b',
	    e->stored,
	    s ? atomic_load_explicit(&s->uc, memory_order_relaxed) : 0,
	    s ? s->hash_key : 0);
      for(i=0; i<e->count; i++)
	{
	  eattr *a = &e->attrs[i];
    rcu_read_lock();
	  struct ea_class *clp = (a->id < ea_class_max) ? ea_class_global[a->id] : NULL;
    rcu_read_unlock();
	  if (clp)
	    RDUMP(" %s", clp->name);
	  else
	    RDUMP(" 0x%x", a->id);

	  RDUMP(".%02x", a->flags);
	  RDUMP("=%c",
	      "?iO?IRP???S??pE?"
	      "??L???N?????????"
	      "?o???r??????????" [a->type]);
	  if (a->originated)
	    RDUMP("o");
	  if (a->undef)
	    RDUMP(":undef");
	  else if (a->type & EAF_EMBEDDED)
	    RDUMP(":%08x", a->u.data);
	  else if (a->id == ea_gen_nexthop.id)
	    nexthop_dump(dreq, a->u.ptr);
	  else
	    {
	      int j, len = a->u.ptr->length;
	      RDUMP("[%d]:", len);
	      for(j=0; j<len; j++)
		RDUMP("%02x", a->u.ptr->data[j]);
	    }
	  RDUMP(" ");
	}
      if (e = e->next)
	RDUMP(" | ");
    }
}

/**
 * ea_hash - calculate an &ea_list hash key
 * @e: attribute list
 *
 * ea_hash() takes an extended attribute list and calculated a hopefully
 * uniformly distributed hash value from its contents.
 */
uint
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

/**
 * DOC: Route attribute storage
 *
 * While local procesing of routes is done on local structures, the attributes
 * have to be stored to a global data structure to have sufficient lifetime.
 * The global storage also serves deduplication purposes, i.e. when an identical
 * attribute set is about to be stored, an existing structure is returned instead.
 *
 * All the globally-stored attribute sets have the attributes sorted by ID.
 *
 * The public interface consists of:
 *
 * - ea_lookup() to get the global instance of the given attribute list,
 *   or to bump its usecount
 * - ea_free() to decrease the instance's usecount, with possibly delayed free
 * - ea_lookup_tmp() to do ea_lookup() with ea_free() auto-called after the end
 *   of the task
 *
 * There are also several low-level interface functions and helpers.
 *
 * There may be attributes which need to recursively refer to another attribute set.
 * These attributes must have |stored| and |freed| hooks of their |struct ea_class|
 * defined.
 *
 * Description of the data structure follows; more detailed information is
 * directly in the code.
 *
 ***************************************
 * Internal structure of route storage *
 ***************************************
 *
 * Attribute lists, publicly available as |ea_list|, are stored as |ea_storage|
 * which contains the |ea_list| and adds storage-private data. One should not access
 * the |ea_storage| from |ea_list|, and definitely not change it.
 *
 * These |struct ea_storage| objects are arranged in a hash array
 * (array of linked lists) stored in the |rta_hash| table. This table
 * gets automatically rehashed by ea_rehash() whenever needed.
 *
 * The usecounts of |ea_storage| must be kept at 1 at all times. Whenever
 * the usecount reaches zero, it must not be increased again and the |ea_storage|
 * is waiting for free.
 *
 * There are two |ea_hash_array|s which are used to allow rehashing without hard locking.
 * These are switched atomically when the rehash is done. Rehash awareness is required
 * for reasonable lockless lookup and free.
 *
 **********
 * Lookup *
 **********
 *
 * The lookup function always checks whether it can return an already existing structure
 * containing the same data. Therefore, after normalizing the attribute set contents,
 * it calculates a hash value from its whole content, and looks into the hash array.
 *
 * If an entry is already there, the existing structure is returned, otherwise a new
 * structure is allocated and put there.
 *
 * That would work in one thread though. We need thread-safe operation and lockless
 * collision resolution. With that, the hash chain pass is done as RCU critical section,
 * and we can't do time-consuming operations during that. Even though in most cases,
 * mslab allocation is waitless (threads have pre-allocated objects), we may still
 * end up doing a syscall during allocation (mmap), and that's not acceptable.
 * Also very large objects (over 1.3k) use mutexes when allocating.
 *
 * Therefore, we do multiple passes. In the zeroth pass, we check for en existing entry.
 * If it is already there, the situation is the easiest, we can just use that,
 * and spare the allocation.
 *
 * Otherwise, we allocate the entry and run another pass. It may have happened
 * that another thread has just done exactly the same, and we may end up
 * re-using that entry. In such case, we simply refcount that, and de-allocate
 * our version. Otherwise, we put the item into the chain.
 *
 * But we may have run into a collision again with somebody putting their item
 * into the chain. That is unfortunate, and therefore we try pass 2, with the
 * same objective as with pass 1: check for collisions, insert.
 *
 * We are not infinitely patient though, and on the pass 3, if we encounter
 * a collision again, we stop checking the chain and just insert the entry.
 * That may lead to deduplication, and therefore we issue a warning in such case.
 * While developing and stress testing, we have never managed to actually trigger it.
 *
 * Note: There may be situations where we encounter an entry which is about
 * to be removed. We ignore these entries.
 *
 *************
 * Use count *
 *************
 *
 * The entries are use-counted. That is an easy way to track their lifetimes
 * but it brings another catch. What if one thread tries to insert an entry at
 * the same time as another thread is deleting it?
 *
 * First, we would like to refuse to increase usecounts which are already zero.
 * That is not so easy though. The easy approach would be that both lookup
 * and free first fetch the count, locally increment/decrement, and then
 * they try to atomically exchange it for the previous value.
 *
 * Yet, when these collide, the cache gets invalidated over and over again,
 * and in our measurements, the allocation times were severely hampered by waiting
 * for the usecount update.
 *
 * While the allocations are scattered quite randomly all around the time
 * in locked contexts of various degrees, free is by default deferred to the
 * end of the task, almost always happens in batches, and does not hold
 * any additional lock. Therefore, we want to speed up allocations.
 *
 *****************************
 * Free: Marking for removal *
 *****************************
 *
 * The whole entry removal ordeal begins with lowering the usecount, and
 * if we are lucky, it is still more than one.
 *
 * If the usecount becomes zero, the hard time starts. It may have been so
 * that the allocator has just found this entry, and raised the usecount again.
 * While we could, in the allocator, first read the usecount and then decide,
 * it's slow (see above). Instead, the allocator just comes, increments,
 * and is done (almost).
 *
 * The allocator also can't simply check for zero usecount after the increment.
 * While that may be seen by the allocator, another allocating thread may have
 * come just after that, seen |uc == 1|, and considered the entry proper again.
 * Or even worse, there may be multiple threads serializing in the most peculiar ways.
 *
 * Therefore, we need a flag. Whenever the usecount becomes zero, the thread
 * subsequently tries to atomically replace that zero by |EA_FREE_FLAG|,
 * which is a very high value reserved for an entry which is about to be
 * removed from the chain. Suddenly, either at least one of the allocating
 * threads has serialized before this, and therefore the zero replacement
 * fails (because the entry has been revived), or they serialize after the
 * exchange, and they now see the flag, and can back off.
 *
 * As soon as the entry is successfully flagged, it can be safely removed from the chain.
 *
 ******************************************
 * Free: Actually removing from the chain *
 ******************************************
 *
 * Chain removal is not safe when multiple threads are removing at once,
 * and there is a well-known race condition between two linked-list deleters,
 * mistakenly reviving an item. Therefore we need to avoid multiple deleters
 * running in parallel. Also, to delete an item, one has to walk the chain from
 * the beginning, to find the ancestor.
 *
 * There is a parallel atomic integer array |delist|, which has an entry
 * for every chain in the table. That entry is a hybrid semaphore-spinlock.
 *
 * Every deleter increments the appropriate |delist| entry when it's
 * about to remove an item from a chain. The first one wins the cleanup job,
 * starts walking the chain and removing items. All other deleters find out
 * that the cleaner is running right now, and they just let go.
 *
 * The removal is just pointer manipulation, and it does not collide with
 * allocation, with the exception of the very first entry in the list,
 * where it may cause an additional lookup pass.
 *
 * When the cleaner is done with removing one item, it decrements the
 * |delist| entry but it continues with removing more entries until the
 * entry is zero again. This loop could, theoretically, be infinite, but
 * considering the workload characteristics, it's very improbable.
 *
 * There could be also a race condition where another cleaner marks an entry
 * for deletion, and the cleaner removes that from the chain before the
 * |delist| counter could get incremented. However, that means that
 * there was another deletion pending, and the cleaner just picked the new one.
 *
 * If the cleaner ends before all finished entries are removed from the chain,
 * it must have been caused by some other threads not yet incrementing the
 * |delist| counter, and one of them will inevitably become the new cleaner,
 * keeping the balance.
 *
 *********************************
 * Free: Deallocating the memory *
 *********************************
 *
 * We must not immediately return the memory block to the mslab, that would be
 * a gross negligence punishable by segfault. Even though the entry has been removed
 * from the list, there may still be an allocator thread holding a pointer to that,
 * sleeping just before checking the usecount (where it would find out that it is
 * indeed bad and ultimately retry).
 *
 * We could simply call synchronize_rcu() to actively wait until all these sleeping
 * threads get flushed but that adds a lot of overhead when freeing hundreds of thousands
 * of routes at once. Instead, we collect these items into a defer call structure,
 * storing the current RCU phase with them, and only after all the chain removals
 * are done, the deferred call waits for RCU synchronization once for all removed entries.
 *
 * Then, and only then, are the entries returned to the mslab.
 *
 *************
 * Rehashing *
 *************
 *
 * Hold on a minute. The hash array is not constantly sized, and it must grow with
 * the amount of actually stored entries. Therefore, all the operations keep track
 * of the number of items inside the whole structure, and whenever the total amount
 * gets over or under certain threshold, the hash array grows or shrinks.
 *
 * The rehash does not lock. Instead, it double-uses the already existing mechanisms
 * to avoid collisions. The only locking mechanism it uses, is the fixation of this
 * task into the main thread, making it impossible to collide two rehashes at once.
 *
 * First, it allocates all the new structures aside, and initializes them. Most notably,
 * it initializes all the new |delist| entries to 1. The fully
 * initialized |ea_hash_array| is then atomically released, with RCU synchronization
 * to flush all previous readers before actually starting the rehash procedure.
 *
 * Lookups always check both arrays whenever rehash is running, and they always
 * add entries to the new one. And free is even easier -- if freeing from
 * a not-yet-rehashed chain, it sees |delist| initialized to 1, and backs off.
 * The rehash routine then simply drops all obsolete entries when rehashing.
 */

#define EA_MIN_ORDER			12
#define EA_FREE_FLAG			(1ULL << 60)
#define EA_FREE_STORAGE_DEFER_MAX	32
#define EA_REHASH_HISTOGRAM		32
#define EA_REHASH_HISTOGRAMS_KEPT	128
#define EA_HASH_UP_RATIO_1024		2048ULL
#define EA_HASH_DOWN_RATIO_1024		128ULL

#define EA_HASH_POOL		rta_pool


enum ea_lookup_pass {
  EA_LOOKUP_FIND,
  EA_LOOKUP_INSERT,
  EA_LOOKUP_RETRY,
  EA_LOOKUP_FORCE,
  EA_LOOKUP_MAX,
};

static struct ea_hash_head {
  struct ea_hash_array {
    struct ea_storage *_Atomic *eas;	/* Hash array of ea_storages */
    _Atomic u16 *delist;		/* Cleaning markers (array of same size as eas) */
    _Atomic uint order;			/* Size of eas is 1 << order; inactive if zero */
  } instance[2];			/* Two arrays to switch on rehash */
  _Atomic u8 cur;			/* Index for instance */
  _Atomic uint count;			/* Total number of stored ea_storages */
  event rehash_event;
  _Atomic u64 pass_cnt[EA_LOOKUP_MAX];	/* Total number of runs by pass */
  _Atomic u64 retry_cnt;		/* Total number of EA_LOOKUP_FORCE retries */
  _Atomic u64 insert_cnt;		/* Total number of attributes ever inserted */
  _Atomic u64 free_cnt;			/* Total number of attributes ever removed */
  _Atomic u64 found_cnt;		/* Total number of lookups without allocataion */
  _Atomic u64 sdc_hist[EA_FREE_STORAGE_DEFER_MAX+1];	/* Instances of ea_free_storage_deferred by size */
  _Atomic u64 sdc_retries;		/* Total number of ea_free_storage_deferred retries */
  _Atomic u64 delist_hist[EA_FREE_STORAGE_DEFER_MAX+1];	/* Delist loops by length; capped at 32 */
  _Atomic u64 delist_loops_cnt;		/* Total number of delist loops running */
  _Atomic u64 delist_collision_cnt;	/* Total number of delist-alloc collisions */
  _Atomic u64 delist_avoided_cnt;	/* Total number of occurences of delist already running */
  struct rehash_info {
    u64 hist[EA_REHASH_HISTOGRAM+1];	/* Rehash collision histograms */
    btime start;			/* When started */
    btime end;				/* When ended */
    uint orig_order;			/* Original order */
    uint next_order;			/* Final order */
    uint max_chain;			/* Longest chain seen  */
    uint delist_loops;			/* Delist loops active */
  } rehash_info[EA_REHASH_HISTOGRAMS_KEPT];	/* Ringbuffer of rehash info */
  uint total_rehash_cnt;		/* How many rehashes happened */
  uint rehashes_aborted;		/* How many rehashes were requested but not needed */
  btime total_rehash_time;		/* How long the rehashes lasted in total */
} rta_hash_table;


/* Rehash indicators */

static bool
ea_needs_rehash_up(const uint count, const uint order)
{
  return count * 1024 > (EA_HASH_UP_RATIO_1024 << order);
}

static bool
ea_needs_rehash_down(const uint count, const uint order)
{
  return (order > EA_MIN_ORDER) && (count * 1024 < (EA_HASH_DOWN_RATIO_1024 << order));
}

static void
ea_maybe_schedule_rehash(uint count, uint order)
{
  if (ea_needs_rehash_up(count, order) || ea_needs_rehash_down(count, order))
    ev_send(&global_work_list, &rta_hash_table.rehash_event);
}

/* Count updaters */

static void
ea_count_up(uint order)
{
  atomic_fetch_add_explicit(&rta_hash_table.insert_cnt, 1, memory_order_relaxed);

  uint count = atomic_fetch_add_explicit(&rta_hash_table.count, 1, memory_order_relaxed);
  ea_maybe_schedule_rehash(count, order);
}

static void
ea_count_down(uint order)
{
  atomic_fetch_add_explicit(&rta_hash_table.free_cnt, 1, memory_order_relaxed);

  uint count = atomic_fetch_sub_explicit(&rta_hash_table.count, 1, memory_order_relaxed);
  ea_maybe_schedule_rehash(count, order);
}

/*
 * EA Lookup and allocation
 */

/* Lookup for ea_storage in the given hash array */
struct ea_chain_info {
  struct ea_storage * _Atomic *chain;
  struct ea_storage *first, *found;
  uint order;
};

static bool
ea_find_in_array(struct ea_chain_info *f, u8 iidx, ea_list *o, u32 squash_upto, uint h)
{
  /* Get instance pointer and info */
  struct ea_hash_array *arr = &rta_hash_table.instance[iidx];
  uint order = atomic_load_explicit(&arr->order, memory_order_acquire);

  /* Inactive instance, keep old info */
  if (!order)
    return false;

  uint idx = h >> (32 - order);
  f->chain = &arr->eas[idx];
  f->first = atomic_load_explicit(f->chain, memory_order_acquire);
  f->order = order;

  for (struct ea_storage *eap = f->first; eap;
      eap = atomic_load_explicit(&eap->next_hash, memory_order_acquire))

    if ((h == eap->hash_key) && ea_same(o, eap->l) &&
	BIT32_TEST(&squash_upto, eap->l->stored))
      /* We found a suitable ea_storage. Lets increment its use count. */

      if (EA_FREE_FLAG &
	  atomic_fetch_add_explicit(&eap->uc, 1, memory_order_relaxed))

	/* Too late, this ea_storage is about to be freed. */
	atomic_fetch_sub_explicit(&eap->uc, 1, memory_order_relaxed);

      else
	/* Successfully usecounted */
	return (f->found = eap), true;

  return false;
}

/* Allocate ea_storage and prepare for chain insertion */
static struct ea_storage*
ea_alloc_storage(ea_list *o, enum ea_stored oid, uint h)
{
  struct ea_storage *r_new = NULL;

  /* Allocation is done from slabs of fixed lengths, find the smallest
   * where this object fits */
  uint elen = ea_list_size(o);
  uint sz = elen + sizeof(struct ea_storage);
  for (uint i = 0; i < ARRAY_SIZE(ea_slab_sizes); i++)
    if (sz <= ea_slab_sizes[i])
    {
      r_new = msl_alloc(ea_slab[i]);
      break;
    }

  /* Too big for slabs, allocate with locking */
  int huge = r_new ? 0 : EALF_HUGE;
  if (huge)
  {
    RTA_LOCK;
    r_new = mb_alloc(EA_HASH_POOL, sz);
    RTA_UNLOCK;
  }

  /* Copy data to storage */
  ea_list_copy(r_new->l, o, elen);
  r_new->l->flags |= huge;
  r_new->l->stored = oid;

  /* Initialize table-internal data */
  r_new->hash_key = h;
  atomic_store_explicit(&r_new->uc, 1, memory_order_relaxed);

  return r_new;
}

/* Fast-free if found after allocation */
static void
ea_free_storage(struct ea_storage *eap)
{
  if (!eap)
    return;

  if (eap->l->flags & EALF_HUGE)
  {
    RTA_LOCK;
    mb_free(eap);
    RTA_UNLOCK;
  } else
    msl_free(eap);
}

/**
 * ea_lookup_slow - find and reference the given ea_list
 * @o: list to insert
 * @squash_upto: storage levels to stop where squashing (bitmask)
 * @oid: the storage level of this ea_list
 *
 * Expects a locally-allocated ea_list, possibly with multiple layers,
 * possibly atop another already cached ea_list. Performs normalization,
 * squashing and cache lookup.
 *
 * Returns a globally-available ea_list object with a use count already incremented.
 * The caller must subsequently explicitly call ea_free() to unreference the object.
 */
ea_list *
ea_lookup_slow(ea_list *o, u32 squash_upto, enum ea_stored oid)
{
  /* Consistency checks and normalization */
  ASSERT(o->stored != oid);
  ASSERT(oid);
  o = ea_normalize(o, squash_upto);
  uint h = ea_hash(o);
  squash_upto |= BIT32_VAL(oid);

/* Try find and ref given ea_list in rta_hash_table, or store it if not found.
 * Lookup is done in up to four passes:
 * 0) Not allocating anything, only try to find given ea_list. If not found,
 *    (or found, but with already zero usecount), pass fails. We do this because
 *    allocating may sometimes be too slow. Besides, most of the lookups are
 *    expected to actually do find the eattr.
 * 1) Allocate the ea_storage in advance, because we do not want to do that
 *    in the critical section. Try to find the ea_list again, if not found, try
 *    to add it. If somebody added od removed the head of linked list with given hash,
 *    next pass will be proceed.
 * 2) Storage already allocated, try to find and add.
 * 3) Storage still allocated. If eattr not found, just keep inserting the ea_storage
 *    until success. This might result in duplicates, but we have spend too much time here.
 */

  struct ea_storage *new = NULL;

  for (enum ea_lookup_pass pass = EA_LOOKUP_FIND; pass < EA_LOOKUP_MAX; pass++)
  {
    switch (pass) {
      case EA_LOOKUP_INSERT:
	/* For the first time, we hope for finding and we do not want prealocated r_new.
	 * We allocate it in the second pass and later we will already have it. */
	new = ea_alloc_storage(o, oid, h);
	break;

      case EA_LOOKUP_FORCE:
	log(L_WARN "Attribute cache lookup collision, deduplication may be suboptimal.");
	break;

      default:
	break;
    }

    /* Entering critical section to avoid collision with rehash and free */
    rcu_read_lock();

    /* Load which array is active */
    u8 icur = atomic_load_explicit(&rta_hash_table.cur, memory_order_acquire);

    /* Lookup in order; find either an entry or at least the appropriate chain.
     * If found anywhere, we're done. If not, r.chain and r.first are set to the
     * rehash-next array chain, and if not rehashing, to the current one.
     */
    struct ea_chain_info r = {};
    if (ea_find_in_array(&r, icur, o, squash_upto, h)
	|| ea_find_in_array(&r, 1-icur, o, squash_upto, h))
    {
      /* Found, we're done! */
      rcu_read_unlock();

      ea_free_storage(new);
      atomic_fetch_add_explicit(&rta_hash_table.pass_cnt[pass], 1, memory_order_relaxed);
      atomic_fetch_add_explicit(&rta_hash_table.found_cnt, 1, memory_order_relaxed);

      return r.found->l;
    }

    /* Can't insert on first pass */
    if (pass == EA_LOOKUP_FIND)
    {
      rcu_read_unlock();
      continue;
    }

    /* Consistency check */
    ASSERT_DIE(r.chain);

    /* Insert the object to the first place of the chain we have found.
     * If in the last phase, retry forcibly. */
    uint retry_count = 0;
    do atomic_store_explicit(&new->next_hash, r.first, memory_order_release);
    while (!atomic_compare_exchange_strong_explicit(
	  r.chain, &r.first, new,
	  memory_order_acq_rel, memory_order_acquire)
	&& ++retry_count && (pass == EA_LOOKUP_FORCE));

    /* Leaving the critical section, the rehasher may now proceed. */
    rcu_read_unlock();

    /* Successfully inserted */
    if (!retry_count || (pass == EA_LOOKUP_FORCE))
    {
      /* Update statistics */
      ea_count_up(r.order);
      atomic_fetch_add_explicit(&rta_hash_table.pass_cnt[pass], 1, memory_order_relaxed);
      atomic_fetch_add_explicit(&rta_hash_table.retry_cnt, retry_count, memory_order_relaxed);

      /* Finalize the list by referencing child storages and return. */
      ea_list_ref(new->l);
      return new->l;
    }

    /* Retrying */
  }

  bug("Exited ea_lookup_slow() insert loop without return!");
}

/*
 * EA Free
 */

/* Deferred final storage free. This must run after yet another RCU synchronization
 * to avoid collisions with chain walks in ea_lookup_slow(). It's inefficient
 * to wait for RCU synchronously for every single EA, and therefore we simply defer
 * the final free to the defer caller */

struct ea_free_storage_deferred_call {
  struct deferred_call dc;
  struct rcu_stored_phase phase;
  struct ea_storage *attrs[EA_FREE_STORAGE_DEFER_MAX];
  int count;
};

/* Every thread keeps its last already-deferred call, so that subsequent frees spare
 * some memory. Freeing attributes often comes in batches. */
_Thread_local struct ea_free_storage_deferred_call *ea_free_storage_deferred_call;

static void
ea_free_storage_deferred(struct deferred_call *dc)
{
  /* Free an ea_storrage in defer call */
  SKIP_BACK_DECLARE(struct ea_free_storage_deferred_call, efsdc, dc, dc);

  /* Drop the cached call */
  if (efsdc == ea_free_storage_deferred_call)
    ea_free_storage_deferred_call = NULL;

  if (!rcu_end_sync(efsdc->phase))
  {
    /* Somebody may still have the pointer to a storage in dc, retry later */
    defer_call(dc, sizeof *efsdc);
    atomic_fetch_add_explicit(&rta_hash_table.sdc_retries, 1, memory_order_relaxed);
    return;
  }

  /* Update stats */
  ASSERT_DIE(efsdc->count <= EA_FREE_STORAGE_DEFER_MAX);
  atomic_fetch_add_explicit(&rta_hash_table.sdc_hist[efsdc->count], 1, memory_order_relaxed);

  for (int i = 0; i < efsdc->count; i++)
  {
    struct ea_storage *r = efsdc->attrs[i];
    ASSERT_DIE(atomic_load_explicit(&r->uc, memory_order_relaxed) == EA_FREE_FLAG);

    ea_list_unref(r->l);
    ea_free_storage(r);
  }
}

/* Loop removing attribute sets from the given chain */
static void
ea_free_delist_loop(struct ea_storage * _Atomic *chain, _Atomic u16 *delist)
{
  /* Once we are here, we will delist eligible items from the given chain.
   * No one else will perform cleaning or rehash until we leave.
   * Access to this function is given only to the first thread which sets the marker
   * in |delist| array from zero to one.
   *
   * This function looks for the first ea_storage to remove from the list. It removes it,
   * decrements |delist|, and if it isn't zero, it continues searching.
   *
   * The loop only ends when |delist| is zero, and in every other case, it consumes
   * more delist requests from that specific chain. It is expected that hash
   * collisions almost never happen.
   *
   * The only thing we truly do not want collide with is a rehash. That is why
   * this whole function is called inside RCU critical section, so that rehash doesn't
   * invalidate the chain inbetween. But we also call this function from the rehash
   * itself, and it doesn't need to be RCU critical there, because it doesn't collide
   * with itself.
   */
  uint count = 0;

  /* Repeatedly walk the ea_storage linked list. We may need to retry if more work
   * is requested from another thread. Start at the beginning. */

  struct ea_storage * _Atomic *prev = chain;
  bool restarted = true;

  while (true)
  {
    struct ea_storage *eap = atomic_load_explicit(prev, memory_order_relaxed);

    /* Restart at the end of the loop */
    if (!eap)
    {
      if (restarted)
	bug("Delist loop restarted twice without work");

      restarted = true;
      prev = chain;
      continue;
    }

    /* Check delist eligibility */
    u64 uc = atomic_load_explicit(&eap->uc, memory_order_relaxed);
    if (!(uc & EA_FREE_FLAG))
    {
      prev = &eap->next_hash;
      continue;
    }

    /* Delisting this eap */
    restarted = false;
    count++;

    /* Load the next pointer */
    struct ea_storage *next = atomic_load_explicit(&eap->next_hash, memory_order_relaxed);

    /* Removing the first item might result in race with adding */
    struct ea_storage *old = eap;
    if (!atomic_compare_exchange_strong_explicit(prev, &old, next, memory_order_acq_rel, memory_order_relaxed))
    {
      /* Update stats */
      atomic_fetch_add_explicit(&rta_hash_table.delist_collision_cnt, 1, memory_order_relaxed);

      /* But the item must be there somewhere deeper, find it */
      while (old != eap)
      {
	prev = &old->next_hash;
	old = atomic_load_explicit((prev = &old->next_hash), memory_order_relaxed);
	ASSERT_DIE(old);
      }

      /* This is no longer the first item, no race with adding (or anything else) */
      ASSERT_DIE(atomic_compare_exchange_strong_explicit(prev, &eap, next,
	    memory_order_acq_rel, memory_order_relaxed));
    }

    struct ea_free_storage_deferred_call *def = ea_free_storage_deferred_call;

    if (def)
    {
      /* Insert eap into existing storage deferred call */
      def->attrs[def->count++] = eap;

      /* We need to push the RCU phase forwards to match this eap being removed. */
      def->phase = rcu_begin_sync();

      /* Deferred call is full */
      if (def->count == EA_FREE_STORAGE_DEFER_MAX)
	ea_free_storage_deferred_call = NULL;
    }
    else
    {
      struct ea_free_storage_deferred_call efsdc = {
	.dc.hook = ea_free_storage_deferred,
	.phase = rcu_begin_sync(), /* Asynchronous wait for RCU */
	.attrs = { eap },
	.count = 1,
      };

      /* Store the deferred call for later additions */
      ea_free_storage_deferred_call = DEFER_CALL(efsdc);
    }

    if (atomic_fetch_sub_explicit(delist, 1, memory_order_acq_rel) == 1)
    {
      /* Update stats */
      if (count > EA_FREE_STORAGE_DEFER_MAX)
	count = EA_FREE_STORAGE_DEFER_MAX;

      atomic_fetch_add_explicit(&rta_hash_table.delist_hist[count], 1, memory_order_relaxed);
      atomic_fetch_add_explicit(&rta_hash_table.delist_loops_cnt, 1, memory_order_relaxed);

      /* Dobby is free! We cleaned everything we could, returning */
      return;
    }

    /* Someone gave us more work to do, we have to continue */
  }
}

/**
 * ea_free_deferred - defer callback to process unreferencing of ea_storage
 * @dc: the deferred call
 *
 * This callback is scheduled by ea_free() and ea_free_later(), to use-uncount
 * one |ea_storage|. The callback runs as a deferred call to ensure that
 * the user may actually get an easy reference with task-local lifetime.
 */
void
ea_free_deferred(struct deferred_call *dc)
{
  struct ea_storage *r = ea_get_storage(SKIP_BACK(struct ea_free_deferred, dc, dc)->attrs);

  /* Usecount is zero now. The item needs to be removed. Entering critical section
   * to avoid collisions with rehash or rarely with other free. */
  rcu_read_lock();

  /* Check whether this is the last user */
  u64 uc = atomic_fetch_sub_explicit(&r->uc, 1, memory_order_acq_rel);
  if (uc != 1)
  {
    /* Someone else has a reference to this ea_storage. We can just decrease use count. */
    ASSERT_DIE(uc > 0); /* Check this is not a double free. */
    rcu_read_unlock();
    return;
  }

  u64 flag = EA_FREE_FLAG;
  u64 null = 0;
  u32 hash_key = r->hash_key;

  /* Someone managed to increase the use count. No need to free the storage. */
  if (!atomic_compare_exchange_strong_explicit(&r->uc, &null, flag, memory_order_acq_rel, memory_order_acquire))
  {
    rcu_read_unlock();
    return;
  }

  /* By marking the structure delistable, it may immediatelly disappear
   * if another thread is running cleanup on the same chain right now.
   * NULLing just to be sure nobody later decides to use it here. */
  r = NULL;

  /* Find the appropriate array. */
  u8 iidx = atomic_load_explicit(&rta_hash_table.cur, memory_order_acquire);
  struct ea_hash_array *esa = &rta_hash_table.instance[iidx];
  struct ea_hash_array *next = &rta_hash_table.instance[1-iidx];
  uint order = atomic_load_explicit(&next->order, memory_order_acquire);
  if (order)
    esa = next;
  else
    order = atomic_load_explicit(&esa->order, memory_order_acquire);

  ASSERT_DIE(order);
  ea_count_down(order);
  uint idx = hash_key >> (32 - order);

  /* Mark pending delisting */
  _Atomic u16 *delist = &esa->delist[idx];
  if (0 == atomic_fetch_add_explicit(delist, 1, memory_order_acq_rel))
    /* Nobody else is cleaning up. Our job. */
    ea_free_delist_loop(&esa->eas[idx], delist);
  else
    /* Update stats */
    atomic_fetch_add_explicit(&rta_hash_table.delist_avoided_cnt, 1, memory_order_relaxed);

  rcu_read_unlock();
}

/*
 * EA rehashing
 */

/* rehash running from event hook, scheduled by ea_maybe_schedule_rehash() */
static void
ea_rehash(void *_ UNUSED)
{
  /* Load data */
  u8 cur = atomic_load_explicit(&rta_hash_table.cur, memory_order_relaxed);

  struct ea_hash_array *orig = &rta_hash_table.instance[cur];
  u32 orig_order = atomic_load_explicit(&orig->order, memory_order_relaxed);

  struct ea_hash_array *next = &rta_hash_table.instance[1-cur];
  ASSERT_DIE(atomic_load_explicit(&next->order, memory_order_relaxed) == 0);

  /* Calculate new order */
  uint count = atomic_load_explicit(&rta_hash_table.count, memory_order_relaxed);
  u32 next_order = orig_order;

  while (ea_needs_rehash_up(count, next_order))
    next_order++;

  while (ea_needs_rehash_down(count, next_order))
    next_order--;

  if (next_order < orig_order - 1)
    next_order--;

  else if (next_order > orig_order + 1)
    next_order++;

  else
  {
    rta_hash_table.rehashes_aborted++;
    return;
  }

  /* Update stats */
  struct rehash_info *rhi = &rta_hash_table.rehash_info[rta_hash_table.total_rehash_cnt++ % ARRAY_SIZE(rta_hash_table.rehash_info)];
  *rhi = (struct rehash_info) {
    .start = current_time_now(),
    .orig_order = orig_order,
    .next_order = next_order,
  };

  /* Prepare new array */
  ASSERT_DIE(next->eas == NULL);

  RTA_LOCK;
  struct ea_storage * _Atomic * new_array = next->eas =
    mb_allocz(EA_HASH_POOL, sizeof(struct ea_storage *_Atomic) * (1 << next_order));

  _Atomic u16 * delist = next->delist =
    mb_alloc(EA_HASH_POOL, sizeof(_Atomic u16) * (1 << next_order));
  RTA_UNLOCK;

  /* Initialize delist to one so that all freeing threads let us do it */
  for (int i = 0; i < 1 << next_order; i++)
    atomic_store_explicit(&delist[i], 1, memory_order_relaxed);

  /* Setting the order causes other threads to start noticing the new array */
  atomic_store_explicit(&next->order, next_order, memory_order_release);

  /* We need all threads working with ea_storages to know there is new array.
   * Once threads notice new array, they add items only to the new array and
   * do not remove any items from the old one.
   *
   * Also, more importantly, after this call, ea_free_delist_loop() is inhibited.
   * All previously running must have ended (it runs inside RCU critical section)
   * and now the |delist| array is all ones and it will stay this way.
   */
  synchronize_rcu();

  /* The rehash procedure must not obscure any entry from lookups. Yet, if we used
   * the usual linked-list procedure to pop the old list and push the new one,
   * there would be short periods of time when some parts of the chain would not be
   * linked from anywhere apart from local variables.
   *
   * Therefore, we use an auxiliary array to store all the pointers, and we transfer
   * the chain members from the end of the chain. That approach keeps the
   * original chain intact, and in worst case lookup would see several entries
   * multiple times. That's acceptable. Also, notably, no transient pointer
   * cycle is ever created here.
   */
  uint rehash_array_len = EA_REHASH_HISTOGRAM;
  struct ea_storage **rha = tmp_alloc(sizeof(struct ea_storage *) * rehash_array_len);

  for (uint i = 0; i < (1U << orig_order); i++)
  {
    uint cnt = 0;

    /* Dump the original chain into the temporary array */
    for (struct ea_storage *ea = atomic_load_explicit(&orig->eas[i], memory_order_relaxed);
	ea; ea = atomic_load_explicit(&ea->next_hash, memory_order_relaxed))
    {
      ASSERT_DIE(ea && atomic_load_explicit(&ea->next_hash, memory_order_relaxed)!=ea);

      /* Too many entries in one chain, realloc up */
      if (cnt >= rehash_array_len)
      {
	struct ea_storage **rha_tmp = tmp_alloc(sizeof(struct ea_storage *) * (rehash_array_len *= 2));
	for (uint k = 0; k < cnt; k++)
	  rha_tmp[k] = rha[k];

	rha = rha_tmp;
      }

      rha[cnt++] = ea;
    }

    /* Update stats */
    if (cnt > rhi->max_chain)
      rhi->max_chain = cnt;

    if (cnt > EA_REHASH_HISTOGRAM)
      rhi->hist[EA_REHASH_HISTOGRAM]++;
    else
      rhi->hist[cnt]++;

    /* Insert the original chain entries into the new chain(s) */
    while (cnt > 0)
    {
      struct ea_storage *eap = rha[--cnt];
      uint idx = eap->hash_key >> (32 - next_order);

      /* Store to the linked list in new array. There might be race with adding. */
      struct ea_storage *first = atomic_load_explicit(&new_array[idx], memory_order_acquire);
      do atomic_store_explicit(&eap->next_hash, first, memory_order_release);
      while (!atomic_compare_exchange_strong_explicit(
	    &new_array[idx], &first, eap,
	    memory_order_acq_rel, memory_order_acquire));
    }

    /* Finally unlink from the original array */
    atomic_store_explicit(&orig->eas[i], NULL, memory_order_release);
    ASSERT_DIE(atomic_load_explicit(&orig->delist[i], memory_order_relaxed) == 0);
  }

  /* Mark the original array invalid to further reduce double-lookups */
  atomic_store_explicit(&orig->order, 0, memory_order_release);

  /* Mark the new array current */
  ASSERT_DIE(atomic_exchange_explicit(&rta_hash_table.cur, 1 - cur, memory_order_release) == cur);

  /* Actually, start the second RCU synchronization now. The new array is already in place.
   * We'll use the waiting time to finish the delisting which came after rehash started.
   * The delisting does not need to be critical if called from here; nobody else will touch that,
   * apart from lookups, but there is no problem with that at all. And because we inhibited the
   * delisting before the whole rehash, nothing can get freed from here neither.
   */
  struct rcu_stored_phase phase = rcu_begin_sync();

  /* Cleaning was suspended for the rehash, we have to clean now. */
  for (int i = 0; i < (1 << next_order); i++)
    /* Substract the one we added */
    if (atomic_fetch_sub_explicit(&delist[i], 1, memory_order_acq_rel) != 1)
    {
      /* Something needs to be delisted in this chain */
      ea_free_delist_loop(&new_array[i], &delist[i]);
      rhi->delist_loops++;
    }

  /* Finalize the waiting, so that we can free the original hash arrays */
  while (!rcu_end_sync(phase))
    birdloop_yield();

  /* Now we can be sure that everybody has seen that orig->order is zero, and therefore
   * they won't read the array pointers. */

  RTA_LOCK;
  mb_free(orig->eas);
  mb_free(orig->delist);
  RTA_UNLOCK;

  orig->eas = NULL;
  orig->delist = NULL;

  /* Update stats */
  rhi->end = current_time_now();
  rta_hash_table.total_rehash_time += rhi->end - rhi->start;
}

/**
 * rta_dump_all - dump attribute cache
 *
 * This function dumps the whole contents of route attribute cache
 * to the debug output.
 */
void
ea_dump_all(struct dump_request *dreq)
{
  u8 iidx = atomic_load_explicit(&rta_hash_table.cur, memory_order_relaxed);

  /* Consistency check: Dump runs from main birdloop, as well as rehash. */
  ASSERT_DIE(atomic_load_explicit(&rta_hash_table.instance[1-iidx].order, memory_order_relaxed) == 0);
  struct ea_hash_array *esa = &rta_hash_table.instance[iidx];

  uint order = atomic_load_explicit(&esa->order, memory_order_relaxed);
  ASSERT_DIE(order);

  RDUMP("Route attribute cache (%d entries, order %d):\n",
      atomic_load_explicit(&rta_hash_table.count, memory_order_relaxed),
      order);

  for (uint i = 0; i < 1U << (order); i++)
  {
    for (
	struct ea_storage *eap = atomic_load_explicit(&esa->eas[i], memory_order_acquire);
	eap; eap = atomic_load_explicit(&eap->next_hash, memory_order_acquire))
    {
      RDUMP("%p ", eap);
      ea_dump(dreq, eap->l);
      RDUMP("\n");
    }
  }

  RDUMP("\n");
}

void
ea_show_list(struct cli *c, ea_list *eal)
{
  ea_list *n = ea_normalize(eal, 0);

  for (int i = 0; i < n->count; i++)
    ea_show(c, &n->attrs[i]);
}

static void
ea_init_hash_table(void)
{
  rta_hash_table = (struct ea_hash_head) {
    .instance[0] = {
      .eas = mb_allocz(EA_HASH_POOL, sizeof(struct ea_storage * _Atomic) * (1 << EA_MIN_ORDER)),
      .delist = mb_allocz(EA_HASH_POOL, sizeof(_Atomic u16) * (1 << EA_MIN_ORDER)),
      .order = EA_MIN_ORDER,
    },
    .rehash_event.hook = ea_rehash,
  };
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
  attrs_domain = DOMAIN_NEW(attrs);

  RTA_LOCK;
  rta_pool = rp_new(&root_pool, attrs_domain.attrs, "Attributes");

  for (uint i=0; i<ARRAY_SIZE(ea_slab_sizes); i++)
    ea_slab[i] = msl_new(rta_pool, &global_work_list, ea_slab_sizes[i]);

  ea_init_hash_table();

  rte_src_init();
  ea_class_init();

  RTA_UNLOCK;

  /* These attributes are required to be first for nice "show route" output */
  ea_register_init(&ea_gen_nexthop);
  ea_register_init(&ea_gen_hostentry);
  ea_register_init(&ea_gen_hostentry_version);

  /* Other generic route attributes */
  ea_register_init(&ea_gen_preference);
  ea_register_init(&ea_gen_igp_metric);
  ea_register_init(&ea_gen_local_metric);
  ea_register_init(&ea_gen_from);
  ea_register_init(&ea_gen_source);
  ea_register_init(&ea_gen_flowspec_valid);

  /* MPLS route attributes */
  ea_register_init(&ea_gen_mpls_policy);
  ea_register_init(&ea_gen_mpls_class);
  ea_register_init(&ea_gen_mpls_label);

  /* ASPA providers */
  ea_register_init(&ea_gen_aspa_providers);
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
