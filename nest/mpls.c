/*
 *	BIRD Internet Routing Daemon -- MPLS Structures
 *
 *	(c) 2022 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: MPLS
 *
 * The MPLS subsystem manages MPLS labels and handles their allocation to
 * MPLS-aware routing protocols. These labels are then attached to IP or VPN
 * routes representing label switched paths -- LSPs. MPLS labels are also used
 * in special MPLS routes (which use labels as network address) that are
 * exported to MPLS routing table in kernel. The MPLS subsystem consists of MPLS
 * domains (struct &mpls_domain), MPLS channels (struct &mpls_channel) and FEC
 * maps (struct &mpls_fec_map).
 *
 * The MPLS domain represents one MPLS label address space, implements the label
 * allocator, and handles associated configuration and management. The domain is
 * declared in the configuration (struct &mpls_domain_config). There might be
 * multiple MPLS domains representing separate label spaces, but in most cases
 * one domain is enough. MPLS-aware protocols and routing tables are associated
 * with a specific MPLS domain.
 *
 * The MPLS domain has configurable label ranges (struct &mpls_range), by
 * default it has two ranges: static (16-1000) and dynamic (1000-10000). When
 * a protocol wants to allocate labels, it first acquires a handle (struct
 * &mpls_handle) for a specific range using mpls_new_handle(), and then it
 * allocates labels from that with mpls_new_label(). When not needed, labels are
 * freed by mpls_free_label() and the handle is released by mpls_free_handle().
 * Note that all labels and handles must be freed manually.
 *
 * Both MPLS domain and MPLS range are reference counted, so when deconfigured
 * they could be freed just after all labels and ranges are freed. Users are
 * expected to hold a reference to a MPLS domain for whole time they use
 * something from that domain (e.g. &mpls_handle), but releasing reference to
 * a range while holding associated handle is OK.
 *
 * The MPLS channel is subclass of a generic protocol channel. It has two
 * distinct purposes - to handle per-protocol MPLS configuration (e.g. which
 * MPLS domain is associated with the protocol, which label range is used by the
 * protocol), and to announce MPLS routes to a routing table (as a regular
 * protocol channel).
 *
 * The FEC map is a helper structure that maps forwarding equivalent classes
 * (FECs) to MPLS labels. It is an internal matter of a routing protocol how to
 * assign meaning to allocated labels, announce LSP routes and associated MPLS
 * routes (i.e. ILM entries). But the common behavior is implemented in the FEC
 * map, which can be used by the protocols that work with IP-prefix-based FECs.
 *
 * The FEC map keeps hash tables of FECs (struct &mpls_fec) based on network
 * prefix, next hop eattr and assigned label. It has three general labeling policies:
 * static assignment (%MPLS_POLICY_STATIC), per-prefix policy (%MPLS_POLICY_PREFIX),
 * and aggregating policy (%MPLS_POLICY_AGGREGATE). In per-prefix policy, each
 * distinct LSP is a separate FEC and uses a separate label, which is kept even
 * if the next hop of the LSP changes. In aggregating policy, LSPs with a same
 * next hop form one FEC and use one label, but when a next hop (or remote
 * label) of such LSP changes then the LSP must be moved to a different FEC and
 * assigned a different label. There is also a special VRF policy (%MPLS_POLICY_VRF)
 * applicable for L3VPN protocols, which uses one label for all routes from a VRF,
 * while replacing the original next hop with lookup in the VRF.
 *
 * The overall process works this way: A protocol wants to announce a LSP route,
 * it does that by announcing e.g. IP route with %EA_MPLS_POLICY attribute.
 * After the route is accepted by filters (which may also change the policy
 * attribute or set a static label), the mpls_handle_rte() is called from
 * rte_update2(), which applies selected labeling policy, finds existing FEC or
 * creates a new FEC (which includes allocating new label and announcing related
 * MPLS route by mpls_announce_fec()), and attach FEC label to the LSP route.
 * After that, the LSP route is stored in routing table by rte_recalculate().
 * Changes in routing tables trigger mpls_rte_insert() and mpls_rte_remove()
 * hooks, which refcount FEC structures and possibly trigger removal of FECs
 * and withdrawal of MPLS routes.
 *
 * TODO:
 *  - special handling of reserved labels
 */

#include <stdlib.h>

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/mpls.h"
#include "nest/cli.h"

static struct mpls_range *mpls_new_range(struct mpls_domain *m, struct mpls_range_config *cf);
static struct mpls_range *mpls_find_range_(list *l, const char *name);
static int mpls_reconfigure_range(struct mpls_domain *m, struct mpls_range *r, struct mpls_range_config *cf);
static void mpls_remove_range(struct mpls_range *r);


/*
 *	MPLS domain
 */

list mpls_domains;

void
mpls_init(void)
{
  init_list(&mpls_domains);
}

struct mpls_domain_config *
mpls_domain_config_new(struct symbol *s)
{
  struct mpls_domain_config *mc = cfg_allocz(sizeof(struct mpls_domain_config));
  struct mpls_range_config *rc;

  cf_define_symbol(new_config, s, SYM_MPLS_DOMAIN, mpls_domain, mc);
  mc->name = s->name;
  init_list(&mc->ranges);

  /* Predefined static range */
  rc = mpls_range_config_new(mc, NULL);
  rc->name = "static";
  rc->start = 16;
  rc->length = 984;
  rc->implicit = 1;
  mc->static_range = rc;

  /* Predefined dynamic range */
  rc = mpls_range_config_new(mc, NULL);
  rc->name = "dynamic";
  rc->start = 1000;
  rc->length = 9000;
  rc->implicit = 1;
  mc->dynamic_range = rc;

  add_tail(&new_config->mpls_domains, &mc->n);

  return mc;
}

static int
mpls_compare_range_configs(const void *r1_, const void *r2_)
{
  const struct mpls_range_config * const *r1 = r1_;
  const struct mpls_range_config * const *r2 = r2_;

  return uint_cmp((*r1)->start, (*r2)->start);
}

void
mpls_domain_postconfig(struct mpls_domain_config *cf UNUSED)
{
  /* Label range non-intersection check */

  int num_ranges = list_length(&cf->ranges);
  struct mpls_range_config **ranges = tmp_alloc(num_ranges * sizeof(struct mpls_range_config *));

  {
    int i = 0;
    struct mpls_range_config *r;
    WALK_LIST(r, cf->ranges)
      ranges[i++] = r;
  }

  qsort(ranges, num_ranges, sizeof(struct mpls_range_config *), mpls_compare_range_configs);

  struct mpls_range_config *max_range = NULL;
  uint max_hi = 0;

  for (int i = 0; i < num_ranges; i++)
  {
    struct mpls_range_config *r = ranges[i];
    uint hi = r->start + r->length;

    if (r->implicit)
      continue;

    if (r->start < max_hi)
      cf_warn("MPLS label ranges %s and %s intersect", max_range->name, r->name);

    if (hi > max_hi)
    {
      max_range = r;
      max_hi = hi;
    }
  }
}

static struct mpls_domain *
mpls_new_domain(struct mpls_domain_config *cf)
{
  struct pool *p = rp_new(&root_pool, "MPLS domain");
  struct mpls_domain *m = mb_allocz(p, sizeof(struct mpls_domain));

  m->cf = cf;
  m->name = cf->name;
  m->pool = p;

  lmap_init(&m->labels, p);
  lmap_set(&m->labels, 0);

  init_list(&m->ranges);
  init_list(&m->handles);

  struct mpls_range_config *rc;
  WALK_LIST(rc, cf->ranges)
    mpls_new_range(m, rc);

  add_tail(&mpls_domains, &m->n);
  cf->domain = m;

  return m;
}

static struct mpls_domain *
mpls_find_domain_(list *l, const char *name)
{
  struct mpls_domain *m;

  WALK_LIST(m, *l)
    if (!strcmp(m->name, name))
      return m;

  return NULL;
}

static int
mpls_reconfigure_domain(struct mpls_domain *m, struct mpls_domain_config *cf)
{
  cf->domain = m;
  m->cf->domain = NULL;
  m->cf = cf;
  m->name = cf->name;

  /* Reconfigure label ranges */
  list old_ranges;
  init_list(&old_ranges);
  add_tail_list(&old_ranges, &m->ranges);
  init_list(&m->ranges);

  struct mpls_range_config *rc;
  WALK_LIST(rc, cf->ranges)
  {
    struct mpls_range *r = mpls_find_range_(&old_ranges, rc->name);

    if (r && mpls_reconfigure_range(m, r, rc))
    {
      rem_node(&r->n);
      add_tail(&m->ranges, &r->n);
      continue;
    }

    mpls_new_range(m, rc);
  }

  struct mpls_range *r, *r2;
  WALK_LIST_DELSAFE(r, r2, old_ranges)
    if (!r->removed)
      mpls_remove_range(r);

  add_tail_list(&m->ranges, &old_ranges);

  return 1;
}

static void
mpls_free_domain(struct mpls_domain *m)
{
  ASSERT(m->use_count == 0);
  ASSERT(m->label_count == 0);
  ASSERT(EMPTY_LIST(m->handles));

  struct config *cfg = m->removed;

  m->cf->domain = NULL;
  rem_node(&m->n);
  rfree(m->pool);

  config_del_obstacle(cfg);
}

static void
mpls_remove_domain(struct mpls_domain *m, struct config *cfg)
{
  m->removed = cfg;
  config_add_obstacle(cfg);

  if (!m->use_count)
    mpls_free_domain(m);
}

void
mpls_lock_domain(struct mpls_domain *m)
{
  m->use_count++;
}

void
mpls_unlock_domain(struct mpls_domain *m)
{
  ASSERT(m->use_count > 0);

  m->use_count--;
  if (!m->use_count && m->removed)
    mpls_free_domain(m);
}

void
mpls_preconfig(struct config *c)
{
  init_list(&c->mpls_domains);
}

void
mpls_commit(struct config *new, struct config *old)
{
  list old_domains;
  init_list(&old_domains);
  add_tail_list(&old_domains, &mpls_domains);
  init_list(&mpls_domains);

  struct mpls_domain_config *mc;
  WALK_LIST(mc, new->mpls_domains)
  {
    struct mpls_domain *m = mpls_find_domain_(&old_domains, mc->name);

    if (m && mpls_reconfigure_domain(m, mc))
    {
      rem_node(&m->n);
      add_tail(&mpls_domains, &m->n);
      continue;
    }

    mpls_new_domain(mc);
  }

  struct mpls_domain *m, *m2;
  WALK_LIST_DELSAFE(m, m2, old_domains)
    mpls_remove_domain(m, old);

  add_tail_list(&mpls_domains, &old_domains);
}


/*
 *	MPLS range
 */

struct mpls_range_config *
mpls_range_config_new(struct mpls_domain_config *mc, struct symbol *s)
{
  struct mpls_range_config *rc = cfg_allocz(sizeof(struct mpls_range_config));

  if (s)
    cf_define_symbol(new_config, s, SYM_MPLS_RANGE, mpls_range, rc);

  rc->domain = mc;
  rc->name = s ? s->name : NULL;
  rc->start = (uint) -1;
  rc->length = (uint) -1;

  add_tail(&mc->ranges, &rc->n);

  return rc;
}

static struct mpls_range *
mpls_new_range(struct mpls_domain *m, struct mpls_range_config *cf)
{
  struct mpls_range *r = mb_allocz(m->pool, sizeof(struct mpls_range));

  r->cf = cf;
  r->name = cf->name;
  r->lo = cf->start;
  r->hi = cf->start + cf->length;

  add_tail(&m->ranges, &r->n);
  cf->range = r;

  return r;
}

static struct mpls_range *
mpls_find_range_(list *l, const char *name)
{
  struct mpls_range *r;

  WALK_LIST(r, *l)
    if (!strcmp(r->name, name) && !r->removed)
      return r;

  return NULL;
}

static int
mpls_reconfigure_range(struct mpls_domain *m, struct mpls_range *r, struct mpls_range_config *cf)
{
  uint last = lmap_last_one_in_range(&m->labels, r->lo, r->hi);
  if (last == r->hi) last = 0;

  if ((cf->start > r->lo) || (cf->start + cf->length <= last))
    return 0;

  cf->range = r;
  r->cf->range = NULL;
  r->cf = cf;
  r->name = cf->name;
  r->lo = cf->start;
  r->hi = cf->start + cf->length;

  return 1;
}

static void
mpls_free_range(struct mpls_range *r)
{
  ASSERT(r->use_count == 0);
  ASSERT(r->label_count == 0);

  rem_node(&r->n);
  mb_free(r);
}

static void
mpls_remove_range(struct mpls_range *r)
{
  ASSERT(!r->removed);

  r->removed = 1;
  r->cf->range = NULL;
  r->cf = NULL;

  if (!r->use_count)
    mpls_free_range(r);
}

void
mpls_lock_range(struct mpls_range *r)
{
  r->use_count++;
}

void
mpls_unlock_range(struct mpls_range *r)
{
  ASSERT(r->use_count > 0);

  r->use_count--;
  if (!r->use_count && r->removed)
    mpls_free_range(r);
}


/*
 *	MPLS handle
 */

struct mpls_handle *
mpls_new_handle(struct mpls_domain *m, struct mpls_range *r)
{
  struct mpls_handle *h = mb_allocz(m->pool, sizeof(struct mpls_handle));

  h->range = r;
  mpls_lock_range(h->range);

  add_tail(&m->handles, &h->n);

  return h;
}

void
mpls_free_handle(struct mpls_domain *m UNUSED, struct mpls_handle *h)
{
  ASSERT(h->label_count == 0);

  mpls_unlock_range(h->range);
  rem_node(&h->n);
  mb_free(h);
}


/*
 *	MPLS label
 */

uint
mpls_new_label(struct mpls_domain *m, struct mpls_handle *h, uint n)
{
  struct mpls_range *r = h->range;

  if (!n)
    n = lmap_first_zero_in_range(&m->labels, r->lo, r->hi);

  if ((n < r->lo) || (n >= r->hi) || lmap_test(&m->labels, n))
    return 0;

  m->label_count++;
  r->label_count++;
  h->label_count++;

  lmap_set(&m->labels, n);
  return n;
}

void
mpls_free_label(struct mpls_domain *m, struct mpls_handle *h, uint n)
{
  struct mpls_range *r = h->range;

  ASSERT(lmap_test(&m->labels, n));
  lmap_clear(&m->labels, n);

  ASSERT(m->label_count);
  m->label_count--;

  ASSERT(r->label_count);
  r->label_count--;

  ASSERT(h->label_count);
  h->label_count--;
}

void
mpls_move_label(struct mpls_domain *m, struct mpls_handle *fh, struct mpls_handle *th, uint n)
{
  struct mpls_range *fr = fh->range;
  struct mpls_range *tr = th->range;

  ASSERT(lmap_test(&m->labels, n));
  ASSERT((n >= fr->lo) && (n < fr->hi));
  ASSERT((n >= tr->lo) && (n < tr->hi));

  ASSERT(fr->label_count);
  fr->label_count--;

  ASSERT(fh->label_count);
  fh->label_count--;

  tr->label_count++;
  th->label_count++;
}


/*
 *	MPLS channel
 */

static void
mpls_channel_init(struct channel *C, struct channel_config *CC)
{
  struct mpls_channel *c = (void *) C;
  struct mpls_channel_config *cc = (void *) CC;

  c->domain = cc->domain->domain;
  c->range = cc->range->range;
  c->label_policy = cc->label_policy;
}

static int
mpls_channel_start(struct channel *C)
{
  struct mpls_channel *c = (void *) C;

  mpls_lock_domain(c->domain);
  mpls_lock_range(c->range);

  return 0;
}

/*
static void
mpls_channel_shutdown(struct channel *C)
{
  struct mpls_channel *c = (void *) C;

}
*/

static void
mpls_channel_cleanup(struct channel *C)
{
  struct mpls_channel *c = (void *) C;

  mpls_unlock_range(c->range);
  mpls_unlock_domain(c->domain);
}

static int
mpls_channel_reconfigure(struct channel *C, struct channel_config *CC, int *import_changed, int *export_changed UNUSED)
{
  struct mpls_channel *c = (void *) C;
  struct mpls_channel_config *new = (void *) CC;

  if (new->domain->domain != c->domain)
    return 0;

  if (new->range->range != c->range)
  {
    if (c->c.channel_state != CS_DOWN)
      mpls_unlock_range(c->range);

    c->range = new->range->range;
    *import_changed = 1;

    if (c->c.channel_state != CS_DOWN)
      mpls_lock_range(c->range);
  }

  if (new->label_policy != c->label_policy)
  {
    c->label_policy = new->label_policy;
    *import_changed = 1;
  }

  return 1;
}

void
mpls_channel_postconfig(struct channel_config *CC)
{
  struct mpls_channel_config *cc = (void *) CC;

  if (!cc->domain)
    cf_error("MPLS domain not specified");

  if (!cc->range)
    cc->range = cc->domain->dynamic_range;

  if (cc->range->domain != cc->domain)
    cf_error("MPLS label range from different MPLS domain");

  if (!cc->c.table)
    cf_error("Routing table not specified");
}

struct channel_class channel_mpls = {
  .channel_size =	sizeof(struct mpls_channel),
  .config_size =	sizeof(struct mpls_channel_config),
  .init =		mpls_channel_init,
  .start =		mpls_channel_start,
//  .shutdown =		mpls_channel_shutdown,
  .cleanup =		mpls_channel_cleanup,
  .reconfigure =	mpls_channel_reconfigure,
};


/*
 *	MPLS FEC map
 */

#define NET_KEY(fec)		fec->net, fec->path_id, fec->hash
#define NET_NEXT(fec)		fec->next_k
#define NET_EQ(n1,i1,h1,n2,i2,h2) h1 == h2 && i1 == i2 && net_equal(n1, n2)
#define NET_FN(n,i,h)		h

#define NET_REHASH		mpls_net_rehash
#define NET_PARAMS		/8, *2, 2, 2, 8, 24


#define RTA_KEY(fec)		fec->rta, fec->class_id, fec->hash
#define RTA_NEXT(fec)		fec->next_k
#define RTA_EQ(r1,i1,h1,r2,i2,h2) h1 == h2 && r1 == r2 && i1 == i2
#define RTA_FN(r,i,h)		h

#define RTA_REHASH		mpls_rta_rehash
#define RTA_PARAMS		/8, *2, 2, 2, 8, 24


#define LABEL_KEY(fec)		fec->label
#define LABEL_NEXT(fec)		fec->next_l
#define LABEL_EQ(l1,l2)		l1 == l2
#define LABEL_FN(l)		u32_hash(l)

#define LABEL_REHASH		mpls_label_rehash
#define LABEL_PARAMS		/8, *2, 2, 2, 8, 24


HASH_DEFINE_REHASH_FN(NET, struct mpls_fec)
HASH_DEFINE_REHASH_FN(RTA, struct mpls_fec)
HASH_DEFINE_REHASH_FN(LABEL, struct mpls_fec)


static void mpls_unlink_fec(struct mpls_fec_map *m, struct mpls_fec *fec);
static void mpls_withdraw_fec(struct mpls_fec_map *m, struct mpls_fec *fec);
static rta * mpls_get_key_rta(struct mpls_fec_map *m, const rta *src);

struct mpls_fec_map *
mpls_fec_map_new(pool *pp, struct channel *C, uint rts)
{
  struct pool *p = rp_new(pp, "MPLS FEC map");
  struct mpls_fec_map *m = mb_allocz(p, sizeof(struct mpls_fec_map));
  struct mpls_channel *c = (void *) C;

  m->pool = p;
  m->channel = C;

  m->domain = c->domain;
  mpls_lock_domain(m->domain);

  m->handle = mpls_new_handle(c->domain, c->range);

  /* net_hash and rta_hash are initialized on-demand */
  HASH_INIT(m->label_hash, m->pool, 4);

  m->mpls_rts = rts;
  m->mpls_scope = SCOPE_UNIVERSE;

  return m;
}

void
mpls_fec_map_reconfigure(struct mpls_fec_map *m, struct channel *C)
{
  struct mpls_channel *c = (void *) C;

  struct mpls_handle *old_d = NULL;
  struct mpls_handle *old_s = NULL;

  /* Reallocate dynamic handle */
  if (m->handle->range != c->range)
  {
    old_d = m->handle;
    m->handle = mpls_new_handle(m->domain, c->range);
  }

  /* Reallocate static handle */
  if (m->static_handle && (m->static_handle->range != m->domain->cf->static_range->range))
  {
    old_s = m->static_handle;
    m->static_handle = mpls_new_handle(m->domain, m->domain->cf->static_range->range);
  }

  /* Skip rest if there is no change */
  if (!old_d && !old_s)
    return;

  /* Process existing FECs */
  HASH_WALK(m->label_hash, next_l, fec)
  {
    /* Skip already dead FECs */
    if (fec->policy == MPLS_POLICY_NONE)
      continue;

    /* Skip FECs with valid handle */
    if ((fec->handle == m->handle) || (fec->handle == m->static_handle))
      continue;

    /* Try new handle for the FEC */
    struct mpls_handle *new = (fec->policy != MPLS_POLICY_STATIC) ? m->handle : m->static_handle;
    if ((fec->label >= new->range->lo) && (fec->label < new->range->hi))
    {
      mpls_move_label(m->domain, fec->handle, new, fec->label);
      fec->handle = new;
      continue;
    }

    /* Unlink the FEC while keep it in the label hash */
    mpls_unlink_fec(m, fec);
    fec->policy = MPLS_POLICY_NONE;
  }
  HASH_WALK_END;

  /* Remove old unused handles */

  if (old_d && !old_d->label_count)
    mpls_free_handle(m->domain, old_d);

  if (old_s && !old_s->label_count)
    mpls_free_handle(m->domain, old_s);
}

void
mpls_fec_map_free(struct mpls_fec_map *m)
{
  /* Free stored rtas */
  if (m->rta_hash.data)
  {
    HASH_WALK(m->rta_hash, next_k, fec)
    {
      rta_free(fec->rta);
      fec->rta = NULL;
    }
    HASH_WALK_END;
  }

  /* Free allocated labels */
  HASH_WALK(m->label_hash, next_l, fec)
  {
    mpls_free_label(m->domain, fec->handle, fec->label);

    if (!fec->policy && !fec->handle->label_count)
      mpls_free_handle(m->domain, fec->handle);
  }
  HASH_WALK_END;

  if (m->static_handle)
    mpls_free_handle(m->domain, m->static_handle);

  mpls_free_handle(m->domain, m->handle);
  mpls_unlock_domain(m->domain);

  rfree(m->pool);
}

static slab *
mpls_slab(struct mpls_fec_map *m, uint type)
{
  ASSERT(type <= NET_VPN6);
  int pos = type ? (type - 1) : 0;

  if (!m->slabs[pos])
    m->slabs[pos] = sl_new(m->pool, sizeof(struct mpls_fec) + net_addr_length[pos + 1]);

  return m->slabs[pos];
}

struct mpls_fec *
mpls_find_fec_by_label(struct mpls_fec_map *m, u32 label)
{
  return HASH_FIND(m->label_hash, LABEL, label);
}

struct mpls_fec *
mpls_get_fec_by_label(struct mpls_fec_map *m, u32 label)
{
  struct mpls_fec *fec = HASH_FIND(m->label_hash, LABEL, label);

  if (fec)
    return (fec->policy == MPLS_POLICY_STATIC) ? fec : NULL;

  if (!m->static_handle)
    m->static_handle = mpls_new_handle(m->domain, m->domain->cf->static_range->range);

  label = mpls_new_label(m->domain, m->static_handle, label);

  if (!label)
    return NULL;

  fec = sl_allocz(mpls_slab(m, 0));

  fec->label = label;
  fec->policy = MPLS_POLICY_STATIC;
  fec->handle = m->static_handle;

  DBG("New FEC lab %u\n", fec->label);

  HASH_INSERT2(m->label_hash, LABEL, m->pool, fec);

  return fec;
}

struct mpls_fec *
mpls_get_fec_by_net(struct mpls_fec_map *m, const net_addr *net, u64 path_id)
{
  if (!m->net_hash.data)
    HASH_INIT(m->net_hash, m->pool, 4);

  u32 hash = net_hash(net) ^ u64_hash(path_id);
  struct mpls_fec *fec = HASH_FIND(m->net_hash, NET, net, path_id, hash);

  if (fec)
    return fec;

  u32 label = mpls_new_label(m->domain, m->handle, 0);

  if (!label)
    return NULL;

  fec = sl_allocz(mpls_slab(m, net->type));

  fec->hash = hash;
  fec->path_id = path_id;
  net_copy(fec->net, net);

  fec->label = label;
  fec->policy = MPLS_POLICY_PREFIX;
  fec->handle = m->handle;

  DBG("New FEC net %u\n", fec->label);

  HASH_INSERT2(m->net_hash, NET, m->pool, fec);
  HASH_INSERT2(m->label_hash, LABEL, m->pool, fec);

  return fec;
}

struct mpls_fec *
mpls_get_fec_by_rta(struct mpls_fec_map *m, const rta *src, u32 class_id)
{
  if (!m->rta_hash.data)
    HASH_INIT(m->rta_hash, m->pool, 4);

  rta *rta = mpls_get_key_rta(m, src);
  u32 hash = rta->hash_key ^ u32_hash(class_id);
  struct mpls_fec *fec = HASH_FIND(m->rta_hash, RTA, rta, class_id, hash);

  if (fec)
  {
    rta_free(rta);
    return fec;
  }

  u32 label = mpls_new_label(m->domain, m->handle, 0);

  if (!label)
  {
    rta_free(rta);
    return NULL;
  }

  fec = sl_allocz(mpls_slab(m, 0));

  fec->hash = hash;
  fec->class_id = class_id;
  fec->rta = rta;

  fec->label = label;
  fec->policy = MPLS_POLICY_AGGREGATE;
  fec->handle = m->handle;

  DBG("New FEC rta %u\n", fec->label);

  HASH_INSERT2(m->rta_hash, RTA, m->pool, fec);
  HASH_INSERT2(m->label_hash, LABEL, m->pool, fec);

  return fec;
}

struct mpls_fec *
mpls_get_fec_for_vrf(struct mpls_fec_map *m)
{
  struct mpls_fec *fec = m->vrf_fec;

  if (fec)
    return fec;

  u32 label = mpls_new_label(m->domain, m->handle, 0);

  if (!label)
    return NULL;

  fec = sl_allocz(mpls_slab(m, 0));

  fec->label = label;
  fec->policy = MPLS_POLICY_VRF;
  fec->handle = m->handle;
  fec->iface = m->vrf_iface;

  DBG("New FEC vrf %u\n", fec->label);

  m->vrf_fec = fec;
  HASH_INSERT2(m->label_hash, LABEL, m->pool, fec);

  return fec;
}

static void
mpls_unlink_fec(struct mpls_fec_map *m, struct mpls_fec *fec)
{
  switch (fec->policy)
  {
  case MPLS_POLICY_NONE:
  case MPLS_POLICY_STATIC:
    break;

  case MPLS_POLICY_PREFIX:
    HASH_REMOVE2(m->net_hash, NET, m->pool, fec);
    break;

  case MPLS_POLICY_AGGREGATE:
    rta_free(fec->rta);
    HASH_REMOVE2(m->rta_hash, RTA, m->pool, fec);
    break;

  case MPLS_POLICY_VRF:
    ASSERT(m->vrf_fec == fec);
    m->vrf_fec = NULL;
    break;

  default:
    bug("Unknown fec type");
  }
}

void
mpls_free_fec(struct mpls_fec_map *m, struct mpls_fec *fec)
{
  if (fec->state != MPLS_FEC_DOWN)
    mpls_withdraw_fec(m, fec);

  DBG("Free FEC %u\n", fec->label);

  mpls_free_label(m->domain, fec->handle, fec->label);

  if (!fec->policy && !fec->handle->label_count)
      mpls_free_handle(m->domain, fec->handle);

  HASH_REMOVE2(m->label_hash, LABEL, m->pool, fec);

  mpls_unlink_fec(m, fec);

  sl_free(fec);
}

static inline void mpls_lock_fec(struct mpls_fec_map *x UNUSED, struct mpls_fec *fec)
{ if (fec) fec->uc++; }

static inline void mpls_unlock_fec(struct mpls_fec_map *x, struct mpls_fec *fec)
{ if (fec && !--fec->uc) mpls_free_fec(x, fec); }

static inline void
mpls_damage_fec(struct mpls_fec_map *m UNUSED, struct mpls_fec *fec)
{
  if (fec && (fec->state == MPLS_FEC_CLEAN))
    fec->state = MPLS_FEC_DIRTY;
}

static rta *
mpls_get_key_rta(struct mpls_fec_map *m, const rta *src)
{
  rta *a = allocz(RTA_MAX_SIZE);

  a->source = m->mpls_rts;
  a->scope = m->mpls_scope;

  if (!src->hostentry)
  {
    /* Just copy the nexthop */
    a->dest = src->dest;
    nexthop_link(a, &src->nh);
  }
  else
  {
    /* Keep the hostentry */
    a->hostentry = src->hostentry;

    /* Keep the original labelstack */
    const u32 *labels = &src->nh.label[src->nh.labels - src->nh.labels_orig];
    a->nh.labels = a->nh.labels_orig = src->nh.labels_orig;
    memcpy(a->nh.label, labels, src->nh.labels_orig * sizeof(u32));
  }

  return rta_lookup(a);
}

static void
mpls_announce_fec(struct mpls_fec_map *m, struct mpls_fec *fec, const rta *src)
{
  rta *a = allocz(RTA_MAX_SIZE);

  a->source = m->mpls_rts;
  a->scope = m->mpls_scope;

  if (!src->hostentry)
  {
    /* Just copy the nexthop */
    a->dest = src->dest;
    nexthop_link(a, &src->nh);
  }
  else
  {
    const u32 *labels = &src->nh.label[src->nh.labels - src->nh.labels_orig];
    mpls_label_stack ms;

    /* Reconstruct the original labelstack */
    ms.len = src->nh.labels_orig;
    memcpy(ms.stack, labels, src->nh.labels_orig * sizeof(u32));

    /* The same hostentry, but different dependent table */
    struct hostentry *s = src->hostentry;
    rta_set_recursive_next_hop(m->channel->table, a, s->owner, s->addr, s->link, &ms);
  }

  net_addr_mpls n = NET_ADDR_MPLS(fec->label);

  rte *e = rte_get_temp(rta_lookup(a), m->channel->proto->main_source);
  e->pflags = 0;

  fec->state = MPLS_FEC_CLEAN;
  rte_update2(m->channel, (net_addr *) &n, e, m->channel->proto->main_source);
}

static void
mpls_withdraw_fec(struct mpls_fec_map *m, struct mpls_fec *fec)
{
  net_addr_mpls n = NET_ADDR_MPLS(fec->label);

  fec->state = MPLS_FEC_DOWN;
  rte_update2(m->channel, (net_addr *) &n, NULL, m->channel->proto->main_source);
}

static void
mpls_apply_fec(rte *r, struct mpls_fec *fec, linpool *lp)
{
  struct ea_list *ea = lp_allocz(lp, sizeof(struct ea_list) + 2 * sizeof(eattr));

  rta *old_attrs = r->attrs;

  if (rta_is_cached(old_attrs))
    r->attrs = rta_do_cow(r->attrs, lp);

  *ea = (struct ea_list) {
    .next = r->attrs->eattrs,
    .flags = EALF_SORTED,
    .count = 2,
  };

  ea->attrs[0] = (struct eattr) {
    .id = EA_MPLS_LABEL,
    .type = EAF_TYPE_INT,
    .u.data = fec->label,
  };

  ea->attrs[1] = (struct eattr) {
    .id = EA_MPLS_POLICY,
    .type = EAF_TYPE_INT,
    .u.data = fec->policy,
  };

  r->attrs->eattrs = ea;

  if (fec->policy == MPLS_POLICY_VRF)
  {
    r->attrs->hostentry = NULL;
    r->attrs->dest = RTD_UNICAST;
    r->attrs->nh = (struct nexthop) { .iface = fec->iface };
  }

  if (rta_is_cached(old_attrs))
  {
    r->attrs = rta_lookup(r->attrs);
    rta_free(old_attrs);
  }
}


int
mpls_handle_rte(struct mpls_fec_map *m, const net_addr *n, rte *r, linpool *lp, struct mpls_fec **locked_fec)
{
  ASSERT(!(r->flags & REF_COW));

  struct mpls_fec *fec = NULL;

  /* Select FEC for route */
  uint policy = ea_get_int(r->attrs->eattrs, EA_MPLS_POLICY, 0);
  switch (policy)
  {
  case MPLS_POLICY_NONE:
    return 0;

  case MPLS_POLICY_STATIC:;
    uint label = ea_get_int(r->attrs->eattrs, EA_MPLS_LABEL, 0);

    if (label < 16)
      return 0;

    fec = mpls_get_fec_by_label(m, label);
    if (!fec)
    {
      log(L_WARN "Static label %u failed for %N from %s",
	  label, n, r->sender->proto->name);
      return -1;
    }

    mpls_damage_fec(m, fec);
    break;

  case MPLS_POLICY_PREFIX:
    fec = mpls_get_fec_by_net(m, n, r->src->private_id);
    mpls_damage_fec(m, fec);
    break;

  case MPLS_POLICY_AGGREGATE:;
    uint class = ea_get_int(r->attrs->eattrs, EA_MPLS_CLASS, 0);
    fec = mpls_get_fec_by_rta(m, r->attrs, class);
    break;

  case MPLS_POLICY_VRF:
    if (!m->vrf_iface)
      return 0;

    fec = mpls_get_fec_for_vrf(m);
    break;

  default:
    log(L_WARN "Route %N has invalid MPLS policy %u", n, policy);
    return -1;
  }

  /* Label allocation failure */
  if (!fec)
  {
    log(L_WARN "Label allocation in range %s failed for %N from %s",
	m->handle->range->name, n, r->sender->proto->name);
    return -1;
  }

  /* Temporarily lock FEC */
  mpls_lock_fec(m, fec);
  *locked_fec = fec;

  /* Apply FEC label to route */
  mpls_apply_fec(r, fec, lp);

  /* Announce MPLS rule for new/updated FEC */
  if (fec->state != MPLS_FEC_CLEAN)
    mpls_announce_fec(m, fec, r->attrs);

  return 0;
}

void
mpls_handle_rte_cleanup(struct mpls_fec_map *m, struct mpls_fec **locked_fec)
{
  /* Unlock temporarily locked FEC from mpls_handle_rte() */
  if (*locked_fec)
  {
    mpls_unlock_fec(m, *locked_fec);
    *locked_fec = NULL;
  }
}

void
mpls_rte_insert(net *n UNUSED, rte *r)
{
  struct proto *p = r->src->proto;
  struct mpls_fec_map *m = p->mpls_map;

  uint label = ea_get_int(r->attrs->eattrs, EA_MPLS_LABEL, 0);
  if (label < 16)
    return;

  struct mpls_fec *fec = mpls_find_fec_by_label(m, label);
  if (!fec)
    return;

  mpls_lock_fec(m, fec);
}

void
mpls_rte_remove(net *n UNUSED, rte *r)
{
  struct proto *p = r->src->proto;
  struct mpls_fec_map *m = p->mpls_map;

  uint label = ea_get_int(r->attrs->eattrs, EA_MPLS_LABEL, 0);
  if (label < 16)
    return;

  struct mpls_fec *fec = mpls_find_fec_by_label(m, label);
  if (!fec)
    return;

  mpls_unlock_fec(m, fec);
}

static void
mpls_show_ranges_rng(struct mpls_show_ranges_cmd *cmd, struct mpls_range *r)
{
  uint last = lmap_last_one_in_range(&cmd->dom->labels, r->lo, r->hi);
  if (last == r->hi) last = 0;

  cli_msg(-1026, "%-11s %7u %7u %7u %7u %7u",
	  r->name, r->lo, r->hi - r->lo, r->hi, r->label_count, last);
}

void
mpls_show_ranges_dom(struct mpls_show_ranges_cmd *cmd, struct mpls_domain *m)
{
  if (cmd->dom)
    cli_msg(-1026, "");

  cmd->dom = m;
  cli_msg(-1026, "MPLS domain %s:", m->name);
  cli_msg(-1026, "%-11s %7s %7s %7s %7s %7s",
	  "Range", "Start", "Length", "End", "Labels", "Last");

  if (cmd->range)
    mpls_show_ranges_rng(cmd, cmd->range->range);
  else
  {
    struct mpls_range *r;
    WALK_LIST(r, m->ranges)
      if (!r->removed)
	mpls_show_ranges_rng(cmd, r);
  }
}

void
mpls_show_ranges(struct mpls_show_ranges_cmd *cmd)
{
  if (cmd->domain)
    mpls_show_ranges_dom(cmd, cmd->domain->domain);
  else
  {
    struct mpls_domain *m;
    WALK_LIST(m, mpls_domains)
      mpls_show_ranges_dom(cmd, m);
  }

  cli_msg(0, "");
}
