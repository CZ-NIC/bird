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
#include "nest/mpls-internal.h"
#include "nest/cli.h"

static struct mpls_range *mpls_new_range(struct mpls_domain *m, struct mpls_range_config *cf);
static struct mpls_range *mpls_find_range_(list *l, const char *name);
static int mpls_reconfigure_range(struct mpls_domain *m, struct mpls_range *r, struct mpls_range_config *cf);
static void mpls_remove_range(struct mpls_range *r);
static void mpls_cleanup_ranges(void *_domain);

static void mpls_free_fec(struct mpls_fec_map *m, struct mpls_fec *fec);
static void mpls_fec_map_cleanup(void *_m);

/*
 *	MPLS domain
 */


#define MPLS_GLOBAL_PUBLIC \
  DOMAIN(the_bird) lock; \

struct mpls_global_private {
  struct { MPLS_GLOBAL_PUBLIC; };
  list domains;
};

union mpls_global_public {
  struct { MPLS_GLOBAL_PUBLIC; };
  struct mpls_global_private priv;
} mpls_global;

#define MPLS_GLOBAL	LOBJ_PRIV(&mpls_global, the_bird)

void
mpls_init(void)
{
  mpls_global.lock = the_bird_domain;
  init_list(&MPLS_GLOBAL->domains);
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

static struct mpls_domain_pub *
mpls_new_domain(struct mpls_domain_config *cf)
{
  ASSERT_THE_BIRD_LOCKED;

  DOMAIN(attrs) dom = DOMAIN_NEW(attrs);
  LOCK_DOMAIN(attrs, dom);

  struct pool *p = rp_newf(&root_pool, dom.attrs, "MPLS domain %s", cf->name);
  struct mpls_domain_pub *mpub = mb_allocz(p, sizeof(struct mpls_domain_pub));
  mpub->lock = dom;
  struct mpls_domain *m = LOBJ_PRIV(mpub, attrs);

  m->cf = cf;
  m->name = cf->name;
  m->pool = p;

  lmap_init(&m->labels, p, birdloop_event_list(&main_birdloop));
  lmap_set(&m->labels, 0);

  init_list(&m->ranges);

  struct mpls_range_config *rc;
  WALK_LIST(rc, cf->ranges)
  {
    struct mpls_range *r = mpls_new_range(m, rc);
    if (rc == cf->static_range)
      m->static_range = r;
  }

  m->range_cleanup = (event) { .hook = mpls_cleanup_ranges, .data = m };

  add_tail(&MPLS_GLOBAL->domains, &m->n);
  mpls_lock_domain(m);

  UNLOCK_DOMAIN(attrs, dom);

  cf->domain = mpub;
  return mpub;
}

static struct mpls_domain_pub *
mpls_find_domain_(list *l, const char *name)
{
  struct mpls_domain_pub *m;

  WALK_LIST(m, *l)
    if (!strcmp(m->name, name))
      return m;

  return NULL;
}

static int
mpls_reconfigure_domain(struct mpls_domain_pub *mpub, struct mpls_domain_config *cf)
{
  cf->domain = mpub;

  MPLS_DOMAIN_LOCK(mpub, m);

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
mpls_free_domain(void *_m)
{
  ASSERT_THE_BIRD_LOCKED;

  struct mpls_domain *m = _m;
  DOMAIN(attrs) dom = m->lock;
  LOCK_DOMAIN(attrs, dom);

  ASSERT(m->use_count == 0);
  ASSERT(m->label_count == 0);
  ASSERT(EMPTY_LIST(m->ranges));

  OBSREF_CLEAR(m->removed);

  m->cf->domain = NULL;
  rem_node(&m->n);
  rfree(m->pool);
  UNLOCK_DOMAIN(attrs, dom);
}

static void
mpls_remove_domain(struct mpls_domain *m, struct config *cfg)
{
  OBSREF_SET(m->removed, cfg);

  struct mpls_range *r, *rnext;
  WALK_LIST_DELSAFE(r, rnext, m->ranges)
    if (!r->removed)
      mpls_remove_range(r);

  mpls_unlock_domain(m);
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
  if (!m->use_count && OBSREF_GET(m->removed))
    ev_new_send(&main_birdloop, m->pool, mpls_free_domain, m);
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
  add_tail_list(&old_domains, &MPLS_GLOBAL->domains);
  init_list(&MPLS_GLOBAL->domains);

  struct mpls_domain_config *mc;
  WALK_LIST(mc, new->mpls_domains)
  {
    struct mpls_domain_pub *m = mpls_find_domain_(&old_domains, mc->name);

    if (m && mpls_reconfigure_domain(m, mc))
    {
      rem_node(&m->n);
      add_tail(&MPLS_GLOBAL->domains, &m->n);
      continue;
    }

    mpls_new_domain(mc);
  }

  struct mpls_domain *m, *m2;
  WALK_LIST_DELSAFE(m, m2, old_domains)
    mpls_remove_domain(m, old);

  add_tail_list(&MPLS_GLOBAL->domains, &old_domains);
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
  struct mpls_range_pub *rpub = mb_allocz(m->pool, sizeof(struct mpls_range_pub));
  rpub->lock = m->lock;

  struct mpls_range *r = LOBJ_PRIV(rpub, attrs);

  r->domain = m;
  mpls_lock_domain(m);

  r->cf = cf;
  r->name = cf->name;
  r->lo = cf->start;
  r->hi = cf->start + cf->length;

  init_list(&r->handles);

  add_tail(&m->ranges, &r->n);
  cf->range = rpub;

  DBGL("Lock range %p (new)", r);
  mpls_lock_range(r);
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

  cf->range = MPLS_RANGE_PUB(r);
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
  /* Must always run in an asynchronous context from main loop */
  ASSERT_THE_BIRD_LOCKED;

  ASSERT(r->use_count == 0);
  ASSERT(r->label_count == 0);

  mpls_unlock_domain(r->domain);

  rem_node(&r->n);
  mb_free(r);
}

static void mpls_cleanup_ranges(void *_domain)
{
  MPLS_DOMAIN_LOCK((struct mpls_domain_pub *) _domain, m);

  struct mpls_range *r, *rnext;
  WALK_LIST_BACKWARDS_DELSAFE(r, rnext, m->ranges)
    if (!r->removed)
      return;
    else if (!r->use_count)
      mpls_free_range(r);
}

static void
mpls_remove_range(struct mpls_range *r)
{
  ASSERT(!r->removed);

  r->removed = 1;
  r->cf->range = NULL;
  r->cf = NULL;

  DBGL("Unlock range %p (remove)", r);
  mpls_unlock_range(r);
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
    ev_send_loop(&main_birdloop, &r->domain->range_cleanup);
}


/*
 *	MPLS handle
 */

struct mpls_handle *
mpls_new_handle(struct mpls_range *r)
{
  struct mpls_domain *m = r->domain;

  struct mpls_handle *h = mb_allocz(m->pool, sizeof(struct mpls_handle));
  h->lock = m->lock;

  DBGL("Lock range %p (new handle %p)", r, h);
  mpls_lock_range(r);
  h->range = r;

  add_tail(&r->handles, &h->n);

  return h;
}

void
mpls_free_handle(struct mpls_handle *h)
{
  ASSERT(h->label_count == 0);

  DBGL("Unlock range %p (free handle %p)", h->range, h);
  mpls_unlock_range(h->range);
  rem_node(&h->n);
  mb_free(h);
}


/*
 *	MPLS label
 */

uint
mpls_new_label(struct mpls_handle *h, uint n)
{
  struct mpls_range *r = h->range;
  struct mpls_domain *m = r->domain;

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
mpls_free_label(struct mpls_handle *h, uint n)
{
  struct mpls_range *r = h->range;
  struct mpls_domain *m = r->domain;

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
mpls_move_label(struct mpls_handle *fh, struct mpls_handle *th, uint n)
{
  struct mpls_range *fr = fh->range;
  struct mpls_domain *m = fr->domain;

  struct mpls_range *tr = th->range;
  ASSERT_DIE(tr->domain == m);

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

  if (cc->rts)
  {
    c->domain = cc->domain->domain;
    c->range = cc->range->range;
    c->label_policy = cc->label_policy;
    c->rts = cc->rts;
  }
}

static int
mpls_channel_start(struct channel *C)
{
  struct mpls_channel *c = (void *) C;
  if (!c->rts)
    return 0;

  c->mpls_map = mpls_fec_map_new(C->proto->pool, C->proto->loop, C, c->rts);
  c->mpls_map->vrf_iface = C->proto->vrf;

  return 0;
}

static void
mpls_channel_shutdown(struct channel *C)
{
  struct mpls_channel *c = (void *) C;

  if (!c->rts)
    return;

  ev_send_loop(c->mpls_map->loop, c->mpls_map->cleanup_event);
}

static void
mpls_channel_cleanup(struct channel *C)
{
  struct mpls_channel *c = (void *) C;
  if (!c->rts)
    return;

  mpls_fec_map_free(c->mpls_map);
  c->mpls_map = NULL;
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
      MPLS_RANGE_LOCKED(c->range, r)
      {
	DBGL("Unlock range %p (channel %p)", r, c);
	mpls_unlock_range(r);
      }

    c->range = new->range->range;
    *import_changed = 1;

    if (c->c.channel_state != CS_DOWN)
      MPLS_RANGE_LOCKED(c->range, r)
      {
	DBGL("Lock range %p (channel %p)", r, c);
	mpls_lock_range(r);
      }
  }

  if (new->label_policy != c->label_policy)
  {
    c->label_policy = new->label_policy;
    *import_changed = 1;
  }

  mpls_fec_map_reconfigure(c->mpls_map, C);

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
  .shutdown =		mpls_channel_shutdown,
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


#define RTA_KEY(fec)		fec->rta
#define RTA_NEXT(fec)		fec->next_k
#define RTA_EQ(r1,r2)		r1 == r2
#define RTA_FN(r)		r->hash_key

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
static struct ea_storage * mpls_get_key_attrs(struct mpls_fec_map *m, ea_list *src);

struct mpls_fec_map *
mpls_fec_map_new(pool *pp, struct birdloop *loop, struct channel *C, uint rts)
{
  struct pool *p = rp_new(pp, pp->domain, "MPLS FEC map");
  struct mpls_fec_map *m = mb_allocz(p, sizeof(struct mpls_fec_map));
  struct mpls_channel *c = (void *) C;

  DBGL("New FEC Map %p", m);

  m->pool = p;
  m->loop = loop;
  m->cleanup_event = ev_new_init(p, mpls_fec_map_cleanup, m);
  m->channel = C;
  channel_add_obstacle(C);

  m->domain = c->domain;
  MPLS_RANGE_LOCKED(c->range, r)
    m->handle = MPLS_HANDLE_PUB(mpls_new_handle(r));

  /* net_hash and rta_hash are initialized on-demand */
  HASH_INIT(m->label_hash, m->pool, 4);

  m->mpls_rts = rts;

  return m;
}

void
mpls_fec_map_reconfigure(struct mpls_fec_map *m, struct channel *C)
{
  struct mpls_channel *c = (void *) C;

  MPLS_DOMAIN_LOCK(m->domain, domain);

  struct mpls_handle *dh = MPLS_HANDLE_PRIV(m->handle);
  struct mpls_handle *sh = m->static_handle ? MPLS_HANDLE_PRIV(m->static_handle) : NULL;

  struct mpls_range *new_range = MPLS_RANGE_PRIV(c->range);

  struct mpls_handle *old_d = NULL;
  struct mpls_handle *old_s = NULL;

  /* Reallocate dynamic handle */
  if (dh->range != new_range)
  {
    old_d = dh;
    m->handle = MPLS_HANDLE_PUB(mpls_new_handle(new_range));
  }

  /* Reallocate static handle */
  if (sh && (sh->range != domain->static_range))
  {
    old_s = sh;
    m->static_handle = MPLS_HANDLE_PUB(mpls_new_handle(domain->static_range));
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

    /* Consistency check: static policy requires static handle to exist */
    if (!m->static_handle)
      ASSERT_DIE(fec->policy != MPLS_POLICY_STATIC);

    /* Try new handle for the FEC */
    struct mpls_handle_pub *new_pub = (fec->policy != MPLS_POLICY_STATIC) ? m->handle : m->static_handle;
    struct mpls_handle *new = MPLS_HANDLE_PRIV(new_pub);
    struct mpls_handle *old = MPLS_HANDLE_PRIV(fec->handle);

    if ((fec->label >= new->range->lo) && (fec->label < new->range->hi))
    {
      mpls_move_label(old, new, fec->label);
      fec->handle = new_pub;
      continue;
    }

    /* Unlink the FEC while keep it in the label hash */
    mpls_unlink_fec(m, fec);
    fec->policy = MPLS_POLICY_NONE;
  }
  HASH_WALK_END;

  /* Remove old unused handles */

  if (old_d && !old_d->label_count)
    mpls_free_handle(old_d);

  if (old_s && !old_s->label_count)
    mpls_free_handle(old_s);
}

static void
mpls_fec_map_cleanup(void *_m)
{
  struct mpls_fec_map *m = _m;
  bool finished = (m->channel->channel_state == CS_STOP);
  HASH_WALK_DELSAFE(m->label_hash, next_l, fec)
    if (lfuc_finished(&fec->uc))
      mpls_free_fec(m, fec);
    else
      finished = 0;
  HASH_WALK_DELSAFE_END;

  DBGL("FEC Map %p Cleanup: %sfinished", m, finished ? "" : "not ");

  if (finished)
  {
    ev_postpone(m->cleanup_event);
    channel_del_obstacle(m->channel);
  }
}

void
mpls_fec_map_free(struct mpls_fec_map *m)
{
  DBGL("Free Whole FEC Map %p", m);

  /* Free stored rtas */
  if (m->attrs_hash.data)
  {
    HASH_WALK(m->attrs_hash, next_k, fec)
    {
      ea_free(fec->rta->l);
      fec->rta = NULL;
    }
    HASH_WALK_END;
  }

  MPLS_DOMAIN_LOCK(m->domain, domain);

  /* Free allocated labels */
  HASH_WALK(m->label_hash, next_l, fec)
  {
    struct mpls_handle *h = MPLS_HANDLE_PRIV(fec->handle);
    mpls_free_label(h, fec->label);

    DBGL("Handle %p policy %d label count %d", fec->policy, h->label_count);
    if (!fec->policy && !h->label_count)
      mpls_free_handle(h);
  }
  HASH_WALK_END;

  if (m->static_handle)
    mpls_free_handle(MPLS_HANDLE_PRIV(m->static_handle));

  mpls_free_handle(MPLS_HANDLE_PRIV(m->handle));

  rfree(m->pool);
}

static slab *
mpls_slab(struct mpls_fec_map *m, uint type)
{
  ASSERT(type <= NET_VPN6);
  int pos = type ? (type - 1) : 0;

  if (!m->slabs[pos])
    m->slabs[pos] = sl_new(m->pool, birdloop_event_list(m->loop), sizeof(struct mpls_fec) + net_addr_length[pos + 1]);

  return m->slabs[pos];
}

struct mpls_fec *
mpls_find_fec_by_label(struct mpls_fec_map *m, u32 label)
{
  return HASH_FIND(m->label_hash, LABEL, label);
}

struct mpls_fec *
mpls_new_fec(struct mpls_fec_map *m, u8 net_type, u32 label)
{
  struct mpls_fec *fec = sl_allocz(mpls_slab(m, net_type));

  fec->map = m;
  fec->label = label;

  HASH_INSERT2(m->label_hash, LABEL, m->pool, fec);

  /* Temporarily lock FEC */
  lfuc_init(&fec->uc);

  return fec;
}

struct mpls_fec *
mpls_get_fec_by_label(struct mpls_fec_map *m, u32 label)
{
  struct mpls_fec *fec = HASH_FIND(m->label_hash, LABEL, label);

  if (fec)
  {
    DBGL("FEC %p found for lab %u in %p, policy %u", fec, label, m, fec->policy);
    if (fec->policy != MPLS_POLICY_STATIC)
      return NULL;

    mpls_revive_fec(fec);
    return fec;
  }

  MPLS_DOMAIN_LOCKED(m->domain, domain)
  {
    struct mpls_handle *h;

    if (m->static_handle)
      h = MPLS_HANDLE_PRIV(m->static_handle);
    else
      m->static_handle = MPLS_HANDLE_PUB(h = mpls_new_handle(domain->static_range));

    label = mpls_new_label(h, label);

    if (!label)
      return NULL;
  }

  fec = mpls_new_fec(m, 0, label);

  fec->policy = MPLS_POLICY_STATIC;
  fec->handle = m->static_handle;

  DBGL("New FEC lab %u map %p", fec->label, m);

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
  {
    mpls_revive_fec(fec);
    return fec;
  }

  u32 label = 0;
  MPLS_HANDLE_LOCKED(m->handle, h)
    label = mpls_new_label(h, 0);

  if (!label)
    return NULL;

  fec = mpls_new_fec(m, net->type, label);

  fec->hash = hash;
  fec->path_id = path_id;
  net_copy(fec->net, net);

  fec->policy = MPLS_POLICY_PREFIX;
  fec->handle = m->handle;

  DBGL("New FEC net %u map %p", fec->label, m);

  HASH_INSERT2(m->net_hash, NET, m->pool, fec);

  return fec;
}

struct mpls_fec *
mpls_get_fec_by_destination(struct mpls_fec_map *m, ea_list *dest)
{
  if (!m->attrs_hash.data)
    HASH_INIT(m->attrs_hash, m->pool, 4);

  struct ea_storage *rta = mpls_get_key_attrs(m, dest);
  u32 hash = rta->hash_key;
  struct mpls_fec *fec = HASH_FIND(m->attrs_hash, RTA, rta);

  if (fec)
  {
    ea_free(rta->l);
    mpls_revive_fec(fec);
    return fec;
  }

  u32 label = 0;
  MPLS_HANDLE_LOCKED(m->handle, h)
    label = mpls_new_label(h, 0);

  if (!label)
  {
    ea_free(rta->l);
    return NULL;
  }

  fec = mpls_new_fec(m, 0, label);

  fec->hash = hash;
  fec->rta = rta;

  fec->policy = MPLS_POLICY_AGGREGATE;
  fec->handle = m->handle;

  DBGL("New FEC rta %u map %p", fec->label, m);

  HASH_INSERT2(m->attrs_hash, RTA, m->pool, fec);

  return fec;
}

struct mpls_fec *
mpls_get_fec_for_vrf(struct mpls_fec_map *m)
{
  struct mpls_fec *fec = m->vrf_fec;

  if (fec)
  {
    mpls_revive_fec(fec);
    return fec;
  }

  u32 label = 0;
  MPLS_HANDLE_LOCKED(m->handle, h)
    label = mpls_new_label(h, 0);

  if (!label)
    return NULL;

  fec = mpls_new_fec(m, 0, label);

  fec->policy = MPLS_POLICY_VRF;
  fec->handle = m->handle;
  fec->iface = m->vrf_iface;

  DBGL("New FEC vrf %u map %p", fec->label, m);

  m->vrf_fec = fec;

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
    DBGL("Unlink FEC %p %u from net_hash");
    HASH_REMOVE2(m->net_hash, NET, m->pool, fec);
    break;

  case MPLS_POLICY_AGGREGATE:
    DBGL("Unlink FEC %p %u from attrs_hash (%d) at %p", fec, fec->label, m->attrs_hash.count, m);
    HASH_REMOVE2(m->attrs_hash, RTA, m->pool, fec);
    ea_free(fec->rta->l);
    break;

  case MPLS_POLICY_VRF:
    ASSERT(m->vrf_fec == fec);
    m->vrf_fec = NULL;
    break;

  default:
    bug("Unknown fec type");
  }
}

static void
mpls_free_fec(struct mpls_fec_map *m, struct mpls_fec *fec)
{
  if (fec->state != MPLS_FEC_DOWN)
    mpls_withdraw_fec(m, fec);

  DBGL("Free FEC %p %u of map %p, handle %p", fec, fec->label, m, fec->handle);

  MPLS_DOMAIN_LOCKED(m->domain, domain)
  {
    struct mpls_handle *h = MPLS_HANDLE_PRIV(fec->handle);
    mpls_free_label(h, fec->label);

    DBGL("Handle %p policy %d label count %d", fec->handle, fec->policy, h->label_count);
    if (!fec->policy && !h->label_count)
      mpls_free_handle(h);
  }

  HASH_REMOVE2(m->label_hash, LABEL, m->pool, fec);

  mpls_unlink_fec(m, fec);

  sl_free(fec);
}

inline void mpls_revive_fec(struct mpls_fec *fec)
{
  UNUSED u64 s = lfuc_lock_revive(&fec->uc);
  DBGL("Locked FEC %p %u, was %lu (i)", fec, fec->label, s);
}

inline void mpls_lock_fec(struct mpls_fec *fec)
{
  UNUSED u64 s = lfuc_lock(&fec->uc);
  DBGL("Locked FEC %p %u, was %lu", fec, fec->label, s);
}

inline void mpls_unlock_fec(struct mpls_fec *fec)
{
  lfuc_unlock(&fec->uc, birdloop_event_list(fec->map->loop), fec->map->cleanup_event);
  DBGL("Unlocked FEC %p %u (deferred)", fec, fec->label);
}

static inline void
mpls_damage_fec(struct mpls_fec_map *m UNUSED, struct mpls_fec *fec)
{
  if (fec->state == MPLS_FEC_CLEAN)
    fec->state = MPLS_FEC_DIRTY;
}

static struct ea_storage *
mpls_get_key_attrs(struct mpls_fec_map *m, ea_list *src)
{
  EA_LOCAL_LIST(4) ea = {};

  uint last_id = 0;
  #define PUT_ATTR(cls)	do { \
    ASSERT_DIE(last_id < (cls)->id); \
    last_id = (cls)->id; \
    eattr *a = ea_find_by_class(src, (cls)); \
    if (a) ea.a[ea.l.count++] = *a; \
  } while (0)

  PUT_ATTR(&ea_gen_nexthop);
  PUT_ATTR(&ea_gen_hostentry);
  ea.a[ea.l.count++] = EA_LITERAL_EMBEDDED(&ea_gen_source, 0, m->mpls_rts);
  PUT_ATTR(&ea_gen_mpls_class);

  return ea_get_storage(ea_lookup(&ea.l, 0, EALS_KEY));
}

static void
mpls_announce_fec(struct mpls_fec_map *m, struct mpls_fec *fec, ea_list *src)
{
  rte e = {
    .src = m->channel->proto->main_source,
  };

  ea_set_attr_u32(&e.attrs, &ea_gen_source, 0, m->mpls_rts);

  /* Check existence of hostentry */
  const struct eattr *heea = ea_find_by_class(src, &ea_gen_hostentry);
  if (heea) {
    /* The same hostentry, but different dependent table */
    SKIP_BACK_DECLARE(struct hostentry_adata, head, ad, heea->u.ad);
    struct hostentry *he = head->he;
    ea_set_hostentry(&e.attrs, m->channel->table, he->owner, he->addr, he->link,
	HOSTENTRY_LABEL_COUNT(head), head->labels);
  }
  else
  {
    const struct eattr *nhea = ea_find_by_class(src, &ea_gen_nexthop);
    if (!nhea)
      bug("FEC has neither a hostentry, nor a nexthop");
    ea_set_attr(&e.attrs, *nhea);
  }

  net_addr_mpls n = NET_ADDR_MPLS(fec->label);

  fec->state = MPLS_FEC_CLEAN;
  rte_update(m->channel, (net_addr *) &n, &e, m->channel->proto->main_source);
}

static void
mpls_withdraw_fec(struct mpls_fec_map *m, struct mpls_fec *fec)
{
  /* The MPLS channel is already stopping */
  if (m->channel->channel_state != CS_UP)
    return;

  net_addr_mpls n = NET_ADDR_MPLS(fec->label);

  fec->state = MPLS_FEC_DOWN;
  rte_update(m->channel, (net_addr *) &n, NULL, m->channel->proto->main_source);
}

static void
mpls_apply_fec(rte *r, struct mpls_fec *fec)
{
  ea_set_attr_u32(&r->attrs, &ea_gen_mpls_label, 0, fec->label);
  ea_set_attr_u32(&r->attrs, &ea_gen_mpls_policy, 0, fec->policy);

  if (fec->policy == MPLS_POLICY_VRF)
  {
    ea_unset_attr(&r->attrs, 0, &ea_gen_hostentry);

    struct nexthop_adata nhad = {
      .nh.iface = fec->iface,
      .ad.length = sizeof nhad - sizeof nhad.ad,
    };
    ea_set_attr_data(&r->attrs, &ea_gen_nexthop, 0, nhad.ad.data, nhad.ad.length);
  }
}


int
mpls_handle_rte(struct channel *c, const net_addr *n, rte *r, struct mpls_fec **fecp)
{
  SKIP_BACK_DECLARE(struct mpls_channel, mc, c, c->proto->mpls_channel);
  struct mpls_fec_map *m = mc->mpls_map;
  struct mpls_fec *fec = *fecp = NULL;

  /* Select FEC for route */
  uint policy = ea_get_int(r->attrs, &ea_gen_mpls_policy, 0);
  switch (policy)
  {
  case MPLS_POLICY_NONE:
    return 0;

  case MPLS_POLICY_STATIC:;
    uint label = ea_get_int(r->attrs, &ea_gen_mpls_label, 0);

    if (label < 16)
      return 0;

    fec = mpls_get_fec_by_label(m, label);
    if (!fec)
    {
      log(L_WARN "Static label %u failed for %N from %s",
	  label, n, r->sender->req->name);
      return -1;
    }

    mpls_damage_fec(m, fec);
    break;

  case MPLS_POLICY_PREFIX:
    fec = mpls_get_fec_by_net(m, n, r->src->private_id);
    mpls_damage_fec(m, fec);
    break;

  case MPLS_POLICY_AGGREGATE:
    fec = mpls_get_fec_by_destination(m, r->attrs);
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
	m->handle->name, n, r->sender->req->name);
    return -1;
  }

  /* Apply FEC label to route */
  mpls_apply_fec(r, fec);

  /* Announce MPLS rule for new/updated FEC */
  if (fec->state != MPLS_FEC_CLEAN)
    mpls_announce_fec(m, fec, r->attrs);

  /* Store the returned FEC for later unlock */
  *fecp = fec;
  return 0;
}

static inline struct mpls_fec *
mpls_rte_get_fec(const rte *r)
{
  struct channel *c = SKIP_BACK(struct proto, sources, r->src->owner)->mpls_channel;
  if (!c)
    return NULL;

  uint label = ea_get_int(r->attrs, &ea_gen_mpls_label, 0);
  if (label < 16)
    return NULL;

  return mpls_find_fec_by_label(SKIP_BACK(struct mpls_channel, c, c)->mpls_map, label);
}

void
mpls_rte_preimport(rte *new, const rte *old)
{
  struct mpls_fec *new_fec = new ? mpls_rte_get_fec(new) : NULL;
  struct mpls_fec *old_fec = old ? mpls_rte_get_fec(old) : NULL;


  if (new_fec == old_fec)
    return;

  if (new_fec)
  {
    DBGL("Lock FEC %p (preimport %p)", new_fec, new);
    mpls_lock_fec(new_fec);
  }

  if (old_fec)
  {
    mpls_unlock_fec(old_fec);
    DBGL("Unlock FEC %p (preimport %p)", old_fec, old);
  }
}

static void
mpls_show_ranges_rng(struct mpls_show_ranges_cmd *cmd UNUSED, struct mpls_range *r)
{
  uint last = lmap_last_one_in_range(&r->domain->labels, r->lo, r->hi);
  if (last == r->hi) last = 0;

  cli_msg(-1026, "%-11s %7u %7u %7u %7u %7u",
	  r->name, r->lo, r->hi - r->lo, r->hi, r->label_count, last);
}

void
mpls_show_ranges_dom(struct mpls_show_ranges_cmd *cmd, struct mpls_domain_pub *mpub)
{
  MPLS_DOMAIN_LOCK(mpub, m);

  cli_msg(-1026, "MPLS domain %s:", m->name);
  cli_msg(-1026, "%-11s %7s %7s %7s %7s %7s",
	  "Range", "Start", "Length", "End", "Labels", "Last");

  if (cmd->range)
    mpls_show_ranges_rng(cmd, MPLS_RANGE_PRIV(cmd->range->range));
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
    struct mpls_domain_pub *m;
    bool first = 1;
    WALK_LIST(m, MPLS_GLOBAL->domains)
    {
      if (first)
	first = 0;
      else
	cli_msg(-1026, "");

      mpls_show_ranges_dom(cmd, m);
    }
  }

  cli_msg(0, "");
}

struct ea_class ea_gen_mpls_policy = {
  .name = "mpls_policy",
  .type = T_ENUM_MPLS_POLICY,
};

struct ea_class ea_gen_mpls_class = {
  .name = "mpls_class",
  .type = T_INT,
};

struct ea_class ea_gen_mpls_label = {
  .name = "mpls_label",
  .type = T_INT,
};
