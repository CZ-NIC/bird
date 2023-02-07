/*
 *	BIRD -- Static Route Generator
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Static
 *
 * The Static protocol is implemented in a straightforward way. It keeps a list
 * of static routes. Routes of dest RTD_UNICAST have associated sticky node in
 * the neighbor cache to be notified about gaining or losing the neighbor and
 * about interface-related events (e.g. link down). They may also have a BFD
 * request if associated with a BFD session. When a route is notified,
 * static_decide() is used to see whether the route activeness is changed. In
 * such case, the route is marked as dirty and scheduled to be announced or
 * withdrawn, which is done asynchronously from event hook. Routes of other
 * types (e.g. black holes) are announced all the time.
 *
 * Multipath routes are a bit tricky. To represent additional next hops, dummy
 * static_route nodes are used, which are chained using @mp_next field and link
 * to the master node by @mp_head field. Each next hop has a separate neighbor
 * entry and an activeness state, but the master node is used for most purposes.
 * Note that most functions DO NOT accept dummy nodes as arguments.
 *
 * The only other thing worth mentioning is that when asked for reconfiguration,
 * Static not only compares the two configurations, but it also calculates
 * difference between the lists of static routes and it just inserts the newly
 * added routes, removes the obsolete ones and reannounces changed ones.
 */

#undef LOCAL_DEBUG

#include <stdlib.h>

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/rt.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "lib/string.h"
#include "lib/alloca.h"

#include "static.h"

static inline struct rte_src * static_get_source(struct static_proto *p, uint i)
{ return i ? rt_get_source(&p->p, i) : p->p.main_source; }

static inline void static_free_source(struct rte_src *src, uint i)
{ if (i) rt_unlock_source(src); }

static void
static_announce_rte(struct static_proto *p, struct static_route *r)
{
  struct rte_src *src;
  ea_list *ea = NULL;
  ea_set_attr_u32(&ea, &ea_gen_preference, 0, p->p.main_channel->preference);
  ea_set_attr_u32(&ea, &ea_gen_source, 0, RTS_STATIC);

  if (r->dest == RTD_UNICAST)
  {
    uint sz = 0;
    for (struct static_route *r2 = r; r2; r2 = r2->mp_next)
      if (r2->active)
	sz += NEXTHOP_SIZE_CNT(r2->mls ? r2->mls->length / sizeof(u32) : 0);

    if (!sz)
      goto withdraw;

    struct nexthop_adata *nhad = allocz(sz + sizeof *nhad);
    struct nexthop *nh = &nhad->nh;

    for (struct static_route *r2 = r; r2; r2 = r2->mp_next)
    {
      if (!r2->active)
	continue;

      *nh = (struct nexthop) {
	.gw = r2->via,
	.iface = r2->neigh->iface,
	.flags = r2->onlink ? RNF_ONLINK : 0,
	.weight = r2->weight,
      };

      if (r2->mls)
      {
	nh->labels = r2->mls->length / sizeof(u32);
	memcpy(nh->label, r2->mls->data, r2->mls->length);
      }

      nh = NEXTHOP_NEXT(nh);
    }

    ea_set_attr_data(&ea, &ea_gen_nexthop, 0,
	nhad->ad.data, (void *) nh - (void *) nhad->ad.data);
  }

  else if (r->dest == RTDX_RECURSIVE)
  {
    rtable *tab = ipa_is_ip4(r->via) ? p->igp_table_ip4 : p->igp_table_ip6;
    u32 *labels = r->mls ? (void *) r->mls->data : NULL;
    u32 lnum = r->mls ? r->mls->length / sizeof(u32) : 0;

    ea_set_hostentry(&ea, p->p.main_channel->table, tab,
	r->via, IPA_NONE, lnum, labels);
  }

  else if (r->dest)
    ea_set_dest(&ea, 0, r->dest);

  /* Already announced */
  if (r->state == SRS_CLEAN)
    return;

  /* We skip rta_lookup() here */
  src = static_get_source(p, r->index);
  rte e0 = { .attrs = ea, .src = src, .net = r->net, }, *e = &e0;

  /* Evaluate the filter */
  if (r->cmds)
    f_eval_rte(r->cmds, e);

  rte_update(p->p.main_channel, r->net, e, src);
  static_free_source(src, r->index);

  r->state = SRS_CLEAN;
  return;

withdraw:
  if (r->state == SRS_DOWN)
    return;

  src = static_get_source(p, r->index);
  rte_update(p->p.main_channel, r->net, NULL, src);
  static_free_source(src, r->index);
  r->state = SRS_DOWN;
}

static void
static_mark_rte(struct static_proto *p, struct static_route *r)
{
  if (r->state == SRS_DIRTY)
    return;

  r->state = SRS_DIRTY;
  BUFFER_PUSH(p->marked) = r;

  if (!ev_active(p->event))
    ev_schedule(p->event);
}

static void
static_mark_all(struct static_proto *p)
{
  struct static_config *cf = (void *) p->p.cf;
  struct static_route *r;

  /* We want to reload all routes, mark them as dirty */

  WALK_LIST(r, cf->routes)
    if (r->state == SRS_CLEAN)
      r->state = SRS_DIRTY;

  p->marked_all = 1;
  BUFFER_FLUSH(p->marked);

  if (!ev_active(p->event))
    ev_schedule(p->event);
}


static void
static_announce_marked(void *P)
{
  struct static_proto *p = P;
  struct static_config *cf = (void *) p->p.cf;
  struct static_route *r;

  if (p->marked_all)
  {
    WALK_LIST(r, cf->routes)
      if (r->state == SRS_DIRTY)
	static_announce_rte(p, r);

    p->marked_all = 0;
  }
  else
  {
    BUFFER_WALK(p->marked, r)
      static_announce_rte(p, r);

    BUFFER_FLUSH(p->marked);
  }
}

static void
static_bfd_notify(struct bfd_request *req);

static void
static_update_bfd(struct static_proto *p, struct static_route *r)
{
  /* The @r is a RTD_UNICAST next hop, may be a dummy node */

  struct neighbor *nb = r->neigh;
  int bfd_up = (nb->scope > 0) && r->use_bfd;

  if (bfd_up && !r->bfd_req)
  {
    // ip_addr local = ipa_nonzero(r->local) ? r->local : nb->ifa->ip;
    r->bfd_req = bfd_request_session(p->p.pool, r->via, nb->ifa->ip,
				     nb->iface, p->p.vrf,
				     static_bfd_notify, r, p->p.loop, NULL);
  }

  if (!bfd_up && r->bfd_req)
  {
    rfree(r->bfd_req);
    r->bfd_req = NULL;
  }
}

static int
static_decide(struct static_proto *p, struct static_route *r)
{
  /* The @r is a RTD_UNICAST next hop, may be a dummy node */

  struct static_config *cf = (void *) p->p.cf;
  uint old_active = r->active;

  if (r->neigh->scope < 0)
    goto fail;

  if (cf->check_link && !(r->neigh->iface->flags & IF_LINK_UP))
    goto fail;

  if (r->bfd_req && (r->bfd_req->state != BFD_STATE_UP))
    goto fail;

  r->active = 1;
  return !old_active;

fail:
  r->active = 0;
  return old_active;
}

static void
static_add_rte(struct static_proto *p, struct static_route *r)
{
  if (r->dest == RTD_UNICAST)
  {
    struct static_route *r2;
    struct neighbor *n;

    for (r2 = r; r2; r2 = r2->mp_next)
    {
      n = neigh_find(&p->p, r2->via, r2->iface, NEF_STICKY |
		     (r2->onlink ? NEF_ONLINK : 0) |
		     (ipa_zero(r2->via) ? NEF_IFACE : 0));

      if (!n)
      {
	log(L_WARN "Invalid next hop %I of static route %N", r2->via, r2->net);
	continue;
      }

      r2->neigh = n;
      r2->chain = n->data;
      n->data = r2;

      static_update_bfd(p, r2);
      static_decide(p, r2);
    }
  }

  static_announce_rte(p, r);
}

static void
static_reset_rte(struct static_proto *p UNUSED, struct static_route *r)
{
  struct static_route *r2;

  for (r2 = r; r2; r2 = r2->mp_next)
  {
    r2->neigh = NULL;
    r2->chain = NULL;

    r2->state = 0;
    r2->active = 0;

    rfree(r2->bfd_req);
    r2->bfd_req = NULL;
  }
}

static void
static_remove_rte(struct static_proto *p, struct static_route *r)
{
  if (r->state)
  {
    struct rte_src *src = static_get_source(p, r->index);
    rte_update(p->p.main_channel, r->net, NULL, src);
    static_free_source(src, r->index);
  }

  static_reset_rte(p, r);
}


static inline int
static_same_dest(struct static_route *x, struct static_route *y)
{
  if (x->dest != y->dest)
    return 0;

  switch (x->dest)
  {
  case RTD_UNICAST:
    for (; x && y; x = x->mp_next, y = y->mp_next)
    {
      if (!ipa_equal(x->via, y->via) ||
	  (x->iface != y->iface) ||
	  (x->onlink != y->onlink) ||
	  (x->weight != y->weight) ||
	  (x->use_bfd != y->use_bfd) ||
	  (!x->mls != !y->mls) ||
	  ((x->mls) && (y->mls) && adata_same(x->mls, y->mls)))
	return 0;
    }
    return !x && !y;

  case RTDX_RECURSIVE:
    if (!ipa_equal(x->via, y->via) ||
	(!x->mls != !y->mls) ||
	((x->mls) && (y->mls) && adata_same(x->mls, y->mls)))
      return 0;

    return 1;

  default:
    return 1;
  }
}

static inline int
static_same_rte(struct static_route *or, struct static_route *nr)
{
  /* Note that i_same() requires arguments in (new, old) order */
  return static_same_dest(or, nr) && f_same(nr->cmds, or->cmds);
}

static void
static_reconfigure_rte(struct static_proto *p, struct static_route *or, struct static_route *nr)
{
  if ((or->state == SRS_CLEAN) && !static_same_rte(or, nr))
    nr->state = SRS_DIRTY;
  else
    nr->state = or->state;

  static_add_rte(p, nr);
  static_reset_rte(p, or);
}


static void
static_neigh_notify(struct neighbor *n)
{
  struct static_proto *p = (void *) n->proto;
  struct static_route *r;

  DBG("Static: neighbor notify for %I: iface %p\n", n->addr, n->iface);
  for (r = n->data; r; r = r->chain)
  {
    static_update_bfd(p, r);

    if (static_decide(p, r))
      static_mark_rte(p, r->mp_head);
  }
}

static void
static_bfd_notify(struct bfd_request *req)
{
  struct static_route *r = req->data;
  struct static_proto *p = (void *) r->neigh->proto;

  // if (req->down) TRACE(D_EVENTS, "BFD session down for nbr %I on %s", XXXX);

  if (static_decide(p, r))
    static_mark_rte(p, r->mp_head);
}

static void
static_reload_routes(struct channel *C)
{
  struct static_proto *p = (void *) C->proto;

  TRACE(D_EVENTS, "Scheduling route reload");

  static_mark_all(p);
}

static int
static_rte_better(rte *new, rte *old)
{
  u32 n = ea_get_int(new->attrs, &ea_gen_igp_metric, IGP_METRIC_UNKNOWN);
  u32 o = ea_get_int(old->attrs, &ea_gen_igp_metric, IGP_METRIC_UNKNOWN);
  return n < o;
}

static int
static_rte_mergable(rte *pri, rte *sec)
{
  u32 a = ea_get_int(pri->attrs, &ea_gen_igp_metric, IGP_METRIC_UNKNOWN);
  u32 b = ea_get_int(sec->attrs, &ea_gen_igp_metric, IGP_METRIC_UNKNOWN);
  return a == b;
}

static void static_index_routes(struct static_config *cf);

static void
static_postconfig(struct proto_config *CF)
{
  struct static_config *cf = (void *) CF;
  struct static_route *r;

  if (! proto_cf_main_channel(CF))
    cf_error("Channel not specified");

  struct channel_config *cc = proto_cf_main_channel(CF);

  if (!cf->igp_table_ip4)
    cf->igp_table_ip4 = (cc->table->addr_type == NET_IP4) ?
      cc->table : rt_get_default_table(cf->c.global, NET_IP4);

  if (!cf->igp_table_ip6)
    cf->igp_table_ip6 = (cc->table->addr_type == NET_IP6) ?
      cc->table : rt_get_default_table(cf->c.global, NET_IP6);

  WALK_LIST(r, cf->routes)
    if (r->net && (r->net->type != CF->net_type))
      cf_error("Route %N incompatible with channel type", r->net);

  static_index_routes(cf);
}

static struct rte_owner_class static_rte_owner_class;

static struct proto *
static_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct static_proto *p = (void *) P;
  struct static_config *cf = (void *) CF;

  P->main_channel = proto_add_channel(P, proto_cf_main_channel(CF));

  P->iface_sub.neigh_notify = static_neigh_notify;
  P->reload_routes = static_reload_routes;
  P->sources.class = &static_rte_owner_class;

  if (cf->igp_table_ip4)
    p->igp_table_ip4 = cf->igp_table_ip4->table;

  if (cf->igp_table_ip6)
    p->igp_table_ip6 = cf->igp_table_ip6->table;

  return P;
}

static int
static_start(struct proto *P)
{
  struct static_proto *p = (void *) P;
  struct static_config *cf = (void *) P->cf;
  struct static_route *r;

  if (p->igp_table_ip4)
    rt_lock_table(p->igp_table_ip4);

  if (p->igp_table_ip6)
    rt_lock_table(p->igp_table_ip6);

  p->event = ev_new_init(p->p.pool, static_announce_marked, p);

  BUFFER_INIT(p->marked, p->p.pool, 4);

  /* We have to go UP before routes could be installed */
  proto_notify_state(P, PS_UP);

  WALK_LIST(r, cf->routes)
  {
    struct lp_state lps;
    lp_save(tmp_linpool, &lps);
    static_add_rte(p, r);
    lp_restore(tmp_linpool, &lps);
  }

  return PS_UP;
}

static int
static_shutdown(struct proto *P)
{
  struct static_proto *p = (void *) P;
  struct static_config *cf = (void *) P->cf;
  struct static_route *r;

  /* Just reset the flag, the routes will be flushed by the nest */
  WALK_LIST(r, cf->routes)
    static_reset_rte(p, r);

  if (p->igp_table_ip4)
    rt_unlock_table(p->igp_table_ip4);

  if (p->igp_table_ip6)
    rt_unlock_table(p->igp_table_ip6);

  return PS_DOWN;
}

static void
static_dump_rte(struct static_route *r)
{
  debug("%-1N (%u): ", r->net, r->index);
  if (r->dest == RTD_UNICAST)
    if (r->iface && ipa_zero(r->via))
      debug("dev %s\n", r->iface->name);
    else
      debug("via %I%J\n", r->via, r->iface);
  else
    debug("rtd %d\n", r->dest);
}

static void
static_dump(struct proto *P)
{
  struct static_config *c = (void *) P->cf;
  struct static_route *r;

  debug("Static routes:\n");
  WALK_LIST(r, c->routes)
    static_dump_rte(r);
}

#define IGP_TABLE(cf, sym) ((cf)->igp_table_##sym ? (cf)->igp_table_##sym ->table : NULL )

static inline int srt_equal(const struct static_route *a, const struct static_route *b)
{ return net_equal(a->net, b->net) && (a->index == b->index); }

static inline int srt_compare(const struct static_route *a, const struct static_route *b)
{ return net_compare(a->net, b->net) ?: uint_cmp(a->index, b->index); }

static inline int srt_compare_qsort(const void *A, const void *B)
{
  return srt_compare(*(const struct static_route * const *)A,
		     *(const struct static_route * const *)B);
}

static void
static_index_routes(struct static_config *cf)
{
  struct static_route *rt, **buf;
  uint num, i, v;

  num = list_length(&cf->routes);
  buf = xmalloc(num * sizeof(void *));

  /* Initialize with sequential indexes to ensure stable sorting */
  i = 0;
  WALK_LIST(rt, cf->routes)
  {
    buf[i] = rt;
    rt->index = i++;
  }

  qsort(buf, num, sizeof(struct static_route *), srt_compare_qsort);

  /* Compute proper indexes - sequential for routes with same network */
  for (i = 0, v = 0, rt = NULL; i < num; i++, v++)
  {
    if (rt && !net_equal(buf[i]->net, rt->net))
      v = 0;

    rt = buf[i];
    rt->index = v;
  }

  xfree(buf);
}

static int
static_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct static_proto *p = (void *) P;
  struct static_config *o = (void *) P->cf;
  struct static_config *n = (void *) CF;
  struct static_route *r, *r2, *or, *nr;

  /* Check change in IGP tables */
  if ((IGP_TABLE(o, ip4) != IGP_TABLE(n, ip4)) ||
      (IGP_TABLE(o, ip6) != IGP_TABLE(n, ip6)))
    return 0;

  if (!proto_configure_channel(P, &P->main_channel, proto_cf_main_channel(CF)))
    return 0;

  p->p.cf = CF;

  /* Reset route lists in neighbor entries */
  WALK_LIST(r, o->routes)
    for (r2 = r; r2; r2 = r2->mp_next)
      if (r2->neigh)
	r2->neigh->data = NULL;

  /* Reconfigure initial matching sequence */
  for (or = HEAD(o->routes), nr = HEAD(n->routes);
       NODE_VALID(or) && NODE_VALID(nr) && srt_equal(or, nr);
       or = NODE_NEXT(or), nr = NODE_NEXT(nr))
    static_reconfigure_rte(p, or, nr);

  if (!NODE_VALID(or) && !NODE_VALID(nr))
    return 1;

  /* Reconfigure remaining routes, sort them to find matching pairs */
  struct static_route *or2, *nr2, **orbuf, **nrbuf;
  uint ornum = 0, nrnum = 0, orpos = 0, nrpos = 0, i;

  for (or2 = or; NODE_VALID(or2); or2 = NODE_NEXT(or2))
    ornum++;

  for (nr2 = nr; NODE_VALID(nr2); nr2 = NODE_NEXT(nr2))
    nrnum++;

  orbuf = xmalloc(ornum * sizeof(void *));
  nrbuf = xmalloc(nrnum * sizeof(void *));

  for (i = 0, or2 = or; i < ornum; i++, or2 = NODE_NEXT(or2))
    orbuf[i] = or2;

  for (i = 0, nr2 = nr; i < nrnum; i++, nr2 = NODE_NEXT(nr2))
    nrbuf[i] = nr2;

  qsort(orbuf, ornum, sizeof(struct static_route *), srt_compare_qsort);
  qsort(nrbuf, nrnum, sizeof(struct static_route *), srt_compare_qsort);

  while ((orpos < ornum) && (nrpos < nrnum))
  {
    int x = srt_compare(orbuf[orpos], nrbuf[nrpos]);
    if (x < 0)
      static_remove_rte(p, orbuf[orpos++]);
    else if (x > 0)
      static_add_rte(p, nrbuf[nrpos++]);
    else
      static_reconfigure_rte(p, orbuf[orpos++], nrbuf[nrpos++]);
  }

  while (orpos < ornum)
    static_remove_rte(p, orbuf[orpos++]);

  while (nrpos < nrnum)
    static_add_rte(p, nrbuf[nrpos++]);

  xfree(orbuf);
  xfree(nrbuf);

  /* All dirty routes were announced anyways */
  BUFFER_FLUSH(p->marked);
  p->marked_all = 0;

  return 1;
}

static void
static_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct static_config *d = (struct static_config *) dest;
  struct static_config *s = (struct static_config *) src;

  struct static_route *srt, *snh;

  /* Copy route list */
  init_list(&d->routes);
  WALK_LIST(srt, s->routes)
  {
    struct static_route *drt = NULL, *dnh = NULL, **dnp = &drt;

    for (snh = srt; snh; snh = snh->mp_next)
    {
      dnh = cfg_alloc(sizeof(struct static_route));
      memcpy(dnh, snh, sizeof(struct static_route));
      memset(&dnh->n, 0, sizeof(node));

      if (!drt)
	add_tail(&d->routes, &(dnh->n));

      *dnp = dnh;
      dnp = &(dnh->mp_next);

      if (snh->mp_head)
	dnh->mp_head = drt;
    }
  }
}

static void
static_get_route_info(rte *rte, byte *buf)
{
  eattr *a = ea_find(rte->attrs, &ea_gen_igp_metric);
  u32 pref = rt_get_preference(rte);
  if (a && (a->u.data < IGP_METRIC_UNKNOWN))
    buf += bsprintf(buf, " (%d/%u)", pref, a->u.data);
  else
    buf += bsprintf(buf, " (%d)", pref);
}

static void
static_show_rt(struct static_route *r)
{
  switch (r->dest)
  {
  case RTD_UNICAST:
  {
    struct static_route *r2;

    cli_msg(-1009, "%N", r->net);
    for (r2 = r; r2; r2 = r2->mp_next)
    {
      if (r2->iface && ipa_zero(r2->via))
	cli_msg(-1009, "\tdev %s%s", r2->iface->name,
		r2->active ? "" : " (dormant)");
      else
	cli_msg(-1009, "\tvia %I%J%s%s%s", r2->via, r2->iface,
		r2->onlink ? " onlink" : "",
		r2->bfd_req ? " (bfd)" : "",
		r2->active ? "" : " (dormant)");
    }
    break;
  }

  case RTD_NONE:
  case RTD_BLACKHOLE:
  case RTD_UNREACHABLE:
  case RTD_PROHIBIT:
    cli_msg(-1009, "%N\t%s", r->net, rta_dest_names[r->dest]);
    break;

  case RTDX_RECURSIVE:
    cli_msg(-1009, "%N\trecursive %I", r->net, r->via);
    break;
  }
}

void
static_show(struct proto *P)
{
  struct static_config *c = (void *) P->cf;
  struct static_route *r;

  WALK_LIST(r, c->routes)
    static_show_rt(r);
}

static struct rte_owner_class static_rte_owner_class = {
  .get_route_info =	static_get_route_info,
  .rte_better =		static_rte_better,
  .rte_mergable =	static_rte_mergable,
};

struct protocol proto_static = {
  .name =		"Static",
  .template =		"static%d",
  .preference =		DEF_PREF_STATIC,
  .channel_mask =	NB_ANY,
  .proto_size =		sizeof(struct static_proto),
  .config_size =	sizeof(struct static_config),
  .postconfig =		static_postconfig,
  .init =		static_init,
  .dump =		static_dump,
  .start =		static_start,
  .shutdown =		static_shutdown,
  .reconfigure =	static_reconfigure,
  .copy_config =	static_copy_config,
};

void
static_build(void)
{
  proto_build(&proto_static);
}
