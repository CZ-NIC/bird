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
 * The Static protocol is implemented in a straightforward way. It keeps
 * two lists of static routes: one containing interface routes and one
 * holding the remaining ones. Interface routes are inserted and removed according
 * to interface events received from the core via the if_notify() hook. Routes
 * pointing to a neighboring router use a sticky node in the neighbor cache
 * to be notified about gaining or losing the neighbor. Special
 * routes like black holes or rejects are inserted all the time.
 *
 * Multipath routes are tricky. Because these routes depends on
 * several neighbors we need to integrate that to the neighbor
 * notification handling, we use dummy static_route nodes, one for
 * each nexthop. Therefore, a multipath route consists of a master
 * static_route node (of dest RTD_MULTIPATH), which specifies prefix
 * and is used in most circumstances, and a list of dummy static_route
 * nodes (of dest RTD_NONE), which stores info about nexthops and are
 * connected to neighbor entries and neighbor notifications. Dummy
 * nodes are chained using mp_next, they aren't in other_routes list,
 * and abuse if_name field for other purposes.
 *
 * The only other thing worth mentioning is that when asked for reconfiguration,
 * Static not only compares the two configurations, but it also calculates
 * difference between the lists of static routes and it just inserts the
 * newly added routes and removes the obsolete ones.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "lib/string.h"
#include "lib/alloca.h"

#include "static.h"

static linpool *static_lp;

static inline rtable *
p_igp_table(struct proto *p)
{
  struct static_config *cf = (void *) p->cf;
  return cf->igp_table ? cf->igp_table->table : p->main_channel->table;
}

static void
static_install(struct proto *p, struct static_route *r)
{
  rta *ap = alloca(RTA_MAX_SIZE);
  rte *e;

  if (!(r->state & STS_WANT) && (r->state & (STS_INSTALLED | STS_FORCE)) && r->dest != RTD_UNICAST)
    goto drop;

  DBG("Installing static route %N, rtd=%d\n", r->net, r->dest);
  bzero(ap, RTA_MAX_SIZE);
  ap->src = p->main_source;
  ap->source = ((r->dest == RTD_UNICAST) && ipa_zero(r->via)) ? RTS_STATIC_DEVICE : RTS_STATIC;
  ap->scope = SCOPE_UNIVERSE;
  ap->dest = r->dest;

  if (r->dest == RTD_UNICAST)
    {
      struct static_route *r2;
      int num = 0, update = 0;

      for (r2 = r; r2; r2 = r2->mp_next)
      {

	if ((r2->state & STS_FORCE) ||
	    (!!(r2->state & STS_INSTALLED) != !!(r2->state & STS_WANT)))
	  update++;

	if (r2->state & STS_WANT)
	  {
	    struct nexthop *nh = (ap->nh.next) ? alloca(NEXTHOP_MAX_SIZE) : &(ap->nh);
	    if (ipa_zero(r2->via)) // Device nexthop
	      {
		nh->gw = IPA_NONE;
		nh->iface = r2->iface;
	      }
	    else // Router nexthop
	      {
		nh->gw = r2->via;
		nh->iface = r2->neigh->iface;
	      }
	    nh->weight = r2->weight;
	    nh->labels = r2->label_count;
	    for (int i=0; i<nh->labels; i++)
	      nh->label[i] = r2->label_stack[i];

	    if (ap->nh.next)
	      nexthop_insert(&(ap->nh), nh);
	    r2->state |= STS_INSTALLED;
	    num++;
	  }
	else
	  r2->state = 0;
      }

      if (!update) // Nothing changed
	return;

      r = r->mp_head;

      if (!num) // No nexthop to install
      {
drop:
	rte_update(p, r->net, NULL);
	return;
      }
    }
  else
    r->state |= STS_INSTALLED;
  
  if (r->dest == RTDX_RECURSIVE)
    rta_set_recursive_next_hop(p->main_channel->table, ap, p_igp_table(p), r->via, IPA_NONE);

  /* We skip rta_lookup() here */

  e = rte_get_temp(ap);
  e->pflags = 0;

  if (r->cmds)
    f_eval_rte(r->cmds, &e, static_lp);

  rte_update(p, r->net, e);

  if (r->cmds)
    lp_flush(static_lp);
}

static void
static_bfd_notify(struct bfd_request *req);

static void
static_update_bfd(struct proto *p, struct static_route *r)
{
  struct neighbor *nb = r->neigh;
  int bfd_up = (nb->scope > 0) && r->use_bfd;

  if (bfd_up && !r->bfd_req)
  {
    // ip_addr local = ipa_nonzero(r->local) ? r->local : nb->ifa->ip;
    r->bfd_req = bfd_request_session(p->pool, r->via, nb->ifa->ip, nb->iface,
				     static_bfd_notify, r);
  }

  if (!bfd_up && r->bfd_req)
  {
    rfree(r->bfd_req);
    r->bfd_req = NULL;
  }
}

static int
static_decide(struct static_config *cf, struct static_route *r)
{
  /* r->dest != RTD_MULTIPATH, but may be RTD_NONE (part of multipath route)
     the route also have to be valid (r->neigh != NULL) */

  r->state &= ~STS_WANT;

  if (r->neigh->scope < 0)
    return 0;

  if (cf->check_link && !(r->neigh->iface->flags & IF_LINK_UP))
    return 0;

  if (r->bfd_req && r->bfd_req->state != BFD_STATE_UP)
    return 0;

  r->state |= STS_WANT;
  return 1;
}


static void
static_add(struct proto *p, struct static_config *cf, struct static_route *r)
{
  if (r->mp_head && r != r->mp_head)
    return;

  DBG("static_add(%N,%d)\n", r->net, r->dest);
  switch (r->dest)
    {
    case RTD_UNICAST:
      {
	int count = 0;
	struct static_route *r2;

	for (r2 = r; r2; r2 = r2->mp_next)
	  {
	    if (ipa_zero(r2->via)) // No struct neighbor for device routes
	      continue;

	    struct neighbor *n = neigh_find2(p, &r2->via, r2->iface, NEF_STICKY);
	    if (n)
	      {
		r2->chain = n->data;
		n->data = r2;
		r2->neigh = n;

		static_update_bfd(p, r2);
		static_decide(cf,r2);
		count++;
	      }
	    else
	      {
		log(L_ERR "Static route destination %I is invalid. Ignoring.", r2->via);
		r2->state = 0;
	      }
	  }

	if (count)
	  static_install(p, r);

	break;
      }

    default:
      static_install(p, r);
    }
}

static void
static_rte_cleanup(struct proto *p UNUSED, struct static_route *r)
{
  if (r->mp_head && (r != r->mp_head))
    return;

  struct static_route *r2;
  
  for (r2 = r; r2; r2 = r2->mp_next)
    if (r2->bfd_req)
    {
      rfree(r2->bfd_req);
      r2->bfd_req = NULL;
    }
}

static int
static_start(struct proto *p)
{
  struct static_config *cf = (void *) p->cf;
  struct static_route *r;

  DBG("Static: take off!\n");

  if (!static_lp)
    static_lp = lp_new(&root_pool, 1008);

  if (cf->igp_table)
    rt_lock_table(cf->igp_table->table);

  /* We have to go UP before routes could be installed */
  proto_notify_state(p, PS_UP);

  WALK_LIST(r, cf->neigh_routes)
    static_add(p, cf, r);

  WALK_LIST(r, cf->iface_routes)
    static_add(p, cf, r);

  WALK_LIST(r, cf->other_routes)
    static_install(p, r);

  return PS_UP;
}

static int
static_shutdown(struct proto *p)
{
  struct static_config *cf = (void *) p->cf;
  struct static_route *r;

  /* Just reset the flag, the routes will be flushed by the nest */
  WALK_LIST(r, cf->other_routes)
  {
    static_rte_cleanup(p, r);
    r->state = 0;
  }
  WALK_LIST(r, cf->iface_routes)
    r->state = 0;
  WALK_LIST(r, cf->neigh_routes)
  {
    static_rte_cleanup(p, r);
    r->state = 0;
  }

  /* Handle failure during channel reconfigure */
  /* FIXME: This should be handled in a better way */
  cf = (void *) p->cf_new;
  if (cf)
  {
    WALK_LIST(r, cf->other_routes)
      r->state = 0;
    WALK_LIST(r, cf->iface_routes)
      r->state = 0;
    WALK_LIST(r, cf->neigh_routes)
      r->state = 0;
  }

  return PS_DOWN;
}

static void
static_cleanup(struct proto *p)
{
  struct static_config *cf = (void *) p->cf;

  if (cf->igp_table)
    rt_unlock_table(cf->igp_table->table);
}

static void
static_update_rte(struct proto *p, struct static_route *r)
{
  if (r->dest != RTD_UNICAST)
    return;

  static_decide((struct static_config *) p->cf, r);
  static_install(p, r);
}

static void
static_neigh_notify(struct neighbor *n)
{
  struct proto *p = n->proto;
  struct static_route *r;

  DBG("Static: neighbor notify for %I: iface %p\n", n->addr, n->iface);
  for(r=n->data; r; r=r->chain)
  {
    static_update_bfd(p, r);
    static_update_rte(p, r);
  }
}

static void
static_bfd_notify(struct bfd_request *req)
{
  struct static_route *r = req->data;
  struct proto *p = r->neigh->proto;

  // if (req->down) TRACE(D_EVENTS, "BFD session down for nbr %I on %s", XXXX);

  static_update_rte(p, r);
}

static void
static_dump_rt(struct static_route *r)
{
  debug("%-1N: ", r->net);
  if (r->dest == RTD_UNICAST)
    if (ipa_zero(r->via))
      debug("dev %s\n", r->if_name);
    else
      debug("via %I\n", r->via);
  else
    debug("rtd %d\n", r->dest);
}

static void
static_dump(struct proto *p)
{
  struct static_config *c = (void *) p->cf;
  struct static_route *r;

  debug("Independent static nexthops:\n");
  WALK_LIST(r, c->neigh_routes)
    static_dump_rt(r);
  debug("Device static nexthops:\n");
  WALK_LIST(r, c->iface_routes)
    static_dump_rt(r);
  debug("Other static routes:\n");
  WALK_LIST(r, c->other_routes)
    static_dump_rt(r);
}

static void
static_if_notify(struct proto *p, unsigned flags, struct iface *i)
{
  struct static_route *r;
  struct static_config *c = (void *) p->cf;

  if (flags & IF_CHANGE_UP)
    {
      WALK_LIST(r, c->iface_routes)
	if (!strcmp(r->if_name, i->name))
	{
	  r->state |= STS_WANT;
	  r->iface = i;
	  static_install(p, r);
	}
    }
  else if (flags & IF_CHANGE_DOWN)
    {
      WALK_LIST(r, c->iface_routes)
	if (!strcmp(r->if_name, i->name))
	{
	  r->state &= ~STS_WANT;
	  r->iface = NULL;
	  static_install(p, r);
	}
    }
}

int
static_rte_mergable(rte *pri UNUSED, rte *sec UNUSED)
{
  return 1;
}

void
static_init_config(struct static_config *c)
{
  init_list(&c->neigh_routes);
  init_list(&c->iface_routes);
  init_list(&c->other_routes);
}

static void
static_postconfig(struct proto_config *CF)
{
  struct static_config *cf = (void *) CF;
  struct static_route *r;

  if (EMPTY_LIST(CF->channels))
    cf_error("Channel not specified");


  WALK_LIST(r, cf->neigh_routes)
    if (r->net && (r->net->type != CF->net_type))
      cf_error("Route %N incompatible with channel type", r->net);

  WALK_LIST(r, cf->iface_routes)
    if (r->net && (r->net->type != CF->net_type))
      cf_error("Route %N incompatible with channel type", r->net);

  WALK_LIST(r, cf->other_routes)
    if (r->net->type != CF->net_type)
      cf_error("Route %N incompatible with channel type", r->net);
}


static struct proto *
static_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  // struct static_proto *p = (void *) P;
  // struct static_config *cf = (void *) CF;

  P->main_channel = proto_add_channel(P, proto_cf_main_channel(CF));

  P->neigh_notify = static_neigh_notify;
  P->if_notify = static_if_notify;
  P->rte_mergable = static_rte_mergable;

  return P;
}

static inline int
static_same_dest(struct static_route *x, struct static_route *y)
{
  if (x->dest != y->dest)
    return 0;

  switch (x->dest)
    {
    case RTD_UNICAST:
      {
	struct static_route *xc, *yc;
	for (xc = x, yc = y; xc && yc; xc = xc->mp_next, yc = yc->mp_next)
	{
	  if (ipa_nonzero(xc->via) && ipa_nonzero(yc->via))
	  {
	    if (!ipa_equal(x->via, y->via) ||
		(x->iface != y->iface) ||
		(x->use_bfd != y->use_bfd) ||
		(x->weight != y->weight) ||
		(x->label_count != y->label_count))
	      return 0;
	    for (int i=0; i<x->label_count; i++)
	      if (x->label_stack[i] != y->label_stack[i])
		return 0;
	  }
	  else
	    if ((!x->if_name) || (!y->if_name) ||
		strcmp(x->if_name, y->if_name) ||
		(x->use_bfd != y->use_bfd) ||
		(x->weight != y->weight))
	      return 0;

	}
	return 1;
      }

    case RTDX_RECURSIVE:
      return ipa_equal(x->via, y->via);

    default:
      return 1;
    }
}

static inline int
static_same_rte(struct static_route *x, struct static_route *y)
{
  return static_same_dest(x, y) && i_same(x->cmds, y->cmds);
}


static void
static_match(struct proto *p, struct static_route *r, struct static_config *n)
{
  struct static_route *t;

  if (r->mp_head && (r->mp_head != r))
    return;

  /*
   * For given old route *r we find whether a route to the same
   * network is also in the new route list. In that case, we keep the
   * route and possibly update the route later if destination changed.
   * Otherwise, we remove the route.
   */

  if (r->neigh)
    r->neigh->data = NULL;

  WALK_LIST(t, n->neigh_routes)
    if ((!t->mp_head || (t->mp_head == t)) && net_equal(r->net, t->net))
      goto found;

  WALK_LIST(t, n->iface_routes)
    if ((!t->mp_head || (t->mp_head == t)) && net_equal(r->net, t->net))
      goto found;

  WALK_LIST(t, n->other_routes)
    if (net_equal(r->net, t->net))
      goto found;

  r->state &= ~STS_WANT;
  static_install(p, r);
  return;

 found:
  t->state = r->state;

  /* If destination is different, force reinstall */
  if (!static_same_rte(r, t))
    t->state |= STS_FORCE;
}

static inline rtable *
cf_igp_table(struct static_config *cf)
{
  return cf->igp_table ? cf->igp_table->table : NULL;
}

static int
static_reconfigure(struct proto *p, struct proto_config *CF)
{
  struct static_config *o = (void *) p->cf;
  struct static_config *n = (void *) CF;
  struct static_route *r;

  if (cf_igp_table(o) != cf_igp_table(n))
    return 0;

  if (!proto_configure_channel(p, &p->main_channel, proto_cf_main_channel(CF)))
    return 0;

  /* Delete all obsolete routes and reset neighbor entries */
  WALK_LIST(r, o->other_routes)
    static_match(p, r, n);
  WALK_LIST(r, o->iface_routes)
    static_match(p, r, n);
  WALK_LIST(r, o->neigh_routes)
    static_match(p, r, n);

  /* Now add all new routes, those not changed will be ignored by static_install() */
  WALK_LIST(r, n->neigh_routes)
    static_add(p, n, r);
  WALK_LIST(r, o->neigh_routes)
    static_rte_cleanup(p, r);

  WALK_LIST(r, n->iface_routes)
    {
      struct iface *ifa;
      if ((ifa = if_find_by_name(r->if_name)) && (ifa->flags & IF_UP))
	{
	  r->iface = ifa;
	  static_install(p, r);
	}
    }

  WALK_LIST(r, n->other_routes)
  {
    r->state |= STS_WANT;
    static_install(p, r);
  }

  WALK_LIST(r, o->other_routes)
    static_rte_cleanup(p, r);

  return 1;
}

static void
static_copy_routes(list *dlst, list *slst)
{
  struct static_route *sr;

  init_list(dlst);
  WALK_LIST(sr, *slst)
    {
      struct static_route *srr, *drr = NULL;
      for (srr = sr->mp_head; srr; srr = srr->mp_next)
      {
	/* copy one route */
	struct static_route *dr = cfg_alloc(sizeof(struct static_route));
	if (drr)
	  drr->mp_next = dr;
	else
	  add_tail(dlst, &(dr->n));

	memcpy(dr, sr, sizeof(struct static_route));
	drr = dr;
      }
    }
}

static void
static_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct static_config *d = (struct static_config *) dest;
  struct static_config *s = (struct static_config *) src;

  /* Copy route lists */
  static_copy_routes(&d->neigh_routes, &s->neigh_routes);
  static_copy_routes(&d->iface_routes, &s->iface_routes);
  static_copy_routes(&d->other_routes, &s->other_routes);
}

struct protocol proto_static = {
  .name =		"Static",
  .template =		"static%d",
  .preference =		DEF_PREF_STATIC,
  .channel_mask =	NB_ANY,
  .proto_size =		sizeof(struct proto),
  .config_size =	sizeof(struct static_config),
  .postconfig =		static_postconfig,
  .init =		static_init,
  .dump =		static_dump,
  .start =		static_start,
  .shutdown =		static_shutdown,
  .cleanup =		static_cleanup,
  .reconfigure =	static_reconfigure,
  .copy_config =	static_copy_config
};

static byte *
static_format_via(struct static_route *r)
{
  static byte via[IPA_MAX_TEXT_LENGTH + 25];

  switch (r->dest)
    {
    case RTD_UNICAST:	if (ipa_zero(r->via)) bsprintf(via, "dev %s", r->if_name);
			else bsprintf(via, "via %I%J", r->via, r->iface);
			break;
    case RTD_BLACKHOLE:	bsprintf(via, "blackhole"); break;
    case RTD_UNREACHABLE: bsprintf(via, "unreachable"); break;
    case RTD_PROHIBIT:	bsprintf(via, "prohibited"); break;
    case RTDX_RECURSIVE: bsprintf(via, "recursive %I", r->via); break;
    default:		bsprintf(via, "???");
    }
  return via;
}

static void
static_show_rt(struct static_route *r)
{
  if (r->mp_head && (r != r->mp_head))
    return;
  if (r->mp_next)
  {
    cli_msg(-1009, "%N", r->net);
    struct static_route *r2;
    for (r2 = r; r2; r2 = r2->mp_next)
    {
      cli_msg(-1009, "\t%s weight %d%s%s", static_format_via(r2), r2->weight + 1,
	      r2->bfd_req ? " (bfd)" : "", (r2->state & STS_INSTALLED) ? "" : " (dormant)");
      if (r2->mp_next == r)
	break;
    }
  }
  else
    cli_msg(-1009, "%N %s%s%s", r->net, static_format_via(r),
	  r->bfd_req ? " (bfd)" : "", (r->state & STS_INSTALLED) ? "" : " (dormant)");
}

void
static_show(struct proto *P)
{
  struct static_config *c = (void *) P->cf;
  struct static_route *r;

  WALK_LIST(r, c->neigh_routes)
    static_show_rt(r);
  WALK_LIST(r, c->iface_routes)
    static_show_rt(r);
  WALK_LIST(r, c->other_routes)
    static_show_rt(r);
  cli_msg(0, "");
}
