/*
 *	BIRD -- UNIX Kernel Synchronization
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Kernel synchronization
 *
 * This system dependent module implements the Kernel and Device protocol,
 * that is synchronization of interface lists and routing tables with the
 * OS kernel.
 *
 * The whole kernel synchronization is a bit messy and touches some internals
 * of the routing table engine, because routing table maintenance is a typical
 * example of the proverbial compatibility between different Unices and we want
 * to keep the overhead of our KRT business as low as possible and avoid maintaining
 * a local routing table copy.
 *
 * The kernel syncer can work in three different modes (according to system config header):
 * Either with a single routing table and single KRT protocol [traditional UNIX]
 * or with many routing tables and separate KRT protocols for all of them
 * or with many routing tables, but every scan including all tables, so we start
 * separate KRT protocols which cooperate with each other [Linux].
 * In this case, we keep only a single scan timer.
 *
 * We use FIB node flags in the routing table to keep track of route
 * synchronization status. We also attach temporary &rte's to the routing table,
 * but it cannot do any harm to the rest of BIRD since table synchronization is
 * an atomic process.
 *
 * When starting up, we cheat by looking if there is another
 * KRT instance to be initialized later and performing table scan
 * only once for all the instances.
 *
 * The code uses OS-dependent parts for kernel updates and scans. These parts are
 * in more specific sysdep directories (e.g. sysdep/linux) in functions krt_sys_*
 * and kif_sys_* (and some others like krt_replace_rte()) and krt-sys.h header file.
 * This is also used for platform specific protocol options and route attributes.
 *
 * There was also an old code that used traditional UNIX ioctls for these tasks.
 * It was unmaintained and later removed. For reference, see sysdep/krt-* files
 * in commit 396dfa9042305f62da1f56589c4b98fac57fc2f6
 */

/*
 *  If you are brave enough, continue now.  You cannot say you haven't been warned.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "filter/filter.h"
#include "conf/conf.h"
#include "lib/string.h"
#include "lib/timer.h"

#include "unix.h"
#include "krt.h"

/*
 *	Global resources
 */

pool *krt_pool;
static linpool *krt_filter_lp;
static list krt_proto_list;

void
krt_io_init(void)
{
  krt_pool = rp_new(&root_pool, "Kernel Syncer");
  krt_filter_lp = lp_new_default(krt_pool);
  init_list(&krt_proto_list);
  krt_sys_io_init();
}

/*
 *	Interfaces
 */

struct kif_proto *kif_proto;
static struct kif_config *kif_cf;
static timer *kif_scan_timer;
static btime kif_last_shot;

static struct kif_iface_config kif_default_iface = {};

struct kif_iface_config *
kif_get_iface_config(struct iface *iface)
{
  struct kif_config *cf = (void *) (kif_proto->p.cf);
  struct kif_iface_config *ic = (void *) iface_patt_find(&cf->iface_list, iface, NULL);
  return ic ?: &kif_default_iface;
}

static void
kif_scan(timer *t)
{
  struct kif_proto *p = t->data;

  KRT_TRACE(p, D_EVENTS, "Scanning interfaces");
  kif_last_shot = current_time();
  kif_do_scan(p);
}

static void
kif_force_scan(void)
{
  if (kif_proto && ((kif_last_shot + 2 S) < current_time()))
    {
      kif_scan(kif_scan_timer);
      tm_start(kif_scan_timer, ((struct kif_config *) kif_proto->p.cf)->scan_time);
    }
}

void
kif_request_scan(void)
{
  if (kif_proto && (kif_scan_timer->expires > (current_time() + 1 S)))
    tm_start(kif_scan_timer, 1 S);
}

static struct proto *
kif_init(struct proto_config *c)
{
  struct kif_proto *p = proto_new(c);

  kif_sys_init(p);
  return &p->p;
}

static int
kif_start(struct proto *P)
{
  struct kif_proto *p = (struct kif_proto *) P;

  kif_proto = p;
  kif_sys_start(p);

  /* Start periodic interface scanning */
  kif_scan_timer = tm_new_init(P->pool, kif_scan, p, KIF_CF->scan_time, 0);
  kif_scan(kif_scan_timer);
  tm_start(kif_scan_timer, KIF_CF->scan_time);

  return PS_UP;
}

static int
kif_shutdown(struct proto *P)
{
  struct kif_proto *p = (struct kif_proto *) P;

  tm_stop(kif_scan_timer);
  kif_sys_shutdown(p);
  kif_proto = NULL;

  return PS_DOWN;
}

static int
kif_reconfigure(struct proto *p, struct proto_config *new)
{
  struct kif_config *o = (struct kif_config *) p->cf;
  struct kif_config *n = (struct kif_config *) new;

  if (!kif_sys_reconfigure((struct kif_proto *) p, n, o))
    return 0;

  if (o->scan_time != n->scan_time)
    {
      tm_stop(kif_scan_timer);
      kif_scan_timer->recurrent = n->scan_time;
      kif_scan(kif_scan_timer);
      tm_start(kif_scan_timer, n->scan_time);
    }

  if (!EMPTY_LIST(o->iface_list) || !EMPTY_LIST(n->iface_list))
    {
      /* This is hack, we have to update a configuration
       * to the new value just now, because it is used
       * for recalculation of preferred addresses.
       */
      p->cf = new;

      if_recalc_all_preferred_addresses();
    }

  return 1;
}


static void
kif_preconfig(struct protocol *P UNUSED, struct config *c)
{
  kif_cf = NULL;
  kif_sys_preconfig(c);
}

struct proto_config *
kif_init_config(int class)
{
  if (kif_cf)
    cf_error("Kernel device protocol already defined");

  kif_cf = (struct kif_config *) proto_config_new(&proto_unix_iface, class);
  kif_cf->scan_time = 60 S;
  init_list(&kif_cf->iface_list);

  kif_sys_init_config(kif_cf);
  return (struct proto_config *) kif_cf;
}

static void
kif_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct kif_config *d = (struct kif_config *) dest;
  struct kif_config *s = (struct kif_config *) src;

  /* Copy interface config list */
  cfg_copy_list(&d->iface_list, &s->iface_list, sizeof(struct kif_iface_config));

  /* Fix sysdep parts */
  kif_sys_copy_config(d, s);
}

struct protocol proto_unix_iface = {
  .name = 		"Device",
  .template = 		"device%d",
  .class =		PROTOCOL_DEVICE,
  .proto_size =		sizeof(struct kif_proto),
  .config_size =	sizeof(struct kif_config),
  .preconfig =		kif_preconfig,
  .init =		kif_init,
  .start =		kif_start,
  .shutdown =		kif_shutdown,
  .reconfigure =	kif_reconfigure,
  .copy_config =	kif_copy_config
};

void
kif_build(void)
{
  proto_build(&proto_unix_iface);
}


/*
 *	Tracing of routes
 */

static inline void
krt_trace_in(struct krt_proto *p, rte *e, char *msg)
{
  if (p->p.debug & D_PACKETS)
    log(L_TRACE "%s: %N: %s", p->p.name, e->net->n.addr, msg);
}

static inline void
krt_trace_in_rl(struct tbf *f, struct krt_proto *p, rte *e, char *msg)
{
  if (p->p.debug & D_PACKETS)
    log_rl(f, L_TRACE "%s: %N: %s", p->p.name, e->net->n.addr, msg);
}

/*
 *	Inherited Routes
 */

#ifdef KRT_ALLOW_LEARN

static struct tbf rl_alien = TBF_DEFAULT_LOG_LIMITS;

/*
 * krt_same_key() specifies what (aside from the net) is the key in
 * kernel routing tables. It should be OS-dependent, this is for
 * Linux. It is important for asynchronous alien updates, because a
 * positive update is implicitly a negative one for any old route with
 * the same key.
 */

static inline u32
krt_metric(rte *a)
{
  eattr *ea = ea_find(a->attrs->eattrs, EA_KRT_METRIC);
  return ea ? ea->u.data : 0;
}

static inline int
krt_same_key(rte *a, rte *b)
{
  return (krt_metric(a) == krt_metric(b));
}

static inline int
krt_uptodate(rte *a, rte *b)
{
  return (a->attrs == b->attrs);
}

static void
krt_learn_announce_update(struct krt_proto *p, rte *e)
{
  net *n = e->net;
  rta *aa = rta_clone(e->attrs);
  rte *ee = rte_get_temp(aa, p->p.main_source);
  rte_update(&p->p, n->n.addr, ee);
}

static void
krt_learn_announce_delete(struct krt_proto *p, net *n)
{
  rte_update(&p->p, n->n.addr, NULL);
}

static void
krt_learn_alien_attr(struct channel *c, rte *e)
{
  ASSERT(!e->attrs->cached);
  e->attrs->pref = c->preference;

  e->attrs = rta_lookup(e->attrs);
}

/* Called when alien route is discovered during scan */
static void
krt_learn_scan(struct krt_proto *p, rte *e)
{
  net *n0 = e->net;
  net *n = net_get(p->krt_table, n0->n.addr);
  rte *m, **mm;

  krt_learn_alien_attr(p->p.main_channel, e);

  for(mm=&n->routes; m = *mm; mm=&m->next)
    if (krt_same_key(m, e))
      break;
  if (m)
    {
      if (krt_uptodate(m, e))
	{
	  krt_trace_in_rl(&rl_alien, p, e, "[alien] seen");
	  rte_free(e);
	  m->pflags |= KRT_REF_SEEN;
	}
      else
	{
	  krt_trace_in(p, e, "[alien] updated");
	  *mm = m->next;
	  rte_free(m);
	  m = NULL;
	}
    }
  else
    krt_trace_in(p, e, "[alien] created");
  if (!m)
    {
      e->next = n->routes;
      n->routes = e;
      e->pflags |= KRT_REF_SEEN;
    }
}

static void
krt_learn_prune(struct krt_proto *p)
{
  struct fib *fib = &p->krt_table->fib;
  struct fib_iterator fit;

  KRT_TRACE(p, D_EVENTS, "Pruning inherited routes");

  FIB_ITERATE_INIT(&fit, fib);
again:
  FIB_ITERATE_START(fib, &fit, net, n)
    {
      rte *e, **ee, *best, **pbest, *old_best;

      /*
       * Note that old_best may be NULL even if there was an old best route in
       * the previous step, because it might be replaced in krt_learn_scan().
       * But in that case there is a new valid best route.
       */

      old_best = NULL;
      best = NULL;
      pbest = NULL;
      ee = &n->routes;
      while (e = *ee)
	{
	  if (e->pflags & KRT_REF_BEST)
	    old_best = e;

	  if (!(e->pflags & KRT_REF_SEEN))
	    {
	      *ee = e->next;
	      rte_free(e);
	      continue;
	    }

	  if (!best || krt_metric(best) > krt_metric(e))
	    {
	      best = e;
	      pbest = ee;
	    }

	  e->pflags &= ~(KRT_REF_SEEN | KRT_REF_BEST);
	  ee = &e->next;
	}
      if (!n->routes)
	{
	  DBG("%I/%d: deleting\n", n->n.prefix, n->n.pxlen);
	  if (old_best)
	    krt_learn_announce_delete(p, n);

	  FIB_ITERATE_PUT(&fit);
	  fib_delete(fib, n);
	  goto again;
	}

      best->pflags |= KRT_REF_BEST;
      *pbest = best->next;
      best->next = n->routes;
      n->routes = best;

      if ((best != old_best) || p->reload)
	{
	  DBG("%I/%d: announcing (metric=%d)\n", n->n.prefix, n->n.pxlen, krt_metric(best));
	  krt_learn_announce_update(p, best);
	}
      else
	DBG("%I/%d: uptodate (metric=%d)\n", n->n.prefix, n->n.pxlen, krt_metric(best));
    }
  FIB_ITERATE_END;

  p->reload = 0;
}

static void
krt_learn_async(struct krt_proto *p, rte *e, int new)
{
  net *n0 = e->net;
  net *n = net_get(p->krt_table, n0->n.addr);
  rte *g, **gg, *best, **bestp, *old_best;

  krt_learn_alien_attr(p->p.main_channel, e);

  old_best = n->routes;
  for(gg=&n->routes; g = *gg; gg = &g->next)
    if (krt_same_key(g, e))
      break;
  if (new)
    {
      if (g)
	{
	  if (krt_uptodate(g, e))
	    {
	      krt_trace_in(p, e, "[alien async] same");
	      rte_free(e);
	      return;
	    }
	  krt_trace_in(p, e, "[alien async] updated");
	  *gg = g->next;
	  rte_free(g);
	}
      else
	krt_trace_in(p, e, "[alien async] created");

      e->next = n->routes;
      n->routes = e;
    }
  else if (!g)
    {
      krt_trace_in(p, e, "[alien async] delete failed");
      rte_free(e);
      return;
    }
  else
    {
      krt_trace_in(p, e, "[alien async] removed");
      *gg = g->next;
      rte_free(e);
      rte_free(g);
    }
  best = n->routes;
  bestp = &n->routes;
  for(gg=&n->routes; g=*gg; gg=&g->next)
  {
    if (krt_metric(best) > krt_metric(g))
      {
	best = g;
	bestp = gg;
      }

    g->pflags &= ~KRT_REF_BEST;
  }

  if (best)
    {
      best->pflags |= KRT_REF_BEST;
      *bestp = best->next;
      best->next = n->routes;
      n->routes = best;
    }

  if (best != old_best)
    {
      DBG("krt_learn_async: distributing change\n");
      if (best)
	krt_learn_announce_update(p, best);
      else
	krt_learn_announce_delete(p, n);
    }
}

static void
krt_learn_init(struct krt_proto *p)
{
  if (KRT_CF->learn)
  {
    struct rtable_config *cf = mb_allocz(p->p.pool, sizeof(struct rtable_config));
    cf->name = "Inherited";
    cf->addr_type = p->p.net_type;
    cf->internal = 1;

    p->krt_table = rt_setup(p->p.pool, cf);
  }
}

static void
krt_dump(struct proto *P)
{
  struct krt_proto *p = (struct krt_proto *) P;

  if (!KRT_CF->learn)
    return;
  debug("KRT: Table of inheritable routes\n");
  rt_dump(p->krt_table);
}

#endif

/*
 *	Routes
 */

static inline int
krt_is_installed(struct krt_proto *p, net *n)
{
  return n->routes && bmap_test(&p->p.main_channel->export_map, n->routes->id);
}

static void
krt_flush_routes(struct krt_proto *p)
{
  struct rtable *t = p->p.main_channel->table;

  KRT_TRACE(p, D_EVENTS, "Flushing kernel routes");
  FIB_WALK(&t->fib, net, n)
    {
      if (krt_is_installed(p, n))
	{
	  /* FIXME: this does not work if gw is changed in export filter */
	  krt_replace_rte(p, n, NULL, n->routes);
	}
    }
  FIB_WALK_END;
}

static struct rte *
krt_export_net(struct krt_proto *p, net *net, rte **rt_free)
{
  struct channel *c = p->p.main_channel;
  const struct filter *filter = c->out_filter;
  rte *rt;

  if (c->ra_mode == RA_MERGED)
    return rt_export_merged(c, net, rt_free, krt_filter_lp, 1);

  rt = net->routes;
  *rt_free = NULL;

  if (!rte_is_valid(rt))
    return NULL;

  if (filter == FILTER_REJECT)
    return NULL;

  /* We could run krt_preexport() here, but it is already handled by krt_is_installed() */

  if (filter == FILTER_ACCEPT)
    goto accept;

  if (f_run(filter, &rt, krt_filter_lp, FF_SILENT) > F_ACCEPT)
    goto reject;


accept:
  if (rt != net->routes)
    *rt_free = rt;
  return rt;

reject:
  if (rt != net->routes)
    rte_free(rt);
  return NULL;
}

static int
krt_same_dest(rte *k, rte *e)
{
  rta *ka = k->attrs, *ea = e->attrs;

  if (ka->dest != ea->dest)
    return 0;

  if (ka->dest == RTD_UNICAST)
    return nexthop_same(&(ka->nh), &(ea->nh));

  return 1;
}

/*
 *  This gets called back when the low-level scanning code discovers a route.
 *  We expect that the route is a temporary rte and its attributes are uncached.
 */

void
krt_got_route(struct krt_proto *p, rte *e, s8 src)
{
  rte *new = NULL, *rt_free = NULL;
  net *n = e->net;
  e->pflags = 0;

#ifdef KRT_ALLOW_LEARN
  switch (src)
    {
    case KRT_SRC_REDIRECT:
      goto delete;

    case KRT_SRC_KERNEL:
      if (KRT_CF->learn != KRT_LEARN_ALL)
        goto ignore;
      /* fallthrough */

    case  KRT_SRC_ALIEN:
      if (KRT_CF->learn)
	krt_learn_scan(p, e);
      else
	{
	  krt_trace_in_rl(&rl_alien, p, e, "[alien] ignored");
	  rte_free(e);
	}
      return;
    }
#endif
  /* The rest is for KRT_SRC_BIRD (or KRT_SRC_UNKNOWN) */


  /* We wait for the initial feed to have correct installed state */
  if (!p->ready)
    goto ignore;

  if (!krt_is_installed(p, n))
    goto delete;

  new = krt_export_net(p, n, &rt_free);

  /* Rejected by filters */
  if (!new)
    goto delete;

  /* Route to this destination was already seen. Strange, but it happens... */
  if (bmap_test(&p->seen_map, new->id))
    goto aseen;

  /* Mark route as seen */
  bmap_set(&p->seen_map, new->id);

  /* TODO: There also may be changes in route eattrs, we ignore that for now. */
  if (!bmap_test(&p->sync_map, new->id) || !krt_same_dest(e, new))
    goto update;

  goto seen;

seen:
  krt_trace_in(p, e, "seen");
  goto done;

aseen:
  krt_trace_in(p, e, "already seen");
  goto done;

ignore:
  krt_trace_in(p, e, "ignored");
  goto done;

update:
  krt_trace_in(p, new, "updating");
  krt_replace_rte(p, n, new, e);
  goto done;

delete:
  krt_trace_in(p, e, "deleting");
  krt_replace_rte(p, n, NULL, e);
  goto done;

done:
  rte_free(e);

  if (rt_free)
    rte_free(rt_free);

  lp_flush(krt_filter_lp);
}

static void
krt_init_scan(struct krt_proto *p)
{
  bmap_reset(&p->seen_map, 1024);
}

static void
krt_prune(struct krt_proto *p)
{
  struct rtable *t = p->p.main_channel->table;

  KRT_TRACE(p, D_EVENTS, "Pruning table %s", t->name);
  FIB_WALK(&t->fib, net, n)
  {
    if (p->ready && krt_is_installed(p, n) && !bmap_test(&p->seen_map, n->routes->id))
    {
      rte *rt_free = NULL;
      rte *new = krt_export_net(p, n, &rt_free);

      if (new)
      {
	krt_trace_in(p, new, "installing");
	krt_replace_rte(p, n, new, NULL);
      }

      if (rt_free)
	rte_free(rt_free);

      lp_flush(krt_filter_lp);
    }
  }
  FIB_WALK_END;

#ifdef KRT_ALLOW_LEARN
  if (KRT_CF->learn)
    krt_learn_prune(p);
#endif

  if (p->ready)
    p->initialized = 1;
}

void
krt_got_route_async(struct krt_proto *p, rte *e, int new, s8 src)
{
  net *net = e->net;
  e->pflags = 0;

  switch (src)
    {
    case KRT_SRC_BIRD:
      /* Should be filtered by the back end */
      bug("BIRD originated routes should not get here.");

    case KRT_SRC_REDIRECT:
      if (new)
	{
	  krt_trace_in(p, e, "[redirect] deleting");
	  krt_replace_rte(p, net, NULL, e);
	}
      /* If !new, it is probably echo of our deletion */
      break;

#ifdef KRT_ALLOW_LEARN
    case KRT_SRC_KERNEL:
      if (KRT_CF->learn != KRT_LEARN_ALL)
        break;
      /* fallthrough */

    case KRT_SRC_ALIEN:
      if (KRT_CF->learn)
	{
	  krt_learn_async(p, e, new);
	  return;
	}
#endif
    }
  rte_free(e);
}


/*
 *	Periodic scanning
 */

static timer *krt_scan_all_timer;
static int krt_scan_all_count;
static _Bool krt_scan_all_tables;

static void
krt_scan_all(timer *t UNUSED)
{
  struct krt_proto *p;
  node *n;

  kif_force_scan();

  /* We need some node to decide whether to print the debug messages or not */
  p = SKIP_BACK(struct krt_proto, krt_node, HEAD(krt_proto_list));
  KRT_TRACE(p, D_EVENTS, "Scanning routing table");

  WALK_LIST2(p, n, krt_proto_list, krt_node)
    krt_init_scan(p);

  krt_do_scan(NULL);

  WALK_LIST2(p, n, krt_proto_list, krt_node)
    krt_prune(p);
}

static void
krt_scan_all_timer_start(struct krt_proto *p)
{
  if (!krt_scan_all_count)
    krt_scan_all_timer = tm_new_init(krt_pool, krt_scan_all, NULL, KRT_CF->scan_time, 0);

  krt_scan_all_count++;

  tm_start(krt_scan_all_timer, 1 S);
}

static void
krt_scan_all_timer_stop(void)
{
  ASSERT(krt_scan_all_count > 0);

  krt_scan_all_count--;

  if (!krt_scan_all_count)
  {
    rfree(krt_scan_all_timer);
    krt_scan_all_timer = NULL;
  }
}

static void
krt_scan_all_timer_kick(void)
{
  tm_start(krt_scan_all_timer, 0);
}

void
krt_use_shared_scan(void)
{
  krt_scan_all_tables = 1;
}


static void
krt_scan(timer *t)
{
  struct krt_proto *p = t->data;

  kif_force_scan();

  KRT_TRACE(p, D_EVENTS, "Scanning routing table");
  krt_init_scan(p);
  krt_do_scan(p);
  krt_prune(p);
}

static void
krt_scan_timer_start(struct krt_proto *p)
{
  if (krt_scan_all_tables)
    krt_scan_all_timer_start(p);
  else
  {
    p->scan_timer = tm_new_init(p->p.pool, krt_scan, p, KRT_CF->scan_time, 0);
    tm_start(p->scan_timer, 1 S);
  }
}

static void
krt_scan_timer_stop(struct krt_proto *p)
{
  if (krt_scan_all_tables)
    krt_scan_all_timer_stop();
  else
    tm_stop(p->scan_timer);
}

static void
krt_scan_timer_kick(struct krt_proto *p)
{
  if (krt_scan_all_tables)
    krt_scan_all_timer_kick();
  else
    tm_start(p->scan_timer, 0);
}


/*
 *	Updates
 */

static int
krt_preexport(struct channel *C, rte *e)
{
  // struct krt_proto *p = (struct krt_proto *) P;
  if (e->src->proto == C->proto)
    return -1;

  if (!krt_capable(e))
    return -1;

  return 0;
}

static void
krt_rt_notify(struct proto *P, struct channel *ch UNUSED, net *net,
	      rte *new, rte *old)
{
  struct krt_proto *p = (struct krt_proto *) P;

  if (config->shutdown)
    return;

#ifdef CONFIG_SINGLE_ROUTE
  /*
   * Implicit withdraw - when the imported kernel route becomes the best one,
   * we know that the previous one exported to the kernel was already removed,
   * but if we processed the update as usual, we would send withdraw to the
   * kernel, which would remove the new imported route instead.
   */
  rte *best = net->routes;
  if (!new && best && (best->src->proto == P))
    return;
#endif

  if (p->initialized)		/* Before first scan we don't touch the routes */
    krt_replace_rte(p, net, new, old);
}

static void
krt_if_notify(struct proto *P, uint flags, struct iface *iface UNUSED)
{
  struct krt_proto *p = (struct krt_proto *) P;

  /*
   * When interface went down, we should remove routes to it. In the ideal world,
   * OS kernel would send us route removal notifications in such cases, but we
   * cannot rely on it as it is often not true. E.g. Linux kernel removes related
   * routes when an interface went down, but it does not notify userspace about
   * that. To be sure, we just schedule a scan to ensure synchronization.
   */

  if ((flags & IF_CHANGE_DOWN) && KRT_CF->learn)
    krt_scan_timer_kick(p);
}

static void
krt_reload_routes(struct channel *C)
{
  struct krt_proto *p = (void *) C->proto;

  /* Although we keep learned routes in krt_table, we rather schedule a scan */

  if (KRT_CF->learn)
  {
    p->reload = 1;
    krt_scan_timer_kick(p);
  }
}

static void
krt_feed_end(struct channel *C)
{
  struct krt_proto *p = (void *) C->proto;

  p->ready = 1;
  krt_scan_timer_kick(p);
}


/*
 *	Protocol glue
 */

struct krt_config *krt_cf;

static void
krt_preconfig(struct protocol *P UNUSED, struct config *c)
{
  krt_cf = NULL;
  krt_sys_preconfig(c);
}

static void
krt_postconfig(struct proto_config *CF)
{
  struct krt_config *cf = (void *) CF;

  /* Do not check templates at all */
  if (cf->c.class == SYM_TEMPLATE)
    return;

  if (! proto_cf_main_channel(CF))
    cf_error("Channel not specified");

  struct channel_config *cc = proto_cf_main_channel(CF);
  struct rtable_config *tab = cc->table;
  if (tab->krt_attached)
    cf_error("Kernel syncer (%s) already attached to table %s", tab->krt_attached->name, tab->name);
  tab->krt_attached = CF;

  if (cf->merge_paths)
  {
    cc->ra_mode = RA_MERGED;
    cc->merge_limit = cf->merge_paths;
  }

  krt_sys_postconfig(cf);
}

static struct proto *
krt_init(struct proto_config *CF)
{
  struct krt_proto *p = proto_new(CF);
  // struct krt_config *cf = (void *) CF;

  p->p.main_channel = proto_add_channel(&p->p, proto_cf_main_channel(CF));

  p->p.preexport = krt_preexport;
  p->p.rt_notify = krt_rt_notify;
  p->p.if_notify = krt_if_notify;
  p->p.reload_routes = krt_reload_routes;
  p->p.feed_end = krt_feed_end;

  krt_sys_init(p);
  return &p->p;
}

static int
krt_start(struct proto *P)
{
  struct krt_proto *p = (struct krt_proto *) P;

  switch (p->p.net_type)
  {
  case NET_IP4:		p->af = AF_INET; break;
  case NET_IP6:		p->af = AF_INET6; break;
  case NET_IP6_SADR:	p->af = AF_INET6; break;
#ifdef AF_MPLS
  case NET_MPLS:	p->af = AF_MPLS; break;
#endif
  default: log(L_ERR "KRT: Tried to start with strange net type: %d", p->p.net_type); return PS_START; break;
  }

  bmap_init(&p->sync_map, p->p.pool, 1024);
  bmap_init(&p->seen_map, p->p.pool, 1024);
  add_tail(&krt_proto_list, &p->krt_node);

#ifdef KRT_ALLOW_LEARN
  krt_learn_init(p);
#endif

  if (!krt_sys_start(p))
  {
    rem_node(&p->krt_node);
    return PS_START;
  }

  krt_scan_timer_start(p);

  if (p->p.gr_recovery && KRT_CF->graceful_restart)
    p->p.main_channel->gr_wait = 1;

  return PS_UP;
}

static int
krt_shutdown(struct proto *P)
{
  struct krt_proto *p = (struct krt_proto *) P;

  krt_scan_timer_stop(p);

  /* FIXME we should flush routes even when persist during reconfiguration */
  if (p->initialized && !KRT_CF->persist && (P->down_code != PDC_CMD_GR_DOWN))
    krt_flush_routes(p);

  p->ready = 0;
  p->initialized = 0;

  if (p->p.proto_state == PS_START)
    return PS_DOWN;

  krt_sys_shutdown(p);
  rem_node(&p->krt_node);
  bmap_free(&p->sync_map);

  return PS_DOWN;
}

static int
krt_reconfigure(struct proto *p, struct proto_config *CF)
{
  struct krt_config *o = (void *) p->cf;
  struct krt_config *n = (void *) CF;

  if (!proto_configure_channel(p, &p->main_channel, proto_cf_main_channel(CF)))
    return 0;

  if (!krt_sys_reconfigure((struct krt_proto *) p, n, o))
    return 0;

  /* persist, graceful restart need not be the same */
  return o->scan_time == n->scan_time && o->learn == n->learn;
}

struct proto_config *
krt_init_config(int class)
{
#ifndef CONFIG_MULTIPLE_TABLES
  if (krt_cf)
    cf_error("Kernel protocol already defined");
#endif

  krt_cf = (struct krt_config *) proto_config_new(&proto_unix_kernel, class);
  krt_cf->scan_time = 60 S;

  krt_sys_init_config(krt_cf);
  return (struct proto_config *) krt_cf;
}

static void
krt_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct krt_config *d = (struct krt_config *) dest;
  struct krt_config *s = (struct krt_config *) src;

  /* Fix sysdep parts */
  krt_sys_copy_config(d, s);
}

static int
krt_get_attr(const eattr *a, byte *buf, int buflen)
{
  switch (a->id)
  {
  case EA_KRT_SOURCE:
    bsprintf(buf, "source");
    return GA_NAME;

  case EA_KRT_METRIC:
    bsprintf(buf, "metric");
    return GA_NAME;

  default:
    return krt_sys_get_attr(a, buf, buflen);
  }
}


#ifdef CONFIG_IP6_SADR_KERNEL
#define MAYBE_IP6_SADR	NB_IP6_SADR
#else
#define MAYBE_IP6_SADR	0
#endif

#ifdef HAVE_MPLS_KERNEL
#define MAYBE_MPLS	NB_MPLS
#else
#define MAYBE_MPLS	0
#endif

struct protocol proto_unix_kernel = {
  .name =		"Kernel",
  .template =		"kernel%d",
  .class =		PROTOCOL_KERNEL,
  .preference =		DEF_PREF_INHERITED,
  .channel_mask =	NB_IP | MAYBE_IP6_SADR | MAYBE_MPLS,
  .proto_size =		sizeof(struct krt_proto),
  .config_size =	sizeof(struct krt_config),
  .preconfig =		krt_preconfig,
  .postconfig =		krt_postconfig,
  .init =		krt_init,
  .start =		krt_start,
  .shutdown =		krt_shutdown,
  .reconfigure =	krt_reconfigure,
  .copy_config =	krt_copy_config,
  .get_attr =		krt_get_attr,
#ifdef KRT_ALLOW_LEARN
  .dump =		krt_dump,
#endif
};

void
krt_build(void)
{
  proto_build(&proto_unix_kernel);
}
