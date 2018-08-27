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

static inline int
krt_same_key(rte *a, rte *b)
{
  return a->u.krt.metric == b->u.krt.metric;
}

static inline int
krt_uptodate(rte *a, rte *b)
{
  if (a->attrs != b->attrs)
    return 0;

  if (a->u.krt.proto != b->u.krt.proto)
    return 0;

  return 1;
}

static void
krt_learn_announce_update(struct krt_proto *p, rte *e)
{
  net *n = e->net;
  rta *aa = rta_clone(e->attrs);
  rte *ee = rte_get_temp(aa);
  ee->pflags = 0;
  ee->u.krt = e->u.krt;
  rte_update(&p->p, n->n.addr, ee);
}

static void
krt_learn_announce_delete(struct krt_proto *p, net *n)
{
  rte_update(&p->p, n->n.addr, NULL);
}

/* Called when alien route is discovered during scan */
static void
krt_learn_scan(struct krt_proto *p, rte *e)
{
  net *n0 = e->net;
  net *n = net_get(&p->krt_table, n0->n.addr);
  rte *m, **mm;

  e->attrs = rta_lookup(e->attrs);

  for(mm=&n->routes; m = *mm; mm=&m->next)
    if (krt_same_key(m, e))
      break;
  if (m)
    {
      if (krt_uptodate(m, e))
	{
	  krt_trace_in_rl(&rl_alien, p, e, "[alien] seen");
	  rte_free(e);
	  m->u.krt.seen = 1;
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
      e->u.krt.seen = 1;
    }
}

static void
krt_learn_prune(struct krt_proto *p)
{
  struct fib *fib = &p->krt_table.fib;
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
	  if (e->u.krt.best)
	    old_best = e;

	  if (!e->u.krt.seen)
	    {
	      *ee = e->next;
	      rte_free(e);
	      continue;
	    }

	  if (!best || best->u.krt.metric > e->u.krt.metric)
	    {
	      best = e;
	      pbest = ee;
	    }

	  e->u.krt.seen = 0;
	  e->u.krt.best = 0;
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

      best->u.krt.best = 1;
      *pbest = best->next;
      best->next = n->routes;
      n->routes = best;

      if ((best != old_best) || p->reload)
	{
	  DBG("%I/%d: announcing (metric=%d)\n", n->n.prefix, n->n.pxlen, best->u.krt.metric);
	  krt_learn_announce_update(p, best);
	}
      else
	DBG("%I/%d: uptodate (metric=%d)\n", n->n.prefix, n->n.pxlen, best->u.krt.metric);
    }
  FIB_ITERATE_END;

  p->reload = 0;
}

static void
krt_learn_async(struct krt_proto *p, rte *e, int new)
{
  net *n0 = e->net;
  net *n = net_get(&p->krt_table, n0->n.addr);
  rte *g, **gg, *best, **bestp, *old_best;

  e->attrs = rta_lookup(e->attrs);

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
    if (best->u.krt.metric > g->u.krt.metric)
      {
	best = g;
	bestp = gg;
      }

    g->u.krt.best = 0;
  }

  if (best)
    {
      best->u.krt.best = 1;
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

    rt_setup(p->p.pool, &p->krt_table, cf);
  }
}

static void
krt_dump(struct proto *P)
{
  struct krt_proto *p = (struct krt_proto *) P;

  if (!KRT_CF->learn)
    return;
  debug("KRT: Table of inheritable routes\n");
  rt_dump(&p->krt_table);
}

static void
krt_dump_attrs(rte *e)
{
  debug(" [m=%d,p=%d]", e->u.krt.metric, e->u.krt.proto);
}

#endif

/*
 *	Routes
 */

static void
krt_flush_routes(struct krt_proto *p)
{
  struct rtable *t = p->p.main_channel->table;

  KRT_TRACE(p, D_EVENTS, "Flushing kernel routes");
  FIB_WALK(&t->fib, net, n)
    {
      rte *e = n->routes;
      if (rte_is_valid(e) && (n->n.flags & KRF_INSTALLED))
	{
	  /* FIXME: this does not work if gw is changed in export filter */
	  krt_replace_rte(p, e->net, NULL, e);
	  n->n.flags &= ~KRF_INSTALLED;
	}
    }
  FIB_WALK_END;
}

static struct rte *
krt_export_net(struct krt_proto *p, net *net, rte **rt_free)
{
  struct channel *c = p->p.main_channel;
  struct filter *filter = c->out_filter;
  rte *rt;

  if (c->ra_mode == RA_MERGED)
    return rt_export_merged(c, net, rt_free, krt_filter_lp, 1);

  rt = net->routes;
  *rt_free = NULL;

  if (!rte_is_valid(rt))
    return NULL;

  if (filter == FILTER_REJECT)
    return NULL;

  rte_make_tmp_attrs(&rt, krt_filter_lp);

  /* We could run krt_import_control() here, but it is already handled by KRF_INSTALLED */

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
krt_got_route(struct krt_proto *p, rte *e)
{
  net *net = e->net;
  int verdict;

#ifdef KRT_ALLOW_LEARN
  switch (e->u.krt.src)
    {
    case KRT_SRC_KERNEL:
      verdict = KRF_IGNORE;
      goto sentenced;

    case KRT_SRC_REDIRECT:
      verdict = KRF_DELETE;
      goto sentenced;

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

  if (net->n.flags & KRF_VERDICT_MASK)
    {
      /* Route to this destination was already seen. Strange, but it happens... */
      krt_trace_in(p, e, "already seen");
      rte_free(e);
      return;
    }

  if (!p->ready)
    {
      /* We wait for the initial feed to have correct KRF_INSTALLED flag */
      verdict = KRF_IGNORE;
      goto sentenced;
    }

  if (net->n.flags & KRF_INSTALLED)
    {
      rte *new, *rt_free;

      new = krt_export_net(p, net, &rt_free);

      /* TODO: There also may be changes in route eattrs, we ignore that for now. */

      if (!new)
	verdict = KRF_DELETE;
      else if ((net->n.flags & KRF_SYNC_ERROR) || !krt_same_dest(e, new))
	verdict = KRF_UPDATE;
      else
	verdict = KRF_SEEN;

      if (rt_free)
	rte_free(rt_free);

      lp_flush(krt_filter_lp);
    }
  else
    verdict = KRF_DELETE;

 sentenced:
  krt_trace_in(p, e, ((char *[]) { "?", "seen", "will be updated", "will be removed", "ignored" }) [verdict]);
  net->n.flags = (net->n.flags & ~KRF_VERDICT_MASK) | verdict;
  if (verdict == KRF_UPDATE || verdict == KRF_DELETE)
    {
      /* Get a cached copy of attributes and temporarily link the route */
      rta *a = e->attrs;
      a->source = RTS_DUMMY;
      e->attrs = rta_lookup(a);
      e->next = net->routes;
      net->routes = e;
    }
  else
    rte_free(e);
}

static void
krt_prune(struct krt_proto *p)
{
  struct rtable *t = p->p.main_channel->table;

  KRT_TRACE(p, D_EVENTS, "Pruning table %s", t->name);
  FIB_WALK(&t->fib, net, n)
    {
      int verdict = n->n.flags & KRF_VERDICT_MASK;
      rte *new, *old, *rt_free = NULL;

      if (verdict == KRF_UPDATE || verdict == KRF_DELETE)
	{
	  /* Get a dummy route from krt_got_route() */
	  old = n->routes;
	  n->routes = old->next;
	}
      else
	old = NULL;

      if (verdict == KRF_CREATE || verdict == KRF_UPDATE)
	{
	  /* We have to run export filter to get proper 'new' route */
	  new = krt_export_net(p, n, &rt_free);

	  if (!new)
	    verdict = (verdict == KRF_CREATE) ? KRF_IGNORE : KRF_DELETE;
	}
      else
	new = NULL;

      switch (verdict)
	{
	case KRF_CREATE:
	  if (new && (n->n.flags & KRF_INSTALLED))
	    {
	      krt_trace_in(p, new, "reinstalling");
	      krt_replace_rte(p, n, new, NULL);
	    }
	  break;
	case KRF_SEEN:
	case KRF_IGNORE:
	  /* Nothing happens */
	  break;
	case KRF_UPDATE:
	  krt_trace_in(p, new, "updating");
	  krt_replace_rte(p, n, new, old);
	  break;
	case KRF_DELETE:
	  krt_trace_in(p, old, "deleting");
	  krt_replace_rte(p, n, NULL, old);
	  break;
	default:
	  bug("krt_prune: invalid route status");
	}

      if (old)
	rte_free(old);
      if (rt_free)
	rte_free(rt_free);
      lp_flush(krt_filter_lp);
      n->n.flags &= ~KRF_VERDICT_MASK;
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
krt_got_route_async(struct krt_proto *p, rte *e, int new)
{
  net *net = e->net;

  switch (e->u.krt.src)
    {
    case KRT_SRC_BIRD:
      ASSERT(0);			/* Should be filtered by the back end */

    case KRT_SRC_REDIRECT:
      if (new)
	{
	  krt_trace_in(p, e, "[redirect] deleting");
	  krt_replace_rte(p, net, NULL, e);
	}
      /* If !new, it is probably echo of our deletion */
      break;

#ifdef KRT_ALLOW_LEARN
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


#ifdef CONFIG_ALL_TABLES_AT_ONCE

static timer *krt_scan_timer;
static int krt_scan_count;

static void
krt_scan(timer *t UNUSED)
{
  struct krt_proto *p;

  kif_force_scan();

  /* We need some node to decide whether to print the debug messages or not */
  p = SKIP_BACK(struct krt_proto, krt_node, HEAD(krt_proto_list));
  KRT_TRACE(p, D_EVENTS, "Scanning routing table");

  krt_do_scan(NULL);

  void *q;
  WALK_LIST(q, krt_proto_list)
  {
    p = SKIP_BACK(struct krt_proto, krt_node, q);
    krt_prune(p);
  }
}

static void
krt_scan_timer_start(struct krt_proto *p)
{
  if (!krt_scan_count)
    krt_scan_timer = tm_new_init(krt_pool, krt_scan, NULL, KRT_CF->scan_time, 0);

  krt_scan_count++;

  tm_start(krt_scan_timer, 1 S);
}

static void
krt_scan_timer_stop(struct krt_proto *p UNUSED)
{
  krt_scan_count--;

  if (!krt_scan_count)
  {
    rfree(krt_scan_timer);
    krt_scan_timer = NULL;
  }
}

static void
krt_scan_timer_kick(struct krt_proto *p UNUSED)
{
  tm_start(krt_scan_timer, 0);
}

#else

static void
krt_scan(timer *t)
{
  struct krt_proto *p = t->data;

  kif_force_scan();

  KRT_TRACE(p, D_EVENTS, "Scanning routing table");
  krt_do_scan(p);
  krt_prune(p);
}

static void
krt_scan_timer_start(struct krt_proto *p)
{
  p->scan_timer = tm_new_init(p->p.pool, krt_scan, p, KRT_CF->scan_time, 0);
  tm_start(p->scan_timer, 1 S);
}

static void
krt_scan_timer_stop(struct krt_proto *p)
{
  tm_stop(p->scan_timer);
}

static void
krt_scan_timer_kick(struct krt_proto *p)
{
  tm_start(p->scan_timer, 0);
}

#endif




/*
 *	Updates
 */

static struct ea_list *
krt_make_tmp_attrs(rte *rt, struct linpool *pool)
{
  struct ea_list *l = lp_alloc(pool, sizeof(struct ea_list) + 2 * sizeof(eattr));

  l->next = NULL;
  l->flags = EALF_SORTED;
  l->count = 2;

  l->attrs[0].id = EA_KRT_SOURCE;
  l->attrs[0].flags = 0;
  l->attrs[0].type = EAF_TYPE_INT | EAF_TEMP;
  l->attrs[0].u.data = rt->u.krt.proto;

  l->attrs[1].id = EA_KRT_METRIC;
  l->attrs[1].flags = 0;
  l->attrs[1].type = EAF_TYPE_INT | EAF_TEMP;
  l->attrs[1].u.data = rt->u.krt.metric;

  return l;
}

static void
krt_store_tmp_attrs(rte *rt)
{
  /* EA_KRT_SOURCE is read-only */
  rt->u.krt.metric = ea_get_int(rt->attrs->eattrs, EA_KRT_METRIC, 0);
}

static int
krt_import_control(struct proto *P, rte **new, struct linpool *pool UNUSED)
{
  // struct krt_proto *p = (struct krt_proto *) P;
  rte *e = *new;

  if (e->attrs->src->proto == P)
  {
#ifdef CONFIG_SINGLE_ROUTE
    /*
     * Implicit withdraw - when the imported kernel route becomes the best one,
     * we know that the previous one exported to the kernel was already removed,
     * but if we processed the update as usual, we would send withdraw to the
     * kernel, which would remove the new imported route instead.
     *
     * We will remove KRT_INSTALLED flag, which stops such withdraw to be
     * processed in krt_rt_notify() and krt_replace_rte().
     */
    if (e == e->net->routes)
      e->net->n.flags &= ~KRF_INSTALLED;
#endif
    return -1;
  }

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
  if (!(net->n.flags & KRF_INSTALLED))
    old = NULL;
  if (new)
    net->n.flags |= KRF_INSTALLED;
  else
    net->n.flags &= ~KRF_INSTALLED;
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


static int
krt_rte_same(rte *a, rte *b)
{
  /* src is always KRT_SRC_ALIEN and type is irrelevant */
  return (a->u.krt.proto == b->u.krt.proto) && (a->u.krt.metric == b->u.krt.metric);
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

  if (EMPTY_LIST(CF->channels))
    cf_error("Channel not specified");

#ifdef CONFIG_ALL_TABLES_AT_ONCE
  if (krt_cf->scan_time != cf->scan_time)
    cf_error("All kernel syncers must use the same table scan interval");
#endif

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

  p->p.import_control = krt_import_control;
  p->p.rt_notify = krt_rt_notify;
  p->p.if_notify = krt_if_notify;
  p->p.reload_routes = krt_reload_routes;
  p->p.feed_end = krt_feed_end;
  p->p.make_tmp_attrs = krt_make_tmp_attrs;
  p->p.store_tmp_attrs = krt_store_tmp_attrs;
  p->p.rte_same = krt_rte_same;

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
  if (p->initialized && !KRT_CF->persist)
    krt_flush_routes(p);

  p->ready = 0;
  p->initialized = 0;

  if (p->p.proto_state == PS_START)
    return PS_DOWN;

  krt_sys_shutdown(p);
  rem_node(&p->krt_node);

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
krt_get_attr(eattr *a, byte *buf, int buflen)
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
  .dump_attrs =		krt_dump_attrs,
#endif
};
