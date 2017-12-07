/*
 *	BIRD -- Router Advertisement
 *
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */


#include <stdlib.h>
#include "radv.h"

/**
 * DOC: Router Advertisements
 *
 * The RAdv protocol is implemented in two files: |radv.c| containing
 * the interface with BIRD core and the protocol logic and |packets.c|
 * handling low level protocol stuff (RX, TX and packet formats).
 * The protocol does not export any routes.
 *
 * The RAdv is structured in the usual way - for each handled interface
 * there is a structure &radv_iface that contains a state related to
 * that interface together with its resources (a socket, a timer).
 * There is also a prepared RA stored in a TX buffer of the socket
 * associated with an iface. These iface structures are created
 * and removed according to iface events from BIRD core handled by
 * radv_if_notify() callback.
 *
 * The main logic of RAdv consists of two functions:
 * radv_iface_notify(), which processes asynchronous events (specified
 * by RA_EV_* codes), and radv_timer(), which triggers sending RAs and
 * computes the next timeout.
 *
 * The RAdv protocol could receive routes (through
 * radv_import_control() and radv_rt_notify()), but only the
 * configured trigger route is tracked (in &active var).  When a radv
 * protocol is reconfigured, the connected routing table is examined
 * (in radv_check_active()) to have proper &active value in case of
 * the specified trigger prefix was changed.
 *
 * Supported standards:
 * - RFC 4861 - main RA standard
 * - RFC 6106 - DNS extensions (RDDNS, DNSSL)
 * - RFC 4191 (partial) - Default Router Preference
 */

static void
radv_timer(timer *tm)
{
  struct radv_iface *ifa = tm->data;
  struct radv_proto *p = ifa->ra;

  RADV_TRACE(D_EVENTS, "Timer fired on %s", ifa->iface->name);

  /*
   * If some dead prefixes expired, regenerate the prefix list and the packet.
   * We do so by pretending there was a change on the interface.
   *
   * This sets the timer, but we replace it just at the end of this function
   * (replacing a timer is fine).
   */
  if (ifa->prefix_expires && (ifa->prefix_expires <= current_time()))
    radv_iface_notify(ifa, RA_EV_GC);

  radv_send_ra(ifa, 0);

  /* Update timer */
  ifa->last = current_time();
  btime t = ifa->cf->min_ra_int S;
  btime r = (ifa->cf->max_ra_int - ifa->cf->min_ra_int) S;
  t += random() % (r + 1);

  if (ifa->initial)
  {
    t = MIN(t, MAX_INITIAL_RTR_ADVERT_INTERVAL);
    ifa->initial--;
  }

  tm_start(ifa->timer, t);
}

static struct radv_prefix_config default_prefix = {
  .onlink = 1,
  .autonomous = 1,
  .valid_lifetime = DEFAULT_VALID_LIFETIME,
  .preferred_lifetime = DEFAULT_PREFERRED_LIFETIME
};

static struct radv_prefix_config dead_prefix = {
};

/* Find a corresponding config for the given prefix */
static struct radv_prefix_config *
radv_prefix_match(struct radv_iface *ifa, net_addr_ip6 *px)
{
  struct radv_proto *p = ifa->ra;
  struct radv_config *cf = (struct radv_config *) (p->p.cf);
  struct radv_prefix_config *pc;

  WALK_LIST(pc, ifa->cf->pref_list)
    if (net_in_net_ip6(px, &pc->prefix))
      return pc;

  WALK_LIST(pc, cf->pref_list)
    if (net_in_net_ip6(px, &pc->prefix))
      return pc;

  return &default_prefix;
}

/*
 * Go through the list of prefixes, compare them with configs and decide if we
 * want them or not.
 */
static void
radv_prepare_prefixes(struct radv_iface *ifa)
{
  struct radv_proto *p = ifa->ra;
  struct radv_iface_config *cf = ifa->cf;
  struct radv_prefix *pfx;

  /* First mark all the prefixes as unused */
  WALK_LIST(pfx, ifa->prefixes)
    pfx->mark = 0;

  /* Find all the prefixes we want to use and make sure they are in the list. */
  struct ifa *addr;
  WALK_LIST(addr, ifa->iface->addrs)
  {
    if ((addr->prefix.type != NET_IP6) ||
	(addr->scope <= SCOPE_LINK))
      continue;

    net_addr_ip6 *prefix = (void *) &addr->prefix;
    struct radv_prefix_config *pc = radv_prefix_match(ifa, prefix);

    if (!pc || pc->skip)
      continue;

    /* Do we have it already? */
    struct radv_prefix *existing = NULL;
    WALK_LIST(pfx, ifa->prefixes)
      if (net_equal_ip6(&pfx->prefix, prefix))
      {
	existing = pfx;
	break;
      }

    if (!existing)
    {
      RADV_TRACE(D_EVENTS, "Adding new prefix %N on %s",
		 prefix, ifa->iface->name);

      existing = mb_allocz(ifa->pool, sizeof *existing);
      net_copy_ip6(&existing->prefix, prefix);
      add_tail(&ifa->prefixes, NODE existing);
    }

    /*
     * Update the information (it may have changed, or even bring a prefix back
     * to life).
     */
    existing->alive = 1;
    existing->mark = 1;
    existing->cf = pc;
  }

  /*
   * Garbage-collect the prefixes. If something isn't used, it dies (but isn't
   * dropped just yet). If something is dead and rots there for long enough,
   * clean it up.
   */
  btime now_ = current_time();
  btime expires = now_ + cf->linger_time S;
  btime expires_min = 0;
  struct radv_prefix *next;
  WALK_LIST_DELSAFE(pfx, next, ifa->prefixes)
  {
    if (pfx->alive && !pfx->mark)
    {
      RADV_TRACE(D_EVENTS, "Marking prefix %N on %s as dead",
		 pfx->prefix, ifa->iface->name);

      pfx->alive = 0;
      pfx->expires = expires;
      pfx->cf = &dead_prefix;
    }

    if (!pfx->alive)
    {
      if (pfx->expires <= now_)
      {
	RADV_TRACE(D_EVENTS, "Removing prefix %N on %s",
		   pfx->prefix, ifa->iface->name);

	rem_node(NODE pfx);
	mb_free(pfx);
      }
      else
      {
	/* Find minimum expiration time */
	if (!expires_min || (pfx->expires < expires_min))
	  expires_min = pfx->expires;
      }
    }
  }

  ifa->prefix_expires = expires_min;
}

static char* ev_name[] = { NULL, "Init", "Change", "RS", "Garbage collect" };

void
radv_iface_notify(struct radv_iface *ifa, int event)
{
  struct radv_proto *p = ifa->ra;

  if (!ifa->sk)
    return;

  RADV_TRACE(D_EVENTS, "Event %s on %s", ev_name[event], ifa->iface->name);

  switch (event)
  {
  case RA_EV_CHANGE:
  case RA_EV_GC:
    ifa->plen = 0;
  case RA_EV_INIT:
    ifa->initial = MAX_INITIAL_RTR_ADVERTISEMENTS;
    break;

  case RA_EV_RS:
    break;
  }

  radv_prepare_prefixes(ifa);

  /* Update timer */
  btime t = ifa->last + ifa->cf->min_delay S - current_time();
  tm_start(ifa->timer, t);
}

static void
radv_iface_notify_all(struct radv_proto *p, int event)
{
  struct radv_iface *ifa;

  WALK_LIST(ifa, p->iface_list)
    radv_iface_notify(ifa, event);
}


static struct radv_iface *
radv_iface_find(struct radv_proto *p, struct iface *what)
{
  struct radv_iface *ifa;

  WALK_LIST(ifa, p->iface_list)
    if (ifa->iface == what)
      return ifa;

  return NULL;
}

static void
radv_iface_add(struct object_lock *lock)
{
  struct radv_iface *ifa = lock->data;
  struct radv_proto *p = ifa->ra;

  if (! radv_sk_open(ifa))
  {
    log(L_ERR "%s: Socket open failed on interface %s", p->p.name, ifa->iface->name);
    return;
  }

  radv_iface_notify(ifa, RA_EV_INIT);
}

static void
radv_iface_new(struct radv_proto *p, struct iface *iface, struct radv_iface_config *cf)
{
  struct radv_iface *ifa;

  RADV_TRACE(D_EVENTS, "Adding interface %s", iface->name);

  pool *pool = rp_new(p->p.pool, iface->name);
  ifa = mb_allocz(pool, sizeof(struct radv_iface));
  ifa->pool = pool;
  ifa->ra = p;
  ifa->cf = cf;
  ifa->iface = iface;
  ifa->addr = iface->llv6;
  init_list(&ifa->prefixes);

  add_tail(&p->iface_list, NODE ifa);

  ifa->timer = tm_new_init(pool, radv_timer, ifa, 0, 0);

  struct object_lock *lock = olock_new(pool);
  lock->addr = IPA_NONE;
  lock->type = OBJLOCK_IP;
  lock->port = ICMPV6_PROTO;
  lock->iface = iface;
  lock->data = ifa;
  lock->hook = radv_iface_add;
  ifa->lock = lock;

  olock_acquire(lock);
}

static void
radv_iface_remove(struct radv_iface *ifa)
{
  struct radv_proto *p = ifa->ra;
  RADV_TRACE(D_EVENTS, "Removing interface %s", ifa->iface->name);

  rem_node(NODE ifa);

  rfree(ifa->pool);
}

static void
radv_if_notify(struct proto *P, unsigned flags, struct iface *iface)
{
  struct radv_proto *p = (struct radv_proto *) P;
  struct radv_config *cf = (struct radv_config *) (P->cf);

  if (iface->flags & IF_IGNORE)
    return;

  if (flags & IF_CHANGE_UP)
  {
    struct radv_iface_config *ic = (void *) iface_patt_find(&cf->patt_list, iface, NULL);

    /* Ignore non-multicast ifaces */
    if (!(iface->flags & IF_MULTICAST))
      return;

    /* Ignore ifaces without link-local address */
    if (!iface->llv6)
      return;

    if (ic)
      radv_iface_new(p, iface, ic);

    return;
  }

  struct radv_iface *ifa = radv_iface_find(p, iface);
  if (!ifa)
    return;

  if (flags & IF_CHANGE_DOWN)
  {
    radv_iface_remove(ifa);
    return;
  }

  if ((flags & IF_CHANGE_LINK) && (iface->flags & IF_LINK_UP))
    radv_iface_notify(ifa, RA_EV_INIT);
}

static void
radv_ifa_notify(struct proto *P, unsigned flags UNUSED, struct ifa *a)
{
  struct radv_proto *p = (struct radv_proto *) P;

  if (a->flags & IA_SECONDARY)
    return;

  if (a->scope <= SCOPE_LINK)
    return;

  struct radv_iface *ifa = radv_iface_find(p, a->iface);

  if (ifa)
    radv_iface_notify(ifa, RA_EV_CHANGE);
}

static inline int
radv_trigger_valid(struct radv_config *cf)
{
  return cf->trigger.type != 0;
}

static inline int
radv_net_match_trigger(struct radv_config *cf, net *n)
{
  return radv_trigger_valid(cf) && net_equal(n->n.addr, &cf->trigger);
}

int
radv_import_control(struct proto *P, rte **new, ea_list **attrs UNUSED, struct linpool *pool UNUSED)
{
  // struct radv_proto *p = (struct radv_proto *) P;
  struct radv_config *cf = (struct radv_config *) (P->cf);

  if (radv_net_match_trigger(cf, (*new)->net))
    return RIC_PROCESS;

  return RIC_DROP;
}

static void
radv_rt_notify(struct proto *P, struct channel *ch UNUSED, net *n, rte *new, rte *old UNUSED, ea_list *attrs UNUSED)
{
  struct radv_proto *p = (struct radv_proto *) P;
  struct radv_config *cf = (struct radv_config *) (P->cf);

  if (radv_net_match_trigger(cf, n))
  {
    u8 old_active = p->active;
    p->active = !!new;

    if (p->active == old_active)
      return;

    if (p->active)
      RADV_TRACE(D_EVENTS, "Triggered");
    else
      RADV_TRACE(D_EVENTS, "Suppressed");

    radv_iface_notify_all(p, RA_EV_CHANGE);
  }
}

static int
radv_check_active(struct radv_proto *p)
{
  struct radv_config *cf = (struct radv_config *) (p->p.cf);

  if (!radv_trigger_valid(cf))
    return 1;

  struct channel *c = p->p.main_channel;
  return rt_examine(c->table, &cf->trigger, &p->p, c->out_filter);
}

static void
radv_postconfig(struct proto_config *CF)
{
  // struct radv_config *cf = (void *) CF;

  /* Define default channel */
  if (EMPTY_LIST(CF->channels))
    channel_config_new(NULL, NET_IP6, CF);
}

static struct proto *
radv_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);

  P->main_channel = proto_add_channel(P, proto_cf_main_channel(CF));

  P->import_control = radv_import_control;
  P->rt_notify = radv_rt_notify;
  P->if_notify = radv_if_notify;
  P->ifa_notify = radv_ifa_notify;

  return P;
}

static int
radv_start(struct proto *P)
{
  struct radv_proto *p = (struct radv_proto *) P;
  struct radv_config *cf = (struct radv_config *) (P->cf);

  init_list(&(p->iface_list));
  p->active = !radv_trigger_valid(cf);

  return PS_UP;
}

static inline void
radv_iface_shutdown(struct radv_iface *ifa)
{
  if (ifa->sk)
    radv_send_ra(ifa, 1);
}

static int
radv_shutdown(struct proto *P)
{
  struct radv_proto *p = (struct radv_proto *) P;

  struct radv_iface *ifa;
  WALK_LIST(ifa, p->iface_list)
    radv_iface_shutdown(ifa);

  return PS_DOWN;
}

static int
radv_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct radv_proto *p = (struct radv_proto *) P;
  // struct radv_config *old = (struct radv_config *) (p->cf);
  struct radv_config *new = (struct radv_config *) CF;

  /*
   * The question is why there is a reconfigure function for RAdv if
   * it has almost none internal state so restarting the protocol
   * would probably suffice. One small reason is that restarting the
   * protocol would lead to sending a RA with Router Lifetime 0
   * causing nodes to temporary remove their default routes.
   */

  if (!proto_configure_channel(P, &P->main_channel, proto_cf_main_channel(CF)))
    return 0;

  P->cf = CF; /* radv_check_active() requires proper P->cf */
  p->active = radv_check_active(p);

  struct iface *iface;
  WALK_LIST(iface, iface_list)
  {
    if (!(iface->flags & IF_UP))
      continue;

    /* Ignore non-multicast ifaces */
    if (!(iface->flags & IF_MULTICAST))
      continue;

    /* Ignore ifaces without link-local address */
    if (!iface->llv6)
      continue;

    struct radv_iface *ifa = radv_iface_find(p, iface);
    struct radv_iface_config *ic = (struct radv_iface_config *)
      iface_patt_find(&new->patt_list, iface, NULL);

    if (ifa && ic)
    {
      ifa->cf = ic;

      /* We cheat here - always notify the change even if there isn't
	 any. That would leads just to a few unnecessary RAs. */
      radv_iface_notify(ifa, RA_EV_CHANGE);
    }

    if (ifa && !ic)
    {
      radv_iface_shutdown(ifa);
      radv_iface_remove(ifa);
    }

    if (!ifa && ic)
      radv_iface_new(p, iface, ic);
  }

  return 1;
}

static void
radv_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct radv_config *d = (struct radv_config *) dest;
  struct radv_config *s = (struct radv_config *) src;

  /* We clean up patt_list, ifaces are non-sharable */
  init_list(&d->patt_list);

  /* We copy pref_list, shallow copy suffices */
  cfg_copy_list(&d->pref_list, &s->pref_list, sizeof(struct radv_prefix_config));
}

static void
radv_get_status(struct proto *P, byte *buf)
{
  struct radv_proto *p = (struct radv_proto *) P;

  if (!p->active)
    strcpy(buf, "Suppressed");
}

struct protocol proto_radv = {
  .name =		"RAdv",
  .template =		"radv%d",
  .channel_mask =	NB_IP6,
  .proto_size =		sizeof(struct radv_proto),
  .config_size =	sizeof(struct radv_config),
  .postconfig =		radv_postconfig,
  .init =		radv_init,
  .start =		radv_start,
  .shutdown =		radv_shutdown,
  .reconfigure =	radv_reconfigure,
  .copy_config =	radv_copy_config,
  .get_status =		radv_get_status
};
