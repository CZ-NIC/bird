/*
 *	BIRD -- Internet Group Management Protocol (IGMP)
 *
 *	(c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *	(c) 2018 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2018 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Internet Group Management Protocol, Version 2
 *
 * The Internet Group Management Protocol (IGMP) is used by IP hosts to report
 * their multicast group memberships to any immediately-neighboring multicast
 * routers. This memo describes only the use of IGMP between hosts and routers
 * to determine group membership. Routers that are members of multicast groups
 * are expected to behave as hosts as well as routers, and may even respond to
 * their own queries. IGMP may also be used between routers, but such use is not
 * specified here.
 *
 * Its implementation is split into three files, |packets.c| handling low-level
 * packet formats and |igmp.c| implementing BIRD interface and protocol logic.
 *
 * IGMP communicates with hosts, and publishes requests for groups and
 * interfaces to the BIRD mutlicast request table. It needs to hold state for
 * every group with local listeners.
 */

#include "igmp.h"


#define HASH_GRP_KEY(n)		n->address
#define HASH_GRP_NEXT(n)	n->next
#define HASH_GRP_EQ(a,b)	ip4_equal(a,b)
#define HASH_GRP_FN(k)		ip4_hash(k)

static const char *igmp_join_state_names[] = {
  [IGMP_JS_NO_MEMBERS]	= "NoMembers",
  [IGMP_JS_MEMBERS]	= "Members",
  [IGMP_JS_V1_MEMBERS]	= "MembersV1",
  [IGMP_JS_CHECKING]	= "Checking",
};

static const char *igmp_query_state_names[] = {
  [IGMP_QS_INIT]	= "Init",
  [IGMP_QS_QUERIER]	= "Querier",
  [IGMP_QS_NONQUERIER]	= "Listener",
};

static struct igmp_group *igmp_find_group(struct igmp_iface *ifa, ip4_addr addr);
static struct igmp_group *igmp_get_group(struct igmp_iface *ifa, ip4_addr addr);
static void igmp_remove_group(struct igmp_group *grp);
static void igmp_announce_group(struct igmp_group *grp, int up);
static void igmp_group_set_state(struct igmp_group *grp, uint state);
static void igmp_iface_set_state(struct igmp_iface *ifa, uint state);


/*
 *	IGMP protocol logic
 */

static void
igmp_query_timeout(struct timer *tm)
{
  struct igmp_iface *ifa = tm->data;

  ASSERT(ifa->query_state == IGMP_QS_QUERIER);

  igmp_send_query(ifa, IP4_NONE, ifa->cf->query_response_int);

  if (ifa->startup_query_cnt > 0)
    ifa->startup_query_cnt--;

  tm_start(ifa->query_timer, ifa->startup_query_cnt
      ? ifa->cf->startup_query_int
      : ifa->cf->query_int);
}

static void
igmp_other_present_timeout(struct timer *tm)
{
  struct igmp_iface *ifa = tm->data;

  ASSERT(ifa->query_state == IGMP_QS_NONQUERIER);

  igmp_iface_set_state(ifa, IGMP_QS_QUERIER);
  tm_start(ifa->query_timer, 0);
}

static void
igmp_join_timeout(struct timer *tm)
{
  struct igmp_group *grp = tm->data;

  ASSERT(grp->join_state != IGMP_JS_NO_MEMBERS);

  igmp_group_set_state(grp, IGMP_JS_NO_MEMBERS);
  igmp_announce_group(grp, 0);
  igmp_remove_group(grp);
}

static void
igmp_v1_host_timeout(struct timer *tm)
{
  struct igmp_group *grp = tm->data;

  ASSERT(grp->join_state == IGMP_JS_V1_MEMBERS);

  igmp_group_set_state(grp, IGMP_JS_MEMBERS);
}

static void
igmp_rxmt_timeout(struct timer *tm)
{
  struct igmp_group *grp = tm->data;
  struct igmp_iface *ifa = grp->ifa;

  ASSERT(grp->join_state == IGMP_JS_CHECKING);

  igmp_send_query(ifa, grp->address, ifa->cf->last_member_query_int);
  tm_start(grp->rxmt_timer, ifa->cf->last_member_query_int);
}

void
igmp_handle_query(struct igmp_iface *ifa, ip4_addr addr, ip4_addr from, btime resp_time)
{
  /* Another router with lower IP shall be the Querier */
  if ((ifa->query_state == IGMP_QS_QUERIER) &&
      (ip4_compare(from, ipa_to_ip4(ifa->sk->saddr)) < 0))
  {
    igmp_iface_set_state(ifa, IGMP_QS_NONQUERIER);
    ifa->startup_query_cnt = 0;
    tm_stop(ifa->query_timer);
    tm_start(ifa->other_present, ifa->cf->other_querier_int);
  }

  if ((ifa->query_state == IGMP_QS_NONQUERIER) && ip4_nonzero(addr))
  {
    struct igmp_group *grp = igmp_find_group(ifa, addr);

    if (grp && (grp->join_state == IGMP_JS_MEMBERS))
    {
      igmp_group_set_state(grp, IGMP_JS_CHECKING);
      tm_start(grp->join_timer, resp_time * ifa->cf->last_member_query_cnt);
      tm_stop(grp->rxmt_timer);
    }
  }
}

void
igmp_handle_report(struct igmp_iface *ifa, ip4_addr addr, int version)
{
  struct igmp_group *grp = igmp_get_group(ifa, addr);
  uint last_state = grp->join_state;

  if (version == 1)
  {
    igmp_group_set_state(grp, IGMP_JS_V1_MEMBERS);
    tm_start(grp->v1_host_timer, ifa->cf->group_member_int + 100 MS);
  }
  else
  {
    if (last_state != IGMP_JS_V1_MEMBERS)
      igmp_group_set_state(grp, IGMP_JS_MEMBERS);
  }

  tm_start(grp->join_timer, ifa->cf->group_member_int);
  tm_stop(grp->rxmt_timer);

  if (last_state == IGMP_JS_NO_MEMBERS)
    igmp_announce_group(grp, 1);
}

void
igmp_handle_leave(struct igmp_iface *ifa, ip4_addr addr)
{
  if (ifa->query_state == IGMP_QS_QUERIER)
  {
    struct igmp_group *grp = igmp_find_group(ifa, addr);

    if (grp && (grp->join_state == IGMP_JS_MEMBERS))
    {
      igmp_group_set_state(grp, IGMP_JS_CHECKING);
      tm_start(grp->join_timer, ifa->cf->last_member_query_int * ifa->cf->last_member_query_cnt);
      tm_start(grp->rxmt_timer, 0);
    }
  }
}


/*
 *	IGMP groups
 */

static struct igmp_group *
igmp_find_group(struct igmp_iface *ifa, ip4_addr addr)
{
  return HASH_FIND(ifa->groups, HASH_GRP, addr);
}

static struct igmp_group *
igmp_get_group(struct igmp_iface *ifa, ip4_addr addr)
{
  struct igmp_proto *p = ifa->proto;
  struct igmp_group *grp = igmp_find_group(ifa, addr);

  if (grp)
    return grp;

  grp = mb_allocz(p->p.pool, sizeof(struct igmp_group));
  grp->address = addr;
  grp->ifa = ifa;
  HASH_INSERT(ifa->groups, HASH_GRP, grp);

  grp->join_timer = tm_new_init(p->p.pool, igmp_join_timeout, grp, 0, 0);
  grp->rxmt_timer = tm_new_init(p->p.pool, igmp_rxmt_timeout, grp, 0, 0);
  grp->v1_host_timer = tm_new_init(p->p.pool, igmp_v1_host_timeout, grp, 0, 0);

  return grp;
}

static void
igmp_remove_group(struct igmp_group *grp)
{
  rfree(grp->join_timer);
  rfree(grp->v1_host_timer);
  rfree(grp->rxmt_timer);

  HASH_REMOVE(grp->ifa->groups, HASH_GRP, grp);
  mb_free(grp);
}

static void
igmp_announce_group(struct igmp_group *grp, int up)
{
  struct igmp_proto *p = grp->ifa->proto;
  net_addr_mreq4 addr = NET_ADDR_MREQ4(grp->address, grp->ifa->iface->index);

  if (up)
  {
    rta a0 = {
      .src = p->p.main_source,
      .source = RTS_IGMP,
      .scope = SCOPE_UNIVERSE,
      .dest = RTD_NONE,
      .nh.iface = grp->ifa->iface,
    };
    rta *a = rta_lookup(&a0);
    rte *e = rte_get_temp(a);

    e->pflags = 0;
    rte_update(&p->p, (net_addr *) &addr, e);
  }
  else
  {
    rte_update(&p->p, (net_addr *) &addr, NULL);
  }
}

static void
igmp_group_set_state(struct igmp_group *grp, uint state)
{
  struct igmp_proto *p = grp->ifa->proto;
  uint last_state = grp->join_state;

  if (state == last_state)
    return;

  TRACE(D_EVENTS, "Group %I4 on %s changed state from %s to %s",
	grp->address, grp->ifa->iface->name,
	igmp_join_state_names[last_state], igmp_join_state_names[state]);

  grp->join_state = state;
}


/*
 *	IGMP interfaces
 */

static struct igmp_iface *
igmp_find_iface(struct igmp_proto *p, struct iface *what)
{
  struct igmp_iface *ifa;

  WALK_LIST(ifa, p->iface_list)
    if (ifa->iface == what)
      return ifa;

  return NULL;
}


static void
igmp_iface_locked(struct object_lock *lock)
{
  struct igmp_iface *ifa = lock->data;
  struct igmp_proto *p = ifa->proto;

  if (!igmp_open_socket(ifa))
  {
    log(L_ERR "%s: Cannot open socket for %s", p->p.name, ifa->iface->name);
    return;
  }

  igmp_iface_set_state(ifa, IGMP_QS_QUERIER);
  ifa->startup_query_cnt = ifa->cf->startup_query_cnt;
  tm_start(ifa->query_timer, 0);
}

static void
igmp_add_iface(struct igmp_proto *p, struct iface *iface, struct igmp_iface_config *ic)
{
  struct igmp_iface *ifa;

  TRACE(D_EVENTS, "Adding interface %s", iface->name);

  ifa = mb_allocz(p->p.pool, sizeof(struct igmp_iface));
  add_tail(&p->iface_list, NODE ifa);
  ifa->proto = p;
  ifa->iface = iface;
  ifa->cf = ic;

  ifa->query_timer = tm_new_init(p->p.pool, igmp_query_timeout, ifa, 0, 0);
  ifa->other_present = tm_new_init(p->p.pool, igmp_other_present_timeout, ifa, 0, 0);

  HASH_INIT(ifa->groups, p->p.pool, 8);

  ifa->mif = mif_get(p->mif_group, iface);
  if (!ifa->mif)
  {
    log(L_ERR "%s: Cannot enable multicast on %s, too many MIFs", p->p.name, ifa->iface->name);
    return;
  }

  struct object_lock *lock = olock_new(p->p.pool);
  lock->type = OBJLOCK_IP;
  lock->port = IGMP_PROTO;
  lock->iface = iface;
  lock->data = ifa;
  lock->hook = igmp_iface_locked;
  ifa->lock = lock;

  olock_acquire(lock);
}

static void
igmp_remove_iface(struct igmp_proto *p, struct igmp_iface *ifa)
{
  TRACE(D_EVENTS, "Removing interface %s", ifa->iface->name);

  HASH_WALK_DELSAFE(ifa->groups, next, grp)
  {
    igmp_announce_group(grp, 0);
    igmp_remove_group(grp);
  }
  HASH_WALK_END;

  rem_node(NODE ifa);

  /* This is not a resource */
  if (ifa->mif)
    mif_free(p->mif_group, ifa->mif);

  rfree(ifa->sk);
  rfree(ifa->lock);
  rfree(ifa->query_timer);
  rfree(ifa->other_present);

  mb_free(ifa);
}

static void
igmp_iface_set_state(struct igmp_iface *ifa, uint state)
{
  struct igmp_proto *p = ifa->proto;
  uint last_state = ifa->query_state;

  if (state == last_state)
    return;

  TRACE(D_EVENTS, "Interface %s changed state from %s to %s", ifa->iface->name,
	igmp_query_state_names[last_state], igmp_query_state_names[state]);

  ifa->query_state = state;
}

static void
igmp_iface_dump(struct igmp_iface *ifa)
{
  debug("\tInterface %s: %s\n", ifa->iface->name, igmp_query_state_names[ifa->query_state]);

  HASH_WALK(ifa->groups, next, grp)
    debug("\t\tGroup %I4: %s\n", grp->address, igmp_join_state_names[grp->join_state]);
  HASH_WALK_END;
}

void
igmp_finish_iface_config(struct igmp_iface_config *cf)
{
  if (cf->query_response_int >= cf->query_int)
    cf_error("Query response interval must be less than query interval");

  /* Dependent default values */
  if (!cf->startup_query_int)
    cf->startup_query_int = cf->query_int / 4;

  if (!cf->startup_query_cnt)
    cf->startup_query_cnt = cf->robustness;

  if (!cf->last_member_query_cnt)
    cf->last_member_query_cnt = cf->robustness;

  cf->group_member_int = cf->robustness * cf->query_int + cf->query_response_int;
  cf->other_querier_int = cf->robustness * cf->query_int + cf->query_response_int / 2;
}

static int
igmp_reconfigure_iface(struct igmp_proto *p, struct igmp_iface *ifa, struct igmp_iface_config *new)
{
  struct igmp_iface_config *old = ifa->cf;

  TRACE(D_EVENTS, "Reconfiguring interface %s", ifa->iface->name);

  ifa->cf = new;

  /* We reconfigure just the query timer, as it is periodic */
  if (ifa->query_state == IGMP_QS_QUERIER)
  {
    if (ifa->startup_query_cnt)
    {
      if (new->startup_query_cnt != old->startup_query_cnt)
      {
	int delta = (int) new->startup_query_cnt - (int) old->startup_query_cnt;
	ifa->startup_query_cnt = MAX(1, ifa->startup_query_cnt + delta);
      }

      if (new->startup_query_int != old->startup_query_int)
	tm_shift(ifa->query_timer, new->startup_query_int - old->startup_query_int);
    }
    else
    {
      if (new->query_int != old->query_int)
	tm_shift(ifa->query_timer, new->query_int - old->query_int);
    }
  }

  return 1;
}

static void
igmp_reconfigure_ifaces(struct igmp_proto *p, struct igmp_config *cf)
{
  struct iface *iface;

  WALK_LIST(iface, iface_list)
  {
    if (!(iface->flags & IF_UP))
      continue;

    /* Ignore non-multicast ifaces */
    if (!(iface->flags & IF_MULTICAST))
      continue;

    /* Ignore ifaces without IPv4 address */
    if (!iface->addr4)
      continue;

    struct igmp_iface *ifa = igmp_find_iface(p, iface);
    struct igmp_iface_config *ic = (void *) iface_patt_find(&cf->iface_list, iface, NULL);

    if (ifa && ic)
    {
      if (igmp_reconfigure_iface(p, ifa, ic))
	continue;

      /* Hard restart */
      log(L_INFO "%s: Restarting interface %s", p->p.name, ifa->iface->name);
      igmp_remove_iface(p, ifa);
      igmp_add_iface(p, iface, ic);
    }

    if (ifa && !ic)
      igmp_remove_iface(p, ifa);

    if (!ifa && ic)
      igmp_add_iface(p, iface, ic);
  }
}


/*
 *	IGMP protocol glue
 */

void
igmp_postconfig(struct proto_config *CF)
{
  // struct igmp_config *cf = (void *) CF;

  /* Define default channel */
  if (EMPTY_LIST(CF->channels))
    channel_config_new(NULL, net_label[NET_MREQ4], NET_MREQ4, CF);
}

static void
igmp_if_notify(struct proto *P, uint flags, struct iface *iface)
{
  struct igmp_proto *p = (void *) P;
  struct igmp_config *cf = (void *) P->cf;

  if (iface->flags & IF_IGNORE)
    return;

  if (flags & IF_CHANGE_UP)
  {
    struct igmp_iface_config *ic = (void *) iface_patt_find(&cf->iface_list, iface, NULL);

    /* Ignore non-multicast ifaces */
    if (!(iface->flags & IF_MULTICAST))
      return;

    /* Ignore ifaces without IPv4 address */
    if (!iface->addr4)
      return;

    if (ic)
      igmp_add_iface(p, iface, ic);

    return;
  }

  struct igmp_iface *ifa = igmp_find_iface(p, iface);

  if (!ifa)
    return;

  if (flags & IF_CHANGE_DOWN)
  {
    igmp_remove_iface(p, ifa);
    return;
  }
}

static struct proto *
igmp_init(struct proto_config *CF)
{
  struct igmp_proto *p = proto_new(CF);

  p->p.main_channel = proto_add_channel(&p->p, proto_cf_main_channel(CF));

  p->p.if_notify = igmp_if_notify;

  p->mif_group = global_mif_group;

  return &p->p;
}

static int
igmp_start(struct proto *P)
{
  struct igmp_proto *p = (void *) P;

  init_list(&p->iface_list);
  p->log_pkt_tbf = (struct tbf){ .rate = 1, .burst = 5 };

  return PS_UP;
}

static int
igmp_shutdown(struct proto *P)
{
  struct igmp_proto *p = (void *) P;
  struct igmp_iface *ifa;

  WALK_LIST_FIRST(ifa, p->iface_list)
    igmp_remove_iface(p, ifa);

  return PS_DOWN;
}

static int
igmp_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct igmp_proto *p = (void *) P;
  struct igmp_config *new = (void *) CF;

  if (!proto_configure_channel(P, &P->main_channel, proto_cf_main_channel(CF)))
    return 0;

  TRACE(D_EVENTS, "Reconfiguring");

  p->p.cf = CF;
  igmp_reconfigure_ifaces(p, new);

  return 1;
}

static void
igmp_dump(struct proto *P)
{
  struct igmp_proto *p = (void *) P;
  struct igmp_iface *ifa;

  WALK_LIST(ifa, p->iface_list)
    igmp_iface_dump(ifa);
}


struct protocol proto_igmp = {
  .name =		"IGMP",
  .template =		"igmp%d",
  .preference =		DEF_PREF_IGMP,
  .channel_mask =	NB_MREQ4,
  .proto_size =		sizeof(struct igmp_proto),
  .config_size =	sizeof(struct igmp_config),
  .postconfig =		igmp_postconfig,
  .init =		igmp_init,
  .dump =		igmp_dump,
  .start =		igmp_start,
  .shutdown =		igmp_shutdown,
  .reconfigure =	igmp_reconfigure,
};
