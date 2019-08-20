/*
 *	BIRD -- OSPF
 *
 *	(c) 1999--2004 Ondrej Filip <feela@network.cz>
 *	(c) 2009--2014 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2009--2014 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "ospf.h"


const char *ospf_ns_names[] = {
  "Down", "Attempt", "Init", "2-Way", "ExStart", "Exchange", "Loading", "Full"
};

const char *ospf_inm_names[] = {
  "HelloReceived", "Start", "2-WayReceived", "NegotiationDone", "ExchangeDone",
  "BadLSReq", "LoadingDone", "AdjOK?", "SeqNumberMismatch", "1-WayReceived",
  "KillNbr", "InactivityTimer", "LLDown"
};


static int can_do_adj(struct ospf_neighbor *n);
static void inactivity_timer_hook(timer * timer);
static void dbdes_timer_hook(timer *t);
static void lsrq_timer_hook(timer *t);
static void lsrt_timer_hook(timer *t);
static void ackd_timer_hook(timer *t);
static void ospf_neigh_stop_graceful_restart_(struct ospf_neighbor *n);
static void graceful_restart_timeout(timer *t);


static void
init_lists(struct ospf_proto *p, struct ospf_neighbor *n)
{
  s_init_list(&(n->lsrql));
  n->lsrqi = SHEAD(n->lsrql);
  n->lsrqh = ospf_top_new(p, n->pool);

  s_init_list(&(n->lsrtl));
  n->lsrth = ospf_top_new(p, n->pool);
}

static void
release_lsrtl(struct ospf_proto *p, struct ospf_neighbor *n)
{
  struct top_hash_entry *ret, *en;

  WALK_SLIST(ret, n->lsrtl)
  {
    en = ospf_hash_find_entry(p->gr, ret);
    if (en)
      en->ret_count--;
  }
}

/* Resets LSA request and retransmit lists.
 * We do not reset DB summary list iterator here,
 * it is reset during entering EXCHANGE state.
 */
static void
reset_lists(struct ospf_proto *p, struct ospf_neighbor *n)
{
  release_lsrtl(p, n);
  ospf_top_free(n->lsrqh);
  ospf_top_free(n->lsrth);
  ospf_reset_lsack_queue(n);

  tm_stop(n->dbdes_timer);
  tm_stop(n->lsrq_timer);
  tm_stop(n->lsrt_timer);
  tm_stop(n->ackd_timer);

  init_lists(p, n);
}

struct ospf_neighbor *
ospf_neighbor_new(struct ospf_iface *ifa)
{
  struct ospf_proto *p = ifa->oa->po;
  struct pool *pool = rp_new(p->p.pool, "OSPF Neighbor");
  struct ospf_neighbor *n = mb_allocz(pool, sizeof(struct ospf_neighbor));

  n->pool = pool;
  n->ifa = ifa;
  add_tail(&ifa->neigh_list, NODE n);
  n->state = NEIGHBOR_DOWN;

  init_lists(p, n);
  s_init(&(n->dbsi), &(p->lsal));

  init_list(&n->ackl[ACKL_DIRECT]);
  init_list(&n->ackl[ACKL_DELAY]);

  n->inactim = tm_new_init(pool, inactivity_timer_hook, n, 0, 0);
  n->dbdes_timer = tm_new_init(pool, dbdes_timer_hook, n, ifa->rxmtint S, 0);
  n->lsrq_timer = tm_new_init(pool, lsrq_timer_hook, n, ifa->rxmtint S, 0);
  n->lsrt_timer = tm_new_init(pool, lsrt_timer_hook, n, ifa->rxmtint S, 0);
  n->ackd_timer = tm_new_init(pool, ackd_timer_hook, n, ifa->rxmtint S / 2, 0);

  return (n);
}

static void
ospf_neigh_down(struct ospf_neighbor *n)
{
  struct ospf_iface *ifa = n->ifa;
  struct ospf_proto *p = ifa->oa->po;
  u32 rid = n->rid;

  if ((ifa->type == OSPF_IT_NBMA) || (ifa->type == OSPF_IT_PTMP))
  {
    struct nbma_node *nn = find_nbma_node(ifa, n->ip);
    if (nn)
      nn->found = 0;
  }

  s_get(&(n->dbsi));
  release_lsrtl(p, n);
  rem_node(NODE n);
  rfree(n->pool);

  OSPF_TRACE(D_EVENTS, "Neighbor %R on %s removed", rid, ifa->ifname);
}

/**
 * ospf_neigh_chstate - handles changes related to new or lod state of neighbor
 * @n: OSPF neighbor
 * @state: new state
 *
 * Many actions have to be taken acording to a change of state of a neighbor. It
 * starts rxmt timers, call interface state machine etc.
 */
static void
ospf_neigh_chstate(struct ospf_neighbor *n, u8 state)
{
  struct ospf_iface *ifa = n->ifa;
  struct ospf_proto *p = ifa->oa->po;
  u8 old_state = n->state;
  int old_fadj = ifa->fadj;

  if (state == old_state)
    return;

  OSPF_TRACE(D_EVENTS, "Neighbor %R on %s changed state from %s to %s",
	     n->rid, ifa->ifname, ospf_ns_names[old_state], ospf_ns_names[state]);

  n->state = state;

  /* Increase number of partial adjacencies */
  if ((state == NEIGHBOR_EXCHANGE) || (state == NEIGHBOR_LOADING))
    p->padj++;

  /* Decrease number of partial adjacencies */
  if ((old_state == NEIGHBOR_EXCHANGE) || (old_state == NEIGHBOR_LOADING))
    p->padj--;

  /* Increase number of full adjacencies */
  if (state == NEIGHBOR_FULL)
    ifa->fadj++;

  /* Decrease number of full adjacencies */
  if (old_state == NEIGHBOR_FULL)
    ifa->fadj--;

  if ((ifa->fadj != old_fadj) && !n->gr_active)
  {
    /* RFC 2328 12.4 Event 4 - neighbor enters/leaves Full state */
    ospf_notify_rt_lsa(ifa->oa);
    ospf_notify_net_lsa(ifa);

    /* RFC 2328 12.4 Event 8 - vlink state change */
    if (ifa->type == OSPF_IT_VLINK)
      ospf_notify_rt_lsa(ifa->voa);
  }

  if (state == NEIGHBOR_EXSTART)
  {
    /* First time adjacency attempt */
    if (old_state < NEIGHBOR_EXSTART)
      n->dds = random_u32();

    n->dds++;
    n->myimms = DBDES_IMMS;
    n->got_my_rt_lsa = 0;

    tm_start(n->dbdes_timer, 0);
    tm_start(n->ackd_timer, ifa->rxmtint S / 2);
  }

  if (state > NEIGHBOR_EXSTART)
    n->myimms &= ~DBDES_I;

  /* Generate NeighborChange event if needed, see RFC 2328 9.2 */
  if ((state == NEIGHBOR_2WAY) && (old_state < NEIGHBOR_2WAY) && !n->gr_active)
    ospf_iface_sm(ifa, ISM_NEICH);
  if ((state < NEIGHBOR_2WAY) && (old_state >= NEIGHBOR_2WAY) && !n->gr_active)
    ospf_iface_sm(ifa, ISM_NEICH);
}

/**
 * ospf_neigh_sm - ospf neighbor state machine
 * @n: neighor
 * @event: actual event
 *
 * This part implements the neighbor state machine as described in 10.3 of
 * RFC 2328. The only difference is that state %NEIGHBOR_ATTEMPT is not
 * used. We discover neighbors on nonbroadcast networks in the
 * same way as on broadcast networks. The only difference is in
 * sending hello packets. These are sent to IPs listed in
 * @ospf_iface->nbma_list .
 */
void
ospf_neigh_sm(struct ospf_neighbor *n, int event)
{
  struct ospf_proto *p = n->ifa->oa->po;

  DBG("Neighbor state machine for %R on %s, event %s\n",
      n->rid, n->ifa->ifname, ospf_inm_names[event]);

  switch (event)
  {
  case INM_START:
    ospf_neigh_chstate(n, NEIGHBOR_ATTEMPT);
    /* NBMA are used different way */
    break;

  case INM_HELLOREC:
    if (n->state < NEIGHBOR_INIT)
      ospf_neigh_chstate(n, NEIGHBOR_INIT);

    /* Restart inactivity timer */
    tm_start(n->inactim, n->ifa->deadint S);
    break;

  case INM_2WAYREC:
    if (n->state < NEIGHBOR_2WAY)
      ospf_neigh_chstate(n, NEIGHBOR_2WAY);
    if ((n->state == NEIGHBOR_2WAY) && can_do_adj(n))
      ospf_neigh_chstate(n, NEIGHBOR_EXSTART);
    break;

  case INM_NEGDONE:
    if (n->state == NEIGHBOR_EXSTART)
    {
      ospf_neigh_chstate(n, NEIGHBOR_EXCHANGE);

      /* Reset DB summary list iterator */
      s_get(&(n->dbsi));
      s_init(&(n->dbsi), &p->lsal);

      /* Add MaxAge LSA entries to retransmission list */
      ospf_add_flushed_to_lsrt(p, n);
    }
    else
      bug("NEGDONE and I'm not in EXSTART?");
    break;

  case INM_EXDONE:
    if (!EMPTY_SLIST(n->lsrql))
      ospf_neigh_chstate(n, NEIGHBOR_LOADING);
    else
      ospf_neigh_chstate(n, NEIGHBOR_FULL);
    break;

  case INM_LOADDONE:
    ospf_neigh_chstate(n, NEIGHBOR_FULL);
    break;

  case INM_ADJOK:
    /* Can In build adjacency? */
    if ((n->state == NEIGHBOR_2WAY) && can_do_adj(n))
    {
      ospf_neigh_chstate(n, NEIGHBOR_EXSTART);
    }
    else if ((n->state >= NEIGHBOR_EXSTART) && !can_do_adj(n))
    {
      reset_lists(p, n);
      ospf_neigh_chstate(n, NEIGHBOR_2WAY);
    }
    break;

  case INM_SEQMIS:
  case INM_BADLSREQ:
    if (n->state >= NEIGHBOR_EXCHANGE)
    {
      reset_lists(p, n);
      ospf_neigh_chstate(n, NEIGHBOR_EXSTART);
    }
    break;

  case INM_KILLNBR:
  case INM_LLDOWN:
  case INM_INACTTIM:
    if (n->gr_active && (event == INM_INACTTIM))
    {
      /* Just down the neighbor, but do not remove it */
      reset_lists(p, n);
      ospf_neigh_chstate(n, NEIGHBOR_DOWN);
      break;
    }

    if (n->gr_active)
      ospf_neigh_stop_graceful_restart_(n);

    /* No need for reset_lists() */
    ospf_neigh_chstate(n, NEIGHBOR_DOWN);
    ospf_neigh_down(n);
    break;

  case INM_1WAYREC:
    reset_lists(p, n);
    ospf_neigh_chstate(n, NEIGHBOR_INIT);
    break;

  default:
    bug("%s: INM - Unknown event?", p->p.name);
    break;
  }
}

static int
can_do_adj(struct ospf_neighbor *n)
{
  struct ospf_iface *ifa = n->ifa;
  struct ospf_proto *p = ifa->oa->po;
  int i = 0;

  switch (ifa->type)
  {
  case OSPF_IT_PTP:
  case OSPF_IT_PTMP:
  case OSPF_IT_VLINK:
    i = 1;
    break;
  case OSPF_IT_BCAST:
  case OSPF_IT_NBMA:
    switch (ifa->state)
    {
    case OSPF_IS_DOWN:
    case OSPF_IS_LOOP:
      bug("%s: Iface %s in down state?", p->p.name, ifa->ifname);
      break;
    case OSPF_IS_WAITING:
      DBG("%s: Neighbor? on iface %s\n", p->p.name, ifa->ifname);
      break;
    case OSPF_IS_DROTHER:
      if (((n->rid == ifa->drid) || (n->rid == ifa->bdrid))
	  && (n->state >= NEIGHBOR_2WAY))
	i = 1;
      break;
    case OSPF_IS_PTP:
    case OSPF_IS_BACKUP:
    case OSPF_IS_DR:
      if (n->state >= NEIGHBOR_2WAY)
	i = 1;
      break;
    default:
      bug("%s: Iface %s in unknown state?", p->p.name, ifa->ifname);
      break;
    }
    break;
  default:
    bug("%s: Iface %s is unknown type?", p->p.name, ifa->ifname);
    break;
  }
  DBG("%s: Iface %s can_do_adj=%d\n", p->p.name, ifa->ifname, i);
  return i;
}

static void
ospf_neigh_start_graceful_restart(struct ospf_neighbor *n, uint gr_time)
{
  struct ospf_proto *p = n->ifa->oa->po;

  OSPF_TRACE(D_EVENTS, "Neighbor %R on %s started graceful restart",
	     n->rid, n->ifa->ifname);

  n->gr_active = 1;
  p->gr_count++;

  n->gr_timer = tm_new_init(n->pool, graceful_restart_timeout, n, 0, 0);
  tm_start(n->gr_timer, gr_time S);
}

static void
ospf_neigh_stop_graceful_restart_(struct ospf_neighbor *n)
{
  struct ospf_proto *p = n->ifa->oa->po;
  struct ospf_iface *ifa = n->ifa;

  n->gr_active = 0;
  p->gr_count--;

  rfree(n->gr_timer);
  n->gr_timer = NULL;

  ospf_notify_rt_lsa(ifa->oa);
  ospf_notify_net_lsa(ifa);

  if (ifa->type == OSPF_IT_VLINK)
    ospf_notify_rt_lsa(ifa->voa);

  ospf_iface_sm(ifa, ISM_NEICH);
}

static void
ospf_neigh_stop_graceful_restart(struct ospf_neighbor *n)
{
  struct ospf_proto *p = n->ifa->oa->po;

  OSPF_TRACE(D_EVENTS, "Neighbor %R on %s finished graceful restart",
	     n->rid, n->ifa->ifname);

  ospf_neigh_stop_graceful_restart_(n);
}

void
ospf_neigh_cancel_graceful_restart(struct ospf_neighbor *n)
{
  struct ospf_proto *p = n->ifa->oa->po;

  OSPF_TRACE(D_EVENTS, "Graceful restart canceled for nbr %R on %s",
	     n->rid, n->ifa->ifname);

  ospf_neigh_stop_graceful_restart_(n);

  if (n->state == NEIGHBOR_DOWN)
    ospf_neigh_down(n);
}

static void
graceful_restart_timeout(timer *t)
{
  struct ospf_neighbor *n = t->data;
  struct ospf_proto *p = n->ifa->oa->po;

  OSPF_TRACE(D_EVENTS, "Graceful restart timer expired for nbr %R on %s",
	     n->rid, n->ifa->ifname);

  ospf_neigh_stop_graceful_restart_(n);

  if (n->state == NEIGHBOR_DOWN)
    ospf_neigh_down(n);
}

static inline int
changes_in_lsrtl(struct ospf_neighbor *n)
{
  /* This could be improved, see RFC 3623 3.1 (2) */

  struct top_hash_entry *en;
  WALK_SLIST(en, n->lsrtl)
    if (LSA_FUNCTION(en->lsa_type) <= LSA_FUNCTION(LSA_T_NSSA))
      return 1;

  return 0;
}

void
ospf_neigh_notify_grace_lsa(struct ospf_neighbor *n, struct top_hash_entry *en)
{
  struct ospf_iface *ifa = n->ifa;
  struct ospf_proto *p = ifa->oa->po;

  /* In OSPFv2, neighbors are identified by either IP or Router ID, based on network type */
  uint t = ifa->type;
  if (ospf_is_v2(p) && ((t == OSPF_IT_BCAST) || (t == OSPF_IT_NBMA) || (t == OSPF_IT_PTMP)))
  {
    struct ospf_tlv *tlv = lsa_get_tlv(en, LSA_GR_ADDRESS);
    if (!tlv || tlv->length != 4)
      return;

    ip_addr addr = ipa_from_u32(tlv->data[0]);
    if (!ipa_equal(n->ip, addr))
      n = find_neigh_by_ip(ifa, addr);
  }
  else
  {
    if (n->rid != en->lsa.rt)
      n = find_neigh(ifa, en->lsa.rt);
  }

  if (!n)
    return;

  if (en->lsa.age < LSA_MAXAGE)
  {
    u32 period = lsa_get_tlv_u32(en, LSA_GR_PERIOD);

    /* Exception for updating grace period */
    if (n->gr_active)
    {
      tm_start(n->gr_timer, (period S) - (en->lsa.age S));
      return;
    }

    /* RFC 3623 3.1 (1) - full adjacency */
    if (n->state != NEIGHBOR_FULL)
      return;

    /* RFC 3623 3.1 (2) - no changes in LSADB */
    if (changes_in_lsrtl(n))
      return;

    /* RFC 3623 3.1 (3) - grace period not expired */
    if (en->lsa.age >= period)
      return;

    /* RFC 3623 3.1 (4) - helper mode allowed */
    if (!p->gr_mode)
      return;

    /* RFC 3623 3.1 (5) - no local graceful restart */
    if (p->p.gr_recovery)
      return;

    ospf_neigh_start_graceful_restart(n, period - en->lsa.age);
  }
  else /* Grace-LSA is flushed */
  {
    if (n->gr_active)
      ospf_neigh_stop_graceful_restart(n);
  }
}

void
ospf_neigh_lsadb_changed_(struct ospf_proto *p, struct top_hash_entry *en)
{
  struct ospf_iface *ifa;
  struct ospf_neighbor *n, *nx;

  if (LSA_FUNCTION(en->lsa_type) > LSA_FUNCTION(LSA_T_NSSA))
    return;

  /* RFC 3623 3.2 (3) - cancel graceful restart when LSdb changed */
  WALK_LIST(ifa, p->iface_list)
    if (lsa_flooding_allowed(en->lsa_type, en->domain, ifa))
      WALK_LIST_DELSAFE(n, nx, ifa->neigh_list)
	if (n->gr_active)
	  ospf_neigh_cancel_graceful_restart(n);
}



static inline u32 neigh_get_id(struct ospf_proto *p, struct ospf_neighbor *n)
{ return ospf_is_v2(p) ? ipa_to_u32(n->ip) : n->rid; }

static struct ospf_neighbor *
elect_bdr(struct ospf_proto *p, list nl)
{
  struct ospf_neighbor *neigh, *n1, *n2;
  u32 nid;

  n1 = NULL;
  n2 = NULL;
  WALK_LIST(neigh, nl)			/* First try those decl. themselves */
  {
    nid = neigh_get_id(p, neigh);

    if (neigh->state >= NEIGHBOR_2WAY)	/* Higher than 2WAY */
      if (neigh->priority > 0)		/* Eligible */
	if (neigh->dr != nid)		/* And not decl. itself DR */
	{
	  if (neigh->bdr == nid)	/* Declaring BDR */
	  {
	    if (n1 != NULL)
	    {
	      if (neigh->priority > n1->priority)
		n1 = neigh;
	      else if (neigh->priority == n1->priority)
		if (neigh->rid > n1->rid)
		  n1 = neigh;
	    }
	    else
	    {
	      n1 = neigh;
	    }
	  }
	  else			/* And NOT declaring BDR */
	  {
	    if (n2 != NULL)
	    {
	      if (neigh->priority > n2->priority)
		n2 = neigh;
	      else if (neigh->priority == n2->priority)
		if (neigh->rid > n2->rid)
		  n2 = neigh;
	    }
	    else
	    {
	      n2 = neigh;
	    }
	  }
	}
  }
  if (n1 == NULL)
    n1 = n2;

  return (n1);
}

static struct ospf_neighbor *
elect_dr(struct ospf_proto *p, list nl)
{
  struct ospf_neighbor *neigh, *n;
  u32 nid;

  n = NULL;
  WALK_LIST(neigh, nl)			/* And now DR */
  {
    nid = neigh_get_id(p, neigh);

    if (neigh->state >= NEIGHBOR_2WAY)	/* Higher than 2WAY */
      if (neigh->priority > 0)		/* Eligible */
	if (neigh->dr == nid)		/* And declaring itself DR */
	{
	  if (n != NULL)
	  {
	    if (neigh->priority > n->priority)
	      n = neigh;
	    else if (neigh->priority == n->priority)
	      if (neigh->rid > n->rid)
		n = neigh;
	  }
	  else
	  {
	    n = neigh;
	  }
	}
  }

  return (n);
}

/**
 * ospf_dr_election - (Backup) Designed Router election
 * @ifa: actual interface
 *
 * When the wait timer fires, it is time to elect (Backup) Designated Router.
 * Structure describing me is added to this list so every electing router has
 * the same list. Backup Designated Router is elected before Designated
 * Router. This process is described in 9.4 of RFC 2328. The function is
 * supposed to be called only from ospf_iface_sm() as a part of the interface
 * state machine.
 */
void
ospf_dr_election(struct ospf_iface *ifa)
{
  struct ospf_proto *p = ifa->oa->po;
  struct ospf_neighbor *neigh, *ndr, *nbdr, me;
  u32 myid = p->router_id;

  DBG("(B)DR election.\n");

  me.state = NEIGHBOR_2WAY;
  me.rid = myid;
  me.priority = ifa->priority;
  me.ip = ifa->addr->ip;

  me.dr  = ospf_is_v2(p) ? ipa_to_u32(ifa->drip) : ifa->drid;
  me.bdr = ospf_is_v2(p) ? ipa_to_u32(ifa->bdrip) : ifa->bdrid;
  me.iface_id = ifa->iface_id;

  add_tail(&ifa->neigh_list, NODE & me);

  nbdr = elect_bdr(p, ifa->neigh_list);
  ndr = elect_dr(p, ifa->neigh_list);

  if (ndr == NULL)
    ndr = nbdr;

  /* 9.4. (4) */
  if (((ifa->drid == myid) && (ndr != &me))
      || ((ifa->drid != myid) && (ndr == &me))
      || ((ifa->bdrid == myid) && (nbdr != &me))
      || ((ifa->bdrid != myid) && (nbdr == &me)))
  {
    me.dr = ndr ? neigh_get_id(p, ndr) : 0;
    me.bdr = nbdr ? neigh_get_id(p, nbdr) : 0;

    nbdr = elect_bdr(p, ifa->neigh_list);
    ndr = elect_dr(p, ifa->neigh_list);

    if (ndr == NULL)
      ndr = nbdr;
  }

  rem_node(NODE & me);


  u32 old_drid = ifa->drid;
  u32 old_bdrid = ifa->bdrid;
  ip_addr none = ospf_is_v2(p) ? IPA_NONE4 : IPA_NONE6;

  ifa->drid = ndr ? ndr->rid : 0;
  ifa->drip = ndr ? ndr->ip  : none;
  ifa->dr_iface_id = ndr ? ndr->iface_id : 0;

  ifa->bdrid = nbdr ? nbdr->rid : 0;
  ifa->bdrip = nbdr ? nbdr->ip  : none;

  DBG("DR=%R, BDR=%R\n", ifa->drid, ifa->bdrid);

  /* We are part of the interface state machine */
  if (ifa->drid == myid)
    ospf_iface_chstate(ifa, OSPF_IS_DR);
  else if (ifa->bdrid == myid)
    ospf_iface_chstate(ifa, OSPF_IS_BACKUP);
  else
    ospf_iface_chstate(ifa, OSPF_IS_DROTHER);

  /* Review neighbor adjacencies if DR or BDR changed */
  if ((ifa->drid != old_drid) || (ifa->bdrid != old_bdrid))
    WALK_LIST(neigh, ifa->neigh_list)
      if (neigh->state >= NEIGHBOR_2WAY)
	ospf_neigh_sm(neigh, INM_ADJOK);

  /* RFC 2328 12.4 Event 3 - DR change */
  if (ifa->drid != old_drid)
    ospf_notify_rt_lsa(ifa->oa);
}

struct ospf_neighbor *
find_neigh(struct ospf_iface *ifa, u32 rid)
{
  struct ospf_neighbor *n;
  WALK_LIST(n, ifa->neigh_list)
    if (n->rid == rid)
      return n;
  return NULL;
}

struct ospf_neighbor *
find_neigh_by_ip(struct ospf_iface *ifa, ip_addr ip)
{
  struct ospf_neighbor *n;
  WALK_LIST(n, ifa->neigh_list)
    if (ipa_equal(n->ip, ip))
      return n;
  return NULL;
}

static void
inactivity_timer_hook(timer * timer)
{
  struct ospf_neighbor *n = (struct ospf_neighbor *) timer->data;
  struct ospf_proto *p = n->ifa->oa->po;

  OSPF_TRACE(D_EVENTS, "Inactivity timer expired for nbr %R on %s",
	     n->rid, n->ifa->ifname);
  ospf_neigh_sm(n, INM_INACTTIM);
}

static void
ospf_neigh_bfd_hook(struct bfd_request *req)
{
  struct ospf_neighbor *n = req->data;
  struct ospf_proto *p = n->ifa->oa->po;

  if (req->down)
  {
    OSPF_TRACE(D_EVENTS, "BFD session down for nbr %R on %s",
	       n->rid, n->ifa->ifname);
    ospf_neigh_sm(n, INM_INACTTIM);
  }
}

void
ospf_neigh_update_bfd(struct ospf_neighbor *n, int use_bfd)
{
  struct ospf_proto *p = n->ifa->oa->po;

  if (use_bfd && !n->bfd_req)
    n->bfd_req = bfd_request_session(n->pool, n->ip, n->ifa->addr->ip,
				     n->ifa->iface, p->p.vrf,
				     ospf_neigh_bfd_hook, n);

  if (!use_bfd && n->bfd_req)
  {
    rfree(n->bfd_req);
    n->bfd_req = NULL;
  }
}


static void
dbdes_timer_hook(timer *t)
{
  struct ospf_neighbor *n = t->data;
  struct ospf_proto *p = n->ifa->oa->po;

  // OSPF_TRACE(D_EVENTS, "DBDES timer expired for nbr %R on %s", n->rid, n->ifa->ifname);

  if (n->state == NEIGHBOR_EXSTART)
    ospf_send_dbdes(p, n);

  if ((n->state == NEIGHBOR_EXCHANGE) && (n->myimms & DBDES_MS))
    ospf_rxmt_dbdes(p, n);

  if ((n->state > NEIGHBOR_LOADING) && !(n->myimms & DBDES_MS))
  {
    ospf_reset_ldd(p, n);
    tm_stop(n->dbdes_timer);
  }
}

static void
lsrq_timer_hook(timer *t)
{
  struct ospf_neighbor *n = t->data;
  struct ospf_proto *p = n->ifa->oa->po;

  // OSPF_TRACE(D_EVENTS, "LSRQ timer expired for nbr %R on %s", n->rid, n->ifa->ifname);

  if ((n->state >= NEIGHBOR_EXCHANGE) && !EMPTY_SLIST(n->lsrql))
    ospf_send_lsreq(p, n);
}

static void
lsrt_timer_hook(timer *t)
{
  struct ospf_neighbor *n = t->data;
  struct ospf_proto *p = n->ifa->oa->po;

  // OSPF_TRACE(D_EVENTS, "LSRT timer expired for nbr %R on %s", n->rid, n->ifa->ifname);

  if ((n->state >= NEIGHBOR_EXCHANGE) && !EMPTY_SLIST(n->lsrtl))
    ospf_rxmt_lsupd(p, n);
}

static void
ackd_timer_hook(timer *t)
{
  struct ospf_neighbor *n = t->data;
  struct ospf_proto *p = n->ifa->oa->po;

  ospf_send_lsack(p, n, ACKL_DELAY);
}


void
ospf_sh_neigh_info(struct ospf_neighbor *n)
{
  struct ospf_iface *ifa = n->ifa;
  char *pos = "PtP  ";

  if ((ifa->type == OSPF_IT_BCAST) || (ifa->type == OSPF_IT_NBMA))
  {
    if (n->rid == ifa->drid)
      pos = "DR   ";
    else if (n->rid == ifa->bdrid)
      pos = "BDR  ";
    else
      pos = "Other";
  }

  cli_msg(-1013, "%-12R\t%3u\t%s/%s\t%6t\t%-10s %I",
	  n->rid, n->priority, ospf_ns_names[n->state], pos,
	  tm_remains(n->inactim), ifa->ifname, n->ip);
}
