/*
 *	BIRD -- OSPF
 *
 *	(c) 1999--2004 Ondrej Filip <feela@network.cz>
 *	(c) 2009--2014 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2009--2014 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Open Shortest Path First (OSPF)
 *
 * The OSPF protocol is quite complicated and its complex implemenation is split
 * to many files. In |ospf.c|, you will find mainly the interface for
 * communication with the core (e.g., reconfiguration hooks, shutdown and
 * initialisation and so on). File |iface.c| contains the interface state
 * machine and functions for allocation and deallocation of OSPF's interface
 * data structures. Source |neighbor.c| includes the neighbor state machine and
 * functions for election of Designated Router and Backup Designated router. In
 * |packet.c|, you will find various functions for sending and receiving generic
 * OSPF packets. There are also routines for authentication and checksumming.
 * In |hello.c|, there are routines for sending and receiving of hello packets
 * as well as functions for maintaining wait times and the inactivity timer.
 * Files |lsreq.c|, |lsack.c|, |dbdes.c| contain functions for sending and
 * receiving of link-state requests, link-state acknowledgements and database
 * descriptions respectively.  In |lsupd.c|, there are functions for sending and
 * receiving of link-state updates and also the flooding algorithm. Source
 * |topology.c| is a place where routines for searching LSAs in the link-state
 * database, adding and deleting them reside, there also are functions for
 * originating of various types of LSAs (router LSA, net LSA, external LSA).
 * File |rt.c| contains routines for calculating the routing table. |lsalib.c|
 * is a set of various functions for working with the LSAs (endianity
 * conversions, calculation of checksum etc.).
 *
 * One instance of the protocol is able to hold LSA databases for multiple OSPF
 * areas, to exchange routing information between multiple neighbors and to
 * calculate the routing tables. The core structure is &ospf_proto to which
 * multiple &ospf_area and &ospf_iface structures are connected. &ospf_proto is
 * also connected to &top_hash_graph which is a dynamic hashing structure that
 * describes the link-state database. It allows fast search, addition and
 * deletion. Each LSA is kept in two pieces: header and body. Both of them are
 * kept in the endianity of the CPU.
 *
 * In OSPFv2 specification, it is implied that there is one IP prefix for each
 * physical network/interface (unless it is an ptp link). But in modern systems,
 * there might be more independent IP prefixes associated with an interface.  To
 * handle this situation, we have one &ospf_iface for each active IP prefix
 * (instead for each active iface); This behaves like virtual interface for the
 * purpose of OSPF.  If we receive packet, we associate it with a proper virtual
 * interface mainly according to its source address.
 *
 * OSPF keeps one socket per &ospf_iface. This allows us (compared to one socket
 * approach) to evade problems with a limit of multicast groups per socket and
 * with sending multicast packets to appropriate interface in a portable way.
 * The socket is associated with underlying physical iface and should not
 * receive packets received on other ifaces (unfortunately, this is not true on
 * BSD). Generally, one packet can be received by more sockets (for example, if
 * there are more &ospf_iface on one physical iface), therefore we explicitly
 * filter received packets according to src/dst IP address and received iface.
 *
 * Vlinks are implemented using particularly degenerate form of &ospf_iface,
 * which has several exceptions: it does not have its iface or socket (it copies
 * these from 'parent' &ospf_iface) and it is present in iface list even when
 * down (it is not freed in ospf_iface_down()).
 *
 * The heart beat of ospf is ospf_disp(). It is called at regular intervals
 * (&ospf_proto->tick). It is responsible for aging and flushing of LSAs in the
 * database, updating topology information in LSAs and for routing table
 * calculation.
 *
 * To every &ospf_iface, we connect one or more &ospf_neighbor's -- a structure
 * containing many timers and queues for building adjacency and for exchange of
 * routing messages.
 *
 * BIRD's OSPF implementation respects RFC2328 in every detail, but some of
 * internal algorithms do differ. The RFC recommends making a snapshot of the
 * link-state database when a new adjacency is forming and sending the database
 * description packets based on the information in this snapshot. The database
 * can be quite large in some networks, so rather we walk through a &slist
 * structure which allows us to continue even if the actual LSA we were working
 * with is deleted. New LSAs are added at the tail of this &slist.
 *
 * We also do not keep a separate OSPF routing table, because the core helps us
 * by being able to recognize when a route is updated to an identical one and it
 * suppresses the update automatically. Due to this, we can flush all the routes
 * we have recalculated and also those we have deleted to the core's routing
 * table and the core will take care of the rest. This simplifies the process
 * and conserves memory.
 *
 * Supported standards:
 * - RFC 2328 - main OSPFv2 standard
 * - RFC 5340 - main OSPFv3 standard
 * - RFC 3101 - OSPFv2 NSSA areas
 * - RFC 3623 - OSPFv2 Graceful Restart
 * - RFC 4576 - OSPFv2 VPN loop prevention
 * - RFC 5187 - OSPFv3 Graceful Restart
 * - RFC 5250 - OSPFv2 Opaque LSAs
 * - RFC 5709 - OSPFv2 HMAC-SHA Cryptographic Authentication
 * - RFC 5838 - OSPFv3 Support of Address Families
 * - RFC 6549 - OSPFv2 Multi-Instance Extensions
 * - RFC 6987 - OSPF Stub Router Advertisement
 * - RFC 7166 - OSPFv3 Authentication Trailer
 * - RFC 7770 - OSPF Router Information LSA
 */

#include <stdlib.h>
#include "ospf.h"

static int ospf_preexport(struct proto *P, rte **new, struct linpool *pool);
static void ospf_make_tmp_attrs(struct rte *rt, struct linpool *pool);
static void ospf_store_tmp_attrs(struct rte *rt, struct linpool *pool);
static void ospf_reload_routes(struct channel *C);
static int ospf_rte_better(struct rte *new, struct rte *old);
static int ospf_rte_same(struct rte *new, struct rte *old);
static void ospf_disp(timer *timer);


static void
add_area_nets(struct ospf_area *oa, struct ospf_area_config *ac)
{
  struct ospf_proto *p = oa->po;
  struct area_net_config *anc;
  struct area_net *an;

  fib_init(&oa->net_fib,  p->p.pool, ospf_get_af(p),
	   sizeof(struct area_net), OFFSETOF(struct area_net, fn), 0, NULL);
  fib_init(&oa->enet_fib, p->p.pool, ospf_get_af(p),
	   sizeof(struct area_net), OFFSETOF(struct area_net, fn), 0, NULL);

  WALK_LIST(anc, ac->net_list)
  {
    an = fib_get(&oa->net_fib, &anc->prefix);
    an->hidden = anc->hidden;
  }

  WALK_LIST(anc, ac->enet_list)
  {
    an = fib_get(&oa->enet_fib, &anc->prefix);
    an->hidden = anc->hidden;
    an->tag = anc->tag;
  }
}

static inline uint
ospf_opts(struct ospf_proto *p)
{
  if (ospf_is_v2(p))
    return OPT_O;

  return ((ospf_is_ip6(p) && !p->af_mc) ? OPT_V6 : 0) |
    (!p->stub_router ? OPT_R : 0) | (p->af_ext ? OPT_AF : 0);
}

static void
ospf_area_add(struct ospf_proto *p, struct ospf_area_config *ac)
{
  struct ospf_area *oa;

  OSPF_TRACE(D_EVENTS, "Adding area %R", ac->areaid);

  oa = mb_allocz(p->p.pool, sizeof(struct ospf_area));
  add_tail(&p->area_list, NODE oa);
  p->areano++;

  oa->ac = ac;
  oa->areaid = ac->areaid;
  oa->rt = NULL;
  oa->po = p;
  fib_init(&oa->rtr, p->p.pool, NET_IP4, sizeof(ort), OFFSETOF(ort, fn), 0, NULL);
  add_area_nets(oa, ac);

  if (oa->areaid == 0)
    p->backbone = oa;

  oa->options = ac->type | ospf_opts(p);

  ospf_notify_rt_lsa(oa);
}

static void
ospf_flush_area(struct ospf_proto *p, u32 areaid)
{
  struct top_hash_entry *en;

  WALK_SLIST(en, p->lsal)
    if ((LSA_SCOPE(en->lsa_type) == LSA_SCOPE_AREA) && (en->domain == areaid))
      ospf_flush_lsa(p, en);
}

static void
ospf_area_remove(struct ospf_area *oa)
{
  struct ospf_proto *p = oa->po;
  OSPF_TRACE(D_EVENTS, "Removing area %R", oa->areaid);

  /* We suppose that interfaces are already removed */
  ospf_flush_area(p, oa->areaid);

  fib_free(&oa->rtr);
  fib_free(&oa->net_fib);
  fib_free(&oa->enet_fib);

  if (oa->translator_timer)
    rfree(oa->translator_timer);

  p->areano--;
  rem_node(NODE oa);
  mb_free(oa);
}

struct ospf_area *
ospf_find_area(struct ospf_proto *p, u32 aid)
{
  struct ospf_area *oa;
  WALK_LIST(oa, p->area_list)
    if (((struct ospf_area *) oa)->areaid == aid)
      return oa;
  return NULL;
}

static struct ospf_iface *
ospf_find_vlink(struct ospf_proto *p, u32 voa, u32 vid)
{
  struct ospf_iface *ifa;
  WALK_LIST(ifa, p->iface_list)
    if ((ifa->type == OSPF_IT_VLINK) && (ifa->voa->areaid == voa) && (ifa->vid == vid))
      return ifa;
  return NULL;
}

static void
ospf_start_gr_recovery(struct ospf_proto *p)
{
  OSPF_TRACE(D_EVENTS, "Graceful restart started");

  p->gr_recovery = 1;
  p->gr_timeout = current_time() + (p->gr_time S);
  channel_graceful_restart_lock(p->p.main_channel);
  p->p.main_channel->gr_wait = 1;

  /* NOTE: We should get end of grace period from non-volatile storage */
}

void
ospf_stop_gr_recovery(struct ospf_proto *p)
{
  p->gr_recovery = 0;
  p->gr_cleanup = 1;
  p->gr_timeout = 0;

  /* Reorigination of router/network LSAs is already scheduled */

  /* Rest is done in ospf_cleanup_gr_recovery() */
}

static void
ospf_cleanup_gr_recovery(struct ospf_proto *p)
{
  struct top_hash_entry *en;

  /* Flush dirty LSAa except external ones, these will be handled by feed */
  WALK_SLIST(en, p->lsal)
    if (en->gr_dirty)
    {
      if ((en->lsa_type == LSA_T_EXT) || (en->lsa_type == LSA_T_NSSA))
	en->mode = LSA_M_EXPORT;
      else
	ospf_flush_lsa(p, en);
    }

  /* End graceful restart on channel, will also schedule feed */
  channel_graceful_restart_unlock(p->p.main_channel);

  p->gr_cleanup = 0;
}

static int
ospf_start(struct proto *P)
{
  struct ospf_proto *p = (struct ospf_proto *) P;
  struct ospf_config *c = (struct ospf_config *) (P->cf);
  struct ospf_area_config *ac;

  p->router_id = proto_get_router_id(P->cf);
  p->ospf2 = c->ospf2;
  p->af_ext = c->af_ext;
  p->af_mc = c->af_mc;
  p->rfc1583 = c->rfc1583;
  p->stub_router = c->stub_router;
  p->merge_external = c->merge_external;
  p->instance_id = c->instance_id;
  p->asbr = c->asbr;
  p->vpn_pe = c->vpn_pe;
  p->ecmp = c->ecmp;
  p->gr_mode = c->gr_mode;
  p->gr_time = c->gr_time;
  p->tick = c->tick;
  p->disp_timer = tm_new_init(P->pool, ospf_disp, p, p->tick S, 0);
  tm_start(p->disp_timer, 100 MS);
  p->lsab_size = 256;
  p->lsab_used = 0;
  p->lsab = mb_alloc(P->pool, p->lsab_size);
  p->nhpool = lp_new(P->pool, 12*sizeof(struct nexthop));
  init_list(&(p->iface_list));
  init_list(&(p->area_list));
  fib_init(&p->rtf, P->pool, ospf_get_af(p), sizeof(ort), OFFSETOF(ort, fn), 0, NULL);
  if (ospf_is_v3(p))
    idm_init(&p->idm, P->pool, 16);
  p->areano = 0;
  p->gr = ospf_top_new(p, P->pool);
  s_init_list(&(p->lsal));

  p->flood_event = ev_new_init(P->pool, ospf_flood_event, p);

  p->log_pkt_tbf = (struct tbf){ .rate = 1, .burst = 5 };
  p->log_lsa_tbf = (struct tbf){ .rate = 4, .burst = 20 };

  /* Lock the channel when in GR recovery mode */
  if (p->p.gr_recovery && (p->gr_mode == OSPF_GR_ABLE))
    ospf_start_gr_recovery(p);

  WALK_LIST(ac, c->area_list)
    ospf_area_add(p, ac);

  if (c->abr)
    ospf_open_vlink_sk(p);

  /* Add all virtual links */
  struct ospf_iface_patt *ic;
  WALK_LIST(ic, c->vlink_list)
    ospf_iface_new_vlink(p, ic);

  return PS_UP;
}

static void
ospf_dump(struct proto *P)
{
  struct ospf_proto *p = (struct ospf_proto *) P;
  struct ospf_iface *ifa;
  struct ospf_neighbor *n;

  OSPF_TRACE(D_EVENTS, "Area number: %d", p->areano);

  WALK_LIST(ifa, p->iface_list)
  {
    OSPF_TRACE(D_EVENTS, "Interface: %s", ifa->ifname);
    OSPF_TRACE(D_EVENTS, "state: %u", ifa->state);
    OSPF_TRACE(D_EVENTS, "DR:  %R", ifa->drid);
    OSPF_TRACE(D_EVENTS, "BDR: %R", ifa->bdrid);
    WALK_LIST(n, ifa->neigh_list)
    {
      OSPF_TRACE(D_EVENTS, "  neighbor %R in state %u", n->rid, n->state);
    }
  }

  /*
  OSPF_TRACE(D_EVENTS, "LSA graph dump start:");
  ospf_top_dump(p->gr, p);
  OSPF_TRACE(D_EVENTS, "LSA graph dump finished");
  */
  neigh_dump_all();
}

static struct proto *
ospf_init(struct proto_config *CF)
{
  struct ospf_config *cf = (struct ospf_config *) CF;
  struct proto *P = proto_new(CF);

  P->main_channel = proto_add_channel(P, proto_cf_main_channel(CF));

  P->rt_notify = ospf_rt_notify;
  P->if_notify = ospf_if_notify;
  P->ifa_notify = cf->ospf2 ? ospf_ifa_notify2 : ospf_ifa_notify3;
  P->preexport = ospf_preexport;
  P->reload_routes = ospf_reload_routes;
  P->feed_begin = ospf_feed_begin;
  P->feed_end = ospf_feed_end;
  P->make_tmp_attrs = ospf_make_tmp_attrs;
  P->store_tmp_attrs = ospf_store_tmp_attrs;
  P->rte_better = ospf_rte_better;
  P->rte_same = ospf_rte_same;

  return P;
}

/* If new is better return 1 */
static int
ospf_rte_better(struct rte *new, struct rte *old)
{
  if (new->u.ospf.metric1 == LSINFINITY)
    return 0;

  if(new->attrs->source < old->attrs->source) return 1;
  if(new->attrs->source > old->attrs->source) return 0;

  if(new->attrs->source == RTS_OSPF_EXT2)
  {
    if(new->u.ospf.metric2 < old->u.ospf.metric2) return 1;
    if(new->u.ospf.metric2 > old->u.ospf.metric2) return 0;
  }

  if (new->u.ospf.metric1 < old->u.ospf.metric1)
    return 1;

  return 0;			/* Old is shorter or same */
}

static int
ospf_rte_same(struct rte *new, struct rte *old)
{
  /* new->attrs == old->attrs always */
  return
    new->u.ospf.metric1 == old->u.ospf.metric1 &&
    new->u.ospf.metric2 == old->u.ospf.metric2 &&
    new->u.ospf.tag == old->u.ospf.tag &&
    new->u.ospf.router_id == old->u.ospf.router_id;
}


void
ospf_schedule_rtcalc(struct ospf_proto *p)
{
  if (p->calcrt)
    return;

  OSPF_TRACE(D_EVENTS, "Scheduling routing table calculation");
  p->calcrt = 1;
}

static void
ospf_reload_routes(struct channel *C)
{
  struct ospf_proto *p = (struct ospf_proto *) C->proto;

  if (p->calcrt == 2)
    return;

  OSPF_TRACE(D_EVENTS, "Scheduling routing table calculation with route reload");
  p->calcrt = 2;
}


/**
 * ospf_disp - invokes routing table calculation, aging and also area_disp()
 * @timer: timer usually called every @ospf_proto->tick second, @timer->data
 * point to @ospf_proto
 */
static void
ospf_disp(timer * timer)
{
  struct ospf_proto *p = timer->data;

  /* Check for end of graceful restart */
  if (p->gr_recovery)
    ospf_update_gr_recovery(p);

  /* Originate or flush local topology LSAs */
  ospf_update_topology(p);

  /* Process LSA DB */
  ospf_update_lsadb(p);

  /* Calculate routing table */
  if (p->calcrt)
    ospf_rt_spf(p);

  /* Cleanup after graceful restart */
  if (p->gr_cleanup)
    ospf_cleanup_gr_recovery(p);
}


/**
 * ospf_preexport - accept or reject new route from nest's routing table
 * @P: OSPF protocol instance
 * @new: the new route
 * @attrs: list of attributes
 * @pool: pool for allocation of attributes
 *
 * Its quite simple. It does not accept our own routes and leaves the decision on
 * import to the filters.
 */
static int
ospf_preexport(struct proto *P, rte **new, struct linpool *pool UNUSED)
{
  struct ospf_proto *p = (struct ospf_proto *) P;
  struct ospf_area *oa = ospf_main_area(p);
  rte *e = *new;

  /* Reject our own routes */
  if (e->attrs->src->proto == P)
    return -1;

  /* Do not export routes to stub areas */
  if (oa_is_stub(oa))
    return -1;

  return 0;
}

static void
ospf_make_tmp_attrs(struct rte *rt, struct linpool *pool)
{
  rte_init_tmp_attrs(rt, pool, 4);
  rte_make_tmp_attr(rt, EA_OSPF_METRIC1, EAF_TYPE_INT, rt->u.ospf.metric1);
  rte_make_tmp_attr(rt, EA_OSPF_METRIC2, EAF_TYPE_INT, rt->u.ospf.metric2);
  rte_make_tmp_attr(rt, EA_OSPF_TAG, EAF_TYPE_INT, rt->u.ospf.tag);
  rte_make_tmp_attr(rt, EA_OSPF_ROUTER_ID, EAF_TYPE_ROUTER_ID, rt->u.ospf.router_id);
}

static void
ospf_store_tmp_attrs(struct rte *rt, struct linpool *pool)
{
  rte_init_tmp_attrs(rt, pool, 4);
  rt->u.ospf.metric1 = rte_store_tmp_attr(rt, EA_OSPF_METRIC1);
  rt->u.ospf.metric2 = rte_store_tmp_attr(rt, EA_OSPF_METRIC2);
  rt->u.ospf.tag = rte_store_tmp_attr(rt, EA_OSPF_TAG);
  rt->u.ospf.router_id = rte_store_tmp_attr(rt, EA_OSPF_ROUTER_ID);
}

/**
 * ospf_shutdown - Finish of OSPF instance
 * @P: OSPF protocol instance
 *
 * RFC does not define any action that should be taken before router
 * shutdown. To make my neighbors react as fast as possible, I send
 * them hello packet with empty neighbor list. They should start
 * their neighbor state machine with event %NEIGHBOR_1WAY.
 */
static int
ospf_shutdown(struct proto *P)
{
  struct ospf_proto *p = (struct ospf_proto *) P;
  struct ospf_iface *ifa;

  OSPF_TRACE(D_EVENTS, "Shutdown requested");

  if ((P->down_code == PDC_CMD_GR_DOWN) && (p->gr_mode == OSPF_GR_ABLE))
  {
    /* Originate Grace LSAs */
    WALK_LIST(ifa, p->iface_list)
      ospf_originate_gr_lsa(p, ifa);
  }
  else
  {
    /* Send to all my neighbors 1WAY */
    WALK_LIST(ifa, p->iface_list)
      ospf_iface_shutdown(ifa);
  }

  /* Cleanup locked rta entries */
  FIB_WALK(&p->rtf, ort, nf)
  {
    rta_free(nf->old_rta);
  }
  FIB_WALK_END;

  return PS_DOWN;
}

static void
ospf_get_status(struct proto *P, byte * buf)
{
  struct ospf_proto *p = (struct ospf_proto *) P;

  if (p->p.proto_state == PS_DOWN)
    buf[0] = 0;
  else
  {
    struct ospf_iface *ifa;
    struct ospf_neighbor *n;
    int adj = 0;

    WALK_LIST(ifa, p->iface_list)
      WALK_LIST(n, ifa->neigh_list) if (n->state == NEIGHBOR_FULL)
      adj = 1;

    if (adj == 0)
      strcpy(buf, "Alone");
    else
      strcpy(buf, "Running");
  }
}

static void
ospf_get_route_info(rte * rte, byte * buf)
{
  char *type = "<bug>";

  switch (rte->attrs->source)
  {
  case RTS_OSPF:
    type = "I";
    break;
  case RTS_OSPF_IA:
    type = "IA";
    break;
  case RTS_OSPF_EXT1:
    type = "E1";
    break;
  case RTS_OSPF_EXT2:
    type = "E2";
    break;
  }

  buf += bsprintf(buf, " %s", type);
  buf += bsprintf(buf, " (%d/%d", rte->pref, rte->u.ospf.metric1);
  if (rte->attrs->source == RTS_OSPF_EXT2)
    buf += bsprintf(buf, "/%d", rte->u.ospf.metric2);
  buf += bsprintf(buf, ")");
  if ((rte->attrs->source == RTS_OSPF_EXT1 || rte->attrs->source == RTS_OSPF_EXT2) && rte->u.ospf.tag)
  {
    buf += bsprintf(buf, " [%x]", rte->u.ospf.tag);
  }
  if (rte->u.ospf.router_id)
    buf += bsprintf(buf, " [%R]", rte->u.ospf.router_id);
}

static int
ospf_get_attr(const eattr * a, byte * buf, int buflen UNUSED)
{
  switch (a->id)
  {
  case EA_OSPF_METRIC1:
    bsprintf(buf, "metric1");
    return GA_NAME;
  case EA_OSPF_METRIC2:
    bsprintf(buf, "metric2");
    return GA_NAME;
  case EA_OSPF_TAG:
    bsprintf(buf, "tag: 0x%08x", a->u.data);
    return GA_FULL;
  case EA_OSPF_ROUTER_ID:
    bsprintf(buf, "router_id");
    return GA_NAME;
  default:
    return GA_UNKNOWN;
  }
}

static void
ospf_area_reconfigure(struct ospf_area *oa, struct ospf_area_config *nac)
{
  struct ospf_proto *p = oa->po;
  struct ospf_area_config *oac = oa->ac;
  struct ospf_iface *ifa, *ifx;

  oa->ac = nac;
  oa->options = nac->type | ospf_opts(p);

  if (nac->type != oac->type)
  {
    log(L_INFO "%s: Restarting area %R", p->p.name, oa->areaid);

    /* Remove area interfaces, will be re-added later */
    WALK_LIST_DELSAFE(ifa, ifx, p->iface_list)
      if (ifa->oa == oa)
      {
	ospf_iface_shutdown(ifa);
	ospf_iface_remove(ifa);
      }

    /* Flush area LSAs */
    ospf_flush_area(p, oa->areaid);
  }

  /* Handle net_list */
  fib_free(&oa->net_fib);
  fib_free(&oa->enet_fib);
  add_area_nets(oa, nac);

  /* No need to handle stubnet_list */

  oa->marked = 0;
  ospf_notify_rt_lsa(oa);
}

/**
 * ospf_reconfigure - reconfiguration hook
 * @P: current instance of protocol (with old configuration)
 * @c: new configuration requested by user
 *
 * This hook tries to be a little bit intelligent. Instance of OSPF
 * will survive change of many constants like hello interval,
 * password change, addition or deletion of some neighbor on
 * nonbroadcast network, cost of interface, etc.
 */
static int
ospf_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct ospf_proto *p = (struct ospf_proto *) P;
  struct ospf_config *old = (struct ospf_config *) (P->cf);
  struct ospf_config *new = (struct ospf_config *) CF;
  struct ospf_area_config *oac, *nac;
  struct ospf_area *oa, *oax;
  struct ospf_iface *ifa, *ifx;
  struct ospf_iface_patt *ip;

  if (proto_get_router_id(CF) != p->router_id)
    return 0;

  if (p->ospf2 != new->ospf2)
    return 0;

  if (p->rfc1583 != new->rfc1583)
    return 0;

  if (p->instance_id != new->instance_id)
    return 0;

  if (old->abr != new->abr)
    return 0;

  if (p->areano == 1)
  {
    oac = HEAD(old->area_list);
    nac = HEAD(new->area_list);

    if (oac->type != nac->type)
      return 0;
  }

  if (old->vpn_pe != new->vpn_pe)
    return 0;

  if ((p->af_ext != new->af_ext) || (p->af_mc != new->af_mc))
    return 0;

  if (!proto_configure_channel(P, &P->main_channel, proto_cf_main_channel(CF)))
    return 0;

  p->stub_router = new->stub_router;
  p->merge_external = new->merge_external;
  p->asbr = new->asbr;
  p->ecmp = new->ecmp;
  p->gr_mode = new->gr_mode;
  p->gr_time = new->gr_time;
  p->tick = new->tick;
  p->disp_timer->recurrent = p->tick S;
  tm_start(p->disp_timer, 10 MS);

  /* Mark all areas and ifaces */
  WALK_LIST(oa, p->area_list)
    oa->marked = 1;

  WALK_LIST(ifa, p->iface_list)
    ifa->marked = 1;

  /* Add and update areas */
  WALK_LIST(nac, new->area_list)
  {
    oa = ospf_find_area(p, nac->areaid);
    if (oa)
      ospf_area_reconfigure(oa, nac);
    else
      ospf_area_add(p, nac);
  }

  /* Add and update interfaces */
  ospf_reconfigure_ifaces(p);

  /* Add and update vlinks */
  WALK_LIST(ip, new->vlink_list)
  {
    ifa = ospf_find_vlink(p, ip->voa, ip->vid);
    if (ifa)
      ospf_iface_reconfigure(ifa, ip);
    else
      ospf_iface_new_vlink(p, ip);
  }

  /* Delete remaining ifaces and areas */
  WALK_LIST_DELSAFE(ifa, ifx, p->iface_list)
    if (ifa->marked)
    {
      ospf_iface_shutdown(ifa);
      ospf_iface_remove(ifa);
    }

  WALK_LIST_DELSAFE(oa, oax, p->area_list)
    if (oa->marked)
      ospf_area_remove(oa);

  ospf_schedule_rtcalc(p);

  return 1;
}


void
ospf_sh_neigh(struct proto *P, const char *iff)
{
  struct ospf_proto *p = (struct ospf_proto *) P;
  struct ospf_iface *ifa = NULL;
  struct ospf_neighbor *n;

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1013, "%s: is not up", p->p.name);
    return;
  }

  cli_msg(-1013, "%s:", p->p.name);
  cli_msg(-1013, "%-12s\t%3s\t%-15s\t%-5s\t%-10s %s", "Router ID", "Pri",
	  "     State", "DTime", "Interface", "Router IP");
  WALK_LIST(ifa, p->iface_list)
    if ((iff == NULL) || patmatch(iff, ifa->ifname))
      WALK_LIST(n, ifa->neigh_list)
	ospf_sh_neigh_info(n);
}

void
ospf_sh(struct proto *P)
{
  struct ospf_proto *p = (struct ospf_proto *) P;
  struct ospf_area *oa;
  struct ospf_iface *ifa;
  struct ospf_neighbor *n;
  int ifano, nno, adjno, firstfib;

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1014, "%s: is not up", p->p.name);
    return;
  }

  cli_msg(-1014, "%s:", p->p.name);
  cli_msg(-1014, "RFC1583 compatibility: %s", (p->rfc1583 ? "enabled" : "disabled"));
  cli_msg(-1014, "Stub router: %s", (p->stub_router ? "Yes" : "No"));
  cli_msg(-1014, "RT scheduler tick: %d", p->tick);
  cli_msg(-1014, "Number of areas: %u", p->areano);
  cli_msg(-1014, "Number of LSAs in DB:\t%u", p->gr->hash_entries);

  WALK_LIST(oa, p->area_list)
  {
    cli_msg(-1014, "\tArea: %R (%u) %s", oa->areaid, oa->areaid,
	    oa->areaid == 0 ? "[BACKBONE]" : "");
    ifano = 0;
    nno = 0;
    adjno = 0;
    WALK_LIST(ifa, p->iface_list)
    {
      if (oa == ifa->oa)
      {
	ifano++;
	WALK_LIST(n, ifa->neigh_list)
	{
	  nno++;
	  if (n->state == NEIGHBOR_FULL)
	    adjno++;
	}
      }
    }

    cli_msg(-1014, "\t\tStub:\t%s", oa_is_stub(oa) ? "Yes" : "No");
    cli_msg(-1014, "\t\tNSSA:\t%s", oa_is_nssa(oa) ? "Yes" : "No");
    cli_msg(-1014, "\t\tTransit:\t%s", oa->trcap ? "Yes" : "No");

    if (oa_is_nssa(oa))
      cli_msg(-1014, "\t\tNSSA translation:\t%s%s", oa->translate ? "Yes" : "No",
	      oa->translate == TRANS_WAIT ? " (run down)" : "");
    cli_msg(-1014, "\t\tNumber of interfaces:\t%u", ifano);
    cli_msg(-1014, "\t\tNumber of neighbors:\t%u", nno);
    cli_msg(-1014, "\t\tNumber of adjacent neighbors:\t%u", adjno);

    firstfib = 1;
    FIB_WALK(&oa->net_fib, struct area_net, anet)
    {
      if(firstfib)
      {
	cli_msg(-1014, "\t\tArea networks:");
	firstfib = 0;
      }
      cli_msg(-1014, "\t\t\t%1N\t%s\t%s", anet->fn.addr,
		anet->hidden ? "Hidden" : "Advertise", anet->active ? "Active" : "");
    }
    FIB_WALK_END;

    firstfib = 1;
    FIB_WALK(&oa->enet_fib, struct area_net, anet)
    {
      if(firstfib)
      {
	cli_msg(-1014, "\t\tArea external networks:");
	firstfib = 0;
      }
      cli_msg(-1014, "\t\t\t%1N\t%s\t%s", anet->fn.addr,
		anet->hidden ? "Hidden" : "Advertise", anet->active ? "Active" : "");
    }
    FIB_WALK_END;

  }
}

void
ospf_sh_iface(struct proto *P, const char *iff)
{
  struct ospf_proto *p = (struct ospf_proto *) P;
  struct ospf_iface *ifa = NULL;

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1015, "%s: is not up", p->p.name);
    return;
  }

  cli_msg(-1015, "%s:", p->p.name);
  WALK_LIST(ifa, p->iface_list)
    if ((iff == NULL) || patmatch(iff, ifa->ifname))
      ospf_iface_info(ifa);
}

/* lsa_compare_for_state() - Compare function for 'show ospf state'
 *
 * First we want to separate network-LSAs and other LSAs (because network-LSAs
 * will be presented as network nodes and other LSAs together as router nodes)
 * Network-LSAs are sorted according to network prefix, other LSAs are sorted
 * according to originating router id (to get all LSA needed to represent one
 * router node together). Then, according to LSA type, ID and age.
 *
 * For OSPFv3, we have to handle also Prefix-LSAs. We would like to put each
 * immediately after the referenced LSA. We will make faked LSA based on ref_
 * values
 */

static struct ospf_lsa_header *
fake_lsa_from_prefix_lsa(struct ospf_lsa_header *dst, struct ospf_lsa_header *src,
			 struct ospf_lsa_prefix *px)
{
  dst->age = src->age;
  dst->type_raw = px->ref_type;
  dst->id = px->ref_id;
  dst->rt = px->ref_rt;
  dst->sn = src->sn;

  return dst;
}


static int lsa_compare_ospf3;

static int
lsa_compare_for_state(const void *p1, const void *p2)
{
  struct top_hash_entry *he1 = * (struct top_hash_entry **) p1;
  struct top_hash_entry *he2 = * (struct top_hash_entry **) p2;
  struct ospf_lsa_header *lsa1 = &(he1->lsa);
  struct ospf_lsa_header *lsa2 = &(he2->lsa);
  struct ospf_lsa_header lsatmp1, lsatmp2;
  u16 lsa1_type = he1->lsa_type;
  u16 lsa2_type = he2->lsa_type;

  if (he1->domain < he2->domain)
    return -1;
  if (he1->domain > he2->domain)
    return 1;


  /* px1 or px2 assumes OSPFv3 */
  int px1 = (lsa1_type == LSA_T_PREFIX);
  int px2 = (lsa2_type == LSA_T_PREFIX);

  if (px1)
  {
    lsa1 = fake_lsa_from_prefix_lsa(&lsatmp1, lsa1, he1->lsa_body);
    lsa1_type = lsa1->type_raw;	/* FIXME: handle unknown ref_type */
  }

  if (px2)
  {
    lsa2 = fake_lsa_from_prefix_lsa(&lsatmp2, lsa2, he2->lsa_body);
    lsa2_type = lsa2->type_raw;
  }


  int nt1 = (lsa1_type == LSA_T_NET);
  int nt2 = (lsa2_type == LSA_T_NET);

  if (nt1 != nt2)
    return nt1 - nt2;

  if (nt1)
  {
    /* In OSPFv3, networks are named based on ID of DR */
    if (lsa_compare_ospf3)
    {
      if (lsa1->rt < lsa2->rt)
	return -1;
      if (lsa1->rt > lsa2->rt)
	return 1;
    }

    /* For OSPFv2, this is IP of the network,
       for OSPFv3, this is interface ID */
    if (lsa1->id < lsa2->id)
      return -1;
    if (lsa1->id > lsa2->id)
      return 1;

    if (px1 != px2)
      return px1 - px2;

    return lsa1->sn - lsa2->sn;
  }
  else
  {
    if (lsa1->rt < lsa2->rt)
      return -1;
    if (lsa1->rt > lsa2->rt)
      return 1;

    if (lsa1_type < lsa2_type)
      return -1;
    if (lsa1_type > lsa2_type)
      return 1;

    if (lsa1->id < lsa2->id)
      return -1;
    if (lsa1->id > lsa2->id)
      return 1;

    if (px1 != px2)
      return px1 - px2;

    return lsa1->sn - lsa2->sn;
  }
}

static int
ext_compare_for_state(const void *p1, const void *p2)
{
  struct top_hash_entry * he1 = * (struct top_hash_entry **) p1;
  struct top_hash_entry * he2 = * (struct top_hash_entry **) p2;
  struct ospf_lsa_header *lsa1 = &(he1->lsa);
  struct ospf_lsa_header *lsa2 = &(he2->lsa);

  if (lsa1->rt < lsa2->rt)
    return -1;
  if (lsa1->rt > lsa2->rt)
    return 1;

  if (lsa1->id < lsa2->id)
    return -1;
  if (lsa1->id > lsa2->id)
    return 1;

  return lsa1->sn - lsa2->sn;
}

static inline void
show_lsa_distance(struct top_hash_entry *he)
{
  if (he->color == INSPF)
    cli_msg(-1016, "\t\tdistance %u", he->dist);
  else
    cli_msg(-1016, "\t\tunreachable");
}

static inline void
show_lsa_router(struct ospf_proto *p, struct top_hash_entry *he, int verbose)
{
  struct ospf_lsa_rt_walk rtl;

  cli_msg(-1016, "");
  cli_msg(-1016, "\trouter %R", he->lsa.rt);
  show_lsa_distance(he);

  lsa_walk_rt_init(p, he, &rtl);
  while (lsa_walk_rt(&rtl))
    if (rtl.type == LSART_VLNK)
      cli_msg(-1016, "\t\tvlink %R metric %u", rtl.id, rtl.metric);

  lsa_walk_rt_init(p, he, &rtl);
  while (lsa_walk_rt(&rtl))
    if (rtl.type == LSART_PTP)
      cli_msg(-1016, "\t\trouter %R metric %u", rtl.id, rtl.metric);

  lsa_walk_rt_init(p, he, &rtl);
  while (lsa_walk_rt(&rtl))
    if (rtl.type == LSART_NET)
    {
      if (ospf_is_v2(p))
      {
	/* In OSPFv2, we try to find network-LSA to get prefix/pxlen */
	struct top_hash_entry *net_he = ospf_hash_find_net2(p->gr, he->domain, rtl.id);

	if (net_he && (net_he->lsa.age < LSA_MAXAGE))
	{
	  struct ospf_lsa_header *net_lsa = &(net_he->lsa);
	  struct ospf_lsa_net *net_ln = net_he->lsa_body;

	  cli_msg(-1016, "\t\tnetwork %I/%d metric %u",
		  ipa_from_u32(net_lsa->id & net_ln->optx),
		  u32_masklen(net_ln->optx), rtl.metric);
	}
	else
	  cli_msg(-1016, "\t\tnetwork [%R] metric %u", rtl.id, rtl.metric);
      }
      else
	cli_msg(-1016, "\t\tnetwork [%R-%u] metric %u", rtl.id, rtl.nif, rtl.metric);
    }

  if (ospf_is_v2(p) && verbose)
  {
    lsa_walk_rt_init(p, he, &rtl);
    while (lsa_walk_rt(&rtl))
      if (rtl.type == LSART_STUB)
	cli_msg(-1016, "\t\tstubnet %I/%d metric %u",
		ipa_from_u32(rtl.id), u32_masklen(rtl.data), rtl.metric);
  }
}

static inline void
show_lsa_network(struct top_hash_entry *he, int ospf2)
{
  struct ospf_lsa_header *lsa = &(he->lsa);
  struct ospf_lsa_net *ln = he->lsa_body;
  u32 i;

  if (ospf2)
  {
    cli_msg(-1016, "");
    cli_msg(-1016, "\tnetwork %I/%d", ipa_from_u32(lsa->id & ln->optx), u32_masklen(ln->optx));
    cli_msg(-1016, "\t\tdr %R", lsa->rt);
  }
  else
  {
    cli_msg(-1016, "");
    cli_msg(-1016, "\tnetwork [%R-%u]", lsa->rt, lsa->id);
  }

  show_lsa_distance(he);

  for (i = 0; i < lsa_net_count(lsa); i++)
    cli_msg(-1016, "\t\trouter %R", ln->routers[i]);
}

static inline void
show_lsa_sum_net(struct top_hash_entry *he, int ospf2, int af)
{
  net_addr net;
  u8 pxopts;
  u32 metric;

  lsa_parse_sum_net(he, ospf2, af, &net, &pxopts, &metric);
  cli_msg(-1016, "\t\txnetwork %N metric %u", &net, metric);
}

static inline void
show_lsa_sum_rt(struct top_hash_entry *he, int ospf2)
{
  u32 metric;
  u32 dst_rid;
  u32 options;

  lsa_parse_sum_rt(he, ospf2, &dst_rid, &metric, &options);
  cli_msg(-1016, "\t\txrouter %R metric %u", dst_rid, metric);
}


static inline void
show_lsa_external(struct top_hash_entry *he, int ospf2, int af)
{
  struct ospf_lsa_ext_local rt;
  char str_via[IPA_MAX_TEXT_LENGTH + 8] = "";
  char str_tag[16] = "";

  if (he->lsa_type == LSA_T_EXT)
    he->domain = 0; /* Unmark the LSA */

  lsa_parse_ext(he, ospf2, af, &rt);

  if (rt.fbit)
    bsprintf(str_via, " via %I", rt.fwaddr);

  if (rt.tag)
    bsprintf(str_tag, " tag %08x", rt.tag);

  cli_msg(-1016, "\t\t%s %N metric%s %u%s%s",
	  (he->lsa_type == LSA_T_NSSA) ? "nssa-ext" : "external",
	  &rt.net, rt.ebit ? "2" : "", rt.metric, str_via, str_tag);
}

static inline void
show_lsa_prefix(struct top_hash_entry *he, struct top_hash_entry *cnode, int af)
{
  struct ospf_lsa_prefix *px = he->lsa_body;
  u32 *buf;
  int i;

  /* We check whether given prefix-LSA is related to the current node */
  if ((px->ref_type != cnode->lsa.type_raw) || (px->ref_rt != cnode->lsa.rt))
    return;

  if ((px->ref_type == LSA_T_RT) && (px->ref_id != 0))
    return;

  if ((px->ref_type == LSA_T_NET) && (px->ref_id != cnode->lsa.id))
    return;

  buf = px->rest;
  for (i = 0; i < px->pxcount; i++)
  {
    net_addr net;
    u8 pxopts;
    u16 metric;

    buf = ospf3_get_prefix(buf, af, &net, &pxopts, &metric);

    if (px->ref_type == LSA_T_RT)
      cli_msg(-1016, "\t\tstubnet %N metric %u", &net, metric);
    else
      cli_msg(-1016, "\t\taddress %N", &net);
  }
}

void
ospf_sh_state(struct proto *P, int verbose, int reachable)
{
  struct ospf_proto *p = (struct ospf_proto *) P;
  int ospf2 = ospf_is_v2(p);
  int af = ospf_get_af(p);
  uint i, ix, j1, jx;
  u32 last_area = 0xFFFFFFFF;

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1016, "%s: is not up", p->p.name);
    cli_msg(0, "");
    return;
  }

  /* We store interesting area-scoped LSAs in array hea and
     global-scoped (LSA_T_EXT) LSAs in array hex */

  uint num = p->gr->hash_entries;
  struct top_hash_entry *hea[num];
  struct top_hash_entry **hex = verbose ? alloca(num * sizeof(struct top_hash_entry *)) : NULL;
  struct top_hash_entry *he;
  struct top_hash_entry *cnode = NULL;

  j1 = jx = 0;
  WALK_SLIST(he, p->lsal)
  {
    int accept;

    if (he->lsa.age == LSA_MAXAGE)
      continue;

    switch (he->lsa_type)
    {
    case LSA_T_RT:
    case LSA_T_NET:
      accept = 1;
      break;

    case LSA_T_SUM_NET:
    case LSA_T_SUM_RT:
    case LSA_T_NSSA:
    case LSA_T_PREFIX:
      accept = verbose;
      break;

    case LSA_T_EXT:
      if (verbose)
      {
	he->domain = 1; /* Abuse domain field to mark the LSA */
	hex[jx++] = he;
      }
      /* fallthrough */
    default:
      accept = 0;
    }

    if (accept)
      hea[j1++] = he;
  }

  ASSERT(j1 <= num && jx <= num);

  lsa_compare_ospf3 = !ospf2;
  qsort(hea, j1, sizeof(struct top_hash_entry *), lsa_compare_for_state);

  if (verbose)
    qsort(hex, jx, sizeof(struct top_hash_entry *), ext_compare_for_state);

  /*
   * This code is a bit tricky, we have a primary LSAs (router and
   * network) that are presented as a node, and secondary LSAs that
   * are presented as a part of a primary node. cnode represents an
   * currently opened node (whose header was presented). The LSAs are
   * sorted to get secondary LSAs just after related primary LSA (if
   * available). We present secondary LSAs only when related primary
   * LSA is opened.
   *
   * AS-external LSAs are stored separately as they might be presented
   * several times (for each area when related ASBR is opened). When
   * the node is closed, related external routes are presented. We
   * also have to take into account that in OSPFv3, there might be
   * more router-LSAs and only the first should be considered as a
   * primary. This is handled by not closing old router-LSA when next
   * one is processed (which is not opened because there is already
   * one opened).
   */

  ix = 0;
  for (i = 0; i < j1; i++)
  {
    he = hea[i];

    /* If there is no opened node, we open the LSA (if appropriate) or skip to the next one */
    if (!cnode)
    {
      if (((he->lsa_type == LSA_T_RT) || (he->lsa_type == LSA_T_NET))
	  && ((he->color == INSPF) || !reachable))
      {
	cnode = he;

	if (he->domain != last_area)
	{
	  cli_msg(-1016, "");
	  cli_msg(-1016, "area %R", he->domain);
	  last_area = he->domain;
	  ix = 0;
	}
      }
      else
	continue;
    }

    ASSERT(cnode && (he->domain == last_area) && (he->lsa.rt == cnode->lsa.rt));

    switch (he->lsa_type)
    {
    case LSA_T_RT:
      if (he->lsa.id == cnode->lsa.id)
	show_lsa_router(p, he, verbose);
      break;

    case LSA_T_NET:
      show_lsa_network(he, ospf2);
      break;

    case LSA_T_SUM_NET:
      if (cnode->lsa_type == LSA_T_RT)
	show_lsa_sum_net(he, ospf2, af);
      break;

    case LSA_T_SUM_RT:
      if (cnode->lsa_type == LSA_T_RT)
	show_lsa_sum_rt(he, ospf2);
      break;

    case LSA_T_EXT:
    case LSA_T_NSSA:
      show_lsa_external(he, ospf2, af);
      break;

    case LSA_T_PREFIX:
      show_lsa_prefix(he, cnode, af);
      break;
    }

    /* In these cases, we close the current node */
    if ((i+1 == j1)
	|| (hea[i+1]->domain != last_area)
	|| (hea[i+1]->lsa.rt != cnode->lsa.rt)
	|| (hea[i+1]->lsa_type == LSA_T_NET))
    {
      while ((ix < jx) && (hex[ix]->lsa.rt < cnode->lsa.rt))
	ix++;

      while ((ix < jx) && (hex[ix]->lsa.rt == cnode->lsa.rt))
	show_lsa_external(hex[ix++], ospf2, af);

      cnode = NULL;
    }
  }

  int hdr = 0;
  u32 last_rt = 0xFFFFFFFF;
  for (ix = 0; ix < jx; ix++)
  {
    he = hex[ix];

    /* If it is still marked, we show it now. */
    if (he->domain)
    {
      he->domain = 0;

      if ((he->color != INSPF) && reachable)
	continue;

      if (!hdr)
      {
	cli_msg(-1016, "");
	cli_msg(-1016, "other ASBRs");
	hdr = 1;
      }

      if (he->lsa.rt != last_rt)
      {
	cli_msg(-1016, "");
	cli_msg(-1016, "\trouter %R", he->lsa.rt);
	last_rt = he->lsa.rt;
      }

      show_lsa_external(he, ospf2, af);
    }
  }

  cli_msg(0, "");
}


static int
lsa_compare_for_lsadb(const void *p1, const void *p2)
{
  struct top_hash_entry * he1 = * (struct top_hash_entry **) p1;
  struct top_hash_entry * he2 = * (struct top_hash_entry **) p2;
  struct ospf_lsa_header *lsa1 = &(he1->lsa);
  struct ospf_lsa_header *lsa2 = &(he2->lsa);
  int sc1 = LSA_SCOPE(he1->lsa_type);
  int sc2 = LSA_SCOPE(he2->lsa_type);

  if (sc1 != sc2)
    return sc2 - sc1;

  if (he1->domain != he2->domain)
    return he1->domain - he2->domain;

  if (lsa1->rt != lsa2->rt)
    return lsa1->rt - lsa2->rt;

  if (lsa1->id != lsa2->id)
    return lsa1->id - lsa2->id;

  if (he1->lsa_type != he2->lsa_type)
    return he1->lsa_type - he2->lsa_type;

  return lsa1->sn - lsa2->sn;
}

void
ospf_sh_lsadb(struct lsadb_show_data *ld)
{
  struct ospf_proto *p = ld->proto;
  uint num = p->gr->hash_entries;
  uint i, j;
  int last_dscope = -1;
  u32 last_domain = 0;
  u16 type_mask = ospf_is_v2(p) ?  0x00ff : 0xffff;	/* see lsa_etype() */

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1017, "%s: is not up", p->p.name);
    cli_msg(0, "");
    return;
  }

  if (ld->router == SH_ROUTER_SELF)
    ld->router = p->router_id;

  struct top_hash_entry *hea[num];
  struct top_hash_entry *he;

  j = 0;
  WALK_SLIST(he, p->lsal)
    if (he->lsa_body)
      hea[j++] = he;

  ASSERT(j <= num);

  qsort(hea, j, sizeof(struct top_hash_entry *), lsa_compare_for_lsadb);

  for (i = 0; i < j; i++)
  {
    struct ospf_lsa_header *lsa = &(hea[i]->lsa);
    u16 lsa_type = lsa->type_raw & type_mask;
    u16 dscope = LSA_SCOPE(hea[i]->lsa_type);

    /* Hack: 1 is used for LSA_SCOPE_LINK, fixed by & 0xf000 */
    if (ld->scope && (dscope != (ld->scope & 0xf000)))
      continue;

    if ((ld->scope == LSA_SCOPE_AREA) && (hea[i]->domain != ld->area))
      continue;

    /* For user convenience ignore high nibble */
    if (ld->type && ((lsa_type & 0x0fff) != (ld->type & 0x0fff)))
      continue;

    if (ld->lsid && (lsa->id != ld->lsid))
      continue;

    if (ld->router && (lsa->rt != ld->router))
      continue;

    if ((dscope != last_dscope) || (hea[i]->domain != last_domain))
    {
      cli_msg(-1017, "");
      switch (dscope)
      {
      case LSA_SCOPE_AS:
	cli_msg(-1017, "Global");
	break;

      case LSA_SCOPE_AREA:
	cli_msg(-1017, "Area %R", hea[i]->domain);
	break;

      case LSA_SCOPE_LINK:
	{
	  struct iface *ifa = if_find_by_index(hea[i]->domain);
	  cli_msg(-1017, "Link %s", (ifa != NULL) ? ifa->name : "?");
	}
	break;
      }
      cli_msg(-1017, "");
      cli_msg(-1017," Type   LS ID           Router          Sequence   Age  Checksum");

      last_dscope = dscope;
      last_domain = hea[i]->domain;
    }

    cli_msg(-1017," %04x  %-15R %-15R  %08x %5u    %04x",
	    lsa_type, lsa->id, lsa->rt, lsa->sn, lsa->age, lsa->checksum);
  }
  cli_msg(0, "");
}


struct protocol proto_ospf = {
  .name =		"OSPF",
  .template =		"ospf%d",
  .class =		PROTOCOL_OSPF,
  .preference =		DEF_PREF_OSPF,
  .channel_mask =	NB_IP,
  .proto_size =		sizeof(struct ospf_proto),
  .config_size =	sizeof(struct ospf_config),
  .init =		ospf_init,
  .dump =		ospf_dump,
  .start =		ospf_start,
  .shutdown =		ospf_shutdown,
  .reconfigure =	ospf_reconfigure,
  .get_status =		ospf_get_status,
  .get_attr =		ospf_get_attr,
  .get_route_info =	ospf_get_route_info
};
