/*
 *  BIRD --IGMP protocol
 *
 *  (c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

/*
 * DOC: Internet Group Management Protocol, Version 2
 *
 * The Internet Group Management Protocol (IGMP) is used by IP hosts to report
 * their multicast group memberships to any immediately- neighboring multicast
 * routers.  This memo describes only the use of IGMP between hosts and routers
 * to determine group membership. Routers that are members of multicast groups
 * are expected to behave as hosts as well as routers, and may even respond to
 * their own queries.  IGMP may also be used between routers, but such use is
 * not specified here.
 *
 * Its implementation is split into three files, |packets.c| handling low-level
 * packet formats and |igmp.c| implementing BIRD interface and protocol logic.
 *
 * IGMP communicates with hosts, and publishes requests for groups and
 * interfaces to the BIRD's mutlicast request table. It needs to hold state for
 * every group with local listeners.
 */

#include "igmp.h"
#include "lib/ip.h"
#include "conf/conf.h"

#define HASH_GRP_KEY(n)		n->ga
#define HASH_GRP_NEXT(n)	n->next
#define HASH_GRP_EQ(a,b)	ip4_equal(a,b)
#define HASH_GRP_FN(k)		ip4_hash(k)


/*
 * A change occured, update the request tables.
 */
static void
igmp_notify_routing(struct igmp_grp *grp, int join)
{
  net_addr_mreq4 addr = NET_ADDR_MREQ4(grp->ga, grp->ifa->iface->index);
  struct igmp_proto *p = grp->ifa->proto;

  TRACE(D_EVENTS, "iface %s %s group %I", grp->ifa->iface->name, join ? "joined" : "left", ipa_from_ip4(grp->ga));

  net *n = net_get(p->mreq_channel->table, (net_addr *) &addr);
  if (join)
    {
      rta a0 = {
	  .src = p->p.main_source,
	  .source = RTS_IGMP,
	  .dest = RTD_MREQUEST,
	  .iface = grp->ifa->iface,
      };
      rta *a = rta_lookup(&a0);
      rte *e = rte_get_temp(a);

      e->net = n;
      rte_update2(p->mreq_channel, (net_addr *) &addr, e, p->p.main_source);
    }
  else
    {
      rte_update2(p->mreq_channel, (net_addr *) &addr, NULL, p->p.main_source);
    }
}

static void
igmp_gen_query_hook(struct timer *tm)
{
  struct igmp_iface *ifa = tm->data;

  if (ifa->startup_query_cnt > 0)
    ifa->startup_query_cnt--;

  igmp_tx_query(ifa, IP4_NONE);

  tm_start(ifa->gen_query, ifa->startup_query_cnt
      ? ifa->cf->startup_query_int TO_S
      : ifa->cf->query_int TO_S);
}

static void
igmp_other_present_expire(struct timer *tm)
{
  struct igmp_iface *ifa = tm->data;

  ifa->query_state = IGMP_QS_QUERIER;
  tm_start(ifa->gen_query, 0);
}

/******************************************************************************
                                Group state management
 ******************************************************************************/


static void
igmp_grp_free(struct igmp_grp *grp)
{
  rfree(grp->join_timer);
  rfree(grp->v1_host_timer);
  rfree(grp->rxmt_timer);

  HASH_REMOVE(grp->ifa->groups, HASH_GRP, grp);
  mb_free(grp);
}

static void
igmp_grp_v1_timer_expire(struct timer *tm)
{
  struct igmp_grp *grp = tm->data;

  if (grp->join_state == IGMP_JS_V1MEMB)
    grp->join_state = IGMP_JS_MEMB;
  else
    bug("V1 timer expired without v1 hosts");
}

static void
igmp_grp_join_timer_expire(struct timer *tm)
{
  struct igmp_grp *grp = tm->data;

  switch (grp->join_state) {
    case IGMP_JS_NOMEMB:
	bug("IGMP GRP without members expired.");
      return;
    case IGMP_JS_V1MEMB:
    case IGMP_JS_MEMB:
    case IGMP_JS_CHECK:
      grp->join_state = IGMP_JS_NOMEMB;
      igmp_notify_routing(grp, 0);
      igmp_grp_free(grp);
  }
}

static void
igmp_grp_retransmit_expire(struct timer *tm)
{
  struct igmp_grp *grp = tm->data;

  if (grp->join_state != IGMP_JS_CHECK)
    return;

  igmp_tx_query(grp->ifa, grp->ga);
  tm_start(grp->rxmt_timer, grp->ifa->cf->last_member_query_int TO_S);
}

struct igmp_grp *
igmp_grp_new(struct igmp_iface *ifa, ip4_addr *ga)
{
  struct igmp_proto *p = ifa->proto;
  struct igmp_grp *grp = mb_allocz(p->p.pool, sizeof(struct igmp_grp));
  grp->ga = *ga;
  grp->ifa = ifa;
  HASH_INSERT(ifa->groups, HASH_GRP, grp);

  grp->join_timer = tm_new_set(ifa->proto->p.pool, igmp_grp_join_timer_expire, grp, 0, 0);
  grp->rxmt_timer = tm_new_set(ifa->proto->p.pool, igmp_grp_retransmit_expire, grp, 0, 0);
  grp->v1_host_timer = tm_new_set(ifa->proto->p.pool, igmp_grp_v1_timer_expire, grp, 0, 0);

  return grp;
}

struct igmp_grp *
igmp_grp_find(struct igmp_iface *ifa, ip4_addr *ga)
{
  return HASH_FIND(ifa->groups, HASH_GRP, *ga);
}


/******************************************************************************
                                Iface management
 ******************************************************************************/

static inline int
igmp_iface_is_up(struct igmp_iface *ifa)
{
  return !!ifa->sk;
}

static struct igmp_iface *
igmp_iface_new(struct igmp_proto *p, struct iface *iface, struct igmp_iface_config *ic)
{
  struct igmp_iface *ifa = mb_allocz(p->p.pool, sizeof(struct igmp_iface));
  add_tail(&p->iface_list, NODE ifa);
  ifa->iface = iface;
  ifa->cf = ic;
  ifa->proto = p;
  ifa->gen_id = random_u32();
  ifa->startup_query_cnt = ifa->cf->startup_query_cnt;

  ifa->gen_query = tm_new_set(p->p.pool, igmp_gen_query_hook, ifa, 0, 0);
  ifa->other_present = tm_new_set(p->p.pool, igmp_other_present_expire, ifa, 0, 0);

  HASH_INIT(ifa->groups, p->p.pool, 8);

  if (igmp_sk_open(ifa))
      log(L_ERR "Failed opening socket for IGMP");

  ifa->query_state = IGMP_QS_QUERIER;
  tm_start(ifa->gen_query, 0);

  return ifa;
}

static int
igmp_iface_down(struct igmp_iface *ifa)
{
  if (!igmp_iface_is_up(ifa))
    return 0;

  rfree(ifa->sk);
  ifa->sk = NULL;
  return 0;
}

static int
igmp_iface_free(struct igmp_iface* ifa)
{
  rem_node(NODE ifa);

  HASH_WALK_DELSAFE(ifa->groups, next, grp)
    {
      igmp_notify_routing(grp, 0);
      igmp_grp_free(grp);
    }
  HASH_WALK_END;

  rfree(ifa->gen_query);
  rfree(ifa->other_present);
  mb_free(ifa);
  return 0;
}

static char *join_states[] = {
  [IGMP_JS_NOMEMB] = "no members",
  [IGMP_JS_MEMB] = "members",
  [IGMP_JS_V1MEMB] = "v1 members",
  [IGMP_JS_CHECK] = "about to expire",
};

static char *query_states[] = {
  [IGMP_QS_INIT] = "initializing",
  [IGMP_QS_QUERIER] = "querier",
  [IGMP_QS_NONQUERIER] = "other querier present",
};

static void
igmp_iface_dump(struct igmp_iface *ifa)
{
    struct igmp_proto *p = ifa->proto;

    debug("\tInterface %s is %s, %s\n", ifa->iface->name, igmp_iface_is_up(ifa) ? "up" : "down", query_states[ifa->query_state]);

    HASH_WALK(ifa->groups, next, grp)
      TRACE(D_EVENTS, "\t\tGroup %I4: %s\n", grp->ga, join_states[grp->join_state]);
    HASH_WALK_END;
}

struct igmp_iface *
igmp_iface_find(struct igmp_proto *p, struct iface * ifa)
{
  struct igmp_iface * pif;
  WALK_LIST(pif, p->iface_list)
    if (pif->iface == ifa)
      return pif;

  return NULL;
}

void
igmp_iface_config_init(struct igmp_iface_config * ifc)
{
  init_list(&ifc->i.ipn_list);

  ifc->robustness = 2;
  ifc->query_int = 125 S;
  ifc->query_response_int = 10 S;
  ifc->last_member_query_int = 1 S;
  ifc->last_member_query_cnt = -1U;

  ifc->startup_query_cnt = -1U;
  ifc->startup_query_int = -1U;
}

void
igmp_iface_config_finish(struct igmp_iface_config * ifc)
{
  /* Explicit constraints - probably bail out? */
  if (ifc->robustness == 0)
    cf_error("IGMP: Robustness must be at least 1.");

  if (ifc->query_response_int > ifc->query_int)
    cf_error("IGMP: The query response interval must not be greater than the query interval.");

  /* Dependent default values */
  if (ifc->startup_query_int == -1U)
    ifc->startup_query_int = ifc->query_int / 4;

  if (ifc->startup_query_cnt == -1U)
    ifc->startup_query_cnt = ifc->robustness;

  if (ifc->last_member_query_cnt == -1U)
    ifc->last_member_query_cnt = ifc->robustness;

  ifc->group_memb_int = ifc->robustness * ifc->query_int + ifc->query_response_int;
  ifc->other_querier_int = ifc->robustness * ifc->query_int + ifc->query_response_int / 2;
}

/******************************************************************************
				Protocol logic
 ******************************************************************************/

int
igmp_query_received(struct igmp_iface *ifa, ip4_addr from)
{

  if (ifa->query_state != IGMP_QS_QUERIER)
    return 0;

  /* Find first IPv4 address of the interface */
  /* XXX: cache and update in if_notify? */
  struct ifa *my_addr = ifa_find_match(ifa->iface, NB_IP4);

  /* Another router with lower IP shall be the Querier */
  if (ip4_compare(ipa_to_ip4(my_addr->ip), from) > 0)
    {
      ifa->query_state = IGMP_QS_NONQUERIER;
      tm_start(ifa->other_present, ifa->cf->other_querier_int TO_S);
    }

  return 0;
}

int
igmp_membership_report(struct igmp_grp *grp, u8 igmp_version, u8 resp_time)
{
  struct igmp_proto *p = grp->ifa->proto;
  uint last_state = grp->join_state;
  TRACE(D_PACKETS, "Membership report received for group %I4 on iface %s", grp->ga, grp->ifa->iface->name);

  if (grp->ifa->query_state == IGMP_QS_QUERIER && igmp_version == 1)
    {
      grp->join_state = IGMP_JS_V1MEMB;
      tm_start(grp->v1_host_timer, grp->ifa->cf->group_memb_int TO_S);
    }

  if (grp->join_state != IGMP_JS_V1MEMB)
    grp->join_state = IGMP_JS_MEMB;

  tm_stop(grp->rxmt_timer);
  tm_start(grp->join_timer, grp->ifa->cf->group_memb_int TO_S);

  if (last_state == IGMP_JS_NOMEMB)
    igmp_notify_routing(grp, 1);

  return 0;
}

int
igmp_leave(struct igmp_grp *grp, u8 resp_time)
{
  if (!grp)
    return 0;

  struct igmp_proto *p = grp->ifa->proto;

  TRACE(D_PACKETS, "Leave received for group %I4 on iface %s", grp->ga, grp->ifa->iface->name);
  grp->join_state = IGMP_JS_CHECK;
  tm_start(grp->rxmt_timer, 0);
  tm_start(grp->join_timer, (grp->ifa->cf->last_member_query_int TO_S) * grp->ifa->cf->last_member_query_cnt);
  return 0;
}

/******************************************************************************
				Others
 ******************************************************************************/

void
igmp_config_init(struct igmp_config *cf)
{
   init_list(&cf->patt_list);
   igmp_iface_config_init(&cf->default_iface_cf);
   igmp_iface_config_finish(&cf->default_iface_cf);
}

void
igmp_config_finish(struct proto_config *c)
{
  if (NULL == proto_cf_find_channel(c, NET_MREQ4))
    channel_config_new(NULL, NET_MREQ4, c);
}

static void
igmp_if_notify(struct proto *P, uint flags, struct iface *iface)
{
  struct igmp_proto *p = (struct igmp_proto *) P;
  struct igmp_config *c = (struct igmp_config *) P->cf;

  if (iface->flags & IF_IGNORE)
    return;

  if (flags & IF_CHANGE_UP)
    {
      struct igmp_iface_config *ic;
      ic = (struct igmp_iface_config *) iface_patt_find(&c->patt_list, iface, iface->addr);
      if (!ic)
	ic = &c->default_iface_cf;
      igmp_iface_new(p, iface, ic);
      return;
    }


  if (flags & IF_CHANGE_DOWN)
    {
      struct igmp_iface * ifa = igmp_iface_find(p, iface);
      igmp_iface_down(ifa);
      igmp_iface_free(ifa);
    }
}

static int
igmp_start(struct proto *P)
{
  struct igmp_proto *p = (struct igmp_proto *) P;
  init_list(&p->iface_list);
  return PS_UP;
}

static int
igmp_shutdown(struct proto *P)
{
  struct igmp_proto *p = (struct igmp_proto *) P;
  struct igmp_iface *ifa;
  WALK_LIST_FIRST(ifa, p->iface_list)
    {
      igmp_iface_down(ifa);
      igmp_iface_free(ifa);
    }

  return PS_DOWN;
}

static void
igmp_dump(struct proto *P)
{
  struct igmp_proto *p = (struct igmp_proto *) P;
  struct igmp_iface *ifa;
  WALK_LIST(ifa, p->iface_list)
    igmp_iface_dump(ifa);
}

/*
 * We do not want to receive any route updates.
 */
static int
igmp_reject(struct proto *p, rte **e, ea_list **attrs, struct linpool *pool)
{ return -1; }

static struct proto *
igmp_init(struct proto_config *C)
{
  struct proto *P = proto_new(C);
  struct igmp_proto *p = (struct igmp_proto *) P;

  p->mreq_channel = proto_add_channel(P, proto_cf_find_channel(C, NET_MREQ4));

  p->cf = (struct igmp_config *) C;
  P->if_notify = igmp_if_notify;
  P->import_control = igmp_reject;

  return P;
}

struct protocol proto_igmp = {
	.name =		"IGMP",
	.template =	"igmp%d",
	.preference =	DEF_PREF_STATIC,
	.proto_size =	sizeof(struct igmp_proto),
	.config_size =	sizeof(struct igmp_config),
	.channel_mask = NB_MREQ4,
	.init =		igmp_init,
	.dump =		igmp_dump,
	.start =	igmp_start,
	.shutdown =	igmp_shutdown,
};

