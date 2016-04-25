#include "l3vpn.h"

static void
l3vpn_alloc_mpls_label(struct l3vpn_proto *p, struct l3vpn_ip_to_mpls *litm, ip_addr gw, struct iface *iface)
{
  net *n = net_get(p->mpls->table, NULL);
  if (!n) {
    log(L_ERR "%s: Couldn't allocate MPLS label.", p->p.name);
    return;
  }

  rta a = {};
  a.gw = gw;
  a.src = p->p.main_source;
  a.iface = iface;
  rte *e = rte_get_temp(rta_lookup(&a));
  rte_update2(p->mpls, n->n.addr, e, p->p.main_source);

  litm->ad.length = sizeof(u32);
  memcpy(litm->ad.data, &((net_addr_mpls *)n->n.addr)->label, sizeof(u32));
}

static ea_list *
l3vpn_get_mpls_label_ea(struct l3vpn_proto *p, ip_addr gw, struct iface *iface)
{
  net_addr_union nu;
  net_fill_ip_host(&nu.n, gw);
  struct l3vpn_ip_to_mpls *litm = fib_get(&p->iptompls, &nu.n);
  if (!litm->ad.length)
    l3vpn_alloc_mpls_label(p, litm, gw, iface);

  if (!litm->ad.length)
    return NULL;

  return &litm->el;
}

static void
l3vpn_iptompls_init(void *ptr)
{
  struct l3vpn_ip_to_mpls *litm = ptr;
  litm->el.count = 1;
  litm->ea.id = EA_GEN_MPLS_STACK;
  litm->ea.type = EAF_TYPE_INT_SET;
  litm->ea.u.ptr = &litm->ad;
}

static void
l3vpn_rt_notify(struct proto *P, struct channel *ch, net *n, rte *new, rte *old, ea_list *ea)
{
  struct l3vpn_proto *p = (struct l3vpn_proto *) P;

  if (!new && !old)
    return;

  if (ch == p->mpls) {
    TRACE(D_EVENTS, "Ignoring MPLS route to %N", &n->n.addr[0]);
    return;
  }

  if (new && ch == new->sender) {
    TRACE(D_EVENTS, "Ignoring back-bounced route to %N", &n->n.addr[0]);
    return;
  }

  net_addr_union new_dst = { .n = n->n.addr[0] };
  if (ch == p->vpn) {
    switch (new_dst.n.type) {
      case NET_VPN4:
	if (new_dst.vpn4.rd != p->rd) {
	  TRACE(D_EVENTS, "Ignoring route to %N with alien RD", &new_dst);
	  return; /* Ignoring routes with alien RD */
	}
	net_fill_ip4(&new_dst.n, net4_prefix(&new_dst.n), net4_pxlen(&new_dst.n));
	break;
      case NET_VPN6:
	if (new_dst.vpn6.rd != p->rd) {
	  TRACE(D_EVENTS, "Ignoring route to %N with alien RD", &new_dst);
	  return; /* Ignoring routes with alien RD */
	}
	new_dst.vpn6.type = NET_IP6;
	net_fill_ip6(&new_dst.n, net6_prefix(&new_dst.n), net6_pxlen(&new_dst.n));
	break;
      default:
	ASSERT(0);
    }
    TRACE(D_EVENTS, "Converted VPN route %N to IP route %N", &n->n.addr[0], &new_dst);
  }
  
  if (ch == p->ip) {
    switch (new_dst.n.type) {
      case NET_IP4:
	net_fill_vpn4(&new_dst.n, net4_prefix(&new_dst.n), net4_pxlen(&new_dst.n), p->rd);
	break;
      case NET_IP6:
	net_fill_vpn6(&new_dst.n, net6_prefix(&new_dst.n), net6_pxlen(&new_dst.n), p->rd);
	break;
      default:
	ASSERT(0);
    }
    TRACE(D_EVENTS, "Converted IP route %N to VPN route %N", &n->n.addr[0], &new_dst);
  }

  rte *e = NULL;
  if (new) {
    rta a;
    memcpy(&a, new->attrs, sizeof(rta));
    a.hostentry = NULL;

    ea_list *mpls_ea = l3vpn_get_mpls_label_ea(p, a.gw, a.iface);

    a.eattrs = mpls_ea;
    mpls_ea->next = ea;

    e = rte_get_temp(rta_lookup(&a));
    e->pflags = 0;

    /* Copy protocol specific embedded attributes. */
    memcpy(&(e->u), &(new->u), sizeof(e->u));
    e->pref = new->pref;
    e->pflags = new->pflags;

    /* FIXME: Add also VPN's MPLS label if ch == p->ip */
  }

  struct rte_src *src = (new ? new->attrs->src : old->attrs->src);

  if (ch == p->ip)
    rte_update2(p->vpn, &new_dst.n, e, src);
  else
    rte_update2(p->ip, &new_dst.n, e, src);
}

static struct proto *
l3vpn_init(struct proto_config *CF)
{
  struct l3vpn_config *cf = (struct l3vpn_config *) CF;
  struct proto *P = proto_new(CF);
  struct l3vpn_proto *p = (struct l3vpn_proto *) P;

  p->vpn = proto_add_channel(P, cf->vpn);
  p->ip = proto_add_channel(P, cf->ip);
  p->mpls = proto_add_channel(P, cf->mpls);
  p->rd = cf->rd;

  P->rt_notify = l3vpn_rt_notify;


  return P;
}

static int
l3vpn_start(struct proto *P)
{
  struct l3vpn_proto *p = (struct l3vpn_proto *) P;
  fib_init(&p->iptompls, P->pool, p->ip->net_type, sizeof(struct l3vpn_ip_to_mpls),
      OFFSETOF(struct l3vpn_ip_to_mpls, n), 0, l3vpn_iptompls_init);

  return PS_UP;
}

struct protocol proto_l3vpn = {
  .name =		"L3VPN",
  .template =		"l3vpn%d",
  .proto_size =		sizeof(struct l3vpn_proto),
  .config_size =	sizeof(struct l3vpn_config),
  .channel_mask =	NB_IP4 | NB_IP6 | NB_VPN4 | NB_VPN6 | NB_MPLS,
  .init =		l3vpn_init,
  .start =		l3vpn_start,
};
