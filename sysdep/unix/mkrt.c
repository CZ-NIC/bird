/*
 *  BIRD -- Multicast routing kernel
 *
 *  (c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

/*
 * DOC: Multicast route kernel synchronization
 *
 * This protocol is the BIRD's interface to the kernel part of multicast
 * routing. It assignes the VIF indices to interfaces, forwards the IGMP
 * packets to SK_IGMP sockets and, of course, adds MFC entries to the kernel.
 *
 * Multicast in current kernel is a bit tricky. There must be exactly one
 * socket on which setsockopt MRT_INIT is called, then multicast forwarding is
 * enabled. Every multicast routing table update must be done through this
 * protocol.
 *
 * Also, that socket is the only one that receives IGMP packets on non-joined
 * groups. These packets IGMP protocol needs to receive, so we forward them
 * internally. To simulate sane behavior, protocol can open socket with type
 * SK_IGMP, which is almost as a SK_IP, IPPROTO_IGMP socket but receives copy
 * of all packets.
 *
 * As always with system-dependent code, prepare for everything. Because the
 * BSD kernel knows nothing apart from (S,G) routes, and Linux even blocked the
 * (*,G) routes for something not being a regular (*,G) routes, we must add the
 * routes in reaction to missed packets. This is very bad, but probably the
 * only solution, until someone rewrites the kernel part.
 *
 * Part of the protocol is global and "static", without the need to configure.
 * Another part is a usual proto instance.
 */

#include "nest/bird.h"
#include "nest/iface.h"
#include "lib/socket.h"
#include "sysdep/unix/unix.h"
#include "sysdep/unix/mkrt.h"

#define HASH_I_KEY(n)	n->iface->index
#define HASH_I_NEXT(n)	n->next
#define HASH_I_EQ(a,b)	(a == b)
#define HASH_I_FN(n)	n

#define HASH_MFC_KEY(n)		n->ga
#define HASH_MFC_NEXT(n)	n->next
#define HASH_MFC_EQ(a,b)	ipa_equal(a, b)
#define HASH_MFC_FN(k)		ipa_hash(k)

static struct mkrt_config *mkrt_cf;

/* Global code for SK_IGMP sockets */

struct mkrt_iface {
  struct mkrt_iface *next;
  struct iface *iface;
  list sockets;
};

static struct mkrt_global {
  pool *pool;
  list sockets;
  HASH(struct mkrt_iface) ifaces;
} mkrt_global;

void
mkrt_io_init(void)
{
  mkrt_global.pool = rp_new(&root_pool, "Multicast kernel Syncer");
  HASH_INIT(mkrt_global.ifaces, mkrt_global.pool, 6);
  init_list(&mkrt_global.sockets);
}

static struct mkrt_iface *
mkrt_iface_find(struct mkrt_proto *p, unsigned ifindex)
{
  return HASH_FIND(mkrt_global.ifaces, HASH_I, ifindex);
}

static struct mkrt_iface *
mkrt_iface_get(unsigned ifindex)
{
  struct mkrt_iface *ifa = HASH_FIND(mkrt_global.ifaces, HASH_I, ifindex);
  if (ifa)
    return ifa;

  ifa = mb_allocz(mkrt_global.pool, sizeof(struct mkrt_iface));
  init_list(&ifa->sockets);
  ifa->iface = if_find_by_index(ifindex);

  HASH_INSERT(mkrt_global.ifaces, HASH_I, ifa);
  return ifa;
}

/*
 * Add the socket into the list of sockets that are passed a copy of every IGMP
 * packet received on the control socket.
 */
void
mkrt_listen(sock *s)
{
  ASSERT(s->type == SK_IGMP);

  if (s->iface)
    {
      struct mkrt_iface *i = mkrt_iface_get(s->iface->index);
      add_tail(&i->sockets, &s->n);
    }
  else
    add_tail(&mkrt_global.sockets, &s->n);

  log(L_INFO "Socket fd %i getting IGMP", s->fd);
}

/*
 * Forward a packet from one socket to another. Emulates the receiving routine.
 * Socket is in exactly the same state as if it received the packet itself, but
 * must not modify it to preserve it for others.
 */
static inline void
mkrt_rx_forward(sock *from, sock *to, int len)
{
  if (!to->rx_hook)
    return;

  to->faddr = from->faddr;
  if (to->flags & SKF_LADDR_RX)
    {
      to->laddr = from->laddr;
      to->lifindex = from->lifindex;
    }

  to->rbuf = from->rbuf;
  to->rpos = from->rpos;
  to->rbsize = from->rbsize;

  to->rx_hook(to, len);

  to->faddr = to->laddr = IPA_NONE;
  to->lifindex = 0;
  to->rbuf = to->rpos = NULL;
  to->rbsize = 0;
}

/*
 * Forward a packet to all sockets on a list.
 */
static inline void
mkrt_rx_forward_all(list *sockets, sock *sk, int len)
{
  node *n, *next;

  WALK_LIST_DELSAFE(n, next, *sockets)
    mkrt_rx_forward(sk, SKIP_BACK(sock, n, n), len);
}

/***************
  Mkernel proto
 ***************/

/*
 * Call a setsockopt with a MRT_ option.
 */
static inline int
mkrt_call(struct mkrt_proto *mkrt, int option_name, const void *val, socklen_t len)
{
  return setsockopt(mkrt->igmp_sock->fd, IPPROTO_IP, option_name, val, len);
}

static inline vifi_t
mkrt_alloc_vifi(struct mkrt_proto *p, struct iface *iface)
{
  if (p->vif_count >= MAXVIFS)
    {
      log(L_ERR "Maximum number of interfaces for multicast routing reached.");
      return -1;
    }

  for (vifi_t i = 0; ; i = (i + 1) % MAXVIFS)
    if (p->vif_map[i] == NULL)
      {
	p->vif_map[i] = iface;
	iface->vifi = i;
	p->vif_count++;
	return i;
      }
}

static inline void
mkrt_free_vifi(struct mkrt_proto *p, vifi_t vifi)
{
  p->vif_count -= p->vif_map[vifi] != NULL;
  p->vif_map[vifi] = NULL;
}

static void
mkrt_add_vif(struct mkrt_proto *p, struct iface *i)
{
  int err;

  if (i->flags & IF_VIFI_ASSIGNED)
    return;

  mkrt_alloc_vifi(p, i);

  struct vifctl vc = {0};
  vc.vifc_vifi = i->vifi;
  vc.vifc_flags = VIFF_USE_IFINDEX;
  vc.vifc_lcl_ifindex = i->index;

  if ((err = mkrt_call(p, MRT_ADD_VIF, &vc, sizeof(vc))) < 0)
    goto err;

  TRACE(D_EVENTS, "Iface %s (%i) assigned VIF %i", i->name, i->index, i->vifi);

  i->flags |= IF_VIFI_ASSIGNED;
  return;

err:
  log(L_ERR "Error while assigning %s VIF %i: %m", i->name, i->vifi, err);
  mkrt_free_vifi(p, i->vifi);
}

static int
mkrt_del_vif(struct mkrt_proto *p, struct iface *i)
{
  int err;

  if (!i->flags & IF_VIFI_ASSIGNED)
    return 0;

  struct vifctl vc = {0};
  vc.vifc_vifi = i->vifi;

  if ((err = mkrt_call(p, MRT_DEL_VIF, &vc, sizeof(vc))) < 0)
    goto err;

  mkrt_free_vifi(p, i->vifi);
  i->flags &= ~IF_VIFI_ASSIGNED;
  return 0;
err:
  log(L_ERR "Error while unassigning %s VIF %i: %m", i->name, i->vifi, err);
  return err;
}

static struct mkrt_mfc_group *
mkrt_mfc_get(struct mkrt_proto *p, ip_addr ga)
{
  struct mkrt_mfc_group *mg = HASH_FIND(p->mfc_groups, HASH_MFC, ga);
  if (mg)
    return mg;

  mg = mb_allocz(p->p.pool, sizeof(struct mkrt_mfc_group));
  mg->ga = ga;
  init_list(&mg->sources);
  HASH_INSERT(p->mfc_groups, HASH_MFC, mg);
  return mg;
}

/*
 * Add a MFC entry for (S, G) with parent vifi, according to the route.
 */
static int
mkrt_mfc_update(struct mkrt_proto *p, ip_addr group, ip_addr source, int vifi, struct rte *rte)
{
  struct mfcctl mc = {0};
  int err;

  mc.mfcc_origin = ipa_to_in4(source);
  mc.mfcc_mcastgrp = ipa_to_in4(group);
  mc.mfcc_parent = vifi;

  if (rte && RTE_MGRP_ISSET(p->vif_map[vifi], rte->u.mkrt.iifs))
    for (int i = 0; i < MAXVIFS; i++)
      if (RTE_MGRP_ISSET(p->vif_map[i], rte->u.mkrt.oifs))
	mc.mfcc_ttls[i] = 1;

  TRACE(D_EVENTS, "%s MFC entry for (%I, %I)", (vifi > 0) ? "Add" : "Delete", source, group);
  if ((err = mkrt_call(p, (vifi > 0) ? MRT_ADD_MFC : MRT_DEL_MFC, &mc, sizeof(mc)) < 0))
    log(L_WARN "Mkernel: failed to %s MFC entry: %m", (vifi > 0) ? "add" : "delete", err);

  return err;
}

struct mfc_request {
  ip_addr *group, *source;
  vifi_t vifi;
  u32 iifs, oifs;
};

/*
 * Expand the attributes from the struct mfc_request and call mkrt_mfc_update,
 * and pass back the result.
 */
static void
mkrt_mfc_call_update(struct proto *p, void *data, rte *rte)
{
  struct mfc_request *req = data;
  mkrt_mfc_update((struct mkrt_proto *) p, *req->group, *req->source, req->vifi, rte);
  if (rte)
    {
      req->iifs = rte->u.mkrt.iifs;
      req->oifs = rte->u.mkrt.oifs;
    }
}

/*
 * Resolve the MFC miss by adding a MFC entry. If no matching entry in the
 * routing table exists, add an empty one to satisfy the kernel.
 */
static void
mkrt_mfc_resolve(struct mkrt_proto *p, ip_addr group, ip_addr source, vifi_t vifi)
{
  struct iface *iface = p->vif_map[vifi];

  TRACE(D_EVENTS, "MFC miss for (%I, %I, %s)", source, group, iface ? iface->name : "??");

  net_addr_mgrp4 n0 = NET_ADDR_MGRP4(ipa_to_ip4(group));

  struct mfc_request req = { &group, &source, vifi };
  if (!rt_route(p->p.main_channel, (net_addr *) &n0, mkrt_mfc_call_update, &req))
    mkrt_mfc_call_update((struct proto *) p, &req, NULL);

  struct mkrt_mfc_group *grp = mkrt_mfc_get(p, group);
  struct mkrt_mfc_source *src = mb_alloc(p->p.pool, sizeof(struct mkrt_mfc_source));
  src->addr = source;
  src->vifi = vifi;
  src->iifs = req.iifs;
  src->oifs = req.oifs;
  add_tail(&grp->sources, NODE src);
}

/*
 * Because a route in the internal table has changed, all the corresponding MFC
 * entries are now wrong. Instead of correcting them, flush the cache.
 */
static void
mkrt_mfc_clean(struct mkrt_proto *p, struct mkrt_mfc_group *mg)
{
  struct mkrt_mfc_source *n, *next;
  WALK_LIST_DELSAFE(n, next, mg->sources)
    {
      mkrt_mfc_update(p, mg->ga, n->addr, -1, NULL);
      rem_node(NODE n);
      mb_free(n);
    }
}

static void
mkrt_mfc_free(struct mkrt_proto *p, struct mkrt_mfc_group *mg)
{
  mkrt_mfc_clean(p, mg);
  HASH_REMOVE(p->mfc_groups, HASH_MFC, mg);
  mb_free(mg);
}

/*
 * An IGMP message received on the socket can be not only a packet received
 * from the network, but also a so-called upcall from the kernel. We must process them here.
 */
static int
mkrt_control_message(struct mkrt_proto *p, sock *sk, int len)
{
  struct igmpmsg *msg = (struct igmpmsg *) sk->rbuf;
  u8 igmp_type = * (u8 *) sk_rx_buffer(sk, &len);

  switch (igmp_type)
    {
    case IGMPMSG_NOCACHE:
      mkrt_mfc_resolve(p, ipa_from_in4(msg->im_dst), ipa_from_in4(msg->im_src), msg->im_vif);
      return 1;

    case IGMPMSG_WRONGVIF:
    case IGMPMSG_WHOLEPKT:
      /* Neither should ever happen. IGMPMSG_WRONGVIF is a common situation,
       * and this upcall is called only when switching to (S,G) tree in other
       * PIM variants.
       *
       * Similarly, the WHOLEPKT should be called only when we add the register
       * VIF and ask kernel for giving us whole packets
       */
      return 1;

    default:
      return 0;
    }
}

static int
mkrt_rx_hook(sock *sk, int len)
{
  struct mkrt_proto *p = sk->data;

  /* Do not forward upcalls, IGMP cannot parse them */
  if (mkrt_control_message(p, sk, len))
    return 1;

  mkrt_rx_forward_all(&mkrt_global.sockets, sk, len);

  struct mkrt_iface *ifa = mkrt_iface_find(p, sk->lifindex);
  if (ifa)
    mkrt_rx_forward_all(&ifa->sockets, sk, len);

  return 1;
}

static void
mkrt_err_hook(sock *sk, int err)
{
  log(L_TRACE "IGMP error: %m", err);
}

static void
mkrt_preconfig(struct protocol *P UNUSED, struct config *c UNUSED)
{
  mkrt_cf = NULL;
}

struct proto_config *
mkrt_config_init(int class)
{
  if (mkrt_cf)
    cf_error("Kernel multicast route syncer already defined");

  mkrt_cf = (struct mkrt_config *) proto_config_new(&proto_mkrt, class);
  return (struct proto_config *) mkrt_cf;
}

void
mkrt_config_finish(struct proto_config *pc)
{
  struct channel_config *cc = proto_cf_main_channel(pc);

  if (!cc)
    cc = channel_config_new(NULL, NET_MGRP4, pc);

  cc->ra_mode = RA_OPTIMAL;
}

static int
mkrt_init_sock(struct mkrt_proto *p)
{
  sock *sk;

  if (!(sk = sk_new(p->p.pool)))
    goto err;

  sk->type = SK_IP;
  sk->subtype = SK_IPV4;
  sk->dport = IPPROTO_IGMP;
  sk->flags = SKF_LADDR_RX;

  sk->data = p;
  sk->ttl = 1;
  sk->rx_hook = mkrt_rx_hook;
  sk->err_hook = mkrt_err_hook;

  sk->rbsize = 4096;
  sk->tbsize = 0;

  if (sk_open(sk) < 0)
    goto err_sk;

  p->igmp_sock = sk;

  int v = 1;
  if (mkrt_call(p, MRT_INIT, &v, sizeof(v)) < 0)
    {
      if (errno == EADDRINUSE)
	log(L_ERR "Mkernel: Another multicast routing daemon is running");
      else
	log(L_ERR "Mkernel: Cannot enable multicast features in kernel: %m", errno);
      goto err_sk;
    }

  log(L_DEBUG "Multicast control socket open with fd %i", sk->fd);
  return 0;

err_sk:
  rfree(sk);
  p->igmp_sock = NULL;
err:
  return -1;
}

void
mkrt_rt_notify(struct proto *P, struct channel *c, net *net, rte *new, rte *old, ea_list *attrs)
{
  struct mkrt_proto *p = (struct mkrt_proto *) P;
  net_addr *n = net->n.addr;
  struct mkrt_mfc_group *mg = mkrt_mfc_get(p, net_prefix(n));

  /* Drop all MFC entries (possibly along with the state information) for a group */
  if (new)
      mkrt_mfc_clean(p, mg);
  else
      mkrt_mfc_free(p, mg);
}

static void
mkrt_if_notify(struct proto *P, uint flags, struct iface *iface)
{
  struct mkrt_proto *p = (struct mkrt_proto *) P;

  if (iface->flags & IF_IGNORE)
    return;

  if (flags & IF_CHANGE_UP)
    mkrt_add_vif(p, iface);

  if (flags & IF_CHANGE_DOWN)
    mkrt_del_vif(p, iface);
}

static struct proto *
mkrt_init(struct proto_config *c)
{
  struct mkrt_proto *p = proto_new(c);

  p->p.main_channel = proto_add_channel(&p->p, proto_cf_main_channel(c));

  p->p.rt_notify = mkrt_rt_notify;
  p->p.if_notify = mkrt_if_notify;

  return &p->p;
}

static int
mkrt_start(struct proto *P)
{
  struct mkrt_proto *p = (struct mkrt_proto *) P;

  p->vif_count = 0;

  HASH_INIT(p->mfc_groups, p->p.pool, 6);

  if (mkrt_init_sock(p) < 0)
    return PS_DOWN;

  return PS_UP;
}

static int
mkrt_shutdown(struct proto *P)
{
  struct mkrt_proto *p = (struct mkrt_proto *) P;
  mkrt_call(p, MRT_DONE, NULL, 0);
  rfree(p->igmp_sock);
  return PS_DOWN;
}

static void
mkrt_dump(struct proto *P)
{
  struct mkrt_proto *p = (struct mkrt_proto *) P;
  struct mkrt_mfc_source *s;

  debug("\tVIFs as in bitmaps:\n\t\t");
  for (int i = MAXVIFS; i >= 0; i--)
    if (p->vif_map[i])
      debug("%s ", p->vif_map[i]->name);
  debug("\n\t(S,G) entries in MFC in kernel:\n");
  HASH_WALK(p->mfc_groups, next, group)
    {
      WALK_LIST(s, group->sources)
	debug("\t\t(%I, %I, %s) -> %b %b\n", s->addr, group->ga, p->vif_map[s->vifi]->name, s->iifs, s->oifs);
    }
  HASH_WALK_END;
}

struct protocol proto_mkrt = {
    .name = "mkernel",
    .template = "mkernel%d",
    .proto_size = sizeof(struct mkrt_proto),
    .config_size = sizeof(struct proto_config),
    .channel_mask = NB_MGRP,
    .preconfig = mkrt_preconfig,
    .init = mkrt_init,
    .start = mkrt_start,
    .shutdown = mkrt_shutdown,
    .dump = mkrt_dump,
};
