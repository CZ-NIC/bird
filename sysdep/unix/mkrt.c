/*
 *	BIRD -- UNIX Kernel Multicast Routing
 *
 *	(c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *	(c) 2018 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2018 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Kernel Multicast Routing
 *
 * This protocol is the interface to the kernel part of multicast routing. It
 * handles registration of multicast interfaces (MIFs), maintenance of kernel
 * Multicast Forwarding Cache (MFC), and reception of incoming IGMP packets.
 *
 * Multicast forwarding in Linux and BSD kernels is a bit tricky. There must be
 * exactly one socket on which setsockopt MRT_INIT is called, then multicast
 * forwarding is enabled and kernel multicast routing table is maintained until
 * the socket is closed. This MRT control socket is stored in &mrt_sock field.
 *
 * Multicast forwarding works only on interfaces registered as MIFs, with
 * assigned MIF index. While MIFs and MIF indexes are handled by OS-independent
 * code in iface.c, actual MIF registration by OS kernel is handled here. The
 * MKernel protocol is associated with a MIF group by mkrt_register_mif_group(),
 * after that it receive mkrt_register_mif() / mkrt_unregister_mif() calls for
 * changes in given MIF group.
 *
 * Unlike kernel unicast routing API, which is proactive, kernel multicast
 * routing API is designed as reactive. Kernel keeps MFC entries for encountered
 * (S, G) flows and when a new flow is noticed, BIRD receives cache miss message
 * (%IGMPMSG_NOCACHE) from kernel and responds with adding appropriate (S, G)
 * MFC entry to the kernel, see mkrt_resolve_mfc(). Therefore, regular route
 * notifications handled by mkrt_rt_notify() are not directly translated to
 * kernel route updates.
 *
 * Although there is also support for (*, G) MFC entries in Linux (using
 * %MRT_ADD_MFC_PROXY), their behavior is strange and not matching our needs,
 * and there is no equivalent in BSD, we do not use them and we manage with
 * traditional (S, G) MFC entries.
 *
 * Finally, the MRT control socket is the only one that receives all IGMP
 * packets, even those from non-joined groups. IGMP protocol needs to receive
 * these packets, so we forward them internally. To simulate the sane behavior,
 * a protocol can open an IGMP socket and use sk_setup_igmp() to register it to
 * reception of all IGMP packets. The socket is relinked to internal MIF socket
 * list. MKernel protocol then use mif_forward_igmp() to forward packets
 * received on the MRT control socket to all sockets on these lists.
 */

#include "nest/bird.h"
#include "nest/iface.h"
#include "lib/socket.h"

#include "unix.h"
#include "mkrt.h"

#include <linux/mroute.h>


/*
 *	MRT socket options
 */

static inline int
sk_mrt_init4(sock *s)
{
  int y = 1;
  return setsockopt(s->fd, IPPROTO_IP, MRT_INIT, &y, sizeof(y));
}

static inline int
sk_mrt_done4(sock *s)
{
  return setsockopt(s->fd, IPPROTO_IP, MRT_DONE, NULL, 0);
}

static inline int
sk_mrt_add_mif4(sock *s, struct mif *mif)
{
  struct vifctl vc = {
    .vifc_vifi = mif->index,
    .vifc_flags = VIFF_USE_IFINDEX,
    .vifc_lcl_ifindex = mif->iface->index,
  };

  return setsockopt(s->fd, IPPROTO_IP, MRT_ADD_VIF, &vc, sizeof(vc));
}

static inline int
sk_mrt_del_mif4(sock *s, struct mif *mif)
{
  struct vifctl vc = {
    .vifc_vifi = mif->index,
  };

  return setsockopt(s->fd, IPPROTO_IP, MRT_DEL_VIF, &vc, sizeof(vc));
}

static inline int
sk_mrt_add_mfc4(sock *s, ip4_addr src, ip4_addr grp, u32 iifs, u32 oifs, int mif_index)
{
  struct mfcctl mc = {
    .mfcc_origin = ip4_to_in4(src),
    .mfcc_mcastgrp = ip4_to_in4(grp),
    .mfcc_parent = mif_index,
  };

  if (BIT32_TEST(&iifs, mif_index) && oifs)
    for (int i = 0; i < MIFS_MAX; i++)
      if (BIT32_TEST(&oifs, i) && (i != mif_index))
	mc.mfcc_ttls[i] = 1;

  return setsockopt(s->fd, IPPROTO_IP, MRT_ADD_MFC, &mc, sizeof(mc));
}

static inline int
sk_mrt_del_mfc4(sock *s, ip4_addr src, ip4_addr grp)
{
  struct mfcctl mc = {
    .mfcc_origin = ip4_to_in4(src),
    .mfcc_mcastgrp = ip4_to_in4(grp),
  };

  return setsockopt(s->fd, IPPROTO_IP, MRT_DEL_MFC, &mc, sizeof(mc));
}


/*
 *	MIF handling
 */

void
mkrt_register_mif(struct mkrt_proto *p, struct mif *mif)
{
  TRACE(D_EVENTS, "Registering interface %s MIF %i", mif->iface->name, mif->index);

  if (sk_mrt_add_mif4(p->mrt_sock, mif) < 0)
    log(L_ERR "%s: Cannot register interface %s MIF %i: %m",
	p->p.name, mif->iface->name, mif->index);
}

void
mkrt_unregister_mif(struct mkrt_proto *p, struct mif *mif)
{
  TRACE(D_EVENTS, "Unregistering interface %s MIF %i", mif->iface->name, mif->index);

  if (sk_mrt_del_mif4(p->mrt_sock, mif) < 0)
    log(L_ERR "%s: Cannot unregister interface %s MIF %i: %m",
	p->p.name, mif->iface->name, mif->index);
}

void
mkrt_register_mif_group(struct mkrt_proto *p, struct mif_group *grp)
{
  ASSERT(!grp->owner);
  grp->owner = &p->p;

  WALK_ARRAY(grp->mifs, MIFS_MAX, mif)
    if (mif)
      mkrt_register_mif(p, mif);
}

void
mkrt_unregister_mif_group(struct mkrt_proto *p, struct mif_group *grp)
{
  grp->owner = NULL;

  WALK_ARRAY(grp->mifs, MIFS_MAX, mif)
    if (mif)
      mkrt_unregister_mif(p, mif);
}


/*
 *	MFC handling
 */

static void
mkrt_init_mfc(void *G)
{
  struct mkrt_mfc_group *grp = G;

  init_list(&grp->sources);
}

static struct mkrt_mfc_source *
mkrt_get_mfc(struct mkrt_proto *p, ip4_addr source, ip4_addr group)
{
  net_addr_mgrp4 n = NET_ADDR_MGRP4(group);
  struct mkrt_mfc_group *grp = fib_get(&p->mfc_groups, (net_addr *) &n);

  struct mkrt_mfc_source *src;
  WALK_LIST(src, grp->sources)
    if (ip4_equal(src->addr, source))
      return src;

  src = mb_allocz(p->p.pool, sizeof(struct mkrt_mfc_source));
  src->addr = source;
  src->parent = -1;
  add_tail(&grp->sources, NODE src);

  return src;
}

struct mfc_result {
  u32 iifs, oifs;
};

static void
mkrt_resolve_mfc_hook(struct proto *p UNUSED, void *data, rte *rte)
{
  struct mfc_result *res = data;
  res->iifs = rta_iifs(rte->attrs);
  res->oifs = rta_oifs(rte->attrs);
}

/*
 * Resolve the MFC miss by adding a MFC entry. If no matching entry in the
 * routing table exists, add an empty one to satisfy the kernel.
 */
static void
mkrt_resolve_mfc(struct mkrt_proto *p, ip4_addr src, ip4_addr grp, int mif_index)
{
  struct mif *mif = (mif_index < MIFS_MAX) ? p->mif_group->mifs[mif_index] : NULL;

  TRACE(D_EVENTS, "MFC miss for (%I4, %I4, %s)", src, grp, mif ? mif->iface->name : "?");

  net_addr_mgrp4 n0 = NET_ADDR_MGRP4(grp);
  struct mfc_result res = {};

  rt_examine(p->p.main_channel, (net_addr *) &n0, mkrt_resolve_mfc_hook, &res);

  struct mkrt_mfc_source *mfc = mkrt_get_mfc(p, src, grp);
  mfc->iifs = res.iifs;
  mfc->oifs = res.oifs;
  mfc->parent = mif_index;

  TRACE(D_EVENTS, "Adding MFC entry for (%I4, %I4)", src, grp);

  if (sk_mrt_add_mfc4(p->mrt_sock, src, grp, mfc->iifs, mfc->oifs, mfc->parent) < 0)
    log(L_ERR "%s: Failed to add MFC entry: %m", p->p.name);
}

static void
mkrt_remove_mfc(struct mkrt_proto *p, struct mkrt_mfc_source *src, ip4_addr grp)
{
  TRACE(D_EVENTS, "Removing MFC entry for (%I4, %I4)", src->addr, grp);

  if (sk_mrt_del_mfc4(p->mrt_sock, src->addr, grp) < 0)
    log(L_ERR "%s: Failed to remove MFC entry: %m", p->p.name);

  rem_node(NODE src);
  mb_free(src);
}


/*
 * Because a route in the internal table has changed, all the corresponding MFC
 * entries are now wrong. Instead of correcting them, just flush the cache.
 */
static void
mkrt_reset_mfc_group(struct mkrt_proto *p, struct mkrt_mfc_group *grp)
{
  ip4_addr group = net4_prefix(grp->n.addr);

  struct mkrt_mfc_source *src;
  WALK_LIST_FIRST(src, grp->sources)
    mkrt_remove_mfc(p, src, group);
}

static void
mkrt_free_mfc_group(struct mkrt_proto *p, struct mkrt_mfc_group *grp)
{
  mkrt_reset_mfc_group(p, grp);
  fib_delete(&p->mfc_groups, grp);
}

static void
mkrt_rt_notify(struct proto *P, struct channel *c UNUSED, net *net, rte *new, rte *old UNUSED, ea_list *attrs UNUSED)
{
  struct mkrt_proto *p = (void *) P;
  struct mkrt_mfc_group *grp = fib_find(&p->mfc_groups, net->n.addr);

  if (!grp)
    return;

  /* Drop all MFC entries (possibly along with the state information) for a group */
  if (new)
    mkrt_reset_mfc_group(p, grp);
  else
    mkrt_free_mfc_group(p, grp);
}


/*
 * On MRT control socket, we receive not only regular IGMP messages but also
 * so-called upcalls from the kernel. We must process them here.
 */
void mif_forward_igmp(struct mif_group *grp, struct mif *mif, sock *src, int len);

static int
mkrt_rx_hook(sock *sk, uint len)
{
  struct mkrt_proto *p = sk->data;
  struct igmpmsg *msg = (void *) sk->rbuf;
  u8 igmp_type = * (u8 *) sk_rx_buffer(sk, &len);

  switch (igmp_type)
  {
  case IGMPMSG_NOCACHE:
    mkrt_resolve_mfc(p, ip4_from_in4(msg->im_src), ip4_from_in4(msg->im_dst), msg->im_vif);
    return 1;

  case IGMPMSG_WRONGVIF:
  case IGMPMSG_WHOLEPKT:
    /* These should not happen unless some PIM-specific MRT options are enabled */
    return 1;

  default:
    // FIXME: Use sk->lifindex or msg->im_vif ?
    mif_forward_igmp(p->mif_group, NULL, sk, len);
    return 1;
  }
}

static void
mkrt_err_hook(sock *sk, int err)
{
  struct mkrt_proto *p = sk->data;

  log(L_ERR "%s: Socket error: %M", p->p.name, err);
}

static int
mkrt_open_socket(struct mkrt_proto *p)
{
  sock *sk = sk_new(p->p.pool);
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
  {
    sk_log_error(sk, p->p.name);
    goto err;
  }

  if (sk_mrt_init4(sk) < 0)
  {
    if (errno == EADDRINUSE)
      log(L_ERR "%s: Another multicast daemon is running", p->p.name);
    else
      log(L_ERR "%s: Cannot enable multicast in kernel: %m", p->p.name);

    goto err;
  }

  p->mrt_sock = sk;
  return 1;

err:
  rfree(sk);
  return 0;
}

static void
mkrt_close_socket(struct mkrt_proto *p)
{
  sk_mrt_done4(p->mrt_sock);
  rfree(p->mrt_sock);
  p->mrt_sock = NULL;
}


/*
 *	Protocol glue
 */

static struct mkrt_config *mkrt_cf;

static void
mkrt_preconfig(struct protocol *P UNUSED, struct config *c UNUSED)
{
  mkrt_cf = NULL;
}

struct proto_config *
mkrt_init_config(int class)
{
  if (mkrt_cf)
    cf_error("Multicast kernel protocol already defined");

  mkrt_cf = (struct mkrt_config *) proto_config_new(&proto_unix_mkrt, class);
  return (struct proto_config *) mkrt_cf;
}

void
mkrt_postconfig(struct proto_config *CF)
{
  // struct mkrt_config *cf = (void *) CF;

  if (EMPTY_LIST(CF->channels))
    cf_error("Channel not specified");
}

static struct proto *
mkrt_init(struct proto_config *CF)
{
  struct mkrt_proto *p = proto_new(CF);

  p->p.main_channel = proto_add_channel(&p->p, proto_cf_main_channel(CF));

  p->p.rt_notify = mkrt_rt_notify;

  p->mif_group = global_mif_group;

  return &p->p;
}

static int
mkrt_start(struct proto *P)
{
  struct mkrt_proto *p = (void *) P;

  fib_init(&p->mfc_groups, p->p.pool, NET_MGRP4, sizeof(struct mkrt_mfc_group),
	   OFFSETOF(struct mkrt_mfc_group, n), 6, mkrt_init_mfc);

  if (!mkrt_open_socket(p))
    return PS_START;

  mkrt_register_mif_group(p, p->mif_group);

  return PS_UP;
}

static int
mkrt_shutdown(struct proto *P)
{
  struct mkrt_proto *p = (void *) P;

  if (p->p.proto_state == PS_START)
    return PS_DOWN;

  mkrt_unregister_mif_group(p, p->mif_group);
  mkrt_close_socket(p);

  return PS_DOWN;
}

static int
mkrt_reconfigure(struct proto *p, struct proto_config *CF)
{
  // struct mkrt_config *o = (void *) p->cf;
  // struct mkrt_config *n = (void *) CF;

  if (!proto_configure_channel(p, &p->main_channel, proto_cf_main_channel(CF)))
    return 0;

  return 1;
}

static void
mkrt_dump(struct proto *P)
{
  struct mkrt_proto *p = (void *) P;

  debug("\t(S,G) entries in MFC in kernel:\n");
  FIB_WALK(&p->mfc_groups, struct mkrt_mfc_group, grp)
  {
    struct mkrt_mfc_source *src;
    WALK_LIST(src, grp->sources)
      debug("\t\t(%I4, %I4, %d) -> %b %b\n",
	    src->addr, net4_prefix(grp->n.addr), src->parent, src->iifs, src->oifs);
  }
  FIB_WALK_END;
}


struct protocol proto_unix_mkrt = {
  .name =		"MKernel",
  .template =		"mkernel%d",
  .channel_mask =	NB_MGRP4,
  .proto_size =		sizeof(struct mkrt_proto),
  .config_size =	sizeof(struct mkrt_config),
  .preconfig =		mkrt_preconfig,
  .postconfig =		mkrt_postconfig,
  .init =		mkrt_init,
  .start =		mkrt_start,
  .shutdown =		mkrt_shutdown,
  .reconfigure =	mkrt_reconfigure,
  .dump =		mkrt_dump,
};
