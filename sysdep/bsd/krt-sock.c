/*
 *	BIRD -- BSD Routing Table Syncing
 *
 *	(c) 2004 Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if.h>
#include <net/if_dl.h>

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "sysdep/unix/unix.h"
#include "sysdep/unix/krt.h"
#include "lib/string.h"
#include "lib/socket.h"

const int rt_default_ecmp = 0;

/*
 * There are significant differences in multiple tables support between BSD variants.
 *
 * OpenBSD has table_id field for routes in route socket protocol, therefore all
 * tables could be managed by one kernel socket. FreeBSD lacks such field,
 * therefore multiple sockets (locked to specific table using SO_SETFIB socket
 * option) must be used.
 *
 * Both FreeBSD and OpenBSD uses separate scans for each table. In OpenBSD,
 * table_id is specified explicitly as sysctl scan argument, while in FreeBSD it
 * is handled implicitly by changing default table using setfib() syscall.
 *
 * KRT_SHARED_SOCKET	- use shared kernel socked instead of one for each krt_proto
 * KRT_USE_SETFIB_SCAN	- use setfib() for sysctl() route scan
 * KRT_USE_SETFIB_SOCK	- use SO_SETFIB socket option for kernel sockets
 * KRT_USE_SYSCTL_7	- use 7-th arg of sysctl() as table id for route scans
 * KRT_USE_SYSCTL_NET_FIBS - use net.fibs sysctl() for dynamic max number of fibs
 */

#ifdef __FreeBSD__
#define KRT_MAX_TABLES 256
#define KRT_USE_SETFIB_SCAN
#define KRT_USE_SETFIB_SOCK
#define KRT_USE_SYSCTL_NET_FIBS
#endif

#ifdef __OpenBSD__
#define KRT_MAX_TABLES (RT_TABLEID_MAX+1)
#define KRT_SHARED_SOCKET
#define KRT_USE_SYSCTL_7
#endif

#ifndef KRT_MAX_TABLES
#define KRT_MAX_TABLES 1
#endif


/* Dynamic max number of tables */

uint krt_max_tables;

#ifdef KRT_USE_SYSCTL_NET_FIBS

static uint
krt_get_max_tables(void)
{
  int fibs;
  size_t fibs_len = sizeof(fibs);

  if (sysctlbyname("net.fibs", &fibs, &fibs_len, NULL, 0) < 0)
  {
    log(L_WARN "KRT: unable to get max number of fib tables: %m");
    return 1;
  }

  /* Should not happen */
  if (fibs < 1)
    return 1;

  return (uint) MIN(fibs, KRT_MAX_TABLES);
}

#else

static int
krt_get_max_tables(void)
{
  return KRT_MAX_TABLES;
}

#endif /* KRT_USE_SYSCTL_NET_FIBS */


/* setfib() syscall for FreeBSD scans */

#ifdef KRT_USE_SETFIB_SCAN

/*
static int krt_default_fib;

static int
krt_get_active_fib(void)
{
  int fib;
  size_t fib_len = sizeof(fib);

  if (sysctlbyname("net.my_fibnum", &fib, &fib_len, NULL, 0) < 0)
  {
    log(L_WARN "KRT: unable to get active fib number: %m");
    return 0;
  }

  return fib;
}
*/

extern int setfib(int fib);

#endif /* KRT_USE_SETFIB_SCAN */


/* table_id -> krt_proto map */

#ifdef KRT_SHARED_SOCKET
static struct krt_proto *krt_table_map[KRT_MAX_TABLES][2];
#endif


/* Route socket message processing */

int
krt_capable(rte *e)
{
  rta *a = e->attrs;

  return
    ((a->dest == RTD_UNICAST && !a->nh.next) /* No multipath support */
#ifdef RTF_REJECT
     || a->dest == RTD_UNREACHABLE
#endif
#ifdef RTF_BLACKHOLE
     || a->dest == RTD_BLACKHOLE
#endif
     );
}

#ifndef RTAX_MAX
#define RTAX_MAX 8
#endif

struct ks_msg
{
  struct rt_msghdr rtm;
  struct sockaddr_storage buf[RTAX_MAX];
} PACKED;

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

#define NEXTADDR(w, u) \
        if (msg.rtm.rtm_addrs & (w)) {\
          l = ROUNDUP(((struct sockaddr *)&(u))->sa_len);\
          memmove(body, &(u), l); body += l;}

#define GETADDR(p, F) \
  bzero(p, sizeof(*p));\
  if ((addrs & (F)) && ((struct sockaddr *)body)->sa_len) {\
    uint l = ROUNDUP(((struct sockaddr *)body)->sa_len);\
    memcpy(p, body, (l > sizeof(*p) ? sizeof(*p) : l));\
    body += l;}

static inline void
sockaddr_fill_dl(struct sockaddr_dl *sa, struct iface *ifa)
{
  uint len = OFFSETOF(struct sockaddr_dl, sdl_data);
  memset(sa, 0, len);
  sa->sdl_len = len;
  sa->sdl_family = AF_LINK;
  sa->sdl_index = ifa->index;
}

static int
krt_send_route(struct krt_proto *p, int cmd, rte *e)
{
  net *net = e->net;
  rta *a = e->attrs;
  static int msg_seq;
  struct iface *j, *i = a->nh.iface;
  int l;
  struct ks_msg msg;
  char *body = (char *)msg.buf;
  sockaddr gate, mask, dst;

  DBG("krt-sock: send %I/%d via %I\n", net->n.prefix, net->n.pxlen, a->gw);

  bzero(&msg,sizeof (struct rt_msghdr));
  msg.rtm.rtm_version = RTM_VERSION;
  msg.rtm.rtm_type = cmd;
  msg.rtm.rtm_seq = msg_seq++;
  msg.rtm.rtm_addrs = RTA_DST;
  msg.rtm.rtm_flags = RTF_UP | RTF_PROTO1;

  /* XXXX */
  if (net_pxlen(net->n.addr) == net_max_prefix_length[net->n.addr->type])
    msg.rtm.rtm_flags |= RTF_HOST;
  else
    msg.rtm.rtm_addrs |= RTA_NETMASK;

#ifdef KRT_SHARED_SOCKET
  msg.rtm.rtm_tableid = KRT_CF->sys.table_id;
#endif

#ifdef RTF_REJECT
  if(a->dest == RTD_UNREACHABLE)
    msg.rtm.rtm_flags |= RTF_REJECT;
#endif
#ifdef RTF_BLACKHOLE
  if(a->dest == RTD_BLACKHOLE)
    msg.rtm.rtm_flags |= RTF_BLACKHOLE;
#endif

  /*
   * This is really very nasty, but I'm not able to add reject/blackhole route
   * without gateway address.
   */
  if (!i)
  {
    WALK_LIST(j, iface_list)
    {
      if (j->flags & IF_LOOPBACK)
      {
        i = j;
        break;
      }
    }

    if (!i)
    {
      log(L_ERR "KRT: Cannot find loopback iface");
      return -1;
    }
  }

  int af = AF_UNSPEC;

  switch (net->n.addr->type) {
    case NET_IP4:
      af = AF_INET;
      break;
    case NET_IP6:
      af = AF_INET6;
      break;
    default:
      log(L_ERR "KRT: Not sending route %N to kernel", net->n.addr);
      return -1;
  }

  sockaddr_fill(&dst,  af, net_prefix(net->n.addr), NULL, 0);
  sockaddr_fill(&mask, af, net_pxmask(net->n.addr), NULL, 0);

  switch (a->dest)
  {
  case RTD_UNICAST:
    if (ipa_nonzero(a->nh.gw))
    {
      ip_addr gw = a->nh.gw;

      /* Embed interface ID to link-local address */
      if (ipa_is_link_local(gw))
	_I0(gw) = 0xfe800000 | (i->index & 0x0000ffff);

      sockaddr_fill(&gate, af, gw, NULL, 0);
      msg.rtm.rtm_flags |= RTF_GATEWAY;
      msg.rtm.rtm_addrs |= RTA_GATEWAY;
      break;
    }

#ifdef RTF_REJECT
  case RTD_UNREACHABLE:
#endif
#ifdef RTF_BLACKHOLE
  case RTD_BLACKHOLE:
#endif
  {
    /* Fallback for all other valid cases */

#if __OpenBSD__
    /* Keeping temporarily old code for OpenBSD */
    struct ifa *addr = (net->n.addr->type == NET_IP4) ? i->addr4 : (i->addr6 ?: i->llv6);

    if (!addr)
    {
      log(L_ERR "KRT: interface %s has no IP addess", i->name);
      return -1;
    }

    /* Embed interface ID to link-local address */
    ip_addr gw = addr->ip;
    if (ipa_is_link_local(gw))
      _I0(gw) = 0xfe800000 | (i->index & 0x0000ffff);

    sockaddr_fill(&gate, af, gw, i, 0);
#else
    sockaddr_fill_dl(&gate, i);
#endif

    msg.rtm.rtm_addrs |= RTA_GATEWAY;
    break;
  }

  default:
    bug("krt-sock: unknown flags, but not filtered");
  }

  msg.rtm.rtm_index = i->index;

  NEXTADDR(RTA_DST, dst);
  NEXTADDR(RTA_GATEWAY, gate);
  NEXTADDR(RTA_NETMASK, mask);

  l = body - (char *)&msg;
  msg.rtm.rtm_msglen = l;

  if ((l = write(p->sys.sk->fd, (char *)&msg, l)) < 0) {
    log(L_ERR "KRT: Error sending route %N to kernel: %m", net->n.addr);
    return -1;
  }

  return 0;
}

void
krt_replace_rte(struct krt_proto *p, net *n, rte *new, rte *old)
{
  int err = 0;

  if (old)
    krt_send_route(p, RTM_DELETE, old);

  if (new)
    err = krt_send_route(p, RTM_ADD, new);

  if (new)
  {
    if (err < 0)
      bmap_clear(&p->sync_map, new->id);
    else
      bmap_set(&p->sync_map, new->id);
  }
}

#define SKIP(ARG...) do { DBG("KRT: Ignoring route - " ARG); return; } while(0)

static void
krt_read_route(struct ks_msg *msg, struct krt_proto *p, int scan)
{
  /* p is NULL iff KRT_SHARED_SOCKET and !scan */

  int ipv6;
  rte *e;
  net *net;
  sockaddr dst, gate, mask;
  ip_addr idst, igate, imask;
  net_addr ndst;
  void *body = (char *)msg->buf;
  int new = (msg->rtm.rtm_type != RTM_DELETE);
  char *errmsg = "KRT: Invalid route received";
  int flags = msg->rtm.rtm_flags;
  int addrs = msg->rtm.rtm_addrs;
  int src;
  byte src2;

  if (!(flags & RTF_UP) && scan)
    SKIP("not up in scan\n");

  if (!(flags & RTF_DONE) && !scan)
    SKIP("not done in async\n");

  if (flags & RTF_LLINFO)
    SKIP("link-local\n");

  GETADDR(&dst, RTA_DST);
  GETADDR(&gate, RTA_GATEWAY);
  GETADDR(&mask, RTA_NETMASK);

  switch (dst.sa.sa_family) {
    case AF_INET:
      ipv6 = 0;
      break;
    case AF_INET6:
      ipv6 = 1;
      break;
    default:
      SKIP("invalid DST");
  }

  /* We do not test family for RTA_NETMASK, because BSD sends us
     some strange values, but interpreting them as IPv4/IPv6 works */
  mask.sa.sa_family = dst.sa.sa_family;

  idst  = ipa_from_sa(&dst);
  imask = ipa_from_sa(&mask);
  igate = (gate.sa.sa_family == dst.sa.sa_family) ? ipa_from_sa(&gate) : IPA_NONE;

#ifdef KRT_SHARED_SOCKET
  if (!scan)
  {
    int table_id = msg->rtm.rtm_tableid;
    p = (table_id < KRT_MAX_TABLES) ? krt_table_map[table_id][ipv6] : NULL;

    if (!p)
      SKIP("unknown table id %d\n", table_id);
  }
#endif
  if ((!ipv6) && (p->p.main_channel->table->addr_type != NET_IP4))
    SKIP("reading only IPv4 routes");
  if (  ipv6  && (p->p.main_channel->table->addr_type != NET_IP6))
    SKIP("reading only IPv6 routes");

  int c = ipa_classify_net(idst);
  if ((c < 0) || !(c & IADDR_HOST) || ((c & IADDR_SCOPE_MASK) <= SCOPE_LINK))
    SKIP("strange class/scope\n");

  int pxlen;
  if (ipv6)
    pxlen = (flags & RTF_HOST) ? IP6_MAX_PREFIX_LENGTH : ip6_masklen(&ipa_to_ip6(imask));
  else
    pxlen = (flags & RTF_HOST) ? IP4_MAX_PREFIX_LENGTH : ip4_masklen(ipa_to_ip4(imask));

  if (pxlen < 0)
    { log(L_ERR "%s (%I) - netmask %I", errmsg, idst, imask); return; }

  if (ipv6)
    net_fill_ip6(&ndst, ipa_to_ip6(idst), pxlen);
  else
    net_fill_ip4(&ndst, ipa_to_ip4(idst), pxlen);

  if ((flags & RTF_GATEWAY) && ipa_zero(igate))
    { log(L_ERR "%s (%N) - missing gateway", errmsg, ndst); return; }

  u32 self_mask = RTF_PROTO1;
  u32 alien_mask = RTF_STATIC | RTF_PROTO1 | RTF_GATEWAY;

  src2 = (flags & RTF_STATIC) ? 1 : 0;
  src2 |= (flags & RTF_PROTO1) ? 2 : 0;

#ifdef RTF_PROTO2
  alien_mask |= RTF_PROTO2;
  src2 |= (flags & RTF_PROTO2) ? 4 : 0;
#endif

#ifdef RTF_PROTO3
  alien_mask |= RTF_PROTO3;
  src2 |= (flags & RTF_PROTO3) ? 8 : 0;
#endif

#ifdef RTF_REJECT
  alien_mask |= RTF_REJECT;
#endif

#ifdef RTF_BLACKHOLE
  alien_mask |= RTF_BLACKHOLE;
#endif

  if (flags & (RTF_DYNAMIC | RTF_MODIFIED))
    src = KRT_SRC_REDIRECT;
  else if (flags & self_mask)
    {
      if (!scan)
	SKIP("echo\n");
      src = KRT_SRC_BIRD;
    }
  else if (flags & alien_mask)
    src = KRT_SRC_ALIEN;
  else
    src = KRT_SRC_KERNEL;

  net = net_get(p->p.main_channel->table, &ndst);

  rta a = {
    .src = p->p.main_source,
    .source = RTS_INHERIT,
    .scope = SCOPE_UNIVERSE,
  };

  /* reject/blackhole routes have also set RTF_GATEWAY,
     we wil check them first. */

#ifdef RTF_REJECT
  if(flags & RTF_REJECT) {
    a.dest = RTD_UNREACHABLE;
    goto done;
  }
#endif

#ifdef RTF_BLACKHOLE
  if(flags & RTF_BLACKHOLE) {
    a.dest = RTD_BLACKHOLE;
    goto done;
  }
#endif

  a.nh.iface = if_find_by_index(msg->rtm.rtm_index);
  if (!a.nh.iface)
    {
      log(L_ERR "KRT: Received route %N with unknown ifindex %u",
	  net->n.addr, msg->rtm.rtm_index);
      return;
    }

  a.dest = RTD_UNICAST;
  if (flags & RTF_GATEWAY)
  {
    neighbor *ng;
    a.nh.gw = igate;

    /* Clean up embedded interface ID returned in link-local address */
    if (ipa_is_link_local(a.nh.gw))
      _I0(a.nh.gw) = 0xfe800000;

    ng = neigh_find(&p->p, a.nh.gw, a.nh.iface, 0);
    if (!ng || (ng->scope == SCOPE_HOST))
      {
	/* Ignore routes with next-hop 127.0.0.1, host routes with such
	   next-hop appear on OpenBSD for address aliases. */
        if (ipa_classify(a.nh.gw) == (IADDR_HOST | SCOPE_HOST))
          return;

	log(L_ERR "KRT: Received route %N with strange next-hop %I",
	    net->n.addr, a.nh.gw);
	return;
      }
  }

 done:
  e = rte_get_temp(&a);
  e->net = net;
  e->u.krt.src = src;
  e->u.krt.proto = src2;
  e->u.krt.seen = 0;
  e->u.krt.best = 0;
  e->u.krt.metric = 0;

  if (scan)
    krt_got_route(p, e);
  else
    krt_got_route_async(p, e, new);
}

static void
krt_read_ifannounce(struct ks_msg *msg)
{
  struct if_announcemsghdr *ifam = (struct if_announcemsghdr *)&msg->rtm;

  if (ifam->ifan_what == IFAN_ARRIVAL)
  {
    /* Not enough info to create the iface, so we just trigger iface scan */
    kif_request_scan();
  }
  else if (ifam->ifan_what == IFAN_DEPARTURE)
  {
    struct iface *iface = if_find_by_index(ifam->ifan_index);

    /* Interface is destroyed */
    if (!iface)
    {
      DBG("KRT: unknown interface (%s, #%d) going down. Ignoring\n", ifam->ifan_name, ifam->ifan_index);
      return;
    }

    if_delete(iface);
  }

  DBG("KRT: IFANNOUNCE what: %d index %d name %s\n", ifam->ifan_what, ifam->ifan_index, ifam->ifan_name);
}

static void
krt_read_ifinfo(struct ks_msg *msg, int scan)
{
  struct if_msghdr *ifm = (struct if_msghdr *)&msg->rtm;
  void *body = (void *)(ifm + 1);
  struct sockaddr_dl *dl = NULL;
  uint i;
  struct iface *iface = NULL, f = {};
  int fl = ifm->ifm_flags;
  int nlen = 0;

  for (i = 1; i<=RTA_IFP; i <<= 1)
  {
    if (i & ifm->ifm_addrs)
    {
      if (i == RTA_IFP)
      {
        dl = (struct sockaddr_dl *)body;
        break;
      }
      body += ROUNDUP(((struct sockaddr *)&(body))->sa_len);
    }
  }

  if (dl && (dl->sdl_family != AF_LINK))
  {
    log(L_WARN "Ignoring strange IFINFO");
    return;
  }

  if (dl)
    nlen = MIN(sizeof(f.name)-1, dl->sdl_nlen);

  /* Note that asynchronous IFINFO messages do not contain iface
     name, so we have to found an existing iface by iface index */

  iface = if_find_by_index(ifm->ifm_index);
  if (!iface)
  {
    /* New interface */
    if (!dl)
      return;	/* No interface name, ignoring */

    memcpy(f.name, dl->sdl_data, nlen);
    DBG("New interface '%s' found\n", f.name);
  }
  else if (dl && memcmp(iface->name, dl->sdl_data, nlen))
  {
    /* Interface renamed */
    if_delete(iface);
    memcpy(f.name, dl->sdl_data, nlen);
  }
  else
  {
    /* Old interface */
    memcpy(f.name, iface->name, sizeof(f.name));
  }

  f.index = ifm->ifm_index;
  f.mtu = ifm->ifm_data.ifi_mtu;

  if (fl & IFF_UP)
    f.flags |= IF_ADMIN_UP;
  if (ifm->ifm_data.ifi_link_state != LINK_STATE_DOWN)
    f.flags |= IF_LINK_UP;          /* up or unknown */
  if (fl & IFF_LOOPBACK)            /* Loopback */
    f.flags |= IF_MULTIACCESS | IF_LOOPBACK | IF_IGNORE;
  else if (fl & IFF_POINTOPOINT)    /* PtP */
    f.flags |= IF_MULTICAST;
  else if (fl & IFF_BROADCAST)      /* Broadcast */
    f.flags |= IF_MULTIACCESS | IF_BROADCAST | IF_MULTICAST;
  else
    f.flags |= IF_MULTIACCESS;      /* NBMA */

  iface = if_update(&f);

  if (!scan)
    if_end_partial_update(iface);
}

static void
krt_read_addr(struct ks_msg *msg, int scan)
{
  struct ifa_msghdr *ifam = (struct ifa_msghdr *)&msg->rtm;
  void *body = (void *)(ifam + 1);
  sockaddr addr, mask, brd;
  struct iface *iface = NULL;
  struct ifa ifa;
  struct sockaddr null;
  ip_addr iaddr, imask, ibrd;
  int addrs = ifam->ifam_addrs;
  int scope, masklen = -1;
  int new = (ifam->ifam_type == RTM_NEWADDR);

  /* Strange messages with zero (invalid) ifindex appear on OpenBSD */
  if (ifam->ifam_index == 0)
    return;

  if(!(iface = if_find_by_index(ifam->ifam_index)))
  {
    log(L_ERR "KIF: Received address message for unknown interface %d", ifam->ifam_index);
    return;
  }

  GETADDR (&null, RTA_DST);
  GETADDR (&null, RTA_GATEWAY);
  GETADDR (&mask, RTA_NETMASK);
  GETADDR (&null, RTA_GENMASK);
  GETADDR (&null, RTA_IFP);
  GETADDR (&addr, RTA_IFA);
  GETADDR (&null, RTA_AUTHOR);
  GETADDR (&brd, RTA_BRD);

  /* Is addr family IP4 or IP6? */
  int ipv6;
  switch (addr.sa.sa_family) {
    case AF_INET: ipv6 = 0; break;
    case AF_INET6: ipv6 = 1; break;
    default: return;
  }

  /* We do not test family for RTA_NETMASK, because BSD sends us
     some strange values, but interpreting them as IPv4/IPv6 works */
  mask.sa.sa_family = addr.sa.sa_family;

  iaddr = ipa_from_sa(&addr);
  imask = ipa_from_sa(&mask);
  ibrd  = ipa_from_sa(&brd);

  if ((ipv6 ? (masklen = ip6_masklen(&ipa_to_ip6(imask))) : (masklen = ip4_masklen(ipa_to_ip4(imask)))) < 0)
  {
    log(L_ERR "KIF: Invalid mask %I for %s", imask, iface->name);
    return;
  }

  /* Clean up embedded interface ID returned in link-local address */

  if (ipa_is_link_local(iaddr))
    _I0(iaddr) = 0xfe800000;

  if (ipa_is_link_local(ibrd))
    _I0(ibrd) = 0xfe800000;


  bzero(&ifa, sizeof(ifa));
  ifa.iface = iface;
  ifa.ip = iaddr;

  scope = ipa_classify(ifa.ip);
  if (scope < 0)
  {
    log(L_ERR "KIF: Invalid interface address %I for %s", ifa.ip, iface->name);
    return;
  }
  ifa.scope = scope & IADDR_SCOPE_MASK;

  if (masklen < (ipv6 ? IP6_MAX_PREFIX_LENGTH : IP4_MAX_PREFIX_LENGTH))
  {
    net_fill_ipa(&ifa.prefix, ifa.ip, masklen);
    net_normalize(&ifa.prefix);

    if (masklen == ((ipv6 ? IP6_MAX_PREFIX_LENGTH : IP4_MAX_PREFIX_LENGTH) - 1))
      ifa.opposite = ipa_opposite_m1(ifa.ip);

    if ((!ipv6) && (masklen == IP4_MAX_PREFIX_LENGTH - 2))
      ifa.opposite = ipa_opposite_m2(ifa.ip);

    if (iface->flags & IF_BROADCAST)
      ifa.brd = ibrd;

    if (!(iface->flags & IF_MULTIACCESS))
      ifa.opposite = ibrd;
  }
  else if (!(iface->flags & IF_MULTIACCESS) && ipa_nonzero(ibrd))
  {
    net_fill_ipa(&ifa.prefix, ibrd, (ipv6 ? IP6_MAX_PREFIX_LENGTH : IP4_MAX_PREFIX_LENGTH));
    ifa.opposite = ibrd;
    ifa.flags |= IA_PEER;
  }
  else
  {
    net_fill_ipa(&ifa.prefix, ifa.ip, (ipv6 ? IP6_MAX_PREFIX_LENGTH : IP4_MAX_PREFIX_LENGTH));
    ifa.flags |= IA_HOST;
  }

  if (new)
    ifa_update(&ifa);
  else
    ifa_delete(&ifa);

  if (!scan)
    if_end_partial_update(iface);
}

static void
krt_read_msg(struct proto *p, struct ks_msg *msg, int scan)
{
  /* p is NULL iff KRT_SHARED_SOCKET and !scan */

  switch (msg->rtm.rtm_type)
  {
    case RTM_GET:
      if(!scan) return;
    case RTM_ADD:
    case RTM_DELETE:
    case RTM_CHANGE:
      krt_read_route(msg, (struct krt_proto *)p, scan);
      break;
    case RTM_IFANNOUNCE:
      krt_read_ifannounce(msg);
      break;
    case RTM_IFINFO:
      krt_read_ifinfo(msg, scan);
      break;
    case RTM_NEWADDR:
    case RTM_DELADDR:
      krt_read_addr(msg, scan);
      break;
    default:
      break;
  }
}


/* Sysctl based scans */

static byte *krt_buffer;
static size_t krt_buflen, krt_bufmin;
static struct proto *krt_buffer_owner;

static byte *
krt_buffer_update(struct proto *p, size_t *needed)
{
  size_t req = *needed;

  if ((req > krt_buflen) ||
      ((p == krt_buffer_owner) && (req < krt_bufmin)))
  {
    /* min buflen is 32 kB, step is 8 kB, or 128 kB if > 1 MB */
    size_t step = (req < 0x100000) ? 0x2000 : 0x20000;
    krt_buflen = (req < 0x6000) ? 0x8000 : (req + step);
    krt_bufmin = (req < 0x8000) ? 0 : (req - 2*step);

    if (krt_buffer) 
      mb_free(krt_buffer);
    krt_buffer = mb_alloc(krt_pool, krt_buflen);
    krt_buffer_owner = p;
  }

  *needed = krt_buflen;
  return krt_buffer;
}

static void
krt_buffer_release(struct proto *p)
{
  if (p == krt_buffer_owner)
  {
    mb_free(krt_buffer);
    krt_buffer = NULL;
    krt_buflen = 0;
    krt_buffer_owner = 0;
  }
}

static void
krt_sysctl_scan(struct proto *p, int cmd, int table_id)
{
  byte *buf, *next;
  int mib[7], mcnt;
  size_t needed;
  struct ks_msg *m;
  int retries = 3;
  int rv;

  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = 0; // Set AF to 0 for all available families
  mib[4] = cmd;
  mib[5] = 0;
  mcnt = 6;

#ifdef KRT_USE_SYSCTL_7
  if (table_id >= 0)
  {
    mib[6] = table_id;
    mcnt = 7;
  }
#endif

#ifdef KRT_USE_SETFIB_SCAN
  if (table_id > 0)
    if (setfib(table_id) < 0)
    {
      log(L_ERR "KRT: setfib(%d) failed: %m", table_id);
      return;
    }
#endif

 try:
  rv = sysctl(mib, mcnt, NULL, &needed, NULL, 0);
  if (rv < 0)
  {
    /* OpenBSD returns EINVAL for not yet used tables */
    if ((errno == EINVAL) && (table_id > 0))
      goto exit;

    log(L_ERR "KRT: Route scan estimate failed: %m");
    goto exit;
  }

  /* The table is empty */
  if (needed == 0)
    goto exit;

  buf = krt_buffer_update(p, &needed);

  rv = sysctl(mib, mcnt, buf, &needed, NULL, 0);
  if (rv < 0)
  {
    /* The buffer size changed since last sysctl ('needed' is not changed) */
    if ((errno == ENOMEM) && retries--)
      goto try;

    log(L_ERR "KRT: Route scan failed: %m");
    goto exit;
  }

#ifdef KRT_USE_SETFIB_SCAN
  if (table_id > 0)
    if (setfib(0) < 0)
      die("KRT: setfib(%d) failed: %m", 0);
#endif

  /* Process received messages */
  for (next = buf; next < (buf + needed); next += m->rtm.rtm_msglen)
  {
    m = (struct ks_msg *)next;
    krt_read_msg(p, m, 1);
  }

  return;

 exit:
  krt_buffer_release(p);

#ifdef KRT_USE_SETFIB_SCAN
  if (table_id > 0)
    if (setfib(0) < 0)
      die("KRT: setfib(%d) failed: %m", 0);
#endif
}

void
krt_do_scan(struct krt_proto *p)
{
  krt_sysctl_scan(&p->p, NET_RT_DUMP, KRT_CF->sys.table_id);
}

void
kif_do_scan(struct kif_proto *p)
{
  if_start_update();
  krt_sysctl_scan(&p->p, NET_RT_IFLIST, -1);
  if_end_update();
}


/* Kernel sockets */

static int
krt_sock_hook(sock *sk, uint size UNUSED)
{
  struct ks_msg msg;
  int l = read(sk->fd, (char *)&msg, sizeof(msg));

  if (l <= 0)
    log(L_ERR "krt-sock: read failed");
  else
    krt_read_msg((struct proto *) sk->data, &msg, 0);

  return 0;
}

static void
krt_sock_err_hook(sock *sk, int e UNUSED)
{
  krt_sock_hook(sk, 0);
}

static sock *
krt_sock_open(pool *pool, void *data, int table_id UNUSED)
{
  sock *sk;
  int fd;

  fd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
  if (fd < 0)
    die("Cannot open kernel socket for routes");

#ifdef KRT_USE_SETFIB_SOCK
  if (table_id > 0)
  {
    if (setsockopt(fd, SOL_SOCKET, SO_SETFIB, &table_id, sizeof(table_id)) < 0)
      die("Cannot set FIB %d for kernel socket: %m", table_id);
  }
#endif

  sk = sk_new(pool);
  sk->type = SK_MAGIC;
  sk->rx_hook = krt_sock_hook;
  sk->err_hook = krt_sock_err_hook;
  sk->fd = fd;
  sk->data = data;

  if (sk_open(sk) < 0)
    bug("krt-sock: sk_open failed");

  return sk;
}

static u32 krt_table_cf[(KRT_MAX_TABLES+31) / 32][2];

#ifdef KRT_SHARED_SOCKET

static sock *krt_sock;
static int krt_sock_count;


static void
krt_sock_open_shared(void)
{
  if (!krt_sock_count)
    krt_sock = krt_sock_open(krt_pool, NULL, -1);
  
  krt_sock_count++;
}

static void
krt_sock_close_shared(void)
{
  krt_sock_count--;

  if (!krt_sock_count)
  {
    rfree(krt_sock);
    krt_sock = NULL;
  }
}

int
krt_sys_start(struct krt_proto *p)
{
  int id = KRT_CF->sys.table_id;

  if (krt_table_cf[id/32][!!(p->af == AF_INET6)] & (1 << (id%32)))
    {
      log(L_ERR "%s: Multiple kernel syncers defined for table #%d", p->p.name, id);
      return 0;
    }

  krt_table_cf[id/32][!!(p->af == AF_INET6)] |= (1 << (id%32));

  krt_table_map[KRT_CF->sys.table_id][!!(p->af == AF_INET6)] = p;

  krt_sock_open_shared();
  p->sys.sk = krt_sock;

  return 1;
}

void
krt_sys_shutdown(struct krt_proto *p)
{
  krt_table_cf[(KRT_CF->sys.table_id)/32][!!(p->af == AF_INET6)] &= ~(1 << ((KRT_CF->sys.table_id)%32));

  krt_sock_close_shared();
  p->sys.sk = NULL;

  krt_table_map[KRT_CF->sys.table_id][!!(p->af == AF_INET6)] = NULL;

  krt_buffer_release(&p->p);
}

#else

int
krt_sys_start(struct krt_proto *p)
{
  int id = KRT_CF->sys.table_id;

  if (krt_table_cf[id/32][!!(p->af == AF_INET6)] & (1 << (id%32)))
    {
      log(L_ERR "%s: Multiple kernel syncers defined for table #%d", p->p.name, id);
      return 0;
    }

  krt_table_cf[id/32][!!(p->af == AF_INET6)] |= (1 << (id%32));

  p->sys.sk = krt_sock_open(p->p.pool, p, KRT_CF->sys.table_id);
  return 1;
}

void
krt_sys_shutdown(struct krt_proto *p)
{
  krt_table_cf[(KRT_CF->sys.table_id)/32][!!(p->af == AF_INET6)] &= ~(1 << ((KRT_CF->sys.table_id)%32));

  rfree(p->sys.sk);
  p->sys.sk = NULL;

  krt_buffer_release(&p->p);
}

#endif /* KRT_SHARED_SOCKET */


/* KRT configuration callbacks */

int
krt_sys_reconfigure(struct krt_proto *p UNUSED, struct krt_config *n, struct krt_config *o)
{
  return n->sys.table_id == o->sys.table_id;
}

void
krt_sys_preconfig(struct config *c UNUSED)
{
  krt_max_tables = krt_get_max_tables();
  bzero(&krt_table_cf, sizeof(krt_table_cf));
}

void krt_sys_init_config(struct krt_config *c)
{
  c->sys.table_id = 0; /* Default table */
}

void krt_sys_copy_config(struct krt_config *d, struct krt_config *s)
{
  d->sys.table_id = s->sys.table_id;
}


/* KIF misc code */

void
kif_sys_start(struct kif_proto *p UNUSED)
{
}

void
kif_sys_shutdown(struct kif_proto *p)
{
  krt_buffer_release(&p->p);
}

int
kif_update_sysdep_addr(struct iface *i)
{
  static int fd = -1;

  if (fd < 0)
    fd = socket(AF_INET, SOCK_DGRAM, 0);

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, i->name, IFNAMSIZ);

  int rv = ioctl(fd, SIOCGIFADDR, (char *) &ifr);
  if (rv < 0)
    return 0;

  ip4_addr old = i->sysdep;
  i->sysdep = ipa_to_ip4(ipa_from_sa4(&ifr.ifr_addr));

  return !ip4_equal(i->sysdep, old);
}
