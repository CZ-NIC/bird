/*
 *	BIRD -- Linux Netlink Interface
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/alloca.h"
#include "sysdep/unix/unix.h"
#include "sysdep/unix/krt.h"
#include "lib/socket.h"
#include "lib/string.h"
#include "lib/hash.h"
#include "conf/conf.h"

#include CONFIG_INCLUDE_NLSYS_H

#define krt_ipv4(p) ((p)->af == AF_INET)

const int rt_default_ecmp = 16;

struct nl_parse_state
{
  struct krt_proto *proto;
  struct linpool *pool;
  int scan;

  u32 rta_flow;
};

/*
 *	Synchronous Netlink interface
 */

struct nl_sock
{
  int fd;
  u32 seq;
  byte *rx_buffer;			/* Receive buffer */
  struct nlmsghdr *last_hdr;		/* Recently received packet */
  uint last_size;
};

#define NL_RX_SIZE 32768

#define NL_OP_DELETE	0
#define NL_OP_ADD	(NLM_F_CREATE|NLM_F_EXCL)
#define NL_OP_REPLACE	(NLM_F_CREATE|NLM_F_REPLACE)
#define NL_OP_APPEND	(NLM_F_CREATE|NLM_F_APPEND)

static linpool *nl_linpool;

static struct nl_sock nl_scan = {.fd = -1};	/* Netlink socket for synchronous scan */
static struct nl_sock nl_req  = {.fd = -1};	/* Netlink socket for requests */

static void
nl_open_sock(struct nl_sock *nl)
{
  if (nl->fd < 0)
    {
      nl->fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
      if (nl->fd < 0)
	die("Unable to open rtnetlink socket: %m");
      nl->seq = (u32) (current_time() TO_S); /* Or perhaps random_u32() ? */
      nl->rx_buffer = xmalloc(NL_RX_SIZE);
      nl->last_hdr = NULL;
      nl->last_size = 0;
    }
}

static int
nl_set_strict_dump(struct nl_sock *nl UNUSED, int strict UNUSED)
{
#ifdef SOL_NETLINK
  return setsockopt(nl->fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &strict, sizeof(strict));
#else
  return -1;
#endif
}

static void
nl_set_rcvbuf(int fd, uint val)
{
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &val, sizeof(val)) < 0)
    log(L_WARN "KRT: Cannot set netlink rx buffer size to %u: %m", val);
}

static uint
nl_cfg_rx_buffer_size(struct config *cfg)
{
  uint bufsize = 0;

  struct proto_config *pc;
  WALK_LIST(pc, cfg->protos)
    if ((pc->protocol == &proto_unix_kernel) && !pc->disabled)
      bufsize = MAX(bufsize, ((struct krt_config *) pc)->sys.netlink_rx_buffer);

  return bufsize;
}


static void
nl_open(void)
{
  if ((nl_scan.fd >= 0) && (nl_req.fd >= 0))
    return;

  nl_open_sock(&nl_scan);
  nl_open_sock(&nl_req);

  if (nl_set_strict_dump(&nl_scan, 1) < 0)
  {
    log(L_WARN "KRT: Netlink strict checking failed, will scan all tables at once");
    krt_use_shared_scan();
  }
}

static void
nl_send(struct nl_sock *nl, struct nlmsghdr *nh)
{
  struct sockaddr_nl sa;

  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  nh->nlmsg_pid = 0;
  nh->nlmsg_seq = ++(nl->seq);
  nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len);
  if (sendto(nl->fd, nh, nh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    die("rtnetlink sendto: %m");
  nl->last_hdr = NULL;
}

static void
nl_request_dump_link(void)
{
  struct {
    struct nlmsghdr nh;
    struct ifinfomsg ifi;
  } req = {
    .nh.nlmsg_type = RTM_GETLINK,
    .nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
    .nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
    .nh.nlmsg_seq = ++(nl_scan.seq),
    .ifi.ifi_family = AF_UNSPEC,
  };

  send(nl_scan.fd, &req, sizeof(req), 0);
  nl_scan.last_hdr = NULL;
}

static void
nl_request_dump_addr(int af)
{
  struct {
    struct nlmsghdr nh;
    struct ifaddrmsg ifa;
  } req = {
    .nh.nlmsg_type = RTM_GETADDR,
    .nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
    .nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
    .nh.nlmsg_seq = ++(nl_scan.seq),
    .ifa.ifa_family = af,
  };

  send(nl_scan.fd, &req, sizeof(req), 0);
  nl_scan.last_hdr = NULL;
}

static void
nl_request_dump_route(int af, int table_id)
{
  struct {
    struct nlmsghdr nh;
    struct rtmsg rtm;
    struct rtattr rta;
    u32 table_id;
  } req = {
    .nh.nlmsg_type = RTM_GETROUTE,
    .nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
    .nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
    .nh.nlmsg_seq = ++(nl_scan.seq),
    .rtm.rtm_family = af,
  };

  if (table_id < 256)
    req.rtm.rtm_table = table_id;
  else
  {
    req.rta.rta_type = RTA_TABLE;
    req.rta.rta_len = RTA_LENGTH(4);
    req.table_id = table_id;
    req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + req.rta.rta_len;
  }

  send(nl_scan.fd, &req, req.nh.nlmsg_len, 0);
  nl_scan.last_hdr = NULL;
}


static struct nlmsghdr *
nl_get_reply(struct nl_sock *nl)
{
  for(;;)
    {
      if (!nl->last_hdr)
	{
	  struct iovec iov = { nl->rx_buffer, NL_RX_SIZE };
	  struct sockaddr_nl sa;
	  struct msghdr m = {
	    .msg_name = &sa,
	    .msg_namelen = sizeof(sa),
	    .msg_iov = &iov,
	    .msg_iovlen = 1,
	  };
	  int x = recvmsg(nl->fd, &m, 0);
	  if (x < 0)
	    die("nl_get_reply: %m");
	  if (sa.nl_pid)		/* It isn't from the kernel */
	    {
	      DBG("Non-kernel packet\n");
	      continue;
	    }
	  nl->last_size = x;
	  nl->last_hdr = (void *) nl->rx_buffer;
	  if (m.msg_flags & MSG_TRUNC)
	    bug("nl_get_reply: got truncated reply which should be impossible");
	}
      if (NLMSG_OK(nl->last_hdr, nl->last_size))
	{
	  struct nlmsghdr *h = nl->last_hdr;
	  nl->last_hdr = NLMSG_NEXT(h, nl->last_size);
	  if (h->nlmsg_seq != nl->seq)
	    {
	      log(L_WARN "nl_get_reply: Ignoring out of sequence netlink packet (%x != %x)",
		  h->nlmsg_seq, nl->seq);
	      continue;
	    }
	  return h;
	}
      if (nl->last_size)
	log(L_WARN "nl_get_reply: Found packet remnant of size %d", nl->last_size);
      nl->last_hdr = NULL;
    }
}

static struct tbf rl_netlink_err = TBF_DEFAULT_LOG_LIMITS;

static int
nl_error(struct nlmsghdr *h, int ignore_esrch)
{
  struct nlmsgerr *e;
  int ec;

  if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
    {
      log(L_WARN "Netlink: Truncated error message received");
      return ENOBUFS;
    }
  e = (struct nlmsgerr *) NLMSG_DATA(h);
  ec = netlink_error_to_os(e->error);
  if (ec && !(ignore_esrch && (ec == ESRCH)))
    log_rl(&rl_netlink_err, L_WARN "Netlink: %s", strerror(ec));
  return ec;
}

static struct nlmsghdr *
nl_get_scan(void)
{
  struct nlmsghdr *h = nl_get_reply(&nl_scan);

  if (h->nlmsg_type == NLMSG_DONE)
    return NULL;
  if (h->nlmsg_type == NLMSG_ERROR)
    {
      nl_error(h, 0);
      return NULL;
    }
  return h;
}

static int
nl_exchange(struct nlmsghdr *pkt, int ignore_esrch)
{
  struct nlmsghdr *h;

  nl_send(&nl_req, pkt);
  for(;;)
    {
      h = nl_get_reply(&nl_req);
      if (h->nlmsg_type == NLMSG_ERROR)
	break;
      log(L_WARN "nl_exchange: Unexpected reply received");
    }
  return nl_error(h, ignore_esrch) ? -1 : 0;
}

/*
 *	Netlink attributes
 */

static int nl_attr_len;

static void *
nl_checkin(struct nlmsghdr *h, int lsize)
{
  nl_attr_len = h->nlmsg_len - NLMSG_LENGTH(lsize);
  if (nl_attr_len < 0)
    {
      log(L_ERR "nl_checkin: underrun by %d bytes", -nl_attr_len);
      return NULL;
    }
  return NLMSG_DATA(h);
}

struct nl_want_attrs {
  u8 defined:1;
  u8 checksize:1;
  u8 size;
};


#define BIRD_IFLA_MAX (IFLA_LINKINFO+1)

static struct nl_want_attrs ifla_attr_want[BIRD_IFLA_MAX] = {
  [IFLA_IFNAME]	  = { 1, 0, 0 },
  [IFLA_MTU]	  = { 1, 1, sizeof(u32) },
  [IFLA_MASTER]	  = { 1, 1, sizeof(u32) },
  [IFLA_WIRELESS] = { 1, 0, 0 },
  [IFLA_LINKINFO] = { 1, 0, 0 },
};

#define BIRD_INFO_MAX (IFLA_INFO_DATA+1)

static struct nl_want_attrs ifinfo_attr_want[BIRD_INFO_MAX] = {
  [IFLA_INFO_KIND]= { 1, 0, 0 },
  [IFLA_INFO_DATA]= { 1, 0, 0 },
};


#define BIRD_IFA_MAX  (IFA_FLAGS+1)

static struct nl_want_attrs ifa_attr_want4[BIRD_IFA_MAX] = {
  [IFA_ADDRESS]	  = { 1, 1, sizeof(ip4_addr) },
  [IFA_LOCAL]	  = { 1, 1, sizeof(ip4_addr) },
  [IFA_BROADCAST] = { 1, 1, sizeof(ip4_addr) },
  [IFA_FLAGS]     = { 1, 1, sizeof(u32) },
};

static struct nl_want_attrs ifa_attr_want6[BIRD_IFA_MAX] = {
  [IFA_ADDRESS]	  = { 1, 1, sizeof(ip6_addr) },
  [IFA_LOCAL]	  = { 1, 1, sizeof(ip6_addr) },
  [IFA_FLAGS]	  = { 1, 1, sizeof(u32) },
};


#define BIRD_RTA_MAX  (RTA_ENCAP+1)

static struct nl_want_attrs nexthop_attr_want4[BIRD_RTA_MAX] = {
  [RTA_GATEWAY]	  = { 1, 1, sizeof(ip4_addr) },
  [RTA_VIA]	  = { 1, 0, 0 },
  [RTA_FLOW]	  = { 1, 1, sizeof(u32) },
  [RTA_ENCAP_TYPE]= { 1, 1, sizeof(u16) },
  [RTA_ENCAP]	  = { 1, 0, 0 },
};

static struct nl_want_attrs nexthop_attr_want6[BIRD_RTA_MAX] = {
  [RTA_GATEWAY]	  = { 1, 1, sizeof(ip6_addr) },
  [RTA_VIA]	  = { 1, 0, 0 },
  [RTA_FLOW]	  = { 1, 1, sizeof(u32) },
  [RTA_ENCAP_TYPE]= { 1, 1, sizeof(u16) },
  [RTA_ENCAP]	  = { 1, 0, 0 },
};

#ifdef HAVE_MPLS_KERNEL
static struct nl_want_attrs nexthop_attr_want_mpls[BIRD_RTA_MAX] = {
  [RTA_VIA]	  = { 1, 0, 0 },
  [RTA_NEWDST]	  = { 1, 0, 0 },
};

static struct nl_want_attrs encap_mpls_want[BIRD_RTA_MAX] = {
  [RTA_DST]       = { 1, 0, 0 },
};
#endif

static struct nl_want_attrs rtm_attr_want4[BIRD_RTA_MAX] = {
  [RTA_DST]	  = { 1, 1, sizeof(ip4_addr) },
  [RTA_OIF]	  = { 1, 1, sizeof(u32) },
  [RTA_GATEWAY]	  = { 1, 1, sizeof(ip4_addr) },
  [RTA_PRIORITY]  = { 1, 1, sizeof(u32) },
  [RTA_PREFSRC]	  = { 1, 1, sizeof(ip4_addr) },
  [RTA_METRICS]	  = { 1, 0, 0 },
  [RTA_MULTIPATH] = { 1, 0, 0 },
  [RTA_FLOW]	  = { 1, 1, sizeof(u32) },
  [RTA_TABLE]	  = { 1, 1, sizeof(u32) },
  [RTA_VIA]	  = { 1, 0, 0 },
  [RTA_ENCAP_TYPE]= { 1, 1, sizeof(u16) },
  [RTA_ENCAP]	  = { 1, 0, 0 },
};

static struct nl_want_attrs rtm_attr_want6[BIRD_RTA_MAX] = {
  [RTA_DST]	  = { 1, 1, sizeof(ip6_addr) },
  [RTA_SRC]	  = { 1, 1, sizeof(ip6_addr) },
  [RTA_IIF]	  = { 1, 1, sizeof(u32) },
  [RTA_OIF]	  = { 1, 1, sizeof(u32) },
  [RTA_GATEWAY]	  = { 1, 1, sizeof(ip6_addr) },
  [RTA_PRIORITY]  = { 1, 1, sizeof(u32) },
  [RTA_PREFSRC]	  = { 1, 1, sizeof(ip6_addr) },
  [RTA_METRICS]	  = { 1, 0, 0 },
  [RTA_MULTIPATH] = { 1, 0, 0 },
  [RTA_FLOW]	  = { 1, 1, sizeof(u32) },
  [RTA_TABLE]	  = { 1, 1, sizeof(u32) },
  [RTA_VIA]	  = { 1, 0, 0 },
  [RTA_ENCAP_TYPE]= { 1, 1, sizeof(u16) },
  [RTA_ENCAP]	  = { 1, 0, 0 },
};

#ifdef HAVE_MPLS_KERNEL
static struct nl_want_attrs rtm_attr_want_mpls[BIRD_RTA_MAX] = {
  [RTA_DST]	  = { 1, 1, sizeof(u32) },
  [RTA_IIF]	  = { 1, 1, sizeof(u32) },
  [RTA_OIF]	  = { 1, 1, sizeof(u32) },
  [RTA_PRIORITY]  = { 1, 1, sizeof(u32) },
  [RTA_METRICS]	  = { 1, 0, 0 },
  [RTA_MULTIPATH] = { 1, 0, 0 },
  [RTA_FLOW]	  = { 1, 1, sizeof(u32) },
  [RTA_TABLE]	  = { 1, 1, sizeof(u32) },
  [RTA_VIA]	  = { 1, 0, 0 },
  [RTA_NEWDST]	  = { 1, 0, 0 },
};
#endif


static int
nl_parse_attrs(struct rtattr *a, struct nl_want_attrs *want, struct rtattr **k, int ksize)
{
  int max = ksize / sizeof(struct rtattr *);
  bzero(k, ksize);

  for ( ; RTA_OK(a, nl_attr_len); a = RTA_NEXT(a, nl_attr_len))
    {
      if ((a->rta_type >= max) || !want[a->rta_type].defined)
	continue;

      if (want[a->rta_type].checksize && (RTA_PAYLOAD(a) != want[a->rta_type].size))
	{
	  log(L_ERR "nl_parse_attrs: Malformed attribute received");
	  return 0;
	}

      k[a->rta_type] = a;
    }

  if (nl_attr_len)
    {
      log(L_ERR "nl_parse_attrs: remnant of size %d", nl_attr_len);
      return 0;
    }

  return 1;
}

static inline u16 rta_get_u16(struct rtattr *a)
{ return *(u16 *) RTA_DATA(a); }

static inline u32 rta_get_u32(struct rtattr *a)
{ return *(u32 *) RTA_DATA(a); }

static inline ip4_addr rta_get_ip4(struct rtattr *a)
{ return ip4_ntoh(*(ip4_addr *) RTA_DATA(a)); }

static inline ip6_addr rta_get_ip6(struct rtattr *a)
{ return ip6_ntoh(*(ip6_addr *) RTA_DATA(a)); }

static inline ip_addr rta_get_ipa(struct rtattr *a)
{
  if (RTA_PAYLOAD(a) == sizeof(ip4_addr))
    return ipa_from_ip4(rta_get_ip4(a));
  else
    return ipa_from_ip6(rta_get_ip6(a));
}

static inline ip_addr rta_get_via(struct rtattr *a)
{
  struct rtvia *v = RTA_DATA(a);
  switch(v->rtvia_family) {
    case AF_INET:  return ipa_from_ip4(ip4_ntoh(*(ip4_addr *) v->rtvia_addr));
    case AF_INET6: return ipa_from_ip6(ip6_ntoh(*(ip6_addr *) v->rtvia_addr));
  }
  return IPA_NONE;
}

#ifdef HAVE_MPLS_KERNEL
static u32 rta_mpls_stack[MPLS_MAX_LABEL_STACK];
static inline int rta_get_mpls(struct rtattr *a, u32 *stack)
{
  if (!a)
    return 0;

  if (RTA_PAYLOAD(a) % 4)
    log(L_WARN "KRT: Strange length of received MPLS stack: %u", RTA_PAYLOAD(a));

  int labels = mpls_get(RTA_DATA(a), RTA_PAYLOAD(a) & ~0x3, stack);

  if (labels < 0)
  {
    log(L_WARN "KRT: Too long MPLS stack received, ignoring");
    labels = 0;
  }

  return labels;
}
#endif

struct rtattr *
nl_add_attr(struct nlmsghdr *h, uint bufsize, uint code, const void *data, uint dlen)
{
  uint pos = NLMSG_ALIGN(h->nlmsg_len);
  uint len = RTA_LENGTH(dlen);

  if (pos + len > bufsize)
    bug("nl_add_attr: packet buffer overflow");

  struct rtattr *a = (struct rtattr *)((char *)h + pos);
  a->rta_type = code;
  a->rta_len = len;
  h->nlmsg_len = pos + len;

  if (dlen > 0)
    memcpy(RTA_DATA(a), data, dlen);

  return a;
}

static inline struct rtattr *
nl_open_attr(struct nlmsghdr *h, uint bufsize, uint code)
{
  return nl_add_attr(h, bufsize, code, NULL, 0);
}

static inline void
nl_close_attr(struct nlmsghdr *h, struct rtattr *a)
{
  a->rta_len = (void *)h + NLMSG_ALIGN(h->nlmsg_len) - (void *)a;
}

static inline void
nl_add_attr_u16(struct nlmsghdr *h, uint bufsize, int code, u16 data)
{
  nl_add_attr(h, bufsize, code, &data, 2);
}

static inline void
nl_add_attr_u32(struct nlmsghdr *h, uint bufsize, int code, u32 data)
{
  nl_add_attr(h, bufsize, code, &data, 4);
}

static inline void
nl_add_attr_ip4(struct nlmsghdr *h, uint bufsize, int code, ip4_addr ip4)
{
  ip4 = ip4_hton(ip4);
  nl_add_attr(h, bufsize, code, &ip4, sizeof(ip4));
}

static inline void
nl_add_attr_ip6(struct nlmsghdr *h, uint bufsize, int code, ip6_addr ip6)
{
  ip6 = ip6_hton(ip6);
  nl_add_attr(h, bufsize, code, &ip6, sizeof(ip6));
}

static inline void
nl_add_attr_ipa(struct nlmsghdr *h, uint bufsize, int code, ip_addr ipa)
{
  if (ipa_is_ip4(ipa))
    nl_add_attr_ip4(h, bufsize, code, ipa_to_ip4(ipa));
  else
    nl_add_attr_ip6(h, bufsize, code, ipa_to_ip6(ipa));
}

#ifdef HAVE_MPLS_KERNEL
static inline void
nl_add_attr_mpls(struct nlmsghdr *h, uint bufsize, int code, int len, u32 *stack)
{
  char buf[len*4];
  mpls_put(buf, len, stack);
  nl_add_attr(h, bufsize, code, buf, len*4);
}

static inline void
nl_add_attr_mpls_encap(struct nlmsghdr *h, uint bufsize, int len, u32 *stack)
{
  nl_add_attr_u16(h, bufsize, RTA_ENCAP_TYPE, LWTUNNEL_ENCAP_MPLS);

  struct rtattr *nest = nl_open_attr(h, bufsize, RTA_ENCAP);
  nl_add_attr_mpls(h, bufsize, RTA_DST, len, stack);
  nl_close_attr(h, nest);
}

static inline void
nl_add_attr_via(struct nlmsghdr *h, uint bufsize, ip_addr ipa)
{
  struct rtvia *via = alloca(sizeof(struct rtvia) + 16);

  if (ipa_is_ip4(ipa))
  {
    via->rtvia_family = AF_INET;
    put_ip4(via->rtvia_addr, ipa_to_ip4(ipa));
    nl_add_attr(h, bufsize, RTA_VIA, via, sizeof(struct rtvia) + 4);
  }
  else
  {
    via->rtvia_family = AF_INET6;
    put_ip6(via->rtvia_addr, ipa_to_ip6(ipa));
    nl_add_attr(h, bufsize, RTA_VIA, via, sizeof(struct rtvia) + 16);
  }
}
#endif

static inline struct rtnexthop *
nl_open_nexthop(struct nlmsghdr *h, uint bufsize)
{
  uint pos = NLMSG_ALIGN(h->nlmsg_len);
  uint len = RTNH_LENGTH(0);

  if (pos + len > bufsize)
    bug("nl_open_nexthop: packet buffer overflow");

  h->nlmsg_len = pos + len;

  return (void *)h + pos;
}

static inline void
nl_close_nexthop(struct nlmsghdr *h, struct rtnexthop *nh)
{
  nh->rtnh_len = (void *)h + NLMSG_ALIGN(h->nlmsg_len) - (void *)nh;
}

static inline void
nl_add_nexthop(struct nlmsghdr *h, uint bufsize, struct nexthop *nh, int af UNUSED)
{
#ifdef HAVE_MPLS_KERNEL
  if (nh->labels > 0)
    if (af == AF_MPLS)
      nl_add_attr_mpls(h, bufsize, RTA_NEWDST, nh->labels, nh->label);
    else
      nl_add_attr_mpls_encap(h, bufsize, nh->labels, nh->label);

  if (ipa_nonzero(nh->gw))
  {
    if (af == (ipa_is_ip4(nh->gw) ? AF_INET : AF_INET6))
      nl_add_attr_ipa(h, bufsize, RTA_GATEWAY, nh->gw);
    else
      nl_add_attr_via(h, bufsize, nh->gw);
  }
#else

  if (ipa_nonzero(nh->gw))
    nl_add_attr_ipa(h, bufsize, RTA_GATEWAY, nh->gw);
#endif
}

static void
nl_add_multipath(struct nlmsghdr *h, uint bufsize, struct nexthop *nh, int af, ea_list *eattrs)
{
  struct rtattr *a = nl_open_attr(h, bufsize, RTA_MULTIPATH);
  eattr *flow = ea_find(eattrs, EA_KRT_REALM);

  for (; nh; nh = nh->next)
  {
    struct rtnexthop *rtnh = nl_open_nexthop(h, bufsize);

    rtnh->rtnh_flags = 0;
    rtnh->rtnh_hops = nh->weight;
    rtnh->rtnh_ifindex = nh->iface->index;

    nl_add_nexthop(h, bufsize, nh, af);

    if (nh->flags & RNF_ONLINK)
      rtnh->rtnh_flags |= RTNH_F_ONLINK;

    /* Our KRT_REALM is per-route, but kernel RTA_FLOW is per-nexthop.
       Therefore, we need to attach the same attribute to each nexthop. */
    if (flow)
      nl_add_attr_u32(h, bufsize, RTA_FLOW, flow->u.data);

    nl_close_nexthop(h, rtnh);
  }

  nl_close_attr(h, a);
}

static struct nexthop *
nl_parse_multipath(struct nl_parse_state *s, struct krt_proto *p, const net_addr *n, struct rtattr *ra, int af, int krt_src)
{
  struct rtattr *a[BIRD_RTA_MAX];
  struct rtnexthop *nh = RTA_DATA(ra);
  struct nexthop *rv, *first, **last;
  unsigned len = RTA_PAYLOAD(ra);

  first = NULL;
  last = &first;

  while (len)
    {
      /* Use RTNH_OK(nh,len) ?? */
      if ((len < sizeof(*nh)) || (len < nh->rtnh_len))
	goto err;

      if ((nh->rtnh_flags & RTNH_F_DEAD) && (krt_src != KRT_SRC_BIRD))
	goto next;

      *last = rv = lp_allocz(s->pool, NEXTHOP_MAX_SIZE);
      last = &(rv->next);

      rv->weight = nh->rtnh_hops;
      rv->iface = if_find_by_index(nh->rtnh_ifindex);
      if (!rv->iface)
	{
	  log(L_ERR "KRT: Received route %N with unknown ifindex %u", n, nh->rtnh_ifindex);
	  return NULL;
	}

      /* Nonexistent RTNH_PAYLOAD ?? */
      nl_attr_len = nh->rtnh_len - RTNH_LENGTH(0);
      switch (af)
        {
	case AF_INET:
	  if (!nl_parse_attrs(RTNH_DATA(nh), nexthop_attr_want4, a, sizeof(a)))
	    goto err;
	  break;

	case AF_INET6:
	  if (!nl_parse_attrs(RTNH_DATA(nh), nexthop_attr_want6, a, sizeof(a)))
	    goto err;
	  break;

#ifdef HAVE_MPLS_KERNEL
	case AF_MPLS:
	  if (!nl_parse_attrs(RTNH_DATA(nh), nexthop_attr_want_mpls, a, sizeof(a)))
	    goto err;

	  if (a[RTA_NEWDST])
	    rv->labels = rta_get_mpls(a[RTA_NEWDST], rv->label);

	  break;
#endif

	default:
	  goto err;
	}

      if (a[RTA_GATEWAY])
	rv->gw = rta_get_ipa(a[RTA_GATEWAY]);

      if (a[RTA_FLOW])
	s->rta_flow = rta_get_u32(a[RTA_FLOW]);

      if (a[RTA_VIA])
	rv->gw = rta_get_via(a[RTA_VIA]);

      if (nh->rtnh_flags & RTNH_F_ONLINK)
	rv->flags |= RNF_ONLINK;

      if (ipa_nonzero(rv->gw))
	{
	  neighbor *nbr;
	  nbr = neigh_find(&p->p, rv->gw, rv->iface,
			   (rv->flags & RNF_ONLINK) ? NEF_ONLINK : 0);
	  if (!nbr || (nbr->scope == SCOPE_HOST))
	    {
	        log(L_ERR "KRT: Received route %N with strange next-hop %I", n, rv->gw);
	        return NULL;
	    }
	}

#ifdef HAVE_MPLS_KERNEL
      if (a[RTA_ENCAP] && a[RTA_ENCAP_TYPE])
      {
	if (rta_get_u16(a[RTA_ENCAP_TYPE]) != LWTUNNEL_ENCAP_MPLS)
	{
	  log(L_WARN "KRT: Received route %N with unknown encapsulation method %d",
	      n, rta_get_u16(a[RTA_ENCAP_TYPE]));
	  return NULL;
	}

	struct rtattr *enca[BIRD_RTA_MAX];
	nl_attr_len = RTA_PAYLOAD(a[RTA_ENCAP]);
	nl_parse_attrs(RTA_DATA(a[RTA_ENCAP]), encap_mpls_want, enca, sizeof(enca));
	rv->labels = rta_get_mpls(enca[RTA_DST], rv->label);
      }
#endif

    next:
      len -= NLMSG_ALIGN(nh->rtnh_len);
      nh = RTNH_NEXT(nh);
    }

  /* Ensure nexthops are sorted to satisfy nest invariant */
  if (!nexthop_is_sorted(first))
    first = nexthop_sort(first);

  return first;

err:
  log(L_ERR "KRT: Received strange multipath route %N", n);
  return NULL;
}

static void
nl_add_metrics(struct nlmsghdr *h, uint bufsize, u32 *metrics, int max)
{
  struct rtattr *a = nl_open_attr(h, bufsize, RTA_METRICS);
  int t;

  for (t = 1; t < max; t++)
    if (metrics[0] & (1 << t))
      nl_add_attr_u32(h, bufsize, t, metrics[t]);

  nl_close_attr(h, a);
}

static int
nl_parse_metrics(struct rtattr *hdr, u32 *metrics, int max)
{
  struct rtattr *a = RTA_DATA(hdr);
  int len = RTA_PAYLOAD(hdr);

  metrics[0] = 0;
  for (; RTA_OK(a, len); a = RTA_NEXT(a, len))
  {
    if (a->rta_type == RTA_UNSPEC)
      continue;

    if (a->rta_type >= max)
      continue;

    if (RTA_PAYLOAD(a) != 4)
      return -1;

    metrics[0] |= 1 << a->rta_type;
    metrics[a->rta_type] = rta_get_u32(a);
  }

  if (len > 0)
    return -1;

  return 0;
}


/*
 *	Scanning of interfaces
 */

static void
nl_parse_link(struct nlmsghdr *h, int scan)
{
  struct ifinfomsg *i;
  struct rtattr *a[BIRD_IFLA_MAX];
  int new = h->nlmsg_type == RTM_NEWLINK;
  struct iface f = {};
  struct iface *ifi;
  const char *name, *kind = NULL;
  u32 mtu, master = 0;
  uint fl;

  if (!(i = nl_checkin(h, sizeof(*i))) || !nl_parse_attrs(IFLA_RTA(i), ifla_attr_want, a, sizeof(a)))
    return;
  if (!a[IFLA_IFNAME] || (RTA_PAYLOAD(a[IFLA_IFNAME]) < 2) || !a[IFLA_MTU])
    {
      /*
       * IFLA_IFNAME and IFLA_MTU are required, in fact, but there may also come
       * a message with IFLA_WIRELESS set, where (e.g.) no IFLA_IFNAME exists.
       * We simply ignore all such messages with IFLA_WIRELESS without notice.
       */

      if (a[IFLA_WIRELESS])
	return;

      log(L_ERR "KIF: Malformed message received");
      return;
    }

  name = RTA_DATA(a[IFLA_IFNAME]);
  mtu = rta_get_u32(a[IFLA_MTU]);

  if (a[IFLA_MASTER])
    master = rta_get_u32(a[IFLA_MASTER]);

  if (a[IFLA_LINKINFO])
  {
    struct rtattr *li[BIRD_INFO_MAX];
    nl_attr_len = RTA_PAYLOAD(a[IFLA_LINKINFO]);
    nl_parse_attrs(RTA_DATA(a[IFLA_LINKINFO]), ifinfo_attr_want, li, sizeof(li));
    if (li[IFLA_INFO_KIND])
      kind = RTA_DATA(li[IFLA_INFO_KIND]);
  }

  ifi = if_find_by_index(i->ifi_index);
  if (!new)
    {
      DBG("KIF: IF%d(%s) goes down\n", i->ifi_index, name);
      if (!ifi)
	return;

      if_delete(ifi);
    }
  else
    {
      DBG("KIF: IF%d(%s) goes up (mtu=%d,flg=%x)\n", i->ifi_index, name, mtu, i->ifi_flags);
      if (ifi && strncmp(ifi->name, name, sizeof(ifi->name)-1))
	if_delete(ifi);

      strncpy(f.name, name, sizeof(f.name)-1);
      f.index = i->ifi_index;
      f.mtu = mtu;

      f.master_index = master;
      f.master = if_find_by_index(master);

      fl = i->ifi_flags;
      if (fl & IFF_UP)
	f.flags |= IF_ADMIN_UP;
      if (fl & IFF_LOWER_UP)
	f.flags |= IF_LINK_UP;
      if (fl & IFF_LOOPBACK)		/* Loopback */
	f.flags |= IF_MULTIACCESS | IF_LOOPBACK | IF_IGNORE;
      else if (fl & IFF_POINTOPOINT)	/* PtP */
	f.flags |= IF_MULTICAST;
      else if (fl & IFF_BROADCAST)	/* Broadcast */
	f.flags |= IF_MULTIACCESS | IF_BROADCAST | IF_MULTICAST;
      else
	f.flags |= IF_MULTIACCESS;	/* NBMA */

      if (fl & IFF_MULTICAST)
	f.flags |= IF_MULTICAST;

      if (kind && !strcmp(kind, "vrf"))
	f.flags |= IF_VRF;

      ifi = if_update(&f);

      if (!scan)
	if_end_partial_update(ifi);
    }
}

static void
nl_parse_addr4(struct ifaddrmsg *i, int scan, int new)
{
  struct rtattr *a[BIRD_IFA_MAX];
  struct iface *ifi;
  u32 ifa_flags;
  int scope;

  if (!nl_parse_attrs(IFA_RTA(i), ifa_attr_want4, a, sizeof(a)))
    return;

  if (!a[IFA_LOCAL])
    {
      log(L_ERR "KIF: Malformed message received (missing IFA_LOCAL)");
      return;
    }
  if (!a[IFA_ADDRESS])
    {
      log(L_ERR "KIF: Malformed message received (missing IFA_ADDRESS)");
      return;
    }

  ifi = if_find_by_index(i->ifa_index);
  if (!ifi)
    {
      log(L_ERR "KIF: Received address message for unknown interface %d", i->ifa_index);
      return;
    }

  if (a[IFA_FLAGS])
    ifa_flags = rta_get_u32(a[IFA_FLAGS]);
  else
    ifa_flags = i->ifa_flags;

  struct ifa ifa;
  bzero(&ifa, sizeof(ifa));
  ifa.iface = ifi;
  if (ifa_flags & IFA_F_SECONDARY)
    ifa.flags |= IA_SECONDARY;

  ifa.ip = rta_get_ipa(a[IFA_LOCAL]);

  if (i->ifa_prefixlen > IP4_MAX_PREFIX_LENGTH)
    {
      log(L_ERR "KIF: Invalid prefix length for interface %s: %d", ifi->name, i->ifa_prefixlen);
      new = 0;
    }
  if (i->ifa_prefixlen == IP4_MAX_PREFIX_LENGTH)
    {
      ifa.brd = rta_get_ipa(a[IFA_ADDRESS]);
      net_fill_ip4(&ifa.prefix, rta_get_ip4(a[IFA_ADDRESS]), i->ifa_prefixlen);

      /* It is either a host address or a peer address */
      if (ipa_equal(ifa.ip, ifa.brd))
	ifa.flags |= IA_HOST;
      else
	{
	  ifa.flags |= IA_PEER;
	  ifa.opposite = ifa.brd;
	}
    }
  else
    {
      net_fill_ip4(&ifa.prefix, ipa_to_ip4(ifa.ip), i->ifa_prefixlen);
      net_normalize(&ifa.prefix);

      if (i->ifa_prefixlen == IP4_MAX_PREFIX_LENGTH - 1)
	ifa.opposite = ipa_opposite_m1(ifa.ip);

      if (i->ifa_prefixlen == IP4_MAX_PREFIX_LENGTH - 2)
	ifa.opposite = ipa_opposite_m2(ifa.ip);

      if (ifi->flags & IF_BROADCAST)
        {
	  /* If kernel offers us a broadcast address, we trust it */
	  if (a[IFA_BROADCAST])
	    ifa.brd = ipa_from_ip4(rta_get_ip4(a[IFA_BROADCAST]));
	  /* Otherwise we create one (except for /31) */
	  else if (i->ifa_prefixlen < (IP4_MAX_PREFIX_LENGTH - 1))
	    ifa.brd = ipa_from_ip4(ip4_or(ipa_to_ip4(ifa.ip),
					  ip4_not(ip4_mkmask(i->ifa_prefixlen))));
	}
    }

  scope = ipa_classify(ifa.ip);
  if (scope < 0)
    {
      log(L_ERR "KIF: Invalid interface address %I for %s", ifa.ip, ifi->name);
      return;
    }
  ifa.scope = scope & IADDR_SCOPE_MASK;

  DBG("KIF: IF%d(%s): %s IPA %I, flg %x, net %N, brd %I, opp %I\n",
      ifi->index, ifi->name,
      new ? "added" : "removed",
      ifa.ip, ifa.flags, &ifa.prefix, ifa.brd, ifa.opposite);

  if (new)
    ifa_update(&ifa);
  else
    ifa_delete(&ifa);

  if (!scan)
    if_end_partial_update(ifi);
}

static void
nl_parse_addr6(struct ifaddrmsg *i, int scan, int new)
{
  struct rtattr *a[BIRD_IFA_MAX];
  struct iface *ifi;
  u32 ifa_flags;
  int scope;

  if (!nl_parse_attrs(IFA_RTA(i), ifa_attr_want6, a, sizeof(a)))
    return;

  if (!a[IFA_ADDRESS])
    {
      log(L_ERR "KIF: Malformed message received (missing IFA_ADDRESS)");
      return;
    }

  ifi = if_find_by_index(i->ifa_index);
  if (!ifi)
    {
      log(L_ERR "KIF: Received address message for unknown interface %d", i->ifa_index);
      return;
    }

  if (a[IFA_FLAGS])
    ifa_flags = rta_get_u32(a[IFA_FLAGS]);
  else
    ifa_flags = i->ifa_flags;

  struct ifa ifa;
  bzero(&ifa, sizeof(ifa));
  ifa.iface = ifi;
  if (ifa_flags & IFA_F_SECONDARY)
    ifa.flags |= IA_SECONDARY;

  /* Ignore tentative addresses silently */
  if (ifa_flags & IFA_F_TENTATIVE)
    return;

  /* IFA_LOCAL can be unset for IPv6 interfaces */
  ifa.ip = rta_get_ipa(a[IFA_LOCAL] ? : a[IFA_ADDRESS]);

  if (i->ifa_prefixlen > IP6_MAX_PREFIX_LENGTH)
    {
      log(L_ERR "KIF: Invalid prefix length for interface %s: %d", ifi->name, i->ifa_prefixlen);
      new = 0;
    }
  if (i->ifa_prefixlen == IP6_MAX_PREFIX_LENGTH)
    {
      ifa.brd = rta_get_ipa(a[IFA_ADDRESS]);
      net_fill_ip6(&ifa.prefix, rta_get_ip6(a[IFA_ADDRESS]), i->ifa_prefixlen);

      /* It is either a host address or a peer address */
      if (ipa_equal(ifa.ip, ifa.brd))
	ifa.flags |= IA_HOST;
      else
	{
	  ifa.flags |= IA_PEER;
	  ifa.opposite = ifa.brd;
	}
    }
  else
    {
      net_fill_ip6(&ifa.prefix, ipa_to_ip6(ifa.ip), i->ifa_prefixlen);
      net_normalize(&ifa.prefix);

      if (i->ifa_prefixlen == IP6_MAX_PREFIX_LENGTH - 1)
	ifa.opposite = ipa_opposite_m1(ifa.ip);
    }

  scope = ipa_classify(ifa.ip);
  if (scope < 0)
    {
      log(L_ERR "KIF: Invalid interface address %I for %s", ifa.ip, ifi->name);
      return;
    }
  ifa.scope = scope & IADDR_SCOPE_MASK;

  DBG("KIF: IF%d(%s): %s IPA %I, flg %x, net %N, brd %I, opp %I\n",
      ifi->index, ifi->name,
      new ? "added" : "removed",
      ifa.ip, ifa.flags, &ifa.prefix, ifa.brd, ifa.opposite);

  if (new)
    ifa_update(&ifa);
  else
    ifa_delete(&ifa);

  if (!scan)
    if_end_partial_update(ifi);
}

static void
nl_parse_addr(struct nlmsghdr *h, int scan)
{
  struct ifaddrmsg *i;

  if (!(i = nl_checkin(h, sizeof(*i))))
    return;

  int new = (h->nlmsg_type == RTM_NEWADDR);

  switch (i->ifa_family)
    {
      case AF_INET:
	return nl_parse_addr4(i, scan, new);

      case AF_INET6:
	return nl_parse_addr6(i, scan, new);
    }
}

void
kif_do_scan(struct kif_proto *p UNUSED)
{
  struct nlmsghdr *h;

  if_start_update();

  nl_request_dump_link();
  while (h = nl_get_scan())
    if (h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK)
      nl_parse_link(h, 1);
    else
      log(L_DEBUG "nl_scan_ifaces: Unknown packet received (type=%d)", h->nlmsg_type);

  /* Re-resolve master interface for slaves */
  struct iface *i;
  WALK_LIST(i, iface_list)
    if (i->master_index)
    {
      struct iface f = {
	.flags = i->flags,
	.mtu = i->mtu,
	.index = i->index,
	.master_index = i->master_index,
	.master = if_find_by_index(i->master_index)
      };

      if (f.master != i->master)
      {
	memcpy(f.name, i->name, sizeof(f.name));
	if_update(&f);
      }
    }

  nl_request_dump_addr(AF_INET);
  while (h = nl_get_scan())
    if (h->nlmsg_type == RTM_NEWADDR || h->nlmsg_type == RTM_DELADDR)
      nl_parse_addr(h, 1);
    else
      log(L_DEBUG "nl_scan_ifaces: Unknown packet received (type=%d)", h->nlmsg_type);

  nl_request_dump_addr(AF_INET6);
  while (h = nl_get_scan())
    if (h->nlmsg_type == RTM_NEWADDR || h->nlmsg_type == RTM_DELADDR)
      nl_parse_addr(h, 1);
    else
      log(L_DEBUG "nl_scan_ifaces: Unknown packet received (type=%d)", h->nlmsg_type);

  if_end_update();
}

/*
 *	Routes
 */

static inline u32
krt_table_id(struct krt_proto *p)
{
  return KRT_CF->sys.table_id;
}

static HASH(struct krt_proto) nl_table_map;

#define RTH_KEY(p)		p->af, krt_table_id(p)
#define RTH_NEXT(p)		p->sys.hash_next
#define RTH_EQ(a1,i1,a2,i2)	a1 == a2 && i1 == i2
#define RTH_FN(a,i)		a ^ u32_hash(i)

#define RTH_REHASH		rth_rehash
#define RTH_PARAMS		/8, *2, 2, 2, 6, 20

HASH_DEFINE_REHASH_FN(RTH, struct krt_proto)

int
krt_capable(rte *e)
{
  rta *a = e->attrs;

  switch (a->dest)
  {
    case RTD_UNICAST:
    case RTD_BLACKHOLE:
    case RTD_UNREACHABLE:
    case RTD_PROHIBIT:
      return 1;

    default:
      return 0;
  }
}

static inline int
nh_bufsize(struct nexthop *nh)
{
  int rv = 0;
  for (; nh != NULL; nh = nh->next)
    rv += RTNH_LENGTH(RTA_LENGTH(sizeof(ip_addr)));
  return rv;
}

static int
nl_send_route(struct krt_proto *p, rte *e, int op)
{
  eattr *ea;
  net *net = e->net;
  rta *a = e->attrs;
  ea_list *eattrs = a->eattrs;
  int bufsize = 128 + KRT_METRICS_MAX*8 + nh_bufsize(&(a->nh));
  u32 priority = 0;

  struct {
    struct nlmsghdr h;
    struct rtmsg r;
    char buf[0];
  } *r;

  int rsize = sizeof(*r) + bufsize;
  r = alloca(rsize);

  DBG("nl_send_route(%N,op=%x)\n", net->n.addr, op);

  bzero(&r->h, sizeof(r->h));
  bzero(&r->r, sizeof(r->r));
  r->h.nlmsg_type = op ? RTM_NEWROUTE : RTM_DELROUTE;
  r->h.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  r->h.nlmsg_flags = op | NLM_F_REQUEST | NLM_F_ACK;

  r->r.rtm_family = p->af;
  r->r.rtm_dst_len = net_pxlen(net->n.addr);
  r->r.rtm_protocol = RTPROT_BIRD;
  r->r.rtm_scope = RT_SCOPE_NOWHERE;
#ifdef HAVE_MPLS_KERNEL
  if (p->af == AF_MPLS)
  {
    /*
     * Kernel MPLS code is a bit picky. We must:
     * 1) Always set RT_SCOPE_UNIVERSE and RTN_UNICAST (even for RTM_DELROUTE)
     * 2) Never use RTA_PRIORITY
     */

    u32 label = net_mpls(net->n.addr);
    nl_add_attr_mpls(&r->h, rsize, RTA_DST, 1, &label);
    r->r.rtm_scope = RT_SCOPE_UNIVERSE;
    r->r.rtm_type = RTN_UNICAST;
  }
  else
#endif
  {
    nl_add_attr_ipa(&r->h, rsize, RTA_DST, net_prefix(net->n.addr));

    /* Add source address for IPv6 SADR routes */
    if (net->n.addr->type == NET_IP6_SADR)
    {
      net_addr_ip6_sadr *a = (void *) &net->n.addr;
      nl_add_attr_ip6(&r->h, rsize, RTA_SRC, a->src_prefix);
      r->r.rtm_src_len = a->src_pxlen;
    }
  }

  /*
   * Strange behavior for RTM_DELROUTE:
   * 1) rtm_family is ignored in IPv6, works for IPv4
   * 2) not setting RTA_PRIORITY is different from setting default value (on IPv6)
   * 3) not setting RTA_PRIORITY is equivalent to setting 0, which is wildcard
   */

  if (krt_table_id(p) < 256)
    r->r.rtm_table = krt_table_id(p);
  else
    nl_add_attr_u32(&r->h, rsize, RTA_TABLE, krt_table_id(p));

  if (p->af == AF_MPLS)
    priority = 0;
  else if (KRT_CF->sys.metric)
    priority = KRT_CF->sys.metric;
  else if ((op != NL_OP_DELETE) && (ea = ea_find(eattrs, EA_KRT_METRIC)))
    priority = ea->u.data;

  if (priority)
    nl_add_attr_u32(&r->h, rsize, RTA_PRIORITY, priority);

  /* For route delete, we do not specify remaining route attributes */
  if (op == NL_OP_DELETE)
    goto done;

  /* Default scope is LINK for device routes, UNIVERSE otherwise */
  if (p->af == AF_MPLS)
    r->r.rtm_scope = RT_SCOPE_UNIVERSE;
  else if (ea = ea_find(eattrs, EA_KRT_SCOPE))
    r->r.rtm_scope = ea->u.data;
  else if (a->dest == RTD_UNICAST && ipa_zero(a->nh.gw))
    r->r.rtm_scope = RT_SCOPE_LINK;
  else
    r->r.rtm_scope = RT_SCOPE_UNIVERSE;

  if (ea = ea_find(eattrs, EA_KRT_PREFSRC))
    nl_add_attr_ipa(&r->h, rsize, RTA_PREFSRC, *(ip_addr *)ea->u.ptr->data);

  if (ea = ea_find(eattrs, EA_KRT_REALM))
    nl_add_attr_u32(&r->h, rsize, RTA_FLOW, ea->u.data);


  u32 metrics[KRT_METRICS_MAX];
  metrics[0] = 0;

  struct ea_walk_state ews = { .eattrs = eattrs };
  while (ea = ea_walk(&ews, EA_KRT_METRICS, KRT_METRICS_MAX))
  {
    int id = ea->id - EA_KRT_METRICS;
    metrics[0] |= 1 << id;
    metrics[id] = ea->u.data;
  }

  if (metrics[0])
    nl_add_metrics(&r->h, rsize, metrics, KRT_METRICS_MAX);

  switch (a->dest)
    {
    case RTD_UNICAST:
      r->r.rtm_type = RTN_UNICAST;
      struct nexthop *nh = &(a->nh);
      if (nh->next)
	nl_add_multipath(&r->h, rsize, nh, p->af, eattrs);
      else
      {
	nl_add_attr_u32(&r->h, rsize, RTA_OIF, nh->iface->index);
	nl_add_nexthop(&r->h, rsize, nh, p->af);

	if (nh->flags & RNF_ONLINK)
	  r->r.rtm_flags |= RTNH_F_ONLINK;
      }
      break;
    case RTD_BLACKHOLE:
      r->r.rtm_type = RTN_BLACKHOLE;
      break;
    case RTD_UNREACHABLE:
      r->r.rtm_type = RTN_UNREACHABLE;
      break;
    case RTD_PROHIBIT:
      r->r.rtm_type = RTN_PROHIBIT;
      break;
    case RTD_NONE:
      break;
    default:
      bug("krt_capable inconsistent with nl_send_route");
    }

done:
  /* Ignore missing for DELETE */
  return nl_exchange(&r->h, (op == NL_OP_DELETE));
}

static inline int
nl_allow_replace(struct krt_proto *p, rte *new)
{
  /*
   * We use NL_OP_REPLACE for IPv4, it has an issue with not checking for
   * matching rtm_protocol, but that is OK when dedicated priority is used.
   *
   * For IPv6, the NL_OP_REPLACE is still broken even in Linux 4.19 LTS
   * (although it seems to be fixed in Linux 5.10 LTS) for sequence:
   *
   * ip route add 2001:db8::/32 via fe80::1 dev eth0
   * ip route replace 2001:db8::/32 dev eth0
   *
   * (it ends with two routes instead of replacing the first by the second one)
   *
   * Replacing with direct and special type (e.g. unreachable) routes does not
   * work, but replacing with regular routes work reliably
   */

  if (krt_ipv4(p))
    return 1;

  rta *a = new->attrs;
  return (a->dest == RTD_UNICAST) && ipa_nonzero(a->nh.gw);
}

void
krt_replace_rte(struct krt_proto *p, net *n UNUSED, rte *new, rte *old)
{
  int err = 0;

  if (old && new && nl_allow_replace(p, new))
  {
    err = nl_send_route(p, new, NL_OP_REPLACE);
  }
  else
  {
    if (old)
      nl_send_route(p, old, NL_OP_DELETE);

    if (new)
      err = nl_send_route(p, new, NL_OP_ADD);
  }

  if (new)
  {
    if (err < 0)
      bmap_clear(&p->sync_map, new->id);
    else
      bmap_set(&p->sync_map, new->id);
  }
}


#define SKIP0(ARG, ...) do { DBG("KRT: Ignoring route - " ARG, ##__VA_ARGS__); return; } while(0)
#define SKIP(ARG, ...)  do { DBG("KRT: Ignoring route %N - " ARG, &dst, ##__VA_ARGS__); return; } while(0)

static void
nl_parse_route(struct nl_parse_state *s, struct nlmsghdr *h)
{
  struct krt_proto *p;
  struct rtmsg *i;
  struct rtattr *a[BIRD_RTA_MAX];
  int new = h->nlmsg_type == RTM_NEWROUTE;

  net_addr dst, src = {};
  u32 oif = ~0;
  u32 table_id;
  u32 priority = 0;
  u32 def_scope = RT_SCOPE_UNIVERSE;
  int krt_src;

  if (!(i = nl_checkin(h, sizeof(*i))))
    return;

  switch (i->rtm_family)
    {
    case AF_INET:
      if (!nl_parse_attrs(RTM_RTA(i), rtm_attr_want4, a, sizeof(a)))
	return;

      if (a[RTA_DST])
	net_fill_ip4(&dst, rta_get_ip4(a[RTA_DST]), i->rtm_dst_len);
      else
	net_fill_ip4(&dst, IP4_NONE, 0);
      break;

    case AF_INET6:
      if (!nl_parse_attrs(RTM_RTA(i), rtm_attr_want6, a, sizeof(a)))
	return;

      if (a[RTA_DST])
	net_fill_ip6(&dst, rta_get_ip6(a[RTA_DST]), i->rtm_dst_len);
      else
	net_fill_ip6(&dst, IP6_NONE, 0);

      if (a[RTA_SRC])
	net_fill_ip6(&src, rta_get_ip6(a[RTA_SRC]), i->rtm_src_len);
      else
	net_fill_ip6(&src, IP6_NONE, 0);
      break;

#ifdef HAVE_MPLS_KERNEL
    case AF_MPLS:
      if (!nl_parse_attrs(RTM_RTA(i), rtm_attr_want_mpls, a, sizeof(a)))
	return;

      if (!a[RTA_DST])
	SKIP0("MPLS route without RTA_DST\n");

      if (rta_get_mpls(a[RTA_DST], rta_mpls_stack) != 1)
	SKIP0("MPLS route with multi-label RTA_DST\n");

      net_fill_mpls(&dst, rta_mpls_stack[0]);
      break;
#endif

    default:
      return;
    }

  if (a[RTA_OIF])
    oif = rta_get_u32(a[RTA_OIF]);

  if (a[RTA_TABLE])
    table_id = rta_get_u32(a[RTA_TABLE]);
  else
    table_id = i->rtm_table;

  if (i->rtm_flags & RTM_F_CLONED)
    SKIP("cloned\n");

  /* Do we know this table? */
  p = HASH_FIND(nl_table_map, RTH, i->rtm_family, table_id);
  if (!p)
    SKIP("unknown table %u\n", table_id);

  if (a[RTA_SRC] && (p->p.net_type != NET_IP6_SADR))
    SKIP("src prefix for non-SADR channel\n");

  if (a[RTA_IIF])
    SKIP("IIF set\n");

  if (i->rtm_tos != 0)			/* We don't support TOS */
    SKIP("TOS %02x\n", i->rtm_tos);

  if (s->scan && !new)
    SKIP("RTM_DELROUTE in scan\n");

  if (a[RTA_PRIORITY])
    priority = rta_get_u32(a[RTA_PRIORITY]);

  int c = net_classify(&dst);
  if ((c < 0) || !(c & IADDR_HOST) || ((c & IADDR_SCOPE_MASK) <= SCOPE_LINK))
    SKIP("strange class/scope\n");

  switch (i->rtm_protocol)
    {
    case RTPROT_UNSPEC:
      SKIP("proto unspec\n");

    case RTPROT_REDIRECT:
      krt_src = KRT_SRC_REDIRECT;
      break;

    case RTPROT_KERNEL:
      krt_src = KRT_SRC_KERNEL;
      break;

    case RTPROT_BIRD:
      if (!s->scan)
	SKIP("echo\n");
      krt_src = KRT_SRC_BIRD;
      break;

    case RTPROT_BOOT:
    default:
      krt_src = KRT_SRC_ALIEN;
    }

  net_addr *n = &dst;
  if (p->p.net_type == NET_IP6_SADR)
  {
    n = alloca(sizeof(net_addr_ip6_sadr));
    net_fill_ip6_sadr(n, net6_prefix(&dst), net6_pxlen(&dst),
		      net6_prefix(&src), net6_pxlen(&src));
  }

  net *net = net_get(p->p.main_channel->table, n);

  rta *ra = lp_allocz(s->pool, RTA_MAX_SIZE);
  ra->source = RTS_INHERIT;
  ra->scope = SCOPE_UNIVERSE;

  {
    ea_list *ea = lp_alloc(s->pool, sizeof(ea_list) + 2 * sizeof(eattr));
    *ea = (ea_list) { .flags = EALF_SORTED, .count = 2 };
    ea->next = ra->eattrs;
    ra->eattrs = ea;

    ea->attrs[0] = (eattr) {
      .id = EA_KRT_SOURCE,
      .type = EAF_TYPE_INT,
      .u.data = i->rtm_protocol
    };

    ea->attrs[1] = (eattr) {
      .id = EA_KRT_METRIC,
      .type = EAF_TYPE_INT,
      .u.data = priority,
    };
  }

  if (a[RTA_FLOW])
    s->rta_flow = rta_get_u32(a[RTA_FLOW]);
  else
    s->rta_flow = 0;

  switch (i->rtm_type)
    {
    case RTN_UNICAST:
      ra->dest = RTD_UNICAST;

      if (a[RTA_MULTIPATH])
        {
	  struct nexthop *nh = nl_parse_multipath(s, p, n, a[RTA_MULTIPATH], i->rtm_family, krt_src);
	  if (!nh)
	    SKIP("strange RTA_MULTIPATH\n");

	  nexthop_link(ra, nh);
	  break;
	}

      if ((i->rtm_flags & RTNH_F_DEAD) && (krt_src != KRT_SRC_BIRD))
	SKIP("ignore RTNH_F_DEAD\n");

      ra->nh.iface = if_find_by_index(oif);
      if (!ra->nh.iface)
	{
	  log(L_ERR "KRT: Received route %N with unknown ifindex %u", net->n.addr, oif);
	  return;
	}

      if (a[RTA_GATEWAY])
	ra->nh.gw = rta_get_ipa(a[RTA_GATEWAY]);

      if (a[RTA_VIA])
	ra->nh.gw = rta_get_via(a[RTA_VIA]);

      if (i->rtm_flags & RTNH_F_ONLINK)
	ra->nh.flags |= RNF_ONLINK;

      if (ipa_nonzero(ra->nh.gw))
	{
	  /* Silently skip strange 6to4 routes */
	  const net_addr_ip6 sit = NET_ADDR_IP6(IP6_NONE, 96);
	  if ((i->rtm_family == AF_INET6) && ipa_in_netX(ra->nh.gw, (net_addr *) &sit))
	    return;

	  neighbor *nbr;
	  nbr = neigh_find(&p->p, ra->nh.gw, ra->nh.iface,
			   (ra->nh.flags & RNF_ONLINK) ? NEF_ONLINK : 0);
	  if (!nbr || (nbr->scope == SCOPE_HOST))
	    {
	      log(L_ERR "KRT: Received route %N with strange next-hop %I", net->n.addr,
                  ra->nh.gw);
	      return;
	    }
	}

      break;
    case RTN_BLACKHOLE:
      ra->dest = RTD_BLACKHOLE;
      break;
    case RTN_UNREACHABLE:
      ra->dest = RTD_UNREACHABLE;
      break;
    case RTN_PROHIBIT:
      ra->dest = RTD_PROHIBIT;
      break;
    /* FIXME: What about RTN_THROW? */
    default:
      SKIP("type %d\n", i->rtm_type);
      return;
    }

#ifdef HAVE_MPLS_KERNEL
  if ((i->rtm_family == AF_MPLS) && a[RTA_NEWDST] && !ra->nh.next)
    ra->nh.labels = rta_get_mpls(a[RTA_NEWDST], ra->nh.label);

  if (a[RTA_ENCAP] && a[RTA_ENCAP_TYPE] && !ra->nh.next)
    {
      switch (rta_get_u16(a[RTA_ENCAP_TYPE]))
	{
	  case LWTUNNEL_ENCAP_MPLS:
	    {
	      struct rtattr *enca[BIRD_RTA_MAX];
	      nl_attr_len = RTA_PAYLOAD(a[RTA_ENCAP]);
	      nl_parse_attrs(RTA_DATA(a[RTA_ENCAP]), encap_mpls_want, enca, sizeof(enca));
	      ra->nh.labels = rta_get_mpls(enca[RTA_DST], ra->nh.label);
	      break;
	    }
	  default:
	    SKIP("unknown encapsulation method %d\n", rta_get_u16(a[RTA_ENCAP_TYPE]));
	    break;
	}
    }
#endif

  if (i->rtm_scope != def_scope)
    {
      ea_list *ea = lp_alloc(s->pool, sizeof(ea_list) + sizeof(eattr));
      ea->next = ra->eattrs;
      ra->eattrs = ea;
      ea->flags = EALF_SORTED;
      ea->count = 1;
      ea->attrs[0] = (eattr) {
        .id = EA_KRT_SCOPE,
        .flags = 0,
        .type = EAF_TYPE_INT,
        .u.data = i->rtm_scope,
      };
    }

  if (a[RTA_PREFSRC])
    {
      ip_addr ps = rta_get_ipa(a[RTA_PREFSRC]);

      struct adata *ad = lp_alloc(s->pool, sizeof(struct adata) + sizeof(ps));
      ad->length = sizeof(ps);
      memcpy(ad->data, &ps, sizeof(ps));

      ea_list *ea = lp_alloc(s->pool, sizeof(ea_list) + sizeof(eattr));
      ea->next = ra->eattrs;
      ra->eattrs = ea;
      ea->flags = EALF_SORTED;
      ea->count = 1;
      ea->attrs[0] = (eattr) {
	.id = EA_KRT_PREFSRC,
        .flags = 0,
        .type = EAF_TYPE_IP_ADDRESS,
        .u.ptr = ad,
      };
    }

  /* Can be set per-route or per-nexthop */
  if (s->rta_flow)
    {
      ea_list *ea = lp_alloc(s->pool, sizeof(ea_list) + sizeof(eattr));
      ea->next = ra->eattrs;
      ra->eattrs = ea;
      ea->flags = EALF_SORTED;
      ea->count = 1;
      ea->attrs[0] = (eattr) {
	.id = EA_KRT_REALM,
	.flags = 0,
	.type = EAF_TYPE_INT,
	.u.data = s->rta_flow,
      };
    }

  if (a[RTA_METRICS])
    {
      u32 metrics[KRT_METRICS_MAX];
      ea_list *ea = lp_alloc(s->pool, sizeof(ea_list) + KRT_METRICS_MAX * sizeof(eattr));
      int t, n = 0;

      if (nl_parse_metrics(a[RTA_METRICS], metrics, ARRAY_SIZE(metrics)) < 0)
        {
	  log(L_ERR "KRT: Received route %N with strange RTA_METRICS attribute", net->n.addr);
	  return;
	}

      for (t = 1; t < KRT_METRICS_MAX; t++)
	if (metrics[0] & (1 << t))
	  ea->attrs[n++] = (eattr) {
	    .id = EA_CODE(PROTOCOL_KERNEL, KRT_METRICS_OFFSET + t),
	    .flags = 0,
	    .type = EAF_TYPE_INT, /* FIXME: Some are EAF_TYPE_BITFIELD */
	    .u.data = metrics[t],
	  };

      if (n > 0)
        {
	  ea->next = ra->eattrs;
	  ea->flags = EALF_SORTED;
	  ea->count = n;
	  ra->eattrs = ea;
	}
    }

  rte *e = rte_get_temp(ra, p->p.main_source);
  e->net = net;

  if (s->scan)
    krt_got_route(p, e, krt_src);
  else
    krt_got_route_async(p, e, new, krt_src);

  lp_flush(s->pool);
}

void
krt_do_scan(struct krt_proto *p)
{
  struct nl_parse_state s = {
    .proto = p,
    .pool = nl_linpool,
    .scan = 1,
  };

  /* Table-specific scan or shared scan */
  if (p)
    nl_request_dump_route(p->af, krt_table_id(p));
  else
    nl_request_dump_route(AF_UNSPEC, 0);

  struct nlmsghdr *h;
  while (h = nl_get_scan())
  {
    if (h->nlmsg_type == RTM_NEWROUTE || h->nlmsg_type == RTM_DELROUTE)
      nl_parse_route(&s, h);
    else
      log(L_DEBUG "nl_scan_fire: Unknown packet received (type=%d)", h->nlmsg_type);
  }
}

/*
 *	Asynchronous Netlink interface
 */

static sock *nl_async_sk;		/* BIRD socket for asynchronous notifications */
static byte *nl_async_rx_buffer;	/* Receive buffer */
static uint nl_async_bufsize;		/* Kernel rx buffer size for the netlink socket */
static struct config *nl_last_config;	/* For tracking changes to nl_async_bufsize */

static void
nl_async_msg(struct nlmsghdr *h)
{
  struct nl_parse_state s = {
    .proto = NULL,
    .pool = nl_linpool,
    .scan = 0,
  };

  switch (h->nlmsg_type)
    {
    case RTM_NEWROUTE:
    case RTM_DELROUTE:
      DBG("KRT: Received async route notification (%d)\n", h->nlmsg_type);
      nl_parse_route(&s, h);
      break;
    case RTM_NEWLINK:
    case RTM_DELLINK:
      DBG("KRT: Received async link notification (%d)\n", h->nlmsg_type);
      if (kif_proto)
	nl_parse_link(h, 0);
      break;
    case RTM_NEWADDR:
    case RTM_DELADDR:
      DBG("KRT: Received async address notification (%d)\n", h->nlmsg_type);
      if (kif_proto)
	nl_parse_addr(h, 0);
      break;
    default:
      DBG("KRT: Received unknown async notification (%d)\n", h->nlmsg_type);
    }
}

static int
nl_async_hook(sock *sk, uint size UNUSED)
{
  struct iovec iov = { nl_async_rx_buffer, NL_RX_SIZE };
  struct sockaddr_nl sa;
  struct msghdr m = {
    .msg_name = &sa,
    .msg_namelen = sizeof(sa),
    .msg_iov = &iov,
    .msg_iovlen = 1,
  };
  struct nlmsghdr *h;
  int x;
  uint len;

  x = recvmsg(sk->fd, &m, 0);
  if (x < 0)
    {
      if (errno == ENOBUFS)
	{
	  /*
	   *  Netlink reports some packets have been thrown away.
	   *  One day we might react to it by asking for route table
	   *  scan in near future.
	   */
	  log(L_WARN "Kernel dropped some netlink messages, will resync on next scan.");
	  return 1;	/* More data are likely to be ready */
	}
      else if (errno != EWOULDBLOCK)
	log(L_ERR "Netlink recvmsg: %m");
      return 0;
    }
  if (sa.nl_pid)		/* It isn't from the kernel */
    {
      DBG("Non-kernel packet\n");
      return 1;
    }
  h = (void *) nl_async_rx_buffer;
  len = x;
  if (m.msg_flags & MSG_TRUNC)
    {
      log(L_WARN "Netlink got truncated asynchronous message");
      return 1;
    }
  while (NLMSG_OK(h, len))
    {
      nl_async_msg(h);
      h = NLMSG_NEXT(h, len);
    }
  if (len)
    log(L_WARN "nl_async_hook: Found packet remnant of size %d", len);
  return 1;
}

static void
nl_async_err_hook(sock *sk, int e UNUSED)
{
  nl_async_hook(sk, 0);
}

static void
nl_open_async(void)
{
  sock *sk;
  struct sockaddr_nl sa;
  int fd;

  if (nl_async_sk)
    return;

  DBG("KRT: Opening async netlink socket\n");

  fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd < 0)
    {
      log(L_ERR "Unable to open asynchronous rtnetlink socket: %m");
      return;
    }

  bzero(&sa, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  sa.nl_groups = RTMGRP_LINK |
    RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE |
    RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE;

  if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
    {
      log(L_ERR "Unable to bind asynchronous rtnetlink socket: %m");
      close(fd);
      return;
    }

  nl_async_rx_buffer = xmalloc(NL_RX_SIZE);

  sk = nl_async_sk = sk_new(krt_pool);
  sk->type = SK_MAGIC;
  sk->rx_hook = nl_async_hook;
  sk->err_hook = nl_async_err_hook;
  sk->fd = fd;
  if (sk_open(sk) < 0)
    bug("Netlink: sk_open failed");
}

static void
nl_update_async_bufsize(void)
{
  /* No async socket */
  if (!nl_async_sk)
    return;

  /* Already reconfigured */
  if (nl_last_config == config)
    return;

  /* Update netlink buffer size */
  uint bufsize = nl_cfg_rx_buffer_size(config);
  if (bufsize && (bufsize != nl_async_bufsize))
  {
    /* Log message for reconfigurations only */
    if (nl_last_config)
      log(L_INFO "KRT: Changing netlink rx buffer size to %u", bufsize);

    nl_set_rcvbuf(nl_async_sk->fd, bufsize);
    nl_async_bufsize = bufsize;
  }

  nl_last_config = config;
}


/*
 *	Interface to the UNIX krt module
 */

void
krt_sys_io_init(void)
{
  nl_linpool = lp_new_default(krt_pool);
  HASH_INIT(nl_table_map, krt_pool, 6);
}

int
krt_sys_start(struct krt_proto *p)
{
  struct krt_proto *old = HASH_FIND(nl_table_map, RTH, p->af, krt_table_id(p));

  if (old)
    {
      log(L_ERR "%s: Kernel table %u already registered by %s",
	  p->p.name, krt_table_id(p), old->p.name);
      return 0;
    }

  HASH_INSERT2(nl_table_map, RTH, krt_pool, p);

  nl_open();
  nl_open_async();
  nl_update_async_bufsize();

  return 1;
}

void
krt_sys_shutdown(struct krt_proto *p)
{
  nl_update_async_bufsize();

  HASH_REMOVE2(nl_table_map, RTH, krt_pool, p);
}

int
krt_sys_reconfigure(struct krt_proto *p UNUSED, struct krt_config *n, struct krt_config *o)
{
  nl_update_async_bufsize();

  return (n->sys.table_id == o->sys.table_id) && (n->sys.metric == o->sys.metric);
}

void
krt_sys_init_config(struct krt_config *cf)
{
  cf->sys.table_id = RT_TABLE_MAIN;
  cf->sys.metric = 32;
}

void
krt_sys_copy_config(struct krt_config *d, struct krt_config *s)
{
  d->sys.table_id = s->sys.table_id;
  d->sys.metric = s->sys.metric;
}

static const char *krt_metrics_names[KRT_METRICS_MAX] = {
  NULL, "lock", "mtu", "window", "rtt", "rttvar", "sstresh", "cwnd", "advmss",
  "reordering", "hoplimit", "initcwnd", "features", "rto_min", "initrwnd", "quickack"
};

static const char *krt_features_names[KRT_FEATURES_MAX] = {
  "ecn", NULL, NULL, "allfrag"
};

int
krt_sys_get_attr(const eattr *a, byte *buf, int buflen UNUSED)
{
  switch (a->id)
  {
  case EA_KRT_PREFSRC:
    bsprintf(buf, "prefsrc");
    return GA_NAME;

  case EA_KRT_REALM:
    bsprintf(buf, "realm");
    return GA_NAME;

  case EA_KRT_SCOPE:
    bsprintf(buf, "scope");
    return GA_NAME;

  case EA_KRT_LOCK:
    buf += bsprintf(buf, "lock:");
    ea_format_bitfield(a, buf, buflen, krt_metrics_names, 2, KRT_METRICS_MAX);
    return GA_FULL;

  case EA_KRT_FEATURES:
    buf += bsprintf(buf, "features:");
    ea_format_bitfield(a, buf, buflen, krt_features_names, 0, KRT_FEATURES_MAX);
    return GA_FULL;

  default:;
    int id = (int)EA_ID(a->id) - KRT_METRICS_OFFSET;
    if (id > 0 && id < KRT_METRICS_MAX)
    {
      bsprintf(buf, "%s", krt_metrics_names[id]);
      return GA_NAME;
    }

    return GA_UNKNOWN;
  }
}



void
kif_sys_start(struct kif_proto *p UNUSED)
{
  nl_open();
  nl_open_async();
}

void
kif_sys_shutdown(struct kif_proto *p UNUSED)
{
}

int
kif_update_sysdep_addr(struct iface *i UNUSED)
{
  return 0;
}
