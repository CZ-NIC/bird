/*
 *	BIRD Internet Routing Daemon -- BSD Multicasting and Network Includes
 *
 *	(c) 2004       Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <net/if_dl.h>
#include <netinet/in_systm.h> // Workaround for some BSDs
#include <netinet/ip.h>
#include <sys/param.h>


#ifdef __FreeBSD__
/* Should be defined in sysdep/cf/bsd.h, but it is flavor-specific */
#define CONFIG_DONTROUTE_UNICAST

#if __FreeBSD_version >= 1201000
#define CONFIG_USE_IP_MREQN
#endif

#endif


#ifdef __OpenBSD__

#if OpenBSD >= 202105
#define CONFIG_USE_IP_MREQN
#endif

#endif


#ifdef __NetBSD__

#ifndef IP_RECVTTL
#define IP_RECVTTL 23
#endif

#ifndef IP_MINTTL
#define IP_MINTTL 24
#endif

#endif


#ifdef __DragonFly__
#define TCP_MD5SIG	TCP_SIGNATURE_ENABLE
#endif


#undef  SA_LEN
#define SA_LEN(x) (x).sa.sa_len


/*
 *	BSD IPv4 multicast syscalls
 */

#define INIT_MREQ4(maddr,ifa) \
  { .imr_multiaddr = ipa_to_in4(maddr), .imr_interface = ip4_to_in4(ifa->sysdep) }

#define INIT_MREQN4(maddr,ifa) \
  { .imr_multiaddr = ipa_to_in4(maddr), .imr_ifindex = ifa->index }

static inline int
sk_setup_multicast4(sock *s)
{
  u8 ttl = s->ttl;
  u8 n = 0;

#ifdef CONFIG_USE_IP_MREQN
  struct ip_mreqn ifa = { .imr_ifindex = s->iface->index };
#else
  struct in_addr ifa = ip4_to_in4(s->iface->sysdep);
#endif

  /* This defines where should we send _outgoing_ multicasts */
  if (setsockopt(s->fd, IPPROTO_IP, IP_MULTICAST_IF, &ifa, sizeof(ifa)) < 0)
    ERR("IP_MULTICAST_IF");

  if (setsockopt(s->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
    ERR("IP_MULTICAST_TTL");

  if (setsockopt(s->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &n, sizeof(n)) < 0)
    ERR("IP_MULTICAST_LOOP");

  return 0;
}

static inline int
sk_join_group4(sock *s, ip_addr maddr)
{
#ifdef CONFIG_USE_IP_MREQN
  struct ip_mreqn mr = INIT_MREQN4(maddr, s->iface);
#else
  struct ip_mreq mr = INIT_MREQ4(maddr, s->iface);
#endif

  if (setsockopt(s->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
    ERR("IP_ADD_MEMBERSHIP");

  return 0;
}

static inline int
sk_leave_group4(sock *s, ip_addr maddr)
{
#ifdef CONFIG_USE_IP_MREQN
  struct ip_mreqn mr = INIT_MREQN4(maddr, s->iface);
#else
  struct ip_mreq mr = INIT_MREQ4(maddr, s->iface);
#endif

  if (setsockopt(s->fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mr, sizeof(mr)) < 0)
    ERR("IP_ADD_MEMBERSHIP");

  return 0;
}


/*
 *	BSD IPv4 packet control messages
 */

/* It uses IP_RECVDSTADDR / IP_RECVIF socket options instead of IP_PKTINFO */

#define CMSG4_SPACE_PKTINFO (CMSG_SPACE(sizeof(struct in_addr)) + \
			     CMSG_SPACE(sizeof(struct sockaddr_dl)))
#define CMSG4_SPACE_TTL CMSG_SPACE(sizeof(char))

static inline int
sk_request_cmsg4_pktinfo(sock *s)
{
  int y = 1;

  if (setsockopt(s->fd, IPPROTO_IP, IP_RECVDSTADDR, &y, sizeof(y)) < 0)
    ERR("IP_RECVDSTADDR");

  if (setsockopt(s->fd, IPPROTO_IP, IP_RECVIF, &y, sizeof(y)) < 0)
    ERR("IP_RECVIF");

  return 0;
}

static inline int
sk_request_cmsg4_ttl(sock *s)
{
  int y = 1;

  if (setsockopt(s->fd, IPPROTO_IP, IP_RECVTTL, &y, sizeof(y)) < 0)
    ERR("IP_RECVTTL");

  return 0;
}

static inline void
sk_process_cmsg4_pktinfo(sock *s, struct cmsghdr *cm)
{
  if (cm->cmsg_type == IP_RECVDSTADDR)
    s->laddr = ipa_from_in4(* (struct in_addr *) CMSG_DATA(cm));

  if (cm->cmsg_type == IP_RECVIF)
    s->lifindex = ((struct sockaddr_dl *) CMSG_DATA(cm))->sdl_index;
}

static inline void
sk_process_cmsg4_ttl(sock *s, struct cmsghdr *cm)
{
  if (cm->cmsg_type == IP_RECVTTL)
    s->rcv_ttl = * (byte *) CMSG_DATA(cm);
}

#ifdef IP_SENDSRCADDR
static inline void
sk_prepare_cmsgs4(sock *s, struct msghdr *msg, void *cbuf, size_t cbuflen)
{
  /* Unfortunately, IP_SENDSRCADDR does not work for raw IP sockets on BSD kernels */

  struct cmsghdr *cm;
  struct in_addr *sa;
  int controllen = 0;

  msg->msg_control = cbuf;
  msg->msg_controllen = cbuflen;

  cm = CMSG_FIRSTHDR(msg);
  cm->cmsg_level = IPPROTO_IP;
  cm->cmsg_type = IP_SENDSRCADDR;
  cm->cmsg_len = CMSG_LEN(sizeof(*sa));
  controllen += CMSG_SPACE(sizeof(*sa));

  sa = (struct in_addr *) CMSG_DATA(cm);
  *sa = ipa_to_in4(s->saddr);

  msg->msg_controllen = controllen;
}
#else
static inline void
sk_prepare_cmsgs4(sock *s UNUSED, struct msghdr *msg UNUSED, void *cbuf UNUSED, size_t cbuflen UNUSED) { }
#endif

static void UNUSED
sk_prepare_ip_header(sock *s, void *hdr, int dlen)
{
  struct ip *ip = hdr;

  bzero(ip, 20);

  ip->ip_v = 4;
  ip->ip_hl = 5;
  ip->ip_tos = (s->tos < 0) ? 0 : s->tos;
  ip->ip_len = 20 + dlen;
  ip->ip_ttl = (s->ttl < 0) ? 64 : s->ttl;
  ip->ip_p = s->dport;
  ip->ip_src = ipa_to_in4(s->saddr);
  ip->ip_dst = ipa_to_in4(s->daddr);

#if (defined __OpenBSD__) || (defined __DragonFly__) || (defined __FreeBSD__ && (__FreeBSD_version >= 1100030))
  /* Different BSDs have different expectations of ip_len endianity */
  ip->ip_len = htons(ip->ip_len);
#endif
}


/*
 *	TCP-AO (not supported)
 */

int
sk_get_ao_info(sock *s UNUSED, struct ao_info *val UNUSED)
{
  ERR_MSG("TCP-AO not supported");
}

int
sk_get_active_ao_keys(sock *s UNUSED, int *current_key UNUSED, int *rnext_key UNUSED)
{
  ERR_MSG("TCP-AO not supported");
}

bool
tcp_ao_alg_known(int algorithm UNUSED)
{
  return 0;
}

int
sk_add_ao_key(sock *s UNUSED, ip_addr prefix UNUSED, int pxlen UNUSED, struct iface *ifa UNUSED, const struct ao_key *key UNUSED, bool current UNUSED, bool rnext UNUSED)
{
  ERR_MSG("TCP-AO not supported");
}

int
sk_delete_ao_key(sock *s UNUSED, ip_addr prefix UNUSED, int pxlen UNUSED, struct iface *ifa UNUSED, const struct ao_key *key UNUSED, const struct ao_key *current UNUSED, const struct ao_key *rnext UNUSED)
{
  ERR_MSG("TCP-AO not supported");
}

int
sk_set_rnext_ao_key(sock *s UNUSED, const struct ao_key *key UNUSED)
{
  ERR_MSG("TCP-AO not supported");
}

int
sk_check_ao_keys(sock *s UNUSED, const struct ao_key **keys UNUSED, int num UNUSED, const char *name UNUSED)
{
  errno = 0;
  s->err = "TCP-AO not supported";
  sk_log_error(s, name);

  return -1;
}

void
sk_dump_ao_info(sock *s UNUSED, struct dump_request *dreq UNUSED)
{
  RDUMP("TCP-AO not supported\n");
}

void
sk_dump_ao_keys(sock *s UNUSED, struct dump_request *dreq UNUSED)
{
  RDUMP("TCP-AO not supported\n");
}


/*
 *	Miscellaneous BSD socket syscalls
 */

#ifndef TCP_KEYLEN_MAX
#define TCP_KEYLEN_MAX 80
#endif

#ifndef TCP_SIG_SPI
#define TCP_SIG_SPI 0x1000
#endif

#if defined(__FreeBSD__)
#define USE_MD5SIG_SETKEY
#include "sysdep/bsd/setkey.h"
#endif

int
sk_set_md5_auth(sock *s, ip_addr local UNUSED, ip_addr remote UNUSED, int pxlen UNUSED, struct iface *ifa UNUSED, const char *passwd, int setkey UNUSED)
{
#ifdef USE_MD5SIG_SETKEY
  if (setkey)
    if (sk_set_md5_in_sasp_db(s, local, remote, pxlen, ifa, passwd) < 0)
      return -1;
#endif

  int enable = (passwd && *passwd) ? TCP_SIG_SPI : 0;
  if (setsockopt(s->fd, IPPROTO_TCP, TCP_MD5SIG, &enable, sizeof(enable)) < 0)
  {
    if (errno == ENOPROTOOPT)
      ERR_MSG("Kernel does not support TCP MD5 signatures");
    else
      ERR("TCP_MD5SIG");
  }

  return 0;
}

static inline int
sk_set_min_ttl4(sock *s, int ttl)
{
  if (setsockopt(s->fd, IPPROTO_IP, IP_MINTTL, &ttl, sizeof(ttl)) < 0)
  {
    if (errno == ENOPROTOOPT)
      ERR_MSG("Kernel does not support IPv4 TTL security");
    else
      ERR("IP_MINTTL");
  }

  return 0;
}

static inline int
sk_set_min_ttl6(sock *s, int ttl UNUSED)
{
  ERR_MSG("Kernel does not support IPv6 TTL security");
}

static inline int
sk_disable_mtu_disc4(sock *s UNUSED)
{
  /* TODO: Set IP_DONTFRAG to 0 ? */
  return 0;
}

static inline int
sk_disable_mtu_disc6(sock *s UNUSED)
{
  /* TODO: Set IPV6_DONTFRAG to 0 ? */
  return 0;
}

int sk_priority_control = -1;

static inline int
sk_set_priority(sock *s, int prio UNUSED)
{
  ERR_MSG("Socket priority not supported");
}

static inline int
sk_set_freebind(sock *s)
{
  ERR_MSG("Freebind is not supported");
}

static inline int
sk_set_udp6_no_csum_rx(sock *s)
{
  ERR_MSG("UDPv6 zero checksum is not supported");
}
