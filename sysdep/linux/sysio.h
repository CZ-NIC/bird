/*
 *	BIRD Internet Routing Daemon -- Linux Multicasting and Network Includes
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <net/if.h>


#ifndef IPV6_UNICAST_HOPS
/* Needed on glibc 2.0 systems */
#include <linux/in6.h>
#define CONFIG_IPV6_GLIBC_20
#endif


#ifndef HAVE_STRUCT_IP_MREQN
/* Several versions of glibc don't define this structure, so we have to do it ourselves */
struct ip_mreqn
{
	struct in_addr	imr_multiaddr;		/* IP multicast address of group */
	struct in_addr	imr_address;		/* local IP address of interface */
	int		imr_ifindex;		/* Interface index */
};
#endif


static inline void fill_mreqn(struct ip_mreqn *m, ip_addr maddr, struct iface *ifa)
{
  bzero(m, sizeof(*m));
  m->imr_ifindex = ifa->index;
  ipa_put_in4(&m->imr_multiaddr, maddr);
}

static inline char *
sk_setup_multicast4(sock *s)
{
  struct ip_mreqn m;
  int zero = 0;

  if (setsockopt(s->fd, SOL_IP, IP_MULTICAST_LOOP, &zero, sizeof(zero)) < 0)
    return "IP_MULTICAST_LOOP";

  if (setsockopt(s->fd, SOL_IP, IP_MULTICAST_TTL, &s->ttl, sizeof(s->ttl)) < 0)
    return "IP_MULTICAST_TTL";

  /* This defines where should we send _outgoing_ multicasts */
  fill_mreqn(&m, IPA_NONE, s->iface);
  if (setsockopt(s->fd, SOL_IP, IP_MULTICAST_IF, &m, sizeof(m)) < 0)
    return "IP_MULTICAST_IF";

  return NULL;
}

static inline char *
sk_join_group4(sock *s, ip_addr maddr)
{
  struct ip_mreqn m;

  fill_mreqn(&m, maddr, s->iface);
  if (setsockopt(s->fd, SOL_IP, IP_ADD_MEMBERSHIP, &m, sizeof(m)) < 0)
    return "IP_ADD_MEMBERSHIP";

  return NULL;
}

static inline char *
sk_leave_group4(sock *s, ip_addr maddr)
{
  struct ip_mreqn m;

  fill_mreqn(&m, maddr, s->iface);
  if (setsockopt(s->fd, SOL_IP, IP_DROP_MEMBERSHIP, &m, sizeof(m)) < 0)
    return "IP_DROP_MEMBERSHIP";

  return NULL;
}


/* For the case that we have older libc headers */
/* Copied from Linux kernel file include/linux/tcp.h */

#ifndef TCP_MD5SIG

#define TCP_MD5SIG  14
#define TCP_MD5SIG_MAXKEYLEN 80

#include <linux/types.h>

struct tcp_md5sig {
  struct  sockaddr_storage tcpm_addr;             /* address associated */
  __u16   __tcpm_pad1;                            /* zero */
  __u16   tcpm_keylen;                            /* key length */
  __u32   __tcpm_pad2;                            /* zero */
  __u8    tcpm_key[TCP_MD5SIG_MAXKEYLEN];         /* key (binary) */
};

#endif

static int
sk_set_md5_auth_int(sock *s, struct sockaddr *sa, int sa_len, char *passwd)
{
  struct tcp_md5sig md5;

  memset(&md5, 0, sizeof(md5));
  memcpy(&md5.tcpm_addr, sa, sa_len);

  if (passwd)
    {
      int len = strlen(passwd);

      if (len > TCP_MD5SIG_MAXKEYLEN)
	{
	  log(L_ERR "MD5 password too long");
	  return -1;
	}

      md5.tcpm_keylen = len;
      memcpy(&md5.tcpm_key, passwd, len);
    }

  int rv = setsockopt(s->fd, SOL_TCP, TCP_MD5SIG, &md5, sizeof(md5));

  if (rv < 0) 
    {
      if (errno == ENOPROTOOPT)
	log(L_ERR "Kernel does not support TCP MD5 signatures");
      else
	log(L_ERR "sk_set_md5_auth_int: TCP_MD5SIG: %m");
    }

  return rv;
}


/* RX/TX packet info handling for IPv4 */
/* Mostly similar to standardized IPv6 code */

#define CMSG4_SPACE_PKTINFO CMSG_SPACE(sizeof(struct in_pktinfo))

static inline char *
sk_request_cmsg4_pktinfo(sock *s)
{
  int ok = 1;

  if (setsockopt(s->fd, SOL_IP, IP_PKTINFO, &ok, sizeof(ok)) < 0)
    return "IP_PKTINFO";

  return NULL;
}

static inline void
sk_process_cmsg4_pktinfo(sock *s, struct cmsghdr *cm)
{
  if ((cm->cmsg_type == IP_PKTINFO) && (s->flags & SKF_LADDR_RX))
  {
    struct in_pktinfo *pi = (struct in_pktinfo *) CMSG_DATA(cm);
    s->laddr = ipa_get_in4(&pi->ipi_addr);
    s->lifindex = pi->ipi_ifindex;
  }
}


#define CMSG4_SPACE_TTL CMSG_SPACE(sizeof(int))

static inline char *
sk_request_cmsg4_ttl(sock *s)
{
  int ok = 1;

  if (setsockopt(s->fd, SOL_IP, IP_RECVTTL, &ok, sizeof(ok)) < 0)
    return "IP_RECVTTL";

  return NULL;
}

static inline void
sk_process_cmsg4_ttl(sock *s, struct cmsghdr *cm)
{
  if ((cm->cmsg_type == IP_TTL) && (s->flags & SKF_TTL_RX))
    s->ttl = * (int *) CMSG_DATA(cm);
}


static inline void
sk_prepare_cmsgs4(sock *s, struct msghdr *msg, void *cbuf, size_t cbuflen)
{
  struct cmsghdr *cm;
  struct in_pktinfo *pi;

  msg->msg_control = cbuf;
  msg->msg_controllen = cbuflen;

  cm = CMSG_FIRSTHDR(msg);
  cm->cmsg_level = SOL_IP;
  cm->cmsg_type = IP_PKTINFO;
  cm->cmsg_len = CMSG_LEN(sizeof(*pi));

  pi = (struct in_pktinfo *) CMSG_DATA(cm);
  pi->ipi_ifindex = s->iface ? s->iface->index : 0;
  ipa_put_in4(&pi->ipi_spec_dst, s->saddr);
  ipa_put_in4(&pi->ipi_addr, IPA_NONE);

  msg->msg_controllen = cm->cmsg_len;
}



#ifndef IP_MINTTL
#define IP_MINTTL 21
#endif

#ifndef IPV6_MINHOPCOUNT
#define IPV6_MINHOPCOUNT 73
#endif

static inline char *
sk_set_min_ttl4(sock *s, int ttl)
{
  if (setsockopt(s->fd, SOL_IP, IP_MINTTL, &ttl, sizeof(ttl)) < 0)
    return "IP_MINTTL";

  return NULL;
}

static inline char *
sk_set_min_ttl6(sock *s, int ttl)
{
  if (setsockopt(s->fd, SOL_IPV6, IPV6_MINHOPCOUNT, &ttl, sizeof(ttl)) < 0)
    return "IPV6_MINHOPCOUNT";

  return NULL;
}


#ifndef IPV6_TCLASS
#define IPV6_TCLASS 67
#endif

int sk_priority_control = 7;

static int
sk_set_priority(sock *s, int prio)
{
  if (setsockopt(s->fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio)) < 0)
  {
    log(L_WARN "sk_set_priority: setsockopt: %m");
    return -1;
  }

  return 0;
}

