/*
 *	BIRD Internet Routing Daemon -- Linux Multicasting and Network Includes
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "sysdep/linux/tcp-ao.h"

#ifndef IPV6_MINHOPCOUNT
#define IPV6_MINHOPCOUNT 73
#endif

#ifndef IPV6_FREEBIND
#define IPV6_FREEBIND 78
#endif

#ifndef TCP_MD5SIG_EXT
#define TCP_MD5SIG_EXT 32
#endif

#ifndef TCP_MD5SIG_FLAG_PREFIX
#define TCP_MD5SIG_FLAG_PREFIX 1
#endif


/* We redefine the tcp_md5sig structure with different name to avoid collision with older headers */
struct tcp_md5sig_ext {
  struct  sockaddr_storage tcpm_addr;		/* Address associated */
  u8    tcpm_flags;				/* Extension flags */
  u8    tcpm_prefixlen;				/* Address prefix */
  u16   tcpm_keylen;				/* Key length */
  u32   __tcpm_pad2;				/* Zero */
  u8    tcpm_key[TCP_MD5SIG_MAXKEYLEN];		/* Key (binary) */
};


/* Linux does not care if sa_len is larger than needed */
#define SA_LEN(x) sizeof(sockaddr)


/*
 *	Linux IPv4 multicast syscalls
 */

#define INIT_MREQ4(maddr,ifa) \
  { .imr_multiaddr = ipa_to_in4(maddr), .imr_ifindex = ifa->index }

static inline int
sk_setup_multicast4(sock *s)
{
  struct ip_mreqn mr = { .imr_ifindex = s->iface->index };
  int ttl = s->ttl;
  int n = 0;

  /* This defines where should we send _outgoing_ multicasts */
  if (setsockopt(s->fd, SOL_IP, IP_MULTICAST_IF, &mr, sizeof(mr)) < 0)
    ERR("IP_MULTICAST_IF");

  if (setsockopt(s->fd, SOL_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
    ERR("IP_MULTICAST_TTL");

  if (setsockopt(s->fd, SOL_IP, IP_MULTICAST_LOOP, &n, sizeof(n)) < 0)
    ERR("IP_MULTICAST_LOOP");

  return 0;
}

static inline int
sk_join_group4(sock *s, ip_addr maddr)
{
  struct ip_mreqn mr = INIT_MREQ4(maddr, s->iface);

  if (setsockopt(s->fd, SOL_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
    ERR("IP_ADD_MEMBERSHIP");

  return 0;
}

static inline int
sk_leave_group4(sock *s, ip_addr maddr)
{
  struct ip_mreqn mr = INIT_MREQ4(maddr, s->iface);

  if (setsockopt(s->fd, SOL_IP, IP_DROP_MEMBERSHIP, &mr, sizeof(mr)) < 0)
    ERR("IP_DROP_MEMBERSHIP");

  return 0;
}


/*
 *	Linux IPv4 packet control messages
 */

/* Mostly similar to standardized IPv6 code */

#define CMSG4_SPACE_PKTINFO CMSG_SPACE(sizeof(struct in_pktinfo))
#define CMSG4_SPACE_TTL CMSG_SPACE(sizeof(int))

static inline int
sk_request_cmsg4_pktinfo(sock *s)
{
  int y = 1;

  if (setsockopt(s->fd, SOL_IP, IP_PKTINFO, &y, sizeof(y)) < 0)
    ERR("IP_PKTINFO");

  return 0;
}

static inline int
sk_request_cmsg4_ttl(sock *s)
{
  int y = 1;

  if (setsockopt(s->fd, SOL_IP, IP_RECVTTL, &y, sizeof(y)) < 0)
    ERR("IP_RECVTTL");

  return 0;
}

static inline void
sk_process_cmsg4_pktinfo(sock *s, struct cmsghdr *cm)
{
  if (cm->cmsg_type == IP_PKTINFO)
  {
    struct in_pktinfo *pi = (struct in_pktinfo *) CMSG_DATA(cm);
    s->laddr = ipa_from_in4(pi->ipi_addr);
    s->lifindex = pi->ipi_ifindex;
  }
}

static inline void
sk_process_cmsg4_ttl(sock *s, struct cmsghdr *cm)
{
  if (cm->cmsg_type == IP_TTL)
    s->rcv_ttl = * (int *) CMSG_DATA(cm);
}

static inline void
sk_prepare_cmsgs4(sock *s, struct msghdr *msg, void *cbuf, size_t cbuflen)
{
  struct cmsghdr *cm;
  struct in_pktinfo *pi;
  int controllen = 0;

  msg->msg_control = cbuf;
  msg->msg_controllen = cbuflen;

  cm = CMSG_FIRSTHDR(msg);
  cm->cmsg_level = SOL_IP;
  cm->cmsg_type = IP_PKTINFO;
  cm->cmsg_len = CMSG_LEN(sizeof(*pi));
  controllen += CMSG_SPACE(sizeof(*pi));

  pi = (struct in_pktinfo *) CMSG_DATA(cm);
  pi->ipi_ifindex = s->iface ? s->iface->index : 0;
  pi->ipi_spec_dst = ipa_to_in4(s->saddr);
  pi->ipi_addr = ipa_to_in4(IPA_NONE);

  msg->msg_controllen = controllen;
}


/*
 *	Miscellaneous Linux socket syscalls
 */

int
sk_set_md5_auth(sock *s, ip_addr local UNUSED, ip_addr remote, int pxlen, struct iface *ifa, const char *passwd, int setkey UNUSED)
{
  struct tcp_md5sig_ext md5;

  memset(&md5, 0, sizeof(md5));
  sockaddr_fill((sockaddr *) &md5.tcpm_addr, s->af, remote, ifa, 0);

  if (passwd)
  {
    int len = strlen(passwd);

    if (len > TCP_MD5SIG_MAXKEYLEN)
      ERR_MSG("The password for TCP MD5 Signature is too long");

    md5.tcpm_keylen = len;
    memcpy(&md5.tcpm_key, passwd, len);
  }

  if (pxlen < 0)
  {
    if (setsockopt(s->fd, SOL_TCP, TCP_MD5SIG, &md5, sizeof(md5)) < 0)
      if (errno == ENOPROTOOPT)
	ERR_MSG("Kernel does not support TCP MD5 signatures");
      else
	ERR("TCP_MD5SIG");
  }
  else
  {
    md5.tcpm_flags = TCP_MD5SIG_FLAG_PREFIX;
    md5.tcpm_prefixlen = pxlen;

    if (setsockopt(s->fd, SOL_TCP, TCP_MD5SIG_EXT, &md5, sizeof(md5)) < 0)
    {
      if (errno == ENOPROTOOPT)
	ERR_MSG("Kernel does not support extended TCP MD5 signatures");
      else
	ERR("TCP_MD5SIG_EXT");
    }
  }

  return 0;
}

void log_tcp_ao_info(int sock_fd)
{
  struct tcp_ao_info_opt_ext tmp;
  memset(&tmp, 0, sizeof(struct tcp_ao_info_opt_ext));
  socklen_t len = sizeof(tmp);

  if (getsockopt(sock_fd, IPPROTO_TCP, TCP_AO_INFO, &tmp, &len))
  {
    log(L_WARN "TCP AO: log tcp ao info failed with err code %i", errno);
    return;
  }
  else
    log(L_INFO "TCP AO on socket %i:\ncurrent key id %i (loc), next key %i (rem),\n set current %i, is ao required %i\n good packets %i, bad packets %i",
		    sock_fd, tmp.current_key, tmp.rnext, tmp.set_current, tmp.ao_required, tmp.pkt_good, tmp.pkt_bad);
}

int get_current_key_id(int sock_fd)
{
  struct tcp_ao_info_opt_ext tmp;
  memset(&tmp, 0, sizeof(struct tcp_ao_info_opt_ext));
  socklen_t len = sizeof(tmp);

  if (getsockopt(sock_fd, IPPROTO_TCP, TCP_AO_INFO, &tmp, &len))
  {
    log(L_WARN "TCP AO: Getting current ao key for socket file descriptor %i failed with errno %i", sock_fd, errno);
    return -1;
  }
  else
    return tmp.current_key;
}

int get_rnext_key_id(int sock_fd)
{
  struct tcp_ao_info_opt_ext tmp;
  memset(&tmp, 0, sizeof(struct tcp_ao_info_opt_ext));
  socklen_t len = sizeof(tmp);

  if (getsockopt(sock_fd, IPPROTO_TCP, TCP_AO_INFO, &tmp, &len))
  {
    log(L_WARN "TCP AO: Getting rnext ao key for socket file descriptor %i failed with errno %i", sock_fd, errno);
    return -1;
  }
  else
    return tmp.rnext;
}

int get_num_ao_keys(int sock_fd)
{
  struct tcp_ao_getsockopt_ext tmp;
  memset(&tmp, 0, sizeof(struct tcp_ao_getsockopt_ext));
  socklen_t len = sizeof(tmp);
  tmp.nkeys = 1;
  tmp.get_all = 1;

  if (getsockopt(sock_fd, IPPROTO_TCP, TCP_AO_GET_KEYS, &tmp, &len))
  {
    log(L_WARN "TCP AO: get keys on socket fd %i failed with err code %i", sock_fd, errno);
    return -1;
  }
  return tmp.nkeys;
}

void
log_tcp_ao_get_key(int sock_fd)
{
  int nkeys = get_num_ao_keys(sock_fd);
  if (nkeys < 0)
    return;
  struct tcp_ao_getsockopt_ext tm_all[nkeys];
  socklen_t len = sizeof(struct tcp_ao_getsockopt_ext);
  memset(tm_all, 0, sizeof(struct tcp_ao_getsockopt_ext)*nkeys);
  tm_all[0].nkeys = nkeys;
  tm_all[0].get_all = 1;
  if (getsockopt(sock_fd, IPPROTO_TCP, TCP_AO_GET_KEYS, tm_all, &len))  // len should be still size of one struct. Because kernel net/ipv4/tcp_ao.c line 2165
  {
    log(L_WARN "TCP AO: getting keys on socket fd %i failed with err code %i", sock_fd, errno);
    return;
  }
  log(L_INFO "TCP AO on socket fd %i has %i keys", tm_all[0].nkeys);
  for (int i = 0; i < nkeys; i++)
  {
  
    char key_val[TCP_AO_MAXKEYLEN_*2+1];
    for (int ik = 0; ik<TCP_AO_MAXKEYLEN_; ik++)
      sprintf(&key_val[ik*2], "%x", tm_all[i].key[ik]);
    key_val[TCP_AO_MAXKEYLEN_*2] = 0;
    log(L_INFO "sndid %i rcvid %i, %s %s, cipher %s key %x (%i/%i)",
		    tm_all[i].sndid, tm_all[i].rcvid, tm_all[i].is_current ? "current" : "",
		    tm_all[i].is_rnext ? "rnext" : "", tm_all[i].alg_name, key_val, i+1, tm_all[0].nkeys);
  }
}

void
tcp_ao_get_info(int sock_fd, int key_info[4])
{
  struct tcp_ao_info_opt_ext tmp;
  memset(&tmp, 0, sizeof(struct tcp_ao_info_opt_ext));
  socklen_t len = sizeof(tmp);

  if (getsockopt(sock_fd, IPPROTO_TCP, TCP_AO_INFO, &tmp, &len))
  {
    log(L_WARN "TCP AO: log tcp ao info failed with err code %i", errno);
    return;
  }
  key_info[0] = tmp.current_key;
  key_info[1] = tmp.rnext;
  key_info[2] = tmp.pkt_good;
  key_info[3] = tmp.pkt_bad;
}

int
sk_set_ao_auth(sock *s, ip_addr local UNUSED, ip_addr remote, int pxlen, struct iface *ifa, const char *passwd, int passwd_id_loc, int passwd_id_rem, const char* cipher, int set_current)
{
  struct tcp_ao_add_ext ao;
  memset(&ao, 0, sizeof(struct tcp_ao_add_ext));
  log(L_DEBUG "tcp ao: socket sets ao, password %s socket fd %i", passwd, s->fd);

  sockaddr_fill((sockaddr *) &ao.addr, s->af, remote, ifa, 0);
  if (set_current)
  {
    ao.set_rnext = 1;
    ao.set_current = 1;
  }
  if (pxlen >= 0)
    ao.prefix = pxlen;
  else if(s->af == AF_INET)
    ao.prefix = 32;
  else
    ao.prefix = 128;
  ao.sndid	= passwd_id_loc;
  ao.rcvid	= passwd_id_rem;
  ao.maclen	= 0;
  ao.keyflags	= 0;
  ao.ifindex	= 0;

  strncpy(ao.alg_name, (cipher) ? cipher : DEFAULT_TEST_ALGO, 64);
  ao.keylen = strlen(passwd);
  memcpy(ao.key, passwd, (strlen(passwd) > TCP_AO_MAXKEYLEN_) ? TCP_AO_MAXKEYLEN_ : strlen(passwd));

  if (setsockopt(s->fd, IPPROTO_TCP, TCP_AO_ADD_KEY, &ao, sizeof(ao)) < 0)
  {
    if (errno == ENOPROTOOPT)
      ERR_MSG("Kernel does not support extended TCP AO signatures");
    else
      ERR("TCP_AOSIG_EXT");
  }
  s->use_ao = 1;
  if (set_current)
    s->desired_ao_key = passwd_id_loc;
  log_tcp_ao_get_key(s->fd);
  return 0;
}

int
ao_delete_key(sock *s, ip_addr remote, int pxlen, struct iface *ifa, int passwd_id_loc, int passwd_id_rem)
{
  struct tcp_ao_del_ext del;
  memset(&del, 0, sizeof(struct tcp_ao_del_ext));
  sockaddr_fill((sockaddr *) &del.addr, s->af, remote, ifa, 0);
  del.sndid = passwd_id_loc;
  del.rcvid = passwd_id_rem;
  if (pxlen >= 0)
    del.prefix = pxlen;
  else if(s->af == AF_INET)
    del.prefix = 32;
  else
    del.prefix = 128;

  if (setsockopt(s->fd, IPPROTO_TCP, TCP_AO_DEL_KEY, &del, sizeof(del)) < 0)
  {
    log(L_WARN "TCP AO: deletion of key %i %i on socket fd %i failed with err %i", passwd_id_loc, passwd_id_rem, s->fd, errno);
    return errno;
  }
  log(L_DEBUG "tcp ao: key %i %i deleted", passwd_id_loc, passwd_id_rem);
  return 0;
}

void
ao_try_change_master(sock *s, int next_master_id_loc, int next_master_id_rem)
{
  struct tcp_ao_info_opt_ext tmp;
  memset(&tmp, 0, sizeof(struct tcp_ao_info_opt_ext));
  tmp.set_rnext = 1;
  tmp.rnext = next_master_id_rem;

  if (setsockopt(s->fd, IPPROTO_TCP, TCP_AO_INFO, &tmp, sizeof(tmp)))
  {
     log(L_WARN "TCP AO: change master key failed with err code %i", errno);
     log_tcp_ao_get_key(s->fd);
     return;
  }
  else
    log(L_DEBUG "tcp ao: tried to change master to %i %i", next_master_id_loc, next_master_id_rem);
  s->desired_ao_key = next_master_id_loc;

}

int check_ao_keys_id(int sock_fd, struct bgp_ao_key *keys)
{
  int errors = 0;
  int expected_keys[256]; //can not have char, because we must support 0 key id
  memset(expected_keys, 0, sizeof(int)*256);
  for (struct bgp_ao_key *key = keys; key; key = key->next_key)
    expected_keys[key->key.local_id] = key->key.remote_id + 1; // the + 1 because we do not want 0 id be 0
  int nkeys = get_num_ao_keys(sock_fd);
  if (nkeys == -1)
  {
    log(L_WARN "TCP AO: unable to get num of keys");
    return 1;
  }
  struct tcp_ao_getsockopt_ext tm_all[nkeys];
  socklen_t len = sizeof(struct tcp_ao_getsockopt_ext);
  memset(tm_all, 0, sizeof(struct tcp_ao_getsockopt_ext)*nkeys);
  tm_all[0].nkeys = nkeys;
  tm_all[0].get_all = 1;
  if (getsockopt(sock_fd, IPPROTO_TCP, TCP_AO_GET_KEYS, tm_all, &len))  // len should be still size of one struct. Because kernel net/ipv4/tcp_ao.c line 2165
  {
    log(L_WARN "TCP AO: log tcp ao get keys failed with err code %i", errno);
    return 1;
  }
  for (int i = 0; i< nkeys; i++)
  {
    struct tcp_ao_getsockopt_ext sock_key = tm_all[i];
    if (expected_keys[sock_key.sndid] - 1 != sock_key.rcvid)
    {
      if (expected_keys[sock_key.rcvid] == 0)
        log(L_WARN "TCP AO: unexpected ao key %i %i", sock_key.rcvid, sock_key.sndid);
      else
        log(L_WARN "TCP AO: expected key local id %i has different remote id than expected (%i vs %i)", sock_key.sndid, expected_keys[sock_key.sndid] - 1, sock_key.rcvid);
      errors++;
    }
    expected_keys[sock_key.sndid] = 0;
  }
  for (int i = 0; i < 256; i++)
  {
    if (expected_keys[i] != 0)
    {
      log(L_WARN "TCP AO: key %i %i is not in socket", i, expected_keys - 1);
      errors++;
    }
  }
  return errors;
}

static inline int
sk_set_min_ttl4(sock *s, int ttl)
{
  if (setsockopt(s->fd, SOL_IP, IP_MINTTL, &ttl, sizeof(ttl)) < 0)
  {
    if (errno == ENOPROTOOPT)
      ERR_MSG("Kernel does not support IPv4 TTL security");
    else
      ERR("IP_MINTTL");
  }

  return 0;
}

static inline int
sk_set_min_ttl6(sock *s, int ttl)
{
  if (setsockopt(s->fd, SOL_IPV6, IPV6_MINHOPCOUNT, &ttl, sizeof(ttl)) < 0)
  {
    if (errno == ENOPROTOOPT)
      ERR_MSG("Kernel does not support IPv6 TTL security");
    else
      ERR("IPV6_MINHOPCOUNT");
  }

  return 0;
}

static inline int
sk_disable_mtu_disc4(sock *s)
{
  int dont = IP_PMTUDISC_DONT;

  if (setsockopt(s->fd, SOL_IP, IP_MTU_DISCOVER, &dont, sizeof(dont)) < 0)
    ERR("IP_MTU_DISCOVER");

  return 0;
}

static inline int
sk_disable_mtu_disc6(sock *s)
{
  int dont = IPV6_PMTUDISC_DONT;

  if (setsockopt(s->fd, SOL_IPV6, IPV6_MTU_DISCOVER, &dont, sizeof(dont)) < 0)
    ERR("IPV6_MTU_DISCOVER");

  return 0;
}

int sk_priority_control = 7;

static inline int
sk_set_priority(sock *s, int prio)
{
  if (setsockopt(s->fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio)) < 0)
    ERR("SO_PRIORITY");

  return 0;
}

static inline int
sk_set_freebind(sock *s)
{
  int y = 1;

  if (sk_is_ipv4(s))
    if (setsockopt(s->fd, SOL_IP, IP_FREEBIND, &y, sizeof(y)) < 0)
      ERR("IP_FREEBIND");

  if (sk_is_ipv6(s))
    if (setsockopt(s->fd, SOL_IPV6, IPV6_FREEBIND, &y, sizeof(y)) < 0)
      ERR("IPV6_FREEBIND");

  return 0;
}
