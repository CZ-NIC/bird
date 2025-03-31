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

/* Used for legacy system builds (e.g. CentOS 7) */
#ifndef UDP_NO_CHECK6_RX
#define UDP_NO_CHECK6_RX 102
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
 *	TCP-AO
 */

int
sk_get_ao_info(sock *s, struct ao_info *val)
{
  struct tcp_ao_info_opt_ext info = {};
  socklen_t len = sizeof(info);

  if (getsockopt(s->fd, IPPROTO_TCP, TCP_AO_INFO, &info, &len) < 0)
    ERR("TCP_AO_INFO");

  *val = (struct ao_info) {
    .current_key = info.set_current ? info.current_key : -1,
    .rnext_key = info.set_rnext ? info.rnext : -1,
    .pkt_good = info.pkt_good,
    .pkt_bad = info.pkt_bad,
  };
  return 0;
}

int
sk_get_active_ao_keys(sock *s, int *current_key, int *rnext_key)
{
  struct tcp_ao_info_opt_ext info = {};
  socklen_t len = sizeof(info);

  if (getsockopt(s->fd, IPPROTO_TCP, TCP_AO_INFO, &info, &len) < 0)
    ERR("TCP_AO_INFO");

  *current_key = info.set_current ? info.current_key : -1;
  *rnext_key = info.set_rnext ? info.rnext : -1;
  return 0;
}

static int
sk_get_ao_keys_num(sock *s)
{
  struct tcp_ao_getsockopt_ext keys = {
    .nkeys = 1,
    .get_all = 1,
  };
  socklen_t len = sizeof(keys);

  if (getsockopt(s->fd, IPPROTO_TCP, TCP_AO_GET_KEYS, &keys, &len) < 0)
    ERR("TCP_AO_GET_KEYS");

  return keys.nkeys;
}

static int
sk_get_ao_keys(sock *s, struct tcp_ao_getsockopt_ext **keys, int *keys_num)
{
  *keys = NULL;
  *keys_num = 0;

  int num = sk_get_ao_keys_num(s);
  if (num < 1)
    return num;

  *keys = tmp_allocz(num * sizeof(struct tcp_ao_getsockopt_ext));
  (*keys)[0].nkeys = num;
  (*keys)[0].get_all = 1;

  /* len should be just size of one struct. See kernel net/ipv4/tcp_ao.c line 2165 */
  socklen_t len = sizeof(struct tcp_ao_getsockopt_ext);

  if (getsockopt(s->fd, IPPROTO_TCP, TCP_AO_GET_KEYS, *keys, &len) < 0)
    ERR("TCP_AO_GET_KEYS");

  *keys_num = (*keys)[0].nkeys;
  return 0;
}

static const char * const tcp_ao_alg_names[] = {
  [ALG_CMAC_AES128_AO]	= "cmac(aes128)",
  [ALG_HMAC_MD5]	= "hmac(md5)",
  [ALG_HMAC_SHA1]	= "hmac(sha1)",
  [ALG_HMAC_SHA224]	= "hmac(sha224)",
  [ALG_HMAC_SHA256]	= "hmac(sha256)",
  [ALG_HMAC_SHA384]	= "hmac(sha384)",
  [ALG_HMAC_SHA512]	= "hmac(sha512)",
};

bool
tcp_ao_alg_known(int algorithm)
{
  return (algorithm > 0) && (algorithm < (int) ARRAY_SIZE(tcp_ao_alg_names)) && tcp_ao_alg_names[algorithm];
}


/**
 * sk_add_ao_key - Add TCP-AO key to the socket
 * @s: Socket
 * @prefix: Prefix
 * @pxlen: Prefix length (or -1 for max)
 * @ifa: Interface (for IPv6 link-local prefix)
 * @key: TCP-AO key to be added
 * @current: Set the new key as current key
 * @rnext: Set the new key as rnext key
 *
 * The function adds the TCP-AO key @key to the kernel list of TCP-AO keys
 * associated with the socket. There can be multiple sets of keys for different
 * peers (for a listening socket), therefore the key is accompanied with the
 * relevant prefix (consists of @prefix, @pxlen, and @ifa).
 *
 * Result: 0 when successful, -1 for an error.
 */
int
sk_add_ao_key(sock *s, ip_addr prefix, int pxlen, struct iface *ifa, const struct ao_key *key, bool current, bool rnext)
{
  if (pxlen < 0)
    pxlen = (s->af == AF_INET) ? IP4_MAX_PREFIX_LENGTH : IP6_MAX_PREFIX_LENGTH;

  struct tcp_ao_add_ext ao = {};
  sockaddr_fill((sockaddr *) &ao.addr, s->af, prefix, ifa, 0);
  ao.prefix = pxlen;
  ao.sndid = key->send_id;
  ao.rcvid = key->recv_id;
  ao.set_current = current;
  ao.set_rnext = rnext;

  if (!tcp_ao_alg_known(key->algorithm))
    ERR_MSG("Unknown TCP-AO algorithm");

  strncpy(ao.alg_name, tcp_ao_alg_names[key->algorithm], sizeof(ao.alg_name));
  ao.keylen = key->keylen;
  memcpy(ao.key, key->key, MIN(key->keylen, TCP_AO_MAXKEYLEN_));

  if (setsockopt(s->fd, IPPROTO_TCP, TCP_AO_ADD_KEY, &ao, sizeof(ao)) < 0)
  {
    if (errno == ENOPROTOOPT)
      ERR_MSG("Kernel does not support TCP-AO signatures");
    else
      ERR("TCP_AO_ADD_KEY");
  }

  return 0;
}

/**
 * sk_delete_ao_key - Delete TCP-AO key from the socket
 * @s: Socket
 * @prefix: Prefix
 * @pxlen: Prefix length (or -1 for max)
 * @ifa: Interface (for IPv6 link-local prefix)
 * @key: TCP-AO key to be deleted
 * @current: Optionally set current key
 * @rnext: Optionally set rnext key
 *
 * The function removes the TCP-AO key @key from the kernel list of TCP-AO keys
 * associated with the socket. There can be multiple sets of keys for different
 * peers, therefore the key for deletion is identified not only by its send/recv
 * ID, but also by the relevant prefix (consists of @prefix, @pxlen, and @ifa).
 * Keys on incoming sockets that were cloned from the listening socket use the
 * same prefix as on the listening socket.
 *
 * Optionally, the current key and the rnext key can be set atomically together
 * with the deletion, avoiding failure when the deleted key is current / rnext.
 *
 * Result: 0 when successful, -1 for an error.
 */
int
sk_delete_ao_key(sock *s, ip_addr prefix, int pxlen, struct iface *ifa, const struct ao_key *key, const struct ao_key *current, const struct ao_key *rnext)
{
  if (pxlen < 0)
    pxlen = (s->af == AF_INET) ? IP4_MAX_PREFIX_LENGTH : IP6_MAX_PREFIX_LENGTH;

  struct tcp_ao_del_ext ao = {};
  sockaddr_fill((sockaddr *) &ao.addr, s->af, prefix, ifa, 0);
  ao.prefix = pxlen;
  ao.sndid = key->send_id;
  ao.rcvid = key->recv_id;

  if (current)
  {
    ao.set_current = 1;
    ao.current_key = current->send_id;
  }

  if (rnext)
  {
    ao.set_rnext = 1;
    ao.rnext = rnext->recv_id;
  }

  if (setsockopt(s->fd, IPPROTO_TCP, TCP_AO_DEL_KEY, &ao, sizeof(ao)) < 0)
    ERR("TCP_AO_DEL_KEY");

  return 0;
}

/**
 * sk_set_rnext_ao_key - Set RNext TCP-AO key from the socket
 * @s: Socket
 * @key: TCP-AO key to be set as RNext
 *
 * Change RNext key of the socket @s to (already added) @key. Cannot be used on
 * listening sockets.
 *
 * Result: 0 when successful, -1 for an error.
 */
int
sk_set_rnext_ao_key(sock *s, const struct ao_key *key)
{
  struct tcp_ao_info_opt_ext ao = {
    .set_rnext = 1,
    .rnext = key->recv_id,
  };

  if (setsockopt(s->fd, IPPROTO_TCP, TCP_AO_INFO, &ao, sizeof(ao)) < 0)
    ERR("TCP_AO_INFO");

  return 0;
}

/**
 * sk_check_ao_keys - Check TCP-AO keys on socket against a list of expected keys
 * @s: Socket
 * @keys: Array of keys
 * @num: Number of keys
 * @name: Name of caller, prefix for error messages
 *
 * The function reads TCP-AO keys from the kernel and compares them to the
 * provided set of keys. When inconsistencies are found, they are logged and the
 * function reports the error. This is useful for fds received from accept(), to
 * avoid race conditions when keys are cloned from the listening fd.
 *
 * Result: 0 when consistent, -1 for an error.
 */
int
sk_check_ao_keys(sock *s, const struct ao_key **keys, int num, const char *name)
{
  u32 expected_keys[256 / 32];
  u8 key_pos[256];
  int errors = 0;

  BIT32_ZERO(expected_keys, 256);
  for (int i = 0; i < num; i++)
  {
    int id = keys[i]->send_id;
    BIT32_SET(expected_keys, id);
    key_pos[id] = i;
  }

  struct tcp_ao_getsockopt_ext *sk_keys;
  int sk_keys_num;

  if (sk_get_ao_keys(s, &sk_keys, &sk_keys_num) < 0)
  {
    sk_log_error(s, name);
    return -1;
  }

  for (int i = 0; i < sk_keys_num; i++)
  {
    const struct tcp_ao_getsockopt_ext *key = &sk_keys[i];

    if (!BIT32_TEST(expected_keys, key->sndid) ||
	(key->rcvid != keys[key_pos[key->sndid]]->recv_id))
    {
      log(L_WARN "%s: Unexpected TCP-AO key %i/%i found on socket",
	  name, key->sndid, key->rcvid);
      errors++;
      continue;
    }

    BIT32_CLR(expected_keys, key->sndid);
  }

  if (!errors && (sk_keys_num == num))
    return 0;

  for (int i = 0; i < 256; i++)
  {
    if (BIT32_TEST(expected_keys, i))
    {
      const struct ao_key *key = keys[key_pos[i]];
      log(L_WARN "%s: Expected TCP-AO key %i/%i not found on socket",
	  name, key->send_id, key->recv_id);
      errors++;
    }
  }

  return errors ? -1 : 0;
}

void
sk_dump_ao_info(sock *s, struct dump_request *dreq)
{
  struct ao_info info;
  if (sk_get_ao_info(s, &info) < 0)
  {
    RDUMP("Socket error: %s%#m\n", s->err);
    return;
  }

  RDUMP("TCP-AO on socket fd %i: current key %i, rnext key %i, good packets %lu, bad packets %lu\n",
	s->fd, info.current_key, info.rnext_key, info.pkt_good, info.pkt_bad);
}

void
sk_dump_ao_keys(sock *s, struct dump_request *dreq)
{
  struct tcp_ao_getsockopt_ext *keys;
  int keys_num;

  if (sk_get_ao_keys(s, &keys, &keys_num) < 0)
  {
    RDUMP("Socket error: %s%#m\n", s->err);
    return;
  }

  RDUMP("TCP-AO on socket fd %i has %i keys\n", s->fd, keys_num);
  for (int i = 0; i < keys_num; i++)
  {
    const struct tcp_ao_getsockopt_ext *key = &keys[i];

    ip_addr prefix; uint unused;
    sockaddr_read((sockaddr *) &key->addr, s->af, &prefix, NULL, &unused);

    net_addr net;
    net_fill_ipa(&net, prefix, key->prefix);

    char secret[TCP_AO_MAXKEYLEN_ * 3];
    bstrbintohex(key->key, MIN(key->keylen, TCP_AO_MAXKEYLEN_), secret, sizeof(secret), ':');

    RDUMP("Key %i/%i for %N: %s%salgo %s, secret %s\n",
	key->sndid, key->rcvid, &net, key->is_current ? "current, " : "",
	key->is_rnext ? "rnext, " : "", key->alg_name, secret);
  }
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

static inline int
sk_set_udp6_no_csum_rx(sock *s)
{
  int y = 1;

  if (setsockopt(s->fd, SOL_UDP, UDP_NO_CHECK6_RX, &y, sizeof(y)) < 0)
    ERR("UDP_NO_CHECK6_RX");

  return 0;
}
