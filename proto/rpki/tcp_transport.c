/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file was part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "rpki.h"

#include "tcp_transport.h"
#include "lib/unix.h"


static int tr_tcp_open(void *tr_tcp_sock);
static void tr_tcp_close(void *tr_tcp_sock);
static void tr_tcp_free(struct tr_socket *tr_sock);
static const char *tr_tcp_ident(void *socket);

int tr_tcp_open(void *tr_tcp_sock)
{
  struct tr_tcp_socket *tcp_socket = tr_tcp_sock;
  struct rpki_cache *cache = tcp_socket->cache;
  struct rpki_proto *p = cache->p;

  sock *sk = cache->sk;
  sk->type = SK_TCP_ACTIVE;

  if (sk_open(sk) != 0)
    return TR_ERROR;

  return TR_SUCCESS;
}

void tr_tcp_close(void *tr_tcp_sock)
{
  struct tr_tcp_socket *tcp_socket = tr_tcp_sock;
  struct rpki_cache *cache = tcp_socket->cache;
  struct rpki_proto *p = cache->p;

  sock *s = cache->sk;
  if (s && s->fd > 0)
  {
    /* TODO: ??? */
  }
}

void tr_tcp_free(struct tr_socket *tr_sock)
{
  struct tr_tcp_socket *tcp_sock = tr_sock->socket;

  if (tcp_sock)
  {
    if (tcp_sock->ident != NULL)
      mb_free(tcp_sock->ident);
    tr_sock->socket = NULL;
    mb_free(tcp_sock);
  }
}

const char *tr_tcp_ident(void *socket)
{
  assert(socket != NULL);

  struct tr_tcp_socket *sock = socket;
  struct rpki_proto *p = sock->cache->p;

  if (sock->ident != NULL)
    return sock->ident;

  size_t colon_and_port_len = 6; /* max ":65535" */
  size_t ident_len;
  if (sock->config.host)
    ident_len = strlen(sock->config.host) + colon_and_port_len + 1;
  else
    ident_len = STD_ADDRESS_P_LENGTH + colon_and_port_len + 1;

  sock->ident = mb_allocz(p->p.pool, ident_len);
  if (sock->ident == NULL)
    return NULL;

  if (sock->config.host)
    bsnprintf(sock->ident, ident_len, "%s:%u", sock->config.host, sock->config.port);
  else
    bsnprintf(sock->ident, ident_len, "%I:%u", sock->config.ip, sock->config.port);

  return sock->ident;
}

/*
 * Fulfill the (ip_addr) tcp_socket->config.ip
 * Return TR_SUCCESS or TR_ERROR
 */
static int
fulfill_ip_addr(struct tr_tcp_socket *tcp_socket)
{
  struct rpki_cache *cache = tcp_socket->cache;
  struct rpki_proto *p = cache->p;

  struct addrinfo hints;
  struct addrinfo *res;
  struct addrinfo *bind_addrinfo = NULL;

  bzero(&hints, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_ADDRCONFIG;

  char port_buf[6]; /* max is "65535" + '\0' */
  snprintf(port_buf, sizeof(port_buf), "%u", tcp_socket->config.port);

  if (getaddrinfo(tcp_socket->config.host, port_buf, &hints, &res) != 0)
  {
    CACHE_TRACE(D_EVENTS, cache, "getaddrinfo error, %s", gai_strerror(errno));
    return TR_ERROR;
  }

  sockaddr sa = {
      .sa = *res->ai_addr,
  };

  uint unused;
  sockaddr_read(&sa, res->ai_family, &tcp_socket->config.ip, NULL, &unused);

  freeaddrinfo(res);
  return TR_SUCCESS;
}

int tr_tcp_init(struct rpki_cache *cache)
{
  struct rpki_proto *p = cache->p;
  struct rpki_cache_cfg *cache_cfg = cache->cfg;
  struct tr_socket *tr_socket = cache->rtr_socket->tr_socket;

  tr_socket->close_fp = &tr_tcp_close;
  tr_socket->free_fp = &tr_tcp_free;
  tr_socket->open_fp = &tr_tcp_open;
  tr_socket->ident_fp = &tr_tcp_ident;

  tr_socket->socket = mb_allocz(p->p.pool, sizeof(struct tr_tcp_socket));
  struct tr_tcp_socket *tcp = tr_socket->socket;

  tcp->cache = cache;
  tcp->config.host = cache_cfg->hostname;
  tcp->config.ip = cache_cfg->ip;
  tcp->config.port = cache_cfg->port;

  assert(ipa_nonzero(tcp->config.ip) || tcp->config.host != NULL);
  if (ipa_zero(tcp->config.ip))
  {
    if (fulfill_ip_addr(tcp) == TR_ERROR)
      return TR_ERROR;
  }

  return TR_SUCCESS;
}
