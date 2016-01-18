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

  sock *sk = cache->sk;
  if (sk && sk->fd > 0)
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
  ASSERT(socket != NULL);

  struct tr_tcp_socket *tcp = socket;
  struct rpki_cache *cache = tcp->cache;

  if (tcp->ident != NULL)
    return tcp->ident;

  const char *host = cache->cfg->hostname;

  size_t colon_and_port_len = 6; /* max ":65535" */
  size_t ident_len;
  if (host)
    ident_len = strlen(host) + colon_and_port_len + 1;
  else
    ident_len = IPA_MAX_TEXT_LENGTH + colon_and_port_len + 1;

  tcp->ident = mb_allocz(cache->p->p.pool, ident_len);
  if (tcp->ident == NULL)
    return NULL;

  if (host)
    bsnprintf(tcp->ident, ident_len, "%s:%u", host, cache->cfg->port);
  else
    bsnprintf(tcp->ident, ident_len, "%I:%u", cache->cfg->ip, cache->cfg->port);

  return tcp->ident;
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

  return TR_SUCCESS;
}
