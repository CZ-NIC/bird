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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "utils.h"
#include "ssh_transport.h"
#include "lib/libssh.h"

#include "rpki.h"

static int tr_ssh_open(void *tr_ssh_sock);
static void tr_ssh_close(void *tr_ssh_sock);
static void tr_ssh_free(struct tr_socket *tr_sock);
static const char *tr_ssh_ident(void *tr_ssh_sock);

int tr_ssh_open(void *socket)
{
  struct tr_ssh_socket *ssh_socket = socket;
  struct rpki_cache *cache = ssh_socket->cache;
  struct rpki_proto *p = cache->p;

  const char *err_msg;
  if((err_msg = load_libssh()) != NULL)
  {
    RPKI_ERROR(p, "%s", err_msg);
    return TR_ERROR;
  }

  sock *s = cache->sk;
  s->type = SK_SSH_ACTIVE;
  s->ssh = mb_allocz(s->pool, sizeof(struct ssh_sock));
  s->ssh->username = cache->cfg->ssh->username;
  s->ssh->client_privkey_path = cache->cfg->ssh->bird_private_key;
  s->ssh->server_hostkey_path = cache->cfg->ssh->cache_public_key;
  s->ssh->subsystem = "rpki-rtr";
  s->ssh->state = BIRD_SSH_CONNECT;

  if (sk_open(s) != 0)
    return TR_ERROR;

  return TR_SUCCESS;
}

void tr_ssh_close(void *tr_ssh_sock)
{
  struct tr_ssh_socket *socket = tr_ssh_sock;
  struct rpki_cache *cache = socket->cache;
  struct rpki_proto *p = cache->p;

  sock *sk = cache->sk;
  if (sk && sk->ssh)
  {
    if (sk->ssh->channel)
    {
      if (ssh_channel_is_open(sk->ssh->channel))
	ssh_channel_close(sk->ssh->channel);
      ssh_channel_free(sk->ssh->channel);
      sk->ssh->channel = NULL;
    }

    if (sk->ssh->session)
    {
      ssh_disconnect(sk->ssh->session);
      ssh_free(sk->ssh->session);
      sk->ssh->session = NULL;
    }
  }
}

void tr_ssh_free(struct tr_socket *tr_sock)
{
  struct tr_ssh_socket *tr_ssh_sock = tr_sock->socket;
  struct rpki_cache *cache = tr_ssh_sock->cache;
  sock *s = cache->sk;

  if (tr_ssh_sock)
  {
    if (tr_ssh_sock->ident != NULL)
      mb_free(tr_ssh_sock->ident);
    mb_free(tr_ssh_sock);
    tr_sock->socket = NULL;
  }
}

const char *tr_ssh_ident(void *tr_ssh_sock)
{
  size_t len;
  struct tr_ssh_socket *ssh_sock = tr_ssh_sock;
  struct rpki_cache *cache = ssh_sock->cache;

  assert(ssh_sock != NULL);

  if (ssh_sock->ident != NULL)
    return ssh_sock->ident;

  const char *username = cache->cfg->ssh->username;
  const char *host = cache->cfg->hostname;

  len = strlen(username) + 1 + strlen(host) + 1 + 5 + 1; /* <user> + '@' + <host> + ':' + <port> + '\0' */
  ssh_sock->ident = mb_alloc(cache->p->p.pool, len);
  if (ssh_sock->ident == NULL)
    return NULL;
  snprintf(ssh_sock->ident, len, "%s@%s:%u", username, host, cache->cfg->port);
  return ssh_sock->ident;
}

int tr_ssh_init(struct rpki_cache *cache)
{
  struct rpki_proto *p = cache->p;
  struct rpki_cache_cfg *cache_cfg = cache->cfg;
  struct tr_socket *tr_socket = cache->rtr_socket->tr_socket;

  tr_socket->close_fp = &tr_ssh_close;
  tr_socket->free_fp = &tr_ssh_free;
  tr_socket->open_fp = &tr_ssh_open;
  tr_socket->ident_fp = &tr_ssh_ident;

  tr_socket->socket = mb_allocz(p->p.pool, sizeof(struct tr_ssh_socket));
  struct tr_ssh_socket *ssh = tr_socket->socket;

  ssh->cache = cache;

  return TR_SUCCESS;
}
