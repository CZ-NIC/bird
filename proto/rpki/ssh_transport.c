/*
 *	BIRD -- An implementation of the SSH protocol for the RPKI transport
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file was a part of RTRlib: http://rpki.realmv6.org/
 *	This transport implementation uses libssh (http://www.libssh.org/)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "rpki.h"
#include "ssh_transport.h"
#include "lib/libssh.h"

static int
rpki_tr_ssh_open(struct rpki_tr_sock *tr)
{
  struct rpki_cache *cache = tr->cache;
  struct rpki_config *cf = (void *) cache->p->p.cf;
  sock *sk = tr->sk;

  const char *err_msg;
  if ((err_msg = load_libssh()) != NULL)
  {
    CACHE_TRACE(D_EVENTS, cache, "%s", err_msg);
    return TR_ERROR;
  }

  sk->type = SK_SSH_ACTIVE;
  sk->ssh = mb_allocz(sk->pool, sizeof(struct ssh_sock));
  sk->ssh->username = cf->ssh->user;
  sk->ssh->client_privkey_path = cf->ssh->bird_private_key;
  sk->ssh->server_hostkey_path = cf->ssh->cache_public_key;
  sk->ssh->subsystem = "rpki-rtr";
  sk->ssh->state = SK_SSH_CONNECT;

  if (sk_open(sk) != 0)
    return TR_ERROR;

  return TR_SUCCESS;
}

static void
rpki_tr_ssh_close(struct rpki_tr_sock *tr)
{
  struct rpki_tr_ssh *ssh = tr->data;

  if (ssh && ssh->ident != NULL)
  {
    mb_free((char *) ssh->ident);
    ssh->ident = NULL;
  }

  /* tr->sk is closed in tr_close() */
}

static const char *
rpki_tr_ssh_ident(struct rpki_tr_sock *tr)
{
  ASSERT(tr != NULL);

  struct rpki_cache *cache = tr->cache;
  struct rpki_config *cf = (void *) cache->p->p.cf;
  struct rpki_tr_ssh *ssh = tr->data;

  if (ssh->ident != NULL)
    return ssh->ident;

  const char *username = cf->ssh->user;
  const char *host = cf->hostname;
  u16 port = cf->port;

  size_t len = strlen(username) + 1 + strlen(host) + 1 + 5 + 1; /* <user> + '@' + <host> + ':' + <port> + '\0' */
  char *ident = mb_alloc(cache->pool, len);
  bsnprintf(ident, len, "%s@%s:%u", username, host, port);
  ssh->ident = ident;

  return ssh->ident;
}

/*
 * Initializes the rpki_tr_sock struct for a SSH connection.
 */
void
rpki_tr_ssh_init(struct rpki_tr_sock *tr)
{
  struct rpki_cache *cache = tr->cache;

  tr->close_fp = &rpki_tr_ssh_close;
  tr->open_fp = &rpki_tr_ssh_open;
  tr->ident_fp = &rpki_tr_ssh_ident;

  tr->data = mb_allocz(cache->pool, sizeof(struct rpki_tr_ssh));
}
