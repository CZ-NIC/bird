/*
 *	BIRD -- An implementation of the SSH protocol for the RPKI transport
 *
 *	(c) 2015 CZ.NIC
 *	(c) 2015 Pavel Tvrdik <pawel.tvrdik@gmail.com>
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

#if HAVE_LIBSSH

static int
rpki_tr_ssh_open(struct rpki_tr_sock *tr)
{
  struct rpki_cache *cache = tr->cache;
  struct rpki_config *cf = (void *) cache->p->p.cf;
  struct rpki_tr_ssh_config *ssh_cf = (void *) cf->tr_config.spec;
  sock *sk = tr->sk;

  sk->type = SK_SSH_ACTIVE;
  sk->ssh = mb_allocz(sk->pool, sizeof(struct ssh_sock));
  sk->ssh->username = ssh_cf->user;
  sk->ssh->client_privkey_path = ssh_cf->bird_private_key;
  sk->ssh->server_hostkey_path = ssh_cf->cache_public_key;
  sk->ssh->subsystem = "rpki-rtr";
  sk->ssh->state = SK_SSH_CONNECT;

  if (sk_open(sk) != 0)
    return RPKI_TR_ERROR;

  return RPKI_TR_SUCCESS;
}

static const char *
rpki_tr_ssh_ident(struct rpki_tr_sock *tr)
{
  struct rpki_cache *cache = tr->cache;
  struct rpki_config *cf = (void *) cache->p->p.cf;
  struct rpki_tr_ssh_config *ssh_cf = (void *) cf->tr_config.spec;
  const char *username = ssh_cf->user;

  if (tr->ident != NULL)
    return tr->ident;

  /* Length: <user> + '@' + <host> + ' port ' + <port> + '\0' */
  size_t len = strlen(username) + 1 + strlen(cf->hostname) + 1 + 5 + 1;
  char *ident = mb_alloc(cache->pool, len);
  bsnprintf(ident, len, "%s@%s:%u", username, cf->hostname, cf->port);
  tr->ident = ident;

  return tr->ident;
}

/**
 * rpki_tr_ssh_init - initializes the RPKI transport structure for a SSH connection
 * @tr: allocated RPKI transport structure
 */
void
rpki_tr_ssh_init(struct rpki_tr_sock *tr)
{
  tr->open_fp = &rpki_tr_ssh_open;
  tr->ident_fp = &rpki_tr_ssh_ident;
}

#endif
