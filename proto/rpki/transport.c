/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *	(c) 2015 Pavel Tvrdik <pawel.tvrdik@gmail.com>
 *
 *	This file was a part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <sys/socket.h>
#include <netdb.h>

#include "rpki.h"
#include "transport.h"
#include "sysdep/unix/unix.h"

/**
 * rpki_hostname_autoresolv - auto-resolve an IP address from a hostname
 * @host: domain name of host, e.g. "rpki-validator.realmv6.org"
 * @err_msg: error message returned in case of errors
 *
 * This function resolves an IP address from a hostname.
 * Returns &ip_addr structure with IP address or |IPA_NONE|.
 */
static ip_addr
rpki_hostname_autoresolv(const char *host, const char **err_msg)
{
  struct addrinfo *res;
  struct addrinfo hints = {
      .ai_family = AF_UNSPEC,
      .ai_socktype = SOCK_STREAM,
      .ai_flags = AI_ADDRCONFIG,
  };

  *err_msg = NULL;

  if (!host)
    return IPA_NONE;

  int err_code = getaddrinfo(host, NULL, &hints, &res);
  if (err_code != 0)
  {
    *err_msg = gai_strerror(err_code);
    return IPA_NONE;
  }

  ip_addr addr = IPA_NONE;
  uint unused;

  sockaddr_read((sockaddr *) res->ai_addr, res->ai_family, &addr, NULL, &unused);

  freeaddrinfo(res);
  return addr;
}

/**
 * rpki_tr_open - prepare and open a socket connection
 * @tr: initialized transport socket
 *
 * Prepare and open a socket connection specified by @tr that must be initialized before.
 * This function ends with a calling the sk_open() function.
 * Returns RPKI_TR_SUCCESS or RPKI_TR_ERROR.
 */
int
rpki_tr_open(struct rpki_tr_sock *tr)
{
  struct rpki_cache *cache = tr->cache;
  struct rpki_config *cf = (void *) cache->p->p.cf;

  ASSERT(tr->sk == NULL);
  tr->sk = sk_new(cache->pool);
  sock *sk = tr->sk;

  /* sk->type -1 is invalid value, a correct value MUST be set in the specific transport layer in open_fp() hook */
  sk->type = -1;

  sk->tx_hook = rpki_connected_hook;
  sk->err_hook = rpki_err_hook;
  sk->data = cache;
  sk->daddr = cf->ip;
  sk->dport = cf->port;
  sk->host = cf->hostname;
  sk->rbsize = RPKI_RX_BUFFER_SIZE;
  sk->tbsize = RPKI_TX_BUFFER_SIZE;
  sk->tos = IP_PREC_INTERNET_CONTROL;
  sk->vrf = cache->p->p.vrf;

  if (ipa_zero(sk->daddr) && sk->host)
  {
    const char *err_msg;

    sk->daddr = rpki_hostname_autoresolv(sk->host, &err_msg);
    if (ipa_zero(sk->daddr))
    {
      log(L_ERR "%s: Cannot resolve hostname '%s': %s",
	  cache->p->p.name, sk->host, err_msg);
      return RPKI_TR_ERROR;
    }
  }

  return tr->open_fp(tr);
}

/**
 * rpki_tr_close - close socket and prepare it for possible next open
 * @tr: successfully opened transport socket
 *
 * Close socket and free resources.
 */
void
rpki_tr_close(struct rpki_tr_sock *tr)
{
  if (tr->ident)
  {
    mb_free((char *) tr->ident);
    tr->ident = NULL;
  }

  if (tr->sk)
  {
    rfree(tr->sk);
    tr->sk = NULL;
  }
}

/**
 * rpki_tr_ident - Returns a string identifier for the rpki transport socket
 * @tr: successfully opened transport socket
 *
 * Returns a \0 terminated string identifier for the socket endpoint, e.g. "<host>:<port>".
 * Memory is allocated inside @tr structure.
 */
inline const char *
rpki_tr_ident(struct rpki_tr_sock *tr)
{
  return tr->ident_fp(tr);
}
