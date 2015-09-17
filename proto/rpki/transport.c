/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
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

/*
 * Fulfill sock->af and sock->daddr if sock->daddr is empty and hostname is defined
 * Return TR_SUCCESS or TR_ERROR
 */
static int
rpki_hostname_autoresolv(sock *sk)
{
  if (ipa_zero(sk->daddr) && sk->host)
  {
    struct addrinfo *res;
    struct addrinfo hints = {
	.ai_family = AF_UNSPEC,
	.ai_socktype = SOCK_STREAM,
	.ai_flags = AI_ADDRCONFIG,
    };

    char port[6]; /* max is "65535" + '\0' */
    bsnprintf(port, sizeof(port), "%u", sk->dport);

    if (getaddrinfo(sk->host, port, &hints, &res) != 0)
    {
      CACHE_TRACE(D_EVENTS, (struct rpki_cache *) sk->data, "getaddrinfo error, %s", gai_strerror(errno));
      return TR_ERROR;
    }

    if (res->ai_family == AF_INET)
      sk->fam = SK_FAM_IPV4;
    else
      sk->fam = SK_FAM_IPV6;

    sockaddr sa = {
	.sa = *res->ai_addr,
    };

    uint unused;
    sockaddr_read(&sa, res->ai_family, &sk->daddr, NULL, &unused);

    freeaddrinfo(res);
  }
  else if (ipa_zero(sk->daddr) && !sk->host)
    return TR_ERROR;
  else
    sk->fam = ip6_is_v4mapped(sk->daddr) ? SK_FAM_IPV4 : SK_FAM_IPV6;

  return TR_SUCCESS;
}

/*
 * Establish the connection.
 * Returns TR_SUCCESS or TR_ERROR
 */
int
rpki_tr_open(struct rpki_tr_sock *tr)
{
  struct rpki_cache *cache = tr->cache;
  struct rpki_config *cf = (void *) cache->p->p.cf;

  ASSERT(tr->sk == NULL);
  tr->sk = sk_new(cache->pool);
  sock *sk = tr->sk;

  sk->tx_hook = rpki_connected_hook;
  sk->err_hook = rpki_err_hook;
  sk->data = cache;
  sk->daddr = cf->ip;
  sk->dport = cf->port;
  sk->host = cf->hostname;
  sk->rbsize = RPKI_RX_BUFFER_SIZE;
  sk->tbsize = RPKI_TX_BUFFER_SIZE;
  sk->tos = IP_PREC_INTERNET_CONTROL;
  sk->type = -1; /* must be set in the specific transport layer in tr_open() */
  rpki_hostname_autoresolv(sk);

  return tr->open_fp(tr);
}

/* Close socket and prepare it for possible next open */
inline void
rpki_tr_close(struct rpki_tr_sock *tr)
{
  tr->close_fp(tr);

  rfree(tr->sk);
  tr->sk = NULL;
}

/* Returns a \0 terminated string identifier for the socket endpoint, eg host:port */
inline const char *
rpki_tr_ident(struct rpki_tr_sock *tr)
{
  return tr->ident_fp(tr);
}
