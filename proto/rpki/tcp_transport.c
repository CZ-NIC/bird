/*
 *	BIRD -- An implementation of the TCP protocol for the RPKI protocol transport
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file was a part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

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
#include "sysdep/unix/unix.h"

static int
rpki_tr_tcp_open(struct rpki_tr_sock *tr)
{
  sock *sk = tr->sk;

  sk->type = SK_TCP_ACTIVE;

  if (sk_open(sk) != 0)
    return TR_ERROR;

  return TR_SUCCESS;
}

static void
rpki_tr_tcp_close(struct rpki_tr_sock *tr)
{
  struct rpki_tr_tcp *tcp = tr->data;

  if (tcp && tcp->ident != NULL)
  {
    mb_free((char *) tcp->ident);
    tcp->ident = NULL;
  }

  /* tr->sk is closed in tr_close() */
}

static const char *
rpki_tr_tcp_ident(struct rpki_tr_sock *tr)
{
  ASSERT(tr != NULL);

  struct rpki_cache *cache = tr->cache;
  struct rpki_config *cf = (void *) cache->p->p.cf;
  struct rpki_tr_tcp *tcp = tr->data;

  if (tcp->ident != NULL)
    return tcp->ident;

  const char *host = cf->hostname;
  ip_addr ip = cf->ip;
  u16 port = cf->port;

  size_t colon_and_port_len = 6; /* max ":65535" */
  size_t ident_len;
  if (host)
    ident_len = strlen(host) + colon_and_port_len + 1;
  else
    ident_len = IPA_MAX_TEXT_LENGTH + colon_and_port_len + 1;

  char *ident = mb_alloc(cache->pool, ident_len);
  if (host)
    bsnprintf(ident, ident_len, "%s:%u", host, port);
  else
    bsnprintf(ident, ident_len, "%I:%u", ip, port);

  tcp->ident = ident;
  return tcp->ident;
}

/* Initializes the rpki_tr_sock struct for a TCP connection. */
void
rpki_tr_tcp_init(struct rpki_tr_sock *tr)
{
  struct rpki_cache *cache = tr->cache;

  tr->close_fp = &rpki_tr_tcp_close;
  tr->open_fp = &rpki_tr_tcp_open;
  tr->ident_fp = &rpki_tr_tcp_ident;

  tr->data = mb_allocz(cache->pool, sizeof(struct rpki_tr_tcp));
}
