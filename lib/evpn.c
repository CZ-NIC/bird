/*
 *	BIRD Internet Routing Daemon -- EVPN Net Type
 *
 *	(c) 2023 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2023 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/net.h"

uint
evpn_format(char *buf, uint blen, const net_addr_evpn *n)
{
  char rds[32];
  rd_format(n->rd, rds, 32);

  switch (n->subtype)
  {
  case NET_EVPN_EAD:
    return bsnprintf(buf, blen, "evpn ead %s %u %10b", rds, n->tag, &n->ead.esi);

  case NET_EVPN_MAC:
    if (n->length < sizeof(net_addr_evpn_mac_ip))
      return bsnprintf(buf, blen, "evpn mac %s %u %6b *", rds, n->tag, &n->mac.mac);
    else
      return bsnprintf(buf, blen, "evpn mac %s %u %6b %I", rds, n->tag, &n->mac_ip.mac, n->mac_ip.ip);

  case NET_EVPN_IMET:
    return bsnprintf(buf, blen, "evpn imet %s %u %I", rds, n->tag, n->imet.rtr);

  case NET_EVPN_ES:
    return bsnprintf(buf, blen, "evpn es %s %10b %I", rds, &n->es.esi, n->es.rtr);
  }

  bug("unknown EVPN type %d", n->subtype);
}
