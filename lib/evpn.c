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
#include "lib/route.h"

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

  default:
    return bsnprintf(buf, blen, "evpn type %d %s %*b", n->subtype, rds, net_evpn_data_length(n), n->data);
  }

  bug("unknown EVPN type %d", n->subtype);
}

/* EVPN ESI eattr */

static void
ea_gen_evpn_esi_format(const eattr *a, byte *buf, uint size UNUSED)
{
  if (a->u.ad->length == 10)
    bsprintf(buf, "%10b", a->u.ptr->data);
  else
    bsprintf(buf, "<invalid>");
}

struct ea_class ea_gen_evpn_esi = {
  .name = "evpn_esi",
  .legacy_name = "evpn_esi",
  .type = T_BYTESTRING,
  .format = ea_gen_evpn_esi_format,
};

