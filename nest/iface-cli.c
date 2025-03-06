/*
 *	BIRD -- Management of Interfaces and Neighbor Cache
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/cli.h"
#include "lib/resource.h"
#include "lib/string.h"
#include "lib/locking.h"

/*
 *  CLI commands.
 */

static void
if_show_addr(struct ifa *a)
{
  byte *flg, opp[IPA_MAX_TEXT_LENGTH + 16];

  flg = (a->flags & IA_PRIMARY) ? "Preferred, " : (a->flags & IA_SECONDARY) ? "Secondary, " : "";

  if (ipa_nonzero(a->opposite))
    bsprintf(opp, "opposite %I, ", a->opposite);
  else
    opp[0] = 0;

  cli_msg(-1003, "\t%I/%d (%s%sscope %s)",
	  a->ip, a->prefix.pxlen, flg, opp, ip_scope_text(a->scope));
}

void
if_show(void)
{
  struct ifa *a;
  char *type;

  IFACE_WALK(i)
    {
      if (i->flags & IF_SHUTDOWN)
	continue;

      char mbuf[16 + sizeof(i->name)] = {};
      if (i->master != &default_vrf)
	bsprintf(mbuf, " master=%s", i->master->name);
      else if (i->master_index)
	bsprintf(mbuf, " master=#%u", i->master_index);

      cli_msg(-1001, "%s %s (index=%d%s)", i->name, (i->flags & IF_UP) ? "up" : "down", i->index, mbuf);
      if (!(i->flags & IF_MULTIACCESS))
	type = "PtP";
      else
	type = "MultiAccess";
      cli_msg(-1004, "\t%s%s%s Admin%s Link%s%s%s MTU=%d",
	      type,
	      (i->flags & IF_BROADCAST) ? " Broadcast" : "",
	      (i->flags & IF_MULTICAST) ? " Multicast" : "",
	      (i->flags & IF_ADMIN_UP) ? "Up" : "Down",
	      (i->flags & IF_LINK_UP) ? "Up" : "Down",
	      (i->flags & IF_LOOPBACK) ? " Loopback" : "",
	      (i->flags & IF_IGNORE) ? " Ignored" : "",
	      i->mtu);

      WALK_LIST(a, i->addrs)
	if (a->prefix.type == NET_IP4)
	  if_show_addr(a);

      WALK_LIST(a, i->addrs)
	if (a->prefix.type == NET_IP6)
	  if_show_addr(a);
    }
  cli_msg(0, "");
}

void
if_show_summary(void)
{
  cli_msg(-2005, "%-10s %-6s %-18s %s", "Interface", "State", "IPv4 address", "IPv6 address");
  IFACE_WALK(i)
    {
      byte a4[IPA_MAX_TEXT_LENGTH + 17];
      byte a6[IPA_MAX_TEXT_LENGTH + 17];

      if (i->flags & IF_SHUTDOWN)
	continue;

      if (i->addr4)
	bsprintf(a4, "%I/%d", i->addr4->ip, i->addr4->prefix.pxlen);
      else
	a4[0] = 0;

      if (i->addr6)
	bsprintf(a6, "%I/%d", i->addr6->ip, i->addr6->prefix.pxlen);
      else
	a6[0] = 0;

      cli_msg(-1005, "%-10s %-6s %-18s %s",
	      i->name, (i->flags & IF_UP) ? "up" : "down", a4, a6);
    }
  cli_msg(0, "");
}
