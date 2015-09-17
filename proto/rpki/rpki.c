/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: The Resource Public Key Infrastructure (RPKI) to Router Protocol
 */

#define LOCAL_DEBUG

#include "proto/rpki/rpki.h"

static struct proto *
rpki_init(struct proto_config *c)
{
  struct proto *p = proto_new(c, sizeof(struct rpki_proto));

  log(L_DEBUG "------------- rpki_init -------------");

  /* TODO: Add defaults */
  return p;
}

static int
rpki_start(struct proto *p)
{
  struct proto_rpki *rpki = (struct proto_rpki *) p;
  struct rpki_config *cf = (struct rpki_config *) (p->cf);

  log(L_DEBUG "------------- rpki_start -------------");

  return PS_UP;
}

static int
rpki_shutdown(struct proto *p)
{
  struct proto_rpki *rp = (struct proto_rpki *) p;

  log(L_DEBUG "------------- rpki_shutdown -------------");

  return PS_DOWN;
}

static int
rpki_reconfigure(struct proto *p, struct proto_config *c)
{
  struct proto_rpki *rpki = (struct proto_rpki *) p;
  struct rpki_config *new = (struct rpki_config *) c;

  log(L_DEBUG "------------- rpki_reconfigure -------------");

  return 1;
}

static void
rpki_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct rpki_config *d = (struct rpki_config *) dest;
  struct rpki_config *s = (struct rpki_config *) src;

  log(L_DEBUG "------------- rpki_copy_config -------------");
}

static void
rpki_get_status(struct proto *p, byte *buf)
{
  struct proto_rpki *rpki = (struct proto_rpki *) p;

  log(L_DEBUG "------------- rpki_get_status -------------");
}

struct protocol proto_rpki = {
  .name = 		"RPKI",
  .template = 		"rpki%d",
//  .attr_class = 	EAP_BGP,
//  .preference = 	DEF_PREF_BGP,
  .config_size =	sizeof(struct rpki_config),
  .init = 		rpki_init,
  .start = 		rpki_start,
  .shutdown = 		rpki_shutdown,
//  .cleanup = 		rpki_cleanup,
  .reconfigure = 	rpki_reconfigure,
  .copy_config = 	rpki_copy_config,
  .get_status = 	rpki_get_status,
//  .get_attr = 		rpki_get_attr,
//  .get_route_info = 	rpki_get_route_info,
//  .show_proto_info = 	rpki_show_proto_info
};
