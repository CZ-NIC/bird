/*
 *	BIRD -- IS-IS
 *
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */


#include <stdlib.h>
#include "isis.h"

/**
 * DOC: Intermediate System to Intermediate System (IS-IS)
 *
 * Intermediate System to Intermediate System 
 * intra-domain routeing information exchange protocol
 *
 * XXXX
 *
 * Supported standards:
 * - ISO 10589 - main IS-IS standard
 * - RFC xxxx - 
 */


static struct proto *
isis_init(struct proto_config *c)
{
  struct proto *pp = proto_new(c, sizeof(struct isis_proto));

  pp->if_notify = isis_if_notify;
  pp->ifa_notify = isis_ifa_notify;
  return pp;
}

static int
isis_start(struct proto *pp)
{
  struct isis_proto *p = (struct isis_proto *) pp;
  // struct isis_config *cf = (struct isis_config *) (pp->cf);

  init_list(&(p->iface_list));

  return PS_UP;
}

static int
isis_shutdown(struct proto *pp)
{
  struct isis_proto *p = (struct isis_proto *) pp;

  struct isis_iface *ifa;
  WALK_LIST(ifa, p->iface_list)
    isis_iface_shutdown(ifa);

  return PS_DOWN;
}

#ifdef XXX
static int
isis_reconfigure(struct proto *pp, struct proto_config *c)
{
  struct isis_proto *p = (struct isis_proto *) pp;
  // struct isis_config *old = (struct isis_config *) (p->cf);
  struct isis_config *new = (struct isis_config *) c;

  /* 
   * The question is why there is a reconfigure function for RAdv if
   * it has almost none internal state so restarting the protocol
   * would probably suffice. One small reason is that restarting the
   * protocol would lead to sending a RA with Router Lifetime 0
   * causing nodes to temporary remove their default routes.
   */

  struct iface *iface;
  WALK_LIST(iface, iface_list)
  {
    struct isis_iface *ifa = isis_iface_find(ra, iface);
    struct isis_iface_config *ic = (struct isis_iface_config *)
      iface_patt_find(&new->patt_list, iface, NULL);

    if (ifa && ic)
    {
      ifa->cf = ic;

      /* We cheat here - always notify the change even if there isn't
	 any. That would leads just to a few unnecessary RAs. */
      isis_iface_notify(ifa, RA_EV_CHANGE);
    }

    if (ifa && !ic)
    {
      isis_iface_shutdown(ifa);
      isis_iface_remove(ifa);
    }

    if (!ifa && ic)
      isis_iface_new(ra, iface, ic);
  }

  return 1;
}

static void
isis_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct isis_config *d = (struct isis_config *) dest;
  struct isis_config *s = (struct isis_config *) src;

  /* We clean up patt_list, ifaces are non-sharable */
  init_list(&d->patt_list);
}
#endif


struct protocol isis_proto = {
  .name =		"IS-IS",
  .template =		"isis%d",
  .init =		isis_init,
  .start =		isis_start,
  .shutdown =		isis_shutdown,
  // .reconfigure =	isis_reconfigure,
  // .copy_config =	isis_copy_config
};
