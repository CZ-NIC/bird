/*
 *	BIRD -- IS-IS Interfaces and Neighbors
 *
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */


#include <stdlib.h>
#include "isis.h"

static char* ev_name[] = { NULL, "Init", "Change", "RS" };

#ifdef XXX
static void
isis_timer(timer *tm)
{
  struct isis_iface *ifa = tm->data;
  struct isis_proto *p = ifa->ra;

  ISIS_TRACE(D_EVENTS, "Timer fired on %s", ifa->iface->name);

  isis_send_ra(ifa, 0);

  /* Update timer */
  ifa->last = now;
  unsigned after = ifa->cf->min_ra_int;
  after += random() % (ifa->cf->max_ra_int - ifa->cf->min_ra_int + 1);

  if (ifa->initial)
    ifa->initial--;

  if (ifa->initial)
    after = MIN(after, MAX_INITIAL_RTR_ADVERT_INTERVAL);

  tm_start(ifa->timer, after);
}

void
isis_iface_notify(struct isis_iface *ifa, int event)
{
  struct isis_proto *p = ifa->p;

  if (!ifa->sk)
    return;

  ISIS_TRACE(D_EVENTS, "Event %s on %s", ev_name[event], ifa->iface->name);

  switch (event)
  {
  case RA_EV_CHANGE:
    ifa->plen = 0;
  case RA_EV_INIT:
    ifa->initial = MAX_INITIAL_RTR_ADVERTISEMENTS;
    break;

  case RA_EV_RS:
    break;
  }

  /* Update timer */
  unsigned delta = now - ifa->last;
  unsigned after = 0;

  if (delta < ifa->cf->min_delay)
    after = ifa->cf->min_delay - delta;

  tm_start(ifa->timer, after);
}
#endif

/*
isis_dr_election()
{
  
    at least one up, all relevant neighbors and myself

    local system becomes or resign -> event lANLevel1/2DesignatedIntermediateSystemChange 
    becomes ->
    set lan-id
    originate new and purge old pseudonode LSP

    zmena dr -> zmenit lan-id
    zmena lan-id -> zmena me LSP
}
   */

static struct isis_iface *
isis_iface_find(struct isis_proto *p, struct iface *what)
{
  struct isis_iface *ifa;

  WALK_LIST(ifa, p->iface_list)
    if (ifa->iface == what)
      return ifa;

  return NULL;
}

static void
iface_olock_hook(struct object_lock *lock)
{
  struct isis_iface *ifa = lock->data;
  struct isis_proto *p = ifa->p;

  if (! isis_sk_open(ifa))
  {
    log(L_ERR "%s: Socket open failed on interface %s", p->p.name, ifa->iface->name);
    return;
  }

  // XXX isis_iface_notify(ifa, RA_EV_INIT);
}


static void
l1_hello_timer_hook(timer *timer)
{
  struct isis_iface *ifa = (struct isis_iface *) timer->data;

  isis_send_lan_hello(ifa, ISIS_L1);
}

static void
l2_hello_timer_hook(timer *timer)
{
  struct isis_iface *ifa = (struct isis_iface *) timer->data;

  isis_send_lan_hello(ifa, ISIS_L2);
}

static void
ptp_hello_timer_hook(timer *timer)
{
  struct isis_iface *ifa = (struct isis_iface *) timer->data;

  isis_send_ptp_hello(ifa);
}

static void
csnp_timer_hook(timer *timer)
{
  struct isis_iface *ifa = (struct isis_iface *) timer->data;
  struct isis_proto *p = ifa->p;
  struct isis_lsp *lsp;
  int n;

  /* FIXME: CSNP rate limiting */

  if (XXX)
  {
    n = 0;
    lsp = isis_lsdb_first(p->lsdb[ISIS_L1], lsp, ifa);
    while (lsp)
      isis_send_csnp(ifa, ISIS_L1, &lsp, n++ == 0);
  }

  if (XXX)
  {
    n = 0;
    lsp = isis_lsdb_first(p->lsdb[ISIS_L2], lsp, ifa);
    while (lsp)
      isis_send_csnp(ifa, ISIS_L2, &lsp, n++ == 0);
  }
}

static void
psnp_timer_hook(timer *timer)
{
  struct isis_iface *ifa = (struct isis_iface *) timer->data;
  struct isis_proto *p = ifa->p;
  struct isis_lsp *lsp;

  if (XXX)
  {
    lsp = isis_lsdb_first_ssn(p->lsdb[ISIS_L1], lsp, ifa);
    while (lsp)
      isis_send_psnp(ifa, ISIS_L1, &lsp);
  }

  if (XXX)
  {
    lsp = isis_lsdb_first_ssn(p->lsdb[ISIS_L2], lsp, ifa);
    while (lsp)
      isis_send_psnp(ifa, ISIS_L2, &lsp);
  }
}


static void
isis_iface_new(struct isis_proto *p, struct iface *iface, struct isis_iface_config *cf)
{
  ISIS_TRACE(D_EVENTS, "Adding interface %s", iface->name);

  pool *pool = rp_new(p->p.pool, "ISIS Interface");
  struct isis_iface *ifa = mb_allocz(pool, sizeof(struct isis_iface));

  add_tail(&p->iface_list, NODE ifa);
  ifa->p = p;
  ifa->cf = cf;
  ifa->iface = iface;

  ifa->pool = pool;
  init_list(&ifa->neigh_list);

  ifa->type = ifa->cf->type;
  ifa->levels = ifa->cf->levels;
  ifa->priority = ifa->cf->priority;
  ifa->hello_int = ifa->cf->hello_int;
  ifa->hold_int = ifa->cf->hold_int;

  if (ifa->type == ISIS_IT_PASSIVE)
    return;

  ifa->hello_timer = tm_new_set(pool, hello_timer_hook, ifa, xxx, xxx);

  struct object_lock *lock = olock_new(pool);
  lock->addr = IPA_NONE;
  lock->type = OBJLOCK_IP;
  lock->port = ISIS_PROTO;
  lock->iface = iface;
  lock->data = ifa;
  lock->hook = iface_olock_hook;
  ifa->lock = lock;

  olock_acquire(lock);
}

/*
static inline void
isis_iface_shutdown(struct isis_iface *ifa)
{
  if (ifa->sk)
    isis_send_ra(ifa, 1);
}
*/

static void
isis_iface_remove(struct isis_iface *ifa)
{
  struct isis_proto *p = ifa->p;

  ISIS_TRACE(D_EVENTS, "Removing interface %s", ifa->iface->name);

  // XXX isis_iface_sm(ifa, ISM_DOWN);
  rem_node(NODE ifa);
  rfree(ifa->pool);
}

void
isis_if_notify(struct proto *pp, unsigned flags, struct iface *iface)
{ 
  struct isis_proto *p = (struct isis_proto *) pp;
  struct isis_config *cf = (struct isis_config *) (pp->cf);

  if (iface->flags & IF_IGNORE)
    return;

  if (flags & IF_CHANGE_UP)
  {
    struct isis_iface_config *ic = (struct isis_iface_config *)
      iface_patt_find(&cf->patt_list, iface, NULL);

    if (ic)
      isis_iface_new(p, iface, ic);

    return;
  }

  struct isis_iface *ifa = isis_iface_find(p, iface);
  if (!ifa)
    return;

  if (flags & IF_CHANGE_DOWN)
  {
    isis_iface_remove(ifa);
    return;
  }

  if ((flags & IF_CHANGE_LINK) && (iface->flags & IF_LINK_UP))
    isis_iface_notify(ifa, RA_EV_INIT);
}

/*
void
isis_ifa_notify(struct proto *pp, unsigned flags, struct ifa *a)
{
  struct isis_proto *p = (struct isis_proto *) pp;

  if (a->flags & IA_SECONDARY)
    return;

  if (a->scope <= SCOPE_LINK)
    return;

  struct isis_iface *ifa = isis_iface_find(ra, a->iface);

  if (ifa)
    isis_iface_notify(ifa, RA_EV_CHANGE);
}

*/




static void
hold_timer_hook(timer *timer)
{
  struct isis_neighbor *n = (struct isis_neighbor *) timer->data;
  struct isis_iface *ifa = n->ifa;
  struct isis_proto *p = ifa->p;

  // xxx ISIS_TRACE(D_EVENTS, "Hold timer expired for neighbor %I", n->ip);
  isis_neighbor_remove(n);
}


struct isis_neighbor *
isis_neighbor_add(struct isis_iface *ifa)
{
  struct isis_proto *p = ifa->p;
  struct isis_neighbor *n = mb_allocz(ifa->pool, sizeof(struct isis_neighbor));

  add_tail(&ifa->neigh_list, NODE n);
  n->ifa = ifa;

  n->hold_timer = tm_new_set(ifa->pool, hold_timer_hook, n, xxx, xxx);

  return (n);
}

void
isis_neighbor_remove(struct isis_neighbor *n)
{
  struct isis_iface *ifa = n->ifa;
  struct isis_proto *p = ifa->p;

  // xxx ISIS_TRACE(D_EVENTS, "Removing neigbor");

  rem_node(NODE n);
  rfree(n->hold_timer);
}

/*
  new:
  t neighbourSystemType - podle typu paketu
  holdingTimer, priorityOfNeighbour, neighbour-SystemID and areaAddressesOfNeighbour - podle obsahu
  mac_addr
  state -> init
  checknout my sysID in list -> up


 */
