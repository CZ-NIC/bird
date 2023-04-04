/*
 *	BIRD -- Management of Interfaces and Neighbor Cache
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Interfaces
 *
 * The interface module keeps track of all network interfaces in the
 * system and their addresses.
 *
 * Each interface is represented by an &iface structure which carries
 * interface capability flags (%IF_MULTIACCESS, %IF_BROADCAST etc.),
 * MTU, interface name and index and finally a linked list of network
 * prefixes assigned to the interface, each one represented by
 * struct &ifa.
 *
 * The interface module keeps a `soft-up' state for each &iface which
 * is a conjunction of link being up, the interface being of a `sane'
 * type and at least one IP address assigned to it.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/cli.h"
#include "lib/resource.h"
#include "lib/string.h"
#include "lib/locking.h"
#include "conf/conf.h"
#include "sysdep/unix/krt.h"

DOMAIN(attrs) iface_domain;

#define IFACE_LOCK	LOCK_DOMAIN(attrs, iface_domain)
#define IFACE_UNLOCK	UNLOCK_DOMAIN(attrs, iface_domain)
#define IFACE_ASSERT_LOCKED	ASSERT_DIE(DOMAIN_IS_LOCKED(attrs, iface_domain))

static TLIST_LIST(ifsub) iface_sub_list;
static slab *iface_sub_slab;
static pool *if_pool;

list global_iface_list;
struct iface default_vrf;

static void if_recalc_preferred(struct iface *i);

static void ifa_dump_locked(struct ifa *);
static void if_dump_locked(struct iface *);

struct iface *
if_walk_first(void)
{
  IFACE_LOCK;
  struct iface *i = HEAD(global_iface_list);
  return NODE_VALID(i) ? i : NULL;
}

struct iface *
if_walk_next(struct iface *i)
{
  IFACE_ASSERT_LOCKED;
  i = NODE_NEXT(i);
  return NODE_VALID(i) ? i : NULL;
}

void
if_walk_done(void)
{
  IFACE_ASSERT_LOCKED;
  IFACE_UNLOCK;
}

/**
 * ifa_dump - dump interface address
 * @a: interface address descriptor
 *
 * This function dumps contents of an &ifa to the debug output.
 */
void
ifa_dump(struct ifa *a)
{
  IFACE_LOCK;
  ifa_dump_locked(a);
  IFACE_UNLOCK;
}

static void
ifa_dump_locked(struct ifa *a)
{
  debug("\t%I, net %N bc %I -> %I%s%s%s%s\n", a->ip, &a->prefix, a->brd, a->opposite,
	(a->flags & IA_PRIMARY) ? " PRIMARY" : "",
	(a->flags & IA_SECONDARY) ? " SEC" : "",
	(a->flags & IA_HOST) ? " HOST" : "",
	(a->flags & IA_PEER) ? " PEER" : "");
}

/**
 * if_dump - dump interface
 * @i: interface to dump
 *
 * This function dumps all information associated with a given
 * network interface to the debug output.
 */
void
if_dump(struct iface *i)
{
  IFACE_LOCK;
  if_dump_locked(i);
  IFACE_UNLOCK;
}

static void
if_dump_locked(struct iface *i)
{
  struct ifa *a;

  debug("IF%d: %s", i->index, i->name);
  if (i->flags & IF_SHUTDOWN)
    debug(" SHUTDOWN");
  if (i->flags & IF_UP)
    debug(" UP");
  else
    debug(" DOWN");
  if (i->flags & IF_ADMIN_UP)
    debug(" LINK-UP");
  if (i->flags & IF_MULTIACCESS)
    debug(" MA");
  if (i->flags & IF_BROADCAST)
    debug(" BC");
  if (i->flags & IF_MULTICAST)
    debug(" MC");
  if (i->flags & IF_LOOPBACK)
    debug(" LOOP");
  if (i->flags & IF_IGNORE)
    debug(" IGN");
  if (i->flags & IF_TMP_DOWN)
    debug(" TDOWN");
  debug(" MTU=%d\n", i->mtu);
  WALK_LIST(a, i->addrs)
    {
      ifa_dump_locked(a);
      ASSERT(!!(a->flags & IA_PRIMARY) ==
	     ((a == i->addr4) || (a == i->addr6) || (a == i->llv6)));
    }
}

/**
 * if_dump_all - dump all interfaces
 *
 * This function dumps information about all known network
 * interfaces to the debug output.
 */
void
if_dump_all(void)
{
  debug("Known network interfaces:\n");
  IFACE_WALK(i)
    if_dump(i);
  debug("Router ID: %08x\n", config->router_id);
}

void
if_link(struct iface *i)
{
  IFACE_ASSERT_LOCKED;

  if (i)
    i->uc++;
}

void
if_unlink(struct iface *i)
{
  IFACE_ASSERT_LOCKED;

  if (i)
    i->uc--;
  /* TODO: Do some interface object cleanup */
}

void ifa_link(struct ifa *a)
{
  IFACE_ASSERT_LOCKED;

  if (a)
  {
    debug("ifa_link: %p %d\n", a, a->uc);
    a->uc++;
  }
}

void ifa_unlink(struct ifa *a)
{
  IFACE_ASSERT_LOCKED;

  if (!a)
    return;

  debug("ifa_unlink: %p %d\n", a, a->uc);
  if (--a->uc)
    return;

  if_unlink(a->iface);
#if DEBUGGING
  memset(a, 0x5b, sizeof(struct ifa));
#endif
  mb_free(a);
}

static inline unsigned
if_what_changed(struct iface *i, struct iface *j)
{
  unsigned c;

  if (((i->flags ^ j->flags) & ~(IF_UP | IF_SHUTDOWN | IF_UPDATED | IF_ADMIN_UP | IF_LINK_UP | IF_TMP_DOWN | IF_JUST_CREATED))
      || (i->index != j->index) || (i->master != j->master))
    return IF_CHANGE_TOO_MUCH;
  c = 0;
  if ((i->flags ^ j->flags) & IF_UP)
    c |= (i->flags & IF_UP) ? IF_CHANGE_DOWN : IF_CHANGE_UP;
  if ((i->flags ^ j->flags) & IF_LINK_UP)
    c |= IF_CHANGE_LINK;
  if (i->mtu != j->mtu)
    c |= IF_CHANGE_MTU;
  return c;
}

static inline void
if_copy(struct iface *to, struct iface *from)
{
  to->flags = from->flags | (to->flags & IF_TMP_DOWN);
  to->mtu = from->mtu;
  to->master_index = from->master_index;

  if_unlink(to->master);
  if_link(to->master = from->master);
}

void
if_enqueue_notify_to(struct iface_notification x, struct iface_subscription *s)
{
  IFACE_ASSERT_LOCKED;

  switch (x.type) {
    case IFNOT_ADDRESS:
      if (!s->ifa_notify) return;
      ifa_link(x.a);
      break;
    case IFNOT_INTERFACE:
      if (!s->if_notify) return;
      if_link(x.i);
      break;
    case IFNOT_NEIGHBOR:
      if (!s->neigh_notify) return;
      neigh_link(x.n);
      break;
    default:
      bug("Unknown interface notification type: %d", x.type);
  }

  struct iface_notification *in = sl_alloc(iface_sub_slab);
  *in = x;

  debug("Enqueue notify %d/%p (%p) to %p\n", x.type, x.a, in, s);

  ifnot_add_tail(&s->queue, in);
  ev_send(s->target, &s->event);
}

void
if_enqueue_notify(struct iface_notification x)
{
  IFACE_ASSERT_LOCKED;

  WALK_TLIST(ifsub, s, &iface_sub_list)
    if_enqueue_notify_to(x, s);
}

static inline void
ifa_send_notify(struct iface_subscription *s, unsigned c, struct ifa *a)
{
  struct proto *p = SKIP_BACK(struct proto, iface_sub, s);

  if (s->ifa_notify &&
      (p->proto_state != PS_DOWN) &&
      (!p->vrf || p->vrf == a->iface->master))
    {
      if (p->debug & D_IFACES)
	log(L_TRACE "%s < address %N on interface %s %s",
	    p->name, &a->prefix, a->iface->name,
	    (c & IF_CHANGE_UP) ? "added" : "removed");
      s->ifa_notify(p, c, a);
    }
}

static void
ifa_notify_change_(unsigned c, struct ifa *a)
{
  DBG("IFA change notification (%x) for %s:%I\n", c, a->iface->name, a->ip);

  if_enqueue_notify((struct iface_notification) {
	.type = IFNOT_ADDRESS,
	.a = a,
	.flags = c,
      });

}

static inline void
ifa_notify_change(unsigned c, struct ifa *a)
{
  if (c & IF_CHANGE_DOWN)
    neigh_ifa_down(a);

  ifa_notify_change_(c, a);

  if (c & IF_CHANGE_UP)
    neigh_ifa_up(a);
}

static inline void
if_send_notify(struct iface_subscription *s, unsigned c, struct iface *i)
{
  struct proto *p = SKIP_BACK(struct proto, iface_sub, s);

  if (s->if_notify &&
      (p->proto_state != PS_DOWN) &&
      (!p->vrf || p->vrf == i->master))
    {
      if (p->debug & D_IFACES)
	log(L_TRACE "%s < interface %s %s", p->name, i->name,
	    (c & IF_CHANGE_UP) ? "goes up" :
	    (c & IF_CHANGE_DOWN) ? "goes down" :
	    (c & IF_CHANGE_MTU) ? "changes MTU" :
	    (c & IF_CHANGE_LINK) ? "changes link" :
	    (c & IF_CHANGE_PREFERRED) ? "changes preferred address" :
	    (c & IF_CHANGE_CREATE) ? "created" :
	    "sends unknown event");
      s->if_notify(p, c, i);
    }
}

static void
if_notify_change(unsigned c, struct iface *i)
{
  struct ifa *a;

  if (i->flags & IF_JUST_CREATED)
    {
      i->flags &= ~IF_JUST_CREATED;
      c |= IF_CHANGE_CREATE | IF_CHANGE_MTU;
    }

  DBG("Interface change notification (%x) for %s\n", c, i->name);
#ifdef LOCAL_DEBUG
  if_dump_locked(i);
#endif

  if (c & IF_CHANGE_DOWN)
    neigh_if_down(i);

  if (c & IF_CHANGE_DOWN)
    WALK_LIST(a, i->addrs)
      ifa_notify_change_(IF_CHANGE_DOWN, a);

  if_enqueue_notify((struct iface_notification) {
	.type = IFNOT_INTERFACE,
	.i = i,
	.flags = c,
      });

  if (c & IF_CHANGE_UP)
    WALK_LIST(a, i->addrs)
      ifa_notify_change_(IF_CHANGE_UP, a);

  if (c & IF_CHANGE_UP)
    neigh_if_up(i);

  if ((c & (IF_CHANGE_UP | IF_CHANGE_DOWN | IF_CHANGE_LINK)) == IF_CHANGE_LINK)
    neigh_if_link(i);
}

static uint
if_recalc_flags(struct iface *i UNUSED, uint flags)
{
  if ((flags & IF_ADMIN_UP) &&
      !(flags & (IF_SHUTDOWN | IF_TMP_DOWN)) &&
      !(i->master_index && i->master == &default_vrf))
    flags |= IF_UP;
  else
    flags &= ~IF_UP;

  return flags;
}

static void
if_change_flags(struct iface *i, uint flags)
{
  uint of = i->flags;
  i->flags = if_recalc_flags(i, flags);

  if ((i->flags ^ of) & IF_UP)
    if_notify_change((i->flags & IF_UP) ? IF_CHANGE_UP : IF_CHANGE_DOWN, i);
}

/**
 * if_delete - remove interface
 * @old: interface
 *
 * This function is called by the low-level platform dependent code
 * whenever it notices an interface disappears. It is just a shorthand
 * for if_update().
 */

void
if_delete(struct iface *old)
{
  IFACE_LOCK;
  struct iface f = {};
  strncpy(f.name, old->name, sizeof(f.name)-1);
  f.flags = IF_SHUTDOWN;
  if_update_locked(&f);
  IFACE_UNLOCK;
}

/**
 * if_update - update interface status
 * @new: new interface status
 *
 * if_update() is called by the low-level platform dependent code
 * whenever it notices an interface change.
 *
 * There exist two types of interface updates -- synchronous and asynchronous
 * ones. In the synchronous case, the low-level code calls if_start_update(),
 * scans all interfaces reported by the OS, uses if_update() and ifa_update()
 * to pass them to the core and then it finishes the update sequence by
 * calling if_end_update(). When working asynchronously, the sysdep code
 * calls if_update() and ifa_update() whenever it notices a change.
 *
 * if_update() will automatically notify all other modules about the change.
 */
struct iface *
if_update(struct iface *new)
{
  IFACE_LOCK;
  struct iface *i = if_update_locked(new);
  IFACE_UNLOCK;
  return i;
}

struct iface *
if_update_locked(struct iface *new)
{
  struct iface *i;
  unsigned c;

  if (!new->master)
    new->master = &default_vrf;

  WALK_LIST(i, global_iface_list)
    if (!strcmp(new->name, i->name))
      {
	new->flags = if_recalc_flags(new, new->flags);
	c = if_what_changed(i, new);
	if (c & IF_CHANGE_TOO_MUCH)	/* Changed a lot, convert it to down/up */
	  {
	    DBG("Interface %s changed too much -- forcing down/up transition\n", i->name);
	    if_change_flags(i, i->flags | IF_TMP_DOWN);
	    rem_node(&i->n);
	    new->addr4 = i->addr4;
	    new->addr6 = i->addr6;
	    new->llv6 = i->llv6;
	    new->sysdep = i->sysdep;
	    memcpy(&new->addrs, &i->addrs, sizeof(i->addrs));
	    memcpy(&new->neighbors, &i->neighbors, sizeof(i->neighbors));
	    memcpy(i, new, sizeof(*i));
	    i->flags &= ~IF_UP;		/* IF_TMP_DOWN will be added later */
	    goto newif;
	  }

	if_copy(i, new);
	if (c)
	  if_notify_change(c, i);

	i->flags |= IF_UPDATED;
	return i;
      }
  i = mb_alloc(if_pool, sizeof(struct iface));
  memcpy(i, new, sizeof(*i));
  if_link(i->master);
  init_list(&i->addrs);
  init_list(&i->neighbors);
newif:
  i->flags |= IF_UPDATED | IF_TMP_DOWN;		/* Tmp down as we don't have addresses yet */
  add_tail(&global_iface_list, &i->n);
  return i;
}

void
if_start_update(void)
{
  struct ifa *a;

  IFACE_WALK(i)
    {
      i->flags &= ~IF_UPDATED;
      WALK_LIST(a, i->addrs)
	a->flags &= ~IA_UPDATED;
    }
}

static void
if_end_partial_update_locked(struct iface *i)
{
  if (i->flags & IF_NEEDS_RECALC)
    if_recalc_preferred(i);

  if (i->flags & IF_TMP_DOWN)
    if_change_flags(i, i->flags & ~IF_TMP_DOWN);
}

void
if_end_partial_update(struct iface *i)
{
  IFACE_LOCK;
  if_end_partial_update_locked(i);
  IFACE_UNLOCK;
}

void
if_end_update(void)
{
  struct ifa *a, *b;

  IFACE_WALK(i)
    {
      if (!(i->flags & IF_UPDATED))
	if_change_flags(i, (i->flags & ~IF_ADMIN_UP) | IF_SHUTDOWN);
      else
	{
	  WALK_LIST_DELSAFE(a, b, i->addrs)
	    if (!(a->flags & IA_UPDATED))
	      ifa_delete(a);
	  if_end_partial_update_locked(i);
	}
    }
}

static void
iface_notify_hook(void *_s)
{
  struct iface_subscription *s = _s;

  IFACE_LOCK;

  while (!EMPTY_TLIST(ifnot, &s->queue))
  {
    struct iface_notification *n = THEAD(ifnot, &s->queue);
    debug("Process notify %d/%p (%p) to %p\n", n->type, n->a, n, s);
    IFACE_UNLOCK;

    switch (n->type) {
      case IFNOT_ADDRESS:
	ifa_send_notify(s, n->flags, n->a);
	IFACE_LOCK;
	ifa_unlink(n->a);
	IFACE_UNLOCK;
	break;
      case IFNOT_INTERFACE:
	if_send_notify(s, n->flags, n->i);
	IFACE_LOCK;
	if_unlink(n->i);
	IFACE_UNLOCK;
	break;
      case IFNOT_NEIGHBOR:
	s->neigh_notify(n->n);
	IFACE_LOCK;
	neigh_unlink(n->n);
	IFACE_UNLOCK;
	break;
      default:
	bug("Bad interface notification type: %d", n->type);
    }

    IFACE_LOCK;
    ifnot_rem_node(&s->queue, n);
    sl_free(n);
  }

  IFACE_UNLOCK;
}


/**
 * iface_subscribe - request interface updates
 * @s: subscription structure
 *
 * When a new protocol starts, this function sends it a series
 * of notifications about all existing interfaces.
 */
void
iface_subscribe(struct iface_subscription *s)
{
  IFACE_LOCK;
  ifsub_add_tail(&iface_sub_list, s);
  s->event = (event) {
    .hook = iface_notify_hook,
    .data = s,
  };

  if (!s->if_notify && !s->ifa_notify)	/* shortcut */
  {
    IFACE_UNLOCK;
    return;
  }

  struct iface *i;
  DBG("Announcing interfaces to new protocol %s\n", p->name);
  WALK_LIST(i, global_iface_list)
    {
      if_enqueue_notify_to(
	  (struct iface_notification) {
	  .type = IFNOT_INTERFACE,
	  .i = i,
	  .flags = IF_CHANGE_CREATE | ((i->flags & IF_UP) ? IF_CHANGE_UP : 0),
	  }, s);

      struct ifa *a;
      if (i->flags & IF_UP)
	WALK_LIST(a, i->addrs)
	  if_enqueue_notify_to(
	      (struct iface_notification) {
	      .type = IFNOT_ADDRESS,
	      .a = a,
	      .flags = IF_CHANGE_CREATE | IF_CHANGE_UP,
	      }, s);
    }

  IFACE_UNLOCK;
}

/**
 * iface_unsubscribe - unsubscribe from interface updates
 * @s: subscription structure
 */
void
iface_unsubscribe(struct iface_subscription *s)
{
  IFACE_LOCK;

  struct proto *p = SKIP_BACK(struct proto, iface_sub, s);
  WALK_TLIST_DELSAFE(proto_neigh, n, &p->neighbors)
    neigh_unlink(n);

  ifsub_rem_node(&iface_sub_list, s);
  ev_postpone(&s->event);

  WALK_TLIST_DELSAFE(ifnot, n, &s->queue)
  {
    debug("Drop notify %d/%p (%p) to %p\n", n->type, n->a, n, s);
    switch (n->type)
    {
      case IFNOT_ADDRESS:
	ifa_unlink(n->a);
	break;
      case IFNOT_INTERFACE:
	if_unlink(n->i);
	break;
      case IFNOT_NEIGHBOR:
	neigh_unlink(n->n);
	break;
      default:
	bug("Bad interface notification type: %d", n->type);
    }

    ifnot_rem_node(&s->queue, n);
    sl_free(n);
  }

  ASSERT_DIE(EMPTY_TLIST(proto_neigh, &p->neighbors));

  IFACE_UNLOCK;
}

/**
 * if_find_by_index - find interface by ifindex
 * @idx: ifindex
 *
 * This function finds an &iface structure corresponding to an interface
 * of the given index @idx. Returns a pointer to the structure or %NULL
 * if no such structure exists.
 */
struct iface *
if_find_by_index_locked(unsigned idx)
{
  struct iface *i;

  WALK_LIST(i, global_iface_list)
    if (i->index == idx && !(i->flags & IF_SHUTDOWN))
      return i;

  return NULL;
}

struct iface *
if_find_by_index(unsigned idx)
{
  IFACE_LOCK;
  struct iface *i = if_find_by_index_locked(idx);
  IFACE_UNLOCK;
  return i;
}

/**
 * if_find_by_name - find interface by name
 * @name: interface name
 *
 * This function finds an &iface structure corresponding to an interface
 * of the given name @name. Returns a pointer to the structure or %NULL
 * if no such structure exists.
 */
struct iface *
if_find_by_name(const char *name)
{
  struct iface *i;

  IFACE_LOCK;
  WALK_LIST(i, global_iface_list)
    if (!strcmp(i->name, name) && !(i->flags & IF_SHUTDOWN))
    {
      IFACE_UNLOCK;
      return i;
    }

  IFACE_UNLOCK;
  return NULL;
}

struct iface *
if_get_by_name(const char *name)
{
  struct iface *i;

  IFACE_LOCK;
  WALK_LIST(i, global_iface_list)
    if (!strcmp(i->name, name))
    {
      IFACE_UNLOCK;
      return i;
    }

  /* No active iface, create a dummy */
  i = mb_allocz(if_pool, sizeof(struct iface));
  strncpy(i->name, name, sizeof(i->name)-1);
  i->flags = IF_SHUTDOWN;
  init_list(&i->addrs);
  init_list(&i->neighbors);
  add_tail(&global_iface_list, &i->n);

  IFACE_UNLOCK;
  return i;
}

static inline void
if_set_preferred(struct ifa **pos, struct ifa *new)
{
  if (*pos)
    (*pos)->flags &= ~IA_PRIMARY;
  if (new)
    new->flags |= IA_PRIMARY;

  *pos = new;
}

static void
if_recalc_preferred(struct iface *i)
{
  /*
   * Preferred address selection priority:
   * 1) Address configured in Device protocol
   * 2) Sysdep IPv4 address (BSD)
   * 3) Old preferred address
   * 4) First address in list
   */

  struct kif_iface_config *ic = kif_get_iface_config(i);
  struct ifa *a4 = i->addr4, *a6 = i->addr6, *ll = i->llv6;
  ip_addr pref_v4 = ic->pref_v4;
  uint change = 0;

  if (kif_update_sysdep_addr(i))
    change |= IF_CHANGE_SYSDEP;

  /* BSD sysdep address */
  if (ipa_zero(pref_v4) && ip4_nonzero(i->sysdep))
    pref_v4 = ipa_from_ip4(i->sysdep);

  struct ifa *a;
  WALK_LIST(a, i->addrs)
    {
      /* Secondary address is never selected */
      if (a->flags & IA_SECONDARY)
	continue;

      if (ipa_is_ip4(a->ip)) {
	if (!a4 || ipa_equal(a->ip, pref_v4))
	  a4 = a;
      } else if (!ipa_is_link_local(a->ip)) {
	if (!a6 || ipa_equal(a->ip, ic->pref_v6))
	  a6 = a;
      } else {
	if (!ll || ipa_equal(a->ip, ic->pref_ll))
	  ll = a;
      }
    }

  if ((a4 != i->addr4) || (i->flags & IF_LOST_ADDR4))
  {
    if_set_preferred(&i->addr4, a4);
    change |= IF_CHANGE_ADDR4;
  }

  if ((a6 != i->addr6) || (i->flags & IF_LOST_ADDR6))
  {
    if_set_preferred(&i->addr6, a6);
    change |= IF_CHANGE_ADDR6;
  }

  if ((ll != i->llv6) || (i->flags & IF_LOST_LLV6))
  {
    if_set_preferred(&i->llv6, ll);
    change |= IF_CHANGE_LLV6;
  }

  i->flags &= ~(IF_NEEDS_RECALC | IF_LOST_ADDR4 | IF_LOST_ADDR6 | IF_LOST_LLV6);

  if (change)
    if_notify_change(change, i);
}

void
if_recalc_all_preferred_addresses(void)
{
  IFACE_WALK(i)
  {
    if_recalc_preferred(i);

    if (i->flags & IF_TMP_DOWN)
      if_change_flags(i, i->flags & ~IF_TMP_DOWN);
  }
}

static inline int
ifa_same(struct ifa *a, struct ifa *b)
{
  return ipa_equal(a->ip, b->ip) && net_equal(&a->prefix, &b->prefix);
}


/**
 * ifa_update - update interface address
 * @a: new interface address
 *
 * This function adds address information to a network
 * interface. It's called by the platform dependent code during
 * the interface update process described under if_update().
 */
struct ifa *
ifa_update(struct ifa *a)
{
  IFACE_LOCK;

  struct iface *i = a->iface;
  struct ifa *b;

  WALK_LIST(b, i->addrs)
    if (ifa_same(b, a))
      {
	if (ipa_equal(b->brd, a->brd) &&
	    ipa_equal(b->opposite, a->opposite) &&
	    b->scope == a->scope &&
	    !((b->flags ^ a->flags) & (IA_SECONDARY | IA_PEER | IA_HOST)))
	  {
	    b->flags |= IA_UPDATED;

	    IFACE_UNLOCK;
	    return b;
	  }
	ifa_delete(b);
	break;
      }

  if ((a->prefix.type == NET_IP4) && (i->flags & IF_BROADCAST) && ipa_zero(a->brd))
    log(L_WARN "Missing broadcast address for interface %s", i->name);

  b = mb_alloc(if_pool, sizeof(struct ifa));
  memcpy(b, a, sizeof(struct ifa));
  ifa_link(b);
  if_link(i);
  add_tail(&i->addrs, &b->n);
  b->flags |= IA_UPDATED;

  i->flags |= IF_NEEDS_RECALC;
  if (i->flags & IF_UP)
    ifa_notify_change(IF_CHANGE_CREATE | IF_CHANGE_UP, b);

  IFACE_UNLOCK;
  return b;
}

/**
 * ifa_delete - remove interface address
 * @a: interface address
 *
 * This function removes address information from a network
 * interface. It's called by the platform dependent code during
 * the interface update process described under if_update().
 */
void
ifa_delete(struct ifa *a)
{
  struct iface *i = a->iface;
  struct ifa *b;

  IFACE_LOCK;

  WALK_LIST(b, i->addrs)
    if (ifa_same(b, a))
      {
	rem_node(&b->n);

	if (b->flags & IA_PRIMARY)
	  {
	    /*
	     * We unlink deleted preferred address and mark for recalculation.
	     * FIXME: This could break if we make iface scan non-atomic, as
	     * protocols still could use the freed address until they get
	     * if_notify from preferred route recalculation. We should fix and
	     * simplify this in the future by having struct ifa refcounted
	     */
	    if (b == i->addr4) { i->addr4 = NULL; i->flags |= IF_LOST_ADDR4; }
	    if (b == i->addr6) { i->addr6 = NULL; i->flags |= IF_LOST_ADDR6; }
	    if (b == i->llv6)  { i->llv6 = NULL;  i->flags |= IF_LOST_LLV6; }
	    i->flags |= IF_NEEDS_RECALC;
	  }

	if (i->flags & IF_UP)
	  ifa_notify_change(IF_CHANGE_DOWN, b);

	ifa_unlink(b);
	IFACE_UNLOCK;
	return;
      }

  IFACE_UNLOCK;
}

u32
if_choose_router_id(struct iface_patt *mask, u32 old_id)
{
  IFACE_LOCK;

  struct iface *i;
  struct ifa *a, *b;

  b = NULL;
  WALK_LIST(i, global_iface_list)
    {
      if (!(i->flags & IF_ADMIN_UP) ||
	  (i->flags & IF_SHUTDOWN))
	continue;

      WALK_LIST(a, i->addrs)
	{
	  if (a->prefix.type != NET_IP4)
	    continue;

	  if (a->flags & IA_SECONDARY)
	    continue;

	  if (a->scope <= SCOPE_LINK)
	    continue;

	  /* Check pattern if specified */
	  if (mask && !iface_patt_match(mask, i, a))
	    continue;

	  /* No pattern or pattern matched */
	  if (!b || ipa_to_u32(a->ip) < ipa_to_u32(b->ip))
	    b = a;
	}
    }

  IFACE_UNLOCK;

  if (!b)
    return 0;

  u32 id = ipa_to_u32(b->ip);
  if (id != old_id)
    log(L_INFO "Chosen router ID %R according to interface %s", id, b->iface->name);

  return id;
}

/**
 * if_init - initialize interface module
 *
 * This function is called during BIRD startup to initialize
 * all data structures of the interface module.
 */
void
if_init(void)
{
  if_pool = rp_new(&root_pool, "Interfaces");
  init_list(&global_iface_list);
  iface_sub_slab = sl_new(if_pool, sizeof(struct iface_notification));
  strcpy(default_vrf.name, "default");
  neigh_init(if_pool);
  iface_domain = DOMAIN_NEW(attrs, "Interfaces");
}

/*
 *	Interface Pattern Lists
 */

int
iface_patt_match(struct iface_patt *ifp, struct iface *i, struct ifa *a)
{
  struct iface_patt_node *p;

  WALK_LIST(p, ifp->ipn_list)
    {
      const char *t = p->pattern;
      int pos = p->positive;

      if (t)
	{
	  if (*t == '-')
	    {
	      t++;
	      pos = !pos;
	    }

	  if (!patmatch(t, i->name))
	    continue;
	}

      if (p->prefix.pxlen == 0)
	return pos;

      if (!a)
	continue;

      if (ipa_in_netX(a->ip, &p->prefix))
	return pos;

      if ((a->flags & IA_PEER) &&
	  ipa_in_netX(a->opposite, &p->prefix))
	return pos;

      continue;
    }

  return 0;
}

struct iface_patt *
iface_patt_find(list *l, struct iface *i, struct ifa *a)
{
  struct iface_patt *p;

  WALK_LIST(p, *l)
    if (iface_patt_match(p, i, a))
      return p;

  return NULL;
}

static int
iface_plists_equal(struct iface_patt *pa, struct iface_patt *pb)
{
  struct iface_patt_node *x, *y;

  x = HEAD(pa->ipn_list);
  y = HEAD(pb->ipn_list);
  while (x->n.next && y->n.next)
    {
      if ((x->positive != y->positive) ||
	  (!x->pattern && y->pattern) ||	/* This nasty lines where written by me... :-( Feela */
	  (!y->pattern && x->pattern) ||
	  ((x->pattern != y->pattern) && strcmp(x->pattern, y->pattern)) ||
	  !net_equal(&x->prefix, &y->prefix))
	return 0;
      x = (void *) x->n.next;
      y = (void *) y->n.next;
    }
  return (!x->n.next && !y->n.next);
}

int
iface_patts_equal(list *a, list *b, int (*comp)(struct iface_patt *, struct iface_patt *))
{
  struct iface_patt *x, *y;

  x = HEAD(*a);
  y = HEAD(*b);
  while (x->n.next && y->n.next)
    {
      if (!iface_plists_equal(x, y) ||
	  (comp && !comp(x, y)))
	return 0;
      x = (void *) x->n.next;
      y = (void *) y->n.next;
    }
  return (!x->n.next && !y->n.next);
}

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
