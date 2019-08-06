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
#include "conf/conf.h"
#include "sysdep/unix/krt.h"

static pool *if_pool;

list iface_list;

static void if_recalc_preferred(struct iface *i);

/**
 * ifa_dump - dump interface address
 * @a: interface address descriptor
 *
 * This function dumps contents of an &ifa to the debug output.
 */
void
ifa_dump(struct ifa *a)
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
      ifa_dump(a);
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
  struct iface *i;

  debug("Known network interfaces:\n");
  WALK_LIST(i, iface_list)
    if_dump(i);
  debug("Router ID: %08x\n", config->router_id);
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
  to->master = from->master;
}

static inline void
ifa_send_notify(struct proto *p, unsigned c, struct ifa *a)
{
  if (p->ifa_notify &&
      (p->proto_state != PS_DOWN) &&
      (!p->vrf_set || p->vrf == a->iface->master))
    {
      if (p->debug & D_IFACES)
	log(L_TRACE "%s < address %N on interface %s %s",
	    p->name, &a->prefix, a->iface->name,
	    (c & IF_CHANGE_UP) ? "added" : "removed");
      p->ifa_notify(p, c, a);
    }
}

static void
ifa_notify_change_(unsigned c, struct ifa *a)
{
  struct proto *p;

  DBG("IFA change notification (%x) for %s:%I\n", c, a->iface->name, a->ip);

  WALK_LIST(p, proto_list)
    ifa_send_notify(p, c, a);
}

static inline void
ifa_notify_change(unsigned c, struct ifa *a)
{
  if (c & IF_CHANGE_DOWN)
    neigh_ifa_update(a);

  ifa_notify_change_(c, a);

  if (c & IF_CHANGE_UP)
    neigh_ifa_update(a);
}

static inline void
if_send_notify(struct proto *p, unsigned c, struct iface *i)
{
  if (p->if_notify &&
      (p->proto_state != PS_DOWN) &&
      (!p->vrf_set || p->vrf == i->master))
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
      p->if_notify(p, c, i);
    }
}

static void
if_notify_change(unsigned c, struct iface *i)
{
  struct proto *p;
  struct ifa *a;

  if (i->flags & IF_JUST_CREATED)
    {
      i->flags &= ~IF_JUST_CREATED;
      c |= IF_CHANGE_CREATE | IF_CHANGE_MTU;
    }

  DBG("Interface change notification (%x) for %s\n", c, i->name);
#ifdef LOCAL_DEBUG
  if_dump(i);
#endif

  if (c & IF_CHANGE_DOWN)
    neigh_if_down(i);

  if (c & IF_CHANGE_DOWN)
    WALK_LIST(a, i->addrs)
      ifa_notify_change_(IF_CHANGE_DOWN, a);

  WALK_LIST(p, proto_list)
    if_send_notify(p, c, i);

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
      !(i->master_index && !i->master))
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
  struct iface f = {};
  strncpy(f.name, old->name, sizeof(f.name)-1);
  f.flags = IF_SHUTDOWN;
  if_update(&f);
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
  struct iface *i;
  unsigned c;

  WALK_LIST(i, iface_list)
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
  init_list(&i->addrs);
newif:
  init_list(&i->neighbors);
  i->flags |= IF_UPDATED | IF_TMP_DOWN;		/* Tmp down as we don't have addresses yet */
  add_tail(&iface_list, &i->n);
  return i;
}

void
if_start_update(void)
{
  struct iface *i;
  struct ifa *a;

  WALK_LIST(i, iface_list)
    {
      i->flags &= ~IF_UPDATED;
      WALK_LIST(a, i->addrs)
	a->flags &= ~IA_UPDATED;
    }
}

void
if_end_partial_update(struct iface *i)
{
  if (i->flags & IF_NEEDS_RECALC)
    if_recalc_preferred(i);

  if (i->flags & IF_TMP_DOWN)
    if_change_flags(i, i->flags & ~IF_TMP_DOWN);
}

void
if_end_update(void)
{
  struct iface *i;
  struct ifa *a, *b;

  WALK_LIST(i, iface_list)
    {
      if (!(i->flags & IF_UPDATED))
	if_change_flags(i, (i->flags & ~IF_ADMIN_UP) | IF_SHUTDOWN);
      else
	{
	  WALK_LIST_DELSAFE(a, b, i->addrs)
	    if (!(a->flags & IA_UPDATED))
	      ifa_delete(a);
	  if_end_partial_update(i);
	}
    }
}

void
if_flush_ifaces(struct proto *p)
{
  if (p->debug & D_EVENTS)
    log(L_TRACE "%s: Flushing interfaces", p->name);
  if_start_update();
  if_end_update();
}

/**
 * if_feed_baby - advertise interfaces to a new protocol
 * @p: protocol to feed
 *
 * When a new protocol starts, this function sends it a series
 * of notifications about all existing interfaces.
 */
void
if_feed_baby(struct proto *p)
{
  struct iface *i;
  struct ifa *a;

  if (!p->if_notify && !p->ifa_notify)	/* shortcut */
    return;
  DBG("Announcing interfaces to new protocol %s\n", p->name);
  WALK_LIST(i, iface_list)
    {
      if_send_notify(p, IF_CHANGE_CREATE | ((i->flags & IF_UP) ? IF_CHANGE_UP : 0), i);
      if (i->flags & IF_UP)
	WALK_LIST(a, i->addrs)
	  ifa_send_notify(p, IF_CHANGE_CREATE | IF_CHANGE_UP, a);
    }
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
if_find_by_index(unsigned idx)
{
  struct iface *i;

  WALK_LIST(i, iface_list)
    if (i->index == idx && !(i->flags & IF_SHUTDOWN))
      return i;
  return NULL;
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
if_find_by_name(char *name)
{
  struct iface *i;

  WALK_LIST(i, iface_list)
    if (!strcmp(i->name, name) && !(i->flags & IF_SHUTDOWN))
      return i;
  return NULL;
}

struct iface *
if_get_by_name(char *name)
{
  struct iface *i;

  WALK_LIST(i, iface_list)
    if (!strcmp(i->name, name))
      return i;

  /* No active iface, create a dummy */
  i = mb_allocz(if_pool, sizeof(struct iface));
  strncpy(i->name, name, sizeof(i->name)-1);
  i->flags = IF_SHUTDOWN;
  init_list(&i->addrs);
  init_list(&i->neighbors);
  add_tail(&iface_list, &i->n);
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
  struct iface *i;

  WALK_LIST(i, iface_list)
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
  struct iface *i = a->iface;
  struct ifa *b;

  WALK_LIST(b, i->addrs)
    if (ifa_same(b, a))
      {
	if (ipa_equal(b->brd, a->brd) &&
	    ipa_equal(b->opposite, a->opposite) &&
	    b->scope == a->scope &&
	    !((b->flags ^ a->flags) & IA_PEER))
	  {
	    b->flags |= IA_UPDATED;
	    return b;
	  }
	ifa_delete(b);
	break;
      }

  if ((a->prefix.type == NET_IP4) && (i->flags & IF_BROADCAST) && ipa_zero(a->brd))
    log(L_WARN "Missing broadcast address for interface %s", i->name);

  b = mb_alloc(if_pool, sizeof(struct ifa));
  memcpy(b, a, sizeof(struct ifa));
  add_tail(&i->addrs, &b->n);
  b->flags |= IA_UPDATED;

  i->flags |= IF_NEEDS_RECALC;
  if (i->flags & IF_UP)
    ifa_notify_change(IF_CHANGE_CREATE | IF_CHANGE_UP, b);
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

	mb_free(b);
	return;
      }
}

u32
if_choose_router_id(struct iface_patt *mask, u32 old_id)
{
  struct iface *i;
  struct ifa *a, *b;

  b = NULL;
  WALK_LIST(i, iface_list)
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
  init_list(&iface_list);
  neigh_init(if_pool);
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
      char *t = p->pattern;
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
  struct iface *i;
  struct ifa *a;
  char *type;

  WALK_LIST(i, iface_list)
    {
      if (i->flags & IF_SHUTDOWN)
	continue;

      char mbuf[16 + sizeof(i->name)] = {};
      if (i->master)
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
  struct iface *i;

  cli_msg(-2005, "%-10s %-6s %-18s %s", "Interface", "State", "IPv4 address", "IPv6 address");
  WALK_LIST(i, iface_list)
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
