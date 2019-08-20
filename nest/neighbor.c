/*
 *	BIRD -- Neighbor Cache
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2008--2018 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2008--2018 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Neighbor cache
 *
 * Most routing protocols need to associate their internal state data with
 * neighboring routers, check whether an address given as the next hop attribute
 * of a route is really an address of a directly connected host and which
 * interface is it connected through. Also, they often need to be notified when
 * a neighbor ceases to exist or when their long awaited neighbor becomes
 * connected. The neighbor cache is there to solve all these problems.
 *
 * The neighbor cache maintains a collection of neighbor entries. Each entry
 * represents one IP address corresponding to either our directly connected
 * neighbor or our own end of the link (when the scope of the address is set to
 * %SCOPE_HOST) together with per-neighbor data belonging to a single protocol.
 * A neighbor entry may be bound to a specific interface, which is required for
 * link-local IP addresses and optional for global IP addresses.
 *
 * Neighbor cache entries are stored in a hash table, which is indexed by triple
 * (protocol, IP, requested-iface), so if both regular and iface-bound neighbors
 * are requested, they are represented by two neighbor cache entries. Active
 * entries are also linked in per-interface list (allowing quick processing of
 * interface change events). Inactive entries exist only when the protocol has
 * explicitly requested it via the %NEF_STICKY flag because it wishes to be
 * notified when the node will again become a neighbor. Such entries are instead
 * linked in a special list, which is walked whenever an interface changes its
 * state to up. Neighbor entry VRF association is implied by respective
 * protocol.
 *
 * Besides the already mentioned %NEF_STICKY flag, there is also %NEF_ONLINK,
 * which specifies that neighbor should be considered reachable on given iface
 * regardless of associated address ranges, and %NEF_IFACE, which represents
 * pseudo-neighbor entry for whole interface (and uses %IPA_NONE IP address).
 *
 * When a neighbor event occurs (a neighbor gets disconnected or a sticky
 * inactive neighbor becomes connected), the protocol hook neigh_notify() is
 * called to advertise the change.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "lib/hash.h"
#include "lib/resource.h"

#define NEIGH_HASH_SIZE 256
#define NEIGH_HASH_OFFSET 24

static slab *neigh_slab;
static list neigh_hash_table[NEIGH_HASH_SIZE], sticky_neigh_list;

static inline uint
neigh_hash(struct proto *p, ip_addr a, struct iface *i)
{
  return (p->hash_key ^ ipa_hash(a) ^ ptr_hash(i)) >> NEIGH_HASH_OFFSET;
}

static int
if_connected(ip_addr a, struct iface *i, struct ifa **ap, uint flags)
{
  struct ifa *b;

  /* Handle iface pseudo-neighbors */
  if (flags & NEF_IFACE)
    return *ap = NULL, (i->flags & IF_UP) ? SCOPE_HOST : -1;

  /* Host addresses match even if iface is down */
  WALK_LIST(b, i->addrs)
    if (ipa_equal(a, b->ip))
      return *ap = b, SCOPE_HOST;

  /* Rest do not match if iface is down */
  if (!(i->flags & IF_UP))
    return *ap = NULL, -1;

  /* Regular neighbors */
  WALK_LIST(b, i->addrs)
  {
    if (b->flags & IA_PEER)
    {
      if (ipa_equal(a, b->opposite))
	return *ap = b, b->scope;
    }
    else
    {
      if (ipa_in_netX(a, &b->prefix))
      {
	/* Do not allow IPv4 network and broadcast addresses */
	if (ipa_is_ip4(a) &&
	    (net_pxlen(&b->prefix) < (IP4_MAX_PREFIX_LENGTH - 1)) &&
	    (ipa_equal(a, net_prefix(&b->prefix)) ||	/* Network address */
	     ipa_equal(a, b->brd)))			/* Broadcast */
	  return *ap = NULL, -1;

	return *ap = b, b->scope;
      }
    }
  }

  /* Handle ONLINK flag */
  if (flags & NEF_ONLINK)
    return *ap = NULL, ipa_classify(a) & IADDR_SCOPE_MASK;

  return *ap = NULL, -1;
}

static inline int
if_connected_any(ip_addr a, struct iface *vrf, uint vrf_set, struct iface **iface, struct ifa **addr, uint flags)
{
  struct iface *i;
  struct ifa *b;
  int s, scope = -1;

  *iface = NULL;
  *addr = NULL;

  /* Get first match, but prefer SCOPE_HOST to other matches */
  WALK_LIST(i, iface_list)
    if ((!vrf_set || vrf == i->master) && ((s = if_connected(a, i, &b, flags)) >= 0))
      if ((scope < 0) || ((scope > SCOPE_HOST) && (s == SCOPE_HOST)))
      {
	*iface = i;
	*addr = b;
	scope = s;
      }

  return scope;
}

/**
 * neigh_find - find or create a neighbor entry
 * @p: protocol which asks for the entry
 * @a: IP address of the node to be searched for
 * @iface: optionally bound neighbor to this iface (may be NULL)
 * @flags: %NEF_STICKY for sticky entry, %NEF_ONLINK for onlink entry
 *
 * Search the neighbor cache for a node with given IP address. Iface can be
 * specified for link-local addresses or for cases, where neighbor is expected
 * on given interface. If it is found, a pointer to the neighbor entry is
 * returned. If no such entry exists and the node is directly connected on one
 * of our active interfaces, a new entry is created and returned to the caller
 * with protocol-dependent fields initialized to zero.  If the node is not
 * connected directly or *@a is not a valid unicast IP address, neigh_find()
 * returns %NULL.
 */
neighbor *
neigh_find(struct proto *p, ip_addr a, struct iface *iface, uint flags)
{
  neighbor *n;
  int class, scope = -1;
  uint h = neigh_hash(p, a, iface);
  struct iface *ifreq = iface;
  struct ifa *addr = NULL;

  WALK_LIST(n, neigh_hash_table[h])	/* Search the cache */
    if ((n->proto == p) && ipa_equal(n->addr, a) && (n->ifreq == iface))
      return n;

  if (flags & NEF_IFACE)
  {
    if (ipa_nonzero(a) || !iface)
      return NULL;
  }
  else
  {
    class = ipa_classify(a);
    if (class < 0)			/* Invalid address */
      return NULL;
    if (((class & IADDR_SCOPE_MASK) == SCOPE_HOST) ||
	(((class & IADDR_SCOPE_MASK) == SCOPE_LINK) && !iface) ||
	!(class & IADDR_HOST))
      return NULL;			/* Bad scope or a somecast */
  }

  if ((flags & NEF_ONLINK) && !iface)
      return NULL;

  if (iface)
  {
    scope = if_connected(a, iface, &addr, flags);
    iface = (scope < 0) ? NULL : iface;
  }
  else
    scope = if_connected_any(a, p->vrf, p->vrf_set, &iface, &addr, flags);

  /* scope < 0 means i don't know neighbor */
  /* scope >= 0  <=>  iface != NULL */

  if ((scope < 0) && !(flags & NEF_STICKY))
    return NULL;

  n = sl_alloc(neigh_slab);
  memset(n, 0, sizeof(neighbor));

  add_tail(&neigh_hash_table[h], &n->n);
  add_tail((scope >= 0) ? &iface->neighbors : &sticky_neigh_list, &n->if_n);
  n->addr = a;
  n->ifa = addr;
  n->iface = iface;
  n->ifreq = ifreq;
  n->proto = p;
  n->flags = flags;
  n->scope = scope;

  return n;
}

/**
 * neigh_dump - dump specified neighbor entry.
 * @n: the entry to dump
 *
 * This functions dumps the contents of a given neighbor entry to debug output.
 */
void
neigh_dump(neighbor *n)
{
  debug("%p %I %s %s ", n, n->addr,
	n->iface ? n->iface->name : "[]",
	n->ifreq ? n->ifreq->name : "[]");
  debug("%s %p %08x scope %s", n->proto->name, n->data, n->aux, ip_scope_text(n->scope));
  if (n->flags & NEF_STICKY)
    debug(" STICKY");
  if (n->flags & NEF_ONLINK)
    debug(" ONLINK");
  debug("\n");
}

/**
 * neigh_dump_all - dump all neighbor entries.
 *
 * This function dumps the contents of the neighbor cache to debug output.
 */
void
neigh_dump_all(void)
{
  neighbor *n;
  int i;

  debug("Known neighbors:\n");
  for(i=0; i<NEIGH_HASH_SIZE; i++)
    WALK_LIST(n, neigh_hash_table[i])
      neigh_dump(n);
  debug("\n");
}

static inline void
neigh_notify(neighbor *n)
{
  if (n->proto->neigh_notify && (n->proto->proto_state != PS_STOP))
    n->proto->neigh_notify(n);
}

static void
neigh_up(neighbor *n, struct iface *i, struct ifa *a, int scope)
{
  DBG("Waking up sticky neighbor %I\n", n->addr);
  n->iface = i;
  n->ifa = a;
  n->scope = scope;

  rem_node(&n->if_n);
  add_tail(&i->neighbors, &n->if_n);

  neigh_notify(n);
}

static void
neigh_down(neighbor *n)
{
  DBG("Flushing neighbor %I on %s\n", n->addr, n->iface->name);
  n->iface = NULL;
  n->ifa = NULL;
  n->scope = -1;

  rem_node(&n->if_n);
  add_tail(&sticky_neigh_list, &n->if_n);

  neigh_notify(n);
}

static inline void
neigh_free(neighbor *n)
{
  rem_node(&n->n);
  rem_node(&n->if_n);
  sl_free(neigh_slab, n);
}

/**
 * neigh_update: update neighbor entry w.r.t. change on specific iface
 * @n: neighbor to update
 * @iface: changed iface
 *
 * The function recalculates state of the neighbor entry @n assuming that only
 * the interface @iface may changed its state or addresses. Then, appropriate
 * actions are executed (the neighbor goes up, down, up-down, or just notified).
 */
void
neigh_update(neighbor *n, struct iface *iface)
{
  struct proto *p = n->proto;
  struct ifa *ifa = NULL;
  int scope = -1;

  /* Iface-bound neighbors ignore other ifaces */
  if (n->ifreq && (n->ifreq != iface))
    return;

  /* VRF-bound neighbors ignore changes in other VRFs */
  if (p->vrf_set && (p->vrf != iface->master))
    return;

  scope = if_connected(n->addr, iface, &ifa, n->flags);

  /* When neighbor is going down, try to respawn it on other ifaces */
  if ((scope < 0) && (n->scope >= 0) && !n->ifreq && (n->flags & NEF_STICKY))
    scope = if_connected_any(n->addr, p->vrf, p->vrf_set, &iface, &ifa, n->flags);

  /* No change or minor change - ignore or notify */
  if ((scope == n->scope) && (iface == n->iface))
  {
    if (ifa != n->ifa)
    {
      n->ifa = ifa;
      neigh_notify(n);
    }

    return;
  }

  /* Major change - going down and/or going up */

  if (n->scope >= 0)
    neigh_down(n);

  if ((n->scope < 0) && !(n->flags & NEF_STICKY))
  {
    neigh_free(n);
    return;
  }

  if (scope >= 0)
    neigh_up(n, iface, ifa, scope);
}


/**
 * neigh_if_up: notify neighbor cache about interface up event
 * @i: interface in question
 *
 * Tell the neighbor cache that a new interface became up.
 *
 * The neighbor cache wakes up all inactive sticky neighbors with
 * addresses belonging to prefixes of the interface @i.
 */
void
neigh_if_up(struct iface *i)
{
  neighbor *n;
  node *x, *y;

  WALK_LIST2_DELSAFE(n, x, y, sticky_neigh_list, if_n)
    neigh_update(n, i);
}

/**
 * neigh_if_down - notify neighbor cache about interface down event
 * @i: the interface in question
 *
 * Notify the neighbor cache that an interface has ceased to exist.
 *
 * It causes all neighbors connected to this interface to be updated or removed.
 */
void
neigh_if_down(struct iface *i)
{
  neighbor *n;
  node *x, *y;

  WALK_LIST2_DELSAFE(n, x, y, i->neighbors, if_n)
    neigh_update(n, i);
}

/**
 * neigh_if_link - notify neighbor cache about interface link change
 * @i: the interface in question
 *
 * Notify the neighbor cache that an interface changed link state. All owners of
 * neighbor entries connected to this interface are notified.
 */
void
neigh_if_link(struct iface *i)
{
  neighbor *n;
  node *x, *y;

  WALK_LIST2_DELSAFE(n, x, y, i->neighbors, if_n)
    neigh_notify(n);
}

/**
 * neigh_ifa_update: notify neighbor cache about interface address add or remove event
 * @a: interface address in question
 *
 * Tell the neighbor cache that an address was added or removed.
 *
 * The neighbor cache wakes up all inactive sticky neighbors with
 * addresses belonging to prefixes of the interface belonging to @ifa
 * and causes all unreachable neighbors to be flushed.
 */
void
neigh_ifa_update(struct ifa *a)
{
  struct iface *i = a->iface;
  neighbor *n;
  node *x, *y;

  /* Update all neighbors whose scope has changed */
  WALK_LIST2_DELSAFE(n, x, y, i->neighbors, if_n)
    neigh_update(n, i);

  /* Wake up all sticky neighbors that are reachable now */
  WALK_LIST2_DELSAFE(n, x, y, sticky_neigh_list, if_n)
    neigh_update(n, i);
}

static inline void
neigh_prune_one(neighbor *n)
{
  if (n->proto->proto_state != PS_DOWN)
    return;

  neigh_free(n);
}

/**
 * neigh_prune - prune neighbor cache
 *
 * neigh_prune() examines all neighbor entries cached and removes those
 * corresponding to inactive protocols. It's called whenever a protocol
 * is shut down to get rid of all its heritage.
 */
void
neigh_prune(void)
{
  neighbor *n;
  node *m;
  int i;

  DBG("Pruning neighbors\n");
  for(i=0; i<NEIGH_HASH_SIZE; i++)
    WALK_LIST_DELSAFE(n, m, neigh_hash_table[i])
      neigh_prune_one(n);
}

/**
 * neigh_init - initialize the neighbor cache.
 * @if_pool: resource pool to be used for neighbor entries.
 *
 * This function is called during BIRD startup to initialize
 * the neighbor cache module.
 */
void
neigh_init(pool *if_pool)
{
  neigh_slab = sl_new(if_pool, sizeof(neighbor));

  for(int i = 0; i < NEIGH_HASH_SIZE; i++)
    init_list(&neigh_hash_table[i]);

  init_list(&sticky_neigh_list);
}
