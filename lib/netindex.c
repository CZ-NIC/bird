/*
 *	BIRD Internet Routing Daemon -- Semi-global index of nets
 *
 *	(c) 2023       Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/birdlib.h"
#include "lib/netindex_private.h"

#define NETINDEX_KEY(n)		(n)->hash, (n)->addr
#define NETINDEX_NEXT(n)	(n)->next
#define NETINDEX_EQ(h,n,i,o)	((h == i) && net_equal(n,o))
#define NETINDEX_FN(h,n)	(h)
#define NETINDEX_ORDER		4 /* Initial */

#define NETINDEX_REHASH		netindex_rehash
#define NETINDEX_PARAMS		/8, *1, 2, 2, 4, 28

HASH_DEFINE_REHASH_FN(NETINDEX, struct netindex);

static void netindex_hash_cleanup(void *netindex_hash);

static struct netindex *
net_lock_revive_unlock(struct netindex_hash_private *hp, struct netindex *i)
{
  if (!i)
    return NULL;

  lfuc_lock_revive(&i->uc);
  lfuc_unlock(&i->uc, hp->cleanup_list, &hp->cleanup_event);
  return i;
}

/*
 * Index initialization
 */
netindex_hash *
netindex_hash_new(pool *sp)
{
  DOMAIN(attrs) dom = DOMAIN_NEW(attrs);
  LOCK_DOMAIN(attrs, dom);

  pool *p = rp_new(sp, dom.attrs, "Network index");

  struct netindex_hash_private *nh = mb_allocz(p, sizeof *nh);
  nh->lock = dom;
  nh->pool = p;

  nh->cleanup_list = &global_event_list;
  nh->cleanup_event = (event) { .hook = netindex_hash_cleanup, nh };

  UNLOCK_DOMAIN(attrs, dom);
  return SKIP_BACK(netindex_hash, priv, nh);
}

static void
netindex_hash_cleanup(void *_nh)
{
  NH_LOCK((netindex_hash *) _nh, nh);

  for (uint t = 0; t < NET_MAX; t++)
  {
    if (!nh->net[t].hash.data)
      continue;

    HASH_WALK_FILTER(nh->net[t].hash, next, i, ii)
      if (lfuc_finished(&i->uc))
      {
	HASH_DO_REMOVE(nh->net[t].hash, NETINDEX, ii);
	hmap_clear(&nh->net[t].id_map, i->index);
	nh->net[t].block[i->index] = NULL;

	if (nh->net[t].slab)
	  sl_free(i);
	else
	  mb_free(i);
      }
    HASH_WALK_DELSAFE_END;
  }
}


static void
netindex_hash_init(struct netindex_hash_private *hp, u8 type)
{
  ASSERT_DIE(hp->net[type].block == NULL);

  hp->net[type].slab = net_addr_length[type] ? sl_new(hp->pool, sizeof (struct netindex) + net_addr_length[type]) : NULL;
  HASH_INIT(hp->net[type].hash, hp->pool, NETINDEX_ORDER);
  hp->net[type].block_size = 128;
  hp->net[type].block = mb_allocz(hp->pool, hp->net[type].block_size * sizeof (struct netindex *));
  hmap_init(&hp->net[type].id_map, hp->pool, 128);
};

/*
 * Private index manipulation
 */
struct netindex *
net_find_index_fragile_chain(struct netindex_hash_private *hp, const net_addr *n)
{
  ASSERT_DIE(n->type < NET_MAX);
  if (!hp->net[n->type].block)
    return NULL;

  u32 h = net_hash(n);
  return HASH_FIND_CHAIN(hp->net[n->type].hash, NETINDEX, h, n);
}

struct netindex *
net_find_index_fragile(struct netindex_hash_private *hp, const net_addr *n)
{
  ASSERT_DIE(n->type < NET_MAX);
  if (!hp->net[n->type].block)
    return NULL;

  u32 h = net_hash(n);
  return HASH_FIND(hp->net[n->type].hash, NETINDEX, h, n);
}

static struct netindex *
net_find_index_locked(struct netindex_hash_private *hp, const net_addr *n)
{
  return net_lock_revive_unlock(hp, net_find_index_fragile(hp, n));
}

static struct netindex *
net_new_index_locked(struct netindex_hash_private *hp, const net_addr *n)
{
  if (!hp->net[n->type].block)
    netindex_hash_init(hp, n->type);

  u32 i = hmap_first_zero(&hp->net[n->type].id_map);
  hmap_set(&hp->net[n->type].id_map, i);

  struct netindex *ni = hp->net[n->type].slab ?
    sl_alloc(hp->net[n->type].slab) :
    mb_alloc(hp->pool, n->length + sizeof *ni);

  *ni = (struct netindex) {
    .hash = net_hash(n),
    .index = i,
  };
  net_copy(ni->addr, n);

  HASH_INSERT2(hp->net[n->type].hash, NETINDEX, hp->pool, ni);
  while (hp->net[n->type].block_size <= i)
  {
    u32 bs = hp->net[n->type].block_size;
    struct netindex **nb = mb_alloc(hp->pool, bs * 2 * sizeof *nb);
    memcpy(nb, hp->net[n->type].block, bs * sizeof *nb);
    memset(&nb[bs], 0, bs * sizeof *nb);
    hp->net[n->type].block_size *= 2;
    hp->net[n->type].block = nb;
  }

  hp->net[n->type].block[i] = ni;

  return net_lock_revive_unlock(hp, ni);
}


/*
 * Public entry points
 */

void net_lock_index(netindex_hash *h UNUSED, struct netindex *i)
{
//  log(L_TRACE "Lock index %p", i);
  lfuc_lock(&i->uc);
}

void net_unlock_index(netindex_hash *h, struct netindex *i)
{
//  log(L_TRACE "Unlock index %p", i);
  lfuc_unlock(&i->uc, h->cleanup_list, &h->cleanup_event);
}

struct netindex *
net_find_index(netindex_hash *h, const net_addr *n)
{
  NH_LOCK(h, hp);
  return net_find_index_locked(hp, n);
}

struct netindex *
net_get_index(netindex_hash *h, const net_addr *n)
{
  NH_LOCK(h, hp);
  return
    net_find_index_locked(hp, n) ?:
    net_new_index_locked(hp, n);
}

struct netindex *
net_resolve_index(netindex_hash *h, u8 net_type, u32 i)
{
  NH_LOCK(h, hp);
  if (i >= hp->net[net_type].block_size)
    return NULL;

  struct netindex *ni = hp->net[net_type].block[i];
  ASSERT_DIE(!ni || (ni->addr->type == net_type));
  return net_lock_revive_unlock(hp, ni);
}
