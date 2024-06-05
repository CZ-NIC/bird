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

void
netindex_hash_consistency_check(struct netindex_hash_private *nh)
{
  uint count = 0;
  HASH_WALK(nh->hash, next, i)
  {
    ASSERT_DIE(count < nh->hash.count);
    ASSERT_DIE(nh->block[i->index] == i);
    count++;
  }
  HASH_WALK_END;

  ASSERT_DIE(count == nh->hash.count);
}

/*
 * Index initialization
 */
netindex_hash *
netindex_hash_new(pool *sp, event_list *cleanup_target, u8 type)
{
  DOMAIN(attrs) dom = DOMAIN_NEW(attrs);
  LOCK_DOMAIN(attrs, dom);

  pool *p = rp_new(sp, dom.attrs, "Network index");

  struct netindex_hash_private *nh = mb_allocz(p, sizeof *nh);
  nh->lock = dom;
  nh->pool = p;
  nh->net_type = type;

  nh->slab = net_addr_length[type] ? sl_new(nh->pool, sizeof (struct netindex) + net_addr_length[type]) : NULL;

  HASH_INIT(nh->hash, nh->pool, NETINDEX_ORDER);
  nh->block_size = 128;
  nh->block = mb_allocz(nh->pool, nh->block_size * sizeof (struct netindex *));

  hmap_init(&nh->id_map, nh->pool, 128);

  nh->cleanup_list = cleanup_target;
  nh->cleanup_event = (event) { .hook = netindex_hash_cleanup, nh };

  UNLOCK_DOMAIN(attrs, dom);
  return SKIP_BACK(netindex_hash, priv, nh);
}

static void
netindex_hash_cleanup(void *_nh)
{
  struct netindex_hash_private *nh = _nh;

  DOMAIN(attrs) dom = nh->lock;
  LOCK_DOMAIN(attrs, dom);

  EXPENSIVE_CHECK(netindex_hash_consistency_check(nh));

  uint kept = 0;

  for (uint i = 0; i < nh->block_size; i++)
  {
    struct netindex *ni = nh->block[i];
    if (!ni)
      continue;

    ASSERT_DIE(i == ni->index);

    if (lfuc_finished(&ni->uc))
    {
      HASH_REMOVE2(nh->hash, NETINDEX, nh->pool, ni);
      hmap_clear(&nh->id_map, ni->index);
      nh->block[i] = NULL;

      if (nh->slab)
	sl_free(ni);
      else
	mb_free(ni);
    }
    else
      kept++;
  }

  EXPENSIVE_CHECK(netindex_hash_consistency_check(nh));

  if (kept || !nh->deleted_event)
  {
    UNLOCK_DOMAIN(attrs, dom);
    return;
  }

  ev_postpone(&nh->cleanup_event);

  event *e = nh->deleted_event;
  event_list *t = nh->deleted_target;

  /* Check cleanliness */
  HASH_WALK(nh->hash, next, i)
    bug("Stray netindex in deleted hash");
  HASH_WALK_END;

  /* Pool free is enough to drop everything */
  rp_free(nh->pool);

  /* And only the lock remains */
  UNLOCK_DOMAIN(attrs, dom);
  DOMAIN_FREE(attrs, dom);

  /* Notify the requestor */
  ev_send(t, e);
}

void
netindex_hash_delete(netindex_hash *h, event *e, event_list *t)
{
  NH_LOCK(h, hp);

  EXPENSIVE_CHECK(netindex_hash_consistency_check(nh));

  hp->deleted_event = e;
  hp->deleted_target = t;

  ev_send(hp->cleanup_list, &hp->cleanup_event);
}

/*
 * Private index manipulation
 */
struct netindex *
net_find_index_fragile_chain(struct netindex_hash_private *hp, const net_addr *n)
{
  ASSERT_DIE(n->type == hp->net_type);
  u32 h = net_hash(n);
  return HASH_FIND_CHAIN(hp->hash, NETINDEX, h, n);
}

struct netindex *
net_find_index_fragile(struct netindex_hash_private *hp, const net_addr *n)
{
  ASSERT_DIE(n->type == hp->net_type);

  EXPENSIVE_CHECK(netindex_hash_consistency_check(hp));

  u32 h = net_hash(n);
  return HASH_FIND(hp->hash, NETINDEX, h, n);
}

static struct netindex *
net_find_index_locked(struct netindex_hash_private *hp, const net_addr *n)
{
  return net_lock_revive_unlock(hp, net_find_index_fragile(hp, n));
}

static struct netindex *
net_new_index_locked(struct netindex_hash_private *hp, const net_addr *n)
{
  ASSERT_DIE(!hp->deleted_event);

  u32 i = hmap_first_zero(&hp->id_map);
  hmap_set(&hp->id_map, i);

  struct netindex *ni = hp->slab ?
    sl_alloc(hp->slab) :
    mb_alloc(hp->pool, n->length + sizeof *ni);

  *ni = (struct netindex) {
    .hash = net_hash(n),
    .index = i,
  };
  net_copy(ni->addr, n);

  HASH_INSERT2(hp->hash, NETINDEX, hp->pool, ni);
  while (hp->block_size <= i)
  {
    u32 bs = hp->block_size;
    struct netindex **nb = mb_alloc(hp->pool, bs * 2 * sizeof *nb);
    memcpy(nb, hp->block, bs * sizeof *nb);
    memset(&nb[bs], 0, bs * sizeof *nb);

    mb_free(hp->block);
    hp->block = nb;

    hp->block_size *= 2;
  }

  hp->block[i] = ni;

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
net_resolve_index(netindex_hash *h, u32 i)
{
  NH_LOCK(h, hp);

  struct netindex *ni = hp->block[i];
  return net_lock_revive_unlock(hp, ni);
}
