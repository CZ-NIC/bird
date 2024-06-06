/*
 *	BIRD Internet Routing Daemon -- Semi-global index of nets
 *
 *	(c) 2023       Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/birdlib.h"
#include "lib/netindex_private.h"

#define NETINDEX_INIT_BLOCK_SIZE	128
struct netindex netindex_in_progress;

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
  struct netindex * _Atomic *block = atomic_load_explicit(&nh->block, memory_order_relaxed);
  u32 block_size = atomic_load_explicit(&nh->block_size, memory_order_relaxed);
  HASH_WALK(nh->hash, next, i)
  {
    ASSERT_DIE(count < nh->hash.count);
    ASSERT_DIE(i->index < block_size);
    ASSERT_DIE(atomic_load_explicit(&block[i->index], memory_order_relaxed) == i);
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
  atomic_store_explicit(&nh->block_size, NETINDEX_INIT_BLOCK_SIZE, memory_order_release);
  atomic_store_explicit(&nh->block,
      mb_allocz(nh->pool, NETINDEX_INIT_BLOCK_SIZE * sizeof *nh->block),
      memory_order_release);

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

  uint bs = atomic_load_explicit(&nh->block_size, memory_order_relaxed);
  struct netindex * _Atomic *block = atomic_load_explicit(&nh->block, memory_order_relaxed);

  for (uint i = 0; i < bs; i++)
  {
    struct netindex *ni = atomic_load_explicit(&block[i], memory_order_acquire);
    if (!ni)
      continue;

    /* We may use the acquired netindex pointer as we are
     * the only process which deletes them */
    ASSERT_DIE(i == ni->index);

    /* Check finished */
    if (!lfuc_finished(&ni->uc))
    {
      kept++;
      continue;
    }

    /* Looks finished, try removing temporarily */
    ASSERT_DIE(ni == atomic_exchange_explicit(&block[i], &netindex_in_progress, memory_order_acq_rel));

    u32 block_epoch = nh->block_epoch;
    UNLOCK_DOMAIN(attrs, dom);
    synchronize_rcu();
    LOCK_DOMAIN(attrs, dom);
    if (block_epoch != nh->block_epoch)
    {
      /* Somebody reallocated the block inbetween, use the new one */
      block = atomic_load_explicit(&nh->block, memory_order_relaxed);
      bs = atomic_load_explicit(&nh->block_size, memory_order_relaxed);
    }

    /* Now no reader can possibly still have the old pointer,
     * unless somebody found it inbetween and ref'd it. */
    if (!lfuc_finished(&ni->uc))
    {
      /* Collision, return the netindex to the block. */
      ASSERT_DIE(&netindex_in_progress == atomic_exchange_explicit(&block[i], ni, memory_order_acq_rel));
      kept++;
      continue;
    }

    /* Now the netindex is definitely obsolete, set block to NULL */
    ASSERT_DIE(&netindex_in_progress == atomic_exchange_explicit(&block[i], NULL, memory_order_acq_rel));

    /* And free it from other structures */
    HASH_REMOVE2(nh->hash, NETINDEX, nh->pool, ni);
    hmap_clear(&nh->id_map, ni->index);

    if (nh->slab)
      sl_free(ni);
    else
      mb_free(ni);
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

  struct netindex * _Atomic *block = atomic_load_explicit(&hp->block, memory_order_relaxed);
  u32 bs = atomic_load_explicit(&hp->block_size, memory_order_relaxed);
  u32 nbs = bs;
  while (nbs <= i)
    nbs *= 2;

  if (nbs > bs)
  {
    struct netindex * _Atomic *nb = mb_alloc(hp->pool, bs * 2 * sizeof *nb);
    memcpy(nb, block, bs * sizeof *nb);
    memset(&nb[bs], 0, (nbs - bs) * sizeof *nb);

    ASSERT_DIE(block == atomic_exchange_explicit(&hp->block, nb, memory_order_acq_rel));
    ASSERT_DIE(bs == atomic_exchange_explicit(&hp->block_size, nbs, memory_order_acq_rel));
    synchronize_rcu();

    mb_free(block);
    block = nb;

    hp->block_epoch++;
  }

  ASSERT_DIE(i < nbs);
  atomic_store_explicit(&block[i], ni, memory_order_release);

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
  struct netindex *ni = net_find_index_fragile(hp, n);
  return (ni == &netindex_in_progress) ? NULL : net_lock_revive_unlock(hp, ni);
}

struct netindex *
net_get_index(netindex_hash *h, const net_addr *n)
{
  while (1)
  {
    NH_LOCK(h, hp);
    struct netindex *ni = net_find_index_fragile(hp, n);
    if (ni == &netindex_in_progress)
      continue;

    if (ni)
      return net_lock_revive_unlock(hp, ni);
    else
      return net_new_index_locked(hp, n);
  }
}

struct netindex *
net_resolve_index(netindex_hash *h, u32 i)
{
  RCU_ANCHOR(u);

  struct netindex * _Atomic *block = atomic_load_explicit(&h->block, memory_order_relaxed);
  u32 bs = atomic_load_explicit(&h->block_size, memory_order_relaxed);

  if (i >= bs)
    return NULL;

  struct netindex *ni = atomic_load_explicit(&block[i], memory_order_acquire);
  if (ni == NULL)
    return NULL;

  if (ni == &netindex_in_progress)
    RCU_RETRY(u);

  lfuc_lock_revive(&ni->uc);
  net_unlock_index(h, ni);

  return ni;
}
