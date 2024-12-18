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

#define NETINDEX_KEY(n)		(n)->hash, (n)->addr
#define NETINDEX_NEXT(n)	(n)->next
#define NETINDEX_EQ(h,n,i,o)	((h == i) && net_equal(n,o))
#define NETINDEX_FN(h,n)	(h)
#define NETINDEX_ORDER		12 /* Initial */

#define NETINDEX_REHASH		netindex_rehash
#define NETINDEX_PARAMS		/8, *2, 2, 2, 12, 28

static void NETINDEX_REHASH(void *_v) {
  netindex_spinhash *v = _v;
  int step;
  SPINHASH_REHASH_PREPARE(v,NETINDEX,struct netindex,step);

  if (!step)	return;

  if (step > 0) SPINHASH_REHASH_UP(v,NETINDEX,struct netindex,step);
  if (step < 0) SPINHASH_REHASH_DOWN(v,NETINDEX,struct netindex,-step);

  SPINHASH_REHASH_FINISH(v,NETINDEX);
}

static void netindex_hash_cleanup(void *netindex_hash);

static struct netindex *
net_lock_revive_unlock(netindex_hash *h, struct netindex *i)
{
  if (!i)
    return NULL;

  lfuc_lock_revive(&i->uc);
  lfuc_unlock(&i->uc, h->cleanup_list, &h->cleanup_event);
  return i;
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

  nh->slab = net_addr_length[type] ? sl_new(nh->pool, cleanup_target, sizeof (struct netindex) + net_addr_length[type]) : NULL;

  SPINHASH_INIT(nh->hash, NETINDEX, nh->pool, cleanup_target);
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

static uint
netindex_hash_cleanup_removed(struct netindex_hash_private *nh, struct netindex * _Atomic *block, struct netindex **removed, uint cnt)
{
  synchronize_rcu();

  uint kept = 0;
  for (uint q = 0; q < cnt; q++)
  {
    struct netindex *ni = removed[q];

    /* Now no reader can possibly still have the old pointer,
     * unless somebody found it inbetween and ref'd it. */
    if (!lfuc_finished(&ni->uc))
    {
      /* Collision, return the netindex back. */
      ASSERT_DIE(NULL == atomic_exchange_explicit(&block[ni->index], ni, memory_order_acq_rel));
      SPINHASH_INSERT(nh->hash, NETINDEX, ni);
      kept++;
      continue;
    }

    /* Now the netindex is definitely obsolete, we can free it */
    hmap_clear(&nh->id_map, ni->index);

    if (nh->slab)
      sl_free(ni);
    else
      mb_free(ni);
  }

  return kept;
}

static void
netindex_hash_cleanup(void *_nh)
{
  struct netindex_hash_private *nh = _nh;

  DOMAIN(attrs) dom = nh->lock;
  LOCK_DOMAIN(attrs, dom);

  uint kept = 0;

  uint bs = atomic_load_explicit(&nh->block_size, memory_order_relaxed);
  struct netindex * _Atomic *block = atomic_load_explicit(&nh->block, memory_order_relaxed);

#define REMOVED_MAX 256
  struct netindex *removed[REMOVED_MAX];
  uint removed_cnt = 0;

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

    /* Looks finished, try dropping */
    ASSERT_DIE(ni == atomic_exchange_explicit(&block[i], NULL, memory_order_acq_rel));
    SPINHASH_REMOVE(nh->hash, NETINDEX, ni);

    /* Store into the removed-block */
    removed[removed_cnt++] = ni;

    /* If removed-block is full, flush it */
    if (removed_cnt == REMOVED_MAX)
    {
      kept += netindex_hash_cleanup_removed(nh, block, removed, removed_cnt);
      removed_cnt = 0;
    }
  }

  /* Flush remaining netindexes */
  if (removed_cnt)
    kept += netindex_hash_cleanup_removed(nh, block, removed, removed_cnt);

  /* Return now unless we're deleted */
  if (kept || !nh->deleted_event)
  {
    UNLOCK_DOMAIN(attrs, dom);
    return;
  }

  ev_postpone(&nh->cleanup_event);

  event *e = nh->deleted_event;
  event_list *t = nh->deleted_target;

  /* Check cleanliness */
  SPINHASH_WALK(nh->hash, NETINDEX, i)
    bug("Stray netindex in deleted hash");
  SPINHASH_WALK_END;

  /* Cleanup the spinhash itself */
  SPINHASH_FREE(nh->hash);

  /* Pool free is enough to drop everything else */
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

  hp->deleted_event = e;
  hp->deleted_target = t;

  ev_send(hp->cleanup_list, &hp->cleanup_event);
}

/*
 * Private index manipulation
 */
static struct netindex *
net_find_index_fragile(netindex_hash *nh, const net_addr *n)
{
  ASSERT_DIE(n->type == nh->net_type);

  u32 h = net_hash(n);
  return SPINHASH_FIND(nh->hash, NETINDEX, h, n);
}

static bool
net_validate_index(netindex_hash *h, struct netindex *ni)
{
  struct netindex * _Atomic *block = atomic_load_explicit(&h->block, memory_order_relaxed);
  u32 bs = atomic_load_explicit(&h->block_size, memory_order_relaxed);

  ASSERT_DIE(ni->index < bs);
  struct netindex *bni = atomic_load_explicit(&block[ni->index], memory_order_acquire);
  return (bni == ni);
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

  SPINHASH_INSERT(hp->hash, NETINDEX, ni);

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

  return ni;
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
  RCU_ANCHOR(u);
  struct netindex *ni = net_find_index_fragile(h, n);
  return (ni && net_validate_index(h, ni)) ? net_lock_revive_unlock(h, ni) : NULL;
}

struct netindex *
net_get_index(netindex_hash *h, const net_addr *n)
{
  struct netindex *ni = net_find_index(h, n);
  if (ni) return ni;

  NH_LOCK(h, hp);

  /* Somebody may have added one inbetween */
  return net_lock_revive_unlock(h,
      (net_find_index_fragile(h, n) ?:
       net_new_index_locked(hp, n)));
}

struct netindex net_index_out_of_range;

struct netindex *
net_resolve_index(netindex_hash *h, u32 i)
{
  RCU_ANCHOR(u);

  struct netindex * _Atomic *block = atomic_load_explicit(&h->block, memory_order_relaxed);
  u32 bs = atomic_load_explicit(&h->block_size, memory_order_relaxed);

  if (i >= bs)
    return &net_index_out_of_range;

  struct netindex *ni = atomic_load_explicit(&block[i], memory_order_acquire);
  if (ni == NULL)
    return NULL;

  return net_lock_revive_unlock(h, ni);
}
