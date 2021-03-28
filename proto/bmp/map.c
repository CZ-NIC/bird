/*
 *	BIRD -- The BGP Monitoring Protocol (BMP)
 *
 *	(c) 2020 Akamai Technologies, Inc. (Pawel Maslanka, pmaslank@akamai.com)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "proto/bmp/map.h"

/* Peer Index Table */
#define PEER_KEY(n) (n)->peer_as, (n)->peer_ip
#define PEER_NEXT(n) (n)->next
#define PEER_EQ(as1,ip1,as2,ip2) \
  (as1) == (as2) && ipa_equal(ip1, ip2)
#define PEER_FN(as,ip) ipa_hash(ip)

#define PEER_REHASH bmp_peer_rehash
#define PEER_PARAMS /8, *2, 2, 2, 6, 20

HASH_DEFINE_REHASH_FN(PEER, struct bmp_peer_map_key)

#define PEER_INIT_ORDER 6

void
bmp_peer_map_init(struct bmp_peer_map *map, pool *mpool)
{
  map->mpool = mpool;
  HASH_INIT(map->peer_hash, map->mpool, PEER_INIT_ORDER);
}

struct bmp_peer_map_key
bmp_peer_map_key_create(const ip_addr peer_ip, const u32 peer_as)
{
  struct bmp_peer_map_key key;
  key.next = NULL;
  key.peer_ip = peer_ip;
  key.peer_as = peer_as;

  return key;
}

void
bmp_peer_map_flush(struct bmp_peer_map *map)
{
  struct bmp_peer_map_entry *entry;
  HASH_WALK_DELSAFE(map->peer_hash, next, e)
  {
    entry = (struct bmp_peer_map_entry *) e;
    mb_free(entry->data.buf);
    HASH_DELETE(map->peer_hash, PEER, PEER_KEY(&entry->key));
    mb_free(entry);
  }
  HASH_WALK_DELSAFE_END;

  HASH_MAY_RESIZE_DOWN(map->peer_hash, PEER, map->mpool);
}

void
bmp_peer_map_free(struct bmp_peer_map *map)
{
  bmp_peer_map_flush(map);
  HASH_FREE(map->peer_hash);
}

void
bmp_peer_map_insert(struct bmp_peer_map *map, const struct bmp_peer_map_key key,
  const byte *data, const size_t data_size)
{
  struct bmp_peer_map_entry *entry
    = (void *) HASH_FIND(map->peer_hash, PEER, PEER_KEY(&key));

  if (entry)
  {
    mb_free(entry->data.buf);
    entry->data.buf = mb_alloc(map->mpool, data_size);
    memcpy(entry->data.buf, data, data_size);
    entry->data.buf_size = data_size;
    return;
  }

  entry = mb_alloc(map->mpool, sizeof (struct bmp_peer_map_entry));
  entry->data.buf = mb_alloc(map->mpool, data_size);
  memcpy(entry->data.buf, data, data_size);
  entry->data.buf_size = data_size;
  entry->key = key;
  HASH_INSERT2(map->peer_hash, PEER, map->mpool, &entry->key);
}

void
bmp_peer_map_remove(struct bmp_peer_map *map, const struct bmp_peer_map_key key)
{
  struct bmp_peer_map_entry *entry
    = (void *) HASH_DELETE(map->peer_hash, PEER, PEER_KEY(&key));

  if (!entry)
    return;

  mb_free(entry->data.buf);
  mb_free(entry);
}

const struct bmp_peer_map_entry *
bmp_peer_map_get(struct bmp_peer_map *map, const struct bmp_peer_map_key key)
{
  return (struct bmp_peer_map_entry *) HASH_FIND(map->peer_hash, PEER, PEER_KEY(&key));
}

void
bmp_peer_map_walk(const struct bmp_peer_map *map, bmp_peer_map_walk_action action, void *arg)
{
  struct bmp_peer_map_entry *entry;
  HASH_WALK_FILTER(map->peer_hash, next, e, _)
  {
    entry = (struct bmp_peer_map_entry *) e;
    action(entry->key, entry->data.buf, entry->data.buf_size, arg);
  }
  HASH_WALK_FILTER_END;
}
