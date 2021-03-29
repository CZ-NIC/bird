/*
 *	BIRD -- The BGP Monitoring Protocol (BMP)
 *
 *	(c) 2020 Akamai Technologies, Inc. (Pawel Maslanka, pmaslank@akamai.com)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "proto/bmp/map.h"
#include "proto/bmp/utils.h"

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

enum bmp_result
bmp_peer_map_init(struct bmp_peer_map *map, pool *mpool)
{
  if (IS_NULL(map) || IS_NULL(mpool))
  {
    return BMP_E_NULL_REF;
  }

  map->mpool = mpool;
  HASH_INIT(map->peer_hash, map->mpool, PEER_INIT_ORDER);

  return BMP_E_NONE;
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

enum bmp_result
bmp_peer_map_flush(struct bmp_peer_map *map)
{
  if (IS_NULL(map))
  {
    return BMP_E_NULL_REF;
  }

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
  return BMP_E_NONE;
}

enum bmp_result
bmp_peer_map_free(struct bmp_peer_map *map)
{
  if (IS_NULL(map))
  {
    return BMP_E_NULL_REF;
  }

  IF_BMP_FAILED_RETURN_RC(bmp_peer_map_flush(map));
  HASH_FREE(map->peer_hash);

  return BMP_E_NONE;
}

enum bmp_result
bmp_peer_map_insert(struct bmp_peer_map *map, const struct bmp_peer_map_key key,
  const byte *data, const size_t data_size)
{
  if (IS_NULL(map))
  {
    return BMP_E_NULL_REF;
  }

  if (HASH_FIND(map->peer_hash, PEER, PEER_KEY(&key)))
  {
    return BMP_E_EXISTS;
  }

  struct bmp_peer_map_entry *entry = mb_alloc(map->mpool,
                                  sizeof (struct bmp_peer_map_entry));
  entry->data.buf = mb_alloc(map->mpool, data_size);
  memcpy(entry->data.buf, data, data_size);
  entry->data.buf_size = data_size;
  entry->key = key;
  HASH_INSERT2(map->peer_hash, PEER, map->mpool, &entry->key);

  return BMP_E_NONE;
}

enum bmp_result
bmp_peer_map_remove(struct bmp_peer_map *map, const struct bmp_peer_map_key key)
{
  if (IS_NULL(map))
  {
    return BMP_E_NULL_REF;
  }

  struct bmp_peer_map_entry *entry
    = (struct bmp_peer_map_entry *) HASH_FIND(map->peer_hash, PEER, PEER_KEY(&key));
  if (IS_NULL(entry))
  {
    return BMP_E_NOT_EXISTS;
  }

  mb_free(entry->data.buf);
  HASH_DELETE(map->peer_hash, PEER, PEER_KEY(&entry->key));
  mb_free(entry);

  return BMP_E_NONE;
}

const struct bmp_peer_map_entry *
bmp_peer_map_get(struct bmp_peer_map *map, const struct bmp_peer_map_key key)
{
  if (IS_NULL(map))
  {
    return NULL;
  }

  return (struct bmp_peer_map_entry *) HASH_FIND(map->peer_hash, PEER, PEER_KEY(&key));
}

void
bmp_peer_map_walk(const struct bmp_peer_map *map, bmp_peer_map_walk_action action)
{
  struct bmp_peer_map_entry *entry;
  HASH_WALK_FILTER(map->peer_hash, next, e, _)
  {
    entry = (struct bmp_peer_map_entry *) e;
    action(entry->key, entry->data.buf, entry->data.buf_size);
  }
  HASH_WALK_FILTER_END;
}
