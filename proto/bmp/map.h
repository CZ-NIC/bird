/*
 *	BIRD -- The BGP Monitoring Protocol (BMP)
 *
 *	(c) 2020 Akamai Technologies, Inc. (Pawel Maslanka, pmaslank@akamai.com)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * This map implementation binds peer IP address as container key with custom data.
 */
#ifndef _BIRD_BMP_MAP_H_
#define _BIRD_BMP_MAP_H_

#include "nest/bird.h"
#include "lib/hash.h"
#include "lib/resource.h"

struct bmp_peer_map_key {
  struct bmp_peer_map_key *next;
  ip_addr peer_ip;
  u32 peer_as;
};

struct bmp_peer_map_data {
  void *buf;
  size_t buf_size;
};

struct bmp_peer_map_entry {
  struct bmp_peer_map_key key;
  struct bmp_peer_map_data data;
};

struct bmp_peer_map {
  pool *mpool;                             // Memory pool for peer entries in peer_hash
  HASH(struct bmp_peer_map_key) peer_hash; // Hash for peers to find the index
};

void
bmp_peer_map_init(struct bmp_peer_map *map, pool *mpool);

struct bmp_peer_map_key
bmp_peer_map_key_create(const ip_addr peer_ip, const u32 peer_as);

void
bmp_peer_map_free(struct bmp_peer_map *map);

void
bmp_peer_map_flush(struct bmp_peer_map *map);

void
bmp_peer_map_insert(struct bmp_peer_map *map, const struct bmp_peer_map_key key,
  const byte *data, const size_t data_size);

void
bmp_peer_map_remove(struct bmp_peer_map *map, const struct bmp_peer_map_key key);

const struct bmp_peer_map_entry *
bmp_peer_map_get(struct bmp_peer_map *map, const struct bmp_peer_map_key key);

typedef void (*bmp_peer_map_walk_action)(const struct bmp_peer_map_key key,
					 const byte *data, const size_t data_size, void *arg);

void
bmp_peer_map_walk(const struct bmp_peer_map *map, bmp_peer_map_walk_action action, void *arg);

#endif /* _BIRD_BMP_MAP_H_ */
