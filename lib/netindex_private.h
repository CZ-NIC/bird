/*
 *	BIRD Internet Routing Daemon -- Semi-global index of nets
 *
 *	(c) 2023       Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LIB_NETINDEX_PRIVATE_H_
#define _BIRD_LIB_NETINDEX_PRIVATE_H_

#include "lib/netindex.h"

#define NETINDEX_HASH_PUBLIC \
  DOMAIN(attrs) lock;		/* Assigned lock */		\
  event_list *cleanup_list;	/* Cleanup event list */	\
  event cleanup_event;		/* Cleanup event */		\
  u8 net_type;			/* Which NET_* is stored */	\

struct netindex_hash_private {
  struct { NETINDEX_HASH_PUBLIC; };
  struct netindex_hash_private **locked_at;
  pool *pool;
  slab *slab;
  HASH(struct netindex) hash;
  uint block_size;
  struct netindex **block;
  struct hmap id_map;
  event *deleted_event;
  event_list *deleted_target;
};

typedef union netindex_hash {
  struct { NETINDEX_HASH_PUBLIC; };
  struct netindex_hash_private priv;
} netindex_hash;

LOBJ_UNLOCK_CLEANUP(netindex_hash, attrs);
#define NH_LOCK(h, hp)	LOBJ_LOCK(h, hp, netindex_hash, attrs)

/* Find indices in a locked context with no usecounting */
struct netindex *net_find_index_fragile(struct netindex_hash_private *hp, const net_addr *n);

/* The same but instead of returning the exact match,
 * return the first item in hash chain */
struct netindex *net_find_index_fragile_chain(struct netindex_hash_private *hp, const net_addr *n);

#endif
