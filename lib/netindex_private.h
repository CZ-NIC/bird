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

typedef SPINHASH(struct netindex) netindex_spinhash;

#define NETINDEX_HASH_PUBLIC \
  DOMAIN(attrs) lock;		/* Assigned lock */		\
  event_list *cleanup_list;	/* Cleanup event list */	\
  event cleanup_event;		/* Cleanup event */		\
  u8 net_type;			/* Which NET_* is stored */	\
  uint _Atomic block_size;	/* How big block is */		\
  struct netindex * _Atomic * _Atomic block;	/* u32 to netindex */		\
  netindex_spinhash hash;	/* Spinlocking hashtable */	\

struct netindex_hash_private {
  struct { NETINDEX_HASH_PUBLIC; };
  struct netindex_hash_private **locked_at;
  pool *pool;
  slab *slab;
  struct hmap id_map;
  u32 block_epoch;
  event *deleted_event;
  event_list *deleted_target;
};

typedef union netindex_hash {
  struct { NETINDEX_HASH_PUBLIC; };
  struct netindex_hash_private priv;
} netindex_hash;

extern struct netindex netindex_in_progress;

LOBJ_UNLOCK_CLEANUP(netindex_hash, attrs);
#define NH_LOCK(h, hp)	LOBJ_LOCK(h, hp, netindex_hash, attrs)

#endif
