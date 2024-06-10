/*
 *	BIRD Internet Routing Daemon -- Semi-global index of nets
 *
 *	(c) 2023       Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LIB_NETINDEX_H_
#define _BIRD_LIB_NETINDEX_H_

#include "lib/bitmap.h"
#include "lib/hash.h"
#include "lib/lockfree.h"
#include "lib/net.h"
#include "lib/resource.h"

/* Index object */
struct netindex {
  struct netindex *next;	/* Next in hash chain */
  u32 hash;			/* Cached hash value */
  u32 index;			/* Assigned index */
  struct lfuc uc;		/* Atomic usecount */
  net_addr addr[0];		/* The net itself (one) */
};

/* Index hash: data structure completely opaque, use handlers */
typedef union netindex_hash netindex_hash;

/* Initialization and teardown */
netindex_hash *netindex_hash_new(pool *, event_list *, u8);
void netindex_hash_delete(netindex_hash *, event *, event_list *);

/* Find/get/resolve index; pointer valid until end of task */ 
struct netindex *net_find_index(netindex_hash *, const net_addr *);
struct netindex *net_get_index(netindex_hash *, const net_addr *);
struct netindex *net_resolve_index(netindex_hash *, u32);

extern struct netindex net_index_out_of_range;

/* Update use-count without allocating a handle. Take same care
 * to ensure that your locks and unlocks are always balanced. */
void net_lock_index(netindex_hash *h, struct netindex *i);
void net_unlock_index(netindex_hash *h, struct netindex *i);

/* Retrieve the index from its addr pointer */
#define NET_TO_INDEX(a) \
  SKIP_BACK(struct netindex, addr, TYPE_CAST(net_addr *, net_addr (*)[0], a))

#endif //_BIRD_LIB_NETINDEX_H_
