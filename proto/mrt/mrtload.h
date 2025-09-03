/*
 *	BIRD -- Multi-Threaded Routing Toolkit (MRT) Route Loader
 *
 *	(c) 2025       Katerina Kubecova <katerina.kubecova@nic.cz>
 *	(c) 2025       CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_MRT_LOAD_H_
#define _BIRD_MRT_LOAD_H_

#include <stdio.h>

#include "nest/bird.h"
#include "nest/protocol.h"
#include "lib/lists.h"
#include "nest/route.h"
#include "proto/bgp/bgp.h"
#include "filter/filter.h"
#include "sysdep/unix/unix.h"
#include "proto/mrt/mrt.h"



extern const struct channel_class channel_mrtload;

struct mrtload_config {
  struct proto_config c;
  union {
    struct rte_class_config rte_class;
    struct { BGP_ROUTE_ATTRIBUTES };
  };

  struct rtable_config *table_cf;
  const char *table_expr;
  const char *filename; /* name of MRT file we are loading from */
  int replay_accel; /* Option for MRT_BGP4MP - do not load stored messages regularly
        but replay_accel-times quicker than each message was recorded */
  struct bgp_channel_config *channel_cf;
  const struct bgp_af_desc *desc;
};

struct mrtload_route_ctx {
  struct bgp_route_ctx ctx;
  int afi;
  struct rte_src *src;
  struct mrtload_route_ctx *next;
};

struct mrtload_peer_entry {
  /* In MRT_TABLE_DUMP_V2, all peers are listed in MRT_PEER_INDEX_TABLE message */
  struct mrtload_route_ctx *route_attrs;
  u32 peer_id;
  u32 peer_as;
  u32 afi;
  ip_addr peer_ip;
};

struct mrtload_proto {
  struct proto p;
    union {
    struct rte_class_config rte_class;
    struct { BGP_ROUTE_CONTEXT };
  };

  u32 afi;
  u64 source_cnt; /* to create new route sources */
  struct bgp_channel *channel;
  pool *ctx_pool;
  HASH(struct mrtload_route_ctx) ctx_hash;   // TODO : maybe it should be stored somewhere else

  /* Loading loop variables */
  timer *load_timer; /* Loading loops timer (simulates acceleration
        and make sure not too much of data is loaded at once)*/
  int replay_accel;
  s64 next_time; /* time of the first header after being called by timer */

  int table_peers_count; /* number of MRT_TABLE_DUMP_V2 peers */
  struct mrtload_peer_entry *table_peers; /* MRT_TABLE_DUMP_V2 peers field */
  struct rfile *parsed_file; /* MRT file we are loading from */
};


void mrtload_check_config(struct proto_config *CF, struct bgp_channel_config *CC);

#endif	/* _BIRD_MRT_LOAD_H_ */
