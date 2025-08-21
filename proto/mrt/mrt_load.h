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
#include "proto/mrt/mrt.h"

#define MRTLOAD_CTX_KEY(n)		n->ctx.remote_as, n->ctx.local_as, \
  n->ctx.remote_ip, n->ctx.local_ip
#define MRTLOAD_CTX_NEXT(n)		n->next
#define MRTLOAD_CTX_EQ(p1, n1, r_ip, l_ip, p2, n2, r_ip1, l_ip1)	ipa_equal(l_ip, l_ip1) && ipa_equal(r_ip, r_ip1) && n1 == n2 && p1 == p2
#define MRTLOAD_CTX_FN(pas, las, r_ip, l_ip)	 u64_hash(pas) + u64_hash(las) + ipa_hash(r_ip) + ipa_hash(l_ip)
#define MRTLOAD_CTX_REHASH		mrtload_ctx_rehash
#define MRTLOAD_CTX_PARAMS		/2, *2, 1, 1, 8, 20
#define MRTLOAD_CTX_INIT_ORDER		6


extern const struct channel_class channel_mrtload;

struct mrtload_config {
  struct proto_config c;
  union {
    struct rte_class_config rte_class;
    struct { BGP_ROUTE_ATTRIBUTES };
  };

  struct rtable_config *table_cf;
  const char *table_expr;
  const struct filter *filter;
  const char *filename;
  int always_add_path;
  int time_replay;
  struct bgp_channel_config *channel_cf;
  const struct bgp_af_desc *desc;
};

struct mrtload_route_ctx {
  struct bgp_route_ctx ctx;
  int addr_fam;
  struct rte_src *src;
  struct mrtload_route_ctx *next;
};

struct mrtload_peer_entry {
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

  u32 addr_fam;
  u64 source_cnt;
  struct mrt_table_dump_state *table_dump;
  struct bgp_channel *channel;
  pool *ctx_pool;
  HASH(struct mrtload_route_ctx) ctx_hash;   // TODO : maybe it should be stored somewhere else
  timer *load_timer;
  int time_replay;
  btime start_time;
  s64 zero_time;
  s64 next_time;
  int table_peers_count;
  struct mrtload_peer_entry *table_peers;
  FILE *parsed_file;
};


void mrtload_check_config(struct proto_config *CF, struct bgp_channel_config *CC);

#endif	/* _BIRD_MRT_LOAD_H_ */
