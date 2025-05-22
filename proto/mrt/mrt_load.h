#ifndef _BIRD_MRT_LOAD_H_
#define _BIRD_MRT_LOAD_H_

#include "nest/bird.h"
#include "nest/protocol.h"
#include "lib/lists.h"
#include "nest/route.h"
#include "proto/bgp/bgp.h"
#include "filter/filter.h"
#include "proto/mrt/mrt.h"

extern const struct channel_class channel_mrtload;

struct mrtload_config {
  struct proto_config c;

  struct rtable_config *table_cf;
  const char *table_expr;
  const struct filter *filter;
  const char *filename;
  int always_add_path;
  struct bgp_channel_config *channel_cf;
  const struct bgp_af_desc *desc;
};

struct mrtload_proto {
  struct proto p;

  struct mrt_table_dump_state *table_dump;
  struct bgp_channel *channel;
};


void mrtload_check_config(struct proto_config *CF, struct bgp_channel_config *CC);

#endif	/* _BIRD_MRT_LOAD_H_ */
