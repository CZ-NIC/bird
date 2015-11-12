#ifndef _BIRD_BGP_MRT_H_
#define _BIRD_BGP_MRT_H_

#include "nest/route.h"
#include "nest/mrtdump.h"
#include "bgp.h"

void bgp_mrt_table_dump_step(struct mrt_table_dump_ctx *state);
void bgp_mrt_peer_index_table_dump(struct mrt_table_dump_ctx *state);

#endif /* _BIRD_BGP_MRT_H_ */
