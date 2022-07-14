/*
 *	BIRD -- Statistics Protocol Configuration
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o. 
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

/* old: #include "proto/pipe/pipe.h" */
#include "proto/stats/stats.h"

CF_DEFINES

/* old: #define PIPE_CFG ((struct pipe_config *) this_proto) */
#define STATS_CFG ((struct stats_config *) this_proto) 

CF_DECLS

/* TODO here add more keywords */
CF_KEYWORDS(STATS, TABLE, MAX, GENERATION)

%type <cc> stats_channel_start

CF_GRAMMAR

proto: stats_proto '}' { this_channel = NULL; }  ;

stats_proto_start: proto_start STATS
{
  this_proto = proto_config_new(&proto_stats, $1);
  STATS_CFG->max_generation = 16;
}

proto_name ;

stats_proto_channel: stats_channel_start channel_opt_list channel_end ;

stats_channel_start: net_type symbol
{
  $$ = this_channel = channel_config_get(NULL, $2->name, $1, this_proto);
}

stats_proto:
   stats_proto_start '{'
 | stats_proto proto_item ';'
 | stats_proto stats_proto_channel ';'
 | stats_proto  ';'
 ;

CF_CODE

CF_END
