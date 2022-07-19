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
#define STATS_CC ((struct stats_channel_config *) this_channel)

CF_DECLS

/* TODO here add more keywords */
CF_KEYWORDS(STATS, TABLE, MAX, GENERATION)

%type <cc> stats_channel_start

CF_GRAMMAR

proto: stats_proto '}' { this_channel = NULL; }  ;

stats_proto_start: proto_start STATS
{
  this_proto = proto_config_new(&proto_stats, $1);
}

proto_name ;

stats_channel_opt_list:
    /* empty */
  | '{' stats_opts '}'
  ;


channel_max_gen:
  MAX GENERATION expr {
    if ($3 > 254) cf_error("Max generation must be in range 0..254, got %u", $3);
    STATS_CC->max_generation = $3;
  }
  ;

stats_opts:
    /* empty */
  | stats_opts channel_item ';'
  | stats_opts channel_max_gen ';'
  ;
     
stats_proto_channel: stats_channel_start stats_channel_opt_list channel_end ;
/* stats_proto_channel: stats_channel_start stats_max_gen channel_opt_list channel_end ; */

stats_channel_start: net_type symbol
{
  this_channel = channel_config_get(&channel_stats, $2->name, $1, this_proto);
  STATS_CC->max_generation = 16;
}

stats_proto:
   stats_proto_start '{'
 | stats_proto proto_item ';'
 | stats_proto stats_proto_channel ';'
 | stats_proto  ';'
 ;

CF_CODE

CF_END
