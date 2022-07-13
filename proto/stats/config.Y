/*
 *	BIRD -- Table-to-Table Protocol Configuration
 *
 *	(c) 1999 Martin Mares <mj@ucw.cz>
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
/* old: CF_KEYWORDS(PIPE, PEER, TABLE, MAX, GENERATION) */
CF_KEYWORDS(STATS, PEER, TABLE, MAX, GENERATION)

CF_GRAMMAR

proto: stats_proto '}' { this_channel = NULL; }  ;

stats_proto_start: proto_start STATS
{
  this_proto = proto_config_new(&proto_stats, $1);
  STATS_CFG->max_generation = 16;
}
proto_name
{
  this_channel = proto_cf_main_channel(this_proto);
  if (!this_channel) {
    this_channel = channel_config_new(NULL, NULL, 0, this_proto);
    this_channel->in_filter = FILTER_ACCEPT;
    this_channel->out_filter = FILTER_ACCEPT;
  }
};

stats_proto:
   stats_proto_start '{'
 | stats_proto proto_item ';'
 | stats_proto channel_item_ ';'
 | stats_proto IMPORT IN net_any imexport ';' {
    if (this_channel->net_type && ($4->type != this_channel->net_type))
      cf_error("Incompatible export prefilter type");
    STATS_CFG->in_subprefix = $4;
    this_channel->in_filter = $5;
  }
 | stats_proto PEER TABLE rtable ';' { STATS_CFG->peer = $4; }
 | stats_proto MAX GENERATION expr ';' {
    if (($4 < 1) || ($4 > 254)) cf_error("Max generation must be in range 1..254, got %u", $4);
    STATS_CFG->max_generation = $4;
  }
 ;

CF_CODE

CF_END
