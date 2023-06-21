/*
 *	BIRD -- Table-to-Table Protocol Configuration
 *
 *	(c) 1999 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/pipe/pipe.h"
#include "nest/route.h"

CF_DEFINES

#define PIPE_CFG ((struct pipe_config *) this_proto)

CF_DECLS

CF_KEYWORDS(PIPE, PEER, TABLE, AGGREGATED, IMPORT, EXPORT, AGGREGATE)

CF_GRAMMAR

proto: pipe_proto '}' { this_channel = NULL; }  ;

pipe_proto_start: proto_start PIPE
{
  this_proto = proto_config_new(&proto_pipe, $1);
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

pipe_proto:
   pipe_proto_start '{'
 | pipe_proto proto_item ';'
 | pipe_proto channel_item_ ';'
 | pipe_proto PEER TABLE rtable ';' { PIPE_CFG->peer = $4; }
 | pipe_proto MERGE PATHS IMPORT bool kern_mp_limit { PIPE_CFG->config_import.limit = $5 ? $6 : 0; PIPE_CFG->config_import.use_aggregator = 0; }
 | pipe_proto MERGE PATHS EXPORT bool kern_mp_limit { PIPE_CFG->config_export.limit = $5 ? $6 : 0; PIPE_CFG->config_export.use_aggregator = 0; }
 ;

CF_CODE

CF_END
