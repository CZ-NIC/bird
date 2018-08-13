/*
 *	BIRD -- Table-to-Table Protocol Configuration
 *
 *	(c) 1999 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/pipe/pipe.h"

CF_DEFINES

#define PIPE_CFG ((struct pipe_config *) ctx->this_proto)

CF_DECLS

CF_KEYWORDS(PIPE, PEER, TABLE)

CF_GRAMMAR

proto: pipe_proto '}' { ctx->this_channel = NULL; }  ;

pipe_proto_start: proto_start PIPE
{
  ctx->this_proto = proto_config_new(ctx, &proto_pipe, $1);
}
proto_name
{
  ctx->this_channel = proto_cf_main_channel(ctx->this_proto);
  if (!ctx->this_channel) {
    ctx->this_channel = channel_config_new(ctx, NULL, NULL, 0, ctx->this_proto);
    ctx->this_channel->in_filter = FILTER_ACCEPT;
    ctx->this_channel->out_filter = FILTER_ACCEPT;
  }
};

pipe_proto:
   pipe_proto_start '{'
 | pipe_proto proto_item ';'
 | pipe_proto channel_item ';'
 | pipe_proto PEER TABLE rtable ';' { PIPE_CFG->peer = $4; }
 ;

CF_CODE

CF_END
