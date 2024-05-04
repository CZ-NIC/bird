/*
 *	BIRD -- Yanet Protocol Configuration
 *
 *	(c) 2021 Andrey V. Elsukov <butcher@yandex-team.ru>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/export/export.h"

CF_DEFINES

#define EXPORT_CFG ((struct export_config *) this_proto)

CF_DECLS

CF_KEYWORDS(EXPORT, SOCKET, TABLE)

CF_GRAMMAR

proto: proto_export '}' { }  ;

proto_export_start: proto_start EXPORT
{
  this_proto = proto_config_new(&proto_export, $1);
}
proto_name

export_channel: TABLE rtable
{
  struct channel_config *cc = channel_config_new(NULL, NULL, 0, this_proto);
  cc->in_filter = FILTER_ACCEPT;
  cc->out_filter = FILTER_ACCEPT;
  cc->table = $2;
}

export_socket: SOCKET text
{
  EXPORT_CFG->socket = $2;
}

proto_export:
   proto_export_start '{'
 | proto_export proto_item ';'
 | proto_export export_channel ';'
 | proto_export export_socket ';'
 ;

CF_CODE

CF_END
