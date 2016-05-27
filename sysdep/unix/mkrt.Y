/*
 *	BIRD -- UNIX Multicast route syncer configuration
 *
 *	(c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "sysdep/unix/mkrt.h"

CF_DEFINES

CF_DECLS

CF_KEYWORDS(MKERNEL)

CF_GRAMMAR

/* Kernel interface protocol */

CF_ADDTO(proto, mkrt_proto '}' { mkrt_config_finish(this_proto); })

mkrt_proto_start: proto_start MKERNEL { this_proto = mkrt_config_init($1); }
 ;

mkrt_proto:
   mkrt_proto_start proto_name '{'
 | mkrt_proto mkrt_proto_item ';'

mkrt_proto_item:
   proto_item
 | proto_channel
 ;

CF_CODE

CF_END
