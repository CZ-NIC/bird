/*
 *	BIRD -- UNIX Kernel Multicast Routing Configuration
 *
 *	(c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "sysdep/unix/mkrt.h"

CF_DEFINES

#define THIS_MKRT ((struct mkrt_config *) this_proto)

CF_DECLS

CF_KEYWORDS(MKERNEL)

CF_GRAMMAR

/* Kernel interface protocol */

CF_ADDTO(proto, mkrt_proto '}')

mkrt_proto_start: proto_start MKERNEL { this_proto = mkrt_init_config($1); }
 ;

mkrt_proto:
   mkrt_proto_start proto_name '{'
 | mkrt_proto mkrt_proto_item ';'

mkrt_proto_item:
   proto_item
 | proto_channel { this_proto->net_type = $1->net_type; }
 ;

CF_CODE

CF_END
