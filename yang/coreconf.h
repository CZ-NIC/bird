/*
 *	BIRD -- CORECONF
 *
 *	(c) 2026       Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *	(c) 2026       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_YANG_CORECONF_H_
#define _BIRD_YANG_CORECONF_H_

#include "lib/coap.h"
#include "yang/yang.h"

struct resource_info {
   enum resource_type type;
   enum coap_msg_code method;
   enum coap_content_format request_format;
   enum coap_content_format response_format;
};

extern struct resource_info content_format_by_resource[];

/* Handler functions */
bool coreconf_datastore(struct yang_session *se);
bool coreconf_yang_library(struct yang_session *se);
bool coreconf_event_stream(struct yang_session *se);
bool coreconf_rpc_action(struct yang_session *se);

#endif
