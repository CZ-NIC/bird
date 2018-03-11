/*
 *	BIRD -- Internet Group Management Protocol (IGMP)
 *
 *	(c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *	(c) 2018 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2018 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/igmp/igmp.h"

CF_DEFINES

#define IGMP_CFG ((struct igmp_config *) this_proto)
#define IGMP_IFACE ((struct igmp_iface_config *) this_ipatt)

CF_DECLS

CF_KEYWORDS(IGMP, ROBUSTNESS, STARTUP, QUERY, COUNT, INTERVAL, LAST, MEMBER, RESPONSE)

CF_GRAMMAR

CF_ADDTO(proto, igmp_proto)

igmp_proto_start: proto_start IGMP
{
  this_proto = proto_config_new(&proto_igmp, $1);
  init_list(&IGMP_CFG->iface_list);
};

igmp_proto_item:
   proto_item
 | proto_channel
 | INTERFACE igmp_iface
 ;

igmp_proto_opts:
   /* empty */
 | igmp_proto_opts igmp_proto_item ';'
 ;

igmp_proto:
   igmp_proto_start proto_name '{' igmp_proto_opts '}';


igmp_iface_start:
{
  this_ipatt = cfg_allocz(sizeof(struct igmp_iface_config));
  add_tail(&IGMP_CFG->iface_list, NODE this_ipatt);
  init_list(&IGMP_IFACE->i.ipn_list);

  IGMP_IFACE->robustness = IGMP_DEFAULT_ROBUSTNESS;
  IGMP_IFACE->query_int = IGMP_DEFAULT_QUERY_INT;
  IGMP_IFACE->query_response_int = IGMP_DEFAULT_RESPONSE_INT;
  IGMP_IFACE->last_member_query_int = IGMP_DEFAULT_LAST_MEMBER_INT;
};

igmp_iface_item:
   ROBUSTNESS expr { IGMP_IFACE->robustness = $2; }
 | QUERY INTERVAL expr_us { IGMP_IFACE->query_int = $3; }
 | STARTUP QUERY COUNT expr { IGMP_IFACE->startup_query_cnt = $4; }
 | STARTUP QUERY INTERVAL expr_us { IGMP_IFACE->startup_query_int = $4; }
 | QUERY RESPONSE INTERVAL expr_us { IGMP_IFACE->query_response_int = $4; }
 | LAST MEMBER QUERY COUNT expr { IGMP_IFACE->last_member_query_cnt = $5; }
 | LAST MEMBER QUERY INTERVAL expr_us { IGMP_IFACE->last_member_query_int = $5; }
 ;

igmp_iface_opts:
   /* empty */
 | igmp_iface_opts igmp_iface_item ';'
 ;

igmp_iface_opt_list:
   /* empty */
 | '{' igmp_iface_opts '}'
 ;

igmp_iface:
  igmp_iface_start iface_patt_list_nopx igmp_iface_opt_list { igmp_finish_iface_config(IGMP_IFACE); }

CF_CODE

CF_END
