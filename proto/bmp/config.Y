/*
 *	BIRD -- The BGP Monitoring Protocol (BMP)
 *
 *	(c) 2020 Akamai Technologies, Inc. (Pawel Maslanka, pmaslank@akamai.com)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/bmp/bmp.h"

CF_DEFINES

#define BMP_CFG ((struct bmp_config *) this_proto)

CF_DECLS

CF_KEYWORDS(BMP, LOCAL, STATION, ADDRESS, IP, PORT, SYSTEM, DESCRIPTION, NAME,
	MONITORING, RIB, IN, PRE_POLICY, POST_POLICY, TX, BUFFER, LIMIT)

CF_GRAMMAR

proto: bmp_proto '}' ;

bmp_proto_start: proto_start BMP {
     this_proto = proto_config_new(&proto_bmp, $1);
     BMP_CFG->sys_descr = "Not defined";
     BMP_CFG->sys_name = "Not defined";
     BMP_CFG->tx_pending_limit = (1 << 30) / page_size;
   }
 ;

bmp_station_address:
   /* empty */
 | bmp_station_address IP ipa {
     if (ipa_zero($3))
       cf_error("Invalid BMP monitoring station IP address");
     BMP_CFG->station_ip = $3;
   }
 | bmp_station_address PORT expr {
     if (($3 < 1) || ($3 > 65535))
       cf_error("Invalid BMP monitoring station port number");
     BMP_CFG->station_port = $3;
   }
 ;

bmp_proto:
   bmp_proto_start proto_name '{'
 | bmp_proto proto_item ';'
 | bmp_proto LOCAL ADDRESS ipa ';' {
     BMP_CFG->local_addr = $4;
   }
 | bmp_proto STATION ADDRESS bmp_station_address ';'
 | bmp_proto SYSTEM DESCRIPTION text ';' {
     if (!$4 || (strlen($4) == 0))
       cf_error("String is empty");
     else if (strlen($4) > 255)
       cf_error("Invalid string length");
     BMP_CFG->sys_descr = $4;
   }
 | bmp_proto SYSTEM NAME text ';' {
     if (!$4 || (strlen($4) == 0))
       cf_error("String is empty");
     else if (strlen($4) > 255)
       cf_error("Invalid string length");
     BMP_CFG->sys_name = $4;
   }
 | bmp_proto MONITORING RIB IN PRE_POLICY bool ';' {
     BMP_CFG->monitoring_rib_in_pre_policy = $6;
   }
 | bmp_proto MONITORING RIB IN POST_POLICY bool ';' {
     BMP_CFG->monitoring_rib_in_post_policy = $6;
   }
 | bmp_proto TX BUFFER LIMIT expr ';' {
     BMP_CFG->tx_pending_limit = $5 * (u64) (1 << 20) / page_size;
     if ($5 < 1) cf_error("BMP TX buffer limit must be at least 1 megabyte");
   }
 ;

CF_CODE

CF_END
