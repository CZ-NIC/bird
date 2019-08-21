/*
 *	BIRD -- Benchmarking Dummy Protocol Configuration
 *
 *	(c) 2018 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "filter/filter.h"
#include "proto/perf/perf.h"

CF_DEFINES

#define PERF_CFG ((struct perf_config *) this_proto)

CF_DECLS

CF_KEYWORDS(PERF, EXP, FROM, TO, REPEAT, THRESHOLD, MIN, MAX, KEEP, MODE, IMPORT, EXPORT)

CF_GRAMMAR

proto: perf_proto '}' ;

perf_proto_start: proto_start PERF
{
  this_proto = proto_config_new(&proto_perf, $1);
  PERF_CFG->from = 10;
  PERF_CFG->to = 20;
  PERF_CFG->repeat = 4;
  PERF_CFG->threshold_max = 500 MS_;
  PERF_CFG->threshold_min = 1 MS_;
  PERF_CFG->attrs_per_rte = 0;
  PERF_CFG->keep = 0;
  PERF_CFG->mode = PERF_MODE_IMPORT;
};

perf_proto:
   perf_proto_start proto_name '{'
 | perf_proto perf_proto_item ';'
 | perf_proto proto_item ';'
 ;

perf_proto_item:
   proto_channel { this_proto->net_type = $1->net_type; }
 | EXP FROM NUM { PERF_CFG->from = $3; }
 | EXP TO NUM { PERF_CFG->to = $3; }
 | REPEAT NUM { PERF_CFG->repeat = $2; }
 | THRESHOLD MIN expr_us { PERF_CFG->threshold_min = $3; }
 | THRESHOLD MAX expr_us { PERF_CFG->threshold_max = $3; }
 | ATTRIBUTES NUM { PERF_CFG->attrs_per_rte = $2; }
 | KEEP bool { PERF_CFG->keep = $2; }
 | MODE IMPORT { PERF_CFG->mode = PERF_MODE_IMPORT; }
 | MODE EXPORT { PERF_CFG->mode = PERF_MODE_EXPORT; }
;


CF_CODE

CF_END
