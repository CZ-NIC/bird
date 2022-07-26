/*
 *	BIRD -- Statistics Protocol Configuration
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o. 
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/stats/stats.h"

CF_DEFINES

#define STATS_CC ((struct stats_channel_config *) this_channel)

CF_DECLS

CF_KEYWORDS(STATS, TABLE, MAX, GENERATION, SETTLE, TIME)

%type <cc> stats_channel_start

CF_GRAMMAR

proto: stats_proto '}' { this_channel = NULL; }  ;

stats_proto_start: proto_start STATS
{
  this_proto = proto_config_new(&proto_stats, $1);
}

proto_name ;

stats_channel_opt_list:
    /* empty */
  | '{' stats_opts '}'
  ;

stats_opt:
    type symbol '=' term {
      struct f_val val;
      if (f_eval(f_linearize($4), &val) > F_RETURN) cf_error("Runtime error");
      if (val.type != $1) cf_error("The expresion does not match defined type");
      /* cf_define_symbol($2, SYM_VARIABLE | $1, val )*/
    }
  | MIN SETTLE TIME expr_us { STATS_CC->min_settle_time = $4; }
  | MAX SETTLE TIME expr_us { STATS_CC->max_settle_time = $4; }
  ;

stats_opts:
    /* empty */
  | stats_opts channel_item ';'
  | stats_opts stats_opt ';'
  ;
     
stats_proto_channel: stats_channel_start stats_channel_opt_list channel_end ;

stats_channel_start: net_type symbol
{
  this_channel = channel_config_get(&channel_stats, $2->name, $1, this_proto);
  STATS_CC->min_settle_time = 1 S_;
  STATS_CC->max_settle_time = 20 S_;
  $2 = cf_define_symbol($2, SYM_COUNTER, ch_config, this_channel);
}

stats_proto:
   stats_proto_start '{'
 | stats_proto proto_item ';'
 | stats_proto stats_proto_channel ';'
 | stats_proto  ';'
 ;

CF_CODE

CF_END
