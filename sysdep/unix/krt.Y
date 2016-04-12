/*
 *	BIRD -- UNIX Kernel Syncer Configuration
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "sysdep/unix/krt.h"

CF_DEFINES

#define THIS_KRT ((struct krt_config *) this_proto)
#define THIS_KIF ((struct kif_config *) this_proto)

static void
krt_set_merge_paths(struct channel_config *cc, uint merge, uint limit)
{
  if ((limit <= 0) || (limit > 255))
    cf_error("Merge paths limit must be in range 1-255");

  cc->ra_mode = merge ? RA_MERGED : RA_OPTIMAL;
  cc->merge_limit = limit;
}

CF_DECLS

CF_KEYWORDS(KERNEL, PERSIST, SCAN, TIME, LEARN, DEVICE, ROUTES, GRACEFUL, RESTART, KRT_SOURCE, KRT_METRIC, MERGE, PATHS)

CF_GRAMMAR

/* Kernel syncer protocol */

CF_ADDTO(proto, kern_proto '}')

kern_proto_start: proto_start KERNEL {
     this_proto = krt_init_config($1);
}
 ;

CF_ADDTO(kern_proto, kern_proto_start proto_name '{')
CF_ADDTO(kern_proto, kern_proto kern_item ';')

kern_item:
   proto_item
 | proto_channel { this_proto->net_type = $1->net_type; }
 | PERSIST bool { THIS_KRT->persist = $2; }
 | SCAN TIME expr {
      /* Scan time of 0 means scan on startup only */
      THIS_KRT->scan_time = $3;
   }
 | LEARN bool {
      THIS_KRT->learn = $2;
#ifndef KRT_ALLOW_LEARN
      if ($2)
	cf_error("Learning of kernel routes not supported in this configuration");
#endif
   }
 | DEVICE ROUTES bool { THIS_KRT->devroutes = $3; }
 | GRACEFUL RESTART bool { THIS_KRT->graceful_restart = $3; }
 | MERGE PATHS bool { krt_set_merge_paths(this_channel, $3, KRT_DEFAULT_ECMP_LIMIT); }
 | MERGE PATHS bool LIMIT expr { krt_set_merge_paths(this_channel, $3, $5); }
 ;

/* Kernel interface protocol */

CF_ADDTO(proto, kif_proto '}')

kif_proto_start: proto_start DEVICE { this_proto = kif_init_config($1); }
 ;

CF_ADDTO(kif_proto, kif_proto_start proto_name '{')
CF_ADDTO(kif_proto, kif_proto kif_item ';')

kif_item:
   proto_item
 | SCAN TIME expr {
      /* Scan time of 0 means scan on startup only */
      THIS_KIF->scan_time = $3;
   }
 | PRIMARY opttext net_or_ipa {
     struct kif_primary_item *kpi = cfg_alloc(sizeof (struct kif_primary_item));
     kpi->addr = $3;
     add_tail(&THIS_KIF->primary, &kpi->n);
   }
 ;

CF_ADDTO(dynamic_attr, KRT_SOURCE { $$ = f_new_dynamic_attr(EAF_TYPE_INT | EAF_TEMP, T_INT, EA_KRT_SOURCE); })
CF_ADDTO(dynamic_attr, KRT_METRIC { $$ = f_new_dynamic_attr(EAF_TYPE_INT | EAF_TEMP, T_INT, EA_KRT_METRIC); })

CF_CODE

CF_END
