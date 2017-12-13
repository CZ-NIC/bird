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
#define KIF_IFACE ((struct kif_iface_config *) this_ipatt)

static void
krt_set_merge_paths(struct channel_config *cc, uint merge, uint limit)
{
  if ((limit <= 0) || (limit > 255))
    cf_error("Merge paths limit must be in range 1-255");

  cc->ra_mode = merge ? RA_MERGED : RA_OPTIMAL;
  cc->merge_limit = limit;
}

static void
kif_set_preferred(ip_addr ip)
{
  if (ipa_is_ip4(ip))
    KIF_IFACE->pref_v4 = ip;
  else if (!ipa_is_link_local(ip))
    KIF_IFACE->pref_v6 = ip;
  else
    KIF_IFACE->pref_ll = ip;
}

CF_DECLS

CF_KEYWORDS(KERNEL, PERSIST, SCAN, TIME, LEARN, DEVICE, ROUTES, GRACEFUL, RESTART, KRT_SOURCE, KRT_METRIC, MERGE, PATHS)

%type <i> kern_mp_limit

CF_GRAMMAR

/* Kernel syncer protocol */

CF_ADDTO(proto, kern_proto '}')

kern_proto_start: proto_start KERNEL {
     this_proto = krt_init_config($1);
}
 ;

CF_ADDTO(kern_proto, kern_proto_start proto_name '{')
CF_ADDTO(kern_proto, kern_proto kern_item ';')

kern_mp_limit:
   /* empty */ { $$ = KRT_DEFAULT_ECMP_LIMIT; }
 | LIMIT expr  { $$ = $2; if (($2 <= 0) || ($2 > 255)) cf_error("Merge paths limit must be in range 1-255"); }
 ;

kern_item:
   proto_item
 | proto_channel { this_proto->net_type = $1->net_type; }
 | PERSIST bool { THIS_KRT->persist = $2; }
 | SCAN TIME expr {
      /* Scan time of 0 means scan on startup only */
      THIS_KRT->scan_time = $3 S_;
   }
 | LEARN bool {
      THIS_KRT->learn = $2;
#ifndef KRT_ALLOW_LEARN
      if ($2)
	cf_error("Learning of kernel routes not supported on this platform");
#endif
   }
 | DEVICE ROUTES bool { THIS_KRT->devroutes = $3; }
 | GRACEFUL RESTART bool { THIS_KRT->graceful_restart = $3; }
 | MERGE PATHS bool kern_mp_limit {
      krt_set_merge_paths(this_channel, $3, $4);
#ifndef KRT_ALLOW_MERGE_PATHS
      if ($3)
	cf_error("Path merging not supported on this platform");
#endif
   }
 ;

/* Kernel interface protocol */

CF_ADDTO(proto, kif_proto '}')

kif_proto_start: proto_start DEVICE { this_proto = kif_init_config($1); }
 ;

CF_ADDTO(kif_proto, kif_proto_start proto_name '{')
CF_ADDTO(kif_proto, kif_proto kif_item ';')

kif_item:
   proto_item
 | INTERFACE kif_iface
 | SCAN TIME expr {
      /* Scan time of 0 means scan on startup only */
      THIS_KIF->scan_time = $3 S_;
   }
 ;

kif_iface_start:
{
  this_ipatt = cfg_allocz(sizeof(struct kif_iface_config));
  add_tail(&THIS_KIF->iface_list, NODE this_ipatt);
  init_list(&this_ipatt->ipn_list);
}

kif_iface_item:
   PREFERRED ipa { kif_set_preferred($2); }
 ;

kif_iface_opts:
   /* empty */
 | kif_iface_opts kif_iface_item ';'
 ;

kif_iface_opt_list:
   /* empty */
 | '{' kif_iface_opts '}'
 ;

kif_iface:
  kif_iface_start iface_patt_list_nopx kif_iface_opt_list;


CF_ADDTO(dynamic_attr, KRT_SOURCE { $$ = f_new_dynamic_attr(EAF_TYPE_INT | EAF_TEMP, T_INT, EA_KRT_SOURCE); })
CF_ADDTO(dynamic_attr, KRT_METRIC { $$ = f_new_dynamic_attr(EAF_TYPE_INT | EAF_TEMP, T_INT, EA_KRT_METRIC); })

CF_CODE

CF_END
