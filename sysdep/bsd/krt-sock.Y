/*
 *	BIRD -- BSD Kernel Syncer Configuration
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

CF_DECLS

CF_KEYWORDS(KERNEL, TABLE, METRIC)

CF_GRAMMAR

kern_proto: kern_proto kern_sys_item ';' ;

kern_sys_item:
   KERNEL TABLE expr {
	if ($3 && (krt_max_tables == 1))
	  cf_error("Multiple kernel routing tables not supported");
	if ($3 >= krt_max_tables)
	  cf_error("Kernel table id must be in range 0-%u", krt_max_tables - 1);

	THIS_KRT->sys.table_id = $3;
   }
 | METRIC expr {
     if ($2 && !krt_max_metric)
       cf_error("Kernel route metric not supported");
     if ($2 > krt_max_metric)
       cf_error("Kernel table id must be in range 0-%u", krt_max_metric);

     THIS_KRT->sys.metric = $2;
   }
 ;

CF_CODE

CF_END
