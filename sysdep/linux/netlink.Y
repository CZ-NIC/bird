/*
 *	BIRD -- Linux Netlink Configuration
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

CF_DECLS

CF_KEYWORDS(KERNEL, TABLE, METRIC, NETLINK, RX, BUFFER,
	    KRT_PREFSRC, KRT_REALM, KRT_SCOPE, KRT_MTU, KRT_WINDOW,
	    KRT_RTT, KRT_RTTVAR, KRT_SSTRESH, KRT_CWND, KRT_ADVMSS, KRT_REORDERING,
	    KRT_HOPLIMIT, KRT_INITCWND, KRT_RTO_MIN, KRT_INITRWND, KRT_QUICKACK,
	    KRT_LOCK_MTU, KRT_LOCK_WINDOW, KRT_LOCK_RTT, KRT_LOCK_RTTVAR,
	    KRT_LOCK_SSTRESH, KRT_LOCK_CWND, KRT_LOCK_ADVMSS, KRT_LOCK_REORDERING,
	    KRT_LOCK_HOPLIMIT, KRT_LOCK_RTO_MIN, KRT_FEATURE_ECN, KRT_FEATURE_ALLFRAG)

CF_GRAMMAR

kern_proto: kern_proto kern_sys_item ';' ;

kern_sys_item:
   KERNEL TABLE expr { THIS_KRT->sys.table_id = $3; }
 | METRIC expr { THIS_KRT->sys.metric = $2; }
 | NETLINK RX BUFFER expr { THIS_KRT->sys.netlink_rx_buffer = $4; }
 ;

/* Bits of EA_KRT_LOCK, based on RTAX_* constants */

attr_bit: KRT_LOCK_MTU	{ $$ = f_new_dynamic_attr_bit(2, "krt_lock"); } ;
attr_bit: KRT_LOCK_WINDOW	{ $$ = f_new_dynamic_attr_bit(3, "krt_lock"); } ;
attr_bit: KRT_LOCK_RTT	{ $$ = f_new_dynamic_attr_bit(4, "krt_lock"); } ;
attr_bit: KRT_LOCK_RTTVAR	{ $$ = f_new_dynamic_attr_bit(5, "krt_lock"); } ;
attr_bit: KRT_LOCK_SSTRESH	{ $$ = f_new_dynamic_attr_bit(6, "krt_lock"); } ;
attr_bit: KRT_LOCK_CWND	{ $$ = f_new_dynamic_attr_bit(7, "krt_lock"); } ;
attr_bit: KRT_LOCK_ADVMSS	{ $$ = f_new_dynamic_attr_bit(8, "krt_lock"); } ;
attr_bit: KRT_LOCK_REORDERING { $$ = f_new_dynamic_attr_bit(9, "krt_lock"); } ;
attr_bit: KRT_LOCK_HOPLIMIT { $$ = f_new_dynamic_attr_bit(10, "krt_lock"); } ;
attr_bit: KRT_LOCK_RTO_MIN { $$ = f_new_dynamic_attr_bit(13, "krt_lock"); } ;

/* Bits of EA_KRT_FEATURES */
attr_bit: KRT_FEATURE_ECN	{ $$ = f_new_dynamic_attr_bit(0, "krt_features"); } ;
attr_bit: KRT_FEATURE_ALLFRAG { $$ = f_new_dynamic_attr_bit(3, "krt_features"); } ;


CF_CODE

CF_END
