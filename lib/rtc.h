/*
 *	BIRD Internet Routing Daemon -- RT Constraint Net Type
 *
 *	(c) 2026 Igor Putovny <igor.putovny@nic.cz>
 *	(c) 2026 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_RTC_NET_H_
#define _BIRD_RTC_NET_H_

int rtc_format(char *buf, int buflen, const struct net_addr_rtc *n);

#endif
