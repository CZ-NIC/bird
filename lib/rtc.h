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

#include "filter/filter.h"

int rtc_format(char *buf, int buflen, const struct net_addr_rtc *n);
struct net_addr * rtc_parse(const char *type_str, u32 asn, struct f_val asn_ip, u32 val, int pxlen);

#endif
