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

#define RTC_TYPE_AS2 0x0002
#define RTC_TYPE_IP4 0x0102
#define RTC_TYPE_AS4 0x0202

/*
 * RT constraint has three fields: type, ASN/IPv4 and value.
 *
 *   +--------+------------+---------+
 *   |  type  |  ASN/IPv4  |  value  |
 *   +--------+------------+---------+
 *
 * User can define RT constraint as a prefix. This enumeration describes the position
 * of boundary between prefix part of RTC and the rest of RTC (which must be all zeroes).
 * This information is important for correctly parsing RT constraints.
 *
 *   RTC_PREFIX_POSITION_IGNORE	  - no valid RTC, the position is irrelevant
 *   RTC_POSITION_TYPE_ASN_IP	  - prefix lies exactly between type field and ASN/IPv4 field
 *   RTC_POSITION_ASN_IP	  - prefix lies inside ASN/IPv4 field
 *   RTC_POSITION_ASN_IP_VALUE	  - prefix lies exactly between ASN/IPv4 field and value field
 *   RTC_POSITION_VALUE		  - prefix lies inside value field
 *   RTC_POSITION_END		  - prefix lies at the end of the RTC
 */
enum rtc_prefix_position {
  RTC_PREFIX_POSITION_IGNORE,
  RTC_PREFIX_POSITION_TYPE_ASN_IP,
  RTC_PREFIX_POSITION_ASN_IP,
  RTC_PREFIX_POSITION_ASN_IP_VALUE,
  RTC_PREFIX_POSITION_VALUE,
  RTC_PREFIX_POSITION_END,
};

int rtc_format(char *buf, int buflen, const struct net_addr_rtc *n);
struct net_addr * rtc_parse(u64 type, u32 asn, struct f_val asn_ip, u64 val, int pxlen, enum rtc_prefix_position px_pos);

#endif
