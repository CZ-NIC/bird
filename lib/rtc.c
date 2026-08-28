/*
 *	BIRD Internet Routing Daemon -- RT Constraint Net Type
 *
 *	(c) 2026 Igor Putovny <igor.putovny@nic.cz>
 *	(c) 2026 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/rtc.h"
#include "conf/conf.h"

int
rtc_format(char *buf, int buflen, const net_addr_rtc *n)
{
  if (n->pxlen == 0 && n->asn == 0)
    return bsnprintf(buf, buflen, "* as *");

  u32 src_asn = n->asn;
  int pxlen = (int)n->pxlen;

  const u64 rt = vrt_to_u64(n->rt);
  const u32 type = rt >> 48;

  const char *type_full  = NULL;
  const char *type_short = NULL;

  /*
   *  Route target constraint can have one of three different formats:
   *
   *  0           16         32           64
   *  |     2B     |    2B    |     4B     |
   *  +------------+----------+------------+
   *  |   0x0002   |    ASN   |    value   |	    RT-AS2
   *  +------------+----------+------------+
   *
   *
   *  0           16         48           64
   *  |     2B     |    4B    |     2B     |
   *  +------------+----------+------------+
   *  |   0x0102   |   IPv4   |    value   |	    RT-IP4
   *  +------------+----------+------------+
   *  |   0x0202   |   ASN    |    value   |	    RT-AS4
   *  +------------+----------+------------+
   *
   */

  /* Position of boundary (in bits) between ASN/IP address and value field */
  int boundary = 48;

  char abuf[32] = { 0 };      /* Buffer for ASN/IP address */
  u32 val = 0;

  if (type == RTC_TYPE_AS2)
  {
    type_full  = "rt";
    type_short = "rt";

    u32 asn = (rt >> 32) & 0xffff;
    val = rt & 0xffffffff;
    bsnprintf(abuf, sizeof(abuf), "%u", asn);
    boundary = 32;
  }
  else if (type == RTC_TYPE_IP4)
  {
    type_full  = "rt";
    type_short = "rt";

    ip4_addr addr = ip4_from_u32((rt >> 16) & 0xffffffff);
    val = rt & 0xffff;
    bsnprintf(abuf, sizeof(abuf), "%I4", addr);
  }
  else if (type == RTC_TYPE_AS4)
  {
    type_full  = "rt-as4";
    type_short = "rt-as4";

    u32 asn = (rt >> 16) & 0xffffffff;
    val = rt & 0xffff;
    bsnprintf(abuf, sizeof(abuf), "%u", asn);

    /* If ASN doesn't fit into 2 bytes, we can safely write "rt" without ambiguity */
    if (asn > 0xffff)
      type_short = "rt";
  }

  /* Unknown type, prefix shorter than type field or pxlen bigger than the size of route target */
  if (!type_full || pxlen < 16 || pxlen > 64)
    return bsnprintf(buf, buflen, "(0x%lx/%d) as %u", rt, pxlen, src_asn);

  if (pxlen == 16)
    return bsnprintf(buf, buflen, "(%s, *, *) as %u", type_short, src_asn);

  if (pxlen < boundary)
    return bsnprintf(buf, buflen, "(%s, %s/%d, *) as %u", type_full, abuf, pxlen - 16, src_asn);

  if (pxlen == boundary)
    return bsnprintf(buf, buflen, "(%s, %s, *) as %u", type_short, abuf, src_asn);

  if (pxlen < 64)
    return bsnprintf(buf, buflen, "(%s, %s, %u/%d) as %u", type_full, abuf, val, pxlen - boundary, src_asn);

  if (pxlen == 64)
    return bsnprintf(buf, buflen, "(%s, %s, %u) as %u", type_short, abuf, val, src_asn);

  return -1;
}

static inline void
check_u16(u64 val, const char *msg)
{
  if (val > 0xffff)
    cf_error(msg);
}

static inline void
check_prefix(u64 prefix, int pxlen, int max_pxlen, const char *s)
{
  if (pxlen < 0 || pxlen > max_pxlen || pxlen > 64)
    cf_error("Invalid pxlen: %d", pxlen);

  if ((prefix & ~u64_mkmask(pxlen)) != 0)
    cf_error("Invalid RTC %s prefix 0x%016lx/%d, maybe you wanted 0x%016lx/%d",
	     s, prefix, pxlen, prefix & u64_mkmask(pxlen), pxlen);
}

struct net_addr *
rtc_parse(u64 type, u32 asn, struct f_val asn_ip, u64 val, int pxlen, enum rtc_prefix_position px_pos)
{
  struct net_addr_rtc *n = cfg_allocz(sizeof(struct net_addr_rtc));
  u64 rt = 0;

  /* Ambiguous specifier 'RT' was entered, we need to distinguish between RT-AS2, RT-AS4 and RT-IP4 */
  if (type == U64(-1))
  {
    if (asn_ip.type == T_EC)
      type = (asn_ip.val.ec > 0xffff) ? RTC_TYPE_AS4 : RTC_TYPE_AS2;
    else if (asn_ip.type == T_IP)
      type = RTC_TYPE_IP4;
  }

  if (type == RTC_TYPE_AS2)
  {
    check_u16(asn_ip.val.ec, "ASN out of range (0-65535) for type RT-AS2");

    if (px_pos == RTC_PREFIX_POSITION_ASN_IP)
      check_prefix(asn_ip.val.ec << 48, pxlen, 16, "ASN");
    else if (px_pos == RTC_PREFIX_POSITION_VALUE)
      check_prefix(val << 32, pxlen, 32, "value");

    rt |= (asn_ip.val.ec & 0xffff) << 32;
    rt |= val & 0xffffffff;
  }
  else if (type == RTC_TYPE_IP4)
  {
    check_u16(val, "Value out of range (0-65535) for type RT-IP4");
    ip4_addr addr = ipa_to_ip4(asn_ip.val.ip);

    if (px_pos == RTC_PREFIX_POSITION_ASN_IP)
    {
      if (!net_validate_px4(addr, pxlen))
	cf_error("Invalid RTC IP prefix %I/%d, maybe you wanted %I/%d",
		 addr, pxlen, ip4_and(addr, ip4_mkmask(pxlen)), pxlen);
    }
    else if (px_pos == RTC_PREFIX_POSITION_VALUE)
      check_prefix(val << 48, pxlen, 16, "value");

    rt |= (u64)ip4_to_u32(addr) << 16;
    rt |= val & 0xffff;
  }
  else if (type == RTC_TYPE_AS4)
  {
    check_u16(val, "Value out of range (0-65535) for type RT-AS4");

    if (px_pos == RTC_PREFIX_POSITION_ASN_IP)
      check_prefix(asn_ip.val.ec << 32, pxlen, 32, "ASN");
    else if (px_pos == RTC_PREFIX_POSITION_VALUE)
      check_prefix(val << 48, pxlen, 16, "value");

    rt |= asn_ip.val.ec << 16;
    rt |= val & 0xffff;
  }
  else if (type == 0)	  /* No RT constraint, just 64-bit value */
  {
    check_prefix(asn_ip.val.ec, pxlen, 64, "");
    rt = asn_ip.val.ec;
  }
  else
    cf_error("Unrecognized RT constraint type");

  rt |= type << 48;

  /*
   * RTC can be interpreted as prefix. In cases when the end of the prefix does
   * not lie directly at the boundary of RTC fields, prefix length is specified
   * relative to this particular field. In order to calculate pxlen of the entire
   * RTC prefix, we have to add length of preceding fields.
   *
   * 1. User did not enter valid RTC prefix, just a 64-bit value. Do nothing.
   * 2. Prefix lies at the boundary between type field and ASN/IPv4 field,
   *	pxlen is equal to the length of the type field (2B).
   * 3. Prefix lies inside ASN/IPv4 field, add length of the preceding type field (2B).
   * 4. Prefix lies at the boundary between ASN/IPv4 field and value field, pxlen is
   *	sum of length of preceding type field (2B) and ASN/IPv4 field (2B/4B).
   * 5. Prefix lies inside value field, add length of preceding type field (2B) and
   *	ASN/IPv4 field (2B/4B).
   * 6. There is no prefix, pxlen is 64.
   */
  if (px_pos == RTC_PREFIX_POSITION_IGNORE)
    ;
  else if (px_pos == RTC_PREFIX_POSITION_TYPE_ASN_IP)
    pxlen = 16;
  else if (px_pos == RTC_PREFIX_POSITION_ASN_IP)
    pxlen += 16;
  else if (px_pos == RTC_PREFIX_POSITION_ASN_IP_VALUE)
    pxlen = (type == RTC_TYPE_AS2) ? 32 : 48;
  else if (px_pos == RTC_PREFIX_POSITION_VALUE)
    pxlen += (type == RTC_TYPE_AS2) ? 32 : 48;
  else if (px_pos == RTC_PREFIX_POSITION_END)
    pxlen = 64;
  else
    cf_error("Invalid RTC prefix position");

  net_fill_rtc((net_addr *)n, asn, vrt_from_u64(rt), (u32)pxlen);

  if (!net_validate_rtc(n))
    cf_error("Invalid net");

  return (net_addr *)n;
}
