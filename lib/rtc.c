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
   *  |   0x0002   |    ASN   |    value   |
   *  +------------+----------+------------+
   *
   *
   *  0           16         48           64
   *  |     2B     |    4B    |     2B     |
   *  +------------+----------+------------+
   *  |   0x0102   |   IPv4   |    value   |
   *  +------------+----------+------------+
   *  |   0x0202   |   ASN    |    value   |
   *  +------------+----------+------------+
   *
   */

  /* Position of boundary (in bits) between ASN/IP address and value field */
  int boundary = 48;

  char abuf[32] = { 0 };      /* Buffer for ASN/IP address */
  u32 val = 0;

  if (type == RTC_TYPE_AS2)
  {
    type_full  = "rt-as2";
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

    /* ASN doesn't fit into 2 bytes, therefore we can write "rt" instead of "rt-as4" without ambiguity */
    if (asn > 0xffff)
      type_short = "rt";
  }

  /* Unknown type, pxlen cutting off type field or pxlen bigger than size of route target constraint */
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

struct net_addr *
rtc_parse(int type, u32 asn, struct f_val asn_ip, u32 val, int pxlen)
{
  struct net_addr_rtc *n = cfg_allocz(sizeof(struct net_addr_rtc));
  u64 rt = 0;

  /* Ambiguous specifier RT was entered, need to distinguish between RT-AS2, RT-AS4 and RT-IP4 */
  if (type == -1)
  {
    if (asn_ip.type == T_EC)
      type = (asn_ip.val.ec > 0xffff) ? RTC_TYPE_AS4 : RTC_TYPE_AS2;  /* Distinguish between RT-AS2 and RT-AS4 */
    else if (asn_ip.type == T_IP)
      type = RTC_TYPE_IP4;
    else
      cf_error("Unknown RT constraint type (type == -1, asn_ip.type = 0x%u)", asn_ip.type);
  }
  else if (type == RTC_TYPE_AS2 || type == RTC_TYPE_IP4 || type == RTC_TYPE_AS4)
    ;
  else if (type != 0)
    cf_error("Unknown RT constraint type (type = 0x%u)", type);

  rt |= (u64)type << 48;

  // store ASN as val.ec (u64) even though u32 is enough, or as val.i (uint) and then cast it here to u64
  if (type == RTC_TYPE_AS2)
  {
    if (asn_ip.val.ec > 0xffff)
      cf_error("ASN out of range for type RT-AS2");

    rt |= (asn_ip.val.ec & 0xffff) << 16;
    rt |= val & 0xffffffff;
  }
  else if (type == RTC_TYPE_IP4)
  {
    if (val > 0xffff)
      cf_error("Value out of range for type RT-IP4");

    rt |= (u64)ip4_to_u32(ipa_to_ip4(asn_ip.val.ip)) << 16;
    rt |= val & 0xffff;
  }
  else if (type == RTC_TYPE_AS4)
  {
    if (val > 0xffff)
      cf_error("Value out of range for type RT-AS4");

    rt |= asn_ip.val.ec << 48;
    rt |= val & 0xffff;
  }
  else	  /* type == 0 */
  {
    /* Supplied RT constraint has no type, it's just a 64-bit number */
    if (asn_ip.type != T_EC)
      cf_error("Invalid type");

    rt = asn_ip.val.ec;
  }

  /*
   * If pxlen lies at the boundary of ASN/IPv4 and value field (indicated by -1),
   * set the correct value according to type.
   */
  if (pxlen == -1)
    pxlen = (type == RTC_TYPE_AS2) ? 32 : 48;

  net_fill_rtc((net_addr *)n, asn, vrt_from_u64(rt), (u32)pxlen);

  if (!net_validate_rtc(n))
    cf_error("Invalid net");

  return (net_addr *)n;
}
