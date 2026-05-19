/*
 *	BIRD Internet Routing Daemon -- RT Constraint Net Type
 *
 *	(c) 2026 Igor Putovny <igor.putovny@nic.cz>
 *	(c) 2026 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/net.h"
#include "lib/rtc.h"

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

  if (type == 0x0002)
  {
    type_full  = "rt-as2";
    type_short = "rt";

    u32 asn = (rt >> 32) & 0xffff;
    val = rt & 0xffffffff;
    bsnprintf(abuf, sizeof(abuf), "%u", asn);
    boundary = 32;
  }
  else if (type == 0x0102)
  {
    type_full  = "rt";
    type_short = "rt";

    ip4_addr addr = ip4_from_u32((rt >> 16) & 0xffffffff);
    val = rt & 0xffff;
    bsnprintf(abuf, sizeof(abuf), "%I4", addr);
  }
  else if (type == 0x0202)
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
