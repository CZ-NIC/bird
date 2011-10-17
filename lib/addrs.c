/*
 *	BIRD Library -- Address Manipulation Functions
 *
 *	(c) 2011 Alexander V. Chernikov <melifaro@ipfw.ru>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nest/bird.h"
#include "nest/route.h"
#include "lib/ip.h"
#include "lib/string.h"
#include "lib/addrs.h"

/**
 * fn_print - prints a FIB node
 * @buf: data buffer
 * @buflen: data buffer size
 * @n: pointer to fib_node structure
 *
 * This function prints fib node address to supplied buffer.
 */
void
fn_print(char *buf, int buflen, struct fib_node *n)
{
  switch (n->addr_type)
  {
    case RT_IPV4:
    case RT_IPV6:
    case RT_VPNV4:
    case RT_VPNV6:
      addr_print(buf, buflen, n->addr_type, FPREFIX(n));
      bsnprintf(buf + strlen(buf), 5, "/%d", n->pxlen);
      break;

    default:
      addr_print(buf, buflen, n->addr_type, FPREFIX(n));
  }
}

/**
 * addr_print - prints address of given type into supplied buffer
 * @buf: data buffer
 * @buflen: data buffer size
 * @rtype: address type
 * @addr: pointer to address data
 *
 * This function prints address into human-readable format.
 */
void
addr_print(char *buf, int buflen, int rtype, void *addr)
{
  int res = 0;
  ip4_addr v4;
  ip6_addr v6;
#ifdef MPLS_VPN
  vpn4_addr *pv4;
  vpn6_addr *pv6;
#endif

  /* 
   * XXX: converting address to network format and 
   * printing it after that is rather complex.
   * However, printing IPv6 address without inet_ntop
   * is not so easy, too
   */
  switch (rtype)
  {
    case RT_IPV4:
      put_addr(&v4, rtype, addr);
      inet_ntop(AF_INET, &v4, buf, buflen);
      break;

    case RT_IPV6:
      put_addr(&v6, rtype, addr);
      inet_ntop(AF_INET6, &v6, buf, buflen);
      break;
#ifdef MPLS_VPN
    case RT_VPNV4:
      pv4 = (vpn4_addr *)addr;
      res = addr_print_rd(buf, buflen, pv4->rd);
      *(buf + res++) = ' ';
      put_addr(&v4, RT_IPV4, &pv4->addr);
      inet_ntop(AF_INET, &v4, buf + res, buflen - res);
      break;

    case RT_VPNV6:
      pv6 = (vpn6_addr *)addr;
      res = addr_print_rd(buf, buflen, pv6->rd);
      *(buf + res++) = ' ';
      put_addr(&v6, RT_IPV6, &pv6->addr);
      inet_ntop(AF_INET6, &v6, buf + res, buflen - res);
      break;
#endif

    default:
      res = bsnprintf(buf, buflen, "RT:%d", rtype);
  }
}

#ifdef MPLS_VPN
/**
 * addr_print_rd - prints route distinguisher into supplied buffer
 * @addr: pointer to destination buffer
 * @len: buffer length
 * @rd: route distinguisher (host format)
 *
 * This function prints RD in human-readable format.
 */
int
addr_print_rd(char *buf, int buflen, u64 rd)
{
  int res = 0;
  u32 key, val;

  switch (rd >> 48) // FIXME check this ???
  {
    case 0:
      /* 2-byte asn id : 4-byte vpn id */
      key = (rd >> 32) & 0xFFFF;
      val = rd;
      res = bsnprintf(buf, buflen, "%u:%u", key, val);
      break;
    case 1:
      /* 4-byte IPv4 id : 2-byte vpn id */
      key = rd >> 16;
      val = rd & 0xFFFF;
      res = bsnprintf(buf, buflen, "%R:%u", key, val);
      break;
    case 2:
      /* 4-byte asn id : 2-byte vpn id */
      key = rd >> 16;
      val = rd & 0xFFFF;
      res = bsnprintf(buf, buflen, "%u:%u", key, val);
      break;
  }

  return res;
}

#endif

#ifdef MPLS_VPN
void inline
get_vpn4(void *addrdata, vpn4_addr *addr)
{
  addr->rd = get_u64(addrdata);
  addr->addr = get_u32(addrdata + 8);
}

void inline
get_vpn6(void *addrdata, vpn6_addr *addr)
{
  int i;
  u32 *old, *new;

  addr->rd = get_u64(addrdata);
  old = addrdata + 8;
  new = (u32 *)&addr->addr;
  for (i = 0; i < 4; i++, old++, new++)
    *new = get_u32(old);
}

void inline
put_vpn4(void *addrdata, vpn4_addr *addr)
{
  u32 *v4;
  put_u64(addrdata, addr->rd);
  v4 = (u32 *)&addr->addr;
  put_u32(addrdata + 8, *v4);
}

void inline
put_vpn6(void *addrdata, vpn6_addr *addr)
{
  int i;
  u32 *old, *new;
  put_u64(addrdata, addr->rd);
  /* Put IPv6 addr */
  new = addrdata + 8;
  old = (u32 *)&addr->addr;
  for (i = 0; i < 4; i++, old++, new++)
    put_u32(new, *old);
}
#endif

/**
 * get_addr - converts address to host representation
 * @addrdata: pointer to network (source) data buffer
 * @rt_family: address family
 * @datanew: pointer to host data buffer
 *
 * Convert address in @rt_family family from network 
 * to host format. @addrdata can be unaligned.
 */
void
get_addr(void *addrdata, int rt_family, void *datanew)
{
  int i;
  u32 *old, *new;

  switch (rt_family)
  {
    case RT_IPV4:
      new = datanew;
      *new = get_u32(addrdata);
      break;

    case RT_IPV6:
      old = addrdata;
      new = datanew;
      for (i = 0; i < 4; i++, old++, new++)
      	*new = get_u32(old);
      break;
#ifdef MPLS_VPN
    case RT_VPNV4:
      get_vpn4(addrdata, (vpn4_addr *)datanew);
      break;

    case RT_VPNV6:
      get_vpn6(addrdata, (vpn6_addr *)datanew);
      break;
#endif
  }
}

/**
 * put_addr - converts address to network presentation
 * @datanew: pointer to network data buffer
 * @rt_family: address family
 * @addrdata: pointer to host data buffer
 *
 * Convert address in @rt_family family from host
 * to network format. @datanew can be unaligned.
 */
void
put_addr(void *datanew, int rt_family, void *addrdata)
{
  int i;
  u32 *old, *new;
  switch (rt_family)
  {
    case RT_IPV4:
      old = addrdata;
      put_u32(datanew, *old);
      break;

    case RT_IPV6:
      old = addrdata;
      new = datanew;
      for (i = 0; i < 4; i++, old++, new++)
      	put_u32(new, *old);
      break;
#ifdef MPLS_VPN
    case RT_VPNV4:
      put_vpn4(datanew, (vpn4_addr *)addrdata);
      break;

    case RT_VPNV6:
      put_vpn6(datanew, (vpn6_addr *)addrdata);
      break;
#endif
  }
}

