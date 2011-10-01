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

#define PBUFS	4
#define PSIZE	50

/**
 * fn_print - prints a FIB node
 * @n: pointer to fib_node structure
 *
 * This function prints fib node address to static buffer and
 * returns it to the caller. Up to PBUFS(4) different buffers are
 * available.
 */
char *
fn_print(struct fib_node *n)
{
  char *x;
  int res;

  switch (n->addr_type)
  {
    case RT_IPV4:
    case RT_IPV6:
    case RT_VPNV4:
    case RT_VPNV6:
      x = addr_print(n->addr_type, FPREFIX(n), &res);
      bsnprintf(x + res, 5, "/%d", n->pxlen);
      break;

    default:
      x = addr_print(n->addr_type, FPREFIX(n), &res);
  }

  return x;
}

/**
 * addr_print - prints address of given type into static buffer
 * @rtype: address type
 * @addr: pointer to address data
 * @len: pointer to save printed address length to. Can be NULL
 *
 * This function prints address int human-readable format to static buffer
 * and returns it to the caller. Up to PBUFS(4) different buffers are
 * available.
 */
char *
addr_print(int rtype, void *addr, int *len)
{
  static int cntr;
  static char buf[PBUFS][PSIZE];
  char *x;
  int res = 0;
  ip4_addr v4;
  ip6_addr v6;
#ifdef MPLS_VPN
  vpn4_addr *pv4;
  vpn6_addr *pv6;
#endif

  x = buf[cntr++ % PBUFS];

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
      inet_ntop(AF_INET, &v4, x, PSIZE);
      break;

    case RT_IPV6:
      put_addr(&v6, rtype, addr);
      inet_ntop(AF_INET6, &v6, x, PSIZE);
      break;
#ifdef MPLS_VPN
    case RT_VPNV4:
      pv4 = (vpn4_addr *)addr;
      res = addr_print_rd(pv4->rd, x, PSIZE);
      *(x + res++) = ' ';
      put_addr(&v4, RT_IPV4, &pv4->addr);
      inet_ntop(AF_INET, &v4, x + res, PSIZE - res);
      break;

    case RT_VPNV6:
      pv6 = (vpn6_addr *)addr;
      res = addr_print_rd(pv6->rd, x, PSIZE);
      *(x + res++) = ' ';
      put_addr(&v6, RT_IPV6, &pv6->addr);
      inet_ntop(AF_INET6, &v6, x + res, PSIZE - res);
      break;
#endif

    default:
      res = bsnprintf(x, PSIZE, "RT:%d", rtype);
  }

  if (len)
    *len = strlen(x);

  return x;
}

#ifdef MPLS_VPN
/**
 * addr_print_rd - prints route distinguisher into supplied buffer
 * @rd: route distinguisher (host format)
 * @addr: pointer to destination buffer
 * @len: buffer length
 *
 * This function prints RD in human-readable format
 */
int
addr_print_rd(u64 rd, char *buf, int buflen)
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
 * get_addr - converts address to host presentation
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
  uint32_t *old, *new;
  switch (rt_family)
  {
    case RT_IPV4:
      old = (uint32_t *)addrdata;
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

