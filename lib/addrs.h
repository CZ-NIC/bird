/*
 *	BIRD Internet Routing Daemon -- The Internet Protocol
 *
 *	(c) 2011 Alexander V. Chernikov <melifaro@ipfw.ru>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_ADDRS_H_
#define _BIRD_ADDRS_H_

/* Build ip4_addr and ip6_addr on top of existing types to support existing macro */
#ifdef DEBUGGING

#ifndef IPV6
typedef struct ipv6_addr {
  u32 addr[4];
} ip6_addr;
typedef ip_addr ip4_addr;
#else
typedef struct ipv4_addr {
  u32 addr;
} ip4_addr;
typedef ip_addr ip6_addr;
#endif

#else	/* ! DEBUGGING */

typedef uint64_t u64;

#ifndef IPV6
typedef struct ipv6_addr {
  u32 addr[4];
} ip6_addr;
typedef ip_addr ip4_addr;
#else
typedef u32 ip4_addr;
typedef ip_addr ip6_addr;
#endif

#endif	/* DEBUGGING */

#ifdef MPLS_VPN
typedef struct vpn4_addr {
	u64		rd;
	ip4_addr	addr;
} vpn4_addr;

typedef struct vpn6_addr {
	u64		rd;
	ip6_addr	addr;
} vpn6_addr;

#ifndef IPV6
typedef vpn4_addr vpn_addr;
#else
typedef vpn6_addr vpn_addr;
#endif

#endif

struct fib_node;

#ifdef MPLS_VPN
int addr_print_rd(u64 rd, char *buf, int buflen);
void get_vpn4(void *addrdata, vpn4_addr *newv4);
void get_vpn6(void *addrdata, vpn6_addr *newv6);
void put_vpn4(void *addrdata, vpn4_addr *addr);
void put_vpn6(void *addrdata, vpn6_addr *addr);
#endif
void get_addr(void *addrdata, int rt_family, void *datanew);
void put_addr(void *datanew, int rt_family, void *addrdata);

char *addr_print(int rtype, void *addr, int *len);
char *fn_print(struct fib_node *f);	/* Prints human-readable fib_node prefix */

#endif

