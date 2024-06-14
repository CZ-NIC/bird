/*
 *	BIRD Internet Routing Daemon -- EVPN Net Type
 *
 *	(c) 2023 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2023 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_EVPN_NET_H_
#define _BIRD_EVPN_NET_H_

enum evpn_net_type {
  NET_EVPN_EAD		=  1,
  NET_EVPN_MAC		=  2,
  NET_EVPN_IMET		=  3,
  NET_EVPN_ES		=  4,
  NET_EVPN_MAX
};

enum evpn_esi_type {
  EVPN_ESI_MANUAL	= 0,
  EVPN_ESI_LACP		= 1,
  EVPN_ESI_MAX
};

#define EVPN_TAG_MAX	0xffffffff
#define EVPN_VNI_MAX	0x00ffffff
#define EVPN_VID_MAX	0x00000fff

typedef struct evpn_esi {
  u8 type;
  u8 value[9];
} evpn_esi;

typedef struct mac_addr {
  u8 addr[6];
} mac_addr;

#define MAC_NONE ((mac_addr){ })

static inline int mac_zero(mac_addr a)
{ return !memcmp(&a, &MAC_NONE, sizeof(mac_addr)); }

static inline int mac_nonzero(mac_addr a)
{ return !mac_zero(a); }

static inline int mac_compare(mac_addr a, mac_addr b)
{ return memcmp(&a, &b, sizeof(mac_addr)); }

union net_addr_evpn;
uint evpn_format(char *buf, uint blen, const union net_addr_evpn *n);

#endif
