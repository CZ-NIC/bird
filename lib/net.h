/*
 *	BIRD Internet Routing Daemon -- Network addresses
 *
 *	(c) 2015 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_NET_H_
#define _BIRD_NET_H_

#include "lib/ip.h"


#define NET_IP4		1
#define NET_IP6		2
#define NET_VPN4	3
#define NET_VPN6	4
#define NET_ROA4	5
#define NET_ROA6	6
#define NET_FLOW4	7
#define NET_FLOW6	8
#define NET_MREQ4	9
#define NET_MREQ6	10
#define NET_MGRP4	11
#define NET_MGRP6	12
#define NET_MPLS	13
#define NET_MAX		14

#define NB_IP4		(1 << NET_IP4)
#define NB_IP6		(1 << NET_IP6)
#define NB_VPN4		(1 << NET_VPN4)
#define NB_VPN6		(1 << NET_VPN6)
#define NB_ROA4		(1 << NET_ROA4)
#define NB_ROA6		(1 << NET_ROA6)
#define NB_FLOW4	(1 << NET_FLOW4)
#define NB_FLOW6	(1 << NET_FLOW6)
#define NB_MREQ4	(1 << NET_MREQ4)
#define NB_MREQ6	(1 << NET_MREQ6)
#define NB_MGRP4	(1 << NET_MGRP4)
#define NB_MGRP6	(1 << NET_MGRP6)
#define NB_MPLS		(1 << NET_MPLS)

#define NB_IP		(NB_IP4 | NB_IP6)
#define NB_VPN		(NB_VPN4 | NB_VPN6)
#define NB_ROA		(NB_ROA4 | NB_ROA6)
#define NB_FLOW		(NB_FLOW4 | NB_FLOW6)
#define NB_MREQ		(NB_MREQ4 | NB_MREQ6)
#define NB_MGRP		(NB_MGRP4 | NB_MGRP6)

/* FIXME: Better validation of (NET, RTD) combinations */
#define NB_HOST		(NB_IP | NB_VPN | NB_ROA)
// #define NB_DEST	(NB_IP | NB_VPN | NB_MPLS)
#define NB_DEST		(NB_IP | NB_VPN | NB_MGRP | NB_MPLS)
#define NB_ANY		0xffffffff

#define MIFS_MAX	32


typedef struct net_addr {
  u8 type;
  u8 pxlen;
  u16 length;
  u8 data[20];
  u64 align[0];
} net_addr;

typedef struct net_addr_ip4 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip4_addr prefix;
} net_addr_ip4;

typedef struct net_addr_ip6 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip6_addr prefix;
} net_addr_ip6;

typedef struct net_addr_vpn4 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip4_addr prefix;
  u64 rd;
} net_addr_vpn4;

typedef struct net_addr_vpn6 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip6_addr prefix;
  u32 padding;
  u64 rd;
} net_addr_vpn6;

typedef struct net_addr_roa4 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip4_addr prefix;
  u32 max_pxlen;
  u32 asn;
} net_addr_roa4;

typedef struct net_addr_roa6 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip6_addr prefix;
  u32 max_pxlen;
  u32 asn;
} net_addr_roa6;

typedef struct net_addr_flow4 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip4_addr prefix;
  byte data[0];
} net_addr_flow4;

typedef struct net_addr_flow6 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip6_addr prefix;
  byte data[0];
} net_addr_flow6;

typedef struct net_addr_mreq4 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip4_addr grp;
  uint ifindex;
} net_addr_mreq4;

typedef struct net_addr_mreq6 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip6_addr grp;
  uint ifindex;
} net_addr_mreq6;

typedef struct net_addr_mgrp4 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip4_addr grp;
} net_addr_mgrp4;

typedef struct net_addr_mgrp6 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip6_addr grp;
} net_addr_mgrp6;

typedef struct net_addr_mpls {
  u8 type;
  u8 pxlen;
  u16 length;
  u32 label;
} net_addr_mpls;

typedef union net_addr_union {
  net_addr n;
  net_addr_ip4 ip4;
  net_addr_ip6 ip6;
  net_addr_vpn4 vpn4;
  net_addr_vpn6 vpn6;
  net_addr_roa4 roa4;
  net_addr_roa6 roa6;
  net_addr_flow4 flow4;
  net_addr_flow6 flow6;
  net_addr_mreq4 mreq4;
  net_addr_mreq6 mreq6;
  net_addr_mgrp4 mgrp4;
  net_addr_mgrp6 mgrp6;
  net_addr_mpls mpls;
} net_addr_union;


extern const char * const net_label[];
extern const u16 net_addr_length[];
extern const u8  net_max_prefix_length[];
extern const u16 net_max_text_length[];

#define NET_MAX_TEXT_LENGTH	256


#define NET_ADDR_IP4(prefix,pxlen) \
  ((net_addr_ip4) { NET_IP4, pxlen, sizeof(net_addr_ip4), prefix })

#define NET_ADDR_IP6(prefix,pxlen) \
  ((net_addr_ip6) { NET_IP6, pxlen, sizeof(net_addr_ip6), prefix })

#define NET_ADDR_VPN4(prefix,pxlen,rd) \
  ((net_addr_vpn4) { NET_VPN4, pxlen, sizeof(net_addr_vpn4), prefix, rd })

#define NET_ADDR_VPN6(prefix,pxlen,rd) \
  ((net_addr_vpn6) { NET_VPN6, pxlen, sizeof(net_addr_vpn6), prefix, 0, rd })

#define NET_ADDR_ROA4(prefix,pxlen,max_pxlen,asn) \
  ((net_addr_roa4) { NET_ROA4, pxlen, sizeof(net_addr_roa4), prefix, max_pxlen, asn })

#define NET_ADDR_ROA6(prefix,pxlen,max_pxlen,asn) \
  ((net_addr_roa6) { NET_ROA6, pxlen, sizeof(net_addr_roa6), prefix, max_pxlen, asn })

#define NET_ADDR_FLOW4(prefix,pxlen,dlen) \
  ((net_addr_flow4) { NET_FLOW4, pxlen, sizeof(net_addr_ip4) + dlen, prefix })

#define NET_ADDR_FLOW6(prefix,pxlen,dlen) \
  ((net_addr_flow6) { NET_FLOW6, pxlen, sizeof(net_addr_ip6) + dlen, prefix })

#define NET_ADDR_MREQ4(grp, ifindex) \
  ((net_addr_mreq4) { NET_MREQ4, IP4_MAX_PREFIX_LENGTH, sizeof(net_addr_mreq4), grp, ifindex })

#define NET_ADDR_MREQ6(grp, ifindex) \
  ((net_addr_mreq6) { NET_MREQ6, IP6_MAX_PREFIX_LENGTH, sizeof(net_addr_mreq6), grp, ifindex })

#define NET_ADDR_MGRP4(grp) \
  ((net_addr_mgrp4) { NET_MGRP4, IP4_MAX_PREFIX_LENGTH, sizeof(net_addr_mgrp4), grp })

#define NET_ADDR_MGRP6(grp) \
  ((net_addr_mgrp6) { NET_MGRP6, IP6_MAX_PREFIX_LENGTH, sizeof(net_addr_mgrp6), grp })

#define NET_ADDR_MPLS(label) \
  ((net_addr_mpls) { NET_MPLS, 20, sizeof(net_addr_mpls), label })


static inline void net_fill_ip4(net_addr *a, ip4_addr prefix, uint pxlen)
{ *(net_addr_ip4 *)a = NET_ADDR_IP4(prefix, pxlen); }

static inline void net_fill_ip6(net_addr *a, ip6_addr prefix, uint pxlen)
{ *(net_addr_ip6 *)a = NET_ADDR_IP6(prefix, pxlen); }

static inline void net_fill_vpn4(net_addr *a, ip4_addr prefix, uint pxlen, u64 rd)
{ *(net_addr_vpn4 *)a = NET_ADDR_VPN4(prefix, pxlen, rd); }

static inline void net_fill_vpn6(net_addr *a, ip6_addr prefix, uint pxlen, u64 rd)
{ *(net_addr_vpn6 *)a = NET_ADDR_VPN6(prefix, pxlen, rd); }

static inline void net_fill_roa4(net_addr *a, ip4_addr prefix, uint pxlen, uint max_pxlen, u32 asn)
{ *(net_addr_roa4 *)a = NET_ADDR_ROA4(prefix, pxlen, max_pxlen, asn); }

static inline void net_fill_roa6(net_addr *a, ip6_addr prefix, uint pxlen, uint max_pxlen, u32 asn)
{ *(net_addr_roa6 *)a = NET_ADDR_ROA6(prefix, pxlen, max_pxlen, asn); }

static inline void net_fill_mreq4(net_addr *a, ip4_addr grp, uint ifindex)
{ *(net_addr_mreq4 *)a = NET_ADDR_MREQ4(grp, ifindex); }

static inline void net_fill_mreq6(net_addr *a, ip6_addr grp, uint ifindex)
{ *(net_addr_mreq6 *)a = NET_ADDR_MREQ6(grp, ifindex); }

static inline void net_fill_mgrp4(net_addr *a, ip4_addr grp)
{ *(net_addr_mgrp4 *)a = NET_ADDR_MGRP4(grp); }

static inline void net_fill_mgrp6(net_addr *a, ip6_addr grp)
{ *(net_addr_mgrp6 *)a = NET_ADDR_MGRP6(grp); }

static inline void net_fill_mpls(net_addr *a, u32 label)
{ *(net_addr_mpls *)a = NET_ADDR_MPLS(label); }

static inline void net_fill_ipa(net_addr *a, ip_addr prefix, uint pxlen)
{
  if (ipa_is_ip4(prefix))
    net_fill_ip4(a, ipa_to_ip4(prefix), pxlen);
  else
    net_fill_ip6(a, ipa_to_ip6(prefix), pxlen);
}

static inline void net_fill_ip_host(net_addr *a, ip_addr prefix)
{
  if (ipa_is_ip4(prefix))
    net_fill_ip4(a, ipa_to_ip4(prefix), IP4_MAX_PREFIX_LENGTH);
  else
    net_fill_ip6(a, ipa_to_ip6(prefix), IP6_MAX_PREFIX_LENGTH);
}

static inline void net_fill_mreq(net_addr *a, ip_addr grp, unsigned ifindex)
{
  if (ipa_is_ip4(grp))
    net_fill_mreq4(a, ipa_to_ip4(grp), ifindex);
  else
    net_fill_mreq6(a, ipa_to_ip6(grp), ifindex);
}

static inline void net_fill_mgrp(net_addr *a, ip_addr grp)
{
  if (ipa_is_ip4(grp))
    net_fill_mgrp4(a, ipa_to_ip4(grp));
  else
    net_fill_mgrp6(a, ipa_to_ip6(grp));
}

static inline void net_fill_flow4(net_addr *a, ip4_addr prefix, uint pxlen, byte *data, uint dlen)
{
  net_addr_flow4 *f = (void *) a;
  *f = NET_ADDR_FLOW4(prefix, pxlen, dlen);
  memcpy(f->data, data, dlen);
}

static inline void net_fill_flow6(net_addr *a, ip6_addr prefix, uint pxlen, byte *data, uint dlen)
{
  net_addr_flow6 *f = (void *) a;
  *f = NET_ADDR_FLOW6(prefix, pxlen, dlen);
  memcpy(f->data, data, dlen);
}

static inline int net_val_match(u8 type, u32 mask)
{ return !!((1 << type) & mask); }

static inline int net_type_match(const net_addr *a, u32 mask)
{ return net_val_match(a->type, mask); }

static inline int net_is_ip(const net_addr *a)
{ return (a->type == NET_IP4) || (a->type == NET_IP6); }

static inline int net_is_vpn(const net_addr *a)
{ return (a->type == NET_VPN4) || (a->type == NET_VPN6); }

static inline int net_is_roa(const net_addr *a)
{ return (a->type == NET_ROA4) || (a->type == NET_ROA6); }

static inline int net_is_flow(const net_addr *a)
{ return (a->type == NET_FLOW4) || (a->type == NET_FLOW6); }

static inline int net_is_mreq(const net_addr *a)
{ return (a->type == NET_MREQ4) || (a->type == NET_MREQ6); }

static inline int net_is_mgrp(const net_addr *a)
{ return (a->type == NET_MGRP4) || (a->type == NET_MGRP6); }


static inline ip4_addr net4_prefix(const net_addr *a)
{ return ((net_addr_ip4 *) a)->prefix; }

static inline ip6_addr net6_prefix(const net_addr *a)
{ return ((net_addr_ip6 *) a)->prefix; }

static inline ip_addr net_prefix(const net_addr *a)
{
  switch (a->type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
  case NET_FLOW4:
  case NET_MREQ4:
  case NET_MGRP4:
    return ipa_from_ip4(net4_prefix(a));

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
  case NET_FLOW6:
  case NET_MREQ6:
  case NET_MGRP6:
    return ipa_from_ip6(net6_prefix(a));

  case NET_MPLS:
  default:
    return IPA_NONE;
  }
}

static inline u32 net_mpls(const net_addr *a)
{
  if (a->type == NET_MPLS)
    return ((net_addr_mpls *) a)->label;

  bug("Can't call net_mpls on non-mpls net_addr");
}

static inline uint net4_pxlen(const net_addr *a)
{ return a->pxlen; }

static inline uint net6_pxlen(const net_addr *a)
{ return a->pxlen; }

static inline uint net_pxlen(const net_addr *a)
{ return a->pxlen; }

ip_addr net_pxmask(const net_addr *a);

static inline u64 net_rd(const net_addr *a)
{
  switch (a->type)
  {
  case NET_VPN4:
    return ((net_addr_vpn4 *) a)->rd;
  case NET_VPN6:
    return ((net_addr_vpn6 *) a)->rd;
  default:
    return 0;
  }
}

static inline int net_ifindex(net_addr *a)
{
  switch (a->type)
  {
  case NET_MREQ4:
    return ((net_addr_mreq4 *) a)->ifindex;
  case NET_MREQ6:
    return ((net_addr_mreq6 *) a)->ifindex;
  default:
    return 0;
  }
}


static inline int net_equal(const net_addr *a, const net_addr *b)
{ return (a->length == b->length) && !memcmp(a, b, a->length); }

static inline int net_equal_ip4(const net_addr_ip4 *a, const net_addr_ip4 *b)
{ return !memcmp(a, b, sizeof(net_addr_ip4)); }

static inline int net_equal_ip6(const net_addr_ip6 *a, const net_addr_ip6 *b)
{ return !memcmp(a, b, sizeof(net_addr_ip6)); }

static inline int net_equal_vpn4(const net_addr_vpn4 *a, const net_addr_vpn4 *b)
{ return !memcmp(a, b, sizeof(net_addr_vpn4)); }

static inline int net_equal_vpn6(const net_addr_vpn6 *a, const net_addr_vpn6 *b)
{ return !memcmp(a, b, sizeof(net_addr_vpn6)); }

static inline int net_equal_roa4(const net_addr_roa4 *a, const net_addr_roa4 *b)
{ return !memcmp(a, b, sizeof(net_addr_roa4)); }

static inline int net_equal_roa6(const net_addr_roa6 *a, const net_addr_roa6 *b)
{ return !memcmp(a, b, sizeof(net_addr_roa6)); }

static inline int net_equal_flow4(const net_addr_flow4 *a, const net_addr_flow4 *b)
{ return net_equal((const net_addr *) a, (const net_addr *) b); }

static inline int net_equal_flow6(const net_addr_flow6 *a, const net_addr_flow6 *b)
{ return net_equal((const net_addr *) a, (const net_addr *) b); }

static inline int net_equal_mpls(const net_addr_mpls *a, const net_addr_mpls *b)
{ return !memcmp(a, b, sizeof(net_addr_mpls)); }


static inline int net_equal_prefix_roa4(const net_addr_roa4 *a, const net_addr_roa4 *b)
{ return ip4_equal(a->prefix, b->prefix) && (a->pxlen == b->pxlen); }

static inline int net_equal_prefix_roa6(const net_addr_roa6 *a, const net_addr_roa6 *b)
{ return ip6_equal(a->prefix, b->prefix) && (a->pxlen == b->pxlen); }

static inline int net_equal_mreq4(const net_addr_mreq4 *a, const net_addr_mreq4 *b)
{ return !memcmp(a, b, sizeof(net_addr_mreq4)); }

static inline int net_equal_mreq6(const net_addr_mreq6 *a, const net_addr_mreq6 *b)
{ return !memcmp(a, b, sizeof(net_addr_mreq6)); }

static inline int net_equal_mgrp4(const net_addr_mgrp4 *a, const net_addr_mgrp4 *b)
{ return !memcmp(a, b, sizeof(net_addr_mgrp4)); }

static inline int net_equal_mgrp6(const net_addr_mgrp6 *a, const net_addr_mgrp6 *b)
{ return !memcmp(a, b, sizeof(net_addr_mgrp6)); }


static inline int net_zero_ip4(const net_addr_ip4 *a)
{ return !a->pxlen && ip4_zero(a->prefix); }

static inline int net_zero_ip6(const net_addr_ip6 *a)
{ return !a->pxlen && ip6_zero(a->prefix); }

static inline int net_zero_vpn4(const net_addr_vpn4 *a)
{ return !a->pxlen && ip4_zero(a->prefix) && !a->rd; }

static inline int net_zero_vpn6(const net_addr_vpn6 *a)
{ return !a->pxlen && ip6_zero(a->prefix) && !a->rd; }

static inline int net_zero_roa4(const net_addr_roa4 *a)
{ return !a->pxlen && ip4_zero(a->prefix) && !a->max_pxlen && !a->asn; }

static inline int net_zero_roa6(const net_addr_roa6 *a)
{ return !a->pxlen && ip6_zero(a->prefix) && !a->max_pxlen && !a->asn; }

static inline int net_zero_flow4(const net_addr_flow4 *a)
{ return !a->pxlen && ip4_zero(a->prefix) && (a->length == sizeof(net_addr_flow4)); }

static inline int net_zero_flow6(const net_addr_flow6 *a)
{ return !a->pxlen && ip6_zero(a->prefix) && (a->length == sizeof(net_addr_flow6)); }

static inline int net_zero_mreq4(const net_addr_mreq4 *a)
{ return ip4_zero(a->grp) && !a->ifindex; }

static inline int net_zero_mreq6(const net_addr_mreq6 *a)
{ return ip6_zero(a->grp) && !a->ifindex; }

static inline int net_zero_mgrp4(const net_addr_mgrp4 *a)
{ return ip4_zero(a->grp); }

static inline int net_zero_mgrp6(const net_addr_mgrp6 *a)
{ return ip6_zero(a->grp); }

static inline int net_zero_mpls(const net_addr_mpls *a)
{ return !a->label; }


static inline int net_compare_ip4(const net_addr_ip4 *a, const net_addr_ip4 *b)
{ return ip4_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen); }

static inline int net_compare_ip6(const net_addr_ip6 *a, const net_addr_ip6 *b)
{ return ip6_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen); }

static inline int net_compare_vpn4(const net_addr_vpn4 *a, const net_addr_vpn4 *b)
{ return u64_cmp(a->rd, b->rd) ?: ip4_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen); }

static inline int net_compare_vpn6(const net_addr_vpn6 *a, const net_addr_vpn6 *b)
{ return u64_cmp(a->rd, b->rd) ?: ip6_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen); }

static inline int net_compare_roa4(const net_addr_roa4 *a, const net_addr_roa4 *b)
{ return ip4_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen) ?: uint_cmp(a->max_pxlen, b->max_pxlen) ?: uint_cmp(a->asn, b->asn); }

static inline int net_compare_roa6(const net_addr_roa6 *a, const net_addr_roa6 *b)
{ return ip6_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen) ?: uint_cmp(a->max_pxlen, b->max_pxlen) ?: uint_cmp(a->asn, b->asn); }

static inline int net_compare_flow4(const net_addr_flow4 *a, const net_addr_flow4 *b)
{ return ip4_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen) ?: uint_cmp(a->length, b->length) ?: memcmp(a->data, b->data, a->length - sizeof(net_addr_flow4)); }

static inline int net_compare_flow6(const net_addr_flow6 *a, const net_addr_flow6 *b)
{ return ip6_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen) ?: uint_cmp(a->length, b->length) ?: memcmp(a->data, b->data, a->length - sizeof(net_addr_flow6)); }

static inline int net_compare_mreq4(const net_addr_mreq4 *a, const net_addr_mreq4 *b)
{ return ip4_compare(a->grp, b->grp) ?: uint_cmp(a->ifindex, b->ifindex); }

static inline int net_compare_mreq6(const net_addr_mreq6 *a, const net_addr_mreq6 *b)
{ return ip6_compare(a->grp, b->grp) ?: uint_cmp(a->ifindex, b->ifindex); }

static inline int net_compare_mgrp4(const net_addr_mgrp4 *a, const net_addr_mgrp4 *b)
{ return ip4_compare(a->grp, b->grp); }

static inline int net_compare_mgrp6(const net_addr_mgrp6 *a, const net_addr_mgrp6 *b)
{ return ip6_compare(a->grp, b->grp); }

static inline int net_compare_mpls(const net_addr_mpls *a, const net_addr_mpls *b)
{ return uint_cmp(a->label, b->label); }

int net_compare(const net_addr *a, const net_addr *b);


static inline void net_copy(net_addr *dst, const net_addr *src)
{ memcpy(dst, src, src->length); }

static inline void net_copy_ip4(net_addr_ip4 *dst, const net_addr_ip4 *src)
{ memcpy(dst, src, sizeof(net_addr_ip4)); }

static inline void net_copy_ip6(net_addr_ip6 *dst, const net_addr_ip6 *src)
{ memcpy(dst, src, sizeof(net_addr_ip6)); }

static inline void net_copy_vpn4(net_addr_vpn4 *dst, const net_addr_vpn4 *src)
{ memcpy(dst, src, sizeof(net_addr_vpn4)); }

static inline void net_copy_vpn6(net_addr_vpn6 *dst, const net_addr_vpn6 *src)
{ memcpy(dst, src, sizeof(net_addr_vpn6)); }

static inline void net_copy_roa4(net_addr_roa4 *dst, const net_addr_roa4 *src)
{ memcpy(dst, src, sizeof(net_addr_roa4)); }

static inline void net_copy_roa6(net_addr_roa6 *dst, const net_addr_roa6 *src)
{ memcpy(dst, src, sizeof(net_addr_roa6)); }

static inline void net_copy_flow4(net_addr_flow4 *dst, const net_addr_flow4 *src)
{ memcpy(dst, src, src->length); }

static inline void net_copy_flow6(net_addr_flow6 *dst, const net_addr_flow6 *src)
{ memcpy(dst, src, src->length); }

static inline void net_copy_mreq4(net_addr_mreq4 *dst, const net_addr_mreq4 *src)
{ memcpy(dst, src, sizeof(net_addr_mreq4)); }

static inline void net_copy_mreq6(net_addr_mreq6 *dst, const net_addr_mreq6 *src)
{ memcpy(dst, src, sizeof(net_addr_mreq6)); }

static inline void net_copy_mgrp4(net_addr_mgrp4 *dst, const net_addr_mgrp4 *src)
{ memcpy(dst, src, sizeof(net_addr_mgrp4)); }

static inline void net_copy_mgrp6(net_addr_mgrp6 *dst, const net_addr_mgrp6 *src)
{ memcpy(dst, src, sizeof(net_addr_mgrp6)); }

static inline void net_copy_mpls(net_addr_mpls *dst, const net_addr_mpls *src)
{ memcpy(dst, src, sizeof(net_addr_mpls)); }


/* XXXX */
static inline u32 u64_hash(u64 a)
{ return u32_hash(a); }

static inline u32 net_hash_ip4(const net_addr_ip4 *n)
{ return ip4_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

static inline u32 net_hash_ip6(const net_addr_ip6 *n)
{ return ip6_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

static inline u32 net_hash_vpn4(const net_addr_vpn4 *n)
{ return ip4_hash(n->prefix) ^ ((u32) n->pxlen << 26) ^ u64_hash(n->rd); }

static inline u32 net_hash_vpn6(const net_addr_vpn6 *n)
{ return ip6_hash(n->prefix) ^ ((u32) n->pxlen << 26) ^ u64_hash(n->rd); }

static inline u32 net_hash_roa4(const net_addr_roa4 *n)
{ return ip4_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

static inline u32 net_hash_roa6(const net_addr_roa6 *n)
{ return ip6_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

static inline u32 net_hash_flow4(const net_addr_flow4 *n)
{ return ip4_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

static inline u32 net_hash_flow6(const net_addr_flow6 *n)
{ return ip6_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

static inline u32 net_hash_mreq4(const net_addr_mreq4 *n)
{ return ip4_hash(n->grp) ^ u32_hash(n->ifindex); }

static inline u32 net_hash_mreq6(const net_addr_mreq6 *n)
{ return ip6_hash(n->grp) ^ u32_hash(n->ifindex); }

static inline u32 net_hash_mgrp4(const net_addr_mgrp4 *n)
{ return ip4_hash(n->grp); }

static inline u32 net_hash_mgrp6(const net_addr_mgrp6 *n)
{ return ip6_hash(n->grp); }

static inline u32 net_hash_mpls(const net_addr_mpls *n)
{ return n->label; }

u32 net_hash(const net_addr *a);


static inline int net_validate_px4(const ip4_addr prefix, uint pxlen)
{
  return (pxlen <= IP4_MAX_PREFIX_LENGTH) &&
    ip4_zero(ip4_and(prefix, ip4_not(ip4_mkmask(pxlen))));
}

static inline int net_validate_px6(const ip6_addr prefix, uint pxlen)
{
  return (pxlen <= IP6_MAX_PREFIX_LENGTH) &&
    ip6_zero(ip6_and(prefix, ip6_not(ip6_mkmask(pxlen))));
}

static inline int net_validate_ip4(const net_addr_ip4 *n)
{ return net_validate_px4(n->prefix, n->pxlen); }

static inline int net_validate_ip6(const net_addr_ip6 *n)
{ return net_validate_px6(n->prefix, n->pxlen); }

static inline int net_validate_vpn4(const net_addr_vpn4 *n)
{ return net_validate_px4(n->prefix, n->pxlen); }

static inline int net_validate_vpn6(const net_addr_vpn6 *n)
{ return  net_validate_px6(n->prefix, n->pxlen); }

static inline int net_validate_roa4(const net_addr_roa4 *n)
{
  return net_validate_px4(n->prefix, n->pxlen) &&
     (n->pxlen <= n->max_pxlen) && (n->max_pxlen <= IP4_MAX_PREFIX_LENGTH);
}

static inline int net_validate_roa6(const net_addr_roa6 *n)
{
  return net_validate_px6(n->prefix, n->pxlen) &&
    (n->pxlen <= n->max_pxlen) && (n->max_pxlen <= IP6_MAX_PREFIX_LENGTH);
}

// FIXME: Better check, call flow_validate?
static inline int net_validate_flow4(const net_addr_flow4 *n)
{ return net_validate_px4(n->prefix, n->pxlen); }

static inline int net_validate_flow6(const net_addr_flow6 *n)
{ return net_validate_px6(n->prefix, n->pxlen); }

static inline int net_validate_mreq4(const net_addr_mreq4 *n)
{ return ip4_is_multicast(n->grp); }

static inline int net_validate_mreq6(const net_addr_mreq6 *n)
{ return ip6_is_multicast(n->grp); }

static inline int net_validate_mgrp4(const net_addr_mgrp4 *n)
{ return ip4_is_multicast(n->grp); }

static inline int net_validate_mgrp6(const net_addr_mgrp6 *n)
{ return ip6_is_multicast(n->grp); }

static inline int net_validate_mpls(const net_addr_mpls *n)
{ return n->label < (1 << 20); }

int net_validate(const net_addr *N);


static inline void net_normalize_ip4(net_addr_ip4 *n)
{ n->prefix = ip4_and(n->prefix, ip4_mkmask(n->pxlen)); }

static inline void net_normalize_ip6(net_addr_ip6 *n)
{ n->prefix = ip6_and(n->prefix, ip6_mkmask(n->pxlen)); }

static inline void net_normalize_vpn4(net_addr_vpn4 *n)
{ net_normalize_ip4((net_addr_ip4 *) n); }

static inline void net_normalize_vpn6(net_addr_vpn6 *n)
{ net_normalize_ip6((net_addr_ip6 *) n); }

void net_normalize(net_addr *N);


int net_classify(const net_addr *N);
int net_format(const net_addr *N, char *buf, int buflen);
int rd_format(const u64 rd, char *buf, int buflen);

static inline int ipa_in_net_ip4(ip4_addr a, const net_addr_ip4 *n)
{ return ip4_zero(ip4_and(ip4_xor(a, n->prefix), ip4_mkmask(n->pxlen))); }

static inline int net_in_net_ip4(const net_addr_ip4 *a, const net_addr_ip4 *b)
{ return (a->pxlen >= b->pxlen) && ipa_in_net_ip4(a->prefix, b); }

static inline int ipa_in_net_ip6(ip6_addr a, const net_addr_ip6 *n)
{ return ip6_zero(ip6_and(ip6_xor(a, n->prefix), ip6_mkmask(n->pxlen))); }

static inline int net_in_net_ip6(const net_addr_ip6 *a, const net_addr_ip6 *b)
{ return (a->pxlen >= b->pxlen) && ipa_in_net_ip6(a->prefix, b); }

int ipa_in_netX(const ip_addr A, const net_addr *N);
int net_in_netX(const net_addr *A, const net_addr *N);

void net_init(void);

#endif
