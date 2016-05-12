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
#define NET_MAX		7

#define NB_IP4		(1 << NET_IP4)
#define NB_IP6		(1 << NET_IP6)
#define NB_VPN4		(1 << NET_VPN4)
#define NB_VPN6		(1 << NET_VPN6)
#define NB_ROA4		(1 << NET_ROA4)
#define NB_ROA6		(1 << NET_ROA6)

#define NB_IP		(NB_IP4 | NB_IP6)
#define NB_ANY		0xffffffff


typedef struct net_addr {
  u8 type;
  u8 pxlen;
  u16 length;
  u8 data[16];
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

typedef union net_addr_union {
  net_addr n;
  net_addr_ip4 ip4;
  net_addr_ip6 ip6;
  net_addr_vpn4 vpn4;
  net_addr_vpn6 vpn6;
  net_addr_roa4 roa4;
  net_addr_roa6 roa6;
} net_addr_union;


extern const char * const net_label[];
extern const u16 net_addr_length[];
extern const u8  net_max_prefix_length[];
extern const u16 net_max_text_length[];

#define NET_MAX_TEXT_LENGTH	65


#define NET_ADDR_IP4(prefix,pxlen) \
  ((net_addr_ip4) { NET_IP4, pxlen, sizeof(net_addr_ip4), prefix })

#define NET_ADDR_IP6(prefix,pxlen) \
  ((net_addr_ip6) { NET_IP6, pxlen, sizeof(net_addr_ip6), prefix })

#define NET_ADDR_VPN4(prefix,pxlen,rd) \
  ((net_addr_vpn4) { NET_VPN4, pxlen, sizeof(net_addr_vpn4), prefix, rd })

#define NET_ADDR_VPN6(prefix,pxlen,rd) \
  ((net_addr_vpn6) { NET_VPN6, pxlen, sizeof(net_addr_vpn6), prefix, rd })

#define NET_ADDR_ROA4(prefix,pxlen,max_pxlen,asn) \
  ((net_addr_roa4) { NET_ROA4, pxlen, sizeof(net_addr_roa4), prefix, max_pxlen, asn })

#define NET_ADDR_ROA6(prefix,pxlen,max_pxlen,asn) \
  ((net_addr_roa6) { NET_ROA6, pxlen, sizeof(net_addr_roa6), prefix, max_pxlen, asn })



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


static inline int net_val_match(u8 type, u32 mask)
{ return !!((1 << type) & mask); }

static inline int net_type_match(const net_addr *a, u32 mask)
{ return net_val_match(a->type, mask); }

static inline int net_is_ip(const net_addr *a)
{ return (a->type == NET_IP4) || (a->type == NET_IP6); }


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
    return ipa_from_ip4(net4_prefix(a));

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
    return ipa_from_ip6(net6_prefix(a));

  default:
    return IPA_NONE;
  }
}

static inline uint net4_pxlen(const net_addr *a)
{ return a->pxlen; }

static inline uint net6_pxlen(const net_addr *a)
{ return a->pxlen; }

static inline uint net_pxlen(const net_addr *a)
{ return a->pxlen; }

ip_addr net_pxmask(const net_addr *a);


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

static inline int net_equal_prefix_roa4(const net_addr_roa4 *a, const net_addr_roa4 *b)
{ return ip4_equal(a->prefix, b->prefix) && (a->pxlen == b->pxlen); }

static inline int net_equal_prefix_roa6(const net_addr_roa6 *a, const net_addr_roa6 *b)
{ return ip6_equal(a->prefix, b->prefix) && (a->pxlen == b->pxlen); }


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


static inline u32 net_hash_ip4(const net_addr_ip4 *n)
{ return ip4_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

static inline u32 net_hash_ip6(const net_addr_ip6 *n)
{ return ip6_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

/* XXXX */
static inline u32 u64_hash(u64 a)
{ return u32_hash(a); }

static inline u32 net_hash_vpn4(const net_addr_vpn4 *n)
{ return ip4_hash(n->prefix) ^ ((u32) n->pxlen << 26) ^ u64_hash(n->rd); }

static inline u32 net_hash_vpn6(const net_addr_vpn6 *n)
{ return ip6_hash(n->prefix) ^ ((u32) n->pxlen << 26) ^ u64_hash(n->rd); }

static inline u32 net_hash_roa4(const net_addr_roa4 *n)
{ return ip4_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

static inline u32 net_hash_roa6(const net_addr_roa6 *n)
{ return ip6_hash(n->prefix) ^ ((u32) n->pxlen << 26); }


static inline int net_validate_ip4(const net_addr_ip4 *n)
{
  return (n->pxlen <= IP4_MAX_PREFIX_LENGTH) &&
    ip4_zero(ip4_and(n->prefix, ip4_not(ip4_mkmask(n->pxlen))));
}

static inline int net_validate_ip6(const net_addr_ip6 *n)
{
  return (n->pxlen <= IP6_MAX_PREFIX_LENGTH) &&
    ip6_zero(ip6_and(n->prefix, ip6_not(ip6_mkmask(n->pxlen))));
}

int net_validate(const net_addr *N);


static inline void net_normalize_ip4(net_addr_ip4 *n)
{ n->prefix = ip4_and(n->prefix, ip4_mkmask(n->pxlen)); }

static inline void net_normalize_ip6(net_addr_ip6 *n)
{ n->prefix = ip6_and(n->prefix, ip6_mkmask(n->pxlen)); }

void net_normalize(net_addr *N);


int net_classify(const net_addr *N);
int net_format(const net_addr *N, char *buf, int buflen);


int ipa_in_netX(const ip_addr A, const net_addr *N);
int net_in_netX(const net_addr *A, const net_addr *N);


#endif
