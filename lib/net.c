
#include "nest/bird.h"
#include "lib/ip.h"
#include "lib/net.h"
#include "lib/flowspec.h"


const char * const net_label[] = {
  [NET_IP4]	= "ipv4",
  [NET_IP6]	= "ipv6",
  [NET_VPN4]	= "vpn4",
  [NET_VPN6]	= "vpn6",
  [NET_ROA4]	= "roa4",
  [NET_ROA6]	= "roa6",
  [NET_FLOW4]	= "flow4",
  [NET_FLOW6]	= "flow6",
  [NET_IP6_SADR]= "ipv6-sadr",
  [NET_MPLS]	= "mpls",
};

const u16 net_addr_length[] = {
  [NET_IP4]	= sizeof(net_addr_ip4),
  [NET_IP6]	= sizeof(net_addr_ip6),
  [NET_VPN4]	= sizeof(net_addr_vpn4),
  [NET_VPN6]	= sizeof(net_addr_vpn6),
  [NET_ROA4]	= sizeof(net_addr_roa4),
  [NET_ROA6]	= sizeof(net_addr_roa6),
  [NET_FLOW4]	= 0,
  [NET_FLOW6]	= 0,
  [NET_IP6_SADR]= sizeof(net_addr_ip6_sadr),
  [NET_MPLS]	= sizeof(net_addr_mpls),
};

const u8 net_max_prefix_length[] = {
  [NET_IP4]	= IP4_MAX_PREFIX_LENGTH,
  [NET_IP6]	= IP6_MAX_PREFIX_LENGTH,
  [NET_VPN4]	= IP4_MAX_PREFIX_LENGTH,
  [NET_VPN6]	= IP6_MAX_PREFIX_LENGTH,
  [NET_ROA4]	= IP4_MAX_PREFIX_LENGTH,
  [NET_ROA6]	= IP6_MAX_PREFIX_LENGTH,
  [NET_FLOW4]	= IP4_MAX_PREFIX_LENGTH,
  [NET_FLOW6]	= IP6_MAX_PREFIX_LENGTH,
  [NET_IP6_SADR]= IP6_MAX_PREFIX_LENGTH,
  [NET_MPLS]	= 0,
};

const u16 net_max_text_length[] = {
  [NET_IP4]	= 18,	/* "255.255.255.255/32" */
  [NET_IP6]	= 43,	/* "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128" */
  [NET_VPN4]	= 40,	/* "4294967296:4294967296 255.255.255.255/32" */
  [NET_VPN6]	= 65,	/* "4294967296:4294967296 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128" */
  [NET_ROA4]	= 34,	/* "255.255.255.255/32-32 AS4294967295" */
  [NET_ROA6]	= 60,	/* "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128-128 AS4294967295" */
  [NET_FLOW4]	= 0,	/* "flow4 { ... }" */
  [NET_FLOW6]	= 0,	/* "flow6 { ... }" */
  [NET_IP6_SADR]= 92,	/* "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 from ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128" */
  [NET_MPLS]	= 7,	/* "1048575" */
};

/* There should be no implicit padding in net_addr structures */
STATIC_ASSERT(sizeof(net_addr)		== 24);
STATIC_ASSERT(sizeof(net_addr_ip4)	==  8);
STATIC_ASSERT(sizeof(net_addr_ip6)	== 20);
STATIC_ASSERT(sizeof(net_addr_vpn4)	== 16);
STATIC_ASSERT(sizeof(net_addr_vpn6)	== 32);
STATIC_ASSERT(sizeof(net_addr_roa4)	== 16);
STATIC_ASSERT(sizeof(net_addr_roa6)	== 28);
STATIC_ASSERT(sizeof(net_addr_flow4)	==  8);
STATIC_ASSERT(sizeof(net_addr_flow6)	== 20);
STATIC_ASSERT(sizeof(net_addr_ip6_sadr)	== 40);
STATIC_ASSERT(sizeof(net_addr_mpls)	==  8);


int
rd_format(const u64 rd, char *buf, int buflen)
{
  switch (rd >> 48)
  {
    case 0: return bsnprintf(buf, buflen, "%u:%u", (u32) (rd >> 32), (u32) rd);
    case 1: return bsnprintf(buf, buflen, "%I4:%u", ip4_from_u32(rd >> 16), (u32) (rd & 0xffff));
    case 2: if (((u32) (rd >> 16)) >> 16)
	      return bsnprintf(buf, buflen, "%u:%u", (u32) (rd >> 16), (u32) (rd & 0xffff));
	    else
	      return bsnprintf(buf, buflen, "2:%u:%u", (u32) (rd >> 16), (u32) (rd & 0xffff));
    default: return bsnprintf(buf, buflen, "X:%08x:%08x", (u32) (rd >> 32), (u32) rd);
  }
}

int
net_format(const net_addr *N, char *buf, int buflen)
{
  net_addr_union *n = (void *) N;
  buf[0] = 0;

  switch (n->n.type)
  {
  case NET_IP4:
    return bsnprintf(buf, buflen, "%I4/%d", n->ip4.prefix, n->ip4.pxlen);
  case NET_IP6:
    return bsnprintf(buf, buflen, "%I6/%d", n->ip6.prefix, n->ip6.pxlen);
  case NET_VPN4:
    {
    int c = rd_format(n->vpn4.rd, buf, buflen);
    ADVANCE(buf, buflen, c);
    return bsnprintf(buf, buflen, " %I4/%d", n->vpn4.prefix, n->vpn4.pxlen);
    }
  case NET_VPN6:
    {
    /* XXX: RD format is specified for VPN4; not found any for VPN6, reusing the same as for VPN4 */
    int c = rd_format(n->vpn6.rd, buf, buflen);
    ADVANCE(buf, buflen, c);
    return bsnprintf(buf, buflen, " %I6/%d", n->vpn6.prefix, n->vpn6.pxlen);
    }
  case NET_ROA4:
    return bsnprintf(buf, buflen, "%I4/%u-%u AS%u",  n->roa4.prefix, n->roa4.pxlen, n->roa4.max_pxlen, n->roa4.asn);
  case NET_ROA6:
    return bsnprintf(buf, buflen, "%I6/%u-%u AS%u",  n->roa6.prefix, n->roa6.pxlen, n->roa6.max_pxlen, n->roa6.asn);
  case NET_FLOW4:
    return flow4_net_format(buf, buflen, &n->flow4);
  case NET_FLOW6:
    return flow6_net_format(buf, buflen, &n->flow6);
  case NET_IP6_SADR:
    return bsnprintf(buf, buflen, "%I6/%d from %I6/%d", n->ip6_sadr.dst_prefix, n->ip6_sadr.dst_pxlen, n->ip6_sadr.src_prefix, n->ip6_sadr.src_pxlen);
  case NET_MPLS:
    return bsnprintf(buf, buflen, "%u", n->mpls.label);
  }

  bug("unknown network type");
}

ip_addr
net_pxmask(const net_addr *a)
{
  switch (a->type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
  case NET_FLOW4:
    return ipa_from_ip4(ip4_mkmask(net4_pxlen(a)));

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
  case NET_FLOW6:
  case NET_IP6_SADR:
    return ipa_from_ip6(ip6_mkmask(net6_pxlen(a)));

  case NET_MPLS:
  default:
    return IPA_NONE;
  }
}

int
net_compare(const net_addr *a, const net_addr *b)
{
  if (a->type != b->type)
    return uint_cmp(a->type, b->type);

  switch (a->type)
  {
  case NET_IP4:
    return net_compare_ip4((const net_addr_ip4 *) a, (const net_addr_ip4 *) b);
  case NET_IP6:
    return net_compare_ip6((const net_addr_ip6 *) a, (const net_addr_ip6 *) b);
  case NET_VPN4:
    return net_compare_vpn4((const net_addr_vpn4 *) a, (const net_addr_vpn4 *) b);
  case NET_VPN6:
    return net_compare_vpn6((const net_addr_vpn6 *) a, (const net_addr_vpn6 *) b);
  case NET_ROA4:
    return net_compare_roa4((const net_addr_roa4 *) a, (const net_addr_roa4 *) b);
  case NET_ROA6:
    return net_compare_roa6((const net_addr_roa6 *) a, (const net_addr_roa6 *) b);
  case NET_FLOW4:
    return net_compare_flow4((const net_addr_flow4 *) a, (const net_addr_flow4 *) b);
  case NET_FLOW6:
    return net_compare_flow6((const net_addr_flow6 *) a, (const net_addr_flow6 *) b);
  case NET_IP6_SADR:
    return net_compare_ip6_sadr((const net_addr_ip6_sadr *) a, (const net_addr_ip6_sadr *) b);
  case NET_MPLS:
    return net_compare_mpls((const net_addr_mpls *) a, (const net_addr_mpls *) b);
  }
  return 0;
}

#define NET_HASH(a,t) net_hash_##t((const net_addr_##t *) a)

u32
net_hash(const net_addr *n)
{
  switch (n->type)
  {
  case NET_IP4: return NET_HASH(n, ip4);
  case NET_IP6: return NET_HASH(n, ip6);
  case NET_VPN4: return NET_HASH(n, vpn4);
  case NET_VPN6: return NET_HASH(n, vpn6);
  case NET_ROA4: return NET_HASH(n, roa4);
  case NET_ROA6: return NET_HASH(n, roa6);
  case NET_FLOW4: return NET_HASH(n, flow4);
  case NET_FLOW6: return NET_HASH(n, flow6);
  case NET_IP6_SADR: return NET_HASH(n, ip6_sadr);
  case NET_MPLS: return NET_HASH(n, mpls);
  default: bug("invalid type");
  }
}


#define NET_VALIDATE(a,t) net_validate_##t((const net_addr_##t *) a)

int
net_validate(const net_addr *n)
{
  switch (n->type)
  {
  case NET_IP4: return NET_VALIDATE(n, ip4);
  case NET_IP6: return NET_VALIDATE(n, ip6);
  case NET_VPN4: return NET_VALIDATE(n, vpn4);
  case NET_VPN6: return NET_VALIDATE(n, vpn6);
  case NET_ROA4: return NET_VALIDATE(n, roa4);
  case NET_ROA6: return NET_VALIDATE(n, roa6);
  case NET_FLOW4: return NET_VALIDATE(n, flow4);
  case NET_FLOW6: return NET_VALIDATE(n, flow6);
  case NET_IP6_SADR: return NET_VALIDATE(n, ip6_sadr);
  case NET_MPLS: return NET_VALIDATE(n, mpls);
  default: return 0;
  }
}

void
net_normalize(net_addr *N)
{
  net_addr_union *n = (void *) N;

  switch (n->n.type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
  case NET_FLOW4:
    return net_normalize_ip4(&n->ip4);

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
  case NET_FLOW6:
    return net_normalize_ip6(&n->ip6);

  case NET_IP6_SADR:
    return net_normalize_ip6_sadr(&n->ip6_sadr);

  case NET_MPLS:
    return;
  }
}

int
net_classify(const net_addr *N)
{
  net_addr_union *n = (void *) N;

  switch (n->n.type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
  case NET_FLOW4:
    return ip4_zero(n->ip4.prefix) ? (IADDR_HOST | SCOPE_UNIVERSE) : ip4_classify(n->ip4.prefix);

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
  case NET_FLOW6:
    return ip6_zero(n->ip6.prefix) ? (IADDR_HOST | SCOPE_UNIVERSE) : ip6_classify(&n->ip6.prefix);

  case NET_IP6_SADR:
    return ip6_zero(n->ip6_sadr.dst_prefix) ? (IADDR_HOST | SCOPE_UNIVERSE) : ip6_classify(&n->ip6_sadr.dst_prefix);

  case NET_MPLS:
    return IADDR_HOST | SCOPE_UNIVERSE;
  }

  return IADDR_INVALID;
}

int
ipa_in_netX(const ip_addr a, const net_addr *n)
{
  switch (n->type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
  case NET_FLOW4:
    if (!ipa_is_ip4(a)) return 0;
    return ip4_zero(ip4_and(ip4_xor(ipa_to_ip4(a), net4_prefix(n)),
			    ip4_mkmask(net4_pxlen(n))));

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
  case NET_FLOW6:
    if (ipa_is_ip4(a)) return 0;
    return ip6_zero(ip6_and(ip6_xor(ipa_to_ip6(a), net6_prefix(n)),
			    ip6_mkmask(net6_pxlen(n))));

  case NET_IP6_SADR:
    if (ipa_is_ip4(a)) return 0;
    return ip6_zero(ip6_and(ip6_xor(ipa_to_ip6(a), net6_prefix(n)),
			    ip6_mkmask(net6_pxlen(n))));

  case NET_MPLS:
  default:
    return 0;
  }
}

int
net_in_netX(const net_addr *a, const net_addr *n)
{
  if (a->type != n->type)
    return 0;

  return (net_pxlen(n) <= net_pxlen(a)) && ipa_in_netX(net_prefix(a), n);
}
