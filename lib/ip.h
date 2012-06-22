/*
 *	BIRD Internet Routing Daemon -- The Internet Protocol
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_IP_H_
#define _BIRD_IP_H_

#include "lib/endian.h"
#include "lib/string.h"
#include "lib/bitops.h"
#include "lib/unaligned.h"


#ifdef DEBUGGING

/*
 *	Use the structural representation when you want to make sure
 *	nobody unauthorized attempts to handle ip_addr as number.
 */

typedef struct ip4_addr {
  u32 addr;
} ip4_addr;

#define _MI4(x) ((struct ip4_addr) { x })
#define _I(x) (x).addr

#else

typedef u32 ip4_addr;

#define _MI4(x) (x)
#define _I(x) (x)

#endif


typedef struct ip6_addr {
  u32 addr[4];
} ip6_addr;

#define _MI6(a,b,c,d) ((struct ip6_addr) {{ a, b, c, d }})
#define _I0(a) ((a).addr[0])
#define _I1(a) ((a).addr[1])
#define _I2(a) ((a).addr[2])
#define _I3(a) ((a).addr[3])


typedef ip6_addr ip_addr;



#define IPA_NONE IP6_NONE
#define IP4_NONE _MI4(0)
#define IP6_NONE _MI6(0,0,0,0)


/*
 *	ip_classify() returns either a negative number for invalid addresses
 *	or scope OR'ed together with address type.
 */
#define IADDR_INVALID		-1
#define IADDR_SCOPE_MASK       	0xfff
#define IADDR_HOST		0x1000
#define IADDR_BROADCAST		0x2000
#define IADDR_MULTICAST		0x4000


/*
 *	Address scope
 */
#define SCOPE_HOST 0
#define SCOPE_LINK 1
#define SCOPE_SITE 2
#define SCOPE_ORGANIZATION 3
#define SCOPE_UNIVERSE 4
#define SCOPE_UNDEFINED 5



#define ipa_equal(x,y) ip6_equal(x,y)
#define ipa_zero(x) ip6_zero(x)
#define ipa_nonzero(x) ip6_nonzero(x)
#define ipa_and(x,y) ip6_and(x,y)
#define ipa_or(x,y) ip6_or(x,y)
#define ipa_xor(x,y) ip6_xor(x,y)
#define ipa_not(x) ip6_not(x)

#define ip4_equal(x,y) (_I(x) == _I(y))
#define ip4_zero(x) (!_I(x))
#define ip4_nonzero(x) _I(x)
#define ip4_and(x,y) _MI4(_I(x) & _I(y))
#define ip4_or(x,y) _MI4(_I(x) | _I(y))
#define ip4_xor(x,y) _MI4(_I(x) ^ _I(y))
#define ip4_not(x) _MI4(~_I(x))

static inline int ip6_equal(ip6_addr a, ip6_addr b)
{ return _I0(a) == _I0(b) && _I1(a) == _I1(b) && _I2(a) == _I2(b) && _I3(a) == _I3(b); }

static inline int ip6_zero(ip6_addr a)
{ return  !_I0(a) && !_I1(a) && !_I2(a) && !_I3(a); }

static inline int ip6_nonzero(ip6_addr a)
{ return _I0(a) || _I1(a) || _I2(a) || _I3(a); }

static inline ip6_addr ip6_and(ip6_addr a, ip6_addr b)
{ return _MI6(_I0(a) & _I0(b), _I1(a) & _I1(b), _I2(a) & _I2(b), _I3(a) & _I3(b)); }

static inline ip6_addr ip6_or(ip6_addr a, ip6_addr b)
{ return _MI6(_I0(a) | _I0(b), _I1(a) | _I1(b), _I2(a) | _I2(b), _I3(a) | _I3(b)); }

static inline ip6_addr ip6_xor(ip6_addr a, ip6_addr b)
{ return _MI6(_I0(a) ^ _I0(b), _I1(a) ^ _I1(b), _I2(a) ^ _I2(b), _I3(a) ^ _I3(b)); }

static inline ip6_addr ip6_not(ip6_addr a)
{ return _MI6(~_I0(a), ~_I1(a), ~_I2(a), ~_I3(a)); }



#define ipa_from_ip4(x) _MI6(0,0,0xffff,_I(x))
#define ipa_from_ip6(x) x

#define ipa_to_ip4(x) _I3(x)
#define ipa_to_ip6(x) x

#define ip4_from_u32(x) _MI4(x)
#define ip4_to_u32(x) _I(x)

#define ipa_is_ip4(a) ip6_is_v4mapped(a)

#define ipa_build4(a,b,c,d) ipa_from_ip4(ip4_build(a,b,c,d))
#define ipa_build6(a,b,c,d) _MI6(a,b,c,d)

#define ip4_build(a,b,c,d) _MI4(((a) << 24) | ((b) << 16) | ((c) << 8) | (d))
#define ip6_build(a,b,c,d) _MI6(a,b,c,d)



#define ipa_hton(x) x = ip6_hton(x)
#define ipa_ntoh(x) x = ip6_ntoh(x)

#define ip4_hton(x) _MI4(htonl(_I(x)))
#define ip4_ntoh(x) _MI4(ntohl(_I(x)))

static inline ip6_addr ip6_hton(ip6_addr a)
{ return _MI6(htonl(_I0(a)), htonl(_I1(a)), htonl(_I2(a)), htonl(_I3(a))); }

static inline ip6_addr ip6_ntoh(ip6_addr a)
{ return _MI6(ntohl(_I0(a)), ntohl(_I1(a)), ntohl(_I2(a)), ntohl(_I3(a))); }



#define ipa_compare(a,b) ip6_compare(a,b)

static inline int ip4_compare(ip4_addr a, ip4_addr b)
{ return (_I(a) > _I(b)) - (_I(a) < _I(b)); }

int ip6_compare(ip6_addr a, ip6_addr b);



#define ipa_hash(a) ip6_hash(a)

static inline unsigned ip4_hash(ip4_addr a)
{
  /* Returns a 16-bit value */
  u32 x = _I(a);
  x ^= x >> 16;
  x ^= x << 10;
  return x & 0xffff;
}

/*
 *  This hash function looks well, but once IPv6 enters
 *  mainstream use, we need to check that it has good
 *  distribution properties on real routing tables.
 */

static inline unsigned ip6_hash(ip6_addr a)
{
  /* Returns a 16-bit hash key */
  u32 x = _I0(a) ^ _I1(a) ^ _I2(a) ^ _I3(a);
  return (x ^ (x >> 16) ^ (x >> 8)) & 0xffff;
}


#define ipa_classify(x) ip6_classify(&(x))
int ip4_classify(ip4_addr ad);
int ip6_classify(ip6_addr *a);

#define ipa_is_link_local(a) ip6_is_link_local(a)

static inline int ip6_is_link_local(ip6_addr a)
{ return (_I0(a) & 0xffc00000) == 0xfe800000; }

static inline int ip6_is_v4mapped(ip6_addr a)
{ return _I0(a) == 0 && _I1(a) == 0 && _I2(a) == 0xffff; }



#define ipa_mkmask(x) ip6_mkmask(x)
#define ipa_mklen(x) ip6_masklen(&x)	// XXXX: ipa_masklen()

#define ip4_mkmask(x) _MI4(u32_mkmask(x))
#define ip4_masklen(x) u32_masklen(_I(x))

ip6_addr ip6_mkmask(unsigned n);
unsigned ip6_masklen(ip_addr *a);	// XXXX: int or unsigned?



/* ipa_pxlen() requires that x != y */
#define ipa_pxlen(a,b) ip6_pxlen(a,b)

static inline u32 ip4_pxlen(ip4_addr a, ip4_addr b)
{ return 31 - u32_log2(_I(a) ^ _I(b)); }

static inline u32 ip6_pxlen(ip6_addr a, ip6_addr b)
{
  int i = 0;
  i+= (a.addr[i] == b.addr[i]);
  i+= (a.addr[i] == b.addr[i]);
  i+= (a.addr[i] == b.addr[i]);
  i+= (a.addr[i] == b.addr[i]);
  return 32 * i + 31 - u32_log2(a.addr[i] ^ b.addr[i]);
}



#define ipa_opposite_m1(x) ip6_opposite_m1(x)
#define ipa_opposite_m2(x) ip6_opposite_m2(x)

#define ip4_opposite_m1(x) _MI4(_I(x) ^ 1)
#define ip4_opposite_m2(x) _MI4(_I(x) ^ 3)

static inline ip6_addr ip6_opposite_m1(ip6_addr a)
{ return _MI6(_I0(a), _I1(a), _I2(a), _I3(a) ^ 1); }

static inline ip6_addr ip6_opposite_m2(ip6_addr a)
{ return _MI6(_I0(a), _I1(a), _I2(a), _I3(a) ^ 3); }



// XXXX
#define ipa_getbit(a,y) ip6_getbit(a,y) 

static inline u32 ip4_getbit(ip4_addr a, u32 pos)
{ return _I(a) & (0x80000000 >> pos); }

static inline u32 ip6_getbit(ip6_addr a, u32 pos)
{ return a.addr[pos / 32] & (0x80000000 >> (pos % 32)); }


// XXXX
#define ipa_put_addr(buf,a) ip6_put(buf,a)

static inline void * ip4_put(void *buf, ip4_addr a)
{
  put_u32(buf, _I(a));
  return buf+4;
}

static inline void * ip6_put(void *buf, ip6_addr a)
{
  a = ip6_hton(a);
  memcpy(buf, &a, 16);
  return buf+16;
}

static inline ip4_addr ip4_get(void *buf)
{
  return _MI4(get_u32(buf));
}

static inline ip6_addr ip6_get(void *buf)
{
  ip6_addr a;
  memcpy(&a, buf, 16);
  return ip6_ntoh(a);
}

static inline void * ip4_put32(void *buf, ip4_addr a)
{
  *(u32 *)buf = htonl(_I(a));
  return buf+4;
}

static inline void * ip6_put32(void *buf, ip6_addr a)
{
  u32 *b = buf;
  b[0] = htonl(_I0(a));
  b[1] = htonl(_I1(a));
  b[2] = htonl(_I2(a));
  b[3] = htonl(_I3(a));
  return buf+16;
}

static inline void * ip6_put32_ip4(void *buf, ip6_addr a)
{
  *(u32 *)buf = htonl(_I3(a));
  return buf+4;
}

static inline ip6_addr ipa_get_in4(struct in_addr *in)
{ return ipa_from_ip4(ip4_ntoh(*(ip4_addr *) in)); }

static inline ip6_addr ipa_get_in6(struct in6_addr *in)
{ return ip6_ntoh(*(ip6_addr *) in); }

// XXXX check callers
static inline void ipa_put_in4(struct in_addr *in, ip6_addr a)
{ ip6_put32_ip4(in, a); }

static inline void ipa_put_in6(struct in6_addr *in, ip6_addr a)
{ ip6_put32(in, a); }



/*
 *	Conversions between internal and string representation
 */

char *ip4_ntop(ip4_addr a, char *b);
char *ip6_ntop(ip6_addr a, char *b);

static inline char * ip4_ntox(ip4_addr a, char *b)
{ return b + bsprintf(b, "%08x", _I(a)); }

static inline char * ip6_ntox(ip6_addr a, char *b)
{ return b + bsprintf(b, "%08x.%08x.%08x.%08x", _I0(a), _I1(a), _I2(a), _I3(a)); }

int ip4_pton(char *a, ip4_addr *o);
int ip6_pton(char *a, ip6_addr *o);





















// XXXX process rest

struct prefix {
  ip_addr addr;
  unsigned int len;
};

#define ip_is_prefix(a,l) (!ipa_nonzero(ipa_and(a, ipa_not(ipa_mkmask(l)))))
#define ipa_in_net(x,n,p) (ipa_zero(ipa_and(ipa_xor((n),(x)),ipa_mkmask(p))))
#define net_in_net(n1,l1,n2,l2) (((l1) >= (l2)) && (ipa_zero(ipa_and(ipa_xor((n1),(n2)),ipa_mkmask(l2)))))

char *ip_scope_text(unsigned);

/*
 *	Network prefixes
 */

static inline int ipa_classify_net(ip_addr a)
{ return ipa_zero(a) ? (IADDR_HOST | SCOPE_UNIVERSE) : ipa_classify(a); }

/*
#define MAX_PREFIX_LENGTH 32
#define BITS_PER_IP_ADDRESS 32
#define STD_ADDRESS_P_LENGTH 15
#define SIZE_OF_IP_HEADER 24
*/



#define MAX_PREFIX_LENGTH 128
#define BITS_PER_IP_ADDRESS 128
#define STD_ADDRESS_P_LENGTH 39
#define SIZE_OF_IP_HEADER 40

#define ipa_class_mask(x) _MI4(ipv4_class_mask(_I(x)))


/*
#define ip_skip_header(x, y) ipv4_skip_header(x, y)

#define IP_PREC_INTERNET_CONTROL 0xc0
*/

u32 ipv4_class_mask(u32);
byte *ipv4_skip_header(byte *, int *);





/* In IPv6, SOCK_RAW does not return packet header */
#define ip_skip_header(x, y) x


/*
 *  RFC 1883 defines packet precendece, but RFC 2460 replaces it
 *  by generic Traffic Class ID with no defined semantics. Better
 *  not use it yet.
 */
#define IP_PREC_INTERNET_CONTROL -1

#endif
