/*
 *	BIRD -- BGP Attributes
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *	(c) 2008--2016 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2008--2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

#include <stdlib.h>

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "lib/attrs.h"
#include "nest/mpls.h"
#include "conf/conf.h"
#include "lib/resource.h"
#include "lib/string.h"
#include "lib/unaligned.h"
#include "lib/macro.h"

#include "bgp.h"

/*
 *   UPDATE message error handling
 *
 * All checks from RFC 4271 6.3 are done as specified with these exceptions:
 *  - The semantic check of an IP address from NEXT_HOP attribute is missing.
 *  - Checks of some optional attribute values are missing.
 *  - Syntactic and semantic checks of NLRIs (done in DECODE_PREFIX())
 *    are probably inadequate.
 *
 * Loop detection based on AS_PATH causes updates to be withdrawn. RFC
 * 4271 does not explicitly specify the behavior in that case.
 *
 * Loop detection related to route reflection (based on ORIGINATOR_ID
 * and CLUSTER_LIST) causes updates to be withdrawn. RFC 4456 8
 * specifies that such updates should be ignored, but that is generally
 * a bad idea.
 *
 * BGP attribute table has several hooks:
 *
 * export - Hook that validates and normalizes attribute during export phase.
 * Receives eattr, may modify it (e.g., sort community lists for canonical
 * representation), UNSET() it (e.g., skip empty lists), or REJECT() the route
 * if necessary. May assume that eattr has value valid w.r.t. its type, but may
 * be invalid w.r.t. BGP constraints. Optional.
 *
 * encode - Hook that converts internal representation to external one during
 * packet writing. Receives eattr and puts it in the buffer (including attribute
 * header). Returns number of bytes, or -1 if not enough space. May assume that
 * eattr has value valid w.r.t. its type and validated by export hook. Mandatory
 * for all known attributes that exist internally after export phase (i.e., all
 * except pseudoattributes MP_(UN)REACH_NLRI).
 *
 * decode - Hook that converts external representation to internal one during
 * packet parsing. Receives attribute data in buffer, validates it and adds
 * attribute to ea_list. If data are invalid, steps DISCARD(), WITHDRAW() or
 * bgp_parse_error() may be used to escape. Mandatory for all known attributes.
 *
 * format - Optional hook that converts eattr to textual representation.
 */

union bgp_attr_desc {
  struct ea_class class;
  struct {
    EA_CLASS_INSIDE;
    void (*export)(struct bgp_export_state *s, eattr *a);
    int  (*encode)(struct bgp_write_state *s, eattr *a, byte *buf, uint size);
    void (*decode)(struct bgp_parse_state *s, uint code, uint flags, byte *data, uint len, ea_list **to);
  };
};

static union bgp_attr_desc bgp_attr_table[];
static inline const union bgp_attr_desc *bgp_find_attr_desc(eattr *a)
{
  const struct ea_class *class = ea_class_find(a->id);

  if ((class < &bgp_attr_table[0].class) || (class >= &bgp_attr_table[BGP_ATTR_MAX].class))
    return NULL;

  return (const union bgp_attr_desc *) class;
}

#define BGP_EA_ID(code)	(bgp_attr_table[code].id)
#define EA_BGP_ID(code)	(((union bgp_attr_desc *) ea_class_find(code)) - bgp_attr_table)

void bgp_set_attr_u32(ea_list **to, uint code, uint flags, u32 val)
{
  const union bgp_attr_desc *desc = &bgp_attr_table[code];

  ea_set_attr(to, EA_LITERAL_EMBEDDED(
	&desc->class,
	desc->flags | (flags & BAF_PARTIAL),
	val
	));
}

void bgp_set_attr_ptr(ea_list **to, uint code, uint flags, const struct adata *ad)
{
  const union bgp_attr_desc *desc = &bgp_attr_table[code];

  ea_set_attr(to, EA_LITERAL_DIRECT_ADATA(
	&desc->class,
	desc->flags | (flags & BAF_PARTIAL),
	ad
	));
}

void
bgp_set_attr_data(ea_list **to, uint code, uint flags, void *data, uint len)
{
  const union bgp_attr_desc *desc = &bgp_attr_table[code];

  ea_set_attr(to, EA_LITERAL_STORE_ADATA(
	&desc->class,
	desc->flags | (flags & BAF_PARTIAL),
	data,
	len
	));
}

void
bgp_unset_attr(ea_list **to, uint code)
{
  const union bgp_attr_desc *desc = &bgp_attr_table[code];
  ea_unset_attr(to, 0, &desc->class);
}

#define REPORT(msg, args...) \
  ({ log(L_REMOTE "%s: " msg, s->proto->p.name, ## args); })

#define RTRACE(msg, args...) \
  ({ if (s->proto->p.debug & D_ROUTES) \
   log(L_TRACE "%s: " msg, s->proto->p.name, ## args); })

#define DISCARD(msg, args...) \
  ({ REPORT(msg, ## args); return; })

#define WITHDRAW(msg, args...) \
  ({ REPORT(msg, ## args); s->err_withdraw = 1; return; })

#define UNSET(a) \
  ({ a->undef = 1; return; })

#define REJECT(msg, args...) \
  ({ log(L_ERR "%s: " msg, s->proto->p.name, ## args); s->err_reject = 1; return; })

#define NEW_BGP		"Discarding %s attribute received from AS4-aware neighbor"
#define BAD_EBGP	"Discarding %s attribute received from EBGP neighbor"
#define BAD_LENGTH	"Malformed %s attribute - invalid length (%u)"
#define BAD_VALUE	"Malformed %s attribute - invalid value (%u)"
#define NO_MANDATORY	"Missing mandatory %s attribute"


static inline int
bgp_put_attr_hdr3(byte *buf, uint code, uint flags, uint len)
{
  *buf++ = flags & ~BAF_EXT_LEN;
  *buf++ = code;
  *buf++ = len;
  return 3;
}

static inline int
bgp_put_attr_hdr4(byte *buf, uint code, uint flags, uint len)
{
  *buf++ = flags | BAF_EXT_LEN;
  *buf++ = code;
  put_u16(buf, len);
  return 4;
}

static inline int
bgp_put_attr_hdr(byte *buf, uint code, uint flags, uint len)
{
  if (len < 256)
    return bgp_put_attr_hdr3(buf, code, flags, len);
  else
    return bgp_put_attr_hdr4(buf, code, flags, len);
}

static int
bgp_encode_u8(struct bgp_write_state *s UNUSED, eattr *a, byte *buf, uint size)
{
  if (size < (3+1))
    return -1;

  bgp_put_attr_hdr3(buf, EA_BGP_ID(a->id), a->flags, 1);
  buf[3] = a->u.data;

  return 3+1;
}

static int
bgp_encode_u32(struct bgp_write_state *s UNUSED, eattr *a, byte *buf, uint size)
{
  if (size < (3+4))
    return -1;

  bgp_put_attr_hdr3(buf, EA_BGP_ID(a->id), a->flags, 4);
  put_u32(buf+3, a->u.data);

  return 3+4;
}

static int
bgp_encode_u32s(struct bgp_write_state *s UNUSED, eattr *a, byte *buf, uint size)
{
  uint len = a->u.ptr->length;

  if (size < (4+len))
    return -1;

  uint hdr = bgp_put_attr_hdr(buf, EA_BGP_ID(a->id), a->flags, len);
  put_u32s(buf + hdr, (u32 *) a->u.ptr->data, len / 4);

  return hdr + len;
}

static int
bgp_put_attr(byte *buf, uint size, uint code, uint flags, const byte *data, uint len)
{
  if (size < (4+len))
    return -1;

  uint hdr = bgp_put_attr_hdr(buf, code, flags, len);
  memcpy(buf + hdr, data, len);

  return hdr + len;
}

static int
bgp_encode_raw(struct bgp_write_state *s UNUSED, eattr *a, byte *buf, uint size)
{
  return bgp_put_attr(buf, size, EA_BGP_ID(a->id), a->flags, a->u.ptr->data, a->u.ptr->length);
}


/*
 *	AIGP handling
 */

static int
bgp_aigp_valid(byte *data, uint len, char *err, uint elen)
{
  byte *pos = data;
  char *err_dsc = NULL;
  uint err_val = 0;

#define BAD(DSC,VAL) ({ err_dsc = DSC; err_val = VAL; goto bad; })
  while (len)
  {
    if (len < 3)
      BAD("TLV framing error", len);

    /* Process one TLV */
    uint ptype = pos[0];
    uint plen = get_u16(pos + 1);

    if (len < plen)
      BAD("TLV framing error", plen);

    if (plen < 3)
      BAD("Bad TLV length", plen);

    if ((ptype == BGP_AIGP_METRIC) && (plen != 11))
      BAD("Bad AIGP TLV length", plen);

    ADVANCE(pos, len, plen);
  }
#undef BAD

  return 1;

bad:
  if (err)
    if (bsnprintf(err, elen, "%s (%u) at %d", err_dsc, err_val, (int) (pos - data)) < 0)
      err[0] = 0;

  return 0;
}

static const byte *
bgp_aigp_get_tlv(const struct adata *ad, uint type)
{
  if (!ad)
    return NULL;

  uint len = ad->length;
  const byte *pos = ad->data;

  while (len)
  {
    uint ptype = pos[0];
    uint plen = get_u16(pos + 1);

    if (ptype == type)
      return pos;

    ADVANCE(pos, len, plen);
  }

  return NULL;
}

static const struct adata *
bgp_aigp_set_tlv(struct linpool *pool, const struct adata *ad, uint type, byte *data, uint dlen)
{
  uint len = ad ? ad->length : 0;
  const byte *pos = ad ? ad->data : NULL;
  struct adata *res = lp_alloc_adata(pool, len + 3 + dlen);
  byte *dst = res->data;
  byte *tlv = NULL;
  int del = 0;

  while (len)
  {
    uint ptype = pos[0];
    uint plen = get_u16(pos + 1);

    /* Find position for new TLV */
    if ((ptype >= type) && !tlv)
    {
      tlv = dst;
      dst += 3 + dlen;
    }

    /* Skip first matching TLV, copy others */
    if ((ptype == type) && !del)
      del = 1;
    else
    {
      memcpy(dst, pos, plen);
      dst += plen;
    }

    ADVANCE(pos, len, plen);
  }

  if (!tlv)
  {
    tlv = dst;
    dst += 3 + dlen;
  }

  /* Store the TLD */
  put_u8(tlv + 0, type);
  put_u16(tlv + 1, 3 + dlen);
  memcpy(tlv + 3, data, dlen);

  /* Update length */
  res->length = dst - res->data;

  return res;
}

static u64 UNUSED
bgp_aigp_get_metric(const struct adata *ad, u64 def)
{
  const byte *b = bgp_aigp_get_tlv(ad, BGP_AIGP_METRIC);
  return b ? get_u64(b + 3) : def;
}

static const struct adata *
bgp_aigp_set_metric(struct linpool *pool, const struct adata *ad, u64 metric)
{
  byte data[8];
  put_u64(data, metric);
  return bgp_aigp_set_tlv(pool, ad, BGP_AIGP_METRIC, data, 8);
}

int
bgp_total_aigp_metric_(const rte *e, u64 *metric, const struct adata **ad)
{
  eattr *a = ea_find(e->attrs, BGP_EA_ID(BA_AIGP));
  if (!a)
    return 0;

  const byte *b = bgp_aigp_get_tlv(a->u.ptr, BGP_AIGP_METRIC);
  if (!b)
    return 0;

  u64 aigp = get_u64(b + 3);
  u64 step = rt_get_igp_metric(e);

  if (!rte_resolvable(e) || (step >= IGP_METRIC_UNKNOWN))
    step = BGP_AIGP_MAX;

  if (!step)
    step = 1;

  *ad = a->u.ptr;
  *metric = aigp + step;
  if (*metric < aigp)
    *metric = BGP_AIGP_MAX;

  return 1;
}

static inline int
bgp_init_aigp_metric(rte *e, u64 *metric, const struct adata **ad)
{
  if (rt_get_source_attr(e) == RTS_BGP)
    return 0;

  *metric = rt_get_igp_metric(e);
  *ad = NULL;
  return *metric < IGP_METRIC_UNKNOWN;
}

u32
bgp_rte_igp_metric(const rte *rt)
{
  u64 metric = bgp_total_aigp_metric(rt);
  return (u32) MIN(metric, (u64) IGP_METRIC_UNKNOWN);
}


/*
 *	Attribute hooks
 */

static void
bgp_export_origin(struct bgp_export_state *s, eattr *a)
{
  if (a->u.data > 2)
    REJECT(BAD_VALUE, "ORIGIN", a->u.data);
}

static void
bgp_decode_origin(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (len != 1)
    WITHDRAW(BAD_LENGTH, "ORIGIN", len);

  if (data[0] > 2)
    WITHDRAW(BAD_VALUE, "ORIGIN", data[0]);

  bgp_set_attr_u32(to, BA_ORIGIN, flags, data[0]);
}

static void
bgp_format_origin(const eattr *a, byte *buf, uint size UNUSED)
{
  static const char *bgp_origin_names[] = { "IGP", "EGP", "Incomplete" };

  bsprintf(buf, (a->u.data <= 2) ? bgp_origin_names[a->u.data] : "?");
}


static inline int
bgp_as_path_first_as_equal(const byte *data, uint len, u32 asn)
{
  return (len >= 6) &&
    ((data[0] == AS_PATH_SEQUENCE) || (data[0] == AS_PATH_CONFED_SEQUENCE)) &&
    (data[1] > 0) &&
    (get_u32(data+2) == asn);
}

static int
bgp_encode_as_path(struct bgp_write_state *s, eattr *a, byte *buf, uint size)
{
  const byte *data = a->u.ptr->data;
  uint len = a->u.ptr->length;

  if (!s->as4_session)
  {
    /* Prepare 16-bit AS_PATH (from 32-bit one) in a temporary buffer */
    byte *dst = alloca(len);
    len = as_path_32to16(dst, data, len);
    data = dst;
  }

  return bgp_put_attr(buf, size, BA_AS_PATH, a->flags, data, len);
}

static void
bgp_decode_as_path(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  struct bgp_proto *p = s->proto;
  int as_length = s->as4_session ? 4 : 2;
  int as_sets = p->cf->allow_as_sets;
  int as_confed = p->cf->confederation && p->is_interior;
  char err[128];

  if (!as_path_valid(data, len, as_length, as_sets, as_confed, err, sizeof(err)))
    WITHDRAW("Malformed AS_PATH attribute - %s", err);

  if (!s->as4_session)
  {
    /* Prepare 32-bit AS_PATH (from 16-bit one) in a temporary buffer */
    byte *src = data;
    data = alloca(2*len);
    len = as_path_16to32(data, src, len);
  }

  /* In some circumstances check for initial AS_CONFED_SEQUENCE; RFC 5065 5.0 */
  if (p->is_interior && !p->is_internal &&
      ((len < 2) || (data[0] != AS_PATH_CONFED_SEQUENCE)))
    WITHDRAW("Malformed AS_PATH attribute - %s", "missing initial AS_CONFED_SEQUENCE");

  /* Reject routes with first AS in AS_PATH not matching neighbor AS; RFC 4271 6.3 */
  if (!p->is_internal && p->cf->enforce_first_as &&
      !bgp_as_path_first_as_equal(data, len, p->remote_as))
    WITHDRAW("Malformed AS_PATH attribute - %s", "First AS differs from neigbor AS");

  bgp_set_attr_data(to, BA_AS_PATH, flags, data, len);
}


static int
bgp_encode_next_hop(struct bgp_write_state *s, eattr *a, byte *buf, uint size)
{
  /*
   * The NEXT_HOP attribute is used only in traditional (IPv4) BGP. In MP-BGP,
   * the next hop is encoded as a part of the MP_REACH_NLRI attribute, so we
   * store it and encode it later by AFI-specific hooks.
   */

  if (!s->mp_reach)
  {
    // ASSERT(a->u.ptr->length == sizeof(ip_addr));

    /* FIXME: skip IPv6 next hops for IPv4 routes during MRT dump */
    ip_addr *addr = (void *) a->u.ptr->data;
    if ((a->u.ptr->length != sizeof(ip_addr)) || !ipa_is_ip4(*addr))
      return 0;

    if (size < (3+4))
      return -1;

    bgp_put_attr_hdr3(buf, BA_NEXT_HOP, a->flags, 4);
    put_ip4(buf+3, ipa_to_ip4(*addr));

    return 3+4;
  }
  else
  {
    s->mp_next_hop = a;
    return 0;
  }
}

static void
bgp_decode_next_hop(struct bgp_parse_state *s, uint code UNUSED, uint flags UNUSED, byte *data, uint len, ea_list **to UNUSED)
{
  if (len != 4)
    WITHDRAW(BAD_LENGTH, "NEXT_HOP", len);

  /* Semantic checks are done later */
  s->ip_next_hop_len = len;
  s->ip_next_hop_data = data;
}

/* TODO: This function should use AF-specific hook */
static void
bgp_format_next_hop(const eattr *a, byte *buf, uint size UNUSED)
{
  ip_addr *nh = (void *) a->u.ptr->data;
  uint len = a->u.ptr->length;

  ASSERT((len == 16) || (len == 32));

  /* in IPv6, we may have two addresses in NEXT HOP */
  if ((len == 16) || ipa_zero(nh[1]))
    bsprintf(buf, "%I", nh[0]);
  else
    bsprintf(buf, "%I %I", nh[0], nh[1]);
}


static void
bgp_decode_med(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (len != 4)
    WITHDRAW(BAD_LENGTH, "MULTI_EXIT_DISC", len);

  u32 val = get_u32(data);
  bgp_set_attr_u32(to, BA_MULTI_EXIT_DISC, flags, val);
}


static void
bgp_export_local_pref(struct bgp_export_state *s, eattr *a)
{
  if (!s->proto->is_interior && !s->proto->cf->allow_local_pref)
    UNSET(a);
}

static void
bgp_decode_local_pref(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (!s->proto->is_interior && !s->proto->cf->allow_local_pref)
    DISCARD(BAD_EBGP, "LOCAL_PREF");

  if (len != 4)
    WITHDRAW(BAD_LENGTH, "LOCAL_PREF", len);

  u32 val = get_u32(data);
  bgp_set_attr_u32(to, BA_LOCAL_PREF, flags, val);
}


static void
bgp_decode_atomic_aggr(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data UNUSED, uint len, ea_list **to)
{
  if (len != 0)
    DISCARD(BAD_LENGTH, "ATOMIC_AGGR", len);

  bgp_set_attr_data(to, BA_ATOMIC_AGGR, flags, NULL, 0);
}

static int
bgp_encode_aggregator(struct bgp_write_state *s, eattr *a, byte *buf, uint size)
{
  const byte *data = a->u.ptr->data;
  uint len = a->u.ptr->length;

  if (!s->as4_session)
  {
    /* Prepare 16-bit AGGREGATOR (from 32-bit one) in a temporary buffer */
    byte *dst = alloca(6);
    len = aggregator_32to16(dst, data);
    data = dst;
  }

  return bgp_put_attr(buf, size, BA_AGGREGATOR, a->flags, data, len);
}

static void
bgp_decode_aggregator(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (len != (s->as4_session ? 8 : 6))
    DISCARD(BAD_LENGTH, "AGGREGATOR", len);

  if (!s->as4_session)
  {
    /* Prepare 32-bit AGGREGATOR (from 16-bit one) in a temporary buffer */
    byte *src = data;
    data = alloca(8);
    len = aggregator_16to32(data, src);
  }

  bgp_set_attr_data(to, BA_AGGREGATOR, flags, data, len);
}

static void
bgp_format_aggregator(const eattr *a, byte *buf, uint size UNUSED)
{
  const byte *data = a->u.ptr->data;

  bsprintf(buf, "%I4 AS%u", get_ip4(data+4), get_u32(data+0));
}


static void
bgp_export_community(struct bgp_export_state *s, eattr *a)
{
  if (a->u.ptr->length == 0)
    UNSET(a);

  a->u.ptr = int_set_sort(s->pool, a->u.ptr);
}

static void
bgp_decode_community(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (!len || (len % 4))
    WITHDRAW(BAD_LENGTH, "COMMUNITY", len);

  struct adata *ad = lp_alloc_adata(s->pool, len);
  get_u32s(data, (u32 *) ad->data, len / 4);
  bgp_set_attr_ptr(to, BA_COMMUNITY, flags, ad);
}


static void
bgp_export_originator_id(struct bgp_export_state *s, eattr *a)
{
  if (!s->proto->is_internal)
    UNSET(a);
}

static void
bgp_decode_originator_id(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (!s->proto->is_internal)
    DISCARD(BAD_EBGP, "ORIGINATOR_ID");

  if (len != 4)
    WITHDRAW(BAD_LENGTH, "ORIGINATOR_ID", len);

  u32 val = get_u32(data);
  bgp_set_attr_u32(to, BA_ORIGINATOR_ID, flags, val);
}


static void
bgp_export_cluster_list(struct bgp_export_state *s UNUSED, eattr *a)
{
  if (!s->proto->is_internal)
    UNSET(a);

  if (a->u.ptr->length == 0)
    UNSET(a);
}

static void
bgp_decode_cluster_list(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (!s->proto->is_internal)
    DISCARD(BAD_EBGP, "CLUSTER_LIST");

  if (!len || (len % 4))
    WITHDRAW(BAD_LENGTH, "CLUSTER_LIST", len);

  struct adata *ad = lp_alloc_adata(s->pool, len);
  get_u32s(data, (u32 *) ad->data, len / 4);
  bgp_set_attr_ptr(to, BA_CLUSTER_LIST, flags, ad);
}

static void
bgp_format_cluster_list(const eattr *a, byte *buf, uint size)
{
  /* Truncates cluster lists larger than buflen, probably not a problem */
  int_set_format(a->u.ptr, 0, -1, buf, size);
}


int
bgp_encode_mp_reach_mrt(struct bgp_write_state *s UNUSED, eattr *a, byte *buf, uint size)
{
  /*
   *	Limited version of MP_REACH_NLRI used for MRT table dumps (IPv6 only):
   *
   *	3 B	MP_REACH_NLRI header
   *	1 B	MP_REACH_NLRI data - Length of Next Hop Network Address
   *	var	MP_REACH_NLRI data - Network Address of Next Hop
   */

  ip_addr *nh = (void *) a->u.ptr->data;
  uint len = a->u.ptr->length;

  ASSERT((len == 16) || (len == 32));

  if (size < (3+1+len))
    return -1;

  bgp_put_attr_hdr3(buf, BA_MP_REACH_NLRI, BAF_OPTIONAL, 1+len);
  buf[3] = len;
  buf += 4;

  put_ip6(buf, ipa_to_ip6(nh[0]));

  if (len == 32)
    put_ip6(buf+16, ipa_to_ip6(nh[1]));

  return 3+1+len;
}

static inline u32
get_af3(byte *buf)
{
  return (get_u16(buf) << 16) | buf[2];
}

static void
bgp_decode_mp_reach_nlri(struct bgp_parse_state *s, uint code UNUSED, uint flags UNUSED, byte *data, uint len, ea_list **to UNUSED)
{
  /*
   *	2 B	MP_REACH_NLRI data - Address Family Identifier
   *	1 B	MP_REACH_NLRI data - Subsequent Address Family Identifier
   *	1 B	MP_REACH_NLRI data - Length of Next Hop Network Address
   *	var	MP_REACH_NLRI data - Network Address of Next Hop
   *	1 B	MP_REACH_NLRI data - Reserved (zero)
   *	var	MP_REACH_NLRI data - Network Layer Reachability Information
   */

  if ((len < 5) || (len < (5 + (uint) data[3])))
    bgp_parse_error(s, 9);

  s->mp_reach_af = get_af3(data);
  s->mp_next_hop_len = data[3];
  s->mp_next_hop_data = data + 4;
  s->mp_reach_len = len - 5 - s->mp_next_hop_len;
  s->mp_reach_nlri = data + 5 + s->mp_next_hop_len;
}


static void
bgp_decode_mp_unreach_nlri(struct bgp_parse_state *s, uint code UNUSED, uint flags UNUSED, byte *data, uint len, ea_list **to UNUSED)
{
  /*
   *	2 B	MP_UNREACH_NLRI data - Address Family Identifier
   *	1 B	MP_UNREACH_NLRI data - Subsequent Address Family Identifier
   *	var	MP_UNREACH_NLRI data - Network Layer Reachability Information
   */

  if (len < 3)
    bgp_parse_error(s, 9);

  s->mp_unreach_af = get_af3(data);
  s->mp_unreach_len = len - 3;
  s->mp_unreach_nlri = data + 3;
}


static void
bgp_export_ext_community(struct bgp_export_state *s, eattr *a)
{
  if (!s->proto->is_interior)
  {
    struct adata *ad = ec_set_del_nontrans(s->pool, a->u.ptr);

    if (ad->length == 0)
      UNSET(a);

    ec_set_sort_x(ad);
    a->u.ptr = ad;
  }
  else
  {
    if (a->u.ptr->length == 0)
      UNSET(a);

    a->u.ptr = ec_set_sort(s->pool, a->u.ptr);
  }
}

static void
bgp_decode_ext_community(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (!len || (len % 8))
    WITHDRAW(BAD_LENGTH, "EXT_COMMUNITY", len);

  struct adata *ad = lp_alloc_adata(s->pool, len);
  get_u32s(data, (u32 *) ad->data, len / 4);
  bgp_set_attr_ptr(to, BA_EXT_COMMUNITY, flags, ad);
}


static void
bgp_decode_as4_aggregator(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (s->as4_session)
    DISCARD(NEW_BGP, "AS4_AGGREGATOR");

  if (len != 8)
    DISCARD(BAD_LENGTH, "AS4_AGGREGATOR", len);

  bgp_set_attr_data(to, BA_AS4_AGGREGATOR, flags, data, len);
}

static void
bgp_decode_as4_path(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  struct bgp_proto *p = s->proto;
  int sets = p->cf->allow_as_sets;

  char err[128];

  if (s->as4_session)
    DISCARD(NEW_BGP, "AS4_PATH");

  if (len < 6)
    DISCARD(BAD_LENGTH, "AS4_PATH", len);

  if (!as_path_valid(data, len, 4, sets, 1, err, sizeof(err)))
    DISCARD("Malformed AS4_PATH attribute - %s", err);

  struct adata *a = lp_alloc_adata(s->pool, len);
  memcpy(a->data, data, len);

  /* AS_CONFED* segments are invalid in AS4_PATH; RFC 6793 6 */
  if (as_path_contains_confed(a))
  {
    REPORT("Discarding AS_CONFED* segment from AS4_PATH attribute");
    a = as_path_strip_confed(s->pool, a);
  }

  bgp_set_attr_ptr(to, BA_AS4_PATH, flags, a);
}


static void
bgp_export_aigp(struct bgp_export_state *s, eattr *a)
{
  if (!s->channel->cf->aigp)
    UNSET(a);
}

static void
bgp_decode_aigp(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  char err[128];

  /* Acceptability test postponed to bgp_finish_attrs() */

  if ((flags ^ bgp_attr_table[BA_AIGP].flags) & (BAF_OPTIONAL | BAF_TRANSITIVE))
    DISCARD("Malformed AIGP attribute - conflicting flags (%02x)", flags);

  if (!bgp_aigp_valid(data, len, err, sizeof(err)))
    DISCARD("Malformed AIGP attribute - %s", err);

  bgp_set_attr_data(to, BA_AIGP, flags, data, len);
}

static void
bgp_format_aigp(const eattr *a, byte *buf, uint size UNUSED)
{
  const byte *b = bgp_aigp_get_tlv(a->u.ptr, BGP_AIGP_METRIC);

  if (!b)
    bsprintf(buf, "?");
  else
    bsprintf(buf, "%lu", get_u64(b + 3));
}


static void
bgp_export_large_community(struct bgp_export_state *s, eattr *a)
{
  if (a->u.ptr->length == 0)
    UNSET(a);

  a->u.ptr = lc_set_sort(s->pool, a->u.ptr);
}

static void
bgp_decode_large_community(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (!len || (len % 12))
    WITHDRAW(BAD_LENGTH, "LARGE_COMMUNITY", len);

  struct adata *ad = lp_alloc_adata(s->pool, len);
  get_u32s(data, (u32 *) ad->data, len / 4);
  bgp_set_attr_ptr(to, BA_LARGE_COMMUNITY, flags, ad);
}


static void
bgp_decode_otc(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data UNUSED, uint len, ea_list **to)
{
  if (len != 4)
    WITHDRAW(BAD_LENGTH, "OTC", len);

  u32 val = get_u32(data);
  bgp_set_attr_u32(to, BA_ONLY_TO_CUSTOMER, flags, val);
}


static void
bgp_export_mpls_label_stack(struct bgp_export_state *s, eattr *a)
{
  const net_addr *n = s->route->net;
  u32 *labels = (u32 *) a->u.ptr->data;
  uint lnum = a->u.ptr->length / 4;

  /* Perhaps we should just ignore it? */
  if (!s->mpls)
    REJECT("Unexpected MPLS stack");

  /* Empty MPLS stack is not allowed */
  if (!lnum)
    REJECT("Malformed MPLS stack - empty");

  /* This is ugly, but we must ensure that labels fit into NLRI field */
  if ((24*lnum + (net_is_vpn(n) ? 64 : 0) + net_pxlen(n)) > 255)
    REJECT("Malformed MPLS stack - too many labels (%u)", lnum);

  for (uint i = 0; i < lnum; i++)
  {
    if (labels[i] > 0xfffff)
      REJECT("Malformed MPLS stack - invalid label (%u)", labels[i]);

    /* TODO: Check for special-purpose label values? */
  }
}

static int
bgp_encode_mpls_label_stack(struct bgp_write_state *s, eattr *a, byte *buf UNUSED, uint size UNUSED)
{
  /*
   * MPLS labels are encoded as a part of the NLRI in MP_REACH_NLRI attribute,
   * so we store MPLS_LABEL_STACK and encode it later by AFI-specific hooks.
   */

  s->mpls_labels = a->u.ptr;
  return 0;
}

static void
bgp_decode_mpls_label_stack(struct bgp_parse_state *s, uint code UNUSED, uint flags UNUSED, byte *data UNUSED, uint len UNUSED, ea_list **to UNUSED)
{
  DISCARD("Discarding received attribute #0");
}

static void
bgp_format_mpls_label_stack(const eattr *a, byte *buf, uint size)
{
  u32 *labels = (u32 *) a->u.ptr->data;
  uint lnum = a->u.ptr->length / 4;
  char *pos = buf;

  for (uint i = 0; i < lnum; i++)
  {
    if (size < 20)
    {
      bsprintf(pos, "...");
      return;
    }

    uint l = bsprintf(pos, "%d/", labels[i]);
    ADVANCE(pos, size, l);
  }

  /* Clear last slash or terminate empty string */
  pos[lnum ? -1 : 0] = 0;
}

static inline void
bgp_export_unknown(struct bgp_export_state *s UNUSED, eattr *a)
{
  if (!(a->flags & BAF_TRANSITIVE))
    UNSET(a);

  a->flags |= BAF_PARTIAL;
}

static inline void
bgp_decode_unknown(struct bgp_parse_state *s UNUSED, uint code, uint flags, byte *data, uint len, ea_list **to)
{
  if (!(flags & BAF_OPTIONAL))
    WITHDRAW("Unknown attribute (code %u) - conflicting flags (%02x)", code, flags);

  /* Cannot use bgp_set_attr_data() as it works on known attributes only */
  ea_set_attr_data(to, &bgp_attr_table[code].class, flags, data, len);
}

static inline void
bgp_format_unknown(const eattr *a, byte *buf, uint size)
{
  if (a->flags & BAF_TRANSITIVE)
    bsnprintf(buf, size, "(transitive)");
}


/*
 *	Attribute table
 */

static union bgp_attr_desc bgp_attr_table[BGP_ATTR_MAX] = {
  [BA_ORIGIN] = {
    .name = "bgp_origin",
    .type = T_ENUM_BGP_ORIGIN,
    .flags = BAF_TRANSITIVE,
    .export = bgp_export_origin,
    .encode = bgp_encode_u8,
    .decode = bgp_decode_origin,
    .format = bgp_format_origin,
  },
  [BA_AS_PATH] = {
    .name = "bgp_path",
    .type = T_PATH,
    .flags = BAF_TRANSITIVE,
    .encode = bgp_encode_as_path,
    .decode = bgp_decode_as_path,
  },
  [BA_NEXT_HOP] = {
    .name = "bgp_next_hop",
    .type = T_IP,
    .flags = BAF_TRANSITIVE,
    .encode = bgp_encode_next_hop,
    .decode = bgp_decode_next_hop,
    .format = bgp_format_next_hop,
  },
  [BA_MULTI_EXIT_DISC] = {
    .name = "bgp_med",
    .type = T_INT,
    .flags = BAF_OPTIONAL,
    .encode = bgp_encode_u32,
    .decode = bgp_decode_med,
  },
  [BA_LOCAL_PREF] = {
    .name = "bgp_local_pref",
    .type = T_INT,
    .flags = BAF_TRANSITIVE,
    .export = bgp_export_local_pref,
    .encode = bgp_encode_u32,
    .decode = bgp_decode_local_pref,
  },
  [BA_ATOMIC_AGGR] = {
    .name = "bgp_atomic_aggr",
    .type = T_OPAQUE,
    .flags = BAF_TRANSITIVE,
    .encode = bgp_encode_raw,
    .decode = bgp_decode_atomic_aggr,
  },
  [BA_AGGREGATOR] = {
    .name = "bgp_aggregator",
    .type = T_OPAQUE,
    .flags = BAF_OPTIONAL | BAF_TRANSITIVE,
    .encode = bgp_encode_aggregator,
    .decode = bgp_decode_aggregator,
    .format = bgp_format_aggregator,
  },
  [BA_COMMUNITY] = {
    .name = "bgp_community",
    .type = T_CLIST,
    .flags = BAF_OPTIONAL | BAF_TRANSITIVE,
    .export = bgp_export_community,
    .encode = bgp_encode_u32s,
    .decode = bgp_decode_community,
  },
  [BA_ORIGINATOR_ID] = {
    .name = "bgp_originator_id",
    .type = T_QUAD,
    .flags = BAF_OPTIONAL,
    .export = bgp_export_originator_id,
    .encode = bgp_encode_u32,
    .decode = bgp_decode_originator_id,
  },
  [BA_CLUSTER_LIST] = {
    .name = "bgp_cluster_list",
    .type = T_CLIST,
    .flags = BAF_OPTIONAL,
    .export = bgp_export_cluster_list,
    .encode = bgp_encode_u32s,
    .decode = bgp_decode_cluster_list,
    .format = bgp_format_cluster_list,
  },
  [BA_MP_REACH_NLRI] = {
    .name = "bgp_mp_reach_nlri",
    .type = T_OPAQUE,
    .hidden = 1,
    .flags = BAF_OPTIONAL,
    .decode = bgp_decode_mp_reach_nlri,
  },
  [BA_MP_UNREACH_NLRI] = {
    .name = "bgp_mp_unreach_nlri",
    .type = T_OPAQUE,
    .hidden = 1,
    .flags = BAF_OPTIONAL,
    .decode = bgp_decode_mp_unreach_nlri,
  },
  [BA_EXT_COMMUNITY] = {
    .name = "bgp_ext_community",
    .type = T_ECLIST,
    .flags = BAF_OPTIONAL | BAF_TRANSITIVE,
    .export = bgp_export_ext_community,
    .encode = bgp_encode_u32s,
    .decode = bgp_decode_ext_community,
  },
  [BA_AS4_PATH] = {
    .name = "bgp_as4_path",
    .type = T_PATH,
    .hidden = 1,
    .flags = BAF_OPTIONAL | BAF_TRANSITIVE,
    .encode = bgp_encode_raw,
    .decode = bgp_decode_as4_path,
  },
  [BA_AS4_AGGREGATOR] = {
    .name = "bgp_as4_aggregator",
    .type = T_OPAQUE,
    .hidden = 1,
    .flags = BAF_OPTIONAL | BAF_TRANSITIVE,
    .encode = bgp_encode_raw,
    .decode = bgp_decode_as4_aggregator,
    .format = bgp_format_aggregator,
  },
  [BA_AIGP] = {
    .name = "bgp_aigp",
    .type = T_OPAQUE,
    .flags = BAF_OPTIONAL | BAF_DECODE_FLAGS,
    .export = bgp_export_aigp,
    .encode = bgp_encode_raw,
    .decode = bgp_decode_aigp,
    .format = bgp_format_aigp,
  },
  [BA_LARGE_COMMUNITY] = {
    .name = "bgp_large_community",
    .type = T_LCLIST,
    .flags = BAF_OPTIONAL | BAF_TRANSITIVE,
    .export = bgp_export_large_community,
    .encode = bgp_encode_u32s,
    .decode = bgp_decode_large_community,
  },
  [BA_ONLY_TO_CUSTOMER] = {
    .name = "otc",
    .type = T_INT,
    .flags = BAF_OPTIONAL | BAF_TRANSITIVE,
    .encode = bgp_encode_u32,
    .decode = bgp_decode_otc,
  },
  [BA_MPLS_LABEL_STACK] = {
    .name = "bgp_mpls_label_stack",
    .type = T_CLIST,
    .readonly = 1,
    .export = bgp_export_mpls_label_stack,
    .encode = bgp_encode_mpls_label_stack,
    .decode = bgp_decode_mpls_label_stack,
    .format = bgp_format_mpls_label_stack,
  },
};

eattr *
bgp_find_attr(ea_list *attrs, uint code)
{
  return ea_find(attrs, BGP_EA_ID(code));
}

struct ea_class ea_bgp_rem_id = {
  .name = "proto_bgp_rem_id",
  .type = T_INT,
};

struct ea_class ea_bgp_rem_as = {
  .name = "proto_bgp_rem_as",
  .type = T_INT,
};

struct ea_class ea_bgp_loc_as = {
  .name = "proto_bgp_loc_as",
  .type = T_INT,
};

struct ea_class ea_bgp_rem_ip = {
  .name = "proto_bgp_rem_ip",
  .type = T_IP,
};

struct ea_class ea_bgp_afi = {
  .name = "bgp_afi",
  .type = T_INT,
};

struct ea_class ea_bgp_peer_type = {
  .name = "bgp_peer_type",
  .type = T_INT,
};

/*
 * Protocol connections information
 */

struct ea_class ea_bgp_in_conn_local_open_msg = {
  .name = "bgp_in_conn_local_open_msg",
  .type = T_BYTESTRING,
};

struct ea_class ea_bgp_in_conn_remote_open_msg = {
  .name = "bgp_in_conn_remote_open_msg",
  .type = T_BYTESTRING,
};

struct ea_class ea_bgp_out_conn_local_open_msg = {
  .name = "bgp_out_conn_local_open_msg",
  .type = T_BYTESTRING,
};

struct ea_class ea_bgp_out_conn_remote_open_msg = {
  .name = "bgp_out_conn_remote_open_msg",
  .type = T_BYTESTRING,
};

struct ea_class ea_bgp_in_conn_state = {
  .name = "bgp_in_conn_state",
  .type = T_INT,
};

struct ea_class ea_bgp_out_conn_state = {
  .name = "bgp_out_conn_state",
  .type = T_INT,
};

struct ea_class ea_bgp_in_conn_sk = {
  .name = "bgp_in_conn_sk",
  .type = T_OPAQUE,
};

struct ea_class ea_bgp_out_conn_sk = {
  .name = "bgp_out_conn_sk",
  .type = T_OPAQUE,
};

/*
 *	Protocol extended state information
 */

struct ea_class ea_bgp_state_startup = {
  .name = "bgp_state_startup",
  .type = T_INT,
};

struct ea_class ea_bgp_close_bmp = {
  .name = "bgp_close_bmp",
  .type = T_OPAQUE,
};

struct ea_class ea_bgp_close_bmp_set = {
  .name = "bgp_close_bmp_set",
  .type = T_INT,
};

struct ea_class ea_bgp_as4_session = {
  .name = "bgp_as4_session",
  .type = T_INT,
};

struct ea_class ea_bgp_as4_in_conn = {
  .name = "bgp_as4_in_conn",
  .type = T_INT,
};

struct ea_class ea_bgp_as4_out_conn = {
  .name = "bgp_as4_out_conn",
  .type = T_INT,
};

void
bgp_register_attrs(void)
{
  for (uint i=0; i<ARRAY_SIZE(bgp_attr_table); i++)
  {
    if (!bgp_attr_table[i].name)
      bgp_attr_table[i] = (union bgp_attr_desc) {
	.name = mb_sprintf(&root_pool, "bgp_unknown_0x%02x", i),
	.type = T_BYTESTRING,
	.flags = BAF_OPTIONAL | BAF_TRANSITIVE,
	.readonly = 1,
	.export = bgp_export_unknown,
	.encode = bgp_encode_raw,
	.decode = bgp_decode_unknown,
	.format = bgp_format_unknown,
      };

    ea_register_init(&bgp_attr_table[i].class);
  }

  EA_REGISTER_ALL(
      &ea_bgp_rem_id, &ea_bgp_rem_as, &ea_bgp_loc_as, &ea_bgp_rem_ip, &ea_bgp_peer_type, &ea_bgp_afi,
      &ea_bgp_in_conn_local_open_msg, &ea_bgp_out_conn_local_open_msg, &ea_bgp_in_conn_remote_open_msg,
      &ea_bgp_out_conn_remote_open_msg, &ea_bgp_close_bmp, &ea_bgp_close_bmp_set, &ea_bgp_as4_session,
      &ea_bgp_state_startup, &ea_bgp_in_conn_state, &ea_bgp_out_conn_state,
      &ea_bgp_in_conn_sk, &ea_bgp_out_conn_sk, &ea_bgp_as4_in_conn, &ea_bgp_as4_out_conn
      );
}

struct ea_class *
bgp_find_ea_class_by_id(uint id)
{
  return (id < ARRAY_SIZE(bgp_attr_table)) ? &bgp_attr_table[id].class : NULL;
}


/*
 *	Attribute export
 */

static inline void
bgp_export_attr(struct bgp_export_state *s, eattr *a, ea_list *to)
{
  const union bgp_attr_desc *desc = bgp_find_attr_desc(a);
  if (!desc)
    return;

  /* The flags should be correct, we reset them just to be sure */
  ASSERT(!((a->flags ^ desc->flags) & (BAF_OPTIONAL | BAF_TRANSITIVE)));
  a->flags = (a->flags & BAF_PARTIAL) | desc->flags;

  /* Set partial bit if new opt-trans attribute is attached to non-local route */
  if ((s->src != NULL) && (a->originated) &&
      (a->flags & BAF_OPTIONAL) && (a->flags & BAF_TRANSITIVE))
    a->flags |= BAF_PARTIAL;

  /* Call specific hook */
  CALL(desc->export, s, a);

  /* Attribute might become undefined in hook */
  if (a->undef)
    return;

  /* Append updated attribute */
  to->attrs[to->count++] = *a;
}

/**
 * bgp_export_attrs - export BGP attributes
 * @s: BGP export state
 * @attrs: a list of extended attributes
 *
 * The bgp_export_attrs() function takes a list of attributes and merges it to
 * one newly allocated and sorted segment. Attributes are validated and
 * normalized by type-specific export hooks and attribute flags are updated.
 * Some attributes may be eliminated (e.g. unknown non-tranitive attributes, or
 * empty community sets).
 *
 * Result: one sorted attribute list segment, or NULL if attributes are unsuitable.
 */
static inline ea_list *
bgp_export_attrs(struct bgp_export_state *s, ea_list *a)
{
  /* Merge the attribute list */
  ea_list *new = ea_normalize(a, 0);
  ASSERT_DIE(new);

  uint i, count;
  count = new->count;
  new->count = 0;

  /* Export each attribute */
  for (i = 0; i < count; i++)
    bgp_export_attr(s, &new->attrs[i], new);

  if (s->err_reject)
    return NULL;

  return new;
}


/*
 *	Attribute encoding
 */

static inline int
bgp_encode_attr(struct bgp_write_state *s, eattr *a, byte *buf, uint size)
{
  const union bgp_attr_desc *desc = bgp_find_attr_desc(a);
  if (s->ignore_non_bgp_attrs == 0)
    ASSERT_DIE(desc);
  else if (desc == NULL)
    return 0;
  return desc->encode(s, a, buf, size);
}

/**
 * bgp_encode_attrs - encode BGP attributes
 * @s: BGP write state
 * @attrs: a list of extended attributes
 * @buf: buffer
 * @end: buffer end
 *
 * The bgp_encode_attrs() function takes a list of extended attributes
 * and converts it to its BGP representation (a part of an Update message).
 * BGP write state may be fake when called from MRT protocol.
 *
 * Result: Length of the attribute block generated or -1 if not enough space.
 */
int
bgp_encode_attrs(struct bgp_write_state *s, ea_list *attrs, byte *buf, byte *end)
{
  byte *pos = buf;
  int i, len;

  for (i = 0; i < attrs->count; i++)
  {
    len = bgp_encode_attr(s, &attrs->attrs[i], pos, end - pos);

    if (len < 0)
      return -1;

    pos += len;
  }

  return pos - buf;
}


/*
 *	Attribute decoding
 */

static void bgp_process_as4_attrs(ea_list **attrs, struct linpool *pool);

static inline int
bgp_as_path_loopy(struct bgp_proto *p, ea_list *attrs, u32 asn)
{
  eattr *e = bgp_find_attr(attrs, BA_AS_PATH);
  int num = p->cf->allow_local_as + 1;
  return (e && (num > 0) && as_path_contains(e->u.ptr, asn, num));
}

static inline int
bgp_originator_id_loopy(struct bgp_proto *p, ea_list *attrs)
{
  eattr *e = bgp_find_attr(attrs, BA_ORIGINATOR_ID);
  return (e && (e->u.data == p->local_id));
}

static inline int
bgp_cluster_list_loopy(struct bgp_proto *p, ea_list *attrs)
{
  eattr *e = bgp_find_attr(attrs, BA_CLUSTER_LIST);
  return (e && int_set_contains(e->u.ptr, p->rr_cluster_id));
}

static inline void
bgp_decode_attr(struct bgp_parse_state *s, byte code, byte flags, byte *data, uint len, ea_list **to)
{
  /* Handle duplicate attributes; RFC 7606 3 (g) */
  if (BIT32_TEST(s->attrs_seen, code))
  {
    if ((code == BA_MP_REACH_NLRI) || (code == BA_MP_UNREACH_NLRI))
      bgp_parse_error(s, 1);
    else
      DISCARD("Discarding duplicate attribute (code %u)", code);
  }
  BIT32_SET(s->attrs_seen, code);

  ASSERT_DIE(bgp_attr_table[code].id);
  const union bgp_attr_desc *desc = &bgp_attr_table[code];

  /* Handle conflicting flags; RFC 7606 3 (c) */
  if (((flags ^ desc->flags) & (BAF_OPTIONAL | BAF_TRANSITIVE)) &&
      !(desc->flags & BAF_DECODE_FLAGS))
    WITHDRAW("Malformed %s attribute - conflicting flags (%02x, expected %02x)", desc->name, flags, desc->flags);

  desc->decode(s, code, flags, data, len, to);
}

/**
 * bgp_decode_attrs - check and decode BGP attributes
 * @s: BGP parse state
 * @data: start of attribute block
 * @len: length of attribute block
 *
 * This function takes a BGP attribute block (a part of an Update message), checks
 * its consistency and converts it to a list of BIRD route attributes represented
 * by an (uncached) &rta.
 */
ea_list *
bgp_decode_attrs(struct bgp_parse_state *s, byte *data, uint len)
{
  struct bgp_proto *p = s->proto;
  ea_list *attrs = NULL;
  uint alen;
  byte code, flags;
  byte *pos = data;

  /* Parse the attributes */
  while (len)
  {
    alen = 0;

    /* Read attribute type */
    if (len < 2)
      goto framing_error;
    flags = pos[0];
    code = pos[1];
    ADVANCE(pos, len, 2);

    /* Read attribute length */
    if (flags & BAF_EXT_LEN)
    {
      if (len < 2)
	goto framing_error;
      alen = get_u16(pos);
      ADVANCE(pos, len, 2);
    }
    else
    {
      if (len < 1)
	goto framing_error;
      alen = *pos;
      ADVANCE(pos, len, 1);
    }

    if (alen > len)
      goto framing_error;

    DBG("Attr %02x %02x %u\n", code, flags, alen);

    bgp_decode_attr(s, code, flags, pos, alen, &attrs);
    ADVANCE(pos, len, alen);
  }

  if (s->err_withdraw)
    goto withdraw;

  /* If there is no reachability NLRI, we are finished */
  if (!s->ip_reach_len && !s->mp_reach_len)
    return NULL;


  /* Handle missing mandatory attributes; RFC 7606 3 (d) */
  if (!BIT32_TEST(s->attrs_seen, BA_ORIGIN))
  { REPORT(NO_MANDATORY, "ORIGIN"); goto withdraw; }

  if (!BIT32_TEST(s->attrs_seen, BA_AS_PATH))
  { REPORT(NO_MANDATORY, "AS_PATH"); goto withdraw; }

  if (s->ip_reach_len && !BIT32_TEST(s->attrs_seen, BA_NEXT_HOP))
  { REPORT(NO_MANDATORY, "NEXT_HOP"); goto withdraw; }

  /* When receiving attributes from non-AS4-aware BGP speaker, we have to
     reconstruct AS_PATH and AGGREGATOR attributes; RFC 6793 4.2.3 */
  if (!p->as4_session)
    bgp_process_as4_attrs(&attrs, s->pool);

#define IS_LOOP(msg, args...)  { RTRACE("update is loop (" msg "), treating as withdraw", ##args); goto loop; }

  /* Reject routes with our ASN in AS_PATH attribute */
  if (bgp_as_path_loopy(p, attrs, p->local_as))
    IS_LOOP("Our ASN %d in AS_PATH", p->local_as);

  /* Reject routes with our Confederation ID in AS_PATH attribute; RFC 5065 4.0 */
  if ((p->public_as != p->local_as) && bgp_as_path_loopy(p, attrs, p->public_as))
    IS_LOOP("Our Confederation ID %d in AS_PATH", p->public_as);

  /* Reject routes with our Router ID in ORIGINATOR_ID attribute; RFC 4456 8 */
  if (p->is_internal && bgp_originator_id_loopy(p, attrs))
    IS_LOOP("Our Router ID is Originator ID");

  /* Reject routes with our Cluster ID in CLUSTER_LIST attribute; RFC 4456 8 */
  if (p->rr_client && bgp_cluster_list_loopy(p, attrs))
    IS_LOOP("Our Cluster ID is in Cluster List");

  /* If there is no local preference, define one */
  if (!BIT32_TEST(s->attrs_seen, BA_LOCAL_PREF))
    bgp_set_attr_u32(&attrs, BA_LOCAL_PREF, 0, p->cf->default_local_pref);

  return attrs;


framing_error:
  /* RFC 7606 4 - handle attribute framing errors */
  REPORT("Malformed attribute list - framing error (%u/%u) at %d",
	 alen, len, (int) (pos - s->attrs));

withdraw:
  /* RFC 7606 5.2 - handle missing NLRI during errors */
  if (!s->ip_reach_len && !s->mp_reach_len)
    bgp_parse_error(s, 1);

  s->err_withdraw = 1;
  return NULL;

loop:
  /* Loops are handled as withdraws, but ignored silently. Do not set err_withdraw. */
  return NULL;
}

void
bgp_finish_attrs(struct bgp_parse_state *s, ea_list **to)
{
  /* AIGP test here instead of in bgp_decode_aigp() - we need to know channel */
  if (BIT32_TEST(s->attrs_seen, BA_AIGP) && !s->channel->cf->aigp)
  {
    REPORT("Discarding AIGP attribute received on non-AIGP session");
    bgp_unset_attr(to, BA_AIGP);
  }

  /* Handle OTC ingress procedure, RFC 9234 */
  if (bgp_channel_is_role_applicable(s->channel))
  {
    struct bgp_proto *p = s->proto;
    eattr *e = bgp_find_attr(*to, BA_ONLY_TO_CUSTOMER);

    /* Reject routes from downstream if they are leaked */
    if (e && (p->cf->local_role == BGP_ROLE_PROVIDER ||
	      p->cf->local_role == BGP_ROLE_RS_SERVER))
      WITHDRAW("Route leak detected - OTC attribute from downstream");

    /* Reject routes from peers if they are leaked */
    if (e && (p->cf->local_role == BGP_ROLE_PEER) && (e->u.data != p->cf->remote_as))
      WITHDRAW("Route leak detected - OTC attribute with mismatched ASN (%u)",
	       (uint) e->u.data);

    /* Mark routes from upstream if it did not happened before */
    if (!e && (p->cf->local_role == BGP_ROLE_CUSTOMER ||
	       p->cf->local_role == BGP_ROLE_PEER ||
	       p->cf->local_role == BGP_ROLE_RS_CLIENT))
      bgp_set_attr_u32(to, BA_ONLY_TO_CUSTOMER, 0, p->cf->remote_as);
  }

  /* Apply MPLS policy for labeled SAFIs */
  if (s->mpls && s->proto->p.mpls_channel)
  {
    struct mpls_channel *mc = (void *) s->proto->p.mpls_channel;
    ea_set_attr_u32(to, &ea_gen_mpls_policy, 0, mc->label_policy);
  }
}


/*
 *	Route bucket hash table
 */

#define RBH_KEY(b)		b->eattrs, b->hash
#define RBH_NEXT(b)		b->next
#define RBH_EQ(a1,h1,a2,h2)	h1 == h2 && ea_same(a1, a2)
#define RBH_FN(a,h)		h

#define RBH_REHASH		bgp_rbh_rehash
#define RBH_PARAMS		/8, *2, 2, 2, 12, 20


HASH_DEFINE_REHASH_FN(RBH, struct bgp_bucket)

static void
bgp_init_bucket_table(struct bgp_ptx_private *c)
{
  HASH_INIT(c->bucket_hash, c->pool, 8);

  init_list(&c->bucket_queue);
  c->withdraw_bucket = NULL;
}

static struct bgp_bucket *
bgp_get_bucket(struct bgp_ptx_private *c, ea_list *new)
{
  /* Hash and lookup */
  u32 hash = ea_hash(new);
  struct bgp_bucket *b = HASH_FIND(c->bucket_hash, RBH, new, hash);

  if (b)
    return b;

  /* Scan the list for total size */
  uint ea_size = BIRD_CPU_ALIGN(ea_list_size(new));
  uint size = sizeof(struct bgp_bucket) + ea_size;

  /* Allocate the bucket */
  b = mb_alloc(c->pool, size);
  *b = (struct bgp_bucket) { };
  init_list(&b->prefixes);
  b->hash = hash;

  /* Copy the ea_list */
  ea_list_copy(b->eattrs, new, ea_size);

  /* Insert the bucket to bucket hash */
  HASH_INSERT2(c->bucket_hash, RBH, c->pool, b);

  return b;
}

static struct bgp_bucket *
bgp_get_withdraw_bucket(struct bgp_ptx_private *c)
{
  if (!c->withdraw_bucket)
  {
    c->withdraw_bucket = mb_allocz(c->pool, sizeof(struct bgp_bucket));
    init_list(&c->withdraw_bucket->prefixes);
  }

  return c->withdraw_bucket;
}

static void
bgp_free_bucket(struct bgp_ptx_private *c, struct bgp_bucket *b)
{
  HASH_REMOVE2(c->bucket_hash, RBH, c->pool, b);
  mb_free(b);
}

int
bgp_done_bucket(struct bgp_ptx_private *c, struct bgp_bucket *b)
{
  /* Won't free the withdraw bucket */
  if (b == c->withdraw_bucket)
    return 0;

  if (enlisted(&b->send_node) && EMPTY_LIST(b->prefixes))
    rem_node(&b->send_node);

  if (b->px_uc || !EMPTY_LIST(b->prefixes))
    return 0;

  bgp_free_bucket(c, b);
  return 1;
}

void
bgp_withdraw_bucket(struct bgp_ptx_private *c, struct bgp_bucket *b)
{
  if (b->bmp)
    return;

  SKIP_BACK_DECLARE(struct bgp_proto, p, p, c->c->c.proto);
  struct bgp_bucket *wb = bgp_get_withdraw_bucket(c);

  log(L_ERR "%s: Attribute list too long", p->p.name);
  while (!EMPTY_LIST(b->prefixes))
  {
    struct bgp_prefix *px = HEAD(b->prefixes);

    log(L_ERR "%s: - withdrawing %N", p->p.name, px->ni->addr);
    rem_node(&px->buck_node);
    add_tail(&wb->prefixes, &px->buck_node);
  }
}


/*
 *	Prefix hash table
 */

#define PXH_KEY(px)		px->ni, px->src
#define PXH_NEXT(px)		px->next
#define PXH_EQ(n1,s1,n2,s2)	(n1 == n2) && (!add_path_tx || (s1 == s2))
#define PXH_FN(ni, src)		u32_hash(ni->index)

#define PXH_REHASH		bgp_pxh_rehash
#define PXH_PARAMS		/8, *2, 2, 2, 12, 20

HASH_DEFINE_REHASH_FN(PXH, struct bgp_prefix);

static void
bgp_init_prefix_table(struct bgp_ptx_private *c)
{
  ASSERT_DIE(!c->prefix_slab);
  c->prefix_slab = sl_new(c->pool, sizeof(struct bgp_prefix));

  HASH_INIT(c->prefix_hash, c->pool, 8);
}

static struct bgp_prefix *
bgp_find_prefix(struct bgp_ptx_private *c, struct netindex *ni, struct rte_src *src, int add_path_tx)
{
  return HASH_FIND(c->prefix_hash, PXH, ni, src);
}

static struct bgp_prefix *
bgp_get_prefix(struct bgp_ptx_private *c, struct netindex *ni, struct rte_src *src, int add_path_tx)
{
  /* Find existing */
  struct bgp_prefix *px = bgp_find_prefix(c, ni, src, add_path_tx);
  if (px)
    return px;

  /* Allocate new prefix */
  px = sl_alloc(c->prefix_slab);
  *px = (struct bgp_prefix) {
    .src = src,
    .ni = ni,
  };

  net_lock_index(c->exporter.netindex, ni);
  rt_lock_source(src);

  HASH_INSERT2(c->prefix_hash, PXH, c->pool, px);

  if (ni->index >= atomic_load_explicit(&c->exporter.max_feed_index, memory_order_relaxed))
    atomic_store_explicit(&c->exporter.max_feed_index, ni->index + 1, memory_order_release);

  return px;
}

static void bgp_free_prefix(struct bgp_ptx_private *c, struct bgp_prefix *px);

static inline int
bgp_update_prefix(struct bgp_ptx_private *c, struct bgp_prefix *px, struct bgp_bucket *b)
{
#define IS_WITHDRAW_BUCKET(b)	((b) == c->withdraw_bucket)
#define BPX_TRACE(what)	do { \
  if (c->c->c.debug & D_ROUTES) log(L_TRACE "%s.%s < %s %N %uG %s", \
      c->c->c.proto->name, c->c->c.name, what, \
      px->ni->addr, px->src->global_id, IS_WITHDRAW_BUCKET(b) ? "withdraw" : "update"); } while (0)
  px->lastmod = current_time();

  /* Already queued for the same bucket */
  if (px->cur == b)
  {
    BPX_TRACE("already queued");
    return 0;
  }

  /* Unqueue from the old bucket */
  if (px->cur)
  {
    rem_node(&px->buck_node);
    bgp_done_bucket(c, px->cur);
  }

  /* The new bucket is the same as we sent before */
  if ((px->last == b) || c->c->tx_keep && !px->last && IS_WITHDRAW_BUCKET(b))
  {
    if (px->cur)
      BPX_TRACE("reverted");
    else
      BPX_TRACE("already sent");

    /* Well, we haven't sent anything yet */
    if (!px->last)
      bgp_free_prefix(c, px);

    px->cur = NULL;
    return 0;
  }

  /* Enqueue the bucket if it has been empty */
  if (!IS_WITHDRAW_BUCKET(b) && EMPTY_LIST(b->prefixes))
    add_tail(&c->bucket_queue, &b->send_node);

  /* Enqueue to the new bucket and indicate the change */
  add_tail(&b->prefixes, &px->buck_node);
  px->cur = b;

  BPX_TRACE("queued");
  return 1;

#undef BPX_TRACE
}

static void
bgp_free_prefix(struct bgp_ptx_private *c, struct bgp_prefix *px)
{
  HASH_REMOVE2(c->prefix_hash, PXH, c->pool, px);

  net_unlock_index(c->exporter.netindex, px->ni);
  rt_unlock_source(px->src);

  sl_free(px);
}

void
bgp_done_prefix(struct bgp_ptx_private *c, struct bgp_prefix *px, struct bgp_bucket *buck)
{
  /* BMP hack */
  if (buck->bmp)
  {
    rem_node(&px->buck_node);
    return;
  }

  /* Cleanup: We're called from bucket senders. */
  ASSERT_DIE(px->cur == buck);
  rem_node(&px->buck_node);

  /* We may want to store the updates */
  if (c->c->tx_keep)
  {
    /* Nothing to be sent right now */
    px->cur = NULL;

    /* Unref the previous sent version */
    if (px->last)
      if (!--px->last->px_uc)
	bgp_done_bucket(c, px->last);

    /* Ref the current sent version */
    if (!IS_WITHDRAW_BUCKET(buck))
    {
      px->last = buck;
      px->last->px_uc++;
      return;
    }

    /* Prefixes belonging to the withdraw bucket are freed always */
  }

  bgp_free_prefix(c, px);
}

void
bgp_tx_resend(struct bgp_proto *p, struct bgp_channel *bc)
{
  uint seen = 0;
  {
    BGP_PTX_LOCK(bc->tx, c);

    ASSERT_DIE(bc->tx_keep);

    HASH_WALK(c->prefix_hash, next, px)
    {
      if (!px->cur)
      {
	ASSERT_DIE(px->last);
	struct bgp_bucket *last = px->last;

	/* Remove the last reference, we wanna resend the route */
	px->last->px_uc--;
	px->last = NULL;

	/* And send it once again */
	seen += bgp_update_prefix(c, px, last);
      }
    }
    HASH_WALK_END;

    if (bc->c.debug & D_EVENTS)
      log(L_TRACE "%s.%s: TX resending %u routes",
	  bc->c.proto->name, bc->c.name, seen);

  }
  if (seen)
    bgp_schedule_packet(p->conn, bc, PKT_UPDATE);
}

/*
 *	Prefix hash table exporter
 */

static void
bgp_out_item_done(struct lfjour *j UNUSED, struct lfjour_item *i UNUSED)
{}

static struct rt_export_feed *
bgp_out_feed_net(struct rt_exporter *e, struct rcu_unwinder *u, u32 index, bool (*prefilter)(struct rt_export_feeder *, const net_addr *), struct rt_export_feeder *f, UNUSED const struct rt_export_item *_first)
{
  ASSERT_DIE(u == NULL);
  SKIP_BACK_DECLARE(struct bgp_ptx_private, c, exporter, e);
  ASSERT_DIE(DOMAIN_IS_LOCKED(rtable, c->lock));

  struct netindex *ni = net_resolve_index(c->exporter.netindex, index);
  if (ni == &net_index_out_of_range)
    return &rt_feed_index_out_of_range;

  if (ni == NULL)
    return NULL;

  if (prefilter && !prefilter(f, ni->addr))
    return NULL;

  struct rt_export_feed *feed = NULL;

  uint count = 0;

  struct bgp_prefix *chain = HASH_FIND_CHAIN(c->prefix_hash, PXH, ni, NULL);

  for (struct bgp_prefix *px = chain; px; px = px->next)
    if (px->ni == ni)
      count += !!px->last + !!px->cur;

  if (count)
  {
    feed = rt_alloc_feed(count, 0);
    feed->ni = ni;

    uint pos = 0;

    for (struct bgp_prefix *px = chain; px; px = px->next)
      if (px->ni == ni)
      {
	if (px->cur)
	  feed->block[pos++] = (rte) {
	    .attrs = (px->cur == c->withdraw_bucket) ? NULL : ea_free_later(ea_lookup_slow(px->cur->eattrs, 0, EALS_CUSTOM)),
	    .net = ni->addr,
	    .src = px->src,
	    .lastmod = px->lastmod,
	    .flags = REF_PENDING,
	  };

	if (px->last)
	  feed->block[pos++] = (rte) {
	    .attrs = (px->last == c->withdraw_bucket) ? NULL : ea_free_later(ea_lookup_slow(px->last->eattrs, 0, EALS_CUSTOM)),
	    .net = ni->addr,
	    .src = px->src,
	    .lastmod = px->lastmod,
	  };
      }

    ASSERT_DIE(pos == count);
  }

  return feed;
}

/* TX structures Init and Free */

void
bgp_init_pending_tx(struct bgp_channel *c)
{
  ASSERT_DIE(c->c.out_table == NULL);
  ASSERT_DIE(c->tx == NULL);

  DOMAIN(rtable) dom = DOMAIN_NEW(rtable);
  LOCK_DOMAIN(rtable, dom);
  pool *p = rp_newf(c->pool, dom.rtable, "%s.%s TX", c->c.proto->name, c->c.name);

  struct bgp_ptx_private *bpp = mb_allocz(p, sizeof *bpp);

  bpp->lock = dom;
  bpp->pool = p;
  bpp->c = c;

  bgp_init_bucket_table(bpp);
  bgp_init_prefix_table(bpp);

  bpp->exporter = (struct rt_exporter) {
    .journal = {
      .loop = c->c.proto->loop,
      .item_size = sizeof(struct rt_export_item),
      .item_done = bgp_out_item_done,
    },
    .name = mb_sprintf(c->c.proto->pool, "%s.%s.export", c->c.proto->name, c->c.name),
    .net_type = c->c.net_type,
    .max_feed_index = 0,
    .netindex = c->c.table->netindex,
    .trace_routes = c->c.debug,
    .feed_net = bgp_out_feed_net,
    .domain = dom,
  };

  rt_exporter_init(&bpp->exporter, &c->cf->ptx_exporter_settle);
  c->c.out_table = &bpp->exporter;

  c->tx = BGP_PTX_PUB(bpp);

  UNLOCK_DOMAIN(rtable, dom);
}

void
bgp_free_pending_tx(struct bgp_channel *bc)
{
  if (!bc->tx)
    return;

  DOMAIN(rtable) dom = bc->tx->lock;
  LOCK_DOMAIN(rtable, dom);
  struct bgp_ptx_private *c = &bc->tx->priv;

  bc->c.out_table = NULL;
  rt_exporter_shutdown(&c->exporter, NULL); /* TODO: actually implement exports */

  /* Move all prefixes to the withdraw bucket to unref the "last" prefixes */
  struct bgp_bucket *b = bgp_get_withdraw_bucket(c);
  HASH_WALK(c->prefix_hash, next, px)
    bgp_update_prefix(c, px, b);
  HASH_WALK_END;

  /* Flush withdrawals */
  struct bgp_prefix *px;
  WALK_LIST_FIRST(px, b->prefixes)
    bgp_done_prefix(c, px, b);

  /* Flush pending TX */
  WALK_LIST_FIRST(b, c->bucket_queue)
  {
    WALK_LIST_FIRST(px, b->prefixes)
      bgp_done_prefix(c, px, b);
    bgp_done_bucket(c, b);
  }

  /* Consistency and resource leak checks */
  HASH_WALK(c->prefix_hash, next, n)
    bug("Stray prefix after cleanup");
  HASH_WALK_END;

  HASH_FREE(c->prefix_hash);
  sl_delete(c->prefix_slab);
  c->prefix_slab = NULL;

  HASH_WALK(c->bucket_hash, next, n)
    bug("Stray bucket after cleanup");
  HASH_WALK_END;

  HASH_FREE(c->bucket_hash);
  sl_delete(c->bucket_slab);
  c->bucket_slab = NULL;

  rp_free(c->pool);

  UNLOCK_DOMAIN(rtable, dom);
  DOMAIN_FREE(rtable, dom);

  bc->tx = NULL;
}


/*
 *	BGP protocol glue
 */

int
bgp_preexport(struct channel *C, rte *e)
{
  struct bgp_proto *p = (struct bgp_proto *) C->proto;
  struct bgp_proto *src = bgp_rte_proto(e);
  struct bgp_channel *c = (struct bgp_channel *) C;

  /* Ignore non-BGP channels */
  if (C->class != &channel_bgp)
    return -1;

  /* Reject our routes */
  if (src == p)
    return -1;

  /* Accept non-BGP routes */
  if (src == NULL)
    return 0;

  /* Reject flowspec that failed validation */
  if (net_is_flow(e->net))
    switch (rt_get_flowspec_valid(e))
    {
      case FLOWSPEC_VALID:
	break;
      case FLOWSPEC_INVALID:
	return -1;
      case FLOWSPEC_UNKNOWN:
 	ASSUME((rt_get_source_attr(e) != RTS_BGP) ||
	    !((struct bgp_channel *) SKIP_BACK(struct channel, in_req, e->sender->req))->base_table);
	break;
      case FLOWSPEC__MAX:
	bug("This never happens.");
    }

  /* IBGP route reflection, RFC 4456 */
  if (p->is_internal && src->is_internal && (p->local_as == src->local_as))
  {
    /* Rejected unless configured as route reflector */
    if (!p->rr_client && !src->rr_client)
      return -1;

    /* Generally, this should be handled when path is received, but we check it
       also here as rr_cluster_id may be undefined or different in src. */
    if (p->rr_cluster_id && bgp_cluster_list_loopy(p, e->attrs))
      return -1;
  }

  /* Handle well-known communities, RFC 1997 */
  struct eattr *a;
  if (p->cf->interpret_communities &&
      (a = bgp_find_attr(e->attrs, BA_COMMUNITY)))
  {
    const struct adata *d = a->u.ptr;

    /* Do not export anywhere */
    if (int_set_contains(d, BGP_COMM_NO_ADVERTISE))
      return -1;

    /* Do not export outside of AS (or member-AS) */
    if (!p->is_internal && int_set_contains(d, BGP_COMM_NO_EXPORT_SUBCONFED))
      return -1;

    /* Do not export outside of AS (or confederation) */
    if (!p->is_interior && int_set_contains(d, BGP_COMM_NO_EXPORT))
      return -1;

    /* Do not export LLGR_STALE routes to LLGR-ignorant peers */
    if (!p->conn->remote_caps->llgr_aware && int_set_contains(d, BGP_COMM_LLGR_STALE))
      return -1;
  }

  /* Do not export routes marked with OTC to upstream, RFC 9234 */
  if (bgp_channel_is_role_applicable(c))
  {
    a = bgp_find_attr(e->attrs, BA_ONLY_TO_CUSTOMER);
    if (a && (p->cf->local_role==BGP_ROLE_CUSTOMER ||
	      p->cf->local_role==BGP_ROLE_PEER ||
	      p->cf->local_role==BGP_ROLE_RS_CLIENT))
      return -1;
  }

  return 0;
}

static ea_list *
bgp_update_attrs(struct bgp_proto *p, struct bgp_channel *c, rte *e, ea_list *attrs0, struct linpool *pool)
{
  struct bgp_proto *src = bgp_rte_proto(e);
  struct bgp_export_state s = { .proto = p, .channel = c, .pool = pool, .src = src, .route = e, .mpls = c->desc->mpls };
  ea_list *attrs = attrs0;
  eattr *a;
  const adata *ad;

  /* ORIGIN attribute - mandatory, attach if missing */
  if (! bgp_find_attr(attrs0, BA_ORIGIN))
    bgp_set_attr_u32(&attrs, BA_ORIGIN, 0, src ? ORIGIN_INCOMPLETE : ORIGIN_IGP);

  /* AS_PATH attribute - mandatory */
  a = bgp_find_attr(attrs0, BA_AS_PATH);
  ad = a ? a->u.ptr : &null_adata;

  /* AS_PATH attribute - strip AS_CONFED* segments outside confederation */
  if ((!p->cf->confederation || !p->is_interior) && as_path_contains_confed(ad))
    ad = as_path_strip_confed(pool, ad);

  /* AS_PATH attribute - keep or prepend ASN */
  if (p->is_internal || p->rs_client)
  {
    /* IBGP or route server -> just ensure there is one */
    if (!a)
      bgp_set_attr_ptr(&attrs, BA_AS_PATH, 0, &null_adata);
  }
  else if (p->is_interior)
  {
    /* Confederation -> prepend ASN as AS_CONFED_SEQUENCE */
    ad = as_path_prepend2(pool, ad, AS_PATH_CONFED_SEQUENCE, p->public_as);
    bgp_set_attr_ptr(&attrs, BA_AS_PATH, 0, ad);
  }
  else /* Regular EBGP (no RS, no confederation) */
  {
    /* Regular EBGP -> prepend ASN as regular sequence */
    ad = as_path_prepend2(pool, ad, AS_PATH_SEQUENCE, p->public_as);
    bgp_set_attr_ptr(&attrs, BA_AS_PATH, 0, ad);

    /* MULTI_EXIT_DESC attribute - accept only if set in export filter */
    a = bgp_find_attr(attrs0, BA_MULTI_EXIT_DISC);
    if (a && !a->fresh && !p->cf->allow_med)
      bgp_unset_attr(&attrs, BA_MULTI_EXIT_DISC);
  }

  /* NEXT_HOP attribute - delegated to AF-specific hook */
  a = bgp_find_attr(attrs0, BA_NEXT_HOP);
  bgp_update_next_hop(&s, a, &attrs);

  /* LOCAL_PREF attribute - required for IBGP, attach if missing */
  if (p->is_interior && ! bgp_find_attr(attrs0, BA_LOCAL_PREF))
    bgp_set_attr_u32(&attrs, BA_LOCAL_PREF, 0, p->cf->default_local_pref);

  /* AIGP attribute - accumulate local metric or originate new one */
  u64 metric;
  if (s.local_next_hop &&
      (bgp_total_aigp_metric_(e, &metric, &ad) ||
       (c->cf->aigp_originate && bgp_init_aigp_metric(e, &metric, &ad))))
  {
    ad = bgp_aigp_set_metric(pool, ad, metric);
    bgp_set_attr_ptr(&attrs, BA_AIGP, 0, ad);
  }

  /* IBGP route reflection, RFC 4456 */
  if (src && src->is_internal && p->is_internal && (src->local_as == p->local_as))
  {
    /* ORIGINATOR_ID attribute - attach if not already set */
    if (! bgp_find_attr(attrs0, BA_ORIGINATOR_ID))
      bgp_set_attr_u32(&attrs, BA_ORIGINATOR_ID, 0, src->remote_id);

    /* CLUSTER_LIST attribute - prepend cluster ID */
    a = bgp_find_attr(attrs0, BA_CLUSTER_LIST);
    ad = a ? a->u.ptr : NULL;

    /* Prepend src cluster ID */
    if (src->rr_cluster_id)
      ad = int_set_prepend(pool, ad, src->rr_cluster_id);

    /* Prepend dst cluster ID if src and dst clusters are different */
    if (p->rr_cluster_id && (src->rr_cluster_id != p->rr_cluster_id))
      ad = int_set_prepend(pool, ad, p->rr_cluster_id);

    /* Should be at least one prepended cluster ID */
    bgp_set_attr_ptr(&attrs, BA_CLUSTER_LIST, 0, ad);
  }

  /* AS4_* transition attributes, RFC 6793 4.2.2 */
  if (! p->as4_session)
  {
    a = bgp_find_attr(attrs, BA_AS_PATH);
    if (a && as_path_contains_as4(a->u.ptr))
    {
      bgp_set_attr_ptr(&attrs, BA_AS_PATH, 0, as_path_to_old(pool, a->u.ptr));
      bgp_set_attr_ptr(&attrs, BA_AS4_PATH, 0, as_path_strip_confed(pool, a->u.ptr));
    }

    a = bgp_find_attr(attrs, BA_AGGREGATOR);
    if (a && aggregator_contains_as4(a->u.ptr))
    {
      bgp_set_attr_ptr(&attrs, BA_AGGREGATOR, 0, aggregator_to_old(pool, a->u.ptr));
      bgp_set_attr_ptr(&attrs, BA_AS4_AGGREGATOR, 0, a->u.ptr);
    }
  }

  /* Mark routes for downstream with OTC, RFC 9234 */
  if (bgp_channel_is_role_applicable(c))
  {
    a = bgp_find_attr(attrs, BA_ONLY_TO_CUSTOMER);
    if (!a && (p->cf->local_role == BGP_ROLE_PROVIDER ||
	       p->cf->local_role == BGP_ROLE_PEER ||
	       p->cf->local_role == BGP_ROLE_RS_SERVER))
      bgp_set_attr_u32(&attrs, BA_ONLY_TO_CUSTOMER, 0, p->public_as);
  }

  /*
   * Presence of mandatory attributes ORIGIN and AS_PATH is ensured by above
   * conditions. Presence and validity of quasi-mandatory NEXT_HOP attribute
   * should be checked in AF-specific hooks.
   */

  /* Apply per-attribute export hooks for validatation and normalization */
  return bgp_export_attrs(&s, attrs);
}

void
bgp_rt_notify(struct proto *P, struct channel *C, const net_addr *n, rte *new, const rte *old)
{
  struct bgp_proto *p = (void *) P;
  struct bgp_channel *bc = (void *) C;
  struct bgp_bucket *buck;
  struct rte_src *path;

  /* Ignore non-BGP channels */
  if (C->class != &channel_bgp)
    return;

  struct ea_list *attrs = new ? bgp_update_attrs(p, bc, new, new->attrs, tmp_linpool) : NULL;

  BGP_PTX_LOCK(bc->tx, c);

  /* Error during attribute processing */
  if (new && !attrs)
    log(L_ERR "%s: Invalid route %N withdrawn", p->p.name, n);

  /* If attributes are invalid, we fail back to withdraw */
  buck = attrs ? bgp_get_bucket(c, attrs) : bgp_get_withdraw_bucket(c);
  path = (new ?: old)->src;

  /* And queue the notification */
  if (bgp_update_prefix(c, bgp_get_prefix(c, NET_TO_INDEX(n), path, bc->add_path_tx), buck))
    bgp_schedule_packet(p->conn, bc, PKT_UPDATE);
}


static inline u32
bgp_get_neighbor(const rte *r)
{
  eattr *e = ea_find(r->attrs, BGP_EA_ID(BA_AS_PATH));
  u32 as;

  if (e && as_path_get_first_regular(e->u.ptr, &as))
    return as;

  /* If AS_PATH is not defined, we treat rte as locally originated */
  struct bgp_proto *p = bgp_rte_proto(r);
  return p->cf->confederation ?: p->local_as;
}

static inline int
rte_stale(const rte *r)
{
  eattr *a = ea_find(r->attrs, BGP_EA_ID(BA_COMMUNITY));
  return a && int_set_contains(a->u.ptr, BGP_COMM_LLGR_STALE);
}

int
bgp_rte_better(const rte *new, const rte *old)
{
  struct bgp_proto *new_bgp = bgp_rte_proto(new);
  struct bgp_proto *old_bgp = bgp_rte_proto(old);
  eattr *x, *y;
  u32 n, o;

  /* Skip suppressed routes (see bgp_rte_recalculate()) */
  n = new->pflags & BGP_REF_SUPPRESSED;
  o = old->pflags & BGP_REF_SUPPRESSED;
  if (n > o)
    return 0;
  if (n < o)
    return 1;

  /* RFC 4271 9.1.2.1. Route resolvability test */
  n = rte_resolvable(new);
  o = rte_resolvable(old);
  if (n > o)
    return 1;
  if (n < o)
    return 0;

  /* LLGR draft - depreference stale routes */
  n = rte_stale(new);
  o = rte_stale(old);
  if (n > o)
    return 0;
  if (n < o)
    return 1;

 /* Start with local preferences */
  x = ea_find(new->attrs, BGP_EA_ID(BA_LOCAL_PREF));
  y = ea_find(old->attrs, BGP_EA_ID(BA_LOCAL_PREF));
  n = x ? x->u.data : new_bgp->cf->default_local_pref;
  o = y ? y->u.data : old_bgp->cf->default_local_pref;
  if (n > o)
    return 1;
  if (n < o)
    return 0;

  /* RFC 7311 4.1 - Apply AIGP metric */
  u64 n2 = bgp_total_aigp_metric(new);
  u64 o2 = bgp_total_aigp_metric(old);
  if (n2 < o2)
    return 1;
  if (n2 > o2)
    return 0;

  /* RFC 4271 9.1.2.2. a)  Use AS path lengths */
  if (new_bgp->cf->compare_path_lengths || old_bgp->cf->compare_path_lengths)
  {
    x = ea_find(new->attrs, BGP_EA_ID(BA_AS_PATH));
    y = ea_find(old->attrs, BGP_EA_ID(BA_AS_PATH));
    n = x ? as_path_getlen(x->u.ptr) : AS_PATH_MAXLEN;
    o = y ? as_path_getlen(y->u.ptr) : AS_PATH_MAXLEN;
    if (n < o)
      return 1;
    if (n > o)
      return 0;
  }

  /* RFC 4271 9.1.2.2. b) Use origins */
  x = ea_find(new->attrs, BGP_EA_ID(BA_ORIGIN));
  y = ea_find(old->attrs, BGP_EA_ID(BA_ORIGIN));
  n = x ? x->u.data : ORIGIN_INCOMPLETE;
  o = y ? y->u.data : ORIGIN_INCOMPLETE;
  if (n < o)
    return 1;
  if (n > o)
    return 0;

  /* RFC 4271 9.1.2.2. c) Compare MED's */
  /* Proper RFC 4271 path selection cannot be interpreted as finding
   * the best path in some ordering. It is implemented partially in
   * bgp_rte_recalculate() when deterministic_med option is
   * active. Without that option, the behavior is just an
   * approximation, which in specific situations may lead to
   * persistent routing loops, because it is nondeterministic - it
   * depends on the order in which routes appeared. But it is also the
   * same behavior as used by default in Cisco routers, so it is
   * probably not a big issue.
   */
  if (new_bgp->cf->med_metric || old_bgp->cf->med_metric ||
      (bgp_get_neighbor(new) == bgp_get_neighbor(old)))
  {
    x = ea_find(new->attrs, BGP_EA_ID(BA_MULTI_EXIT_DISC));
    y = ea_find(old->attrs, BGP_EA_ID(BA_MULTI_EXIT_DISC));
    n = x ? x->u.data : new_bgp->cf->default_med;
    o = y ? y->u.data : old_bgp->cf->default_med;
    if (n < o)
      return 1;
    if (n > o)
      return 0;
  }

  /* RFC 4271 9.1.2.2. d) Prefer external peers */
  if (new_bgp->is_interior > old_bgp->is_interior)
    return 0;
  if (new_bgp->is_interior < old_bgp->is_interior)
    return 1;

  /* RFC 4271 9.1.2.2. e) Compare IGP metrics */
  n = new_bgp->cf->igp_metric ? rt_get_igp_metric(new) : 0;
  o = old_bgp->cf->igp_metric ? rt_get_igp_metric(old) : 0;
  if (n < o)
    return 1;
  if (n > o)
    return 0;

  /* RFC 4271 9.1.2.2. f) Compare BGP identifiers */
  /* RFC 4456 9. a) Use ORIGINATOR_ID instead of local neighbor ID */
  x = ea_find(new->attrs, BGP_EA_ID(BA_ORIGINATOR_ID));
  y = ea_find(old->attrs, BGP_EA_ID(BA_ORIGINATOR_ID));
  n = x ? x->u.data : new_bgp->remote_id;
  o = y ? y->u.data : old_bgp->remote_id;

  /* RFC 5004 - prefer older routes */
  /* (if both are external and from different peer) */
  if ((new_bgp->cf->prefer_older || old_bgp->cf->prefer_older) &&
      !new_bgp->is_internal && n != o)
    return 0;

  /* rest of RFC 4271 9.1.2.2. f) */
  if (n < o)
    return 1;
  if (n > o)
    return 0;

  /* RFC 4456 9. b) Compare cluster list lengths */
  x = ea_find(new->attrs, BGP_EA_ID(BA_CLUSTER_LIST));
  y = ea_find(old->attrs, BGP_EA_ID(BA_CLUSTER_LIST));
  n = x ? int_set_get_size(x->u.ptr) : 0;
  o = y ? int_set_get_size(y->u.ptr) : 0;
  if (n < o)
    return 1;
  if (n > o)
    return 0;

  /* RFC 4271 9.1.2.2. g) Compare peer IP adresses */
  return ipa_compare(new_bgp->remote_ip, old_bgp->remote_ip) < 0;
}


int
bgp_rte_mergable(const rte *pri, const rte *sec)
{
  struct bgp_proto *pri_bgp = bgp_rte_proto(pri);
  struct bgp_proto *sec_bgp = bgp_rte_proto(sec);
  eattr *x, *y;
  u32 p, s;

  /* Skip suppressed routes (see bgp_rte_recalculate()) */
  if ((pri->pflags ^ sec->pflags) & BGP_REF_SUPPRESSED)
    return 0;

  /* RFC 4271 9.1.2.1. Route resolvability test */
  if (rte_resolvable(pri) != rte_resolvable(sec))
    return 0;

  /* LLGR draft - depreference stale routes */
  if (rte_stale(pri) != rte_stale(sec))
    return 0;

  /* Start with local preferences */
  x = ea_find(pri->attrs, BGP_EA_ID(BA_LOCAL_PREF));
  y = ea_find(sec->attrs, BGP_EA_ID(BA_LOCAL_PREF));
  p = x ? x->u.data : pri_bgp->cf->default_local_pref;
  s = y ? y->u.data : sec_bgp->cf->default_local_pref;
  if (p != s)
    return 0;

  /* RFC 4271 9.1.2.2. a)  Use AS path lengths */
  if (pri_bgp->cf->compare_path_lengths || sec_bgp->cf->compare_path_lengths)
  {
    x = ea_find(pri->attrs, BGP_EA_ID(BA_AS_PATH));
    y = ea_find(sec->attrs, BGP_EA_ID(BA_AS_PATH));
    p = x ? as_path_getlen(x->u.ptr) : AS_PATH_MAXLEN;
    s = y ? as_path_getlen(y->u.ptr) : AS_PATH_MAXLEN;

    if (p != s)
      return 0;

//    if (DELTA(p, s) > pri_bgp->cf->relax_multipath)
//      return 0;
  }

  /* RFC 4271 9.1.2.2. b) Use origins */
  x = ea_find(pri->attrs, BGP_EA_ID(BA_ORIGIN));
  y = ea_find(sec->attrs, BGP_EA_ID(BA_ORIGIN));
  p = x ? x->u.data : ORIGIN_INCOMPLETE;
  s = y ? y->u.data : ORIGIN_INCOMPLETE;
  if (p != s)
    return 0;

  /* RFC 4271 9.1.2.2. c) Compare MED's */
  if (pri_bgp->cf->med_metric || sec_bgp->cf->med_metric ||
      (bgp_get_neighbor(pri) == bgp_get_neighbor(sec)))
  {
    x = ea_find(pri->attrs, BGP_EA_ID(BA_MULTI_EXIT_DISC));
    y = ea_find(sec->attrs, BGP_EA_ID(BA_MULTI_EXIT_DISC));
    p = x ? x->u.data : pri_bgp->cf->default_med;
    s = y ? y->u.data : sec_bgp->cf->default_med;
    if (p != s)
      return 0;
  }

  /* RFC 4271 9.1.2.2. d) Prefer external peers */
  if (pri_bgp->is_interior != sec_bgp->is_interior)
    return 0;

  /* RFC 4271 9.1.2.2. e) Compare IGP metrics */
  p = pri_bgp->cf->igp_metric ? rt_get_igp_metric(pri) : 0;
  s = sec_bgp->cf->igp_metric ? rt_get_igp_metric(sec) : 0;
  if (p != s)
    return 0;

  /* Remaining criteria are ignored */

  return 1;
}


static inline int
same_group(const rte *r, u32 lpref, u32 lasn)
{
  return (rt_get_preference(r) == lpref) && (bgp_get_neighbor(r) == lasn);
}

static inline int
use_deterministic_med(struct rte_storage *r)
{
  struct bgp_proto *p = bgp_rte_proto(&r->rte);
  return p && p->cf->deterministic_med;
}

int
bgp_rte_recalculate(struct rtable_private *table, net *net,
    struct rte_storage *new_stored, struct rte_storage *old_stored, struct rte_storage *old_best_stored)
{
  struct rte_storage *key_stored = new_stored ? new_stored : old_stored;
  const struct rte *new = &new_stored->rte,
		   *old = &old_stored->rte,
		   *old_best = &old_best_stored->rte,
		   *key = &key_stored->rte;

  u32 lpref = rt_get_preference(key);
  u32 lasn = bgp_get_neighbor(key);
  int old_suppressed = old ? !!(old->pflags & BGP_REF_SUPPRESSED) : 0;

  /*
   * Proper RFC 4271 path selection is a bit complicated, it cannot be
   * implemented just by rte_better(), because it is not a linear
   * ordering. But it can be splitted to two levels, where the lower
   * level chooses the best routes in each group of routes from the
   * same neighboring AS and higher level chooses the best route (with
   * a slightly different ordering) between the best-in-group routes.
   *
   * When deterministic_med is disabled, we just ignore this issue and
   * choose the best route by bgp_rte_better() alone. If enabled, the
   * lower level of the route selection is done here (for the group
   * to which the changed route belongs), all routes in group are
   * marked as suppressed, just chosen best-in-group is not.
   *
   * Global best route selection then implements higher level by
   * choosing between non-suppressed routes (as they are always
   * preferred over suppressed routes). Routes from BGP protocols
   * that do not set deterministic_med are just never suppressed. As
   * they do not participate in the lower level selection, it is OK
   * that this fn is not called for them.
   *
   * The idea is simple, the implementation is more problematic,
   * mostly because of optimizations in rte_recalculate() that
   * avoids full recalculation in most cases.
   *
   * We can assume that at least one of new, old is non-NULL and both
   * are from the same protocol with enabled deterministic_med. We
   * group routes by both neighbor AS (lasn) and preference (lpref),
   * because bgp_rte_better() does not handle preference itself.
   */

  /* If new and old are from different groups, we just process that
     as two independent events */
  if (new && old && !same_group(old, lpref, lasn))
  {
    int i1, i2;
    i1 = bgp_rte_recalculate(table, net, NULL, old_stored, old_best_stored);
    i2 = bgp_rte_recalculate(table, net, new_stored, NULL, old_best_stored);
    return i1 || i2;
  }

  /*
   * We could find the best-in-group and then make some shortcuts like
   * in rte_recalculate, but as we would have to walk through all
   * net->routes just to find it, it is probably not worth. So we
   * just have one simple fast case that use just the old route.
   * We also set suppressed flag to avoid using it in bgp_rte_better().
   */

  if (new)
    new_stored->pflags |= BGP_REF_SUPPRESSED;

  if (old)
  {
    old_stored->pflags |= BGP_REF_SUPPRESSED;

    /* The fast case - replace not best with worse (or remove not best) */
    if (old_suppressed && !(new && bgp_rte_better(new, old)))
      return 0;
  }

  /* The default case - find a new best-in-group route */
  struct rte_storage *r = new_stored; /* new may not be in the list */
  struct rte_storage *spinlocked = atomic_load_explicit(&net->routes, memory_order_acquire);
  ASSERT_DIE(spinlocked->rte.flags & REF_OBSOLETE);
  ASSERT_DIE(!spinlocked->rte.src);

  for (struct rte_storage *s, * _Atomic *ptr = &spinlocked->next;
      s = atomic_load_explicit(ptr, memory_order_acquire);
      ptr = &s->next)
    if (!rte_is_valid(&s->rte))
      break;
    else if (use_deterministic_med(s) && same_group(&s->rte, lpref, lasn))
    {
      s->pflags |= BGP_REF_SUPPRESSED;
      if (!r || bgp_rte_better(&s->rte, &r->rte))
	r = s;
    }

  /* Simple case - the last route in group disappears */
  if (!r)
    return 0;

  /* Found if new is mergable with best-in-group */
  if (new && (new_stored != r) && bgp_rte_mergable(&r->rte, new))
    new_stored->pflags &= ~BGP_REF_SUPPRESSED;

  /* Found all existing routes mergable with best-in-group */
  for (struct rte_storage *s, * _Atomic *ptr = &spinlocked->next;
      s = atomic_load_explicit(ptr, memory_order_acquire);
      ptr = &s->next)
    if (!rte_is_valid(&s->rte))
      break;
    else if (use_deterministic_med(s) && same_group(&s->rte, lpref, lasn))
      if ((s != r) && bgp_rte_mergable(&r->rte, &s->rte))
	s->pflags &= ~BGP_REF_SUPPRESSED;

  /* Found best-in-group */
  r->pflags &= ~BGP_REF_SUPPRESSED;

  /*
   * There are generally two reasons why we have to force
   * recalculation (return 1): First, the new route may be wrongfully
   * chosen to be the best in the first case check in
   * rte_recalculate(), this may happen only if old_best is from the
   * same group. Second, another (different than new route)
   * best-in-group is chosen and that may be the proper best (although
   * rte_recalculate() without ignore that possibility).
   *
   * There are three possible cases according to whether the old route
   * was the best in group (OBG, i.e. !old_suppressed) and whether the
   * new route is the best in group (NBG, tested by r == new). These
   * cases work even if old or new is NULL.
   *
   * NBG -> new is a possible candidate for the best route, so we just
   *        check for the first reason using same_group().
   *
   * !NBG && OBG -> Second reason applies, return 1
   *
   * !NBG && !OBG -> Best in group does not change, old != old_best,
   *                 rte_better(new, old_best) is false and therefore
   *                 the first reason does not apply, return 0
   */

  if (r == new_stored)
    return old_best && same_group(old_best, lpref, lasn);
  else
    return !old_suppressed;
}

void
bgp_rte_modify_stale(void *_bc)
{
  struct bgp_channel *c = _bc;
  struct rt_import_hook *irh = c->c.in_req.hook;

  RT_FEED_WALK(&c->stale_feed, f) TMP_SAVED
  {
    for (uint i = 0; i < f->count_routes; i++)
    {
      rte *r = &f->block[i];
      if ((r->sender != irh) ||		/* Not our route */
	  (r->stale_cycle == irh->stale_set))	/* A new route, do not mark as stale */
	continue;

      /* Don't reinstate obsolete routes */
      if (r->flags & REF_OBSOLETE)
	break;

      eattr *ea = ea_find(r->attrs, BGP_EA_ID(BA_COMMUNITY));
      const struct adata *ad = ea ? ea->u.ptr : NULL;
      uint flags = ea ? ea->flags : BAF_PARTIAL;

      /* LLGR not allowed, withdraw the route */
      if (ad && int_set_contains(ad, BGP_COMM_NO_LLGR))
      {
	rte_import(&c->c.in_req, r->net, NULL, r->src);
	continue;
      }

      /* Route already marked as LLGR, do nothing */
      if (ad && int_set_contains(ad, BGP_COMM_LLGR_STALE))
	continue;

      /* Mark the route as LLGR */
      bgp_set_attr_ptr(&r->attrs, BA_COMMUNITY, flags, int_set_add(tmp_linpool, ad, BGP_COMM_LLGR_STALE));

      /* We need to update the route but keep it stale. */
      ASSERT_DIE(irh->stale_set == irh->stale_valid + 1);
      irh->stale_set--;
      rte_import(&c->c.in_req, r->net, r, r->src);
      irh->stale_set++;
    }

    MAYBE_DEFER_TASK(proto_event_list(c->c.proto), &c->stale_event,
	"BGP %s.%s LLGR updater", c->c.proto->name, c->c.name);
  }

  rt_feeder_unsubscribe(&c->stale_feed);
}


/*
 * Reconstruct AS_PATH and AGGREGATOR according to RFC 6793 4.2.3
 */
static void
bgp_process_as4_attrs(ea_list **attrs, struct linpool *pool)
{
  eattr *p2 = bgp_find_attr(*attrs, BA_AS_PATH);
  eattr *p4 = bgp_find_attr(*attrs, BA_AS4_PATH);
  eattr *a2 = bgp_find_attr(*attrs, BA_AGGREGATOR);
  eattr *a4 = bgp_find_attr(*attrs, BA_AS4_AGGREGATOR);

  /* First, unset AS4_* attributes */
  if (p4) bgp_unset_attr(attrs, BA_AS4_PATH);
  if (a4) bgp_unset_attr(attrs, BA_AS4_AGGREGATOR);

  /* Handle AGGREGATOR attribute */
  if (a2 && a4)
  {
    u32 a2_asn = get_u32(a2->u.ptr->data);

    /* If routes were aggregated by an old router, then AS4_PATH and
       AS4_AGGREGATOR are invalid. In that case we give up. */
    if (a2_asn != AS_TRANS)
      return;

    /* Use AS4_AGGREGATOR instead of AGGREGATOR */
    a2->u.ptr = a4->u.ptr;
  }

  /* Handle AS_PATH attribute */
  if (p2 && p4)
  {
    /* Both as_path_getlen() and as_path_cut() take AS_CONFED* as zero length */
    int p2_len = as_path_getlen(p2->u.ptr);
    int p4_len = as_path_getlen(p4->u.ptr);

    /* AS_PATH is too short, give up */
    if (p2_len < p4_len)
      return;

    /* Merge AS_PATH and AS4_PATH */
    struct adata *apc = as_path_cut(pool, p2->u.ptr, p2_len - p4_len);
    p2->u.ptr = as_path_merge(pool, apc, p4->u.ptr);
  }
}

void
bgp_get_route_info(const rte *e, byte *buf)
{
  eattr *p = ea_find(e->attrs, BGP_EA_ID(BA_AS_PATH));
  eattr *o = ea_find(e->attrs, BGP_EA_ID(BA_ORIGIN));
  u32 origas;

  buf += bsprintf(buf, " (%d", rt_get_preference(e));

  if (!net_is_flow(e->net))
  {
    if (e->pflags & BGP_REF_SUPPRESSED)
      buf += bsprintf(buf, "-");

    if (rte_stale(e))
      buf += bsprintf(buf, "s");

    u64 metric = bgp_total_aigp_metric(e);
    if (metric < BGP_AIGP_MAX)
    {
      buf += bsprintf(buf, "/%lu", metric);
    }
    else if (metric = rt_get_igp_metric(e))
    {
      if (!rte_resolvable(e))
	buf += bsprintf(buf, "/-");
      else if (metric >= IGP_METRIC_UNKNOWN)
	buf += bsprintf(buf, "/?");
      else
	buf += bsprintf(buf, "/%d", metric);
    }
  }
  buf += bsprintf(buf, ") [");

  if (p && as_path_get_last(p->u.ptr, &origas))
    buf += bsprintf(buf, "AS%u", origas);
  if (o)
    buf += bsprintf(buf, "%c", "ie?"[o->u.data]);
  strcpy(buf, "]");
}
