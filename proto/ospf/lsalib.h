/*
 *      BIRD -- OSPF
 *
 *      (c) 1999--2000 Ondrej Filip <feela@network.cz>
 *	(c) 2009--2014 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2009--2014 CZ.NIC z.s.p.o.
 *
 *      Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_OSPF_LSALIB_H_
#define _BIRD_OSPF_LSALIB_H_

#ifdef CPU_BIG_ENDIAN
static inline void lsa_hton_hdr(struct ospf_lsa_header *h, struct ospf_lsa_header *n) { *n = *h; };
static inline void lsa_ntoh_hdr(struct ospf_lsa_header *n, struct ospf_lsa_header *h) { *h = *n; };
static inline void lsa_hton_body(void *h, void *n, u16 len) { ASSERT(h != n); memcpy(n, h, len); };
static inline void lsa_ntoh_body(void *n, void *h, u16 len) { ASSERT(n != h); memcpy(h, n, len); };
static inline void lsa_hton_body1(void *h, u16 len) { };
static inline void lsa_ntoh_body1(void *n, u16 len) { };
#else
void lsa_hton_hdr(struct ospf_lsa_header *h, struct ospf_lsa_header *n);
void lsa_ntoh_hdr(struct ospf_lsa_header *n, struct ospf_lsa_header *h);
void lsa_hton_body(void *h, void *n, u16 len);
void lsa_ntoh_body(void *n, void *h, u16 len);
static inline void lsa_hton_body1(void *h, u16 len) { lsa_hton_body(h, h, len); };
static inline void lsa_ntoh_body1(void *n, u16 len) { lsa_ntoh_body(n, n, len); };
#endif

struct ospf_lsa_rt_walk {
  struct top_hash_entry *en;
  void *buf, *bufend;
  int ospf2;
  u16 type, metric;
  u32 id, data, lif, nif;
};


void lsa_get_type_domain_(u32 type, u32 id, struct ospf_iface *ifa, u32 *otype, u32 *domain);

static inline void lsa_get_type_domain(struct ospf_lsa_header *lsa, struct ospf_iface *ifa, u32 *otype, u32 *domain)
{ lsa_get_type_domain_(lsa->type_raw, lsa->id, ifa, otype, domain); }

static inline u32 lsa_get_etype(struct ospf_lsa_header *h, struct ospf_proto *p)
{ return ospf_is_v2(p) ? (h->type_raw & LSA_T_V2_MASK) : h->type_raw; }

int lsa_is_opaque(u32 type);
u32 lsa_get_opaque_type(u32 type);
int lsa_flooding_allowed(u32 type, u32 domain, struct ospf_iface *ifa);
int lsa_is_acceptable(u32 type, struct ospf_neighbor *n, struct ospf_proto *p);
void lsa_generate_checksum(struct ospf_lsa_header *lsa, const u8 *body);
u16 lsa_verify_checksum(const void *lsa_n, int lsa_len);

#define CMP_NEWER 1
#define CMP_SAME 0
#define CMP_OLDER -1
int lsa_comp(struct ospf_lsa_header *l1, struct ospf_lsa_header *l2);

struct ospf_tlv * lsa_get_tlv(struct top_hash_entry *en, uint type);

static inline u32
lsa_get_tlv_u32(struct top_hash_entry *en, uint type)
{
  struct ospf_tlv *tlv = lsa_get_tlv(en, type);
  return (tlv && (tlv->length == 4)) ? tlv->data[0] : 0;
}

void lsa_walk_rt_init(struct ospf_proto *po, struct top_hash_entry *act, struct ospf_lsa_rt_walk *rt);
int lsa_walk_rt(struct ospf_lsa_rt_walk *rt);
void lsa_parse_sum_net(struct top_hash_entry *en, int ospf2, int af, net_addr *net, u8 *pxopts, u32 *metric);
void lsa_parse_sum_rt(struct top_hash_entry *en, int ospf2, u32 *drid, u32 *metric, u32 *options);
void lsa_parse_ext(struct top_hash_entry *en, int ospf2, int af, struct ospf_lsa_ext_local *rt);
int lsa_validate(struct ospf_lsa_header *lsa, u32 lsa_type, int ospf2, void *body);

static inline btime lsa_inst_age(struct top_hash_entry *en)
{ return current_time() - en->inst_time; }

#endif /* _BIRD_OSPF_LSALIB_H_ */
