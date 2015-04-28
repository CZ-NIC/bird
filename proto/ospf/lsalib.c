/*
 *	BIRD -- OSPF
 *
 *	(c) 1999--2004 Ondrej Filip <feela@network.cz>
 *	(c) 2009--2014 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2009--2014 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "ospf.h"


#ifndef CPU_BIG_ENDIAN
void
lsa_hton_hdr(struct ospf_lsa_header *h, struct ospf_lsa_header *n)
{
  n->age = htons(h->age);
  n->type_raw = htons(h->type_raw);
  n->id = htonl(h->id);
  n->rt = htonl(h->rt);
  n->sn = htonl(h->sn);
  n->checksum = htons(h->checksum);
  n->length = htons(h->length);
}

void
lsa_ntoh_hdr(struct ospf_lsa_header *n, struct ospf_lsa_header *h)
{
  h->age = ntohs(n->age);
  h->type_raw = ntohs(n->type_raw);
  h->id = ntohl(n->id);
  h->rt = ntohl(n->rt);
  h->sn = ntohl(n->sn);
  h->checksum = ntohs(n->checksum);
  h->length = ntohs(n->length);
}

void
lsa_hton_body(void *h, void *n, u16 len)
{
  u32 *hid = h;
  u32 *nid = n;
  uint i;

  for (i = 0; i < (len / sizeof(u32)); i++)
    nid[i] = htonl(hid[i]);
}

void
lsa_ntoh_body(void *n, void *h, u16 len)
{
  u32 *nid = n;
  u32 *hid = h;
  uint i;

  for (i = 0; i < (len / sizeof(u32)); i++)
    hid[i] = ntohl(nid[i]);
}
#endif /* little endian */



int
lsa_flooding_allowed(u32 type, u32 domain, struct ospf_iface *ifa)
{
  /* Handle inactive vlinks */
  if (ifa->state == OSPF_IS_DOWN)
    return 0;

  /* 4.5.2 (Case 2) */
  switch (LSA_SCOPE(type))
  {
  case LSA_SCOPE_LINK:
    return ifa->iface_id == domain;

  case LSA_SCOPE_AREA:
    return ifa->oa->areaid == domain;

  case LSA_SCOPE_AS:
    if (ifa->type == OSPF_IT_VLINK)
      return 0;
    if (!oa_is_ext(ifa->oa))
      return 0;
    return 1;

  default:
    log(L_ERR "OSPF: LSA with invalid scope");
    return 0;
  }
}


static int
unknown_lsa_type(u32 type)
{
  switch (type)
  {
  case LSA_T_RT:
  case LSA_T_NET:
  case LSA_T_SUM_NET:
  case LSA_T_SUM_RT:
  case LSA_T_EXT:
  case LSA_T_NSSA:
  case LSA_T_LINK:
  case LSA_T_PREFIX:
    return 0;

  default:
    return 1;
  }
}

#define LSA_V2_TMAX 8
static const u16 lsa_v2_types[LSA_V2_TMAX] =
  {0, LSA_T_RT, LSA_T_NET, LSA_T_SUM_NET, LSA_T_SUM_RT, LSA_T_EXT, 0, LSA_T_NSSA};

void
lsa_get_type_domain_(u32 itype, struct ospf_iface *ifa, u32 *otype, u32 *domain)
{
  if (ospf_is_v2(ifa->oa->po))
  {
    itype = itype & LSA_T_V2_MASK;
    itype = (itype < LSA_V2_TMAX) ? lsa_v2_types[itype] : 0;
  }
  else
  {
    /* For unkown LSAs without U-bit change scope to LSA_SCOPE_LINK */
    if (unknown_lsa_type(itype) && !(itype & LSA_UBIT))
      itype = itype & ~LSA_SCOPE_MASK;
  }

  *otype = itype;

  switch (LSA_SCOPE(itype))
  {
  case LSA_SCOPE_LINK:
    *domain = ifa->iface_id;
    return;

  case LSA_SCOPE_AREA:
    *domain = ifa->oa->areaid;
    return;

  case LSA_SCOPE_AS:
  default:
    *domain = 0;
    return;
  }
}



/*
void
buf_dump(const char *hdr, const byte *buf, int blen)
{
  char b2[1024];
  char *bp;
  int first = 1;
  int i;

  const char *lhdr = hdr;

  bp = b2;
  for(i = 0; i < blen; i++)
    {
      if ((i > 0) && ((i % 16) == 0))
	{
	      *bp = 0;
	      log(L_WARN "%s\t%s", lhdr, b2);
	      lhdr = "";
	      bp = b2;
	}

      bp += snprintf(bp, 1022, "%02x ", buf[i]);

    }

  *bp = 0;
  log(L_WARN "%s\t%s", lhdr, b2);
}
*/

#define MODX 4102		/* larges signed value without overflow */

/* Fletcher Checksum -- Refer to RFC1008. */
#define MODX                 4102
#define LSA_CHECKSUM_OFFSET    15

/* FIXME This is VERY uneficient, I have huge endianity problems */
void
lsasum_calculate(struct ospf_lsa_header *h, void *body)
{
  u16 length = h->length;

  //  log(L_WARN "Checksum %R %R %d start (len %d)", h->id, h->rt, h->type, length);
  lsa_hton_hdr(h, h);
  lsa_hton_body1(body, length - sizeof(struct ospf_lsa_header));

  /*
  char buf[1024];
  memcpy(buf, h, sizeof(struct ospf_lsa_header));
  memcpy(buf + sizeof(struct ospf_lsa_header), body, length - sizeof(struct ospf_lsa_header));
  buf_dump("CALC", buf, length);
  */

  (void) lsasum_check(h, body, 1);

  //  log(L_WARN "Checksum result %4x", h->checksum);

  lsa_ntoh_hdr(h, h);
  lsa_ntoh_body1(body, length - sizeof(struct ospf_lsa_header));
}

/*
 * Calculates the Fletcher checksum of an OSPF LSA.
 *
 * If 'update' is non-zero, the checkbytes (X and Y in RFC905) are calculated
 * and the checksum field in the header is updated. The return value is the
 * checksum as placed in the header (in network byte order).
 *
 * If 'update' is zero, only C0 and C1 are calculated and the header is kept
 * intact. The return value is a combination of C0 and C1; if the return value
 * is exactly zero the checksum is considered valid, any non-zero value is
 * invalid.
 *
 * Note that this function expects the input LSA to be in network byte order.
 */
u16
lsasum_check(struct ospf_lsa_header *h, void *body, int update)
{
  u8 *sp, *ep, *p, *q, *b;
  int c0 = 0, c1 = 0;
  int x, y;
  u16 length;

  b = body;
  sp = (char *) h;
  sp += 2; /* Skip Age field */
  length = ntohs(h->length) - 2;
  if (update) h->checksum = 0;

  for (ep = sp + length; sp < ep; sp = q)
  {				/* Actually MODX is very large, do we need the for-cyclus? */
    q = sp + MODX;
    if (q > ep)
      q = ep;
    for (p = sp; p < q; p++)
    {
      /*
       * I count with bytes from header and than from body
       * but if there is no body, it's appended to header
       * (probably checksum in update receiving) and I go on
       * after header
       */
      if ((b == NULL) || (p < (u8 *) (h + 1)))
      {
	c0 += *p;
      }
      else
      {
	c0 += *(b + (p - (u8 *) (h + 1)));
      }

      c1 += c0;
    }
    c0 %= 255;
    c1 %= 255;
  }

  if (!update) {
    /*
     * When testing the checksum, we don't need to calculate x and y. The
     * checksum passes if c0 and c1 are both 0.
     */
    return (c0 << 8) | (c1 & 0xff);
  }

  x = (int)((length - LSA_CHECKSUM_OFFSET) * c0 - c1) % 255;
  if (x <= 0)
    x += 255;
  y = 510 - c0 - x;
  if (y > 255)
    y -= 255;

  ((u8 *) & h->checksum)[0] = x;
  ((u8 *) & h->checksum)[1] = y;
  return h->checksum;
}

int
lsa_comp(struct ospf_lsa_header *l1, struct ospf_lsa_header *l2)
			/* Return codes from point of view of l1 */
{
  u32 sn1, sn2;

  sn1 = l1->sn - LSA_INITSEQNO + 1;
  sn2 = l2->sn - LSA_INITSEQNO + 1;

  if (sn1 > sn2)
    return CMP_NEWER;
  if (sn1 < sn2)
    return CMP_OLDER;

  if (l1->checksum != l2->checksum)
    return l1->checksum < l2->checksum ? CMP_OLDER : CMP_NEWER;

  if ((l1->age == LSA_MAXAGE) && (l2->age != LSA_MAXAGE))
    return CMP_NEWER;
  if ((l2->age == LSA_MAXAGE) && (l1->age != LSA_MAXAGE))
    return CMP_OLDER;

  if (ABS(l1->age - l2->age) > LSA_MAXAGEDIFF)
    return l1->age < l2->age ? CMP_NEWER : CMP_OLDER;

  return CMP_SAME;
}


static inline int
lsa_walk_rt2(struct ospf_lsa_rt_walk *rt)
{
  if (rt->buf >= rt->bufend)
    return 0;

  struct ospf_lsa_rt2_link *l = rt->buf;
  rt->buf += sizeof(struct ospf_lsa_rt2_link) + l->no_tos * sizeof(struct ospf_lsa_rt2_tos);

  rt->type = l->type;
  rt->metric = l->metric;
  rt->id = l->id;
  rt->data = l->data;
  return 1;
}

static inline int
lsa_walk_rt3(struct ospf_lsa_rt_walk *rt)
{
  while (rt->buf >= rt->bufend)
  {
    rt->en = ospf_hash_find_rt3_next(rt->en);
    if (!rt->en)
      return 0;

    rt->buf = rt->en->lsa_body;
    rt->bufend = rt->buf + rt->en->lsa.length - sizeof(struct ospf_lsa_header);
    rt->buf += sizeof(struct ospf_lsa_rt);
  }

  struct ospf_lsa_rt3_link *l = rt->buf;
  rt->buf += sizeof(struct ospf_lsa_rt3_link);

  rt->type = l->type;
  rt->metric = l->metric;
  rt->lif = l->lif;
  rt->nif = l->nif;
  rt->id = l->id;
  return 1;
}

void
lsa_walk_rt_init(struct ospf_proto *p, struct top_hash_entry *act, struct ospf_lsa_rt_walk *rt)
{
  rt->ospf2 = ospf_is_v2(p);
  rt->id = rt->data = rt->lif = rt->nif = 0;

  if (rt->ospf2)
    rt->en = act;
  else
    rt->en = ospf_hash_find_rt3_first(p->gr, act->domain, act->lsa.rt);

  rt->buf = rt->en->lsa_body;
  rt->bufend = rt->buf + rt->en->lsa.length - sizeof(struct ospf_lsa_header);
  rt->buf += sizeof(struct ospf_lsa_rt);
}

int
lsa_walk_rt(struct ospf_lsa_rt_walk *rt)
{
  return rt->ospf2 ? lsa_walk_rt2(rt) : lsa_walk_rt3(rt);
}


void
lsa_parse_sum_net(struct top_hash_entry *en, int ospf2, ip_addr *ip, int *pxlen, u8 *pxopts, u32 *metric)
{
  if (ospf2)
  {
    struct ospf_lsa_sum2 *ls = en->lsa_body;
    *ip = ipa_from_u32(en->lsa.id & ls->netmask);
    *pxlen = u32_masklen(ls->netmask);
    *pxopts = 0;
    *metric = ls->metric & LSA_METRIC_MASK;
  }
  else
  {
    struct ospf_lsa_sum3_net *ls = en->lsa_body;
    u16 rest;
    lsa_get_ipv6_prefix(ls->prefix, ip, pxlen, pxopts, &rest);
    *metric = ls->metric & LSA_METRIC_MASK;
  }
}

void
lsa_parse_sum_rt(struct top_hash_entry *en, int ospf2, u32 *drid, u32 *metric, u32 *options)
{
  if (ospf2)
  {
    struct ospf_lsa_sum2 *ls = en->lsa_body;
    *drid = en->lsa.id;
    *metric = ls->metric & LSA_METRIC_MASK;
    *options = 0;
  }
  else
  {
    struct ospf_lsa_sum3_rt *ls = en->lsa_body;
    *drid = ls->drid;
    *metric = ls->metric & LSA_METRIC_MASK;
    *options = ls->options & LSA_OPTIONS_MASK;
  }
}

void
lsa_parse_ext(struct top_hash_entry *en, int ospf2, struct ospf_lsa_ext_local *rt)
{
  if (ospf2)
  {
    struct ospf_lsa_ext2 *ext = en->lsa_body;
    rt->ip = ipa_from_u32(en->lsa.id & ext->netmask);
    rt->pxlen = u32_masklen(ext->netmask);
    rt->pxopts = 0;
    rt->metric = ext->metric & LSA_METRIC_MASK;
    rt->ebit = ext->metric & LSA_EXT2_EBIT;

    rt->fbit = ext->fwaddr;
    rt->fwaddr = ipa_from_u32(ext->fwaddr);

    rt->tag = ext->tag;
    rt->propagate = lsa_get_options(&en->lsa) & OPT_P;
  }
  else
  {
    struct ospf_lsa_ext3 *ext = en->lsa_body;
    u16 rest;
    u32 *buf = lsa_get_ipv6_prefix(ext->rest, &rt->ip, &rt->pxlen, &rt->pxopts, &rest);
    rt->metric = ext->metric & LSA_METRIC_MASK;
    rt->ebit = ext->metric & LSA_EXT3_EBIT;

    rt->fbit = ext->metric & LSA_EXT3_FBIT;
    if (rt->fbit)
      buf = lsa_get_ipv6_addr(buf, &rt->fwaddr);
    else
      rt->fwaddr = IPA_NONE;

    rt->tag = (ext->metric & LSA_EXT3_TBIT) ? *buf++ : 0;
    rt->propagate = rt->pxopts & OPT_PX_P;
  }
}

#define HDRLEN sizeof(struct ospf_lsa_header)

static int
lsa_validate_rt2(struct ospf_lsa_header *lsa, struct ospf_lsa_rt *body)
{
  if (lsa->length < (HDRLEN + sizeof(struct ospf_lsa_rt)))
    return 0;

  uint i = 0;
  void *buf = body;
  void *bufend = buf + lsa->length - HDRLEN;
  buf += sizeof(struct ospf_lsa_rt);

  while (buf < bufend)
  {
    struct ospf_lsa_rt2_link *l = buf;
    buf += sizeof(struct ospf_lsa_rt2_link) + l->no_tos * sizeof(struct ospf_lsa_rt2_tos);
    i++;

    if (buf > bufend)
      return 0;

    if (!((l->type == LSART_PTP) ||
	  (l->type == LSART_NET) ||
	  (l->type == LSART_STUB) ||
	  (l->type == LSART_VLNK)))
      return 0;
  }

  if ((body->options & LSA_RT2_LINKS) != i)
    return 0;

  return 1;
}


static int
lsa_validate_rt3(struct ospf_lsa_header *lsa, struct ospf_lsa_rt *body)
{
  if (lsa->length < (HDRLEN + sizeof(struct ospf_lsa_rt)))
    return 0;

  void *buf = body;
  void *bufend = buf + lsa->length - HDRLEN;
  buf += sizeof(struct ospf_lsa_rt);

  while (buf < bufend)
  {
    struct ospf_lsa_rt3_link *l = buf;
    buf += sizeof(struct ospf_lsa_rt3_link);

    if (buf > bufend)
      return 0;

    if (!((l->type == LSART_PTP) ||
	  (l->type == LSART_NET) ||
	  (l->type == LSART_VLNK)))
      return 0;
  }
  return 1;
}

static int
lsa_validate_net(struct ospf_lsa_header *lsa, struct ospf_lsa_net *body UNUSED)
{
  if (lsa->length < (HDRLEN + sizeof(struct ospf_lsa_net)))
    return 0;

  return 1;
}

static int
lsa_validate_sum2(struct ospf_lsa_header *lsa, struct ospf_lsa_sum2 *body)
{
  if (lsa->length < (HDRLEN + sizeof(struct ospf_lsa_sum2)))
    return 0;

  /* First field should have TOS = 0, we ignore other TOS fields */
  if ((body->metric & LSA_SUM2_TOS) != 0)
    return 0;

  return 1;
}

static inline int
pxlen(u32 *buf)
{
  return *buf >> 24;
}

static int
lsa_validate_sum3_net(struct ospf_lsa_header *lsa, struct ospf_lsa_sum3_net *body)
{
  if (lsa->length < (HDRLEN + sizeof(struct ospf_lsa_sum3_net) + 4))
    return 0;

  u8 pxl = pxlen(body->prefix);
  if (pxl > MAX_PREFIX_LENGTH)
    return 0;

  if (lsa->length != (HDRLEN + sizeof(struct ospf_lsa_sum3_net) +
		      IPV6_PREFIX_SPACE(pxl)))
    return 0;

  return 1;
}

static int
lsa_validate_sum3_rt(struct ospf_lsa_header *lsa, struct ospf_lsa_sum3_rt *body)
{
  if (lsa->length != (HDRLEN + sizeof(struct ospf_lsa_sum3_rt)))
    return 0;

  return 1;
}

static int
lsa_validate_ext2(struct ospf_lsa_header *lsa, struct ospf_lsa_ext2 *body)
{
  if (lsa->length < (HDRLEN + sizeof(struct ospf_lsa_ext2)))
    return 0;

  /* First field should have TOS = 0, we ignore other TOS fields */
  if ((body->metric & LSA_EXT2_TOS) != 0)
    return 0;

  return 1;
}

static int
lsa_validate_ext3(struct ospf_lsa_header *lsa, struct ospf_lsa_ext3 *body)
{
  if (lsa->length < (HDRLEN + sizeof(struct ospf_lsa_ext3) + 4))
    return 0;

  u8 pxl = pxlen(body->rest);
  if (pxl > MAX_PREFIX_LENGTH)
    return 0;

  int len = IPV6_PREFIX_SPACE(pxl);
  if (body->metric & LSA_EXT3_FBIT) // forwardinf address
    len += 16;
  if (body->metric & LSA_EXT3_TBIT) // route tag
    len += 4;
  if (*body->rest & 0xFFFF) // referenced LS type field
    len += 4;

  if (lsa->length != (HDRLEN + sizeof(struct ospf_lsa_ext3) + len))
    return 0;

  return 1;
}

static int
lsa_validate_pxlist(struct ospf_lsa_header *lsa, u32 pxcount, uint offset, u8 *pbuf)
{
  uint bound = lsa->length - HDRLEN - 4;
  u32 i;

  for (i = 0; i < pxcount; i++)
    {
      if (offset > bound)
	return 0;

      u8 pxl = pxlen((u32 *) (pbuf + offset));
      if (pxl > MAX_PREFIX_LENGTH)
	return 0;

      offset += IPV6_PREFIX_SPACE(pxl);
    }

  if (lsa->length != (HDRLEN + offset))
    return 0;

  return 1;
}

static int
lsa_validate_link(struct ospf_lsa_header *lsa, struct ospf_lsa_link *body)
{
  if (lsa->length < (HDRLEN + sizeof(struct ospf_lsa_link)))
    return 0;

  return lsa_validate_pxlist(lsa, body->pxcount, sizeof(struct ospf_lsa_link), (u8 *) body);
}

static int
lsa_validate_prefix(struct ospf_lsa_header *lsa, struct ospf_lsa_prefix *body)
{
  if (lsa->length < (HDRLEN + sizeof(struct ospf_lsa_prefix)))
    return 0;

  return lsa_validate_pxlist(lsa, body->pxcount, sizeof(struct ospf_lsa_prefix), (u8 *) body);
}


/**
 * lsa_validate - check whether given LSA is valid
 * @lsa: LSA header
 * @body: pointer to LSA body
 *
 * Checks internal structure of given LSA body (minimal length,
 * consistency). Returns true if valid.
 */

int
lsa_validate(struct ospf_lsa_header *lsa, u32 lsa_type, int ospf2, void *body)
{
  if (ospf2)
  {
    switch (lsa_type)
    {
    case LSA_T_RT:
      return lsa_validate_rt2(lsa, body);
    case LSA_T_NET:
      return lsa_validate_net(lsa, body);
    case LSA_T_SUM_NET:
      return lsa_validate_sum2(lsa, body);
    case LSA_T_SUM_RT:
      return lsa_validate_sum2(lsa, body);
    case LSA_T_EXT:
    case LSA_T_NSSA:
      return lsa_validate_ext2(lsa, body);
    default:
      return 0;	/* Should not happen, unknown LSAs are already rejected */
    }
  }
  else
  {
    switch (lsa_type)
    {
    case LSA_T_RT:
      return lsa_validate_rt3(lsa, body);
    case LSA_T_NET:
      return lsa_validate_net(lsa, body);
    case LSA_T_SUM_NET:
      return lsa_validate_sum3_net(lsa, body);
    case LSA_T_SUM_RT:
      return lsa_validate_sum3_rt(lsa, body);
    case LSA_T_EXT:
    case LSA_T_NSSA:
      return lsa_validate_ext3(lsa, body);
    case LSA_T_LINK:
      return lsa_validate_link(lsa, body);
    case LSA_T_PREFIX:
      return lsa_validate_prefix(lsa, body);
    default:
      return 1;	/* Unknown LSAs are OK in OSPFv3 */
    }
  }
}
