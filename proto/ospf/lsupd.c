/*
 *	BIRD -- OSPF
 *
 *	(c) 2000--2004 Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "ospf.h"


/*
struct ospf_lsupd_packet
{
  struct ospf_packet hdr;
  // union ospf_auth auth;

  u32 lsa_count;
  void lsas[];
};
*/


/* Beware of unaligned access */
void ospf_dump_lsahdr(struct proto_ospf *po, struct ospf_lsa_header *lsa_n)
{
  struct ospf_lsa_header lsa;
  u32 lsa_type;

  lsa_ntoh_hdr(lsa_n, &lsa);
  lsa_type = lsa_get_type(po, lsa.type_raw);

  log(L_TRACE "%s:     LSA      Type: %04x, Id: %R, Rt: %R, Age: %u, Seq: %08x, Sum: %04x",
      po->proto.name, lsa_type, lsa.id, lsa.rt, lsa.age, lsa.sn, lsa.checksum);
}

void ospf_dump_common(struct proto_ospf *po, struct ospf_packet *pkt)
{
  struct proto *p = &po->proto;
  log(L_TRACE "%s:     length   %d", p->name, ntohs(pkt->length));
  log(L_TRACE "%s:     router   %R", p->name, ntohl(pkt->routerid));
}

static inline unsigned
ospf_lsupd_hdrlen(struct proto_ospf *po)
{
  return ospf_pkt_hdrlen(po) + 4; /* + u32 lsa count field */
}

static inline u32 *
ospf_lsupd_lsa_count(struct ospf_packet *pkt, unsigned hdrlen)
{ return ((void *) pkt) + hdrlen - 4; }

static inline void
ospf_lsupd_body(struct proto_ospf *po, struct ospf_packet *pkt,
		unsigned *offset, unsigned *bound, unsigned *lsa_count)
{
  unsigned hlen = ospf_lsupd_hdrlen(po);
  *offset = hlen;
  *bound = ntohs(pkt->length) - sizeof(struct ospf_lsa_header);
  *lsa_count = ntohl(*ospf_lsupd_lsa_count(pkt, hlen));
}

static void ospf_lsupd_dump(struct proto_ospf *po, struct ospf_packet *pkt)
{
  struct proto *p = &po->proto;

  ASSERT(pkt->type == LSUPD_P);
  ospf_dump_common(po, pkt);

  /* We know that ntohs(pkt->length) >= sizeof(struct ospf_lsa_header) */
  unsigned offset, bound, i, lsa_count, lsalen;
  ospf_lsupd_body(po, pkt, &offset, &bound, &lsa_count);

  for (i = 0; i < lsa_count; i++)
    {
      if (offset > bound)
	{
	  log(L_TRACE "%s:     LSA      invalid", p->name);
	  return;
	}

      struct ospf_lsa_header *lsa = ((void *) pkt) + offset;
      ospf_dump_lsahdr(po, lsa);
      lsalen = ntohs(lsa->length);
      offset += lsalen;

      if (((lsalen % 4) != 0) || (lsalen <= sizeof(struct ospf_lsa_header)))
	{
	  log(L_TRACE "%s:     LSA      invalid", p->name);
	  return;
	}
    }
}


/**
 * ospf_lsupd_flood - send received or generated lsa to the neighbors
 * @po: OSPF protocol
 * @n: neighbor than sent this lsa (or NULL if generated)
 * @hn: LSA header followed by lsa body in network endianity (may be NULL) 
 * @hh: LSA header in host endianity (must be filled)
 * @domain: domain of LSA (must be filled)
 * @rtl: add this LSA into retransmission list
 *
 *
 * return value - was the LSA flooded back?
 */

int
ospf_lsupd_flood(struct proto_ospf *po,
		 struct ospf_neighbor *n, struct ospf_lsa_header *hn,
		 struct ospf_lsa_header *hh, u32 domain, int rtl)
{
  struct ospf_iface *ifa;
  struct ospf_neighbor *nn;
  struct top_hash_entry *en;
  int ret, retval = 0;

  /* pg 148 */
  WALK_LIST(ifa, po->iface_list)
  {
    if (ifa->stub)
      continue;

    if (! ospf_lsa_flooding_allowed(hh, domain, ifa))
      continue;

    DBG("Wanted to flood LSA: Type: %u, ID: %R, RT: %R, SN: 0x%x, Age %u\n",
	hh->type, hh->id, hh->rt, hh->sn, hh->age);

    ret = 0;
    WALK_LIST(nn, ifa->neigh_list)
    {
      /* 13.3 (1a) */
      if (nn->state < NEIGHBOR_EXCHANGE)
	continue;

      /* 13.3 (1b) */
      if (nn->state < NEIGHBOR_FULL)
      {
	if ((en = ospf_hash_find_header(nn->lsrqh, domain, hh)) != NULL)
	{
	  DBG("That LSA found in lsreq list for neigh %R\n", nn->rid);

	  switch (lsa_comp(hh, &en->lsa))
	  {
	  case CMP_OLDER:
	    continue;
	    break;
	  case CMP_SAME:
	    s_rem_node(SNODE en);
	    if (en->lsa_body != NULL)
	      mb_free(en->lsa_body);
	    en->lsa_body = NULL;
	    DBG("Removing from lsreq list for neigh %R\n", nn->rid);
	    ospf_hash_delete(nn->lsrqh, en);
	    if (EMPTY_SLIST(nn->lsrql))
	      ospf_neigh_sm(nn, INM_LOADDONE);
	    continue;
	    break;
	  case CMP_NEWER:
	    s_rem_node(SNODE en);
	    if (en->lsa_body != NULL)
	      mb_free(en->lsa_body);
	    en->lsa_body = NULL;
	    DBG("Removing from lsreq list for neigh %R\n", nn->rid);
	    ospf_hash_delete(nn->lsrqh, en);
	    if (EMPTY_SLIST(nn->lsrql))
	      ospf_neigh_sm(nn, INM_LOADDONE);
	    break;
	  default:
	    bug("Bug in lsa_comp?");
	  }
	}
      }

      /* 13.3 (1c) */
      if (nn == n)
	continue;

      /* 13.3 (1d) */
      if (rtl)
      {
	/* In OSPFv3, there should be check whether receiving router understand
	   that type of LSA (for LSA types with U-bit == 0). But as we does not support
	   any optional LSA types, this is not needed yet */

	if ((en = ospf_hash_find_header(nn->lsrth, domain, hh)) == NULL)
	{
	  en = ospf_hash_get_header(nn->lsrth, domain, hh);
	}
	else
	{
	  s_rem_node(SNODE en);
	}
	s_add_tail(&nn->lsrtl, SNODE en);
	memcpy(&en->lsa, hh, sizeof(struct ospf_lsa_header));
	DBG("Adding that LSA for flood to %I\n", nn->ip);
      }
      else
      {
	if ((en = ospf_hash_find_header(nn->lsrth, domain, hh)) != NULL)
	{
	  s_rem_node(SNODE en);
	  ospf_hash_delete(nn->lsrth, en);
	}
      }

      ret = 1;
    }

    if (ret == 0)
      continue;			/* pg 150 (2) */

    if (n && (n->ifa == ifa))
    {
      if ((n->rid == ifa->drid) || n->rid == ifa->bdrid)
	continue;		/* pg 150 (3) */
      if (ifa->state == OSPF_IS_BACKUP)
	continue;		/* pg 150 (4) */
      retval = 1;
    }

    {
      u16 len, age;
      unsigned hlen;
      struct ospf_packet *pkt;
      struct ospf_lsa_header *lh;

      pkt = ospf_tx_buffer(ifa);
      hlen = ospf_lsupd_hdrlen(po);

      ospf_pkt_fill_hdr(ifa, pkt, LSUPD_P);
      *ospf_lsupd_lsa_count(pkt, hlen) = htonl(1);
      lh = (((void *) pkt) + hlen);

      /* Copy LSA into the packet */
      if (hn)
      {
	memcpy(lh, hn, ntohs(hn->length));
      }
      else
      {
	u8 *help;
	struct top_hash_entry *en;

	lsa_hton_hdr(hh, lh);
	help = (u8 *) (lh + 1);
	en = ospf_hash_find_header(po->gr, domain, hh);
	lsa_hton_body(en->lsa_body, help, hh->length - sizeof(struct ospf_lsa_header));
      }

      age = ntohs(lh->age);
      age += ifa->inftransdelay;
      if (age > LSA_MAXAGE)
	age = LSA_MAXAGE;
      lh->age = htons(age);

      len = hlen + ntohs(lh->length);
      pkt->length = htons(len);

      OSPF_PACKET(ospf_lsupd_dump, pkt, "LSUPD packet flooded via %s", ifa->iface->name);

      switch (ifa->type)
      {
      case OSPF_IT_BCAST:
	if ((ifa->state == OSPF_IS_BACKUP) || (ifa->state == OSPF_IS_DR))
	  ospf_send_to_all(ifa);
	else
	  ospf_send_to_des(ifa);
	break;

      case OSPF_IT_NBMA:
	if ((ifa->state == OSPF_IS_BACKUP) || (ifa->state == OSPF_IS_DR))
	  ospf_send_to_agt(ifa, NEIGHBOR_EXCHANGE);
	else
	  ospf_send_to_bdr(ifa);
	break;

      case OSPF_IT_PTP:
	ospf_send_to_all(ifa);
	break;

      case OSPF_IT_PTMP:
	ospf_send_to_agt(ifa, NEIGHBOR_EXCHANGE);
	break;

      case OSPF_IT_VLINK:
	ospf_send_to(ifa, ifa->vip);
	break;

      default:
	bug("Bug in ospf_lsupd_flood()");
      }
    }
  }
  return retval;
}

void				/* I send all I received in LSREQ */
ospf_lsupd_send_list(struct ospf_neighbor *n, struct ospf_lsreq_item *lsr)
{
  struct ospf_area *oa = n->ifa->oa;
  struct proto_ospf *po = oa->po;
  struct top_hash_entry *en;
  struct ospf_packet *pkt;
  unsigned hlen, pos, pos2, maxsize, lsano;

  pkt = ospf_tx_buffer(n->ifa);
  hlen = ospf_lsupd_hdrlen(po);
  maxsize = ospf_pkt_maxsize(n->ifa);

  while (lsr)
  {
    /* Prepare the packet */
    ospf_pkt_fill_hdr(n->ifa, pkt, LSUPD_P);
    pos = hlen;
    lsano = 0;

    /* Fill the packet with LSAs */
    while (lsr)
    {
      en = ospf_hash_find(oa->po->gr, lsr->domain, lsr->id, lsr->rt, lsr->type);
      if (!en)
      {
	/* Probably flushed LSA, this should not happen */
	log(L_WARN "OSPF: LSA disappeared (Type: %04x, Id: %R, Rt: %R)", 
	    lsr->type, lsr->id, lsr->rt);
	lsr = lsr->next;
	continue;
      }

      pos2 = pos + en->lsa.length;
      if (pos2 > maxsize)
      {
	/* The packet if full, stop adding LSAs and sent it */
	if (lsano > 0)
	  break;

	/* LSA is larger than MTU, check buffer size */
	if (pos2 > ospf_pkt_bufsize(n->ifa))
	{
	  /* Cannot fit in a tx buffer, skip that */
	  log(L_WARN "OSPF: LSA too large to send (Type: %04x, Id: %R, Rt: %R)", 
	      lsr->type, lsr->id, lsr->rt);
	  lsr = lsr->next;
	  continue;
	}
      }

      /* Copy the LSA to the packet */
      void *lsabuf = ((void *) pkt) + pos;
      lsa_hton_hdr(&(en->lsa), (struct ospf_lsa_header *) lsabuf);
      lsa_hton_body(en->lsa_body, lsabuf + sizeof(struct ospf_lsa_header),
		    en->lsa.length - sizeof(struct ospf_lsa_header));
      pos = pos2;
      lsano++;
      lsr = lsr->next;
    }

    if (lsano == 0)
      break;

    /* Send the packet */
    pkt->length = htons(pos);
    *ospf_lsupd_lsa_count(pkt, hlen) = htonl(lsano);
    OSPF_PACKET(ospf_lsupd_dump, pkt, "LSUPD packet sent to %I via %s",
		n->ip, n->ifa->iface->name);
    ospf_send_to(n->ifa, n->ip);
  }
}

void
ospf_lsupd_receive(struct ospf_packet *pkt, struct ospf_iface *ifa,
		   struct ospf_neighbor *n)
{

  struct ospf_neighbor *ntmp;
  struct proto_ospf *po = ifa->oa->po;
  struct proto *p = &po->proto;
  unsigned sendreq = 1;

  unsigned plen = ntohs(pkt->length);
  if (plen < (ospf_lsupd_hdrlen(po) + sizeof(struct ospf_lsa_header)))
  {
    log(L_ERR "OSPF: Bad LSUPD packet from %I - too short (%u B)", n->ip, plen);
    return;
  }

  OSPF_PACKET(ospf_lsupd_dump, pkt, "LSUPD packet received from %I via %s", n->ip, ifa->iface->name);

  if (n->state < NEIGHBOR_EXCHANGE)
  {
    OSPF_TRACE(D_PACKETS, "Received lsupd in lesser state than EXCHANGE from (%I)", n->ip);
    return;
  }

  ospf_neigh_sm(n, INM_HELLOREC);	/* Questionable */

  unsigned offset, bound, i, lsa_count;
  ospf_lsupd_body(po, pkt, &offset, &bound, &lsa_count);

  for (i = 0; i < lsa_count; i++)
  {
    struct ospf_lsa_header lsatmp;
    struct top_hash_entry *lsadb;

    if (offset > bound)
    {
      log(L_WARN "OSPF: Received LSUPD from %I is too short", n->ip);
      ospf_neigh_sm(n, INM_BADLSREQ);
      return;
    }

    struct ospf_lsa_header *lsa = ((void *) pkt) + offset;
    unsigned int lsalen = ntohs(lsa->length);
    offset += lsalen;
 
    if ((offset > plen) || ((lsalen % 4) != 0) ||
	(lsalen <= sizeof(struct ospf_lsa_header)))
    {
      log(L_WARN "OSPF: Received LSA from %I with bad length", n->ip);
      ospf_neigh_sm(n, INM_BADLSREQ);
      break;
    }

    /* pg 143 (1) */
    u16 chsum = lsa->checksum;
    if (chsum != lsasum_check(lsa, NULL))
    {
      log(L_WARN "OSPF: Received LSA from %I with bad checskum: %x %x",
	  n->ip, chsum, lsa->checksum);
      continue;
    }

    u32 lsa_type, lsa_domain;
    lsa_ntoh_hdr(lsa, &lsatmp);
    lsa_xxxxtype(lsatmp.type_raw, ifa, &lsa_type, &lsa_domain);

    /* pg 143 (2) */
    if (!lsa_type)
    {
      log(L_WARN "OSPF: Received unknown LSA type from %I", n->ip);
      continue;
    }

    /* 4.5.1 (2) */
    if ((LSA_SCOPE(lsa_type) == LSA_SCOPE_AS) && !oa_is_ext(ifa->oa))
    {
      log(L_WARN "OSPF: Received LSA with AS scope in stub area from %I", n->ip);
      continue;
    }

    /* 4.5.1 (3) */
    if (LSA_SCOPE(lsa_type) == LSA_SCOPE_RES)
    {
      log(L_WARN "OSPF: Received LSA with invalid scope from %I", n->ip);
      continue;
    }

    DBG("Update Type: %04x, Id: %R, Rt: %R, Sn: 0x%08x, Age: %u, Sum: %u\n",
	lsa_type, lsatmp.id, lsatmp.rt, lsatmp.sn, lsatmp.age, lsatmp.checksum);

    lsadb = ospf_hash_find(po->gr, lsa_domain, lsatmp.id, lsatmp.rt, lsa_type);

#ifdef LOCAL_DEBUG
    if (lsadb)
      DBG("I have Type: %04x, Id: %R, Rt: %R, Sn: 0x%08x, Age: %u, Sum: %u\n",
	  lsadb->lsa_type, lsadb->lsa.id, lsadb->lsa.rt,
	  lsadb->lsa.sn, lsadb->lsa.age, lsadb->lsa.checksum);
#endif

    /* pg 143 (4) */
    if ((lsatmp.age == LSA_MAXAGE) && (lsadb == NULL) && can_flush_lsa(po))
    {
      ospf_lsack_enqueue(n, lsa, ACKL_DIRECT);
      continue;
    }

    /* pg 144 (5) */
    if ((lsadb == NULL) || (lsa_comp(&lsatmp, &lsadb->lsa) == CMP_NEWER))
    {
      struct ospf_iface *ift = NULL;
      int self = (lsatmp.rt == po->router_id);

      DBG("PG143(5): Received LSA is newer\n");

#ifdef OSPFv2
      /* 13.4 - check self-originated LSAs of NET type */
      if ((!self) && (lsa_type == LSA_T_NET))
      {
	struct ospf_iface *nifa;
	WALK_LIST(nifa, po->iface_list)
	{
	  if (!nifa->iface)
	    continue;
	  if (ipa_equal(nifa->addr->ip, ipa_from_u32(lsatmp.id)))
	  {
	    self = 1;
	    break;
	  }
	}
      }
#endif

      /* pg 145 (5f) - premature aging of self originated lsa */
      if (self)
      {
	if ((lsatmp.age == LSA_MAXAGE) && (lsatmp.sn == LSA_MAXSEQNO))
	{
	  ospf_lsack_enqueue(n, lsa, ACKL_DIRECT);
	  continue;
	}

	OSPF_TRACE(D_EVENTS, "Received old self-originated LSA (Type: %04x, Id: %R, Rt: %R)",
		   lsa_type, lsatmp.id, lsatmp.rt);

	if (lsadb)
	{
	  OSPF_TRACE(D_EVENTS, "Reflooding new self-originated LSA with newer sequence number");
	  lsadb->lsa.sn = lsatmp.sn + 1;
	  lsadb->lsa.age = 0;
	  lsadb->inst_t = now;
	  lsadb->ini_age = 0;
	  lsasum_calculate(&lsadb->lsa, lsadb->lsa_body);
	  ospf_lsupd_flood(po, NULL, NULL, &lsadb->lsa, lsa_domain, 1);
	}
	else
	{
	  OSPF_TRACE(D_EVENTS, "Premature aging it");
	  lsatmp.age = LSA_MAXAGE;
	  lsatmp.sn = LSA_MAXSEQNO;
	  lsa->age = htons(LSA_MAXAGE);
	  lsa->sn = htonl(LSA_MAXSEQNO);
	  lsasum_check(lsa, (lsa + 1));	/* It also calculates chsum! */
	  lsatmp.checksum = ntohs(lsa->checksum);
	  ospf_lsupd_flood(po, NULL, lsa, &lsatmp, lsa_domain, 0);
	}
	continue;
      }

      /* pg 144 (5a) */
      if (lsadb && ((now - lsadb->inst_t) <= MINLSARRIVAL))	/* FIXME: test for flooding? */
      {
	OSPF_TRACE(D_EVENTS, "Skipping LSA received in less that MINLSARRIVAL");
	sendreq = 0;
	continue;
      }

      /* Remove old from all ret lists */
      /* pg 144 (5c) */
      /* Must be done before (5b), otherwise it also removes the new entries from (5b) */
      if (lsadb)
	WALK_LIST(ift, po->iface_list)
	  WALK_LIST(ntmp, ift->neigh_list)
      {
	struct top_hash_entry *en;
	if (ntmp->state > NEIGHBOR_EXSTART)
	  if ((en = ospf_hash_find_header(ntmp->lsrth, lsa_domain, &lsadb->lsa)) != NULL)
	  {
	    s_rem_node(SNODE en);
	    ospf_hash_delete(ntmp->lsrth, en);
	  }
      }

      /* pg 144 (5b) */
      if (ospf_lsupd_flood(po, n, lsa, &lsatmp, lsa_domain, 1) == 0)
      {
	DBG("Wasn't flooded back\n");	/* ps 144(5e), pg 153 */
	if (ifa->state == OSPF_IS_BACKUP)
	{
	  if (ifa->drid == n->rid)
	    ospf_lsack_enqueue(n, lsa, ACKL_DELAY);
	}
	else
	  ospf_lsack_enqueue(n, lsa, ACKL_DELAY);
      }

      if ((lsatmp.age == LSA_MAXAGE) && (lsatmp.sn == LSA_MAXSEQNO)
	  && lsadb && can_flush_lsa(po))
      {
	flush_lsa(lsadb, po);
	schedule_rtcalc(po);
	continue;
      }				/* FIXME lsack? */

      /* pg 144 (5d) */
      void *body = mb_alloc(p->pool, lsatmp.length - sizeof(struct ospf_lsa_header));
      lsa_ntoh_body(lsa + 1, body, lsatmp.length - sizeof(struct ospf_lsa_header));

      /* We will do validation check after flooding and
	 acknowledging given LSA to minimize problems
	 when communicating with non-validating peer */
      if (lsa_validate(&lsatmp, lsa_type, ospf_is_v2(po), body) == 0)
      {
	log(L_WARN "Received invalid LSA from %I", n->ip);
	mb_free(body);
	continue;	
      }

      lsadb = lsa_install_new(po, &lsatmp, lsa_domain, body);
      DBG("New LSA installed in DB\n");

      /* Events 6,7 from RFC5340 4.4.3. */
      if ((lsa_type == LSA_T_LINK) && (ifa->state == OSPF_IS_DR))
	schedule_net_lsa(ifa);

      continue;
    }

    /* FIXME pg145 (6) */

    /* pg145 (7) */
    if (lsa_comp(&lsatmp, &lsadb->lsa) == CMP_SAME)
    {
      struct top_hash_entry *en;
      DBG("PG145(7) Got the same LSA\n");
      if ((en = ospf_hash_find_header(n->lsrth, lsadb->domain, &lsadb->lsa)) != NULL)
      {
	/* pg145 (7a) */
	s_rem_node(SNODE en);
	ospf_hash_delete(n->lsrth, en);

	if (ifa->state == OSPF_IS_BACKUP)
	{
	  if (n->rid == ifa->drid)
	    ospf_lsack_enqueue(n, lsa, ACKL_DELAY);
	}
      }
      else
      {
	/* pg145 (7b) */
	ospf_lsack_enqueue(n, lsa, ACKL_DIRECT);
      }
      sendreq = 0;
      continue;
    }

    /* pg145 (8) */
    if ((lsadb->lsa.age == LSA_MAXAGE) && (lsadb->lsa.sn == LSA_MAXSEQNO))
    {
      continue;
    }

    struct ospf_lsreq_item lsr = {
      .domain = lsadb->domain,
      .type = lsadb->lsa_type,
      .id = lsadb->lsa.id,
      .rt = lsadb->lsa.rt
    };
    ospf_lsupd_send_list(n, &lsr);
  }

  /* Send direct LSAs */
  ospf_lsack_send(n, ACKL_DIRECT);

  if (sendreq && (n->state == NEIGHBOR_LOADING))
  {
    ospf_lsreq_send(n);		/* Ask for another part of neighbor's database */
  }
}

void
ospf_lsupd_flush_nlsa(struct proto_ospf *po, struct top_hash_entry *en)
{
  struct ospf_lsa_header *lsa = &en->lsa;

  lsa->age = LSA_MAXAGE;
  lsa->sn = LSA_MAXSEQNO;
  lsasum_calculate(lsa, en->lsa_body);
  OSPF_TRACE(D_EVENTS, "Premature aging self originated lsa!");
  OSPF_TRACE(D_EVENTS, "Type: %04x, Id: %R, Rt: %R", en->lsa_type, lsa->id, lsa->rt);
  ospf_lsupd_flood(po, NULL, NULL, lsa, en->domain, 0);
}
