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

static inline uint
ospf_lsupd_hdrlen(struct proto_ospf *po)
{
  return ospf_pkt_hdrlen(po) + 4; /* + u32 lsa count field */
}

static inline u32
ospf_lsupd_get_lsa_count(struct ospf_packet *pkt, uint hdrlen)
{
  u32 *c = ((void *) pkt) + hdrlen - 4;
  return ntohl(*c);
}

static inline void
ospf_lsupd_set_lsa_count(struct ospf_packet *pkt, uint hdrlen, u32 val)
{
  u32 *c = ((void *) pkt) + hdrlen - 4;
  *c = htonl(val);
}

static inline void
ospf_lsupd_body(struct proto_ospf *po, struct ospf_packet *pkt,
		uint *offset, uint *bound, uint *lsa_count)
{
  uint hlen = ospf_lsupd_hdrlen(po);
  *offset = hlen;
  *bound = ntohs(pkt->length) - sizeof(struct ospf_lsa_header);
  *lsa_count = ospf_lsupd_get_lsa_count(pkt, hlen);
}

static void ospf_lsupd_dump(struct proto_ospf *po, struct ospf_packet *pkt)
{
  struct proto *p = &po->proto;

  ASSERT(pkt->type == LSUPD_P);
  ospf_dump_common(po, pkt);

  /* We know that ntohs(pkt->length) >= sizeof(struct ospf_lsa_header) */
  uint offset, bound, i, lsa_count, lsalen;
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


static inline void
ospf_lsa_lsrt_up(struct top_hash_entry *en, struct ospf_neighbor *n)
{
  struct top_hash_entry *ret = ospf_hash_get_entry(n->lsrth, en);

  if (! ospf_hash_is_new(ret))
    s_rem_node(SNODE ret);

  s_add_tail(&n->lsrtl, SNODE ret);
  memcpy(&ret->lsa, &en->lsa, sizeof(struct ospf_lsa_header));
}

static inline int
ospf_lsa_lsrt_down(struct top_hash_entry *en, struct ospf_neighbor *n)
{
  struct top_hash_entry *ret = ospf_hash_find_entry(n->lsrth, en);

  if (ret)
  {
    s_rem_node(SNODE ret);
    ospf_hash_delete(n->lsrth, ret);
    return 1;
  }

  return 0;
}


static void ospf_lsupd_flood_ifa(struct proto_ospf *po, struct ospf_iface *ifa, struct top_hash_entry *en);


static inline int
ospf_addr_is_local(struct proto_ospf *po, struct ospf_area *oa, ip_addr ip)
{
  struct ospf_iface *ifa;
  WALK_LIST(ifa, po->iface_list)
    if ((ifa->oa == oa) && ifa->addr && ipa_equal(ifa->addr->ip, ip))
      return 1;

  return 0;
}

static void
ospf_lsupd_handle_self_originated_lsa()
{
  // XXXX

  /* 13. (5a) - handle MinLSArrival timeout */

  /* pg 145 (5f) - premature aging of self originated lsa */
  /*
  if ((lsa.age == LSA_MAXAGE) && (lsa.sn == LSA_MAXSEQNO))
  {
    ospf_lsack_enqueue(n, lsa_n, ACKL_DIRECT);
    return;
  }

  OSPF_TRACE(D_EVENTS, "Received old self-originated LSA (Type: %04x, Id: %R, Rt: %R)",
	     lsa_type, lsa.id, lsa.rt);

  if (en)
  {
    OSPF_TRACE(D_EVENTS, "Reflooding new self-originated LSA with newer sequence number");
    en->lsa.sn = lsa.sn + 1;
    en->lsa.age = 0;
    en->inst_t = now;
    en->ini_age = 0;
    lsasum_calculate(&en->lsa, en->lsa_body);
    ospf_lsupd_flood(po, NULL, NULL, &en->lsa, lsa_domain, 1);
  }
  else
  {
    OSPF_TRACE(D_EVENTS, "Premature aging it");
    lsa.age = LSA_MAXAGE;
    lsa.sn = LSA_MAXSEQNO;
    lsa_n->age = htons(LSA_MAXAGE);
    lsa_n->sn = htonl(LSA_MAXSEQNO);
    lsasum_check(lsa_n, (lsa_n + 1)); */	/* It also calculates chsum! */ /*
    lsa.checksum = ntohs(lsa_n->checksum);
    ospf_lsupd_flood(po, NULL, lsa_n, &lsa, lsa_domain, 0);
  }
*/
}

void
ospf_lsupd_receive(struct ospf_packet *pkt, struct ospf_iface *ifa,
		   struct ospf_neighbor *n)
{
  struct proto_ospf *po = ifa->oa->po;
  struct proto *p = &po->proto;

  uint sendreq = 1; /* XXXX ?? */

  uint plen = ntohs(pkt->length);
  if (plen < (ospf_lsupd_hdrlen(po) + sizeof(struct ospf_lsa_header)))
  {
    log(L_ERR "OSPF: Bad LSUPD packet from %I - too short (%u B)", n->ip, plen);
    return;
  }

  OSPF_PACKET(ospf_lsupd_dump, pkt, "LSUPD packet received from %I via %s", n->ip, ifa->ifname);

  if (n->state < NEIGHBOR_EXCHANGE)
  {
    OSPF_TRACE(D_PACKETS, "Received lsupd in lesser state than EXCHANGE from (%I)", n->ip);
    return;
  }

  ospf_neigh_sm(n, INM_HELLOREC);	/* Questionable */

  uint offset, bound, i, lsa_count;
  ospf_lsupd_body(po, pkt, &offset, &bound, &lsa_count);

  for (i = 0; i < lsa_count; i++)
  {
    struct ospf_lsa_header lsa, *lsa_n;
    struct top_hash_entry *en;
    u32 lsa_len, lsa_type, lsa_domain;

    if (offset > bound)
    {
      log(L_WARN "OSPF: Received LSUPD from %I is too short", n->ip);
      ospf_neigh_sm(n, INM_BADLSREQ);
      return;
    }

    /* LSA header in network order */
    lsa_n = ((void *) pkt) + offset;
    lsa_len = ntohs(lsa_n->length);
    offset += lsa_len;
 
    if ((offset > plen) || ((lsa_len % 4) != 0) ||
	(lsa_len <= sizeof(struct ospf_lsa_header)))
    {
      log(L_WARN "%s: Received LSA from %I with bad length", p->name, n->ip);
      ospf_neigh_sm(n, INM_BADLSREQ);
      break;
    }

    /* RFC 2328 13. (1) - validate LSA checksum */
    u16 chsum = lsa_n->checksum;
    if (chsum != lsasum_check(lsa_n, NULL))
    {
      log(L_WARN "%s: Received LSA from %I with bad checskum: %x %x",
	  p->name, n->ip, chsum, lsa_n->checksum);
      continue;
    }

    /* LSA header in host order */
    lsa_ntoh_hdr(lsa_n, &lsa);
    lsa_xxxxtype(lsa.type_raw, ifa, &lsa_type, &lsa_domain);

    DBG("Update Type: %04x, Id: %R, Rt: %R, Sn: 0x%08x, Age: %u, Sum: %u\n",
	lsa_type, lsa.id, lsa.rt, lsa.sn, lsa.age, lsa.checksum);

    /* RFC 2328 13. (2) */
    if (!lsa_type)
    {
      log(L_WARN "%s: Received unknown LSA type from %I", p->name, n->ip);
      continue;
    }

    /* RFC 5340 4.5.1 (2) and RFC 2328 13. (3) */
    if ((LSA_SCOPE(lsa_type) == LSA_SCOPE_AS) && !oa_is_ext(ifa->oa))
    {
      log(L_WARN "%s: Received LSA with AS scope in stub area from %I", p->name, n->ip);
      continue;
    }

    /* RFC 5340 4.5.1 (3) */
    if (LSA_SCOPE(lsa_type) == LSA_SCOPE_RES)
    {
      log(L_WARN "%s: Received LSA with invalid scope from %I", p->name, n->ip);
      continue;
    }

    /* Find local copy of LSA in link state database */
    en = ospf_hash_find(po->gr, lsa_domain, lsa.id, lsa.rt, lsa_type);

#ifdef LOCAL_DEBUG
    if (en)
      DBG("I have Type: %04x, Id: %R, Rt: %R, Sn: 0x%08x, Age: %u, Sum: %u\n",
	  en->lsa_type, en->lsa.id, en->lsa.rt, en->lsa.sn, en->lsa.age, en->lsa.checksum);
#endif

    /* 13. (4) - ignore maxage LSA if i have no local copy */
    if ((lsa.age == LSA_MAXAGE) && !en && can_flush_lsa(po))
    {
      /* 13.5. - schedule ACKs (tbl 19, case 5) */ 
      ospf_lsack_enqueue(n, lsa_n, ACKL_DIRECT);
      continue;
    }

    /* 13. (5) - received LSA is newer (or no local copy) */
    if (!en || (lsa_comp(&lsa, &en->lsa) == CMP_NEWER))
    {
      /* 13. (5f) - handle self-originated LSAs, see also 13.4. */
      if ((lsa.rt == po->router_id) ||
	  (ospf_is_v2(po) && (lsa_type == LSA_T_NET) && ospf_addr_is_local(po, ifa->oa, ipa_from_u32(lsa.id))))
      {
	ospf_lsupd_handle_self_originated_lsa();
	continue;
      }

      /* 13. (5a) - enforce minimum time between updates */
      /* Note that en was received via flooding, because local LSAs are handled above */
      if (en && ((now - en->inst_t) <= MINLSARRIVAL))
      {
	OSPF_TRACE(D_EVENTS, "Skipping LSA received in less that MinLSArrival");
	sendreq = 0;
	continue;
      }

      /* 13. (5c) - remove old LSA from all retransmission lists */
      /* Must be done before (5b), otherwise it also removes the new entries from (5b) */
      if (en)
      {
	struct ospf_iface *ifi;
	struct ospf_neighbor *ni;

	WALK_LIST(ifi, po->iface_list)
	  WALK_LIST(ni, ifi->neigh_list)
	    if (ni->state > NEIGHBOR_EXSTART)
	      ospf_lsa_lsrt_down(en, ni);
      }

      /* 13. (5d) - install new LSA into database */
      int blen = lsa.length - sizeof(struct ospf_lsa_header);
      void *body = mb_alloc(p->pool, blen);
      lsa_ntoh_body(lsa_n + 1, body, blen);

      en = ospf_install_lsa(po, &lsa, lsa_domain, body);

      /*
      XXXX

      if (lsa_validate(&lsa, lsa_type, ospf_is_v2(po), body) == 0)
      {
	log(L_WARN "Received invalid LSA from %I", n->ip);
	mb_free(body);
	continue;
      }
      */


      /* 13. (5b) - flood new LSA */
      int flood_back = ospf_lsupd_flood(po, en, n);

      /* 13.5. - schedule ACKs (tbl 19, cases 1+2) */ 
      if (! flood_back)
	if ((ifa->state != OSPF_IS_BACKUP) || (n->rid == ifa->drid))
	  ospf_lsack_enqueue(n, lsa_n, ACKL_DELAY);

      /* RFC 5340 4.4.3. events 6+7 */
      if ((lsa_type == LSA_T_LINK) && (ifa->state == OSPF_IS_DR))
	schedule_net_lsa(ifa);

      continue;
    }

    /* FIXME pg145 (6) */

    /* 13. (7) - received LSA is same */
    if (lsa_comp(&lsa, &en->lsa) == CMP_SAME)
    {
      /* Duplicate LSA, treat as implicit ACK */
      int implicit_ack = ospf_lsa_lsrt_down(en, n);

      /* 13.5. - schedule ACKs (tbl 19, cases 3+4) */ 
      if (implicit_ack)
      {
	if ((ifa->state == OSPF_IS_BACKUP) && (n->rid == ifa->drid))
	  ospf_lsack_enqueue(n, lsa_n, ACKL_DELAY);
      }
      else
	ospf_lsack_enqueue(n, lsa_n, ACKL_DIRECT);

      sendreq = 0;
      continue;
    }

    /* 13. (8) - received LSA is older */
    {
      /* Seqnum is wrapping, wait until it is flushed */
      if ((en->lsa.age == LSA_MAXAGE) && (en->lsa.sn == LSA_MAXSEQNO))
	continue;

      /* Send newer local copy back to neighbor */
      /* FIXME - check for MinLSArrival ? */
      ospf_lsupd_send(n, &en, 1);
    }
  }

  /* Send direct LSAs */
  ospf_lsack_send(n, ACKL_DIRECT);

  if (sendreq && (n->state == NEIGHBOR_LOADING))
  {
    ospf_lsreq_send(n);		/* Ask for another part of neighbor's database */
  }
}


/**
 * ospf_lsupd_flood - send received or generated LSA to the neighbors
 * @po: OSPF protocol
 * @en: LSA entry
 * @from: neighbor than sent this LSA (or NULL if LSA is local)
 *
 * return value - was the LSA flooded back?
 */

int
ospf_lsupd_flood(struct proto_ospf *po, struct top_hash_entry *en, struct ospf_neighbor *from)
{
  struct ospf_iface *ifa;
  struct ospf_neighbor *n;

  int back = 0;
  WALK_LIST(ifa, po->iface_list)
  {
    if (ifa->stub)
      continue;

    if (! lsa_flooding_allowed(en->lsa_type, en->domain, ifa))
      continue;

    DBG("Wanted to flood LSA: Type: %u, ID: %R, RT: %R, SN: 0x%x, Age %u\n",
	hh->type, hh->id, hh->rt, hh->sn, hh->age);

    int used = 0;
    WALK_LIST(n, ifa->neigh_list)
    {
      /* 13.3 (1a) */
      if (n->state < NEIGHBOR_EXCHANGE)
	continue;

      /* 13.3 (1b) */
      if (n->state < NEIGHBOR_FULL)
      {
	struct top_hash_entry *req = ospf_hash_find_entry(n->lsrqh, en);
	if (req != NULL)
	{
	  int cmp = lsa_comp(&en->lsa, &req->lsa);

	  /* If same or newer, remove LSA from the link state request list */
	  if (cmp > CMP_OLDER)
	  {
	    s_rem_node(SNODE req);
	    ospf_hash_delete(n->lsrqh, req);
	    if ((EMPTY_SLIST(n->lsrql)) && (n->state == NEIGHBOR_LOADING))
	      ospf_neigh_sm(n, INM_LOADDONE);
	  }

	  /* If older or same, skip processing of this LSA */
	  if (cmp < CMP_NEWER)
	    continue;
	}
      }

      /* 13.3 (1c) */
      if (n == from)
	continue;

      /* In OSPFv3, there should be check whether receiving router understand
	 that type of LSA (for LSA types with U-bit == 0). But as we do not support
	 any optional LSA types, this is not needed yet */

      /* 13.3 (1d) - add LSA to the link state retransmission list */
      ospf_lsa_lsrt_up(en, n);

      used = 1;
    }

    /* 13.3 (2) */
    if (!used)
      continue;

    if (from && (from->ifa == ifa))
    {
      /* 13.3 (3) */
      if ((from->rid == ifa->drid) || from->rid == ifa->bdrid)
	continue;

      /* 13.3 (4) */
      if (ifa->state == OSPF_IS_BACKUP)
	continue;

      back = 1;
    }

    /* 13.3 (5) - finally flood the packet */
    ospf_lsupd_flood_ifa(po, ifa, en);
  }

  return back;
}

static int
ospf_lsupd_prepare(struct proto_ospf *po, struct ospf_iface *ifa,
		   struct top_hash_entry **lsa_list, uint lsa_count)
{
  struct ospf_packet *pkt;
  uint hlen, pos, i, maxsize;

  pkt = ospf_tx_buffer(ifa);
  hlen = ospf_lsupd_hdrlen(po);
  maxsize = ospf_pkt_maxsize(ifa);

  ospf_pkt_fill_hdr(ifa, pkt, LSUPD_P);
  pos = hlen;

  for (i = 0; i < lsa_count; i++)
  {
    struct top_hash_entry *en = lsa_list[i];
    uint len = en->lsa.length;

    if ((pos + len) > maxsize)
    {
      /* The packet if full, stop adding LSAs and sent it */
      if (i > 0)
	break;

      /* LSA is larger than MTU, check buffer size */
      if (ospf_iface_assure_bufsize(ifa, pos + len) < 0)
      {
	/* Cannot fit in a tx buffer, skip that */
	log(L_ERR "OSPF: LSA too large to send on %s (Type: %04x, Id: %R, Rt: %R)", 
	    ifa->ifname, en->lsa_type, en->lsa.id, en->lsa.rt);
	XXXX(); /* XXXX: handle packets with no LSA */
	continue;
      }

      /* TX buffer could be reallocated */
      pkt = ospf_tx_buffer(ifa);
    }

    struct ospf_lsa_header *buf = ((void *) pkt) + pos;
    lsa_hton_hdr(&en->lsa, buf);
    lsa_hton_body(en->lsa_body, ((void *) buf) + sizeof(struct ospf_lsa_header),
		  len - sizeof(struct ospf_lsa_header));
    buf->age = htons(MIN(en->lsa.age + ifa->inftransdelay, LSA_MAXAGE));

    pos += len;
  }
   
  ospf_lsupd_set_lsa_count(pkt, hlen, i);
  pkt->length = htons(pos);

  return i;
}


static void
ospf_lsupd_flood_ifa(struct proto_ospf *po, struct ospf_iface *ifa, struct top_hash_entry *en)
{
  ospf_lsupd_prepare(po, ifa, &en, 1);

  OSPF_PACKET(ospf_lsupd_dump, ospf_tx_buffer(ifa),
	      "LSUPD packet flooded via %s", ifa->ifname);

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

int
ospf_lsupd_send(struct ospf_neighbor *n, struct top_hash_entry **lsa_list, uint lsa_count)
{
  struct ospf_iface *ifa = n->ifa;
  struct proto_ospf *po = ifa->oa->po;
  uint i, c;

  for (i = 0; i < lsa_count; i += c)
  {
    c = ospf_lsupd_prepare(po, ifa, lsa_list + i, lsa_count - i);

    OSPF_PACKET(ospf_lsupd_dump, ospf_tx_buffer(ifa),
		"LSUPD packet sent to %I via %s", n->ip, ifa->ifname);

    ospf_send_to(ifa, n->ip);
  }

  return lsa_count;
}

void
ospf_lsupd_rxmt(struct ospf_neighbor *n)
{
  struct proto_ospf *po = n->ifa->oa->po;

  const uint max = 128;
  struct top_hash_entry *entries[max];
  struct top_hash_entry *ret, *en;
  uint i = 0;

  WALK_SLIST(ret, n->lsrtl)
  {
    en = ospf_hash_find_entry(po->gr, ret);
    if (!en)
    {
      /* Probably flushed LSA, this should not happen */
      // log(L_WARN "%s: LSA disappeared (Type: %04x, Id: %R, Rt: %R)",
      //     po->proto.name, ret->lsa_type, ret->lsa.id, ret->lsa.rt);

      XXXX(); /* remove entry */
      continue;
    }

    entries[i] = en;
    i++;

    if (i == max)
      break;
  }

  ospf_lsupd_send(n, entries, i);
}
