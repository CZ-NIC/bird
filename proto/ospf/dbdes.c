/*
 *	BIRD -- OSPF
 *
 *	(c) 1999--2004 Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "ospf.h"


struct ospf_dbdes2_packet
{
  struct ospf_packet hdr;
  union ospf_auth auth;

  u16 iface_mtu;
  u8 options;
  u8 imms;			/* I, M, MS bits */
  u32 ddseq;

  struct ospf_lsa_header lsas[];
};

struct ospf_dbdes3_packet
{
  struct ospf_packet hdr;

  u32 options;
  u16 iface_mtu;
  u8 padding;
  u8 imms;			/* I, M, MS bits */
  u32 ddseq;

  struct ospf_lsa_header lsas[];
};


static inline unsigned
ospf_dbdes_hdrlen(struct proto_ospf *po)
{
  return ospf_is_v2(po) ?
    sizeof(struct ospf_dbdes2_packet) :
    sizeof(struct ospf_dbdes3_packet);
}

static void
ospf_dbdes_body(struct proto_ospf *po, struct ospf_packet *pkt, unsigned plen,
		struct ospf_lsa_header **body, unsigned *count)
{
  unsigned hdrlen = ospf_dbdes_hdrlen(po);
  *body = ((void *) pkt) + hdrlen;
  *count = (plen - hdrlen) / sizeof(struct ospf_lsa_header);
}
  
static void ospf_dbdes_dump(struct proto_ospf *po, struct ospf_packet *pkt)
{
  struct ospf_lsa_header *lsas;
  unsigned i, lsa_count;
  u32 pkt_ddseq;
  u16 pkt_iface_mtu;
  u8 pkt_imms;

  ASSERT(pkt->type == DBDES_P);
  ospf_dump_common(po, pkt);

  if (ospf_is_v2(po))
  {
    struct ospf_dbdes2_packet *ps = (void *) pkt;
    pkt_iface_mtu = ntohs(ps->iface_mtu);
    pkt_imms = ps->imms;
    pkt_ddseq = ntohl(ps->ddseq);
  }
  else /* OSPFv3 */
  {
    struct ospf_dbdes3_packet *ps = (void *) pkt;
    pkt_iface_mtu = ntohs(ps->iface_mtu);
    pkt_imms = ps->imms;
    pkt_ddseq = ntohl(ps->ddseq);
  }

  log(L_TRACE "%s:     mtu      %u", po->proto.name, pkt_iface_mtu);
  log(L_TRACE "%s:     imms     %s%s%s", po->proto.name,
      (pkt_imms & DBDES_I) ? "I " : "",
      (pkt_imms & DBDES_M) ? "M " : "",
      (pkt_imms & DBDES_MS) ? "MS" : "");
  log(L_TRACE "%s:     ddseq    %u", po->proto.name, pkt_ddseq);

  ospf_dbdes_body(po, pkt, ntohs(pkt->length), &lsas, &lsa_count);
  for (i = 0; i < lsa_count; i++)
    ospf_dump_lsahdr(po, lsas + i);
}


static void
ospf_dbdes_prepare(struct ospf_neighbor *n, struct ospf_packet *pkt, int lsdb)
{
  struct ospf_iface *ifa = n->ifa;
  struct proto_ospf *po = ifa->oa->po;
  int i = 0;

  ospf_pkt_fill_hdr(ifa, pkt, DBDES_P);

  if (lsdb && (n->myimms & DBDES_M))
  {
    struct ospf_lsa_header *lsas;
    unsigned lsa_max;
    snode *sn;

    ospf_dbdes_body(po, pkt, ospf_pkt_maxsize(ifa), &lsas, &lsa_max);
    sn = s_get(&(n->dbsi));

    while (i < lsa_max)
    {
      struct top_hash_entry *en = (struct top_hash_entry *) sn;

      if (lsa_flooding_allowed(en->lsa_type, en->domain, ifa))
      {
	lsa_hton_hdr(&(en->lsa), lsas + i);
	i++;
      }

      if (sn == STAIL(po->lsal))
      {
	n->myimms &= ~DBDES_M;	/* Unset more bit */
	break;
      }

      sn = sn->next;
    }

    s_put(&(n->dbsi), sn);
  }

  u16 iface_mtu = (ifa->type == OSPF_IT_VLINK) ? 0 : ifa->iface->mtu;
  unsigned length;

  if (ospf_is_v2(po))
  {
    struct ospf_dbdes2_packet *ps = (void *) pkt;

    ps->iface_mtu = htons(iface_mtu);
    ps->options = ifa->oa->options;
    ps->imms = n->myimms;
    ps->ddseq = htonl(n->dds);

    length = sizeof(struct ospf_dbdes2_packet);
  }
  else /* OSPFv3 */
  {
    struct ospf_dbdes3_packet *ps = (void *) pkt;

    ps->options = htonl(ifa->oa->options);
    ps->iface_mtu = htons(iface_mtu);
    ps->imms = n->myimms;
    ps->ddseq = htonl(n->dds);

    length = sizeof(struct ospf_dbdes3_packet);
  }

  length += i * sizeof(struct ospf_lsa_header);
  pkt->length = htons(length);
}

/**
 * ospf_dbdes_send - transmit database description packet
 * @n: neighbor
 * @next: whether to send a next packet in a sequence (1) or to retransmit the old one (0)
 *
 * Sending of a database description packet is described in 10.8 of RFC 2328.
 * Reception of each packet is acknowledged in the sequence number of another.
 * When I send a packet to a neighbor I keep a copy in a buffer. If the neighbor
 * does not reply, I don't create a new packet but just send the content
 * of the buffer.
 */
void
ospf_dbdes_send(struct ospf_neighbor *n, int next)
{
  struct ospf_iface *ifa = n->ifa;
  struct ospf_area *oa = ifa->oa;
  struct proto_ospf *po = oa->po;
  struct ospf_packet *pkt;
  unsigned length;

  /* FIXME ??? */
  if ((oa->rt == NULL) || (EMPTY_LIST(po->lsal)))
    update_rt_lsa(oa);

  switch (n->state)
  {
  case NEIGHBOR_EXSTART:
    n->myimms |= DBDES_I;

    /* Send empty packets */
    pkt = ospf_tx_buffer(ifa);
    ospf_dbdes_prepare(n, pkt, 0);
    OSPF_PACKET(ospf_dbdes_dump, pkt, "DBDES packet sent to %I via %s", n->ip, ifa->iface->name);
    ospf_send_to(ifa, n->ip);
    break;

  case NEIGHBOR_EXCHANGE:
    n->myimms &= ~DBDES_I;

    if (next)
      ospf_dbdes_prepare(n, n->ldbdes, 1);

  case NEIGHBOR_LOADING:
  case NEIGHBOR_FULL:

    length = ntohs(((struct ospf_packet *) n->ldbdes)->length);
    if (!length)
    {
      OSPF_TRACE(D_PACKETS, "No packet in my buffer for repeating");
      ospf_neigh_sm(n, INM_KILLNBR);
      return;
    }

    /* Copy last sent packet again */
    pkt = ospf_tx_buffer(ifa);
    memcpy(pkt, n->ldbdes, length);

    OSPF_PACKET(ospf_dbdes_dump, pkt, "DBDES packet sent to %I via %s", n->ip, ifa->iface->name);
    ospf_send_to(ifa, n->ip);

    /* XXXX remove this? */
    if (n->myimms & DBDES_MS)
      tm_start(n->rxmt_timer, n->ifa->rxmtint);		/* Restart timer */

    if (!(n->myimms & DBDES_MS))
      if (!(n->myimms & DBDES_M) && 
	  !(n->imms & DBDES_M) &&
	  (n->state == NEIGHBOR_EXCHANGE))
	ospf_neigh_sm(n, INM_EXDONE);

    break;

  default:			/* Ignore it */
    break;
  }
}

static void
ospf_dbdes_process(struct ospf_neighbor *n, struct ospf_packet *pkt, unsigned plen)
{
  struct ospf_iface *ifa = n->ifa;
  struct proto_ospf *po = ifa->oa->po;
  struct ospf_lsa_header *lsas;
  unsigned i, lsa_count;

  ospf_dbdes_body(po, pkt, plen, &lsas, &lsa_count);

  for (i = 0; i < lsa_count; i++)
  {
    struct top_hash_entry *en, *req;
    struct ospf_lsa_header lsa;
    u32 lsa_type, lsa_domain;

    lsa_ntoh_hdr(lsas + i, &lsa);
    lsa_xxxxtype(lsa.type_raw, ifa, &lsa_type, &lsa_domain);

    /* XXXX: Add check for 0-type or flooding_allowed */

    en = ospf_hash_find(po->gr, lsa_domain, lsa.id, lsa.rt, lsa_type);
    if (!en || (lsa_comp(&lsa, &(en->lsa)) == CMP_NEWER))
    {
      req = ospf_hash_get(n->lsrqh, lsa_domain, lsa.id, lsa.rt, lsa_type);

      if (ospf_hash_is_new(req))
	s_add_tail(&(n->lsrql), SNODE req);

      en->lsa = lsa; // XXXX ??? should be req->lsa ?
    }
  }
}

void
ospf_dbdes_receive(struct ospf_packet *pkt, struct ospf_iface *ifa,
		   struct ospf_neighbor *n)
{
  struct proto_ospf *po = ifa->oa->po;
  u32 rcv_ddseq, rcv_options;
  u16 rcv_iface_mtu;
  u8 rcv_imms;
  unsigned plen;

  plen = ntohs(pkt->length);
  if (plen < ospf_dbdes_hdrlen(po))
  {
    log(L_ERR "OSPF: Bad DBDES packet from %I - too short (%u B)", n->ip, plen);
    return;
  }

  OSPF_PACKET(ospf_dbdes_dump, pkt, "DBDES packet received from %I via %s", n->ip, ifa->iface->name);

  ospf_neigh_sm(n, INM_HELLOREC);

  if (ospf_is_v2(po))
  {
    struct ospf_dbdes2_packet *ps = (void *) pkt;
    rcv_iface_mtu = ntohs(ps->iface_mtu);
    rcv_options = ps->options;
    rcv_imms = ps->imms;
    rcv_ddseq = ntohl(ps->ddseq);
  }
  else /* OSPFv3 */
  {
    struct ospf_dbdes3_packet *ps = (void *) pkt;
    rcv_options = ntohl(ps->options);
    rcv_iface_mtu = ntohs(ps->iface_mtu);
    rcv_imms = ps->imms;
    rcv_ddseq = ntohl(ps->ddseq);
  }
  
  switch (n->state)
  {
  case NEIGHBOR_DOWN:
  case NEIGHBOR_ATTEMPT:
  case NEIGHBOR_2WAY:
    return;

  case NEIGHBOR_INIT:
    ospf_neigh_sm(n, INM_2WAYREC);
    if (n->state != NEIGHBOR_EXSTART)
      return;

  case NEIGHBOR_EXSTART:
    if ((rcv_iface_mtu != ifa->iface->mtu) &&
	(rcv_iface_mtu != 0) &&
	(ifa->iface->mtu != 0) && 
	(ifa->type != OSPF_IT_VLINK))
      log(L_WARN "OSPF: MTU mismatch with neighbor %I on interface %s (remote %d, local %d)",
	  n->ip, ifa->iface->name, rcv_iface_mtu, ifa->iface->mtu);

    if ((rcv_imms == DBDES_IMMS) &&
	(n->rid > po->router_id) &&
	(plen == ospf_dbdes_hdrlen(po)))
    {
      /* I'm slave! */
      n->dds = rcv_ddseq;
      n->ddr = rcv_ddseq;
      n->options = rcv_options;
      n->myimms &= ~DBDES_MS;
      n->imms = rcv_imms;
      OSPF_TRACE(D_PACKETS, "I'm slave to %I", n->ip);
      ospf_neigh_sm(n, INM_NEGDONE);
      ospf_dbdes_send(n, 1);
      break;
    }

    if (!(rcv_imms & DBDES_I) &&
	!(rcv_imms & DBDES_MS) &&
        (n->rid < po->router_id) &&
	(n->dds == rcv_ddseq))
    {
      /* I'm master! */
      n->options = rcv_options;
      n->ddr = rcv_ddseq - 1;	/* It will be set corectly a few lines down */
      n->imms = rcv_imms;
      OSPF_TRACE(D_PACKETS, "I'm master to %I", n->ip);
      ospf_neigh_sm(n, INM_NEGDONE);
    }
    else
    {
      DBG("%s: Nothing happend to %I (imms=%d)\n", p->name, n->ip, rcv_imms);
      break;
    }

  case NEIGHBOR_EXCHANGE:
    if ((rcv_imms == n->imms) &&
	(rcv_options == n->options) &&
	(rcv_ddseq == n->ddr))
    {
      /* Duplicate packet */
      OSPF_TRACE(D_PACKETS, "Received duplicate dbdes from %I", n->ip);
      if (!(n->myimms & DBDES_MS))
      {
	/* Slave should retransmit dbdes packet */
	ospf_dbdes_send(n, 0);
      }
      return;
    }

    if ((rcv_imms & DBDES_MS) != (n->imms & DBDES_MS))	/* M/S bit differs */
    {
      OSPF_TRACE(D_PACKETS, "dbdes - sequence mismatch neighbor %I (bit MS)", n->ip);
      ospf_neigh_sm(n, INM_SEQMIS);
      break;
    }

    if (rcv_imms & DBDES_I)		/* I bit is set */
    {
      OSPF_TRACE(D_PACKETS, "dbdes - sequence mismatch neighbor %I (bit I)", n->ip);
      ospf_neigh_sm(n, INM_SEQMIS);
      break;
    }

    if (rcv_options != n->options)	/* Options differs */
    {
      OSPF_TRACE(D_PACKETS, "dbdes - sequence mismatch neighbor %I (options)", n->ip);
      ospf_neigh_sm(n, INM_SEQMIS);
      break;
    }

    n->ddr = rcv_ddseq;
    n->imms = rcv_imms;

    if (n->myimms & DBDES_MS)
    {
      if (rcv_ddseq != n->dds)	/* MASTER */
      {
	OSPF_TRACE(D_PACKETS, "dbdes - sequence mismatch neighbor %I (master)", n->ip);
	ospf_neigh_sm(n, INM_SEQMIS);
	break;
      }
      n->dds++;
      DBG("Incrementing dds\n");
      ospf_dbdes_process(n, pkt, plen);
      if (!(n->myimms & DBDES_M) &&
	  !(rcv_imms & DBDES_M))
      {
	ospf_neigh_sm(n, INM_EXDONE);
      }
      else
      {
	ospf_dbdes_send(n, 1);
      }

    }
    else
    {
      if (rcv_ddseq != (n->dds + 1))	/* SLAVE */
      {
	OSPF_TRACE(D_PACKETS, "dbdes - sequence mismatch neighbor %I (slave)", n->ip);
	ospf_neigh_sm(n, INM_SEQMIS);
	break;
      }
      n->ddr = rcv_ddseq;
      n->dds = rcv_ddseq;
      ospf_dbdes_process(n, pkt, plen);
      ospf_dbdes_send(n, 1);
    }
    break;

  case NEIGHBOR_LOADING:
  case NEIGHBOR_FULL:
    if ((rcv_imms == n->imms) &&
	(rcv_options == n->options) &&
	(rcv_ddseq == n->ddr))
      /* Only duplicate are accepted */
    {
      OSPF_TRACE(D_PACKETS, "Received duplicate dbdes from %I", n->ip);
      if (!(n->myimms & DBDES_MS))
      {
	/* Slave should retransmit dbdes packet */
	ospf_dbdes_send(n, 0);
      }
      return;
    }
    else
    {
      OSPF_TRACE(D_PACKETS, "dbdes - sequence mismatch neighbor %I (full)", n->ip);
      DBG("PS=%u, DDR=%u, DDS=%u\n", rcv_ddseq, n->ddr, n->dds);
      ospf_neigh_sm(n, INM_SEQMIS);
    }
    break;
  default:
    bug("Received dbdes from %I in undefined state.", n->ip);
  }
}
