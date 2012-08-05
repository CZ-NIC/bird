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



#ifdef OSPFv2

#define hton_opt(X) X
#define ntoh_opt(X) X
#endif


#ifdef OSPFv3

#define hton_opt(X) htonl(X)
#define ntoh_opt(X) ntohl(X)
#endif

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
  struct proto *p = &po->proto;
  struct ospf_lsa_header *lsas;
  unsigned i, lsa_count;

  ASSERT(pkt->type == DBDES_P);
  ospf_dump_common(po, pkt);

  log(L_TRACE "%s:     imms     %s%s%s", p->name,
      (imms & DBDES_I) ? "I " : "",
      (imms & DBDES_M) ? "M " : "",
      (imms & DBDES_MS) ? "MS" : "");
  log(L_TRACE "%s:     ddseq    %u", p->name, ntohl(pkt->ddseq));

  struct ospf_lsa_header *plsa = (void *) (pkt + 1);
  unsigned int i, j;

  j = (ntohs(op->length) - sizeof(struct ospf_dbdes_packet)) /
    sizeof(struct ospf_lsa_header);

  for (i = 0; i < j; i++)
    ospf_dump_lsahdr(p, &lsas[i]);
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

  struct ospf_dbdes_packet *pkt;
  struct ospf_packet *op;
  u16 length, i, j;

  /* FIXME ??? */
  if ((oa->rt == NULL) || (EMPTY_LIST(po->lsal)))
    update_rt_lsa(oa);

  switch (n->state)
  {
  case NEIGHBOR_EXSTART:	/* Send empty packets */
    n->myimms |= DBDES_I;
    pkt = ospf_tx_buffer(ifa);
    op = &pkt->ospf_packet;
    ospf_pkt_fill_hdr(ifa, pkt, DBDES_P);
    pkt->iface_mtu = (ifa->type == OSPF_IT_VLINK) ? 0 : htons(ifa->iface->mtu);
    pkt->options = hton_opt(oa->options);
    pkt->imms = n->myimms;
    pkt->ddseq = htonl(n->dds);
    length = sizeof(struct ospf_dbdes_packet);
    op->length = htons(length);

    OSPF_PACKET(ospf_dump_dbdes, pkt, "DBDES packet sent to %I via %s", n->ip, ifa->iface->name);
    ospf_send_to(ifa, n->ip);
    break;

  case NEIGHBOR_EXCHANGE:
    n->myimms &= ~DBDES_I;

    if (next)
    {
      snode *sn;
      struct ospf_lsa_header *lsa;

      pkt = n->ldbdes;
      op = (struct ospf_packet *) pkt;

      ospf_pkt_fill_hdr(ifa, pkt, DBDES_P);
      pkt->iface_mtu = (ifa->type == OSPF_IT_VLINK) ? 0 : htons(ifa->iface->mtu);
      pkt->ddseq = htonl(n->dds);
      pkt->options = hton_opt(oa->options);

      j = i = (ospf_pkt_maxsize(ifa) - sizeof(struct ospf_dbdes_packet)) / sizeof(struct ospf_lsa_header);	/* Number of possible lsaheaders to send */
      lsa = (n->ldbdes + sizeof(struct ospf_dbdes_packet));

      if (n->myimms & DBDES_M)
      {
	sn = s_get(&(n->dbsi));

	DBG("Number of LSA: %d\n", j);
	for (; i > 0; i--)
	{
	  struct top_hash_entry *en= (struct top_hash_entry *) sn;

          if (ospf_lsa_flooding_allowed(&en->lsa, en->domain, ifa))
          {
	    htonlsah(&(en->lsa), lsa);
	    DBG("Working on: %d\n", i);
	    DBG("\tX%01x %-1R %-1R %p\n", en->lsa.type, en->lsa.id, en->lsa.rt, en->lsa_body);

	    lsa++;
          }
          else i++;	/* No lsa added */

	  if (sn == STAIL(po->lsal))
          {
            i--;
	    break;
          }

	  sn = sn->next;
	}

	if (sn == STAIL(po->lsal))
	{
	  DBG("Number of LSA NOT sent: %d\n", i);
	  DBG("M bit unset.\n");
	  n->myimms &= ~DBDES_M;	/* Unset more bit */
	}

	s_put(&(n->dbsi), sn);
      }

      pkt->imms = n->myimms;

      length = (j - i) * sizeof(struct ospf_lsa_header) +
	sizeof(struct ospf_dbdes_packet);
      op->length = htons(length);

      DBG("%s: DB_DES (M) prepared for %I.\n", p->name, n->ip);
    }

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

    OSPF_PACKET(ospf_dump_dbdes, pkt, "DBDES packet sent to %I via %s", n->ip, ifa->iface->name);
    ospf_send_to(ifa, n->ip);

    if (n->myimms & DBDES_MS)
      tm_start(n->rxmt_timer, n->ifa->rxmtint);		/* Restart timer */

    if (!(n->myimms & DBDES_MS))
    {
      if (!(n->myimms & DBDES_M) && 
	  !(n->imms & DBDES_M) &&
	  (n->state == NEIGHBOR_EXCHANGE))
      {
	ospf_neigh_sm(n, INM_EXDONE);
      }
    }
    break;

  default:			/* Ignore it */
    break;
  }
}

static void
ospf_dbdes_reqladd(struct ospf_dbdes_packet *ps, struct ospf_neighbor *n)
{
  struct ospf_lsa_header *plsa, lsa;
  struct top_hash_entry *he, *sn;
  struct ospf_area *oa = n->ifa->oa;
  struct top_graph *gr = oa->po->gr;
  struct ospf_packet *op;
  int i, j;

  op = (struct ospf_packet *) ps;

  plsa = (void *) (ps + 1);

  j = (ntohs(op->length) - sizeof(struct ospf_dbdes_packet)) /
    sizeof(struct ospf_lsa_header);

  for (i = 0; i < j; i++)
  {
    ntohlsah(plsa + i, &lsa);
    u32 dom = ospf_lsa_domain(lsa.type, n->ifa);
    if (((he = ospf_hash_find_header(gr, dom, &lsa)) == NULL) ||
	(lsa_comp(&lsa, &(he->lsa)) == 1))
    {
      /* Is this condition necessary? */
      if (ospf_hash_find_header(n->lsrqh, dom, &lsa) == NULL)
      {
	sn = ospf_hash_get_header(n->lsrqh, dom, &lsa);
	ntohlsah(plsa + i, &(sn->lsa));
	s_add_tail(&(n->lsrql), SNODE sn);
      }
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


  unsigned int size = ntohs(ps_i->length);
  if (size < sizeof(struct ospf_dbdes_packet))
  {
    log(L_ERR "Bad OSPF DBDES packet from %I -  too short (%u B)", n->ip, size);
    return;
  }

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
  
  OSPF_PACKET(ospf_dbdes_dump, ps, "DBDES packet received from %I via %s", n->ip, ifa->iface->name);

  ospf_neigh_sm(n, INM_HELLOREC);

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
      log(L_WARN "OSPF: MTU mismatch with neighbour %I on interface %s (remote %d, local %d)",
	  n->ip, ifa->iface->name, rcv_iface_mtu, ifa->iface->mtu);

    if ((rcv_imms == DBDES_IMMS) &&
	(n->rid > po->router_id) &&
	(size == sizeof(struct ospf_dbdes_packet)))
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
      OSPF_TRACE(D_PACKETS, "Received duplicate dbdes from %I.", n->ip);
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
      ospf_dbdes_reqladd(ps, n);
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
      ospf_dbdes_reqladd(ps, n);
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
      OSPF_TRACE(D_PACKETS, "Received duplicate dbdes from %I.", n->ip);
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
