/*
 *	BIRD -- OSPF
 *
 *	(c) 2000-2004 Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "ospf.h"


/*
struct ospf_lsack_packet
{
  struct ospf_packet hdr;
  // union ospf_auth auth;

  struct ospf_lsa_header lsas[];
};
*/


static void
ospf_lsack_body(struct proto_ospf *po, struct ospf_packet *pkt, unsigned plen,
		struct ospf_lsa_header **body, unsigned *count)
{
  unsigned hdrlen = ospf_pkt_hdrlen(po);
  *body = ((void *) pkt) + hdrlen;
  *count = (plen - hdrlen) / sizeof(struct ospf_lsa_header);
}

static void
ospf_lsack_dump(struct proto_ospf *po, struct ospf_packet *pkt)
{
  struct ospf_lsa_header *lsas;
  unsigned i, lsa_count;

  ASSERT(pkt->type == LSACK_P);
  ospf_dump_common(po, pkt);

  ospf_lsack_body(po, pkt, ntohs(pkt->length), &lsas, &lsa_count);
  for (i = 0; i < lsa_count; i++)
    ospf_dump_lsahdr(po, lsas + i);
}


/*
 * =====================================
 * Note, that h is in network endianity!
 * =====================================
 */

void
ospf_lsack_enqueue(struct ospf_neighbor *n, struct ospf_lsa_header *h, int queue)
{
  struct lsah_n *no = mb_alloc(n->pool, sizeof(struct lsah_n));
  memcpy(&no->lsa, h, sizeof(struct ospf_lsa_header));
  add_tail(&n->ackl[queue], NODE no);
  DBG("Adding (%s) ack for %R, ID: %R, RT: %R, Type: %u\n",
      (queue == ACKL_DIRECT) ? "direct" : "delayed",
      n->rid, ntohl(h->id), ntohl(h->rt), h->type);
}

static inline void
ospf_lsack_send_one(struct ospf_neighbor *n, int queue)
{
  struct ospf_iface *ifa = n->ifa;
  struct proto_ospf *po = ifa->oa->po;
  struct ospf_lsa_header *lsas;
  struct ospf_packet *pkt;
  struct lsah_n *no;
  unsigned i, lsa_max, length;


  pkt = ospf_tx_buffer(ifa);
  ospf_pkt_fill_hdr(ifa, pkt, LSACK_P);
  ospf_lsack_body(po, pkt, ospf_pkt_maxsize(ifa), &lsas, &lsa_max);

  for (i = 0; i < lsa_max && !EMPTY_LIST(n->ackl[queue]); i++)
  {
    no = (struct lsah_n *) HEAD(n->ackl[queue]);
    memcpy(&lsas[i], &no->lsa, sizeof(struct ospf_lsa_header));
    DBG("Iter %u ID: %R, RT: %R, Type: %04x\n",
	i, ntohl(lsas[i].id), ntohl(lsas[i].rt), lsas[i].type);
    rem_node(NODE no);
    mb_free(no);
  }

  length = ospf_pkt_hdrlen(po) + i * sizeof(struct ospf_lsa_header);
  pkt->length = htons(length);

  OSPF_PACKET(ospf_lsack_dump, pkt, "LSACK packet sent via %s", ifa->iface->name);

  /* XXXX this is very strange */
  if (ifa->type == OSPF_IT_BCAST)
  {
    if ((ifa->state == OSPF_IS_DR) || (ifa->state == OSPF_IS_BACKUP))
      ospf_send_to_all(ifa);
    else
      ospf_send_to_des(ifa);
  }
  else
    ospf_send_to_agt(ifa, NEIGHBOR_EXCHANGE);

  /*
    if ((ifa->state == OSPF_IS_DR) || (ifa->state == OSPF_IS_BACKUP))
      ospf_send_to_agt(ifa, NEIGHBOR_EXCHANGE);
    else
      ospf_send_to_bdr(ifa);
  */
}

void
ospf_lsack_send(struct ospf_neighbor *n, int queue)
{
  while (!EMPTY_LIST(n->ackl[queue]))
    ospf_lsack_send_one(n, queue);
}

void
ospf_lsack_receive(struct ospf_packet *pkt, struct ospf_iface *ifa,
		   struct ospf_neighbor *n)
{
  struct proto_ospf *po = ifa->oa->po;
  struct ospf_lsa_header lsa, *lsas;
  struct top_hash_entry *en;
  unsigned i, lsa_count;
  u32 lsa_dom, lsa_type;


  /* No need to check length, lsack has only basic header */

  OSPF_PACKET(ospf_lsack_dump, pkt, "LSACK packet received from %I via %s",
	      n->ip, ifa->iface->name);

  if (n->state < NEIGHBOR_EXCHANGE)
    return;

  ospf_neigh_sm(n, INM_HELLOREC);	/* Not in RFC */

  ospf_lsack_body(po, pkt, ntohs(pkt->length), &lsas, &lsa_count);
  for (i = 0; i < lsa_count; i++)
  {
    lsa_ntoh_hdr(&lsas[i], &lsa);
    lsa_xxxxtype(lsa.type_raw, n->ifa, &lsa_type, &lsa_dom);

    en = ospf_hash_find(n->lsrth, lsa_dom, lsa.id, lsa.rt, lsa_type);
    if (!en)
      continue;			/* pg 155 */

    if (lsa_comp(&lsa, &en->lsa) != CMP_SAME)	/* pg 156 */
    {
      if ((lsa.sn == LSA_MAXSEQNO) && (lsa.age == LSA_MAXAGE))
	continue;

      OSPF_TRACE(D_PACKETS, "Strange LSACK from %I", n->ip);
      OSPF_TRACE(D_PACKETS, "Type: %04x, Id: %R, Rt: %R",
		 lsa_type, lsa.id, lsa.rt);
      OSPF_TRACE(D_PACKETS, "I have: Age: %4u, Seq: %08x, Sum: %04x",
		 en->lsa.age, en->lsa.sn, en->lsa.checksum);
      OSPF_TRACE(D_PACKETS, "He has: Age: %4u, Seq: %08x, Sum: %04x",
		 lsa.age, lsa.sn, lsa.checksum);
      continue;
    }

    DBG("Deleting LSA (Type: %04x Id: %R Rt: %R) from lsrtl for neighbor %R\n",
	lsa_type, lsa.id, lsa.rt, n->rid);
    s_rem_node(SNODE en);
    ospf_hash_delete(n->lsrth, en);
  }
}
