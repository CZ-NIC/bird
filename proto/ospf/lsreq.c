/*
 *	BIRD -- OSPF
 *
 *	(c) 2000--2004 Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "ospf.h"


/*
struct ospf_lsreq_packet
{
  struct ospf_packet hdr;
  // union ospf_auth auth;

  struct ospf_lsreq_header lsrs[];
};
*/

static inline void
ospf_lsreq_body(struct proto_ospf *po, struct ospf_packet *pkt, unsigned plen,
		struct ospf_lsreq_header **body, unsigned *count)
{
  unsigned hdrlen = ospf_pkt_hdrlen(po);
  *body = ((void *) pkt) + hdrlen;
  *count = (plen - hdrlen) / sizeof(struct ospf_lsreq_header);
}

static void
ospf_lsreq_dump(struct proto_ospf *po, struct ospf_packet *pkt)
{
  struct ospf_lsreq_header *lsrs;
  unsigned i, lsr_count;

  ASSERT(pkt->type == LSREQ_P);
  ospf_dump_common(po, pkt);

  ospf_lsreq_body(po, pkt, ntohs(pkt->length), &lsrs, &lsr_count);
  for (i = 0; i < lsr_count; i++)
    log(L_TRACE "%s:     LSR      Type: %04x, Id: %R, Rt: %R", po->proto.name,
	ntohl(lsrs[i].type), ntohl(lsrs[i].id), ntohl(lsrs[i].rt));
}

void
ospf_lsreq_send(struct ospf_neighbor *n)
{
  struct ospf_iface *ifa = n->ifa;
  struct proto_ospf *po = ifa->oa->po;
  struct ospf_lsreq_header *lsrs;
  struct top_hash_entry *en;
  struct ospf_packet *pkt;
  unsigned i, lsh_max, length;
  snode *sn;


  if (EMPTY_SLIST(n->lsrql))
  {
    if (n->state == NEIGHBOR_LOADING)
      ospf_neigh_sm(n, INM_LOADDONE);
    return;
  }

  pkt = ospf_tx_buffer(ifa);
  ospf_pkt_fill_hdr(ifa, pkt, LSREQ_P);
  ospf_lsreq_body(po, pkt, ospf_pkt_maxsize(ifa), &lsrs, &lsh_max);

  sn = SHEAD(n->lsrql);
  for (i = 0; i < lsh_max; i++)
  {
    en = (struct top_hash_entry *) sn;
    DBG("Requesting %uth LSA: Type: %u, ID: %R, RT: %R, SN: 0x%x, Age %u\n",
	i, en->lsa_type, en->lsa.id, en->lsa.rt, en->lsa.sn, en->lsa.age);

    u32 rtype = lsa_get_type(po, en->lsa.type_raw);
    lsrs[i].type = htonl(rtype);
    lsrs[i].rt = htonl(en->lsa.rt);
    lsrs[i].id = htonl(en->lsa.id);

    if (sn == STAIL(n->lsrql))
      break;
    sn = sn->next;
  }

  length = ospf_pkt_hdrlen(po) + i * sizeof(struct ospf_lsreq_header);
  pkt->length = htons(length);

  OSPF_PACKET(ospf_lsreq_dump, pkt, "LSREQ packet sent to %I via %s",
	      n->ip, ifa->iface->name);
  ospf_send_to(ifa, n->ip);
}


void
ospf_lsreq_receive(struct ospf_packet *pkt, struct ospf_iface *ifa,
		   struct ospf_neighbor *n)
{
  struct proto_ospf *po = ifa->oa->po;
  struct ospf_lsreq_header *lsrs;
  unsigned i, lsr_count;

  /* No need to check length, lsreq has only basic header */

  OSPF_PACKET(ospf_lsreq_dump, pkt, "LSREQ packet received from %I via %s",
	      n->ip, ifa->iface->name);

  if (n->state < NEIGHBOR_EXCHANGE)
    return;

  ospf_neigh_sm(n, INM_HELLOREC);	/* Not in RFC */

  ospf_lsreq_body(po, pkt, ntohs(pkt->length), &lsrs, &lsr_count);

  struct top_hash_entry *en, *entries[lsr_count];

  for (i = 0; i < lsr_count; i++)
  {
    u32 id, rt, type, dom;

    id = ntohl(lsrs[i].id);
    rt = ntohl(lsrs[i].rt);
    lsa_xxxxtype(ntohl(lsrs[i].type), ifa, &type, &dom);

    DBG("Processing requested LSA: Type: %04x, Id: %R, Rt: %R\n", type, id, rt);

    en = ospf_hash_find(po->gr, dom, id, rt, type); 
    if (!en)
    {
      log(L_WARN "%s: Received LSREQ from %I for missing LSA (Type: %04x, Id: %R, Rt: %R)",
	  po->proto.name, n->ip, type, id, rt);
      ospf_neigh_sm(n, INM_BADLSREQ);
      return;
    }

    entries[i] = en;
  }

  ospf_lsupd_send(n, entries, lsr_count);
}
