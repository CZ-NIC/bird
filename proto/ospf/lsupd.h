/*
 *      BIRD -- OSPF
 *
 *      (c) 2000--2004 Ondrej Filip <feela@network.cz>
 *
 *      Can be freely distributed and used under the terms of the GNU GPL.
 *
 */

#ifndef _BIRD_OSPF_LSUPD_H_
#define _BIRD_OSPF_LSUPD_H_

void ospf_dump_lsahdr(struct proto_ospf *po, struct ospf_lsa_header *lsa_n);
void ospf_dump_common(struct proto_ospf *po, struct ospf_packet *pkt);
void ospf_lsupd_receive(struct ospf_packet *ps_i, struct ospf_iface *ifa, struct ospf_neighbor *n);
int ospf_lsupd_flood(struct proto_ospf *po, struct top_hash_entry *en, struct ospf_neighbor *from);
int ospf_lsupd_send(struct ospf_neighbor *n, struct top_hash_entry **lsa_list, unsigned lsa_count);


#endif /* _BIRD_OSPF_LSUPD_H_ */
