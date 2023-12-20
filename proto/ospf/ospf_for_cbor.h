/**
 * There are cli functions for ospf.c adapted for cbor.
 */

#ifndef _BIRD_OSPF_CBOR_H_
#define _BIRD_OSPF_CBOR_H_

#include "nest/protocol.h"
#include "nest/cbor.h"
#include "ospf.h"

void show_lsa_distance_cbor(struct cbor_writer *w, struct top_hash_entry *he);
void show_lsa_router_cbor(struct cbor_writer *w, struct ospf_proto *p, struct top_hash_entry *he, int verbose);
void show_lsa_network_cbor(struct cbor_writer *w, struct top_hash_entry *he, int ospf2);
void show_lsa_sum_net_cbor(struct cbor_writer *w, struct top_hash_entry *he, int ospf2, int af);
void show_lsa_sum_rt_cbor(struct cbor_writer *w, struct top_hash_entry *he, int ospf2);
void show_lsa_external_cbor(struct cbor_writer *w, struct top_hash_entry *he, int ospf2, int af);
void show_lsa_prefix_cbor(struct cbor_writer *w, struct top_hash_entry *he, struct top_hash_entry *cnoed, int af);
struct ospf_lsa_header *fake_lsa_from_prefix_lsa_cbor(struct ospf_lsa_header *dst, struct ospf_lsa_header *src, struct ospf_lsa_prefix *px);


//int lsa_compare_for_state_cbor(const void *p1, const void *p2);
//int ext_compare_for_state_cbor(const void *p1, const void *p2);

void ospf_sh_state_cbor(struct cbor_writer *w, struct proto *P, int verbose, int reachable);

#endif
