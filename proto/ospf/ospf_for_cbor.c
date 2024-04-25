
/**
 * There are cli functions from ospf.c adapted for cbor.
 */

#include <stdlib.h>
#include "ospf.h"
#include "nest/cbor_shortcuts.h"

void
show_lsa_distance_cbor (struct cbor_writer *w, struct top_hash_entry *he)
{
  if (he->color == INSPF)
    cbor_string_int (w, "distance", he->dist);
  else
    cbor_string_string (w, "distance", "unreachable");
}

void
show_lsa_router_cbor (struct cbor_writer *w, struct ospf_proto *p,
		      struct top_hash_entry *he, int verbose)
{
  struct ospf_lsa_rt_walk rtl;

  cbor_add_string (w, "lsa_router");
  cbor_open_block (w);
  cbor_string_ipv4 (w, "router", he->lsa.rt);
  show_lsa_distance_cbor (w, he);

  cbor_add_string(w, "rt");
  cbor_open_list(w);
  lsa_walk_rt_init(p, he, &rtl);
  
  int dummy_id = 0;
  while (lsa_walk_rt(&rtl))
  {
    cbor_open_block(w);
    cbor_string_int(w, "dummy_id", dummy_id);
    dummy_id++;
    cbor_string_int(w, "metric", rtl.metric);
    switch (rtl.type) {
    case (LSART_VLNK):
    {
      cbor_add_string(w, "vlink");
      cbor_open_block_with_length(w, 1);
      cbor_string_ipv4(w, "vlink", rtl.id);
      break;
    }
  
    case (LSART_PTP):
    {
      cbor_add_string(w, "router_metric");
      cbor_open_block_with_length(w, 1);
      cbor_string_ipv4(w, "router", rtl.id);
      break;
    }

    case (LSART_NET):
    {
      cbor_add_string(w, "network");
      if (ospf_is_v2(p))
      {
	/* In OSPFv2, we try to find network-LSA to get prefix/pxlen */
	struct top_hash_entry *net_he = ospf_hash_find_net2(p->gr, he->domain, rtl.id);

	if (net_he && (net_he->lsa.age < LSA_MAXAGE))
	{
	  struct ospf_lsa_header *net_lsa = &(net_he->lsa);
	  struct ospf_lsa_net *net_ln = net_he->lsa_body;

	  cbor_open_block_with_length(w, 2);
	  cbor_string_ipv4(w, "network", net_lsa->id & net_ln->optx);
	  cbor_string_int(w, "len", u32_masklen(net_ln->optx));
	}
	else
	{
	  cbor_open_block_with_length(w, 1);
	  cbor_string_ipv4(w, "network", rtl.id);
	}
      }
      else
      {
	cbor_open_block_with_length(w, 2);
	cbor_string_ipv4(w, "network", rtl.id);
	cbor_string_int(w, "nif", rtl.nif);
      }
      break;
    }
    case (LSART_STUB):
    {
      if (ospf_is_v2(p) && verbose)
      {
	cbor_add_string(w, "stubnet");
	cbor_open_block_with_length(w, 2);
	cbor_string_ipv4(w, "stubnet", rtl.id);
	cbor_string_int(w, "len", u32_masklen(rtl.data));
      }
      break;
    }} // both case and switch
    cbor_close_block_or_list(w);
  }
  cbor_close_block_or_list(w);
  cbor_close_block_or_list(w);
}

void
show_lsa_network_cbor (struct cbor_writer *w, struct top_hash_entry *he,
		       int ospf2)
{
  cbor_add_string (w, "lsa_network");
  cbor_open_block_with_length (w, 3);
  struct ospf_lsa_header *lsa = &(he->lsa);
  struct ospf_lsa_net *ln = he->lsa_body;
  u32 i;

  if (ospf2)
    {
      cbor_add_string (w, "ospf2");
      cbor_open_block_with_length (w, 3);
      cbor_string_ipv4 (w, "network", lsa->id & ln->optx);
      cbor_string_int (w, "optx", u32_masklen (ln->optx));
      cbor_string_ipv4 (w, "dr", lsa->rt);
    }
  else
    {
      cbor_add_string (w, "ospf");
      cbor_open_block_with_length (w, 2);
      cbor_string_ipv4 (w, "network", lsa->rt);
      cbor_string_int (w, "lsa_id", lsa->id);
    }

  show_lsa_distance_cbor (w, he);

  cbor_add_string (w, "routers");
  cbor_open_list (w);
  for (i = 0; i < lsa_net_count (lsa); i++)
    {
      cbor_open_block_with_length (w, 1);
      cbor_string_ipv4 (w, "router", ln->routers[i]);
    }

  cbor_close_block_or_list (w);
}

void
show_lsa_sum_net_cbor (struct cbor_writer *w, struct top_hash_entry *he,
		       int ospf2, int af)
{
  net_addr net;
  u8 pxopts;
  u32 metric;

  lsa_parse_sum_net (he, ospf2, af, &net, &pxopts, &metric);
  cbor_add_string (w, "lsa_sum_net");
  cbor_open_block_with_length (w, 2);
  cbor_add_string (w, "net");
  cbor_add_net (w, &net);
  cbor_string_int (w, "metric", metric);
}

void
show_lsa_sum_rt_cbor (struct cbor_writer *w, struct top_hash_entry *he,
		      int ospf2)
{
  u32 metric;
  u32 dst_rid;
  u32 options;

  lsa_parse_sum_rt (he, ospf2, &dst_rid, &metric, &options);

  cbor_add_string (w, "lsa_sum_rt");
  cbor_open_block_with_length (w, 2);
  cbor_string_ipv4 (w, "router", dst_rid);
  cbor_string_int (w, "metric", metric);
}

void
show_lsa_external_cbor (struct cbor_writer *w, struct top_hash_entry *he,
			int ospf2, int af)
{
  struct ospf_lsa_ext_local rt;

  cbor_add_string (w, "lsa_external");
  cbor_open_block (w);
  if (he->lsa_type == LSA_T_EXT)
    he->domain = 0;		/* Unmark the LSA */

  lsa_parse_ext (he, ospf2, af, &rt);

  if (rt.fbit)
    {
      cbor_string_ipv4 (w, "via", rt.fwaddr.addr[0]);
    }

  if (rt.tag)
    cbor_string_int (w, "tag", rt.tag);

  if (he->lsa_type == LSA_T_NSSA)
    {
      cbor_string_string (w, "lsa_type", "nssa-ext");
    }
  else
    {
      cbor_string_string (w, "lsa_type", "external");
    }
  cbor_add_string (w, "rt_net");
  cbor_add_net (w, &rt.net);

  if (rt.ebit)
    {
      cbor_string_int (w, "lsa_type_num", 2);
    }
  cbor_string_int (w, "metric", rt.metric);
  cbor_close_block_or_list (w);
}


void
show_lsa_prefix_cbor (struct cbor_writer *w, struct top_hash_entry *he,
		      struct top_hash_entry *cnode, int af)
{
  struct ospf_lsa_prefix *px = he->lsa_body;
  u32 *buf;
  int i;
  cbor_add_string (w, "lsa_prefix");
  cbor_open_block (w);

  /* We check whether given prefix-LSA is related to the current node */
  if ((px->ref_type != cnode->lsa.type_raw) || (px->ref_rt != cnode->lsa.rt))
    {
      cbor_close_block_or_list (w);
      return;
    }

  if ((px->ref_type == LSA_T_RT) && (px->ref_id != 0))
    {
      cbor_close_block_or_list (w);
      return;
    }

  if ((px->ref_type == LSA_T_NET) && (px->ref_id != cnode->lsa.id))
    {
      cbor_close_block_or_list (w);
      return;
    }

  buf = px->rest;

  cbor_add_string (w, "prefixes");
  cbor_open_list (w);
  for (i = 0; i < px->pxcount; i++)
    {
      net_addr net;
      u8 pxopts;
      u16 metric;

      cbor_open_block (w);

      buf = ospf3_get_prefix (buf, af, &net, &pxopts, &metric);

      if (px->ref_type == LSA_T_RT)
	{
	  cbor_add_string (w, "stubnet");
	  cbor_add_net (w, &net);
	  cbor_string_int (w, "metric", metric);
	}
      else
	{
	  cbor_add_string (w, "stubnet");
	  cbor_add_net (w, &net);
	}
      cbor_close_block_or_list (w);
    }

  cbor_close_block_or_list (w);
  cbor_close_block_or_list (w);
}

struct ospf_lsa_header *
fake_lsa_from_prefix_lsa_cbor (struct ospf_lsa_header *dst,
			       struct ospf_lsa_header *src,
			       struct ospf_lsa_prefix *px)
{
  dst->age = src->age;
  dst->type_raw = px->ref_type;
  dst->id = px->ref_id;
  dst->rt = px->ref_rt;
  dst->sn = src->sn;

  return dst;
}

static int lsa_compare_ospf3_cbor;

static int
lsa_compare_for_state_cbor (const void *p1, const void *p2)
{
  struct top_hash_entry *he1 = *(struct top_hash_entry **) p1;
  struct top_hash_entry *he2 = *(struct top_hash_entry **) p2;
  struct ospf_lsa_header *lsa1 = &(he1->lsa);
  struct ospf_lsa_header *lsa2 = &(he2->lsa);
  struct ospf_lsa_header lsatmp1, lsatmp2;
  u16 lsa1_type = he1->lsa_type;
  u16 lsa2_type = he2->lsa_type;

  if (he1->domain < he2->domain)
    return -1;
  if (he1->domain > he2->domain)
    return 1;


  /* px1 or px2 assumes OSPFv3 */
  int px1 = (lsa1_type == LSA_T_PREFIX);
  int px2 = (lsa2_type == LSA_T_PREFIX);

  if (px1)
    {
      lsa1 = fake_lsa_from_prefix_lsa_cbor (&lsatmp1, lsa1, he1->lsa_body);
      lsa1_type = lsa1->type_raw;	/* FIXME: handle unknown ref_type */
    }

  if (px2)
    {
      lsa2 = fake_lsa_from_prefix_lsa_cbor (&lsatmp2, lsa2, he2->lsa_body);
      lsa2_type = lsa2->type_raw;
    }


  int nt1 = (lsa1_type == LSA_T_NET);
  int nt2 = (lsa2_type == LSA_T_NET);

  if (nt1 != nt2)
    return nt1 - nt2;

  if (nt1)
    {
      /* In OSPFv3, networks are named based on ID of DR */
      if (lsa_compare_ospf3_cbor)
	{
	  if (lsa1->rt < lsa2->rt)
	    return -1;
	  if (lsa1->rt > lsa2->rt)
	    return 1;
	}

      /* For OSPFv2, this is IP of the network,
         for OSPFv3, this is interface ID */
      if (lsa1->id < lsa2->id)
	return -1;
      if (lsa1->id > lsa2->id)
	return 1;

      if (px1 != px2)
	return px1 - px2;

      return lsa1->sn - lsa2->sn;
    }
  else
    {
      if (lsa1->rt < lsa2->rt)
	return -1;
      if (lsa1->rt > lsa2->rt)
	return 1;

      if (lsa1_type < lsa2_type)
	return -1;
      if (lsa1_type > lsa2_type)
	return 1;

      if (lsa1->id < lsa2->id)
	return -1;
      if (lsa1->id > lsa2->id)
	return 1;

      if (px1 != px2)
	return px1 - px2;

      return lsa1->sn - lsa2->sn;
    }
}

static int
ext_compare_for_state_cbor (const void *p1, const void *p2)
{
  struct top_hash_entry *he1 = *(struct top_hash_entry **) p1;
  struct top_hash_entry *he2 = *(struct top_hash_entry **) p2;
  struct ospf_lsa_header *lsa1 = &(he1->lsa);
  struct ospf_lsa_header *lsa2 = &(he2->lsa);

  if (lsa1->rt < lsa2->rt)
    return -1;
  if (lsa1->rt > lsa2->rt)
    return 1;

  if (lsa1->id < lsa2->id)
    return -1;
  if (lsa1->id > lsa2->id)
    return 1;

  return lsa1->sn - lsa2->sn;
}

void
ospf_sh_state_cbor (struct cbor_writer *w, struct proto *P, int verbose,
		    int reachable)
{
  log ("in ospf_state");
  struct ospf_proto *p = (struct ospf_proto *) P;
  int ospf2 = ospf_is_v2 (p);
  int af = ospf_get_af (p);
  uint i;

  if (p->p.proto_state != PS_UP)
    {
      cbor_string_string (w, "error", "protocol is not up");
      return;
    }

  /* We store interesting area-scoped LSAs in array hea and
     global-scoped (LSA_T_EXT) LSAs in array hex */

  struct top_hash_entry *he;
  struct top_hash_entry *cnode = NULL;

  cbor_open_block(w);
  cbor_add_string(w, "areas");
  cbor_open_list(w);

  WALK_SLIST(he, p->lsal)
  {
    cbor_open_block(w);
    cbor_string_int(w, "dummy_yang_id", i);
    i++;
    cbor_string_ipv4(w, "area", he->domain);

    switch (he->lsa_type)
    {
    case LSA_T_RT:
      if (he->lsa.id == cnode->lsa.id)
	show_lsa_router_cbor(w, p, he, verbose);
      break;

    case LSA_T_NET:
      show_lsa_network_cbor(w, he, ospf2);
      break;

    case LSA_T_SUM_NET:
      if (cnode->lsa_type == LSA_T_RT)
	show_lsa_sum_net_cbor(w, he, ospf2, af);
      break;

    case LSA_T_SUM_RT:
      if (cnode->lsa_type == LSA_T_RT)
	show_lsa_sum_rt_cbor(w, he, ospf2);
      break;

    case LSA_T_EXT:
    case LSA_T_NSSA:
      show_lsa_external_cbor(w, he, ospf2, af);
      break;

    case LSA_T_PREFIX:
      show_lsa_prefix_cbor(w, he, cnode, af);
      break;
    }

    u32 last_rt = 0xFFFFFFFF;
    if (he->domain)
    {
      he->domain = 0;

	  if ((he->color != INSPF) && reachable)
	    continue;

      cbor_add_string(w, "other_ASBR");
      cbor_open_block(w);

	  if (he->lsa.rt != last_rt)
	    {
	      cbor_string_ipv4 (w, "router", he->lsa.rt);
	      last_rt = he->lsa.rt;
	    }

	  show_lsa_external_cbor (w, he, ospf2, af);
	  cbor_close_block_or_list (w);
    }
    
    cbor_close_block_or_list (w); // "areas" list entry (cbor map)
  }
  cbor_close_block_or_list (w); // "areas" list
  cbor_close_block_or_list (w); // outer map
}
