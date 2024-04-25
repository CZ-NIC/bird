static inline void
show_lsa_distance_cbor(UYTC_CONTEXT_TYPE UYTC_CONTEXT, struct top_hash_entry *he)
{
  if (he->color == INSPF)
    UYTC_LEAF(distance, he->dist);
  else
    UYTC_LEAF(distance, unreachable);
}

static inline void
show_lsa_router_cbor(UYTC_CONTEXT_TYPE UYTC_CONTEXT, struct top_hash_entry *he, int verbose)
{
  //FIXME: This is not accurate - in yang this corresponds to DEFINITION, not USAGE of the grouping. That means, from yang point of view, we are calling definition of grouping. From cbor perspective this is correct. 
  UYTC_DEF_GROUPING(lsa_router) {
    UYTC_LEAF(router, he->lsa.rt);
    show_lsa_distance_cbor(UYTC_CONTEXT, he);

    lsa_walk_rt_init(p, he, &rtl);
    int dummy_id_ = 0;
    UYTC_LIST_WHILE (rt, lsa_walk_rt(&rtl))  // The while corresponds to list and they need to be tight together.
    {
      UITC_LEAF(dummy_id, dummy_id_);
      dummy_id_++;
      UYTC_LEAF(metric, rtl.metric);
      switch (rtl.type)
      {
        case (LSART_VLNK)
        {
          UYTC_CONTAINER(vlink)
          {
            UYTC_LEAF(vlink, rtl.id);
          }
          break;
        }
  
        case (LSART_PTP)
        {
          UYTC_CONTAINER(router_metric)
          {
            UYTC_LEAF(router, rtl.id);
          }
          break;
        }

        case (LSART_NET)
        {
          if (ospf_is_v2(p))
          {
	    /* In OSPFv2, we try to find network-LSA to get prefix/pxlen */
            struct top_hash_entry *net_he = ospf_hash_find_net2(p->gr, he->domain, rtl.id);

	    if (net_he && (net_he->lsa.age < LSA_MAXAGE))
	    {
	      struct ospf_lsa_header *net_lsa = &(net_he->lsa);
	      struct ospf_lsa_net *net_ln = net_he->lsa_body;

              UYTC_CONTAINER(network)
              {
                UYTC_LEAF(network, net_lsa->id & net_ln->optx);
                UYTC_LEAF(len, u32_masklen(net_ln->optx));
              }
            }
	    else
	    {
	      UYTC_CONTAINER(network)
              {
                UYTC_LEAF(network, rtl.id);
              }
            }
          }
          else
          {
            UYTC_CONTAINER(network)
            {
              UYTC_LEAF(network, rtl.id);
              UITC_LEAF(nif, rtl.nif);
            }
            break;
          }
          case (LSART_STUB)
          {
            if (ospf_is_v2(p) && verbose)
            {
              UYTC_CONTAINER(stubnet)
              {
                UYTC_LEAF(stubnet, rtl.id);
                UYTC_LEAF(len, u32_masklen(rtl.data));
              }
            }
          }
        }
      }
    }
  }
}

static inline void
show_lsa_network_cbor(UYTC_CONTEXT_TYPE UYTC_CONTEXT, struct top_hash_entry *he, int ospf2)
{
  UYTC_DEF_GROUPING(lsa_network)
  {
    struct ospf_lsa_header *lsa = &(he->lsa);
    struct ospf_lsa_net *ln = he->lsa_body;
    u32 i;

    if (ospf2)
    {
      UYTC_CONTAINER(ospf2)
      {
        UYTC_LEAF(network, lsa->id & ln->optx);
        UYTC_LEAF(optx, u32_masklen(ln->optx));
        UYTC_LEAF(dr, lsa->rt);
      }
    }
    else
    {
      UYTC_CONTAINER(ospf)
      {
        UYTC_LEAF(network, lsa->rt);
        UYTC_LEAF(lsa_id, lsa->id);
      }
    }

    show_lsa_distance_cbor(UYTC_CONTEXT, he);

    int i = 0;
    UITC_LIST_FOR (routers, i; i < lsa_net_count(lsa); i++) // Not sure if this syntax is ok, but, again, we need to squash cbor list and for()
    {
      UYTC_LEAF(router, ln->routers[i]);
    }
  }
}

static inline void
show_lsa_sum_net_cbor(UYTC_CONTEXT_TYPE UYTC_CONTEXT, struct top_hash_entry *he, int ospf2, int af)
{
  net_addr net;
  u8 pxopts;
  u32 metric_;

  lsa_parse_sum_net(he, ospf2, af, &net, &pxopts, &metric_);
  UYTC_DEF_GROUPING(lsa_sum_net)
  {
    UYTC_LEAF(net, &net);
    UYTC_LEAF(metric_, metric);
  }
}

static inline void
show_lsa_sum_rt_cbor(UYTC_CONTEXT_TYPE UYTC_CONTEXT, struct top_hash_entry *he, int ospf2)
{
  u32 metric;
  u32 dst_rid;
  u32 options;

  lsa_parse_sum_rt(he, ospf2, &dst_rid, &metric, &options);

  UYTC_DEF_GROUPING(lsa_sum_rt);
  UYTC_LEAF(router, dst_rid);
  UYTC_LEAF(metric, metric);
}

static inline void
show_lsa_external_cbor(UYTC_CONTEXT_TYPE UYTC_CONTEXT, struct top_hash_entry *he, int ospf2, int af)
{
  struct ospf_lsa_ext_local rt;

  UYTC_DEF_GROUPING(lsa_external)
  {
    if (he->lsa_type == LSA_T_EXT)
      he->domain = 0; /* Unmark the LSA */

    lsa_parse_ext(he, ospf2, af, &rt);

    if (rt.fbit)
    {
      UYTC_LEAF(via, rt.fwaddr.addr[0]);
    }

    if (rt.tag)
      UYTC_LEAF(tag, rt.tag);

    if (he->lsa_type == LSA_T_NSSA)
    {
      UYTC_LEAF(lsa_type, "nssa-ext");
    } else {
      UYTC_LEAF(lsa_type, "external");
    }
    UYTC_LEAF(rt_net, &rt.net);

    if(rt.ebit)
    {
      UYTC_LEAF(lsa_type_num, 2);
    }
    UYTC_LEAF(metric, rt.metric);
  }
}

static inline void
show_lsa_prefix_cbor(UYTC_CONTEXT_TYPE UYTC_CONTEXT, struct top_hash_entry *he, struct top_hash_entry *cnode, int af)
{
  struct ospf_lsa_prefix *px = he->lsa_body;
  u32 *buf;
  int i;

  /* We check whether given prefix-LSA is related to the current node */
  if ((px->ref_type != cnode->lsa.type_raw) || (px->ref_rt != cnode->lsa.rt))
    return;

  if ((px->ref_type == LSA_T_RT) && (px->ref_id != 0))
    return;

  if ((px->ref_type == LSA_T_NET) && (px->ref_id != cnode->lsa.id))
    return;

  UYTC_DEF_GROUPING(lsa_prefix)
  {
    buf = px->rest;

    int i = 0;
    UYTC_LIST_FOR (prefixes, i; i < px->pxcount; i++)
    {
      net_addr net;
      u8 pxopts;
      u16 metric_;

      buf = ospf3_get_prefix(buf, af, &net, &pxopts, &metric_);

      if (px->ref_type == LSA_T_RT)
      {
        UYTC_LEAF(stubnet, &net);
        UYTC_LEAF(metric_, metric);
      }
      else
      {
        UYTC_LEAF(address, &net);
      }
    }
  }
}

void
ospf_sh_state_cbor(UYTC_CONTEXT_TYPE UYTC_CONTEXT, struct proto *P, int verbose, int reachable)
{
  struct ospf_proto *p = (struct ospf_proto *) P;
  int ospf2 = ospf_is_v2(p);
  int af = ospf_get_af(p);
  uint i, ix, j1, jx;
  u32 last_area = 0xFFFFFFFF;

  if (p->p.proto_state != PS_UP)
  {
    UYTC_LEAF(error, "protocol is not up");
    return;
  }

  /* We store interesting area-scoped LSAs in array hea and
     global-scoped (LSA_T_EXT) LSAs in array hex */

  uint num = p->gr->hash_entries;
  struct top_hash_entry *hea[num];
  struct top_hash_entry **hex = verbose ? alloca(num * sizeof(struct top_hash_entry *)) : NULL;
  struct top_hash_entry *he;
  struct top_hash_entry *cnode = NULL;

  int i = 0;
  UYTC_LIST_WALK_SLIST(areas, he, p->lsal)
  {
    UYTC_LEAF(dummy_yang_id, i);
    i++;
    UYTC_LEAF(area, he->domain);
    switch (he->lsa_type)
    {
    case LSA_T_RT:
      if (he->lsa.id == cnode->lsa.id)
	show_lsa_router_cbor(UYTC_CONTEXT, p, he, verbose);
      break;

    case LSA_T_NET:
      show_lsa_network_cbor(UYTC_CONTEXT, he, ospf2);
      break;

    case LSA_T_SUM_NET:
      if (cnode->lsa_type == LSA_T_RT)
	show_lsa_sum_net_cbor(UYTC_CONTEXT, he, ospf2, af);
      break;

    case LSA_T_SUM_RT:
      if (cnode->lsa_type == LSA_T_RT)
	show_lsa_sum_rt_cbor(UYTC_CONTEXT, he, ospf2);
      break;

    case LSA_T_EXT:
    case LSA_T_NSSA:
      show_lsa_external_cbor(UYTC_CONTEXT, he, ospf2, af);
      break;

    case LSA_T_PREFIX:
      show_lsa_prefix_cbor(UYTC_CONTEXT, he, cnode, af);
      break;
    }

    u32 last_rt = 0xFFFFFFFF;
    if (he->domain)
    {
      he->domain = 0;

      if ((he->color != INSPF) && reachable)
	continue;

      UITC_CONTAINER(other_ASBR)
      {
        if (he->lsa.rt != last_rt)
        {
	  UYTC_LEAF(router, he->lsa.rt);
	  last_rt = he->lsa.rt;
        }

        show_lsa_external_cbor(UYTC_CONTEXT, he, ospf2, af);
      }
    }
  }
}

