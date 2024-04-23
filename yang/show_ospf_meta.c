static inline void
show_lsa_router_cbor(UYTC_CONTEXT_TYPE UYTC_CONTEXT, struct top_hash_entry *he, int verbose)
{
  UYTC_GROUPING(lsa_router) {
    UYTC_ITEM(router, he->lsa.rt);
    
    ...;

    lsa_walk_rt_init(p, he, &rtl);
    int i = 0;
    while (lsa_walk_rt(&rtl))
    {
      i++;
      UYTC_LIST_ITEM(rt) {
	UYTC_LEAF(dummy_yang_id, i);
	UYTC_LEAF(metric, rtl.metric);
	switch (rtl.type) {
	  case LSART_VLNK:
	    UYTC_CHOICE_ITEM(rt_type, vlink) {
	      UYTC_GROUPING(vlink) {
		UYTC_LEAF(vlink, rtl.id);
		UYTC_LEAF(name, rtl.name);
	      }
	    }
	    break;

	  case LSART_PTP:
	    ...;
	}
      }
    }
  }
}


for (i = 0; i < j1; i++) {
  UYTC_LIST_ITEM(areas) {
    struct top_hash_entry *he = hea[i];
    UYTC_LEAF(dummy_yang_id, i);
    UYTC_LEAF(area, he->domain);

    switch (he->lsa_type)
    {
      case LSA_T_RT:
	UYTC_CHOICE_ITEM(lsa_type, rt, show_lsa_router_cbor(UYTC_CONTEXT, he));
	break;

      case LSA_T_NET:
	UYTC_CHOICE_ITEM(lsa_type, net, show_lsa_network_cbor(UYTC_CONTEXT, he, ospf2));
	break;
    }
  }
}
