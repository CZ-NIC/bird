/*
 *	BIRD Internet Routing Daemon -- Filter and Attribute Types
 *
 *	(c) 2026       CZ.NIC z.s.p.o.
 *	(c) 2026       Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

TYPEDEF(T_VOID, void, void) {
  TD_STR("(void)");
  TD_COMPARE(0);
}

TYPEDEF(T_NONE, void, none) {}

TYPEDEF(T_INT, uint, int) {
  TD_CF_NAME(Number);
  TD_SET_MEMBER;
  TD_EA(EAF_TYPE_INT);
  TD_STR("%u", _v);
  TD_COMPARE(uint_cmp(_v1, _v2));
}

TYPEDEF(T_BOOL, uint, bool) {
  TD_CF_NAME(Boolean);
  TD_STR(_v ? "true" : "false");
  TD_COMPARE(uint_cmp(_v1, _v2));
}

TYPEDEF(T_PAIR, uint, pair) {
  TD_SET_MEMBER;
  TD_STR("(%u,%u)", _v >> 16, _v & 0xffff);
  TD_COMPARE(uint_cmp(_v1, _v2));
}
TYPEDEF(T_QUAD, uint, quad) {
  TD_SET_MEMBER;
  TD_EA(EAF_TYPE_ROUTER_ID);
  TD_STR("%R", _v);
  TD_COMPARE(uint_cmp(_v1, _v2));
}

/* This should be per partes in protocols */
ENUMDEF(rts,
			RTS_NONE,
    static:		RTS_STATIC,
    inherit:		RTS_INHERIT,
    device:		RTS_DEVICE,
    static-device:	RTS_STATIC_DEVICE,
    redirect:		RTS_REDIRECT,
    RIP:		RTS_RIP,
    OSPF:		RTS_OSPF,
    OSPF-IA:		RTS_OSPF_IA,
    OSPF-E1:		RTS_OSPF_EXT1,
    OSPF-E2:		RTS_OSPF_EXT2,
    BGP:		RTS_BGP,
    pipe:		RTS_PIPE,
    Babel:		RTS_BABEL,
    RPKI:		RTS_RPKI,
    Perf:		RTS_PERF,
    L3VPN:		RTS_L3VPN,
    aggregated:		RTS_AGGREGATED,
    );
TD_ENUM_INTERNAL_ITEM(rts, RTS_MAX);

/* This should be in proto/bgp/types.h */
ENUMDEF(bgp_origin,
    IGP:		ORIGIN_IGP,
    EGP:		ORIGIN_EGP,
    Incomplete:		ORIGIN_INCOMPLETE,
    );

/* ip.h ? */
ENUMDEF(scope,
    host:		SCOPE_HOST,
    link:		SCOPE_LINK,
    site:		SCOPE_SITE,
    org:		SCOPE_ORGANIZATION,
    univ:		SCOPE_UNIVERSE,
    undef:		SCOPE_UNDEFINED,
    );

/* nest/route.h */
ENUMDEF(rtd,
    :			RTD_NONE,
    unicast:		RTD_UNICAST,
    blackhole:		RTD_BLACKHOLE,
    unreachable:	RTD_UNREACHABLE,
    prohibited:		RTD_PROHIBIT,
    );
TD_ENUM_INTERNAL_ITEM(rtd, RTD_MAX);

ENUMDEF(roa,
    unknown:		ROA_UNKNOWN,
    valid:		ROA_VALID,
    invalid:		ROA_INVALID,
    )

ENUMDEF(aspa,
    unknown:		ASPA_UNKNOWN,
    valid:		ASPA_VALID,
    invalid:		ASPA_INVALID,
    )

/* net.h */
ENUMDEF(net_type,
    ipv4:		NET_IP4 = 1,
    ipv6:		NET_IP6,
    vpn4:		NET_VPN4,
    vpn6:		NET_VPN6,
    roa4:		NET_ROA4,
    roa6:		NET_ROA6,
    flow4:		NET_FLOW4,
    flow6:		NET_FLOW6,
    ipv6-sadr:		NET_IP6_SADR,
    mpls:		NET_MPLS,
    aspa:		NET_ASPA,
    );
TD_ENUM_INTERNAL_ITEM(net_type, NET_MAX);

/* RAdv */
ENUMDEF(ra_preference,
    low:		RA_PREF_LOW = 0x18,
    medium:		RA_PREF_MEDIUM = 0x00,
    high:		RA_PREF_HIGH = 0x08,
    );

/* ip.h but looks totally unused */
ENUMDEF(af,
    AF_IPV4 = 1,
    AF_IPV6 = 2,
    );

/* mpls.h */
ENUMDEF(mpls_policy,
    none:		MPLS_POLICY_NONE,
    static:		MPLS_POLICY_STATIC,
    prefix:		MPLS_POLICY_PREFIX,
    aggregate:		MPLS_POLICY_AGGREGATE,
    vrf:		MPLS_POLICY_VRF,
    );

/* Old bytestring hack */
TYPEDEF(T_ENUM_EMPTY, const struct adata *, enum empty);

TYPEDEF(T_IP, ip_addr, ip) {
  TD_INCLUDE(lib/ip.h)
  TD_CF_NAME(IP address);
  TD_SET_MEMBER;
  TD_EA(EAF_TYPE_IP_ADDRESS);
  TD_STR("%I", _v);
  TD_COMPARE(ipa_compare(_v1, _v2));
}

TYPEDEF(T_NET, const net_addr *, prefix) {
  TD_INCLUDE(lib/net.h)
  TD_CF_NAME(Network);
  TD_STR("%N", _v);
  TD_COMPARE(net_compare(_v1, _v2));
}

TYPEDEF(T_STRING, const char *, string) {
  TD_CF_NAME(String);
  TD_EA(EAF_TYPE_STRING);
  TD_STR("%s", _v);
  TD_COMPARE(strcmp(_v1, _v2));
}

/* mask for BGP AS Path */
TYPEDEF(T_PATH_MASK, const struct f_path_mask *, bgpmask) {
  TD_STR_BUF(pm_format(_v, _buf));
  TD_SAME(pm_same(_v1, _v2));
}

/* BGP AS Path */
TYPEDEF(T_PATH, const struct adata *, bgppath) {
  TD_EA(EAF_TYPE_AS_PATH);
  TD_STR("(path) [%s]", ( as_path_format(_v, _aux, 1000), _aux ));
  TD_COMPARE(as_path_compare(_v1, _v2));
}

/* Community list */
TYPEDEF(T_CLIST, const struct adata *, clist) {
  TD_EA(EAF_TYPE_INT_SET);
  TD_STR("(clist) [%s]", ( int_set_format(_v, 1, -1, _aux, 1000), _aux ));
  TD_SAME(adata_same(_v1, _v2));
}

/* Extended community value, u64 */
TYPEDEF(T_EC, u64, ec) {
  TD_STR("%s", ( ec_format(_aux, _v), _aux ));
  TD_COMPARE(u64_cmp(_v1, _v2));
}

/* Extended community list */
TYPEDEF(T_ECLIST, const struct adata *, eclist) {
  TD_EA(EAF_TYPE_EC_SET);
  TD_STR("(eclist) [%s]", ( ec_set_format(_v, -1, _aux, 1000), _aux ));
  TD_SAME(adata_same(_v1, _v2));
}

/* Large community value, lcomm */
TYPEDEF(T_LC, struct lcomm *, lc) {
  TD_INCLUDE(nest/attrs.h);
  TD_STR("%s", ( lc_format(_aux, _v), _aux ));
  TD_COMPARE(lcomm_cmp(_v1, _v2));
}

/* Large community list */
TYPEDEF(T_LCLIST, const struct adata *, lclist) {
  TD_EA(EAF_TYPE_LC_SET);
  TD_STR("(lclist) [%s]", ( lc_set_format(_v, -1, _aux, 1000), _aux ));
  TD_SAME(adata_same(_v1, _v2));
}

/* Route distinguisher for VPN addresses */
TYPEDEF(T_RD, vpn_rd, rd) {
  TD_INCLUDE(lib/ip.h);
  TD_INCLUDE(lib/net.h);
  TD_STR("%s", ( rd_format(_v, _aux, 1000), _aux ));
  TD_COMPARE(rd_compare(_v1, _v2));
}

/* Path mask item for path mask constructors */
TYPEDEF(T_PATH_MASK_ITEM, struct f_path_mask_item *, bgpmask_item) {
  TD_SAME(pmi_same(_v1, _v2));
}

TYPEDEF(T_BYTESTRING, const struct adata *, bytestring) {
  TD_CF_NAME(Bytestring);
  TD_EA(EAF_TYPE_OPAQUE);
  TD_STR("%s", ( bstrbintohex(_v->data, _v->length, _aux, 1000, ':'), _aux ));
  TD_SAME(adata_same(_v1, _v2));
}

TYPEDEF(T_ROUTE, struct rte *, route) {
  TD_INCLUDE(nest/route.h);
  TD_STR_BUF(rte_format(_v, _buf));
  TD_SAME(_v1 == _v2);	/* TODO: Check whether this is right */
}

TYPEDEF(T_ROUTES_BLOCK, struct rte *, route set) {
  TD_INCLUDE(nest/route.h);
  TD_STR_BUF(rte_block_format(_v, _buf));
  TD_SAME(_v1 == _v2);
}

TYPEDEF(T_SET, const struct f_tree *, set) {
  TD_INCLUDE(filter/tree.h);
  TD_STR_BUF(tree_format(_v, _buf));
  TD_SAME(same_tree(_v1, _v2));
}

TYPEDEF(T_PREFIX_SET, const struct f_trie *, prefix set) {
  TD_INCLUDE(filter/trie.h);
  TD_STR_BUF(trie_format(_v, _buf));
  TD_SAME(trie_same(_v1, _v2));
}
