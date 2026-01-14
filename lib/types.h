/*
 *	BIRD Internet Routing Daemon -- Filter and Attribute Types
 *
 *	(c) 2026       CZ.NIC z.s.p.o.
 *	(c) 2026       Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

TYPEDEF(T_VOID, void, void) {}
TYPEDEF(T_NONE, void, none) {}

TYPEDEF(T_INT, uint, int) {
  TD_CF_NAME(Number);
  TD_SET_MEMBER;
  TD_EA(EAF_TYPE_INT);
}

TYPEDEF(T_BOOL, uint, bool) {
  TD_CF_NAME(Boolean);
}

TYPEDEF(T_PAIR, uint, pair) {
  TD_SET_MEMBER;
}
TYPEDEF(T_QUAD, uint, quad) {
  TD_SET_MEMBER;
  TD_EA(EAF_TYPE_ROUTER_ID);
}

/* This should be per partes in protocols */
ENUMDEF(rts,
    RTS_NONE,
    RTS_STATIC,
    RTS_INHERIT,
    RTS_DEVICE,
    RTS_STATIC_DEVICE,
    RTS_REDIRECT,
    RTS_RIP,
    RTS_OSPF,
    RTS_OSPF_IA,
    RTS_OSPF_EXT1,
    RTS_OSPF_EXT2,
    RTS_BGP,
    RTS_PIPE,
    RTS_BABEL,
    RTS_RPKI,
    RTS_PERF,
    RTS_L3VPN,
    RTS_AGGREGATED,
    );
TD_ENUM_INTERNAL_ITEM(rts, RTS_MAX);

/* This should be in proto/bgp/types.h */
ENUMDEF(bgp_origin,
    ORIGIN_IGP,
    ORIGIN_EGP,
    ORIGIN_INCOMPLETE,
    );

/* ip.h ? */
ENUMDEF(scope,
    SCOPE_HOST,
    SCOPE_LINK,
    SCOPE_SITE,
    SCOPE_ORGANIZATION,
    SCOPE_UNIVERSE,
    SCOPE_UNDEFINED,
    );

/* nest/route.h */
ENUMDEF(rtd,
    RTD_NONE,
    RTD_UNICAST,
    RTD_BLACKHOLE,
    RTD_UNREACHABLE,
    RTD_PROHIBIT,
    );
TD_ENUM_INTERNAL_ITEM(rtd, RTD_MAX);

ENUMDEF(roa,
    ROA_UNKNOWN,
    ROA_VALID,
    ROA_INVALID,
    )

ENUMDEF(aspa,
    ASPA_UNKNOWN,
    ASPA_VALID,
    ASPA_INVALID,
    )

/* net.h */
ENUMDEF(net_type,
    NET_IP4 = 1,
    NET_IP6,
    NET_VPN4,
    NET_VPN6,
    NET_ROA4,
    NET_ROA6,
    NET_FLOW4,
    NET_FLOW6,
    NET_IP6_SADR,
    NET_MPLS,
    NET_ASPA,
    );
TD_ENUM_INTERNAL_ITEM(net_type, NET_MAX);

/* RAdv */
ENUMDEF(ra_preference,
    RA_PREF_LOW = 0x18,
    RA_PREF_MEDIUM = 0x00,
    RA_PREF_HIGH = 0x08,
    );

/* ip.h */
ENUMDEF(af,
    AF_IPV4 = 1,
    AF_IPV6 = 2,
    );

/* mpls.h */
ENUMDEF(mpls_policy,
    MPLS_POLICY_NONE,
    MPLS_POLICY_STATIC,
    MPLS_POLICY_PREFIX,
    MPLS_POLICY_AGGREGATE,
    MPLS_POLICY_VRF,
    );

/* Old bytestring hack */
TYPEDEF(T_ENUM_EMPTY, const struct adata *, enum empty);

TYPEDEF(T_IP, ip_addr, ip) {
  TD_INCLUDE(lib/ip.h)
  TD_CF_NAME(IP address);
  TD_SET_MEMBER;
  TD_EA(EAF_TYPE_IP_ADDRESS);
}

TYPEDEF(T_NET, const net_addr *, prefix) {
  TD_INCLUDE(lib/net.h)
  TD_CF_NAME(Network);
}

TYPEDEF(T_STRING, const char *, string) {
  TD_CF_NAME(String);
  TD_EA(EAF_TYPE_STRING);
}

/* mask for BGP AS Path */
TYPEDEF(T_PATH_MASK, const struct f_path_mask *, bgpmask);

/* BGP AS Path */
TYPEDEF(T_PATH, const struct adata *, bgppath) {
  TD_EA(EAF_TYPE_AS_PATH);
}

/* Community list */
TYPEDEF(T_CLIST, const struct adata *, clist) {
  TD_EA(EAF_TYPE_INT_SET);
}

/* Extended community value, u64 */
TYPEDEF(T_EC, u64, ec);

/* Extended community list */
TYPEDEF(T_ECLIST, const struct adata *, eclist) {
  TD_EA(EAF_TYPE_EC_SET);
}

/* Large community value, lcomm */
TYPEDEF(T_LC, lcomm, lc);

/* Large community list */
TYPEDEF(T_LCLIST, const struct adata *, lclist) {
  TD_EA(EAF_TYPE_LC_SET);
}

/* Route distinguisher for VPN addresses */
TYPEDEF(T_RD, vpn_rd, rd);

/* Path mask item for path mask constructors */
TYPEDEF(T_PATH_MASK_ITEM, struct f_path_mask_item, bgpmask_item);

TYPEDEF(T_BYTESTRING, const struct adata *, bytestring) {
  TD_CF_NAME(Bytestring);
  TD_EA(EAF_TYPE_OPAQUE);
}

TYPEDEF(T_ROUTE, struct rte *, route);
TYPEDEF(T_ROUTES_BLOCK, struct rte *, route set);

TYPEDEF(T_SET, const struct f_tree *, set);
TYPEDEF(T_PREFIX_SET, const struct f_trie *, prefix set);


#endif
