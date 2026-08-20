/*
 *	Filters: Data classes
 *
 *	(c) 1998 Pavel Machek <pavel@ucw.cz>
 *	(c) 2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 */

//#define PARSER 1

#include "nest/bird.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/string.h"
#include "lib/unaligned.h"
#include "lib/net.h"
#include "lib/ip.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/attrs.h"
#include "filter/filter.h"
#include "filter/f-inst.h"
#include "filter/data.h"
#include "conf/conf.h"
//#include "conf/cf-parse.tab.h"

#include "filter/class-m4-auto-pre.c"

SUBLAMBDA(COMPARE, int, F_CLASS_COMPARE);

#ifdef M4_AUTO
AUX_SECTION(INCH, H_BEGIN, [[
/*
 *	Filters: Data classes
 *
 *	Automatically generated from ]]m4_builtin(__file__)[[ by ]]AUX_MACROSET()[[
 */
#ifndef _BIRD_FILTER_CLASS_M4_AUTO_H_
#define _BIRD_FILTER_CLASS_M4_AUTO_H_
]],)

AUX_END_SECTION(INCH, H_END,,[[
#endif
]])

AUX_SECTION(INCH, H_ENUM,[[
PACKED enum f_type {
]],[[
  T_SET,
  T_PREFIX_SET,
  T__MAX,
};
]])

m4_define(FC_ID,[[H_ENUM()  $1,
AUX_MUTE()]])
#else
#define FC_ID(x)  .id = x
#endif


static const struct f_class f_type_void = {
  FC_ID(T_VOID),
  .name = "void",
};

static const struct f_class f_type_none = {
  FC_ID(T_NONE),
  .hidden = true,
  .name = "none",
};

static const struct f_class f_type_int = {
  FC_ID(T_INT),
  .ea_type = EAF_TYPE_INT,
  .legacy_kw = true,
  .name = "int",
  .pretty_name = "Integer",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_bool = {
  FC_ID(T_BOOL),
  .legacy_kw = true,
  .name = "bool",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_pair = {
  FC_ID(T_PAIR),
  .legacy_kw = true,
  .name = "pair",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_quad = {
  FC_ID(T_QUAD),
  .ea_type = EAF_TYPE_ROUTER_ID,
  .legacy_kw = true,
  .name = "quad",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_enum_lo = {
  FC_ID(T_ENUM_LO),
  .hidden = true,
  .name = "enum __lo",
};

static const struct f_class f_type_enum_rts = {
  FC_ID(T_ENUM_RTS),
  .name = "enum rts",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_enum_bgp_origin = {
  FC_ID(T_ENUM_BGP_ORIGIN),
  .name = "enum bgp_origin",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_enum_scope = {
  FC_ID(T_ENUM_SCOPE),
  .name = "enum scope",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_enum_rtd = {
  FC_ID(T_ENUM_RTD),
  .name = "enum rtd",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_enum_roa = {
  FC_ID(T_ENUM_ROA),
  .name = "enum roa",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_enum_aspa = {
  FC_ID(T_ENUM_ASPA),
  .name = "enum aspa",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_enum_net_type = {
  FC_ID(T_ENUM_NET_TYPE),
  .name = "enum net_type",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_enum_ra_preference = {
  FC_ID(T_ENUM_RA_PREFERENCE),
  .name = "enum ra_preference",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_enum_af = {
  FC_ID(T_ENUM_AF),
  .name = "enum af",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_enum_mpls_policy = {
  FC_ID(T_ENUM_MPLS_POLICY),
  .name = "enum mpls_policy",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_enum_net_evpn_type = {
  FC_ID(T_ENUM_NET_EVPN_TYPE),
  .name = "enum net_evpn_type",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_enum_kbr_source = {
  FC_ID(T_ENUM_KBR_SOURCE),
  .name = "enum kbr_source",
  .compare = COMPARE(uint_cmp(v1->val.i, v2->val.i)),
};

static const struct f_class f_type_enum_empty = {
  FC_ID(T_ENUM_EMPTY),
  .hidden = true,
  .name = "enum __empty",
};

static const struct f_class f_type_enum_hi = {
  FC_ID(T_ENUM_HI),
  .hidden = true,
  .name = "enum __hi",
};

static const struct f_class f_type_ip = {
  FC_ID(T_IP),
  .ea_type = EAF_TYPE_IP_ADDRESS,
  .legacy_kw = true,
  .name = "ip",
  .pretty_name = "IP address",
  .compare = COMPARE(ipa_compare(v1->val.ip, v2->val.ip)),
};

static const struct f_class f_type_prefix = {
  FC_ID(T_NET),
  .legacy_kw = true,
  .name = "prefix",
  .compare = COMPARE(net_compare(v1->val.net, v2->val.net)),
};

static int
f_string_compare(F_CLASS_COMPARE)
{
  int i = strcmp(v1->val.s, v2->val.s);
  return (i > 0) - (i < 0);
}

static const struct f_class f_type_string = {
  FC_ID(T_STRING),
  .ea_type = EAF_TYPE_STRING,
  .legacy_kw = true,
  .name = "string",
  .pretty_name = "String",
  .compare = f_string_compare,
};

static const struct f_class f_type_bytestring = {
  FC_ID(T_BYTESTRING),
  .ea_type = EAF_TYPE_OPAQUE,
  .legacy_kw = true,
  .name = "bytestring",
  .pretty_name = "Bytestring",
  .compare = COMPARE(bytestring_compare(v1->val.ad, v2->val.ad)),
};

static const struct f_class f_type_bgpmask = {
  FC_ID(T_PATH_MASK),
  .legacy_kw = true,
  .name = "bgpmask",
};

static const struct f_class f_type_bgpmask_item = {
  FC_ID(T_PATH_MASK_ITEM),
  .hidden = true,
  .name = "bgpmask_item",
};

static const struct f_class f_type_bgppath = {
  FC_ID(T_PATH),
  .ea_type = EAF_TYPE_AS_PATH,
  .legacy_kw = true,
  .name = "bgppath",
  .empty = { .type = T_PATH, .val.ad = &null_adata },
  .compare = COMPARE(as_path_compare(v1->val.ad, v2->val.ad)),
};

static const struct f_class f_type_clist = {
  FC_ID(T_CLIST),
  .ea_type = EAF_TYPE_INT_SET,
  .legacy_kw = true,
  .name = "clist",
  .empty = { .type = T_CLIST, .val.ad = &null_adata },
};

static const struct f_class f_type_ec = {
  FC_ID(T_EC),
  .legacy_kw = true,
  .name = "ec",
  .compare = COMPARE(u64_cmp(v1->val.ec, v2->val.ec)),
};

static const struct f_class f_type_eclist = {
  FC_ID(T_ECLIST),
  .ea_type = EAF_TYPE_EC_SET,
  .legacy_kw = true,
  .name = "eclist",
  .empty = { .type = T_ECLIST, .val.ad = &null_adata },
};

static const struct f_class f_type_lc = {
  FC_ID(T_LC),
  .legacy_kw = true,
  .name = "lc",
  .compare = COMPARE(lcomm_cmp(v1->val.lc, v2->val.lc)),
};

static const struct f_class f_type_lclist = {
  FC_ID(T_LCLIST),
  .ea_type = EAF_TYPE_LC_SET,
  .legacy_kw = true,
  .name = "lclist",
  .empty = { .type = T_LCLIST, .val.ad = &null_adata },
};

static const struct f_class f_type_rd = {
  FC_ID(T_RD),
  .legacy_kw = true,
  .name = "rd",
  .compare = COMPARE(u64_cmp(v1->val.ec, v2->val.ec)),
};

static const struct f_class f_type_mac = {
  FC_ID(T_MAC),
  .legacy_kw = true,
  .name = "mac",
  .compare = COMPARE(mac_compare(v1->val.mac, v2->val.mac)),
};

static const struct f_class f_type_route = {
  FC_ID(T_ROUTE),
  .legacy_kw = true,
  .name = "route",
  .empty = { .type = T_ROUTE, },
};

static const struct f_class f_type_routes = {
  FC_ID(T_ROUTES_BLOCK),
  .name = "routes",
};

const struct f_class *f_base_types[0x7f];	/* TODO: Autocompute the limit */

void
f_class_register_static(const struct f_class *cls)
{
  ASSERT_DIE(f_base_types[cls->id] == NULL);
  f_base_types[cls->id] = cls;
}

void
f_class_build(void)
{
  /* TODO: Autogenerate this by M4 */
  f_class_register_static(&f_type_void);
  f_class_register_static(&f_type_none);
  f_class_register_static(&f_type_int);
  f_class_register_static(&f_type_bool);
  f_class_register_static(&f_type_pair);
  f_class_register_static(&f_type_quad);
  f_class_register_static(&f_type_enum_rts);
  f_class_register_static(&f_type_enum_bgp_origin);
  f_class_register_static(&f_type_enum_scope);
  f_class_register_static(&f_type_enum_rtd);
  f_class_register_static(&f_type_enum_roa);
  f_class_register_static(&f_type_enum_aspa);
  f_class_register_static(&f_type_enum_net_type);
  f_class_register_static(&f_type_enum_ra_preference);
  f_class_register_static(&f_type_enum_af);
  f_class_register_static(&f_type_enum_mpls_policy);
  f_class_register_static(&f_type_enum_net_evpn_type);
  f_class_register_static(&f_type_ip);
  f_class_register_static(&f_type_prefix);
  f_class_register_static(&f_type_string);
  f_class_register_static(&f_type_bytestring);
  f_class_register_static(&f_type_bgpmask);
  f_class_register_static(&f_type_bgppath);
  f_class_register_static(&f_type_clist);
  f_class_register_static(&f_type_ec);
  f_class_register_static(&f_type_eclist);
  f_class_register_static(&f_type_lc);
  f_class_register_static(&f_type_lclist);
  f_class_register_static(&f_type_rd);
  f_class_register_static(&f_type_mac);
  f_class_register_static(&f_type_route);
  f_class_register_static(&f_type_routes);
}

const struct f_class *
f_type_get_class(enum f_type t)
{
  return (t < ARRAY_SIZE(f_base_types)) ? f_base_types[t] : NULL;
}


