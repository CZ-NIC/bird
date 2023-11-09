/*
 *	BIRD -- BGP/MPLS IP Virtual Private Networks (L3VPN)
 *
 *	(c) 2022 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/l3vpn/l3vpn.h"


CF_DEFINES

#define L3VPN_CFG ((struct l3vpn_config *) this_proto)

static void
f_tree_only_rt(struct f_tree *t)
{
  /* Parsed degenerate trees have link to the last node in t->right */
  t->right = NULL;

  while (t)
  {
    uint type1 = t->from.val.ec >> 48;
    uint type2 = t->to.val.ec >> 48;
    ASSERT(type1 == type2);

    if (!ec_type_is_rt(type1))
      cf_error("Extended community is not route target");

    ASSERT(!t->right);
    t = t->left;
  }
}


CF_DECLS

CF_KEYWORDS(L3VPN, ROUTE, IMPORT, EXPORT, TARGET, RD, DISTINGUISHER)

%type <e> l3vpn_targets
%type <cc> l3vpn_channel_start l3vpn_channel

CF_GRAMMAR

proto: l3vpn_proto;


l3vpn_channel_start: net_type_base
{
  /* Redefining proto_channel to change default values */
  $$ = this_channel = channel_config_get(NULL, net_label[$1], $1, this_proto);
  if (!this_channel->copy)
  {
    this_channel->out_filter = FILTER_ACCEPT;
    this_channel->preference = net_val_match($1, NB_IP) ?
      DEF_PREF_L3VPN_IMPORT :
      DEF_PREF_L3VPN_EXPORT;
  }
};

l3vpn_channel: l3vpn_channel_start channel_opt_list channel_end;

l3vpn_proto_start: proto_start L3VPN
{
  this_proto = proto_config_new(&proto_l3vpn, $1);
};


l3vpn_proto_item:
   proto_item
 | l3vpn_channel
 | mpls_channel
 | RD VPN_RD { L3VPN_CFG->rd = $2; }
 | ROUTE DISTINGUISHER VPN_RD { L3VPN_CFG->rd = $3; }
 | IMPORT TARGET l3vpn_targets { L3VPN_CFG->import_target = $3; }
 | EXPORT TARGET l3vpn_targets { L3VPN_CFG->export_target = $3; }
 | ROUTE TARGET l3vpn_targets { L3VPN_CFG->import_target = L3VPN_CFG->export_target = $3; }
 ;

l3vpn_proto_opts:
   /* empty */
 | l3vpn_proto_opts l3vpn_proto_item ';'
 ;

l3vpn_proto:
   l3vpn_proto_start proto_name '{' l3vpn_proto_opts '}';


l3vpn_targets:
   ec_item { f_tree_only_rt($1); $$ = $1; }
 | '[' ec_items ']' { f_tree_only_rt($2); $$ = build_tree($2); }
 ;


CF_CODE

CF_END
