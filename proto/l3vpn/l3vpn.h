/*
 *	BIRD -- BGP/MPLS IP Virtual Private Networks (L3VPN)
 *
 *	(c) 2022 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_L3VPN_H_
#define _BIRD_L3VPN_H_

extern const struct f_tree l3vpn_rt_all;

#define RT_ALL		(&l3vpn_rt_all)
#define RT_NONE		((struct f_tree *) NULL)
#define RT_UNDEF	((struct f_tree *) 1)

struct l3vpn_config {
  struct proto_config c;

  vpn_rd rd;
  const struct f_tree *import_target;
  const struct f_tree *export_target;
};

struct l3vpn_proto {
  struct proto p;
  struct channel *ip4_channel;
  struct channel *ip6_channel;
  struct channel *vpn4_channel;
  struct channel *vpn6_channel;

  vpn_rd rd;
  const struct f_tree *import_target;
  const struct f_tree *export_target;
  u32 *export_target_data;
  uint export_target_length;
  uint import_target_one;
};

#endif
