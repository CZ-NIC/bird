/*
 *	BIRD -- BGP/MPLS Ethernet Virtual Private Networks (EVPN)
 *
 *	(c) 2023 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2023 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_EVPN_H_
#define _BIRD_EVPN_H_

struct evpn_config {
  struct proto_config c;

  vpn_rd rd;
  struct f_tree *import_target;
  struct f_tree *export_target;

  struct iface *tunnel_dev;
  ip_addr router_addr;
  u32 vni;
  u32 vid;
};

struct evpn_proto {
  struct proto p;
  struct channel *eth_channel;
  struct channel *evpn_channel;

  vpn_rd rd;
  struct f_tree *import_target;
  struct f_tree *export_target;
  u32 *export_target_data;
  uint export_target_length;
  uint import_target_one;

  struct iface *tunnel_dev;
  ip_addr router_addr;
  u32 vni;
  u32 vid;
};

#endif
