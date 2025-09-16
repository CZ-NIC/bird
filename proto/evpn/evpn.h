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

#include "nest/bird.h"
#include "lib/lists.h"
#include "lib/hash.h"
#include "filter/data.h"


/* BGP Tunnel Encapsulation Attribute Tunnel Types (RFC 8365) */

enum evpn_encap_type {
  EVPN_ENCAP_TYPE_VXLAN = 8,
  EVPN_ENCAP_TYPE_MAX,
};


struct evpn_config {
  struct proto_config c;

  vpn_rd rd;
  struct f_tree *import_target;
  struct f_tree *export_target;

  u32 vni;
  u32 vid;
  u32 tagX;

  list encaps;				/* List of encapsulations (struct evpn_encap_config) */
  list vlans;				/* List of VLANs (struct evpn_vlan_config) */
};

struct evpn_encap_config {
  node n;				/* Node in evpn_config.encaps */

  enum evpn_encap_type type;
  bool is_default;
  struct iface *tunnel_dev;
  ip_addr router_addr;
};

struct evpn_vlan_config {
  node n;				/* Node in evpn_config.vlans */

  u32 id;
  u32 range;
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
  bool import_target_one;
  bool eth_refreshing;
  bool evpn_refreshing;

  u32 vni;
  u32 vid;
  u32 tagX;

  list encaps;				/* List of encapsulations (struct evpn_encap) */
  list vlans;				/* List of VLANs (struct evpn_vlan) */

  HASH(struct evpn_vlan) vlan_tag_hash;
  HASH(struct evpn_vlan) vlan_vid_hash;
  ps_publisher *vlan_pub;
};

struct evpn_encap {
  node n;				/* Node in evpn_proto.encaps */

  enum evpn_encap_type type;
  bool is_default;
  struct iface *tunnel_dev;
  ip_addr router_addr;
};

struct evpn_vlan {
  node n;				/* Node in evpn_proto.vlans */

  u32 tag;
  u32 vni;
  u32 vid;

  struct evpn_vlan *next_tag;
  struct evpn_vlan *next_vid;
};

#endif
