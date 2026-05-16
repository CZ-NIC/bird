/*
 *	BIRD -- Linux Bridge Interface
 *
 *	(c) 2023--2026 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2023--2026 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_BRIDGE_H_
#define _BIRD_BRIDGE_H_


#define EA_KBR_SOURCE		EA_CODE(PROTOCOL_BRIDGE, 0)

#define KBR_SRC_BIRD		0
#define KBR_SRC_LOCAL		1
#define KBR_SRC_STATIC		2
#define KBR_SRC_DYNAMIC		3
#define KBR_SRC_MAX		4


struct kbr_config {
  struct proto_config c;

  struct iface *bridge_dev;
  btime scan_time;
  int vlan_filtering;
};

struct kbr_proto {
  struct proto p;

  struct iface *bridge_dev;
  timer *scan_timer;
  struct bmap sync_map[2];	/* Bridge/VXLAN FDB entries successfully written to kernel */
  struct bmap seen_map[2];	/* Bridge/VXLAN FDB entries seen during last periodic scan */

  ps_subscriber *vlan_sub;
  int vlan_filtering;
  bool ready;			/* Initial feed has been finished */
  bool synced;			/* First scan has been finished */

  struct kbr_proto *hash_next;

  HASH(struct kbr_vlan) vlan_hash;
  HASH(struct kbr_vlan) vlan_vni_hash;
};

struct kbr_vlan {
  u32 ifi;
  u32 vid;
  u32 vni;
  u32 vni_req;
  u16 flags;
  bool active;
  bool vni_link;
  bool mark_vlan;
  bool mark_tunnel;
  uintptr_t owner;
  struct kbr_vlan *next;
  struct kbr_vlan *next_vni;
};

extern struct ea_class ea_kbr_source;

void kbr_got_fdb(struct kbr_proto *p, const net_addr *n, rte *e, const struct nexthop_adata *nhad, int src, bool scan, bool tunnel);
void kbr_got_vlan(struct kbr_proto *p, struct iface *i, uint vid, uint flags);
void kbr_got_vlan_tunnel(struct kbr_proto *p, struct iface *i, uint vid, uint vni, uint flags);
struct kbr_vlan * kbr_find_vlan_by_vni(struct kbr_proto *p, uint ifi, uint vni);
int kbr_alt_export(const struct rt_prefilter *, const net_addr *);

/* krt sysdep */

int kbr_sys_start(struct kbr_proto *p);
void kbr_sys_shutdown(struct kbr_proto *p);

void kbr_replace_fdb(struct kbr_proto *p, const net_addr *n, rte *new, const rte *old, int tunnel);
void kbr_update_fdb(struct kbr_proto *p, const net_addr *n, rte *new, const rte *old, int tunnel);
void kbr_do_fdb_scan(struct kbr_proto *p);

void kbr_update_vlan(struct iface *i, uint vid, bool new, bool old, bool new_tunnel, bool old_tunnel, uint new_vni, uint old_vni);
void kbr_do_vlan_scan(struct kbr_proto *p);

#endif
