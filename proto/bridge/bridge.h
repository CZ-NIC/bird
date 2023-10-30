/*
 *	BIRD -- Linux Bridge Interface
 *
 *	(c) 2023 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2023 CZ.NIC z.s.p.o.
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
  int vlan_filtering;

  struct kbr_proto *hash_next;
};

void kbr_got_route(struct kbr_proto *p, const net_addr *n, rte *e, int src, int scan);


/* krt sysdep */

int kbr_sys_start(struct kbr_proto *p);
void kbr_sys_shutdown(struct kbr_proto *p);

void kbr_replace_fdb(const net_addr *n, rte *new, rte *old, int tunnel);
void kbr_update_fdb(const net_addr *n, rte *new, rte *old, int tunnel);
void kbr_do_scan(struct kbr_proto *p);

#endif
