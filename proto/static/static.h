/*
 *	BIRD -- Static Route Generator
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_STATIC_H_
#define _BIRD_STATIC_H_

#include "nest/route.h"
#include "nest/bfd.h"
#include "lib/buffer.h"

struct static_config {
  struct proto_config c;
  list routes;				/* List of static routes (struct static_route) */
  int check_link;			/* Whether iface link state is used */
  struct rtable_config *igp_table_ip4;	/* Table for recursive IPv4 next hop lookups */
  struct rtable_config *igp_table_ip6;	/* Table for recursive IPv6 next hop lookups */
  list mifs;				/* Multicast ifaces for multicast routes */

  BUFFER_(struct static_mif *) mif_stack; /* MIF stack for parser */
};

struct static_proto {
  struct proto p;

  struct event *event;			/* Event for announcing updated routes */
  BUFFER_(struct static_route *) marked; /* Routes marked for reannouncement */
  rtable *igp_table_ip4;		/* Table for recursive IPv4 next hop lookups */
  rtable *igp_table_ip6;		/* Table for recursive IPv6 next hop lookups */
  struct mif_group *mif_group;		/* Associated MIF group for multicast routes */
};

struct static_route {
  node n;
  net_addr *net;			/* Network we route */
  union {
    ip_addr via;			/* Destination router */
    struct { u32 iifs, oifs; };		/* Active IIFs and OIFs for multicast routes */
  };
  struct iface *iface;			/* Destination iface, for link-local vias or device routes */
  struct neighbor *neigh;		/* Associated neighbor entry */
  struct static_route *chain;		/* Next for the same neighbor */
  struct static_route *mp_head;		/* First nexthop of this route */
  struct static_route *mp_next;		/* Nexthops for multipath routes */
  struct f_inst *cmds;			/* List of commands for setting attributes */
  byte dest;				/* Destination type (RTD_*) */
  byte state;				/* State of route announcement (SRS_*) */
  byte active;				/* Next hop is active (nbr/iface/BFD available) */
  byte onlink;				/* Gateway is onlink regardless of IP ranges */
  byte weight;				/* Multipath next hop weight */
  byte use_bfd;				/* Configured to use BFD */
  byte from_len, to_len;
  struct bfd_request *bfd_req;		/* BFD request, if BFD is used */
  mpls_label_stack *mls;		/* MPLS label stack; may be NULL */
  struct static_mif **from;
  struct static_mif **to;
};

struct static_mif {
  node n;
  struct iface *iface;
  struct mif *mif;
  struct neighbor *nbr;			/* Associated neighbor entry */
  BUFFER_(struct static_route *) routes; /* List of routes using this MIF */
  u8 active;
};

/*
 * Note that data fields neigh, chain, state, active and bfd_req are runtime
 * data, not real configuration data. Must be handled carefully.
 *
 * Regular (i.e. dest == RTD_UNICAST) routes use static_route structure for
 * additional next hops (fields mp_head, mp_next). Note that 'state' is for
 * whole route, while 'active' is for each next hop. Also note that fields
 * mp_head, mp_next, active are zero for other kinds of routes.
 */

#define RTDX_RECURSIVE 0x7f		/* Phony dest value for recursive routes */

#define SRS_DOWN	0		/* Route is not announced */
#define SRS_CLEAN	1		/* Route is active and announced */
#define SRS_DIRTY	2		/* Route changed since announcement */

void static_cfg_add_mif(struct static_config *cf, char *name);
void static_cfg_flush_mifs(struct static_config *cf, struct static_mif ***buf, u8 *blen);

void static_show(struct proto *);

#endif
