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

struct static_config {
  struct proto_config c;
  list iface_routes;		/* Routes to search on interface events */
  list neigh_routes;		/* Routes to search on neighbor events */
  list other_routes;		/* Non-nexthop routes */
  int check_link;			/* Whether iface link state is used */
  struct rtable_config *igp_table;	/* Table used for recursive next hop lookups */
};


void static_init_config(struct static_config *);

struct static_route {
  node n;
  struct static_route *chain;		/* Next for the same neighbor */
  net_addr *net;			/* Network we route */
  int dest;				/* Destination type (RTD_*) */
  ip_addr via;				/* Destination router */
  struct iface *iface;			/* Destination iface, for link-local vias or device routes */
  struct neighbor *neigh;
  byte *if_name;			/* Name for device routes */
  struct static_route *mp_next;		/* Nexthops for multipath routes */
  struct static_route *mp_head;		/* First nexthop of this route */
  struct f_inst *cmds;			/* List of commands for setting attributes */
  u32 state;				/* Current state: STS_* */
  int weight;				/* Multipath next hop weight */
  byte use_bfd;				/* Configured to use BFD */
  byte label_count;			/* Number of labels in stack */
  struct bfd_request *bfd_req;		/* BFD request, if BFD is used */
  u32 *label_stack;			/* Label stack if label_count > 0 */
};

#define STS_INSTALLED		0x1
#define STS_WANT		0x2
#define STS_FORCE		0x4

/* Dummy nodes (parts of multipath route) abuses masklen field for weight
   and if_name field for a ptr to the master (RTD_MULTIPATH) node. */


#define RTDX_RECURSIVE 0x7f		/* Phony dest value for recursive routes */

void static_show(struct proto *);

#endif
