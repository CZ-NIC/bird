/*
 *	BIRD -- UNIX Kernel Multicast Routing
 *
 *	(c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *	(c) 2018 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2018 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_MKRT_H_
#define _BIRD_MKRT_H_

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "lib/socket.h"


extern struct protocol proto_unix_mkrt;

struct mkrt_config {
  struct proto_config cf;
};

struct mkrt_mfc_group {
  list sources;				/* List of MFC entries (struct mkrt_mfc_source) */
  struct fib_node n;
};

struct mkrt_mfc_source {
  node n;
  ip4_addr addr;

  int parent;				/* MIF index of valid incoming iface */
  u32 iifs, oifs;			/* Values from the multicast route */
};

struct mkrt_proto {
  struct proto p;

  struct mif_group *mif_group;		/* Associated MIF group for multicast routes */
  sock *mrt_sock;			/* MRT control socket */

  struct fib mfc_groups;		/* MFC entries/groups managed by protocol */
};

struct proto_config *mkrt_init_config(int class);

#endif
