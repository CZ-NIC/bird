/*
 *  BIRD -- Multicast routing kernel
 *
 *  (c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "nest/protocol.h"
#include "lib/socket.h"
#include "lib/hash.h"

#include <linux/mroute.h>

extern struct protocol proto_mkrt;

/* Proto state - kernel comm */

struct mkrt_config {
  struct proto_config cf;
};

struct mkrt_mfc_group {
  struct mkrt_mfc_group *next;
  ip_addr ga;
  list sources;
};

struct mkrt_mfc_source {
  node n;
  ip_addr addr;

  /* remember these for dumping  */
  vifi_t vifi;
  u32 iifs, oifs;
};

struct mkrt_proto {
  struct proto p;

  sock *igmp_sock;
  unsigned vif_count;
  struct iface *vif_map[MAXVIFS];

  HASH(struct mkrt_mfc_group) mfc_groups;
};

void mkrt_io_init(void);
unsigned mkrt_get_vif(struct iface *i);
void mkrt_listen(sock *s);
void mkrt_stop(sock *s);

struct proto_config *mkrt_config_init(int class);
void mkrt_config_finish(struct proto_config *);
