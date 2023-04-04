/*
 *	BIRD Internet Routing Daemon -- Network Interfaces
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_IFACE_H_
#define _BIRD_IFACE_H_

#include "lib/locking.h"
#include "lib/event.h"
#include "lib/lists.h"
#include "lib/tlists.h"
#include "lib/ip.h"

struct proto;
struct pool;

struct ifa {				/* Interface address */
  node n;
  struct iface *iface;			/* Interface this address belongs to */
  net_addr prefix;			/* Network prefix */
  ip_addr ip;				/* IP address of this host */
  ip_addr brd;				/* Broadcast address */
  ip_addr opposite;			/* Opposite end of a point-to-point link */
  unsigned scope;			/* Interface address scope */
  unsigned flags;			/* Analogous to iface->flags */
  unsigned uc;				/* Use (link) count */
};

extern struct iface default_vrf;

struct iface {
  node n;
  char name[16];
  unsigned flags;
  unsigned mtu;
  unsigned index;			/* OS-dependent interface index */
  unsigned master_index;		/* Interface index of master iface */
  struct iface *master;			/* Master iface (e.g. for VRF) */
  list addrs;				/* Addresses assigned to this interface */
  struct ifa *addr4;			/* Primary address for IPv4 */
  struct ifa *addr6;			/* Primary address for IPv6 */
  struct ifa *llv6;			/* Primary link-local address for IPv6 */
  ip4_addr sysdep;			/* Arbitrary IPv4 address for internal sysdep use */
  list neighbors;			/* All neighbors on this interface */
  unsigned uc;				/* Use (link) count */
};

#define IF_UP 1				/* Currently just IF_ADMIN_UP */
#define IF_MULTIACCESS 2
#define IF_BROADCAST 4
#define IF_MULTICAST 8
#define IF_SHUTDOWN 0x10		/* Interface disappeared */
#define IF_LOOPBACK 0x20
#define IF_IGNORE 0x40			/* Not to be used by routing protocols (loopbacks etc.) */
#define IF_ADMIN_UP 0x80		/* Administrative up (e.g. IFF_UP in Linux) */
#define IF_LINK_UP 0x100		/* Link available (e.g. IFF_LOWER_UP in Linux) */

#define IA_PRIMARY 0x10000		/* This address is primary */
#define IA_SECONDARY 0x20000		/* This address has been reported as secondary by the kernel */
#define IA_PEER 0x40000			/* A peer/ptp address */
#define IA_HOST 0x80000			/* A host/loopback address */
#define IA_FLAGS 0xff0000

/*
 * There are three kinds of addresses in BIRD:
 *  - Standard (prefix-based) addresses, these may define ifa.opposite (for /30 or /31).
 *  - Peer/ptp addresses, without common prefix for ifa.ip and ifa.opposite.
 *    ifa.opposite is defined and ifa.prefix/pxlen == ifa.opposite/32 (for simplicity).
 *  - Host addresses, with ifa.prefix/pxlen == ifa.ip/32 (or /128).
 *    May be considered a special case of standard addresses.
 *
 * Peer addresses (AFAIK) do not exist in IPv6. Linux also supports generalized peer
 * addresses (with pxlen < 32 and ifa.ip outside prefix), we do not support that.
 */


#define IF_JUST_CREATED	0x10000000	/* Send creation event as soon as possible */
#define IF_TMP_DOWN	0x20000000	/* Temporary shutdown due to interface reconfiguration */
#define IF_UPDATED	0x40000000	/* Iface touched in last scan */
#define IF_NEEDS_RECALC	0x80000000	/* Preferred address recalculation is needed */
#define IF_LOST_ADDR4	0x01000000	/* Preferred address was deleted, notification needed */
#define IF_LOST_ADDR6	0x02000000
#define IF_LOST_LLV6	0x04000000

#define IA_UPDATED	IF_UPDATED	/* Address touched in last scan */

/* Interface change events */

#define IF_CHANGE_UP 1
#define IF_CHANGE_DOWN 2
#define IF_CHANGE_MTU 4
#define IF_CHANGE_CREATE 8		/* Seen this interface for the first time */
#define IF_CHANGE_LINK 0x10
#define IF_CHANGE_ADDR4	0x100		/* Change of iface->addr4 */
#define IF_CHANGE_ADDR6	0x200		/* ... */
#define IF_CHANGE_LLV6 0x400
#define IF_CHANGE_SYSDEP 0x800
#define IF_CHANGE_TOO_MUCH 0x40000000	/* Used internally */

#define IF_CHANGE_UPDOWN (IF_CHANGE_UP | IF_CHANGE_DOWN)
#define IF_CHANGE_PREFERRED (IF_CHANGE_ADDR4 | IF_CHANGE_ADDR6 | IF_CHANGE_LLV6)

void if_init(void);
void if_dump(struct iface *);
void if_dump_all(void);
void ifa_dump(struct ifa *);
void if_show(void);
void if_show_summary(void);
struct iface *if_update(struct iface *);
struct iface *if_update_locked(struct iface *);
void if_delete(struct iface *old);
struct ifa *ifa_update(struct ifa *);
void ifa_delete(struct ifa *);
void if_start_update(void);
void if_end_partial_update(struct iface *);
void if_end_update(void);
struct iface *if_find_by_index(unsigned);
struct iface *if_find_by_index_locked(unsigned);
struct iface *if_find_by_name(const char *);
struct iface *if_get_by_name(const char *);
void if_recalc_all_preferred_addresses(void);

struct iface *if_walk_first(void);
struct iface *if_walk_next(struct iface *);
void if_walk_done(void);

#define IFACE_WALK(_i)	for (struct iface *_i = if_walk_first(); _i || (if_walk_done(), 0); _i = if_walk_next(_i))

/* The Neighbor Cache */

typedef struct neighbor {
  node n;				/* Node in neighbor hash table chain */
  node if_n;				/* Node in per-interface neighbor list */
  TLIST_NODE(proto_neigh, struct neighbor) proto_n;
  ip_addr addr;				/* Address of the neighbor */
  struct ifa *ifa;			/* Ifa on related iface */
  struct iface *iface;			/* Interface it's connected to */
  struct iface *ifreq;			/* Requested iface, NULL for any */
  struct proto *proto;			/* Protocol this belongs to */
  void *data;				/* Protocol-specific data */
  uint aux;				/* Protocol-specific data */
  u16 flags;				/* NEF_* flags */
  s16 scope;				/* Address scope, -1 for unreachable neighbors,
					   SCOPE_HOST when it's our own address */
  uint uc;				/* Use (link) count */
} neighbor;

#define TLIST_PREFIX proto_neigh
#define TLIST_TYPE struct neighbor
#define TLIST_ITEM proto_n
#define TLIST_WANT_WALK
#define TLIST_WANT_ADD_TAIL
#include "lib/tlists.h"

#define NEF_STICKY	1
#define NEF_ONLINK	2
#define NEF_IFACE	4		/* Entry for whole iface */


neighbor *neigh_find(struct proto *p, ip_addr a, struct iface *ifa, uint flags);

void neigh_dump_all(void);
void neigh_if_up(struct iface *);
void neigh_if_down(struct iface *);
void neigh_if_link(struct iface *);
void neigh_ifa_up(struct ifa *a);
void neigh_ifa_down(struct ifa *a);
void neigh_init(struct pool *);

void neigh_link(neighbor *);
void neigh_unlink(neighbor *);

/*
 *	Notification mechanism
 */

#define TLIST_PREFIX ifnot
#define TLIST_TYPE struct iface_notification
#define TLIST_ITEM nn
#define TLIST_WANT_WALK
#define TLIST_WANT_ADD_TAIL

struct iface_notification {
  TLIST_DEFAULT_NODE;
  enum {
    IFNOT_INVALID,
    IFNOT_ADDRESS,
    IFNOT_INTERFACE,
    IFNOT_NEIGHBOR,
  } type;
  unsigned flags;
  union {
    struct ifa *a;
    struct iface *i;
    neighbor *n;
  };
};

#include "lib/tlists.h"

#define TLIST_PREFIX ifsub
#define TLIST_TYPE struct iface_subscription
#define TLIST_ITEM n
#define TLIST_WANT_WALK
#define TLIST_WANT_ADD_TAIL

struct iface_subscription {
  TLIST_DEFAULT_NODE;

  event event;
  event_list *target;
  TLIST_LIST(ifnot) queue;

  void (*if_notify)(struct proto *, unsigned flags, struct iface *i);
  void (*ifa_notify)(struct proto *, unsigned flags, struct ifa *a);
  void (*neigh_notify)(struct neighbor *neigh);
};

#include "lib/tlists.h"

void if_enqueue_notify(struct iface_notification);
void if_enqueue_notify_to(struct iface_notification x, struct iface_subscription *s);

void iface_flush_notifications(struct iface_subscription *);
void iface_subscribe(struct iface_subscription *);
void iface_unsubscribe(struct iface_subscription *);

/*
 *	Interface Pattern Lists
 */

struct iface_patt_node {
  node n;
  int positive;
  const byte *pattern;
  net_addr prefix;
};

struct iface_patt {
  node n;
  list ipn_list;			/* A list of struct iface_patt_node */

  /* Protocol-specific data follow after this structure */
};

int iface_patt_match(struct iface_patt *ifp, struct iface *i, struct ifa *a);
struct iface_patt *iface_patt_find(list *l, struct iface *i, struct ifa *a);
int iface_patts_equal(list *, list *, int (*)(struct iface_patt *, struct iface_patt *));


u32 if_choose_router_id(struct iface_patt *mask, u32 old_id);

#endif
