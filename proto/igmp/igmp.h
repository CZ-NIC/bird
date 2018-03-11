/*
 *	BIRD -- IGMP protocol
 *
 *	(c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *	(c) 2018 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2018 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_IGMP_H_
#define _BIRD_IGMP_H_

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/locks.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "conf/conf.h"
#include "lib/lists.h"
#include "lib/hash.h"
#include "lib/socket.h"
#include "lib/timer.h"


#define IGMP_PROTO  2

#define IGMP_DEFAULT_ROBUSTNESS		2
#define IGMP_DEFAULT_QUERY_INT		(125 S_)
#define IGMP_DEFAULT_RESPONSE_INT  	(10 S_)
#define IGMP_DEFAULT_LAST_MEMBER_INT	(1 S_)


struct igmp_config
{
  struct proto_config c;
  list iface_list;			/* List of ifaces (struct igmp_iface_config) */
};

struct igmp_iface_config
{
  struct iface_patt i;

  /* These are configurable */
  uint robustness, startup_query_cnt, last_member_query_cnt;
  btime query_int, query_response_int, startup_query_int, last_member_query_int;

  /* These are not */
  btime group_member_int, other_querier_int;
};

struct igmp_proto
{
  struct proto p;
  list iface_list;			/* List of interfaces (struct igmp_iface) */
  struct mif_group *mif_group;		/* Associated MIF group for multicast routes */

  struct tbf log_pkt_tbf;		/* TBF for packet messages */
};

struct igmp_iface
{
  node n;				/* Member of igmp_proto->iface_list */
  struct igmp_proto *proto;
  struct iface *iface;			/* Underyling core interface */
  struct mif *mif;			/* Associated multicast iface */
  struct igmp_iface_config *cf;		/* Related config, must be updated in reconfigure */
  struct object_lock *lock;		/* Interface lock */
  sock *sk;				/* IGMP socket */

  HASH(struct igmp_group) groups;

  uint query_state;			/* initial / querier / non-querier */
  int startup_query_cnt;		/* Remaining startup queries to send */
  timer *query_timer, *other_present;
};

struct igmp_group
{
  struct igmp_group *next;		/* Member of igmp_iface->groups */
  struct igmp_iface *ifa;
  ip4_addr address;

  uint join_state;
  timer *join_timer, *v1_host_timer, *rxmt_timer;
};


#define IGMP_JS_NO_MEMBERS	0
#define IGMP_JS_MEMBERS		1
#define IGMP_JS_V1_MEMBERS	2
#define IGMP_JS_CHECKING	3

#define IGMP_QS_INIT            0
#define IGMP_QS_QUERIER         1
#define IGMP_QS_NONQUERIER      2


/* igmp.c */
void igmp_handle_query(struct igmp_iface *ifa, ip4_addr addr, ip4_addr from, btime resp_time);
void igmp_handle_report(struct igmp_iface *ifa, ip4_addr addr, int version);
void igmp_handle_leave(struct igmp_iface *ifa, ip4_addr addr);
void igmp_finish_iface_config(struct igmp_iface_config *cf);

/* packets.c */
int igmp_open_socket(struct igmp_iface *ifa);
void igmp_send_query(struct igmp_iface *ifa, ip4_addr addr, btime resp_time);


#endif
