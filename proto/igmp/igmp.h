/*
 *  BIRD --IGMP protocol
 *
 *  (c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_IGMP_H_
#define _BIRD_IGMP_H_

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/locks.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "conf/conf.h"
#include "lib/hash.h"
#include "lib/socket.h"
#include "filter/filter.h"

#include <linux/mroute.h>


struct igmp_iface_config
{
  struct iface_patt i;

  /* These are configurable */
  uint robustness, startup_query_cnt, last_member_query_cnt;
  btime query_int, query_response_int, startup_query_int,
	last_member_query_int;

  /* These are not */
  btime group_memb_int, other_querier_int;
};

struct igmp_config
{
  struct proto_config c;
  list patt_list;			/* list of ifaces (struct igmp_iface_config) */

  struct igmp_iface_config default_iface_cf;
};

struct igmp_grp
{
  struct igmp_grp *next;		/* member of igmp_iface->groups */
  struct igmp_iface *ifa;

  ip4_addr ga;
  uint join_state;
  timer *join_timer, *v1_host_timer, *rxmt_timer;
};

#define IGMP_JS_NOMEMB  0
#define IGMP_JS_MEMB    1
#define IGMP_JS_V1MEMB  2
#define IGMP_JS_CHECK   3

struct igmp_iface
{
  node n;				/* member of igmp_proto->iface_list */
  struct igmp_proto *proto;
  struct iface *iface;
  struct igmp_iface_config *cf;

  sock *sk;				/* The one receiving packets */
  uint query_state;			/* initial / querier / non-querier */
  vifi_t vifi;				/* VIF containing just this device */

  HASH(struct igmp_grp) groups;

  u32 gen_id;
  uint startup_query_cnt;		/* Remaining startup queries to send */
  timer *gen_query, *other_present;
};

#define IGMP_QS_INIT            0
#define IGMP_QS_QUERIER         1
#define IGMP_QS_NONQUERIER      2

struct igmp_proto
{
  struct proto p;
  struct igmp_config *cf;

  struct channel *mreq_channel;		/* Channel to multicast requests table */

  list iface_list;			/* list of managed ifaces (struct igmp_iface) */
};

#define IGMP_PROTO  2

/* igmp.c */
int igmp_query_received(struct igmp_iface *ifa, ip4_addr from);
int igmp_membership_report(struct igmp_grp *grp, u8 igmp_version, u8 resp_time);
int igmp_leave(struct igmp_grp *grp, u8 resp_time);

struct igmp_grp *igmp_grp_new(struct igmp_iface *ifa, ip4_addr *ga);
struct igmp_grp *igmp_grp_find(struct igmp_iface *ifa, ip4_addr *ga);

void igmp_config_init(struct igmp_config *cf);
void igmp_config_finish(struct proto_config *cf);
void igmp_iface_config_init(struct igmp_iface_config * ifc);
void igmp_iface_config_finish(struct igmp_iface_config * ifc);

/* packets.c */
int igmp_sk_open(struct igmp_iface * ifa);
int igmp_tx_query(struct igmp_iface *ifa, ip4_addr addr);


#endif
