/*
 *	BIRD -- Router Advertisement
 *
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_ISIS_H_
#define _BIRD_ISIS_H_

#include "nest/bird.h"

#include "lib/ip.h"
#include "lib/lists.h"
#include "lib/socket.h"
#include "lib/timer.h"
#include "lib/resource.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "nest/locks.h"
#include "conf/conf.h"
#include "lib/string.h"


#define ISIS_PROTO		90	// XXX

#define ISIS_LEVELS		2
#define ISIS_L1			0
#define ISIS_L2			1

#define ISIS_AREAS		3


#define mac_addr ip_addr // XXX

#define ETH_ALL_ISS		 ipa_from_u32(0xe0000005)	/* 224.0.0.5 */
#define ETH_ALL_L1_ISS		 ipa_from_u32(0xe0000005)	/* 224.0.0.5 */
#define ETH_ALL_L2_ISS		 ipa_from_u32(0xe0000005)	/* 224.0.0.5 */


struct isis_area_id
{
  byte length;
  byte body[];
};

struct isis_config
{
  struct proto_config c;
  list patt_list;		/* List of iface configs (struct isis_iface_config) */
  struct isis_area_id *areas[ISIS_AREAS];

  u64 system_id;

  u16 lsp_lifetime;
  u16 rx_buffer_size;
  u16 tx_buffer_size;
};

#define ISIS_DEFAULT_LSP_LIFETIME	1200
#define ISIS_DEFAULT_RX_BUFFER_SIZE	1492
#define ISIS_DEFAULT_TX_BUFFER_SIZE	1492

struct isis_iface_config
{
  struct iface_patt i;

  u8 levels[ISIS_LEVELS];
  u8 passive;
  u8 type;
  u8 metric;
  u8 priority;

  u16 hello_int;
  u16 hold_int;
  u16 hold_mult;
  u16 rxmt_int;
  u16 csnp_int;
  u16 psnp_int;
};

#define ISIS_LEVEL_PASSIVE	2

#define ISIS_DEFAULT_LEVEL_1	1
#define ISIS_DEFAULT_LEVEL_2	0
#define ISIS_DEFAULT_METRIC	1
#define ISIS_DEFAULT_PRIORITY	64

#define ISIS_DEFAULT_HELLO_INT	10
#define ISIS_DEFAULT_HOLD_INT	0
#define ISIS_DEFAULT_HOLD_MULT	3
#define ISIS_DEFAULT_RXMT_INT	5
#define ISIS_DEFAULT_CSNP_INT	10
#define ISIS_DEFAULT_PSNP_INT	2


struct isis_proto
{
  struct proto p;
  list iface_list;		/* List of active ifaces */

  u64 system_id;
  u16 lsp_max_age;
  u16 lsp_refresh;
  u16 buffer_size;
};

struct isis_iface
{
  node n;
  struct isis_proto *p;
  struct isis_iface_config *cf;	/* Related config, must be updated in reconfigure */
  struct iface *iface;

  pool *pool;
  struct object_lock *lock;
  sock *sk;
  list neigh_list;		/* List of neigbours */

  u8 type;
  u8 levels;
  u8 priority;

  u16 hello_int;
  u16 hold_int;
};

#define ISIS_IT_UNDEF		0
#define ISIS_IT_BCAST		1
#define ISIS_IT_PTP		2


struct isis_neighbor
{
  node n;
  struct isis_iface *ifa;
  mac_addr addr;
  u64 id;

  timer *hold_timer;

  u8 levels;
  u8 priority;
};

struct isis_lsdb
{
  pool *pool;
  slab *slab;
  list list;
};

struct isis_lsp_hdr
{
  u64 id;
  u32 seqnum;
  u16 lifetime;
  u16 checksum;
}

struct isis_lsp
{
  node n;
  struct isis_lsp_hdr hdr;
  void *body;
  u16 blen;
};



#define RA_EV_INIT 1		/* Switch to initial mode */
#define RA_EV_CHANGE 2		/* Change of options or prefixes */
#define RA_EV_RS 3		/* Received RS */



#ifdef LOCAL_DEBUG
#define ISIS_FORCE_DEBUG 1
#else
#define ISIS_FORCE_DEBUG 0
#endif
#define ISIS_TRACE(flags, msg, args...) do { if ((p->p.debug & flags) || ISIS_FORCE_DEBUG) \
        log(L_TRACE "%s: " msg, p->p.name , ## args ); } while(0)


/* isis.c */
void isis_iface_notify(struct isis_iface *ifa, int event);

/* ifaces.c */
void isis_if_notify(struct proto *pp, unsigned flags, struct iface *iface);
void isis_ifa_notify(struct proto *pp, unsigned flags, struct ifa *a);

/* packets.c */
void isis_send_lan_hello(struct isis_iface *ifa, int level);
void isis_send_ptp_hello(struct isis_iface *ifa);
void isis_send_lsp(struct isis_iface *ifa, struct lsp_entry *en);
void isis_send_csnp(struct isis_iface *ifa, int level);
void isis_send_psnp(struct isis_iface *ifa, int level);

int isis_sk_open(struct isis_iface *ifa);



#endif /* _BIRD_ISIS_H_ */
