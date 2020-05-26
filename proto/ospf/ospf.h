/*
 *	BIRD -- OSPF
 *
 *	(c) 1999--2005 Ondrej Filip <feela@network.cz>
 *	(c) 2009--2014 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2009--2014 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_OSPF_H_
#define _BIRD_OSPF_H_

#include "nest/bird.h"

#include "lib/checksum.h"
#include "lib/idm.h"
#include "lib/lists.h"
#include "lib/slists.h"
#include "lib/socket.h"
#include "lib/timer.h"
#include "lib/resource.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "nest/locks.h"
#include "nest/bfd.h"
#include "conf/conf.h"
#include "lib/string.h"


#ifdef LOCAL_DEBUG
#define OSPF_FORCE_DEBUG 1
#else
#define OSPF_FORCE_DEBUG 0
#endif


#define OSPF_TRACE(flags, msg, args...) \
  do { if ((p->p.debug & flags) || OSPF_FORCE_DEBUG) \
    log(L_TRACE "%s: " msg, p->p.name , ## args ); } while(0)

#define OSPF_PACKET(dumpfn, buffer, msg, args...) \
  do { if ((p->p.debug & D_PACKETS) || OSPF_FORCE_DEBUG)		\
    { log(L_TRACE "%s: " msg, p->p.name, ## args ); dumpfn(p, buffer); } } while(0)

#define LOG_PKT(msg, args...) \
  log_rl(&p->log_pkt_tbf, L_REMOTE "%s: " msg, p->p.name, args)

#define LOG_PKT_AUTH(msg, args...) \
  log_rl(&p->log_pkt_tbf, L_AUTH "%s: " msg, p->p.name, args)

#define LOG_PKT_WARN(msg, args...) \
  log_rl(&p->log_pkt_tbf, L_WARN "%s: " msg, p->p.name, args)

#define LOG_LSA1(msg, args...) \
  log_rl(&p->log_lsa_tbf, L_REMOTE "%s: " msg, p->p.name, args)

#define LOG_LSA2(msg, args...) \
  do { if (! p->log_lsa_tbf.drop) \
    log(L_REMOTE "%s: " msg, p->p.name, args); } while(0)


#define OSPF_PROTO 89

#define LSREFRESHTIME		1800	/* 30 minutes */
#define MINLSINTERVAL		(5 S_)
#define MINLSARRIVAL		(1 S_)
#define LSINFINITY		0xffffff

#define OSPF_PKT_TYPES		5	/* HELLO_P .. LSACK_P */
#define OSPF3_CRYPTO_ID		1	/* OSPFv3 Cryptographic Protocol ID */

#define OSPF_DEFAULT_TICK 1
#define OSPF_DEFAULT_STUB_COST 1000
#define OSPF_DEFAULT_ECMP_LIMIT 16
#define OSPF_DEFAULT_GR_TIME 120
#define OSPF_DEFAULT_TRANSINT 40

#define OSPF_MIN_PKT_SIZE 256
#define OSPF_MAX_PKT_SIZE 65535

#define OSPF_VLINK_ID_OFFSET 0x80000000

#define OSPF_GR_ABLE		1
#define OSPF_GR_AWARE		2

struct ospf_config
{
  struct proto_config c;
  uint tick;
  u8 ospf2;
  u8 af_ext;
  u8 af_mc;
  u8 rfc1583;
  u8 stub_router;
  u8 merge_external;
  u8 instance_id;
  u8 instance_id_set;
  u8 abr;
  u8 asbr;
  u8 vpn_pe;
  u8 gr_mode;			/* Graceful restart mode (OSPF_GR_*) */
  uint gr_time;			/* Graceful restart interval */
  uint ecmp;
  list area_list;		/* list of area configs (struct ospf_area_config) */
  list vlink_list;		/* list of configured vlinks (struct ospf_iface_patt) */
};

struct ospf_area_config
{
  node n;
  u32 areaid;
  u32 default_cost;		/* Cost of default route for stub areas
				   (With possible LSA_EXT3_EBIT for NSSA areas) */
  u8 type;			/* Area type (standard, stub, NSSA), represented
				   by option flags (OPT_E, OPT_N) */
  u8 summary;			/* Import summaries to this stub/NSSA area, valid for ABR */
  u8 default_nssa;		/* Generate default NSSA route for NSSA+summary area */
  u8 translator;		/* Translator role, for NSSA ABR */
  u32 transint;			/* Translator stability interval */
  list patt_list;		/* List of iface configs (struct ospf_iface_patt) */
  list net_list;		/* List of aggregate networks for that area */
  list enet_list;		/* List of aggregate external (NSSA) networks */
  list stubnet_list;		/* List of stub networks added to Router LSA */
};

struct area_net_config
{
  node n;
  net_addr prefix;
  u32 tag;
  u8 hidden;
};

struct area_net
{
  u32 metric;			/* With possible LSA_EXT3_EBIT for NSSA area nets */
  u32 tag;
  u8 hidden;
  u8 active;
  struct fib_node fn;
};

struct ospf_stubnet_config
{
  node n;
  net_addr prefix;
  u32 cost;
  u8 hidden;
  u8 summary;
};

struct nbma_node
{
  node n;
  ip_addr ip;
  byte eligible;
  byte found;
};

struct ospf_iface_patt
{
  struct iface_patt i;
  u32 type;
  u32 stub;
  u32 cost;
  u32 helloint;
  u32 rxmtint;
  u32 pollint;
  u32 waitint;
  u32 deadc;
  u32 deadint;
  u32 inftransdelay;
  list nbma_list;
  u32 priority;
  u32 voa;
  u32 vid;
  int tx_tos;
  int tx_priority;
  u16 tx_length;
  u16 rx_buffer;
#define OSPF_RXBUF_MINSIZE 256	/* Minimal allowed size */
  u8 instance_id;
  u8 instance_id_set;
  u8 autype;			/* OSPF_AUTH_*, not really used in OSPFv3 */
  u8 strictnbma;
  u8 check_link;
  u8 ecmp_weight;
  u8 link_lsa_suppression;
  u8 real_bcast;		/* Not really used in OSPFv3 */
  u8 ptp_netmask;		/* bool + 2 for unspecified */
  u8 ptp_address;		/* bool + 2 for unspecified */
  u8 ttl_security;		/* bool + 2 for TX only */
  u8 bfd;
  list *passwords;
};

/* Default values for interface parameters */
#define COST_D 10
#define RXMTINT_D 5
#define INFTRANSDELAY_D 1
#define PRIORITY_D 1
#define HELLOINT_D 10
#define POLLINT_D 20
#define DEADC_D 4
#define WAIT_DMH 4
  /* Value of Wait timer - not found it in RFC * - using 4*HELLO */



struct ospf_proto
{
  struct proto p;
  timer *disp_timer;		/* OSPF proto dispatcher */
  uint tick;
  struct top_graph *gr;		/* LSA graph */
  slist lsal;			/* List of all LSA's */
  int calcrt;			/* Routing table calculation scheduled?
				   0=no, 1=normal, 2=forced reload */
  list iface_list;		/* List of OSPF interfaces (struct ospf_iface) */
  list area_list;		/* List of OSPF areas (struct ospf_area) */
  int areano;			/* Number of area I belong to */
  int padj;			/* Number of neighbors in Exchange or Loading state */
  int gr_count;			/* Number of neighbors in graceful restart state */
  u8 gr_recovery;		/* Graceful restart recovery is active */
  u8 gr_cleanup;		/* GR cleanup scheduled */
  btime gr_timeout;		/* The end time of grace restart recovery */
  struct fib rtf;		/* Routing table */
  struct idm idm;		/* OSPFv3 LSA ID map */
  u8 ospf2;			/* OSPF v2 or v3 */
  u8 af_ext;			/* OSPFv3-AF extension */
  u8 af_mc;			/* OSPFv3-AF multicast */
  u8 rfc1583;			/* RFC1583 compatibility */
  u8 stub_router;		/* Do not forward transit traffic */
  u8 merge_external;		/* Should i merge external routes? */
  u8 instance_id;		/* Differentiate between more OSPF instances */
  u8 asbr;			/* May i originate any ext/NSSA lsa? */
  u8 vpn_pe;			/* Should we do VPN PE specific behavior (RFC 4577)? */
  u8 ecmp;			/* Maximal number of nexthops in ECMP route, or 0 */
  u8 gr_mode;			/* Graceful restart mode (OSPF_GR_*) */
  uint gr_time;			/* Graceful restart interval */
  u64 csn64;			/* Last used cryptographic sequence number */
  struct ospf_area *backbone;	/* If exists */
  event *flood_event;		/* Event for flooding LS updates */
  void *lsab;			/* LSA buffer used when originating router LSAs */
  int lsab_size, lsab_used;
  linpool *nhpool;		/* Linpool used for next hops computed in SPF */
  sock *vlink_sk;		/* IP socket used for vlink TX */
  u32 router_id;
  u32 last_vlink_id;		/* Interface IDs for vlinks (starts at 0x80000000) */
  struct tbf log_pkt_tbf;	/* TBF for packet messages */
  struct tbf log_lsa_tbf;	/* TBF for LSA messages */
};

struct ospf_area
{
  node n;
  u32 areaid;
  struct ospf_area_config *ac;	/* Related area config */
  struct top_hash_entry *rt;	/* My own router LSA */
  struct top_hash_entry *pxr_lsa; /* Originated prefix LSA */
  list cand;			/* List of candidates for RT calc. */
  struct fib net_fib;		/* Networks to advertise or not */
  struct fib enet_fib;		/* External networks for NSSAs */
  u32 options;			/* Optional features */
  u8 update_rt_lsa;		/* Rt lsa origination scheduled? */
  u8 trcap;			/* Transit capability? */
  u8 marked;			/* Used in OSPF reconfigure */
  u8 translate;			/* Translator state (TRANS_*), for NSSA ABR  */
  timer *translator_timer;	/* For NSSA translator switch */
  struct ospf_proto *po;
  struct fib rtr;		/* Routing tables for routers */
};

struct ospf_iface
{
  node n;
  struct iface *iface;		/* Nest's iface (NULL for vlinks) */
  struct ifa *addr;		/* IP prefix associated with that OSPF iface */
  struct ospf_area *oa;
  struct ospf_iface_patt *cf;
  char *ifname;			/* Interface name (iface->name), new one for vlinks */

  pool *pool;
  sock *sk;			/* IP socket */
  list neigh_list;		/* List of neighbors (struct ospf_neighbor) */
  u32 cost;			/* Cost of iface */
  u32 waitint;			/* Number of seconds before changing state from wait */
  u32 rxmtint;			/* Number of seconds between LSA retransmissions */
  u32 pollint;			/* Poll interval in seconds */
  u32 deadint;			/* After deadint seconds without hellos is router dead */
  u32 iface_id;			/* Interface ID (iface->index or new value for vlinks) */
  u32 vid;			/* ID of peer of virtual link */
  ip_addr vip;			/* IP of peer of virtual link */
  struct ospf_iface *vifa;	/* OSPF iface which the vlink goes through */
  struct ospf_area *voa;	/* OSPF area which the vlink goes through */
  u16 inftransdelay;		/* The estimated number of seconds it takes to
				   transmit a Link State Update Packet over this
				   interface.  LSAs contained in the update */
  u16 helloint;			/* number of seconds between hello sending */
  list *passwords;
  u32 csn;			/* Last used crypt seq number */
  btime csn_use;		/* Last time when packet with that CSN was sent */
  ip_addr all_routers;		/* Multicast (or broadcast) address for all routers */
  ip_addr des_routers;		/* Multicast (or NULL) address for designated routers */
  ip_addr drip;			/* Designated router IP */
  ip_addr bdrip;		/* Backup DR IP */
  u32 drid;			/* DR Router ID */
  u32 bdrid;			/* BDR Router ID */
  s16 rt_pos_beg;		/* Position of iface in Router-LSA, begin, inclusive */
  s16 rt_pos_end;		/* Position of iface in Router-LSA, end, exclusive */
  s16 px_pos_beg;		/* Position of iface in Rt Prefix-LSA, begin, inclusive */
  s16 px_pos_end;		/* Position of iface in Rt Prefix-LSA, end, exclusive */
  u32 dr_iface_id;		/* if drid is valid, this is iface_id of DR (for connecting network) */
  u8 instance_id;		/* Used to differentiate between more OSPF
				   instances on one interface */
  u8 autype;			/* Authentication type (OSPF_AUTH_*) */
  u8 type;			/* OSPF view of type (OSPF_IT_*) */
  u8 strictnbma;		/* Can I talk with unknown neighbors? */
  u8 stub;			/* Inactive interface */
  u8 state;			/* Interface state machine (OSPF_IS_*) */
  timer *wait_timer;		/* WAIT timer */
  timer *hello_timer;		/* HELLOINT timer */
  timer *poll_timer;		/* Poll Interval - for NBMA */

  struct top_hash_entry *link_lsa;	/* Originated link LSA */
  struct top_hash_entry *net_lsa;	/* Originated network LSA */
  struct top_hash_entry *pxn_lsa;	/* Originated prefix LSA */
  struct top_hash_entry **flood_queue;	/* LSAs queued for LSUPD */
  u8 update_link_lsa;
  u8 update_net_lsa;
  u16 flood_queue_used;		/* The current number of LSAs in flood_queue */
  u16 flood_queue_size;		/* The maximum number of LSAs in flood_queue */
  int fadj;			/* Number of fully adjacent neighbors */
  list nbma_list;
  u8 priority;			/* A router priority for DR election */
  u8 ioprob;
#define OSPF_I_OK 0		/* Everything OK */
#define OSPF_I_SK 1		/* Socket open failed */
#define OSPF_I_LL 2		/* Missing link-local address (OSPFv3) */
  u8 sk_dr;			/* Socket is a member of designated routers group */
  u8 marked;			/* Used in OSPF reconfigure, 2 for force restart */
  u16 rxbuf;			/* Buffer size */
  u16 tx_length;		/* Soft TX packet length limit, usually MTU */
  u16 tx_hdrlen;		/* Expected packet header length, less than tx_length */
  u8 check_link;		/* Whether iface link change is used */
  u8 ecmp_weight;		/* Weight used for ECMP */
  u8 link_lsa_suppression;	/* Suppression of Link-LSA origination */
  u8 ptp_netmask;		/* Send real netmask for P2P */
  u8 ptp_address;		/* Send IP address in data field for PtP */
  u8 check_ttl;			/* Check incoming packets for TTL 255 */
  u8 bfd;			/* Use BFD on iface */
};

struct ospf_neighbor
{
  node n;
  pool *pool;
  struct ospf_iface *ifa;
  u8 state;
  u8 gr_active;			/* We act as GR helper for the neighbor */
  u8 got_my_rt_lsa;		/* Received my Rt-LSA in DBDES exchanged */
  timer *inactim;		/* Inactivity timer */
  u8 imms;			/* I, M, Master/slave received */
  u8 myimms;			/* I, M Master/slave */
  u32 dds;			/* DD Sequence number being sent */
  u32 ddr;			/* last Dat Des packet received */

  u32 rid;			/* Router ID */
  ip_addr ip;			/* IP of it's interface */
  u8 priority;			/* Priority */
  u32 options;			/* Options received */

  /* Entries dr and bdr store IP addresses in OSPFv2 and router IDs in
     OSPFv3, we use the same type to simplify handling */
  u32 dr;			/* Neighbor's idea of DR */
  u32 bdr;			/* Neighbor's idea of BDR */
  u32 iface_id;			/* ID of Neighbour's iface connected to common network */

  /* Database summary list iterator, controls initial dbdes exchange.
   * Advances in the LSA list as dbdes packets are sent.
   */
  siterator dbsi;		/* iterator of po->lsal */

  /* Link state request list, controls initial LSA exchange.
   * Entries added when received in dbdes packets, removed as sent in lsreq packets.
   */
  slist lsrql;			/* slist of struct top_hash_entry from n->lsrqh */
  struct top_graph *lsrqh;
  struct top_hash_entry *lsrqi;	/* Pointer to the first unsent node in lsrql */

  /* Link state retransmission list, controls LSA retransmission during flood.
   * Entries added as sent in lsupd packets, removed when received in lsack packets.
   * These entries hold ret_count in appropriate LSA entries.
   */
  slist lsrtl;			/* slist of struct top_hash_entry from n->lsrth */
  struct top_graph *lsrth;
  timer *dbdes_timer;		/* DBDES exchange timer */
  timer *lsrq_timer;		/* LSA request timer */
  timer *lsrt_timer;		/* LSA retransmission timer */
  list ackl[2];
#define ACKL_DIRECT 0
#define ACKL_DELAY 1
  timer *ackd_timer;		/* Delayed ack timer */
  timer *gr_timer;		/* Graceful restart timer, non-NULL only if gr_active */
  struct bfd_request *bfd_req;	/* BFD request, if BFD is used */
  void *ldd_buffer;		/* Last database description packet */
  u32 ldd_bsize;		/* Buffer size for ldd_buffer */
  u32 csn;			/* OSPFv2: Last received crypt seq number */
  u64 csn64[OSPF_PKT_TYPES];	/* OSPFv3: Last received CSN for each type of packet */
};


/* OSPF interface types */
#define OSPF_IT_BCAST	0
#define OSPF_IT_NBMA	1
#define OSPF_IT_PTP	2
#define OSPF_IT_PTMP	3
#define OSPF_IT_VLINK	4
#define OSPF_IT_UNDEF	5

/* OSPF interface states */
#define OSPF_IS_DOWN	0	/* Not active */
#define OSPF_IS_LOOP	1	/* Iface with no link */
#define OSPF_IS_WAITING	2	/* Waiting for Wait timer */
#define OSPF_IS_PTP	3	/* PTP operational */
#define OSPF_IS_DROTHER	4	/* I'm on BCAST or NBMA and I'm not DR */
#define OSPF_IS_BACKUP	5	/* I'm BDR */
#define OSPF_IS_DR	6	/* I'm DR */

/* Definitions for interface state machine */
#define ISM_UP		0	/* Interface Up */
#define ISM_WAITF	1	/* Wait timer fired */
#define ISM_BACKS	2	/* Backup seen */
#define ISM_NEICH	3	/* Neighbor change */
#define ISM_LOOP	4	/* Link down */
#define ISM_UNLOOP	5	/* Link up */
#define ISM_DOWN	6	/* Interface down */

/* OSPF authentication types */
#define OSPF_AUTH_NONE	0
#define OSPF_AUTH_SIMPLE 1
#define OSPF_AUTH_CRYPT	2

#define OSPF3_AUTH_HMAC 1	/* HMAC Cryptographic Authentication */

/* OSPF neighbor states */
#define NEIGHBOR_DOWN	0
#define NEIGHBOR_ATTEMPT 1
#define NEIGHBOR_INIT	2
#define NEIGHBOR_2WAY	3
#define NEIGHBOR_EXSTART 4
#define NEIGHBOR_EXCHANGE 5
#define NEIGHBOR_LOADING 6
#define NEIGHBOR_FULL	7

/* Definitions for neighbor state machine */
#define INM_HELLOREC	0	/* Hello Received */
#define INM_START	1	/* Neighbor start - for NBMA */
#define INM_2WAYREC	2	/* 2-Way received */
#define INM_NEGDONE	3	/* Negotiation done */
#define INM_EXDONE	4	/* Exchange done */
#define INM_BADLSREQ	5	/* Bad LS Request */
#define INM_LOADDONE	6	/* Load done */
#define INM_ADJOK	7	/* AdjOK? */
#define INM_SEQMIS	8	/* Sequence number mismatch */
#define INM_1WAYREC	9	/* 1-Way */
#define INM_KILLNBR	10	/* Kill Neighbor */
#define INM_INACTTIM	11	/* Inactivity timer */
#define INM_LLDOWN	12	/* Line down */

#define TRANS_OFF	0
#define TRANS_ON	1
#define TRANS_WAIT	2	/* Waiting before the end of translation */


/* Generic option flags */
#define OPT_V6		0x0001	/* OSPFv3, LSA relevant for IPv6 routing calculation */
#define OPT_E		0x0002	/* Related to AS-external LSAs */
#define OPT_MC		0x0004	/* Related to MOSPF, not used and obsolete */
#define OPT_N		0x0008	/* Related to NSSA */
#define OPT_P		0x0008	/* OSPFv2, flags P and N share position, see NSSA RFC */
#define OPT_L_V2	0x0010	/* OSPFv2, link-local signaling, not used */
#define OPT_R		0x0010	/* OSPFv3, originator is active router */
#define OPT_DC		0x0020	/* Related to demand circuits, not used */
#define OPT_O		0x0040	/* OSPFv2 Opaque LSA (RFC 5250) */
#define OPT_DN		0x0080	/* OSPFv2 VPN loop prevention (RFC 4576) */
#define OPT_AF		0x0100	/* OSPFv3 Address Families (RFC 5838) */
#define OPT_L_V3	0x0200	/* OSPFv3, link-local signaling */
#define OPT_AT          0x0400	/* OSPFv3, authentication trailer */

#define HELLO2_OPT_MASK	(OPT_E | OPT_N | OPT_L_V2)
#define DBDES2_OPT_MASK	(OPT_E         | OPT_L_V2 | OPT_O)

#define HELLO3_OPT_MASK	(OPT_V6 | OPT_E | OPT_N | OPT_R | OPT_AF | OPT_L_V3 | OPT_AT )
#define DBDES3_OPT_MASK	(OPT_V6 | OPT_E |         OPT_R | OPT_AF | OPT_L_V3 | OPT_AT )

/* Router-LSA VEB flags are are stored together with links (OSPFv2) or options (OSPFv3) */
#define OPT_RT_B	(0x01 << 24)
#define OPT_RT_E	(0x02 << 24)
#define OPT_RT_V	(0x04 << 24)
#define OPT_RT_NT	(0x10 << 24)

/* Prefix flags, specific for OSPFv3 */
#define OPT_PX_NU	0x01
#define OPT_PX_LA	0x02
#define OPT_PX_P	0x08
#define OPT_PX_DN	0x10


struct ospf_packet
{
  u8 version;
  u8 type;
  u16 length;
  u32 routerid;
  u32 areaid;
  u16 checksum;
  u8 instance_id;		/* See RFC 6549 */
  u8 autype;			/* Undefined for OSPFv3 */
};

struct ospf_lls
{
  u16 checksum;
  u16 length;
  byte data[0];
};

struct ospf_auth_crypto
{
  u16 zero;
  u8 keyid;
  u8 len;
  u32 csn;			/* Cryptographic sequence number (32-bit) */
};

union ospf_auth2
{
  u8 password[8];
  struct ospf_auth_crypto c32;
};

struct ospf_auth3
{
  u16 type;			/* Authentication type (OSPF3_AUTH_*) */
  u16 length;			/* Authentication trailer length (header + data) */
  u16 reserved;
  u16 sa_id;			/* Security association identifier (key_id) */
  u64 csn;			/* Cryptographic sequence number (64-bit) */
  byte data[0];			/* Authentication data */
};


/* Packet types */
#define HELLO_P		1	/* Hello */
#define DBDES_P		2	/* Database description */
#define LSREQ_P		3	/* Link state request */
#define LSUPD_P		4	/* Link state update */
#define LSACK_P		5	/* Link state acknowledgement */


#define DBDES_I		4	/* Init bit */
#define DBDES_M		2	/* More bit */
#define DBDES_MS	1	/* Master/Slave bit */
#define DBDES_IMMS	(DBDES_I | DBDES_M | DBDES_MS)


/* OSPFv3 LSA Types / LSA Function Codes */
/* https://www.iana.org/assignments/ospfv3-parameters/ospfv3-parameters.xhtml#ospfv3-parameters-3 */
#define LSA_T_RT		0x2001
#define LSA_T_NET		0x2002
#define LSA_T_SUM_NET		0x2003
#define LSA_T_SUM_RT		0x2004
#define LSA_T_EXT		0x4005
#define LSA_T_NSSA		0x2007
#define LSA_T_LINK		0x0008
#define LSA_T_PREFIX		0x2009
#define LSA_T_GR		0x000B
#define LSA_T_RI_		0x000C
#define LSA_T_RI_LINK		0x800C
#define LSA_T_RI_AREA		0xA00C
#define LSA_T_RI_AS		0xC00C
#define LSA_T_OPAQUE_		0x1FFF
#define LSA_T_OPAQUE_LINK	0x9FFF
#define LSA_T_OPAQUE_AREA	0xBFFF
#define LSA_T_OPAQUE_AS	 	0xDFFF

#define LSA_T_V2_OPAQUE_	0x0009
#define LSA_T_V2_MASK		0x00ff

/* OSPFv2 Opaque LSA Types */
/* https://www.iana.org/assignments/ospf-opaque-types/ospf-opaque-types.xhtml#ospf-opaque-types-2 */
#define LSA_OT_GR		0x03
#define LSA_OT_RI		0x04

#define LSA_FUNCTION_MASK	0x1FFF
#define LSA_FUNCTION(type)	((type) & LSA_FUNCTION_MASK)

#define LSA_UBIT		0x8000

#define LSA_SCOPE_LINK		0x0000
#define LSA_SCOPE_AREA		0x2000
#define LSA_SCOPE_AS		0x4000
#define LSA_SCOPE_RES		0x6000
#define LSA_SCOPE_MASK		0x6000
#define LSA_SCOPE(type)		((type) & LSA_SCOPE_MASK)
#define LSA_SCOPE_ORDER(type)	(((type) >> 13) & 0x3)


#define LSA_MAXAGE	3600	/* 1 hour */
#define LSA_CHECKAGE	300	/* 5 minutes */
#define LSA_MAXAGEDIFF	900	/* 15 minutes */

#define LSA_ZEROSEQNO	((s32) 0x80000000)
#define LSA_INITSEQNO	((s32) 0x80000001)
#define LSA_MAXSEQNO	((s32) 0x7fffffff)

#define LSA_METRIC_MASK  0x00FFFFFF
#define LSA_OPTIONS_MASK 0x00FFFFFF


#define LSART_PTP	1
#define LSART_NET	2
#define LSART_STUB	3
#define LSART_VLNK	4

#define LSA_RT2_LINKS	0x0000FFFF

#define LSA_SUM2_TOS	0xFF000000

#define LSA_EXT2_TOS	0x7F000000
#define LSA_EXT2_EBIT	0x80000000

#define LSA_EXT3_EBIT	0x04000000
#define LSA_EXT3_FBIT	0x02000000
#define LSA_EXT3_TBIT	0x01000000

/* OSPF Grace LSA (GR) TLVs */
/* https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#ospfv2-parameters-13 */
#define LSA_GR_PERIOD		1
#define LSA_GR_REASON		2
#define LSA_GR_ADDRESS		3

/* OSPF Router Information (RI) TLVs */
/* https://www.iana.org/assignments/ospf-parameters/ospf-parameters.xhtml#ri-tlv */
#define LSA_RI_RIC		1
#define LSA_RI_RFC		2

/* OSPF Router Informational Capability Bits */
/* https://www.iana.org/assignments/ospf-parameters/ospf-parameters.xhtml#router-informational-capability */
#define LSA_RIC_GR_CAPABLE	0
#define LSA_RIC_GR_HELPER	1
#define LSA_RIC_STUB_ROUTER	2


struct ospf_lsa_header
{
  u16 age;			/* LS Age */
  u16 type_raw;			/* Type, mixed with options on OSPFv2 */

  u32 id;
  u32 rt;			/* Advertising router */
  s32 sn;			/* LS Sequence number */
  u16 checksum;
  u16 length;
};


/* In OSPFv2, options are embedded in higher half of type_raw */
static inline u8 lsa_get_options(struct ospf_lsa_header *lsa)
{ return lsa->type_raw >> 8; }

static inline void lsa_set_options(struct ospf_lsa_header *lsa, u16 options)
{ lsa->type_raw = (lsa->type_raw & 0xff) | (options << 8); }


struct ospf_lsa_rt
{
  u32 options;	/* VEB flags, mixed with link count for OSPFv2 and options for OSPFv3 */
};

struct ospf_lsa_rt2_link
{
  u32 id;
  u32 data;
#ifdef CPU_BIG_ENDIAN
  u8 type;
  u8 no_tos;
  u16 metric;
#else
  u16 metric;
  u8 no_tos;
  u8 type;
#endif
};

struct ospf_lsa_rt2_tos
{
#ifdef CPU_BIG_ENDIAN
  u8 tos;
  u8 padding;
  u16 metric;
#else
  u16 metric;
  u8 padding;
  u8 tos;
#endif
};

struct ospf_lsa_rt3_link
{
#ifdef CPU_BIG_ENDIAN
  u8 type;
  u8 padding;
  u16 metric;
#else
  u16 metric;
  u8 padding;
  u8 type;
#endif
  u32 lif;	/* Local interface ID */
  u32 nif;	/* Neighbor interface ID */
  u32 id;	/* Neighbor router ID */
};


struct ospf_lsa_net
{
  u32 optx;	/* Netmask for OSPFv2, options for OSPFv3 */
  u32 routers[];
};

struct ospf_lsa_sum2
{
  u32 netmask;
  u32 metric;
};

struct ospf_lsa_sum3_net
{
  u32 metric;
  u32 prefix[];
};

struct ospf_lsa_sum3_rt
{
  u32 options;
  u32 metric;
  u32 drid;
};

struct ospf_lsa_ext2
{
  u32 netmask;
  u32 metric;
  u32 fwaddr;
  u32 tag;
};

struct ospf_lsa_ext3
{
  u32 metric;
  u32 rest[];
};

struct ospf_lsa_ext_local
{
  net_addr net;
  ip_addr fwaddr;
  u32 metric, ebit, fbit, tag, propagate, downwards;
  u8 pxopts;
};

struct ospf_lsa_link
{
  u32 options;
  ip6_addr lladdr;
  u32 pxcount;
  u32 rest[];
};

struct ospf_lsa_prefix
{
#ifdef CPU_BIG_ENDIAN
  u16 pxcount;
  u16 ref_type;
#else
  u16 ref_type;
  u16 pxcount;
#endif
  u32 ref_id;
  u32 ref_rt;
  u32 rest[];
};

struct ospf_tlv
{
#ifdef CPU_BIG_ENDIAN
  u16 type;
  u16 length;
#else
  u16 length;
  u16 type;
#endif
  u32 data[];
};


static inline uint
lsa_net_count(struct ospf_lsa_header *lsa)
{
  return (lsa->length - sizeof(struct ospf_lsa_header) - sizeof(struct ospf_lsa_net))
    / sizeof(u32);
}

/* In ospf_area->rtr we store paths to routers, but we use RID (and not IP address)
   as index, so we need to encapsulate RID to IP address */

#define net_from_rid(x) NET_ADDR_IP4(ip4_from_u32(x), IP4_MAX_PREFIX_LENGTH)
#define rid_from_net(x) ip4_to_u32(((net_addr_ip4 *) x)->prefix)

#define IPV6_PREFIX_SPACE(x) ((((x) + 63) / 32) * 4)
#define IPV6_PREFIX_WORDS(x) (((x) + 63) / 32)


static inline int
ospf_valid_prefix(net_addr *n)
{
  /*
   * In OSPFv2, prefix is stored as netmask; ip4_masklen() returns 255 for
   * invalid one. But OSPFv3-AF may receive IPv4 net with 32 < pxlen < 128.
   */
  uint max = (n->type == NET_IP4) ? IP4_MAX_PREFIX_LENGTH : IP6_MAX_PREFIX_LENGTH;
  return n->pxlen <= max;
}

/*
 * In OSPFv3-AF (RFC 5835), IPv4 address is encoded by just placing it in the
 * first 32 bits of IPv6 address and setting remaining bits to zero. Likewise
 * for IPv4 prefix, where remaining bits do not matter. We use following
 * functions to convert between IPv4 and IPv4-in-IPv6 representations:
 */

static inline ip4_addr ospf3_6to4(ip6_addr a)
{ return _MI4(_I0(a)); }

static inline ip6_addr ospf3_4to6(ip4_addr a)
{ return _MI6(_I(a), 0, 0, 0); }


static inline u32 *
ospf3_get_prefix(u32 *buf, int af, net_addr *n, u8 *pxopts, u16 *rest)
{
  ip6_addr px = IP6_NONE;
  uint pxlen = (*buf >> 24);
  *pxopts = (*buf >> 16) & 0xff;
  if (rest) *rest = *buf & 0xffff;
  buf++;

  if (pxlen > 0)
    _I0(px) = *buf++;
  if (pxlen > 32)
    _I1(px) = *buf++;
  if (pxlen > 64)
    _I2(px) = *buf++;
  if (pxlen > 96)
    _I3(px) = *buf++;

  /* Clean up remaining bits */
  if (pxlen < 128)
    px.addr[pxlen / 32] &= u32_mkmask(pxlen % 32);

  if (af == NET_IP4)
    net_fill_ip4(n, ospf3_6to4(px), pxlen);
  else
    net_fill_ip6(n, px, pxlen);

  return buf;
}

static inline u32 *
ospf3_put_prefix(u32 *buf, net_addr *n, u8 pxopts, u16 rest)
{
  ip6_addr px = (n->type == NET_IP4) ? ospf3_4to6(net4_prefix(n)) : net6_prefix(n);
  uint pxlen = n->pxlen;

  *buf++ = ((pxlen << 24) | (pxopts << 16) | rest);

  if (pxlen > 0)
    *buf++ = _I0(px);
  if (pxlen > 32)
    *buf++ = _I1(px);
  if (pxlen > 64)
    *buf++ = _I2(px);
  if (pxlen > 96)
    *buf++ = _I3(px);

  return buf;
}

static inline u32 *
ospf3_get_addr(u32 *buf, int af, ip_addr *addr)
{
  ip6_addr a;
  memcpy(&a, buf, 16);
  *addr = (af == NET_IP4) ? ipa_from_ip4(ospf3_6to4(a)) : ipa_from_ip6(a);
  return buf + 4;
}

static inline u32 *
ospf3_put_addr(u32 *buf, ip_addr addr)
{
  ip6_addr a = ipa_is_ip4(addr) ? ospf3_4to6(ipa_to_ip4(addr)) : ipa_to_ip6(addr);
  memcpy(buf, &a, 16);
  return buf + 4;
}


struct ospf_lsreq_header
{
  u32 type;
  u32 id;
  u32 rt;
};



#define SH_ROUTER_SELF 0xffffffff

struct lsadb_show_data {
  struct ospf_proto *proto;	/* Protocol to request data from */
  u16 type;		/* LSA Type, 0 -> all */
  u16 scope;		/* Scope, 0 -> all, hack to handle link scope as 1 */
  u32 area;		/* Specified for area scope */
  u32 lsid;		/* LSA ID, 0 -> all */
  u32 router;		/* Advertising router, 0 -> all */
};


#define EA_OSPF_METRIC1	EA_CODE(PROTOCOL_OSPF, 0)
#define EA_OSPF_METRIC2	EA_CODE(PROTOCOL_OSPF, 1)
#define EA_OSPF_TAG	EA_CODE(PROTOCOL_OSPF, 2)
#define EA_OSPF_ROUTER_ID EA_CODE(PROTOCOL_OSPF, 3)


/* ospf.c */
void ospf_schedule_rtcalc(struct ospf_proto *p);

static inline void ospf_notify_rt_lsa(struct ospf_area *oa)
{ oa->update_rt_lsa = 1; }

static inline void ospf_notify_net_lsa(struct ospf_iface *ifa)
{ ifa->update_net_lsa = 1; }

static inline void ospf_notify_link_lsa(struct ospf_iface *ifa)
{ ifa->update_link_lsa = 1; }

static inline int ospf_is_v2(struct ospf_proto *p)
{ return p->ospf2; }

static inline int ospf_is_v3(struct ospf_proto *p)
{ return ! p->ospf2; }

static inline int ospf_get_version(struct ospf_proto *p)
{ return ospf_is_v2(p) ? 2 : 3; }

static inline int ospf_is_ip4(struct ospf_proto *p)
{ return p->p.net_type == NET_IP4; }

static inline int ospf_is_ip6(struct ospf_proto *p)
{ return p->p.net_type == NET_IP6; }

static inline int ospf_get_af(struct ospf_proto *p)
{ return p->p.net_type; }

struct ospf_area *ospf_find_area(struct ospf_proto *p, u32 aid);

static inline struct ospf_area *ospf_main_area(struct ospf_proto *p)
{ return (p->areano == 1) ? HEAD(p->area_list) : p->backbone; }

static inline int oa_is_stub(struct ospf_area *oa)
{ return (oa->options & (OPT_E | OPT_N)) == 0; }

static inline int oa_is_ext(struct ospf_area *oa)
{ return oa->options & OPT_E; }

static inline int oa_is_nssa(struct ospf_area *oa)
{ return oa->options & OPT_N; }

void ospf_stop_gr_recovery(struct ospf_proto *p);

void ospf_sh_neigh(struct proto *P, const char *iff);
void ospf_sh(struct proto *P);
void ospf_sh_iface(struct proto *P, const char *iff);
void ospf_sh_state(struct proto *P, int verbose, int reachable);

void ospf_sh_lsadb(struct lsadb_show_data *ld);

/* iface.c */
void ospf_iface_chstate(struct ospf_iface *ifa, u8 state);
void ospf_iface_sm(struct ospf_iface *ifa, int event);
struct ospf_iface *ospf_iface_find(struct ospf_proto *p, struct iface *what);
void ospf_if_notify(struct proto *P, uint flags, struct iface *iface);
void ospf_ifa_notify2(struct proto *P, uint flags, struct ifa *a);
void ospf_ifa_notify3(struct proto *P, uint flags, struct ifa *a);
void ospf_iface_info(struct ospf_iface *ifa);
void ospf_iface_new(struct ospf_area *oa, struct ifa *addr, struct ospf_iface_patt *ip);
void ospf_iface_new_vlink(struct ospf_proto *p, struct ospf_iface_patt *ip);
void ospf_iface_remove(struct ospf_iface *ifa);
void ospf_iface_shutdown(struct ospf_iface *ifa);
int ospf_iface_assure_bufsize(struct ospf_iface *ifa, uint plen);
int ospf_iface_reconfigure(struct ospf_iface *ifa, struct ospf_iface_patt *new);
void ospf_reconfigure_ifaces(struct ospf_proto *p);
void ospf_open_vlink_sk(struct ospf_proto *p);
struct nbma_node *find_nbma_node_(list *nnl, ip_addr ip);

static inline struct nbma_node * find_nbma_node(struct ospf_iface *ifa, ip_addr ip)
{ return find_nbma_node_(&ifa->nbma_list, ip); }

static inline u32 ospf_iface_get_data(struct ospf_iface *ifa)
{
  /*
   * Return expected value of the link data field in Rt-LSA for given iface.
   * It should be ifa->iface_id for unnumbered PtP links, IP address otherwise
   * (see RFC 2328 12.4.1.1). It is controlled by ifa->ptp_address field so it
   * can be overriden for compatibility purposes.
   */

  return ((ifa->type == OSPF_IT_PTP) && !ifa->ptp_address) ?
    ifa->iface_id :
    ipa_to_u32(ifa->addr->ip);
}

/* neighbor.c */
struct ospf_neighbor *ospf_neighbor_new(struct ospf_iface *ifa);
void ospf_neigh_sm(struct ospf_neighbor *n, int event);
void ospf_neigh_cancel_graceful_restart(struct ospf_neighbor *n);
void ospf_neigh_notify_grace_lsa(struct ospf_neighbor *n, struct top_hash_entry *en);
void ospf_neigh_lsadb_changed_(struct ospf_proto *p, struct top_hash_entry *en);
void ospf_dr_election(struct ospf_iface *ifa);
struct ospf_neighbor *find_neigh(struct ospf_iface *ifa, u32 rid);
struct ospf_neighbor *find_neigh_by_ip(struct ospf_iface *ifa, ip_addr ip);
void ospf_neigh_update_bfd(struct ospf_neighbor *n, int use_bfd);
void ospf_sh_neigh_info(struct ospf_neighbor *n);

static inline void ospf_neigh_lsadb_changed(struct ospf_proto *p, struct top_hash_entry *en)
{ if (p->gr_count) ospf_neigh_lsadb_changed_(p, en); }

/* packet.c */
void ospf_pkt_fill_hdr(struct ospf_iface *ifa, void *buf, u8 h_type);
int ospf_rx_hook(sock * sk, uint size);
// void ospf_tx_hook(sock * sk);
void ospf_err_hook(sock * sk, int err);
void ospf_verr_hook(sock *sk, int err);
void ospf_send_to(struct ospf_iface *ifa, ip_addr ip);
void ospf_send_to_agt(struct ospf_iface *ifa, u8 state);
void ospf_send_to_bdr(struct ospf_iface *ifa);

static inline uint ospf_pkt_maxsize(struct ospf_iface *ifa)
{ return ifa->tx_length - ifa->tx_hdrlen; }

static inline void ospf_send_to_all(struct ospf_iface *ifa)
{ ospf_send_to(ifa, ifa->all_routers); }

static inline void ospf_send_to_des(struct ospf_iface *ifa)
{
  if (ipa_nonzero(ifa->des_routers))
    ospf_send_to(ifa, ifa->des_routers);
  else
    ospf_send_to_bdr(ifa);
}

#ifndef PARSER
#define DROP(DSC,VAL) do { err_dsc = DSC; err_val = VAL; goto drop; } while(0)
#define DROP1(DSC) do { err_dsc = DSC; goto drop; } while(0)
#define SKIP(DSC) do { err_dsc = DSC; goto skip; } while(0)
#endif

static inline uint ospf_pkt_hdrlen(struct ospf_proto *p)
{ return ospf_is_v2(p) ? (sizeof(struct ospf_packet) + sizeof(union ospf_auth2)) : sizeof(struct ospf_packet); }

static inline void * ospf_tx_buffer(struct ospf_iface *ifa)
{ return ifa->sk->tbuf; }

/* hello.c */
#define OHS_HELLO    0
#define OHS_POLL     1
#define OHS_SHUTDOWN 2

void ospf_send_hello(struct ospf_iface *ifa, int kind, struct ospf_neighbor *dirn);
void ospf_receive_hello(struct ospf_packet *pkt, struct ospf_iface *ifa, struct ospf_neighbor *n, ip_addr faddr);
uint ospf_hello3_options(struct ospf_packet *pkt);

/* dbdes.c */
void ospf_send_dbdes(struct ospf_proto *p, struct ospf_neighbor *n);
void ospf_rxmt_dbdes(struct ospf_proto *p, struct ospf_neighbor *n);
void ospf_reset_ldd(struct ospf_proto *p, struct ospf_neighbor *n);
void ospf_receive_dbdes(struct ospf_packet *pkt, struct ospf_iface *ifa, struct ospf_neighbor *n);
uint ospf_dbdes3_options(struct ospf_packet *pkt);

/* lsreq.c */
void ospf_send_lsreq(struct ospf_proto *p, struct ospf_neighbor *n);
void ospf_receive_lsreq(struct ospf_packet *pkt, struct ospf_iface *ifa, struct ospf_neighbor *n);

/* lsupd.c */
void ospf_dump_lsahdr(struct ospf_proto *p, struct ospf_lsa_header *lsa_n);
void ospf_dump_common(struct ospf_proto *p, struct ospf_packet *pkt);
void ospf_lsa_lsrt_down_(struct top_hash_entry *en, struct ospf_neighbor *n, struct top_hash_entry *ret);
void ospf_add_flushed_to_lsrt(struct ospf_proto *p, struct ospf_neighbor *n);
void ospf_flood_event(void *ptr);
int ospf_flood_lsa(struct ospf_proto *p, struct top_hash_entry *en, struct ospf_neighbor *from);
int ospf_send_lsupd(struct ospf_proto *p, struct top_hash_entry **lsa_list, uint lsa_count, struct ospf_neighbor *n);
void ospf_rxmt_lsupd(struct ospf_proto *p, struct ospf_neighbor *n);
void ospf_receive_lsupd(struct ospf_packet *pkt, struct ospf_iface *ifa, struct ospf_neighbor *n);

/* lsack.c */
void ospf_enqueue_lsack(struct ospf_neighbor *n, struct ospf_lsa_header *h_n, int queue);
void ospf_reset_lsack_queue(struct ospf_neighbor *n);
void ospf_send_lsack(struct ospf_proto *p, struct ospf_neighbor *n, int queue);
void ospf_receive_lsack(struct ospf_packet *pkt, struct ospf_iface *ifa, struct ospf_neighbor *n);


#include "proto/ospf/rt.h"
#include "proto/ospf/topology.h"
#include "proto/ospf/lsalib.h"

#endif /* _BIRD_OSPF_H_ */
