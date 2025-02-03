/*
 *	BIRD -- Bidirectional Forwarding Detection (BFD)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_BFD_H_
#define _BIRD_BFD_H_

#include <pthread.h>

#include "nest/bird.h"
#include "nest/cli.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/password.h"
#include "conf/conf.h"
#include "lib/hash.h"
#include "lib/io-loop.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/string.h"
#include "lib/tlists.h"

#include "nest/bfd.h"


#define BFD_CONTROL_PORT	3784
#define BFD_ECHO_PORT		3785
#define BFD_MULTI_CTL_PORT	4784

#define BFD_DEFAULT_MIN_RX_INT	(10 MS_)
#define BFD_DEFAULT_MIN_TX_INT	(100 MS_)
#define BFD_DEFAULT_IDLE_TX_INT	(1 S_)
#define BFD_DEFAULT_MULTIPLIER	5

struct bfd_iface_config
{
  struct iface_patt i;			/* contains list node (!) */
  struct bfd_options opts;
};

#define TLIST_PREFIX bfd_neighbor
#define TLIST_TYPE struct bfd_neighbor
#define TLIST_ITEM n
#define TLIST_WANT_ADD_TAIL
struct bfd_neighbor
{
  TLIST_DEFAULT_NODE;
  ip_addr addr;
  ip_addr local;
  struct iface *iface;

  struct neighbor *neigh;
  struct bfd_request_ref *req;

  callback notify;

  u8 multihop;
  u8 active;
};
#include "lib/tlists.h"

struct bfd_config
{
  struct proto_config c;
  struct thread_group_config *express_thread_group;
  list patt_list;	/* List of iface configs (struct bfd_iface_config) */
  TLIST_LIST(bfd_neighbor) neigh_list;		/* List of configured neighbors */
  struct bfd_iface_config *multihop; /* Multihop pseudoiface config */
  u8 accept_ipv4;
  u8 accept_ipv6;
  u8 accept_direct;
  u8 accept_multihop;
  u8 strict_bind;
  u8 zero_udp6_checksum_rx;
};


struct bfd_proto
{
  struct proto p;

  pthread_spinlock_t lock;

  pool *tpool;

  struct birdloop *eloop;

  TLIST_NODE(bfd_proto, struct bfd_proto) bfd_node;

  slab *session_slab;
  HASH(struct bfd_session) session_hash_id;
  HASH(struct bfd_session) session_hash_ip;

  callback pickup;
  callback cleanup;

  sock *rx4_1;
  sock *rx6_1;
  sock *rx4_m;
  sock *rx6_m;
  list iface_list;
};

#define TLIST_PREFIX bfd_proto
#define TLIST_TYPE struct bfd_proto
#define TLIST_ITEM bfd_node
#define TLIST_WANT_ADD_TAIL
#include "lib/tlists.h"

struct bfd_iface
{
  node n;
  ip_addr local;
  struct iface *iface;
  struct bfd_iface_config *cf;
  struct bfd_proto *bfd;

  sock *sk;
  sock *rx;
  u32 uc;
  u8 changed;
};

struct bfd_session
{
  node n;
  ip_addr addr;				/* Address of session */
  struct bfd_iface *ifa;		/* Iface associated with session */
  struct bfd_session *next_id;		/* Next in bfd.session_hash_id */
  struct bfd_session *next_ip;		/* Next in bfd.session_hash_ip */

  u8 opened_unused;
  u8 passive;
  u8 poll_active;
  u8 poll_scheduled;

  struct bfd_state_pair _Atomic state;
  u32 loc_id;				/* Local session ID (local discriminator) */
  u32 rem_id;				/* Remote session ID (remote discriminator) */

  struct bfd_options cf;		/* Static configuration parameters */

  u32 des_min_tx_int;			/* Desired min rx interval, local option */
  u32 des_min_tx_new;			/* Used for des_min_tx_int change */
  u32 req_min_rx_int;			/* Required min tx interval, local option */
  u32 req_min_rx_new;			/* Used for req_min_rx_int change */
  u32 rem_min_tx_int;			/* Last received des_min_tx_int */
  u32 rem_min_rx_int;			/* Last received req_min_rx_int */
  u8 demand_mode;			/* Currently unused */
  u8 rem_demand_mode;
  u8 detect_mult;			/* Announced detect_mult, local option */
  u8 rem_detect_mult;			/* Last received detect_mult */

  uint ifindex;				/* Iface index, for hashing in bfd.session_hash_ip */
  btime last_tx;			/* Time of last sent periodic control packet */
  btime last_rx;			/* Time of last received valid control packet */

  timer *tx_timer;			/* Periodic control packet timer */
  timer *hold_timer;			/* Timer for session down detection time */

  TLIST_LIST(bfd_request) request_list;	/* List of client requests (struct bfd_request) */
  _Atomic btime last_state_change;	/* Time of last state change */

  callback notify;			/* Sent to the main protocol loop */

  u8 rx_csn_known;			/* Received crypto sequence number is known */
  u32 rx_csn;				/* Last received crypto sequence number */
  u32 tx_csn;				/* Last transmitted crypto sequence number */
  u32 tx_csn_time;			/* Timestamp of last tx_csn change */
};

struct bfd_show_sessions_cmd {
  net_addr address;
  struct iface *iface;
  struct symbol *name;
  u8 verbose;
  u8 ipv4;
  u8 ipv6;
  u8 direct;
  u8 multihop;
};


extern const char *bfd_state_names[];

#define BFD_STATE_ADMIN_DOWN	0
#define BFD_STATE_DOWN		1
#define BFD_STATE_INIT		2
#define BFD_STATE_UP		3

#define BFD_DIAG_NOTHING	0
#define BFD_DIAG_TIMEOUT	1
#define BFD_DIAG_ECHO_FAILED	2
#define BFD_DIAG_NEIGHBOR_DOWN	3
#define BFD_DIAG_FWD_RESET	4
#define BFD_DIAG_PATH_DOWN	5
#define BFD_DIAG_C_PATH_DOWN	6
#define BFD_DIAG_ADMIN_DOWN	7
#define BFD_DIAG_RC_PATH_DOWN	8

#define BFD_POLL_TX		1
#define BFD_POLL_RX		2

#define BFD_FLAGS		0x3f
#define BFD_FLAG_POLL		(1 << 5)
#define BFD_FLAG_FINAL		(1 << 4)
#define BFD_FLAG_CPI		(1 << 3)
#define BFD_FLAG_AP		(1 << 2)
#define BFD_FLAG_DEMAND		(1 << 1)
#define BFD_FLAG_MULTIPOINT	(1 << 0)

#define BFD_AUTH_NONE			0
#define BFD_AUTH_SIMPLE			1
#define BFD_AUTH_KEYED_MD5		2
#define BFD_AUTH_METICULOUS_KEYED_MD5	3
#define BFD_AUTH_KEYED_SHA1		4
#define BFD_AUTH_METICULOUS_KEYED_SHA1	5

extern const u8 bfd_auth_type_to_hash_alg[];

/* bfd.c */
struct bfd_session * bfd_find_session_by_id(struct bfd_proto *p, u32 id);
struct bfd_session * bfd_find_session_by_addr(struct bfd_proto *p, ip_addr addr, uint ifindex);
void bfd_session_process_ctl(struct bfd_session *s, struct bfd_state_pair sp, u8 flags, u32 old_tx_int, u32 old_rx_int);
void bfd_show_sessions(struct proto *P, struct bfd_show_sessions_cmd *args);
void bfd_neighbor_notify(callback *);

/* packets.c */
void bfd_send_ctl(struct bfd_proto *p, struct bfd_session *s, int final);
sock * bfd_open_rx_sk(struct bfd_proto *p, int multihop, int inet_version);
sock * bfd_open_rx_sk_bound(struct bfd_proto *p, ip_addr local, struct iface *ifa);
sock * bfd_open_tx_sk(struct bfd_proto *p, ip_addr local, struct iface *ifa);


#endif /* _BIRD_BFD_H_ */
