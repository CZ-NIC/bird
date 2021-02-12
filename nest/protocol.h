/*
 *	BIRD Internet Routing Daemon -- Protocols
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_PROTOCOL_H_
#define _BIRD_PROTOCOL_H_

#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/event.h"
#include "nest/route.h"
#include "conf/conf.h"

struct iface;
struct ifa;
struct rtable;
struct rte;
struct neighbor;
struct rta;
struct network;
struct proto_config;
struct channel_limit;
struct channel_config;
struct config;
struct proto;
struct channel;
struct ea_list;
struct eattr;
struct symbol;


/*
 *	Routing Protocol
 */

enum protocol_class {
  PROTOCOL_NONE,
  PROTOCOL_BABEL,
  PROTOCOL_BFD,
  PROTOCOL_BGP,
  PROTOCOL_DEVICE,
  PROTOCOL_DIRECT,
  PROTOCOL_KERNEL,
  PROTOCOL_OSPF,
  PROTOCOL_MRT,
  PROTOCOL_PERF,
  PROTOCOL_PIPE,
  PROTOCOL_RADV,
  PROTOCOL_RIP,
  PROTOCOL_RPKI,
  PROTOCOL_STATIC,
  PROTOCOL__MAX
};

extern struct protocol *class_to_protocol[PROTOCOL__MAX];

struct protocol {
  node n;
  char *name;
  char *template;			/* Template for automatic generation of names */
  int name_counter;			/* Counter for automatic name generation */
  enum protocol_class class;		/* Machine readable protocol class */
  uint preference;			/* Default protocol preference */
  uint channel_mask;			/* Mask of accepted channel types (NB_*) */
  uint proto_size;			/* Size of protocol data structure */
  uint config_size;			/* Size of protocol config data structure */

  void (*preconfig)(struct protocol *, struct config *);	/* Just before configuring */
  void (*postconfig)(struct proto_config *);			/* After configuring each instance */
  struct proto * (*init)(struct proto_config *);		/* Create new instance */
  int (*reconfigure)(struct proto *, struct proto_config *);	/* Try to reconfigure instance, returns success */
  void (*dump)(struct proto *);			/* Debugging dump */
  void (*dump_attrs)(struct rte *);		/* Dump protocol-dependent attributes */
  int (*start)(struct proto *);			/* Start the instance */
  int (*shutdown)(struct proto *);		/* Stop the instance */
  void (*cleanup)(struct proto *);		/* Called after shutdown when protocol became hungry/down */
  void (*get_status)(struct proto *, byte *buf); /* Get instance status (for `show protocols' command) */
  void (*get_route_info)(struct rte *, byte *buf); /* Get route information (for `show route' command) */
  int (*get_attr)(const struct eattr *, byte *buf, int buflen);	/* ASCIIfy dynamic attribute (returns GA_*) */
  void (*show_proto_info)(struct proto *);	/* Show protocol info (for `show protocols all' command) */
  void (*copy_config)(struct proto_config *, struct proto_config *);	/* Copy config from given protocol instance */
};

void protos_build(void);
void proto_build(struct protocol *);
void protos_preconfig(struct config *);
void protos_commit(struct config *new, struct config *old, int force_restart, int type);
struct proto * proto_spawn(struct proto_config *cf, uint disabled);
void protos_dump_all(void);

#define GA_UNKNOWN	0		/* Attribute not recognized */
#define GA_NAME		1		/* Result = name */
#define GA_FULL		2		/* Result = both name and value */

/*
 *	Known protocols
 */

extern struct protocol
  proto_device, proto_radv, proto_rip, proto_static, proto_mrt,
  proto_ospf, proto_perf,
  proto_pipe, proto_bgp, proto_bfd, proto_babel, proto_rpki;

/*
 *	Routing Protocol Instance
 */

struct proto_config {
  node n;
  struct config *global;		/* Global configuration data */
  struct protocol *protocol;		/* Protocol */
  struct proto *proto;			/* Instance we've created */
  struct proto_config *parent;		/* Parent proto_config for dynamic protocols */
  const char *name;
  const char *dsc;
  int class;				/* SYM_PROTO or SYM_TEMPLATE */
  u8 net_type;				/* Protocol network type (NET_*), 0 for undefined */
  u8 disabled;				/* Protocol enabled/disabled by default */
  u8 vrf_set;				/* Related VRF instance (below) is defined */
  u32 debug, mrtdump;			/* Debugging bitfields, both use D_* constants */
  u32 router_id;			/* Protocol specific router ID */

  list channels;			/* List of channel configs (struct channel_config) */
  struct iface *vrf;			/* Related VRF instance, NULL if global */

  /* Check proto_reconfigure() and proto_copy_config() after changing struct proto_config */

  /* Protocol-specific data follow... */
};

/* Protocol statistics */
struct proto_stats {
  /* Import - from protocol to core */
  u32 imp_routes;		/* Number of routes successfully imported to the (adjacent) routing table */
  u32 filt_routes;		/* Number of routes rejected in import filter but kept in the routing table */
  u32 pref_routes;		/* Number of routes selected as best in the (adjacent) routing table */
  u32 imp_updates_received;	/* Number of route updates received */
  u32 imp_updates_invalid;	/* Number of route updates rejected as invalid */
  u32 imp_updates_filtered;	/* Number of route updates rejected by filters */
  u32 imp_updates_ignored;	/* Number of route updates rejected as already in route table */
  u32 imp_updates_accepted;	/* Number of route updates accepted and imported */
  u32 imp_withdraws_received;	/* Number of route withdraws received */
  u32 imp_withdraws_invalid;	/* Number of route withdraws rejected as invalid */
  u32 imp_withdraws_ignored;	/* Number of route withdraws rejected as already not in route table */
  u32 imp_withdraws_accepted;	/* Number of route withdraws accepted and processed */

  /* Export - from core to protocol */
  u32 exp_routes;		/* Number of routes successfully exported to the protocol */
  u32 exp_updates_received;	/* Number of route updates received */
  u32 exp_updates_rejected;	/* Number of route updates rejected by protocol */
  u32 exp_updates_filtered;	/* Number of route updates rejected by filters */
  u32 exp_updates_accepted;	/* Number of route updates accepted and exported */
  u32 exp_withdraws_received;	/* Number of route withdraws received */
  u32 exp_withdraws_accepted;	/* Number of route withdraws accepted and processed */
};

struct proto {
  node n;				/* Node in global proto_list */
  struct protocol *proto;		/* Protocol */
  struct proto_config *cf;		/* Configuration data */
  struct proto_config *cf_new;		/* Configuration we want to switch to after shutdown (NULL=delete) */
  pool *pool;				/* Pool containing local objects */
  event *event;				/* Protocol event */

  list channels;			/* List of channels to rtables (struct channel) */
  struct channel *main_channel;		/* Primary channel */
  struct rte_src *main_source;		/* Primary route source */
  struct iface *vrf;			/* Related VRF instance, NULL if global */

  const char *name;				/* Name of this instance (== cf->name) */
  u32 debug;				/* Debugging flags */
  u32 mrtdump;				/* MRTDump flags */
  uint active_channels;			/* Number of active channels */
  byte net_type;			/* Protocol network type (NET_*), 0 for undefined */
  byte disabled;			/* Manually disabled */
  byte vrf_set;				/* Related VRF instance (above) is defined */
  byte proto_state;			/* Protocol state machine (PS_*, see below) */
  byte active;				/* From PS_START to cleanup after PS_STOP */
  byte do_start;			/* Start actions are scheduled */
  byte do_stop;				/* Stop actions are scheduled */
  byte reconfiguring;			/* We're shutting down due to reconfiguration */
  byte gr_recovery;			/* Protocol should participate in graceful restart recovery */
  byte down_sched;			/* Shutdown is scheduled for later (PDS_*) */
  byte down_code;			/* Reason for shutdown (PDC_* codes) */
  u32 hash_key;				/* Random key used for hashing of neighbors */
  btime last_state_change;		/* Time of last state transition */
  char *last_state_name_announced;	/* Last state name we've announced to the user */
  char *message;			/* State-change message, allocated from proto_pool */

  /*
   *	General protocol hooks:
   *
   *	   if_notify	Notify protocol about interface state changes.
   *	   ifa_notify	Notify protocol about interface address changes.
   *	   rt_notify	Notify protocol about routing table updates.
   *	   neigh_notify	Notify protocol about neighbor cache events.
   *	   make_tmp_attrs  Add attributes to rta from from private attrs stored in rte. The route and rta MUST NOT be cached.
   *	   store_tmp_attrs Store private attrs back to rte and undef added attributes. The route and rta MUST NOT be cached.
   *	   preexport  Called as the first step of the route exporting process.
   *			It can construct a new rte, add private attributes and
   *			decide whether the route shall be exported: 1=yes, -1=no,
   *			0=process it through the export filter set by the user.
   *	   reload_routes   Request channel to reload all its routes to the core
   *			(using rte_update()). Returns: 0=reload cannot be done,
   *			1= reload is scheduled and will happen (asynchronously).
   *	   feed_begin	Notify channel about beginning of route feeding.
   *	   feed_end	Notify channel about finish of route feeding.
   */

  void (*if_notify)(struct proto *, unsigned flags, struct iface *i);
  void (*ifa_notify)(struct proto *, unsigned flags, struct ifa *a);
  void (*rt_notify)(struct proto *, struct channel *, struct network *net, struct rte *new, struct rte *old);
  void (*neigh_notify)(struct neighbor *neigh);
  void (*make_tmp_attrs)(struct rte *rt, struct linpool *pool);
  void (*store_tmp_attrs)(struct rte *rt, struct linpool *pool);
  int (*preexport)(struct proto *, struct rte **rt, struct linpool *pool);
  void (*reload_routes)(struct channel *);
  void (*feed_begin)(struct channel *, int initial);
  void (*feed_end)(struct channel *);

  /*
   *	Routing entry hooks (called only for routes belonging to this protocol):
   *
   *	   rte_recalculate Called at the beginning of the best route selection
   *	   rte_better	Compare two rte's and decide which one is better (1=first, 0=second).
   *       rte_same	Compare two rte's and decide whether they are identical (1=yes, 0=no).
   *       rte_mergable	Compare two rte's and decide whether they could be merged (1=yes, 0=no).
   *	   rte_insert	Called whenever a rte is inserted to a routing table.
   *	   rte_remove	Called whenever a rte is removed from the routing table.
   */

  int (*rte_recalculate)(struct rtable *, struct network *, struct rte *, struct rte *, struct rte *);
  int (*rte_better)(struct rte *, struct rte *);
  int (*rte_same)(struct rte *, struct rte *);
  int (*rte_mergable)(struct rte *, struct rte *);
  struct rte * (*rte_modify)(struct rte *, struct linpool *);
  void (*rte_insert)(struct network *, struct rte *);
  void (*rte_remove)(struct network *, struct rte *);

  /* Hic sunt protocol-specific data */
};

struct proto_spec {
  const void *ptr;
  int patt;
};


#define PDS_DISABLE		1	/* Proto disable scheduled */
#define PDS_RESTART		2	/* Proto restart scheduled */

#define PDC_CF_REMOVE		0x01	/* Removed in new config */
#define PDC_CF_DISABLE		0x02	/* Disabled in new config */
#define PDC_CF_RESTART		0x03	/* Restart due to reconfiguration */
#define PDC_CMD_DISABLE		0x11	/* Result of disable command */
#define PDC_CMD_RESTART		0x12	/* Result of restart command */
#define PDC_CMD_SHUTDOWN	0x13	/* Result of global shutdown */
#define PDC_CMD_GR_DOWN		0x14	/* Result of global graceful restart */
#define PDC_RX_LIMIT_HIT	0x21	/* Route receive limit reached */
#define PDC_IN_LIMIT_HIT	0x22	/* Route import limit reached */
#define PDC_OUT_LIMIT_HIT	0x23	/* Route export limit reached */


void *proto_new(struct proto_config *);
void *proto_config_new(struct protocol *, int class);
void proto_copy_config(struct proto_config *dest, struct proto_config *src);
void proto_clone_config(struct symbol *sym, struct proto_config *parent);
void proto_set_message(struct proto *p, char *msg, int len);

void graceful_restart_recovery(void);
void graceful_restart_init(void);
void graceful_restart_show_status(void);
void channel_graceful_restart_lock(struct channel *c);
void channel_graceful_restart_unlock(struct channel *c);

#define DEFAULT_GR_WAIT	240

void channel_show_limit(struct channel_limit *l, const char *dsc);
void channel_show_info(struct channel *c);
void channel_cmd_debug(struct channel *c, uint mask);

void proto_cmd_show(struct proto *, uintptr_t, int);
void proto_cmd_disable(struct proto *, uintptr_t, int);
void proto_cmd_enable(struct proto *, uintptr_t, int);
void proto_cmd_restart(struct proto *, uintptr_t, int);
void proto_cmd_reload(struct proto *, uintptr_t, int);
void proto_cmd_debug(struct proto *, uintptr_t, int);
void proto_cmd_mrtdump(struct proto *, uintptr_t, int);

void proto_apply_cmd(struct proto_spec ps, void (* cmd)(struct proto *, uintptr_t, int), int restricted, uintptr_t arg);
struct proto *proto_get_named(struct symbol *, struct protocol *);
struct proto *proto_iterate_named(struct symbol *sym, struct protocol *proto, struct proto *old);

#define PROTO_WALK_CMD(sym,pr,p) for(struct proto *p = NULL; p = proto_iterate_named(sym, pr, p); )


#define CMD_RELOAD	0
#define CMD_RELOAD_IN	1
#define CMD_RELOAD_OUT	2

static inline u32
proto_get_router_id(struct proto_config *pc)
{
  return pc->router_id ? pc->router_id : pc->global->router_id;
}


extern pool *proto_pool;
extern list proto_list;

/*
 *  Each protocol instance runs two different state machines:
 *
 *  [P] The protocol machine: (implemented inside protocol)
 *
 *		DOWN    ---->    START
 *		  ^		   |
 *		  |		   V
 *		STOP    <----     UP
 *
 *	States:	DOWN	Protocol is down and it's waiting for the core
 *			requesting protocol start.
 *		START	Protocol is waiting for connection with the rest
 *			of the network and it's not willing to accept
 *			packets. When it connects, it goes to UP state.
 *		UP	Protocol is up and running. When the network
 *			connection breaks down or the core requests
 *			protocol to be terminated, it goes to STOP state.
 *		STOP	Protocol is disconnecting from the network.
 *			After it disconnects, it returns to DOWN state.
 *
 *	In:	start()	Called in DOWN state to request protocol startup.
 *			Returns new state: either UP or START (in this
 *			case, the protocol will notify the core when it
 *			finally comes UP).
 *		stop()	Called in START, UP or STOP state to request
 *			protocol shutdown. Returns new state: either
 *			DOWN or STOP (in this case, the protocol will
 *			notify the core when it finally comes DOWN).
 *
 *	Out:	proto_notify_state() -- called by protocol instance when
 *			it does any state transition not covered by
 *			return values of start() and stop(). This includes
 *			START->UP (delayed protocol startup), UP->STOP
 *			(spontaneous shutdown) and STOP->DOWN (delayed
 *			shutdown).
 */

#define PS_DOWN 0
#define PS_START 1
#define PS_UP 2
#define PS_STOP 3

void proto_notify_state(struct proto *p, unsigned state);

/*
 *  [F] The feeder machine: (implemented in core routines)
 *
 *		HUNGRY    ---->   FEEDING
 *		 ^		     |
 *		 |		     V
 *		FLUSHING  <----   HAPPY
 *
 *	States:	HUNGRY	Protocol either administratively down (i.e.,
 *			disabled by the user) or temporarily down
 *			(i.e., [P] is not UP)
 *		FEEDING	The protocol came up and we're feeding it
 *			initial routes. [P] is UP.
 *		HAPPY	The protocol is up and it's receiving normal
 *			routing updates. [P] is UP.
 *		FLUSHING The protocol is down and we're removing its
 *			routes from the table. [P] is STOP or DOWN.
 *
 *	Normal lifecycle of a protocol looks like:
 *
 *		HUNGRY/DOWN --> HUNGRY/START --> HUNGRY/UP -->
 *		FEEDING/UP --> HAPPY/UP --> FLUSHING/STOP|DOWN -->
 *		HUNGRY/STOP|DOWN --> HUNGRY/DOWN
 *
 *	Sometimes, protocol might switch from HAPPY/UP to FEEDING/UP
 *	if it wants to refeed the routes (for example BGP does so
 *	as a result of received ROUTE-REFRESH request).
 */



/*
 *	Debugging flags
 */

#define D_STATES 1		/* [core] State transitions */
#define D_ROUTES 2		/* [core] Routes passed by the filters */
#define D_FILTERS 4		/* [core] Routes rejected by the filters */
#define D_IFACES 8		/* [core] Interface events */
#define D_EVENTS 16		/* Protocol events */
#define D_PACKETS 32		/* Packets sent/received */

#ifndef PARSER
#define TRACE(flags, msg, args...) \
  do { if (p->p.debug & flags) log(L_TRACE "%s: " msg, p->p.name , ## args ); } while(0)
#endif


/*
 *	MRTDump flags
 */

#define MD_STATES	1		/* Protocol state changes (BGP4MP_MESSAGE_AS4) */
#define MD_MESSAGES	2		/* Protocol packets (BGP4MP_MESSAGE_AS4) */

/*
 *	Known unique protocol instances as referenced by config routines
 */

extern struct proto_config *cf_dev_proto;


/*
 * Protocol limits
 */

#define PLD_RX		0	/* Receive limit */
#define PLD_IN		1	/* Import limit */
#define PLD_OUT		2	/* Export limit */
#define PLD_MAX		3

#define PLA_NONE	0	/* No limit */
#define PLA_WARN	1	/* Issue log warning */
#define PLA_BLOCK	2	/* Block new routes */
#define PLA_RESTART	4	/* Force protocol restart */
#define PLA_DISABLE	5	/* Shutdown and disable protocol */

#define PLS_INITIAL	0	/* Initial limit state after protocol start */
#define PLS_ACTIVE	1	/* Limit was hit */
#define PLS_BLOCKED	2	/* Limit is active and blocking new routes */

struct channel_limit {
  u32 limit;			/* Maximum number of prefixes */
  u8 action;			/* Action to take (PLA_*) */
  u8 state;			/* State of limit (PLS_*) */
};

void channel_notify_limit(struct channel *c, struct channel_limit *l, int dir, u32 rt_count);


/*
 *	Channels
 */

struct channel_class {
  uint channel_size;			/* Size of channel data structure */
  uint config_size;			/* Size of channel config data structure */

  void (*init)(struct channel *, struct channel_config *);	/* Create new instance */
  int (*reconfigure)(struct channel *, struct channel_config *, int *import_changed, int *export_changed);	/* Try to reconfigure instance, returns success */
  int (*start)(struct channel *);	/* Start the instance */
  void (*shutdown)(struct channel *);	/* Stop the instance */
  void (*cleanup)(struct channel *);	/* Channel finished flush */

  void (*copy_config)(struct channel_config *, struct channel_config *); /* Copy config from given channel instance */
#if 0
  XXXX;
  void (*preconfig)(struct protocol *, struct config *);	/* Just before configuring */
  void (*postconfig)(struct proto_config *);			/* After configuring each instance */


  void (*dump)(struct proto *);			/* Debugging dump */
  void (*dump_attrs)(struct rte *);		/* Dump protocol-dependent attributes */

  void (*get_status)(struct proto *, byte *buf); /* Get instance status (for `show protocols' command) */
  void (*get_route_info)(struct rte *, byte *buf); /* Get route information (for `show route' command) */
  int (*get_attr)(struct eattr *, byte *buf, int buflen);	/* ASCIIfy dynamic attribute (returns GA_*) */
  void (*show_proto_info)(struct proto *);	/* Show protocol info (for `show protocols all' command) */

#endif
};

extern struct channel_class channel_bgp;

struct channel_config {
  node n;
  const char *name;
  const struct channel_class *channel;

  struct proto_config *parent;		/* Where channel is defined (proto or template) */
  struct rtable_config *table;		/* Table we're attached to */
  const struct filter *in_filter, *out_filter; /* Attached filters */
  struct channel_limit rx_limit;	/* Limit for receiving routes from protocol
					   (relevant when in_keep_filtered is active) */
  struct channel_limit in_limit;	/* Limit for importing routes from protocol */
  struct channel_limit out_limit;	/* Limit for exporting routes to protocol */

  u8 net_type;				/* Routing table network type (NET_*), 0 for undefined */
  u8 ra_mode;				/* Mode of received route advertisements (RA_*) */
  u16 preference;			/* Default route preference */
  u32 debug;				/* Debugging flags (D_*) */
  u8 merge_limit;			/* Maximal number of nexthops for RA_MERGED */
  u8 in_keep_filtered;			/* Routes rejected in import filter are kept */
  u8 rpki_reload;			/* RPKI changes trigger channel reload */
};

struct channel {
  node n;				/* Node in proto->channels */
  node table_node;			/* Node in table->channels */

  const char *name;			/* Channel name (may be NULL) */
  const struct channel_class *channel;
  struct proto *proto;

  struct rtable *table;
  const struct filter *in_filter;	/* Input filter */
  const struct filter *out_filter;	/* Output filter */
  struct bmap export_map;		/* Keeps track which routes passed export filter */
  struct channel_limit rx_limit;	/* Receive limit (for in_keep_filtered) */
  struct channel_limit in_limit;	/* Input limit */
  struct channel_limit out_limit;	/* Output limit */

  struct event *feed_event;		/* Event responsible for feeding */
  struct fib_iterator feed_fit;		/* Routing table iterator used during feeding */
  struct proto_stats stats;		/* Per-channel protocol statistics */
  u32 refeed_count;			/* Number of routes exported during refeed regardless of out_limit */

  u8 net_type;				/* Routing table network type (NET_*), 0 for undefined */
  u8 ra_mode;				/* Mode of received route advertisements (RA_*) */
  u16 preference;			/* Default route preference */
  u32 debug;				/* Debugging flags (D_*) */
  u8 merge_limit;			/* Maximal number of nexthops for RA_MERGED */
  u8 in_keep_filtered;			/* Routes rejected in import filter are kept */
  u8 disabled;
  u8 stale;				/* Used in reconfiguration */

  u8 channel_state;
  u8 export_state;			/* Route export state (ES_*, see below) */
  u8 feed_active;
  u8 flush_active;
  u8 refeeding;				/* We are refeeding (valid only if export_state == ES_FEEDING) */
  u8 reloadable;			/* Hook reload_routes() is allowed on the channel */
  u8 gr_lock;				/* Graceful restart mechanism should wait for this channel */
  u8 gr_wait;				/* Route export to channel is postponed until graceful restart */

  btime last_state_change;		/* Time of last state transition */

  struct rtable *in_table;		/* Internal table for received routes */
  struct event *reload_event;		/* Event responsible for reloading from in_table */
  struct fib_iterator reload_fit;	/* FIB iterator in in_table used during reloading */
  struct rte *reload_next_rte;		/* Route iterator in in_table used during reloading */
  u8 reload_active;			/* Iterator reload_fit is linked */

  u8 reload_pending;			/* Reloading and another reload is scheduled */
  u8 refeed_pending;			/* Refeeding and another refeed is scheduled */
  u8 rpki_reload;			/* RPKI changes trigger channel reload */

  struct rtable *out_table;		/* Internal table for exported routes */

  list roa_subscriptions;		/* List of active ROA table subscriptions based on filters roa_check() */
};


/*
 * Channel states
 *
 * CS_DOWN - The initial and the final state of a channel. There is no route
 * exchange between the protocol and the table. Channel is not counted as
 * active. Channel keeps a ptr to the table, but do not lock the table and is
 * not linked in the table. Generally, new closed channels are created in
 * protocols' init() hooks. The protocol is expected to explicitly activate its
 * channels (by calling channel_init() or channel_open()).
 *
 * CS_START - The channel as a connection between the protocol and the table is
 * initialized (counted as active by the protocol, linked in the table and keeps
 * the table locked), but there is no current route exchange. There still may be
 * routes associated with the channel in the routing table if the channel falls
 * to CS_START from CS_UP. Generally, channels are initialized in protocols'
 * start() hooks when going to PS_START.
 *
 * CS_UP - The channel is initialized and the route exchange is allowed. Note
 * that even in CS_UP state, route export may still be down (ES_DOWN) by the
 * core decision (e.g. waiting for table convergence after graceful restart).
 * I.e., the protocol decides to open the channel but the core decides to start
 * route export. Route import (caused by rte_update() from the protocol) is not
 * restricted by that and is on volition of the protocol. Generally, channels
 * are opened in protocols' start() hooks when going to PS_UP.
 *
 * CS_FLUSHING - The transitional state between initialized channel and closed
 * channel. The channel is still initialized, but no route exchange is allowed.
 * Instead, the associated table is running flush loop to remove routes imported
 * through the channel. After that, the channel changes state to CS_DOWN and
 * is detached from the table (the table is unlocked and the channel is unlinked
 * from it). Unlike other states, the CS_FLUSHING state is not explicitly
 * entered or left by the protocol. A protocol may request to close a channel
 * (by calling channel_close()), which causes the channel to change state to
 * CS_FLUSHING and later to CS_DOWN. Also note that channels are closed
 * automatically by the core when the protocol is going down.
 *
 * Allowed transitions:
 *
 * CS_DOWN	-> CS_START / CS_UP
 * CS_START	-> CS_UP / CS_FLUSHING
 * CS_UP	-> CS_START / CS_FLUSHING
 * CS_FLUSHING	-> CS_DOWN (automatic)
 */

#define CS_DOWN		0
#define CS_START	1
#define CS_UP		2
#define CS_FLUSHING	3

#define ES_DOWN		0
#define ES_FEEDING	1
#define ES_READY	2


struct channel_config *proto_cf_find_channel(struct proto_config *p, uint net_type);
static inline struct channel_config *proto_cf_main_channel(struct proto_config *pc)
{ struct channel_config *cc = HEAD(pc->channels); return NODE_VALID(cc) ? cc : NULL; }

struct channel *proto_find_channel_by_table(struct proto *p, struct rtable *t);
struct channel *proto_find_channel_by_name(struct proto *p, const char *n);
struct channel *proto_add_channel(struct proto *p, struct channel_config *cf);
int proto_configure_channel(struct proto *p, struct channel **c, struct channel_config *cf);

void channel_set_state(struct channel *c, uint state);
void channel_setup_in_table(struct channel *c);
void channel_setup_out_table(struct channel *c);
void channel_schedule_reload(struct channel *c);

static inline void channel_init(struct channel *c) { channel_set_state(c, CS_START); }
static inline void channel_open(struct channel *c) { channel_set_state(c, CS_UP); }
static inline void channel_close(struct channel *c) { channel_set_state(c, CS_FLUSHING); }

void channel_request_feeding(struct channel *c);
void *channel_config_new(const struct channel_class *cc, const char *name, uint net_type, struct proto_config *proto);
void *channel_config_get(const struct channel_class *cc, const char *name, uint net_type, struct proto_config *proto);
int channel_reconfigure(struct channel *c, struct channel_config *cf);


/* Moved from route.h to avoid dependency conflicts */
static inline void rte_update(struct proto *p, const net_addr *n, rte *new) { rte_update2(p->main_channel, n, new, p->main_source); }

static inline void
rte_update3(struct channel *c, const net_addr *n, rte *new, struct rte_src *src)
{
  if (c->in_table && !rte_update_in(c, n, new, src))
    return;

  rte_update2(c, n, new, src);
}


#endif
