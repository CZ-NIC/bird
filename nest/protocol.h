/*
 *	BIRD Internet Routing Daemon -- Protocols
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_PROTOCOL_H_
#define _BIRD_PROTOCOL_H_

#include "lib/tlists.h"
#include "lib/resource.h"
#include "lib/event.h"
#include "nest/iface.h"
#include "lib/settle.h"
#include "nest/rt.h"
#include "nest/limit.h"
#include "conf/conf.h"

struct iface;
struct ifa;
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


struct protocol {
  node n;
  char *name;
  char *template;			/* Template for automatic generation of names */
  int name_counter;			/* Counter for automatic name generation */
  uint preference;			/* Default protocol preference */
  uint channel_mask;			/* Mask of accepted channel types (NB_*) */
  uint proto_size;			/* Size of protocol data structure */
  uint config_size;			/* Size of protocol config data structure */

  uint eattr_begin;			/* First ID of registered eattrs */
  uint eattr_end;			/* End of eattr id zone */

  void (*preconfig)(struct protocol *, struct config *);	/* Just before configuring */
  void (*postconfig)(struct proto_config *);			/* After configuring each instance */
  struct proto * (*init)(struct proto_config *);		/* Create new instance */
  int (*reconfigure)(struct proto *, struct proto_config *);	/* Try to reconfigure instance, returns success */
  void (*dump)(struct proto *);			/* Debugging dump */
  int (*start)(struct proto *);			/* Start the instance */
  int (*shutdown)(struct proto *);		/* Stop the instance */
  void (*cleanup)(struct proto *);		/* Cleanup the instance right before tearing it all down */
  void (*get_status)(struct proto *, byte *buf); /* Get instance status (for `show protocols' command) */
//  int (*get_attr)(const struct eattr *, byte *buf, int buflen);	/* ASCIIfy dynamic attribute (returns GA_*) */
  void (*show_proto_info)(struct proto *);	/* Show protocol info (for `show protocols all' command) */
  void (*copy_config)(struct proto_config *, struct proto_config *);	/* Copy config from given protocol instance */
};

void protos_build(void);		/* Called from sysdep to initialize protocols */
void proto_build(struct protocol *);	/* Called from protocol to register itself */
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
  u8 late_if_feed;			/* Delay interface feed after channels are up */
  u32 debug, mrtdump;			/* Debugging bitfields, both use D_* constants */
  u32 router_id;			/* Protocol specific router ID */
  uint loop_order;			/* Launch a birdloop on this locking level; use DOMAIN_ORDER(the_bird) for mainloop */

  list channels;			/* List of channel configs (struct channel_config) */
  struct iface *vrf;			/* Related VRF instance, NULL if global */

  /* Check proto_reconfigure() and proto_copy_config() after changing struct proto_config */

  /* Protocol-specific data follow... */
};

/* Protocol statistics */
struct proto {
  node n;				/* Node in global proto_list */
  struct protocol *proto;		/* Protocol */
  struct proto_config *cf;		/* Configuration data */
  struct proto_config *cf_new;		/* Configuration we want to switch to after shutdown (NULL=delete) */
  pool *pool;				/* Pool containing local objects */
  event *event;				/* Protocol event */
  timer *restart_timer;			/* Timer to restart the protocol from limits */
  event *restart_event;			/* Event to restart/shutdown the protocol from limits */
  struct birdloop *loop;		/* BIRDloop running this protocol */

  list channels;			/* List of channels to rtables (struct channel) */
  struct channel *main_channel;		/* Primary channel */
  struct rte_src *main_source;		/* Primary route source */
  struct rte_owner sources;		/* Route source owner structure */
  struct iface *vrf;			/* Related VRF instance, NULL if global */
  TLIST_LIST(proto_neigh) neighbors;	/* List of neighbor structures */
  struct iface_subscription iface_sub;	/* Interface notification subscription */

  const char *name;			/* Name of this instance (== cf->name) */
  u32 debug;				/* Debugging flags */
  u32 mrtdump;				/* MRTDump flags */
  uint active_channels;			/* Number of active channels */
  uint active_loops;			/* Number of active IO loops */
  byte net_type;			/* Protocol network type (NET_*), 0 for undefined */
  byte disabled;			/* Manually disabled */
  byte proto_state;			/* Protocol state machine (PS_*, see below) */
  byte active;				/* From PS_START to cleanup after PS_STOP */
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
   *	   preexport	Called as the first step of the route exporting process.
   *			It can decide whether the route shall be exported:
   *			  -1 = reject,
   *			   0 = continue to export filter
   *			   1 = accept immediately
   *	   reload_routes   Request channel to reload all its routes to the core
   *			(using rte_update()). Returns: 0=reload cannot be done,
   *			1= reload is scheduled and will happen (asynchronously).
   *	   feed_begin	Notify channel about beginning of route feeding.
   *	   feed_end	Notify channel about finish of route feeding.
   */

  void (*rt_notify)(struct proto *, struct channel *, const net_addr *net, struct rte *new, const struct rte *old);
  int (*preexport)(struct channel *, struct rte *rt);
  void (*reload_routes)(struct channel *);
  void (*feed_begin)(struct channel *, int initial);
  void (*feed_end)(struct channel *);

  /*
   *	Routing entry hooks (called only for routes belonging to this protocol):
   *
   *	   rte_recalculate Called at the beginning of the best route selection
   *       rte_mergable	Compare two rte's and decide whether they could be merged (1=yes, 0=no).
   *	   rte_insert	Called whenever a rte is inserted to a routing table.
   *	   rte_remove	Called whenever a rte is removed from the routing table.
   */

  int (*rte_recalculate)(struct rtable_private *, struct network *, struct rte *, struct rte *, struct rte *);
  int (*rte_mergable)(struct rte *, struct rte *);
  void (*rte_insert)(struct network *, struct rte *);
  void (*rte_remove)(struct network *, struct rte *);
  u32 (*rte_igp_metric)(const struct rte *);

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

static inline event_list *proto_event_list(struct proto *p)
{ return p->loop == &main_birdloop ? &global_event_list : birdloop_event_list(p->loop); }

static inline event_list *proto_work_list(struct proto *p)
{ return p->loop == &main_birdloop ? &global_work_list : birdloop_event_list(p->loop); }

static inline void proto_send_event(struct proto *p, event *e)
{ ev_send(proto_event_list(p), e); }

void channel_show_limit(struct limit *l, const char *dsc, int active, int action);
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

#define PROTO_ENTER_FROM_MAIN(p)    ({ \
    ASSERT_DIE(birdloop_inside(&main_birdloop)); \
    struct birdloop *_loop = (p)->loop; \
    if (_loop != &main_birdloop) birdloop_enter(_loop); \
    _loop; \
    })

#define PROTO_LEAVE_FROM_MAIN(loop) ({ if (loop != &main_birdloop) birdloop_leave(loop); })

#define PROTO_LOCKED_FROM_MAIN(p)	for (struct birdloop *_proto_loop = PROTO_ENTER_FROM_MAIN(p); _proto_loop; PROTO_LEAVE_FROM_MAIN(_proto_loop), (_proto_loop = NULL))


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

static inline int proto_is_inactive(struct proto *p)
{
  return (p->active_channels == 0)
      && (p->active_loops == 0)
      && (p->sources.uc == 0)
      && EMPTY_TLIST(proto_neigh, &p->neighbors)
    ;
}


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

struct channel_limit {
  u32 limit;			/* Maximum number of prefixes */
  u8 action;			/* Action to take (PLA_*) */
};

struct channel_limit_data {
  struct channel *c;
  int dir;
};

#define CLP__RX(_c) (&(_c)->rx_limit)
#define CLP__IN(_c) (&(_c)->in_limit)
#define CLP__OUT(_c) (&(_c)->out_limit)


#if 0
#define CHANNEL_LIMIT_LOG(_c, _dir, _op)  log(L_TRACE "%s.%s: %s limit %s %u", (_c)->proto->name, (_c)->name, #_dir, _op, (CLP__##_dir(_c))->count)
#else
#define CHANNEL_LIMIT_LOG(_c, _dir, _op)
#endif

#define CHANNEL_LIMIT_PUSH(_c, _dir)  ({ CHANNEL_LIMIT_LOG(_c, _dir, "push from"); struct channel_limit_data cld = { .c = (_c), .dir = PLD_##_dir }; limit_push(CLP__##_dir(_c), &cld); })
#define CHANNEL_LIMIT_POP(_c, _dir)   ({ limit_pop(CLP__##_dir(_c)); CHANNEL_LIMIT_LOG(_c, _dir, "pop to"); })

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
  const net_addr *out_subprefix;	/* Export only subprefixes of this net */

  struct channel_limit rx_limit;	/* Limit for receiving routes from protocol
					   (relevant when in_keep & RIK_REJECTED) */
  struct channel_limit in_limit;	/* Limit for importing routes from protocol */
  struct channel_limit out_limit;	/* Limit for exporting routes to protocol */

  struct settle_config roa_settle;	/* Settle times for ROA-induced reload */

  u8 net_type;				/* Routing table network type (NET_*), 0 for undefined */
  u8 ra_mode;				/* Mode of received route advertisements (RA_*) */
  u16 preference;			/* Default route preference */
  u32 debug;				/* Debugging flags (D_*) */
  u8 copy;				/* Value from channel_config_get() is new (0) or from template (1) */
  u8 merge_limit;			/* Maximal number of nexthops for RA_MERGED */
  u8 in_keep;				/* Which states of routes to keep (RIK_*) */
  u8 rpki_reload;			/* RPKI changes trigger channel reload */
};

struct channel {
  node n;				/* Node in proto->channels */

  const char *name;			/* Channel name (may be NULL) */
  const struct channel_class *channel;
  struct proto *proto;

  rtable *table;
  const struct filter *in_filter;	/* Input filter */
  const struct filter *out_filter;	/* Output filter */
  const net_addr *out_subprefix;	/* Export only subprefixes of this net */
  struct bmap export_map;		/* Keeps track which routes were really exported */
  struct bmap export_reject_map;	/* Keeps track which routes were rejected by export filter */

  struct limit rx_limit;		/* Receive limit (for in_keep & RIK_REJECTED) */
  struct limit in_limit;		/* Input limit */
  struct limit out_limit;		/* Output limit */

  struct settle_config roa_settle;	/* Settle times for ROA-induced reload */

  u8 limit_actions[PLD_MAX];		/* Limit actions enum */
  u8 limit_active;			/* Flags for active limits */

  struct channel_import_stats {
    /* Import - from protocol to core */
    u32 updates_received;		/* Number of route updates received */
    u32 updates_invalid;		/* Number of route updates rejected as invalid */
    u32 updates_filtered;		/* Number of route updates rejected by filters */
    u32 updates_limited_rx;		/* Number of route updates exceeding the rx_limit */
    u32 updates_limited_in;		/* Number of route updates exceeding the in_limit */
    u32 withdraws_received;		/* Number of route withdraws received */
    u32 withdraws_invalid;		/* Number of route withdraws rejected as invalid */
  } import_stats;

  struct channel_export_stats {
    /* Export - from core to protocol */
    u32 updates_rejected;		/* Number of route updates rejected by protocol */
    u32 updates_filtered;		/* Number of route updates rejected by filters */
    u32 updates_accepted;		/* Number of route updates accepted and exported */
    u32 updates_limited;		/* Number of route updates exceeding the out_limit */
    u32 withdraws_accepted;		/* Number of route withdraws accepted and processed */
  } export_stats;

  struct rt_import_request in_req;	/* Table import connection */
  struct rt_export_request out_req;	/* Table export connection */

  u32 refeed_count;			/* Number of routes exported during refeed regardless of out_limit */

  u8 net_type;				/* Routing table network type (NET_*), 0 for undefined */
  u8 ra_mode;				/* Mode of received route advertisements (RA_*) */
  u16 preference;			/* Default route preference */
  u32 debug;				/* Debugging flags (D_*) */
  u8 merge_limit;			/* Maximal number of nexthops for RA_MERGED */
  u8 in_keep;				/* Which states of routes to keep (RIK_*) */
  u8 disabled;
  u8 stale;				/* Used in reconfiguration */

  u8 channel_state;
  u8 refeeding;				/* Refeeding the channel. */
  u8 reloadable;			/* Hook reload_routes() is allowed on the channel */
  u8 gr_lock;				/* Graceful restart mechanism should wait for this channel */
  u8 gr_wait;				/* Route export to channel is postponed until graceful restart */

  btime last_state_change;		/* Time of last state transition */

  struct rt_export_request reload_req;	/* Feeder for import reload */

  u8 reload_pending;			/* Reloading and another reload is scheduled */
  u8 refeed_pending;			/* Refeeding and another refeed is scheduled */
  u8 rpki_reload;			/* RPKI changes trigger channel reload */

  struct rt_exporter *out_table;	/* Internal table for exported routes */

  list roa_subscriptions;		/* List of active ROA table subscriptions based on filters' roa_check() calls */
};

#define RIK_REJECTED	1			/* Routes rejected in import filter are kept */
#define RIK_PREFILTER	(2 | RIK_REJECTED)	/* All routes' attribute state before import filter is kept */

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
 * CS_STOP - The transitional state between initialized channel and closed
 * channel. The channel is still initialized, but no route exchange is allowed.
 * Instead, the associated table is running flush loop to remove routes imported
 * through the channel. After that, the channel changes state to CS_DOWN and
 * is detached from the table (the table is unlocked and the channel is unlinked
 * from it). Unlike other states, the CS_STOP state is not explicitly
 * entered or left by the protocol. A protocol may request to close a channel
 * (by calling channel_close()), which causes the channel to change state to
 * CS_STOP and later to CS_DOWN. Also note that channels are closed
 * automatically by the core when the protocol is going down.
 *
 * CS_PAUSE - Almost the same as CS_STOP, just the table import is kept and
 * the table export is stopped before transitioning to CS_START.
 *
 * Allowed transitions:
 *
 * CS_DOWN	-> CS_START / CS_UP
 * CS_START	-> CS_UP / CS_STOP
 * CS_UP	-> CS_PAUSE / CS_STOP
 * CS_PAUSE	-> CS_START (automatic)
 * CS_STOP	-> CS_DOWN (automatic)
 */

#define CS_DOWN		0
#define CS_START	1
#define CS_UP		2
#define CS_STOP		3
#define CS_PAUSE	4

struct channel_config *proto_cf_find_channel(struct proto_config *p, uint net_type);
static inline struct channel_config *proto_cf_main_channel(struct proto_config *pc)
{ return proto_cf_find_channel(pc, pc->net_type); }

struct channel *proto_find_channel_by_table(struct proto *p, rtable *t);
struct channel *proto_find_channel_by_name(struct proto *p, const char *n);
struct channel *proto_add_channel(struct proto *p, struct channel_config *cf);
int proto_configure_channel(struct proto *p, struct channel **c, struct channel_config *cf);

void channel_set_state(struct channel *c, uint state);
void channel_schedule_reload(struct channel *c);

static inline void channel_init(struct channel *c) { channel_set_state(c, CS_START); }
static inline void channel_open(struct channel *c) { channel_set_state(c, CS_UP); }
static inline void channel_close(struct channel *c) { channel_set_state(c, CS_STOP); }

void channel_request_feeding(struct channel *c);
void *channel_config_new(const struct channel_class *cc, const char *name, uint net_type, struct proto_config *proto);
void *channel_config_get(const struct channel_class *cc, const char *name, uint net_type, struct proto_config *proto);
int channel_reconfigure(struct channel *c, struct channel_config *cf);

#endif
