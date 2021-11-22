/*
 *	BIRD Internet Routing Daemon -- Routing Table
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2019--2021 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_ROUTE_H_
#define _BIRD_ROUTE_H_

#include "lib/lists.h"
#include "lib/bitmap.h"
#include "lib/resource.h"
#include "lib/net.h"

struct ea_list;
struct protocol;
struct proto;
struct channel;
struct rte_src;
struct symbol;
struct timer;
struct filter;
struct cli;

/*
 *	Generic data structure for storing network prefixes. Also used
 *	for the master routing table. Currently implemented as a hash
 *	table.
 *
 *	Available operations:
 *		- insertion of new entry
 *		- deletion of entry
 *		- searching for entry by network prefix
 *		- asynchronous retrieval of fib contents
 */

struct fib_node {
  struct fib_node *next;		/* Next in hash chain */
  struct fib_iterator *readers;		/* List of readers of this node */
  net_addr addr[0];
};

struct fib_iterator {			/* See lib/slists.h for an explanation */
  struct fib_iterator *prev, *next;	/* Must be synced with struct fib_node! */
  byte efef;				/* 0xff to distinguish between iterator and node */
  byte pad[3];
  struct fib_node *node;		/* Or NULL if freshly merged */
  uint hash;
};

typedef void (*fib_init_fn)(void *);

struct fib {
  pool *fib_pool;			/* Pool holding all our data */
  slab *fib_slab;			/* Slab holding all fib nodes */
  struct fib_node **hash_table;		/* Node hash table */
  uint hash_size;			/* Number of hash table entries (a power of two) */
  uint hash_order;			/* Binary logarithm of hash_size */
  uint hash_shift;			/* 32 - hash_order */
  uint addr_type;			/* Type of address data stored in fib (NET_*) */
  uint node_size;			/* FIB node size, 0 for nonuniform */
  uint node_offset;			/* Offset of fib_node struct inside of user data */
  uint entries;				/* Number of entries */
  uint entries_min, entries_max;	/* Entry count limits (else start rehashing) */
  fib_init_fn init;			/* Constructor */
};

static inline void * fib_node_to_user(struct fib *f, struct fib_node *e)
{ return e ? (void *) ((char *) e - f->node_offset) : NULL; }

static inline struct fib_node * fib_user_to_node(struct fib *f, void *e)
{ return e ? (void *) ((char *) e + f->node_offset) : NULL; }

void fib_init(struct fib *f, pool *p, uint addr_type, uint node_size, uint node_offset, uint hash_order, fib_init_fn init);
void *fib_find(struct fib *, const net_addr *);	/* Find or return NULL if doesn't exist */
void *fib_get_chain(struct fib *f, const net_addr *a); /* Find first node in linked list from hash table */
void *fib_get(struct fib *, const net_addr *);	/* Find or create new if nonexistent */
void *fib_route(struct fib *, const net_addr *); /* Longest-match routing lookup */
void fib_delete(struct fib *, void *);	/* Remove fib entry */
void fib_free(struct fib *);		/* Destroy the fib */
void fib_check(struct fib *);		/* Consistency check for debugging */

void fit_init(struct fib_iterator *, struct fib *); /* Internal functions, don't call */
struct fib_node *fit_get(struct fib *, struct fib_iterator *);
void fit_put(struct fib_iterator *, struct fib_node *);
void fit_put_next(struct fib *f, struct fib_iterator *i, struct fib_node *n, uint hpos);
void fit_put_end(struct fib_iterator *i);
void fit_copy(struct fib *f, struct fib_iterator *dst, struct fib_iterator *src);


#define FIB_WALK(fib, type, z) do {				\
	struct fib_node *fn_, **ff_ = (fib)->hash_table;	\
	uint count_ = (fib)->hash_size;				\
	type *z;						\
	while (count_--)					\
	  for (fn_ = *ff_++; z = fib_node_to_user(fib, fn_); fn_=fn_->next)

#define FIB_WALK_END } while (0)

#define FIB_ITERATE_INIT(it, fib) fit_init(it, fib)

#define FIB_ITERATE_START(fib, it, type, z) do {		\
	struct fib_node *fn_ = fit_get(fib, it);		\
	uint count_ = (fib)->hash_size;				\
	uint hpos_ = (it)->hash;				\
	type *z;						\
	for(;;) {						\
	  if (!fn_)						\
	    {							\
	       if (++hpos_ >= count_)				\
		 break;						\
	       fn_ = (fib)->hash_table[hpos_];			\
	       continue;					\
	    }							\
	  z = fib_node_to_user(fib, fn_);

#define FIB_ITERATE_END fn_ = fn_->next; } } while(0)

#define FIB_ITERATE_PUT(it) fit_put(it, fn_)

#define FIB_ITERATE_PUT_NEXT(it, fib) fit_put_next(fib, it, fn_, hpos_)

#define FIB_ITERATE_PUT_END(it) fit_put_end(it)

#define FIB_ITERATE_UNLINK(it, fib) fit_get(fib, it)

#define FIB_ITERATE_COPY(dst, src, fib) fit_copy(fib, dst, src)


/*
 *	Master Routing Tables. Generally speaking, each of them contains a FIB
 *	with each entry pointing to a list of route entries representing routes
 *	to given network (with the selected one at the head).
 *
 *	Each of the RTE's contains variable data (the preference and protocol-dependent
 *	metrics) and a pointer to a route attribute block common for many routes).
 *
 *	It's guaranteed that there is at most one RTE for every (prefix,proto) pair.
 */

struct rtable_config {
  node n;
  char *name;
  struct rtable *table;
  struct proto_config *krt_attached;	/* Kernel syncer attached to this table */
  uint addr_type;			/* Type of address data stored in table (NET_*) */
  int gc_max_ops;			/* Maximum number of operations before GC is run */
  int gc_min_time;			/* Minimum time between two consecutive GC runs */
  byte sorted;				/* Routes of network are sorted according to rte_better() */
  btime min_settle_time;		/* Minimum settle time for notifications */
  btime max_settle_time;		/* Maximum settle time for notifications */
};

typedef struct rtable {
  resource r;
  node n;				/* Node in list of all tables */
  pool *rp;				/* Resource pool to allocate everything from, including itself */
  struct slab *rte_slab;		/* Slab to allocate route objects */
  struct fib fib;
  char *name;				/* Name of this table */
  uint addr_type;			/* Type of address data stored in table (NET_*) */
  int use_count;			/* Number of protocols using this table */
  u32 rt_count;				/* Number of routes in the table */

  list imports;				/* Registered route importers */
  list exports;				/* Registered route exporters */

  struct hmap id_map;
  struct hostcache *hostcache;
  struct rtable_config *config;		/* Configuration of this table */
  void (*deleted)(void *);		/* Table should free itself. Call this when it is done. */
  void *del_data;
  struct event *rt_event;		/* Routing table event */
  btime last_rt_change;			/* Last time when route changed */
  btime base_settle_time;		/* Start time of rtable settling interval */
  btime gc_time;			/* Time of last GC */
  int gc_counter;			/* Number of operations since last GC */
  byte prune_state;			/* Table prune state, 1 -> scheduled, 2-> running */
  byte hcu_scheduled;			/* Hostcache update is scheduled */
  byte nhu_state;			/* Next Hop Update state */
  struct fib_iterator prune_fit;	/* Rtable prune FIB iterator */
  struct fib_iterator nhu_fit;		/* Next Hop Update FIB iterator */
  struct tbf rl_pipe;			/* Rate limiting token buffer for pipe collisions */

  list subscribers;			/* Subscribers for notifications */
  struct timer *settle_timer;		/* Settle time for notifications */
} rtable;

struct rt_subscription {
  node n;
  rtable *tab;
  void (*hook)(struct rt_subscription *b);
  void *data;
};

#define NHU_CLEAN	0
#define NHU_SCHEDULED	1
#define NHU_RUNNING	2
#define NHU_DIRTY	3

typedef struct network {
  struct rte_storage *routes;			/* Available routes for this network */
  struct fib_node n;			/* FIB flags reserved for kernel syncer */
} net;

struct hostcache {
  slab *slab;				/* Slab holding all hostentries */
  struct hostentry **hash_table;	/* Hash table for hostentries */
  unsigned hash_order, hash_shift;
  unsigned hash_max, hash_min;
  unsigned hash_items;
  linpool *lp;				/* Linpool for trie */
  struct f_trie *trie;			/* Trie of prefixes that might affect hostentries */
  list hostentries;			/* List of all hostentries */
  byte update_hostcache;
};

struct hostentry {
  node ln;
  ip_addr addr;				/* IP address of host, part of key */
  ip_addr link;				/* (link-local) IP address of host, used as gw
					   if host is directly attached */
  struct rtable *tab;			/* Dependent table, part of key */
  struct hostentry *next;		/* Next in hash chain */
  unsigned hash_key;			/* Hash key */
  unsigned uc;				/* Use count */
  struct rta *src;			/* Source rta entry */
  byte dest;				/* Chosen route destination type (RTD_...) */
  byte nexthop_linkable;		/* Nexthop list is completely non-device */
  u32 igp_metric;			/* Chosen route IGP metric */
};

typedef struct rte {
  struct rta *attrs;			/* Attributes of this route */
  const net_addr *net;			/* Network this RTE belongs to */
  struct rte_src *src;			/* Route source that created the route */
  struct rt_import_hook *sender;	/* Import hook used to send the route to the routing table */
  btime lastmod;			/* Last modified (set by table) */
  u32 id;				/* Table specific route id */
  byte flags;				/* Table-specific flags */
  byte pflags;				/* Protocol-specific flags */
  u8 generation;			/* If this route import is based on other previously exported route,
					   this value should be 1 + MAX(generation of the parent routes).
					   Otherwise the route is independent and this value is zero. */
  u8 stale_cycle;			/* Auxiliary value for route refresh */
} rte;

struct rte_storage {
  struct rte_storage *next;		/* Next in chain */
  struct rte rte;			/* Route data */
};

#define RTES_CLONE(r, l)	((r) ? (((*(l)) = (r)->rte), (l)) : NULL)
#define RTES_OR_NULL(r)		((r) ? &((r)->rte) : NULL)

#define REF_FILTERED	2		/* Route is rejected by import filter */
#define REF_USE_STALE	4		/* Do not reset route's stale_cycle to the actual value */

/* Route is valid for propagation (may depend on other flags in the future), accepts NULL */
static inline int rte_is_valid(const rte *r) { return r && !(r->flags & REF_FILTERED); }

/* Route just has REF_FILTERED flag */
static inline int rte_is_filtered(const rte *r) { return !!(r->flags & REF_FILTERED); }


/* Table-channel connections */

struct rt_import_request {
  struct rt_import_hook *hook;		/* The table part of importer */
  char *name;
  u8 trace_routes;

  void (*dump_req)(struct rt_import_request *req);
  void (*log_state_change)(struct rt_import_request *req, u8 state);
  /* Preimport is called when the @new route is just-to-be inserted, replacing @old.
   * Return a route (may be different or modified in-place) to continue or NULL to withdraw. */
  struct rte *(*preimport)(struct rt_import_request *req, struct rte *new, struct rte *old);
};

struct rt_import_hook {
  node n;
  rtable *table;			/* The connected table */
  struct rt_import_request *req;	/* The requestor */

  struct rt_import_stats {
    /* Import - from protocol to core */
    u32 pref;				/* Number of routes selected as best in the (adjacent) routing table */
    u32 updates_ignored;		/* Number of route updates rejected as already in route table */
    u32 updates_accepted;		/* Number of route updates accepted and imported */
    u32 withdraws_ignored;		/* Number of route withdraws rejected as already not in route table */
    u32 withdraws_accepted;		/* Number of route withdraws accepted and processed */
  } stats;

  btime last_state_change;		/* Time of last state transition */

  u8 import_state;			/* IS_* */
  u8 stale_set;				/* Set this stale_cycle to imported routes */
  u8 stale_valid;			/* Routes with this stale_cycle and bigger are considered valid */
  u8 stale_pruned;			/* Last prune finished when this value was set at stale_valid */
  u8 stale_pruning;			/* Last prune started when this value was set at stale_valid */

  void (*stopped)(struct rt_import_request *);	/* Stored callback when import is stopped */
};

struct rt_pending_export {
  struct rte_storage *new, *new_best, *old, *old_best;
};

struct rt_export_request {
  struct rt_export_hook *hook;		/* Table part of the export */
  char *name;
  u8 trace_routes;

  /* There are two methods of export. You can either request feeding every single change
   * or feeding the whole route feed. In case of regular export, &export_one is preferred.
   * Anyway, when feeding, &export_bulk is preferred, falling back to &export_one.
   * Thus, for RA_OPTIMAL, &export_one is only set,
   *	   for RA_MERGED and RA_ACCEPTED, &export_bulk is only set
   *	   and for RA_ANY, both are set to accomodate for feeding all routes but receiving single changes
   */
  void (*export_one)(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *rpe);
  void (*export_bulk)(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *rpe, rte **feed, uint count);

  void (*dump_req)(struct rt_export_request *req);
  void (*log_state_change)(struct rt_export_request *req, u8);
};

struct rt_export_hook {
  node n;
  rtable *table;			/* The connected table */

  pool *pool;
  linpool *lp;

  struct rt_export_request *req;	/* The requestor */

  struct rt_export_stats {
    /* Export - from core to protocol */
    u32 updates_received;		/* Number of route updates received */
    u32 withdraws_received;		/* Number of route withdraws received */
  } stats;

  struct fib_iterator feed_fit;		/* Routing table iterator used during feeding */

  btime last_state_change;		/* Time of last state transition */

  u8 refeed_pending;			/* Refeeding and another refeed is scheduled */
  u8 export_state;			/* Route export state (TES_*, see below) */

  struct event *event;			/* Event running all the export operations */

  void (*stopped)(struct rt_export_request *);	/* Stored callback when export is stopped */
};

#define TIS_DOWN	0
#define TIS_UP		1
#define TIS_STOP	2
#define TIS_FLUSHING	3
#define TIS_WAITING	4
#define TIS_CLEARED	5
#define TIS_MAX		6

#define TES_DOWN	0
#define TES_HUNGRY	1
#define TES_FEEDING	2
#define TES_READY	3
#define TES_STOP	4
#define TES_MAX		5

void rt_request_import(rtable *tab, struct rt_import_request *req);
void rt_request_export(rtable *tab, struct rt_export_request *req);

void rt_stop_import(struct rt_import_request *, void (*stopped)(struct rt_import_request *));
void rt_stop_export(struct rt_export_request *, void (*stopped)(struct rt_export_request *));

const char *rt_import_state_name(u8 state);
const char *rt_export_state_name(u8 state);

static inline u8 rt_import_get_state(struct rt_import_hook *ih) { return ih ? ih->import_state : TIS_DOWN; }
static inline u8 rt_export_get_state(struct rt_export_hook *eh) { return eh ? eh->export_state : TES_DOWN; }

void rte_import(struct rt_import_request *req, const net_addr *net, rte *new, struct rte_src *src);

/* Types of route announcement, also used as flags */
#define RA_UNDEF	0		/* Undefined RA type */
#define RA_OPTIMAL	1		/* Announcement of optimal route change */
#define RA_ACCEPTED	2		/* Announcement of first accepted route */
#define RA_ANY		3		/* Announcement of any route change */
#define RA_MERGED	4		/* Announcement of optimal route merged with next ones */

/* Return value of preexport() callback */
#define RIC_ACCEPT	1		/* Accepted by protocol */
#define RIC_PROCESS	0		/* Process it through import filter */
#define RIC_REJECT	-1		/* Rejected by protocol */
#define RIC_DROP	-2		/* Silently dropped by protocol */

#define rte_update  channel_rte_import
/**
 * rte_update - enter a new update to a routing table
 * @c: channel doing the update
 * @net: network address
 * @rte: a &rte representing the new route
 * @src: old route source identifier
 *
 * This function imports a new route to the appropriate table (via the channel).
 * Table keys are @net (obligatory) and @rte->attrs->src.
 * Both the @net and @rte pointers can be local.
 *
 * The route attributes (@rte->attrs) are obligatory. They can be also allocated
 * locally. Anyway, if you use an already-cached attribute object, you shall
 * call rta_clone() on that object yourself. (This semantics may change in future.)
 *
 * If the route attributes are local, you may set @rte->attrs->src to NULL, then
 * the protocol's default route source will be supplied.
 *
 * When rte_update() gets a route, it automatically validates it. This includes
 * checking for validity of the given network and next hop addresses and also
 * checking for host-scope or link-scope routes. Then the import filters are
 * processed and if accepted, the route is passed to route table recalculation.
 *
 * The accepted routes are then inserted into the table, replacing the old route
 * for the same @net identified by @src. Then the route is announced
 * to all the channels connected to the table using the standard export mechanism.
 * Setting @rte to NULL makes this a withdraw, otherwise @rte->src must be the same
 * as @src.
 *
 * All memory used for temporary allocations is taken from a special linpool
 * @rte_update_pool and freed when rte_update() finishes.
 */
void rte_update(struct channel *c, const net_addr *net, struct rte *rte, struct rte_src *src);

extern list routing_tables;
struct config;

void rt_init(void);
void rt_preconfig(struct config *);
void rt_commit(struct config *new, struct config *old);
void rt_lock_table(rtable *);
void rt_unlock_table(rtable *);
void rt_subscribe(rtable *tab, struct rt_subscription *s);
void rt_unsubscribe(struct rt_subscription *s);
rtable *rt_setup(pool *, struct rtable_config *);
static inline void rt_shutdown(rtable *r) { rfree(r->rp); }

static inline net *net_find(rtable *tab, const net_addr *addr) { return (net *) fib_find(&tab->fib, addr); }
static inline net *net_find_valid(rtable *tab, const net_addr *addr)
{ net *n = net_find(tab, addr); return (n && n->routes && rte_is_valid(&n->routes->rte)) ? n : NULL; }
static inline net *net_get(rtable *tab, const net_addr *addr) { return (net *) fib_get(&tab->fib, addr); }
void *net_route(rtable *tab, const net_addr *n);
int net_roa_check(rtable *tab, const net_addr *n, u32 asn);
int rt_examine(rtable *t, net_addr *a, struct channel *c, const struct filter *filter);
rte *rt_export_merged(struct channel *c, rte ** feed, uint count, linpool *pool, int silent);

void rt_refresh_begin(struct rt_import_request *);
void rt_refresh_end(struct rt_import_request *);
void rt_schedule_prune(rtable *t);
void rte_dump(struct rte_storage *);
void rte_free(struct rte_storage *, rtable *);
struct rte_storage *rte_store(const rte *, net *net, rtable *);
void rt_dump(rtable *);
void rt_dump_all(void);
void rt_dump_hooks(rtable *);
void rt_dump_hooks_all(void);
void rt_prune_sync(rtable *t, int all);
struct rtable_config *rt_new_table(struct symbol *s, uint addr_type);

/* Default limit for ECMP next hops, defined in sysdep code */
extern const int rt_default_ecmp;

struct rt_show_data_rtable {
  node n;
  rtable *table;
  struct channel *export_channel;
};

struct rt_show_data {
  net_addr *addr;
  list tables;
  struct rt_show_data_rtable *tab;	/* Iterator over table list */
  struct rt_show_data_rtable *last_table; /* Last table in output */
  struct fib_iterator fit;		/* Iterator over networks in table */
  int verbose, tables_defined_by;
  const struct filter *filter;
  struct proto *show_protocol;
  struct proto *export_protocol;
  struct channel *export_channel;
  struct config *running_on_config;
  struct krt_proto *kernel;
  struct rt_export_hook *kernel_export_hook;
  int export_mode, primary_only, filtered, stats, show_for;

  int table_open;			/* Iteration (fit) is open */
  int net_counter, rt_counter, show_counter, table_counter;
  int net_counter_last, rt_counter_last, show_counter_last;
};

void rt_show(struct rt_show_data *);
struct rt_show_data_rtable * rt_show_add_table(struct rt_show_data *d, rtable *t);

/* Value of table definition mode in struct rt_show_data */
#define RSD_TDB_DEFAULT	  0		/* no table specified */
#define RSD_TDB_INDIRECT  0		/* show route ... protocol P ... */
#define RSD_TDB_ALL	  RSD_TDB_SET			/* show route ... table all ... */
#define RSD_TDB_DIRECT	  RSD_TDB_SET | RSD_TDB_NMN	/* show route ... table X table Y ... */

#define RSD_TDB_SET	  0x1		/* internal: show empty tables */
#define RSD_TDB_NMN	  0x2		/* internal: need matching net */

/* Value of export_mode in struct rt_show_data */
#define RSEM_NONE	0		/* Export mode not used */
#define RSEM_PREEXPORT	1		/* Routes ready for export, before filtering */
#define RSEM_EXPORT	2		/* Routes accepted by export filter */
#define RSEM_NOEXPORT	3		/* Routes rejected by export filter */
#define RSEM_EXPORTED	4		/* Routes marked in export map */

/*
 *	Route Attributes
 *
 *	Beware: All standard BGP attributes must be represented here instead
 *	of making them local to the route. This is needed to ensure proper
 *	construction of BGP route attribute lists.
 */

/* Nexthop structure */
struct nexthop {
  ip_addr gw;				/* Next hop */
  struct iface *iface;			/* Outgoing interface */
  struct nexthop *next;
  byte flags;
  byte weight;
  byte labels_orig;			/* Number of labels before hostentry was applied */
  byte labels;				/* Number of all labels */
  u32 label[0];
};

#define RNF_ONLINK		0x1	/* Gateway is onlink regardless of IP ranges */


struct rte_src {
  struct rte_src *next;			/* Hash chain */
  struct proto *proto;			/* Protocol the source is based on */
  u32 private_id;			/* Private ID, assigned by the protocol */
  u32 global_id;			/* Globally unique ID of the source */
  unsigned uc;				/* Use count */
};


typedef struct rta {
  struct rta *next, **pprev;		/* Hash chain */
  u32 uc;				/* Use count */
  u32 hash_key;				/* Hash over important fields */
  struct ea_list *eattrs;		/* Extended Attribute chain */
  struct hostentry *hostentry;		/* Hostentry for recursive next-hops */
  ip_addr from;				/* Advertising router */
  u32 igp_metric;			/* IGP metric to next hop (for iBGP routes) */
  u16 cached:1;				/* Are attributes cached? */
  u16 source:7;				/* Route source (RTS_...) */
  u16 scope:4;				/* Route scope (SCOPE_... -- see ip.h) */
  u16 dest:4;				/* Route destination type (RTD_...) */
  word pref;
  struct nexthop nh;			/* Next hop */
} rta;

#define RTS_STATIC 1			/* Normal static route */
#define RTS_INHERIT 2			/* Route inherited from kernel */
#define RTS_DEVICE 3			/* Device route */
#define RTS_STATIC_DEVICE 4		/* Static device route */
#define RTS_REDIRECT 5			/* Learned via redirect */
#define RTS_RIP 6			/* RIP route */
#define RTS_OSPF 7			/* OSPF route */
#define RTS_OSPF_IA 8			/* OSPF inter-area route */
#define RTS_OSPF_EXT1 9			/* OSPF external route type 1 */
#define RTS_OSPF_EXT2 10		/* OSPF external route type 2 */
#define RTS_BGP 11			/* BGP route */
#define RTS_PIPE 12			/* Inter-table wormhole */
#define RTS_BABEL 13			/* Babel route */
#define RTS_RPKI 14			/* Route Origin Authorization */
#define RTS_PERF 15			/* Perf checker */
#define RTS_MAX 16

#define RTD_NONE 0			/* Undefined next hop */
#define RTD_UNICAST 1			/* Next hop is neighbor router */
#define RTD_BLACKHOLE 2			/* Silently drop packets */
#define RTD_UNREACHABLE 3		/* Reject as unreachable */
#define RTD_PROHIBIT 4			/* Administratively prohibited */
#define RTD_MAX 5

#define IGP_METRIC_UNKNOWN 0x80000000	/* Default igp_metric used when no other
					   protocol-specific metric is availabe */


extern const char * rta_dest_names[RTD_MAX];

static inline const char *rta_dest_name(uint n)
{ return (n < RTD_MAX) ? rta_dest_names[n] : "???"; }

/* Route has regular, reachable nexthop (i.e. not RTD_UNREACHABLE and like) */
static inline int rte_is_reachable(rte *r)
{ return r->attrs->dest == RTD_UNICAST; }


/*
 *	Extended Route Attributes
 */

typedef struct eattr {
  word id;				/* EA_CODE(PROTOCOL_..., protocol-dependent ID) */
  byte flags;				/* Protocol-dependent flags */
  byte type;				/* Attribute type and several flags (EAF_...) */
  union {
    uintptr_t data;
    const struct adata *ptr;		/* Attribute data elsewhere */
  } u;
} eattr;


#define EA_CODE(proto,id) (((proto) << 8) | (id))
#define EA_ID(ea) ((ea) & 0xff)
#define EA_PROTO(ea) ((ea) >> 8)
#define EA_CUSTOM(id) ((id) | EA_CUSTOM_BIT)
#define EA_IS_CUSTOM(ea) ((ea) & EA_CUSTOM_BIT)
#define EA_CUSTOM_ID(ea) ((ea) & ~EA_CUSTOM_BIT)

const char *ea_custom_name(uint ea);

#define EA_GEN_IGP_METRIC EA_CODE(PROTOCOL_NONE, 0)

#define EA_CODE_MASK 0xffff
#define EA_CUSTOM_BIT 0x8000
#define EA_ALLOW_UNDEF 0x10000		/* ea_find: allow EAF_TYPE_UNDEF */
#define EA_BIT(n) ((n) << 24)		/* Used in bitfield accessors */
#define EA_BIT_GET(ea) ((ea) >> 24)

#define EAF_TYPE_MASK 0x1f		/* Mask with this to get type */
#define EAF_TYPE_INT 0x01		/* 32-bit unsigned integer number */
#define EAF_TYPE_OPAQUE 0x02		/* Opaque byte string (not filterable) */
#define EAF_TYPE_IP_ADDRESS 0x04	/* IP address */
#define EAF_TYPE_ROUTER_ID 0x05		/* Router ID (IPv4 address) */
#define EAF_TYPE_AS_PATH 0x06		/* BGP AS path (encoding per RFC 1771:4.3) */
#define EAF_TYPE_BITFIELD 0x09		/* 32-bit embedded bitfield */
#define EAF_TYPE_INT_SET 0x0a		/* Set of u32's (e.g., a community list) */
#define EAF_TYPE_PTR 0x0d		/* Pointer to an object */
#define EAF_TYPE_EC_SET 0x0e		/* Set of pairs of u32's - ext. community list */
#define EAF_TYPE_LC_SET 0x12		/* Set of triplets of u32's - large community list */
#define EAF_TYPE_UNDEF 0x1f		/* `force undefined' entry */
#define EAF_EMBEDDED 0x01		/* Data stored in eattr.u.data (part of type spec) */
#define EAF_VAR_LENGTH 0x02		/* Attribute length is variable (part of type spec) */
#define EAF_ORIGINATED 0x20		/* The attribute has originated locally */
#define EAF_FRESH 0x40			/* An uncached attribute (e.g. modified in export filter) */

typedef struct adata {
  uint length;				/* Length of data */
  byte data[0];
} adata;

extern const adata null_adata;		/* adata of length 0 */

static inline struct adata *
lp_alloc_adata(struct linpool *pool, uint len)
{
  struct adata *ad = lp_alloc(pool, sizeof(struct adata) + len);
  ad->length = len;
  return ad;
}

static inline int adata_same(const struct adata *a, const struct adata *b)
{ return (a->length == b->length && !memcmp(a->data, b->data, a->length)); }


typedef struct ea_list {
  struct ea_list *next;			/* In case we have an override list */
  byte flags;				/* Flags: EALF_... */
  byte rfu;
  word count;				/* Number of attributes */
  eattr attrs[0];			/* Attribute definitions themselves */
} ea_list;

#define EALF_SORTED 1			/* Attributes are sorted by code */
#define EALF_BISECT 2			/* Use interval bisection for searching */
#define EALF_CACHED 4			/* Attributes belonging to cached rta */

struct rte_src *rt_find_source(struct proto *p, u32 id);
struct rte_src *rt_get_source(struct proto *p, u32 id);
static inline void rt_lock_source(struct rte_src *src) { src->uc++; }
static inline void rt_unlock_source(struct rte_src *src) { src->uc--; }
void rt_prune_sources(void);

struct ea_walk_state {
  ea_list *eattrs;			/* Ccurrent ea_list, initially set by caller */
  eattr *ea;				/* Current eattr, initially NULL */
  u32 visited[4];			/* Bitfield, limiting max to 128 */
};

eattr *ea_find(ea_list *, unsigned ea);
eattr *ea_walk(struct ea_walk_state *s, uint id, uint max);
uintptr_t ea_get_int(ea_list *, unsigned ea, uintptr_t def);
void ea_dump(ea_list *);
void ea_sort(ea_list *);		/* Sort entries in all sub-lists */
unsigned ea_scan(ea_list *);		/* How many bytes do we need for merged ea_list */
void ea_merge(ea_list *from, ea_list *to); /* Merge sub-lists to allocated buffer */
int ea_same(ea_list *x, ea_list *y);	/* Test whether two ea_lists are identical */
uint ea_hash(ea_list *e);	/* Calculate 16-bit hash value */
ea_list *ea_append(ea_list *to, ea_list *what);
void ea_format_bitfield(const struct eattr *a, byte *buf, int bufsize, const char **names, int min, int max);

#define ea_normalize(ea) do { \
  if (ea->next) { \
    ea_list *t = alloca(ea_scan(ea)); \
    ea_merge(ea, t); \
    ea = t; \
  } \
  ea_sort(ea); \
  if (ea->count == 0) \
    ea = NULL; \
} while(0) \

static inline eattr *
ea_set_attr(ea_list **to, struct linpool *pool, uint id, uint flags, uint type, uintptr_t val)
{
  ea_list *a = lp_alloc(pool, sizeof(ea_list) + sizeof(eattr));
  eattr *e = &a->attrs[0];

  a->flags = EALF_SORTED;
  a->count = 1;
  a->next = *to;
  *to = a;

  e->id = id;
  e->type = type;
  e->flags = flags;

  if (type & EAF_EMBEDDED)
    e->u.data = (u32) val;
  else
    e->u.ptr = (struct adata *) val;

  return e;
}

static inline void
ea_set_attr_u32(ea_list **to, struct linpool *pool, uint id, uint flags, uint type, u32 val)
{ ea_set_attr(to, pool, id, flags, type, (uintptr_t) val); }

static inline void
ea_set_attr_ptr(ea_list **to, struct linpool *pool, uint id, uint flags, uint type, struct adata *val)
{ ea_set_attr(to, pool, id, flags, type, (uintptr_t) val); }

static inline void
ea_set_attr_data(ea_list **to, struct linpool *pool, uint id, uint flags, uint type, void *data, uint len)
{
  struct adata *a = lp_alloc_adata(pool, len);
  memcpy(a->data, data, len);
  ea_set_attr(to, pool, id, flags, type, (uintptr_t) a);
}


#define NEXTHOP_MAX_SIZE (sizeof(struct nexthop) + sizeof(u32)*MPLS_MAX_LABEL_STACK)

static inline size_t nexthop_size(const struct nexthop *nh)
{ return sizeof(struct nexthop) + sizeof(u32)*nh->labels; }
int nexthop__same(struct nexthop *x, struct nexthop *y); /* Compare multipath nexthops */
static inline int nexthop_same(struct nexthop *x, struct nexthop *y)
{ return (x == y) || nexthop__same(x, y); }
struct nexthop *nexthop_merge(struct nexthop *x, struct nexthop *y, int rx, int ry, int max, linpool *lp);
struct nexthop *nexthop_sort(struct nexthop *x);
static inline void nexthop_link(struct rta *a, struct nexthop *from)
{ memcpy(&a->nh, from, nexthop_size(from)); }
void nexthop_insert(struct nexthop **n, struct nexthop *y);
int nexthop_is_sorted(struct nexthop *x);

void rta_init(void);
static inline size_t rta_size(const rta *a) { return sizeof(rta) + sizeof(u32)*a->nh.labels; }
#define RTA_MAX_SIZE (sizeof(rta) + sizeof(u32)*MPLS_MAX_LABEL_STACK)
rta *rta_lookup(rta *);			/* Get rta equivalent to this one, uc++ */
static inline int rta_is_cached(rta *r) { return r->cached; }
static inline rta *rta_clone(rta *r) { r->uc++; return r; }
void rta__free(rta *r);
static inline void rta_free(rta *r) { if (r && !--r->uc) rta__free(r); }
rta *rta_do_cow(rta *o, linpool *lp);
static inline rta * rta_cow(rta *r, linpool *lp) { return rta_is_cached(r) ? rta_do_cow(r, lp) : r; }
static inline void rta_uncache(rta *r) { r->cached = 0; r->uc = 0; }
void rta_dump(rta *);
void rta_dump_all(void);
void rta_show(struct cli *, rta *);

u32 rt_get_igp_metric(rte *);
struct hostentry * rt_get_hostentry(rtable *tab, ip_addr a, ip_addr ll, rtable *dep);
void rta_apply_hostentry(rta *a, struct hostentry *he, mpls_label_stack *mls);

static inline void
rta_set_recursive_next_hop(rtable *dep, rta *a, rtable *tab, ip_addr gw, ip_addr ll, mpls_label_stack *mls)
{
  rta_apply_hostentry(a, rt_get_hostentry(tab, gw, ll, dep), mls);
}

/*
 * rta_set_recursive_next_hop() acquires hostentry from hostcache and fills
 * rta->hostentry field.  New hostentry has zero use count. Cached rta locks its
 * hostentry (increases its use count), uncached rta does not lock it. Hostentry
 * with zero use count is removed asynchronously during host cache update,
 * therefore it is safe to hold such hostentry temorarily. Hostentry holds a
 * lock for a 'source' rta, mainly to share multipath nexthops.
 *
 * There is no need to hold a lock for hostentry->dep table, because that table
 * contains routes responsible for that hostentry, and therefore is non-empty if
 * given hostentry has non-zero use count. If the hostentry has zero use count,
 * the entry is removed before dep is referenced.
 *
 * The protocol responsible for routes with recursive next hops should hold a
 * lock for a 'source' table governing that routes (argument tab to
 * rta_set_recursive_next_hop()), because its routes reference hostentries
 * (through rta) related to the governing table. When all such routes are
 * removed, rtas are immediately removed achieving zero uc. Then the 'source'
 * table lock could be immediately released, although hostentries may still
 * exist - they will be freed together with the 'source' table.
 */

static inline void rt_lock_hostentry(struct hostentry *he) { if (he) he->uc++; }
static inline void rt_unlock_hostentry(struct hostentry *he) { if (he) he->uc--; }

/*
 *	Default protocol preferences
 */

#define DEF_PREF_DIRECT		240	/* Directly connected */
#define DEF_PREF_STATIC		200	/* Static route */
#define DEF_PREF_OSPF		150	/* OSPF intra-area, inter-area and type 1 external routes */
#define DEF_PREF_BABEL		130	/* Babel */
#define DEF_PREF_RIP		120	/* RIP */
#define DEF_PREF_BGP		100	/* BGP */
#define DEF_PREF_RPKI		100	/* RPKI */
#define DEF_PREF_INHERITED	10	/* Routes inherited from other routing daemons */

/*
 *	Route Origin Authorization
 */

#define ROA_UNKNOWN	0
#define ROA_VALID	1
#define ROA_INVALID	2

#endif
