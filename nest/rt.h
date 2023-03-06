/*
 *	BIRD Internet Routing Daemon -- Routing Table
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2019--2021 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_NEST_RT_H_
#define _BIRD_NEST_RT_H_

#include "lib/lists.h"
#include "lib/bitmap.h"
#include "lib/resource.h"
#include "lib/net.h"
#include "lib/type.h"
#include "lib/fib.h"
#include "lib/route.h"
#include "lib/event.h"
#include "lib/rcu.h"
#include "lib/io-loop.h"
#include "lib/settle.h"

#include <stdatomic.h>

struct ea_list;
struct protocol;
struct proto;
struct channel;
struct rte_src;
struct hostcache;
struct symbol;
struct timer;
struct filter;
struct f_trie;
struct f_trie_walk_state;
struct cli;

struct rt_cork_threshold {
  u64 low, high;
};

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
  union rtable *table;
  struct proto_config *krt_attached;	/* Kernel syncer attached to this table */
  uint addr_type;			/* Type of address data stored in table (NET_*) */
  uint gc_threshold;			/* Maximum number of operations before GC is run */
  uint gc_period;			/* Approximate time between two consecutive GC runs */
  byte sorted;				/* Routes of network are sorted according to rte_better() */
  byte trie_used;			/* Rtable has attached trie */
  byte debug;				/* Whether to log */
  struct rt_cork_threshold cork_threshold;	/* Cork threshold values */
  struct settle_config export_settle;	/* Export announcement settler */
  struct settle_config export_rr_settle;/* Export announcement settler config valid when any
					   route refresh is running */
};

struct rt_export_hook;
struct rt_export_request;
struct rt_exporter;

struct rt_exporter_class {
  void (*start)(struct rt_exporter *, struct rt_export_request *);
  void (*stop)(struct rt_export_hook *);
  void (*done)(void *_rt_export_hook);
};

struct rt_exporter {
  const struct rt_exporter_class *class;
  pool *rp;
  list hooks;				/* Registered route export hooks */
  uint addr_type;			/* Type of address data exported (NET_*) */
};

struct rt_table_exporter {
  struct rt_exporter e;
  list pending;				/* List of packed struct rt_pending_export */

  struct rt_pending_export *first;	/* First export to announce */
  u64 next_seq;				/* The next export will have this ID */
};

extern uint rtable_max_id;

DEFINE_DOMAIN(rtable);

/* The public part of rtable structure */
#define RTABLE_PUBLIC \
    resource r;											\
    node n;				/* Node in list of all tables */			\
    char *name;				/* Name of this table */				\
    uint addr_type;			/* Type of address data stored in table (NET_*) */	\
    uint id;				/* Integer table ID for fast lookup */			\
    DOMAIN(rtable) lock;		/* Lock to take to access the private parts */		\
    struct rtable_config *config;	/* Configuration of this table */			\
    struct birdloop *loop;		/* Service thread */					\

/* The complete rtable structure */
struct rtable_private {
  /* Once more the public part */
  RTABLE_PUBLIC;

  /* Here the private items not to be accessed without locking */
  pool *rp;				/* Resource pool to allocate everything from, including itself */
  struct slab *rte_slab;		/* Slab to allocate route objects */
  struct fib fib;
  struct f_trie *trie;			/* Trie of prefixes defined in fib */
  int use_count;			/* Number of protocols using this table */
  u32 rt_count;				/* Number of routes in the table */

  list imports;				/* Registered route importers */
  struct rt_table_exporter exporter;	/* Exporter API structure */

  struct hmap id_map;
  struct hostcache *hostcache;
  struct config *deleted;		/* Table doesn't exist in current configuration,
					 * delete as soon as use_count becomes 0 and remove
					 * obstacle from this routing table.
					 */
  struct event *nhu_uncork_event;	/* Helper event to schedule NHU on uncork */
  struct settle export_settle;		/* Export batching settle timer */
  struct timer *prune_timer;		/* Timer for periodic pruning / GC */
  struct birdloop_flag_handler fh;	/* Handler for simple events */
  btime last_rt_change;			/* Last time when route changed */
  btime gc_time;			/* Time of last GC */
  uint gc_counter;			/* Number of operations since last GC */
  uint rr_counter;			/* Number of currently running route refreshes,
					   in fact sum of (stale_set - stale_pruned) over all importers
					   + one for each TIS_FLUSHING importer */
  uint wait_counter;			/* Number of imports in TIS_WAITING state */
  byte prune_state;			/* Table prune state, 1 -> scheduled, 2-> running */
  byte prune_trie;			/* Prune prefix trie during next table prune */
  byte imports_flushing;		/* Some imports are being flushed right now */
  byte nhu_state;			/* Next Hop Update state */
  byte nhu_corked;			/* Next Hop Update is corked with this state */
  byte export_used;			/* Pending Export pruning is scheduled */
  byte cork_active;			/* Cork has been activated */
  struct rt_cork_threshold cork_threshold;	/* Threshold for table cork */
  struct fib_iterator prune_fit;	/* Rtable prune FIB iterator */
  struct fib_iterator nhu_fit;		/* Next Hop Update FIB iterator */
  struct f_trie *trie_new;		/* New prefix trie defined during pruning */
  struct f_trie *trie_old;		/* Old prefix trie waiting to be freed */
  u32 trie_lock_count;			/* Prefix trie locked by walks */
  u32 trie_old_lock_count;		/* Old prefix trie locked by walks */
  struct tbf rl_pipe;			/* Rate limiting token buffer for pipe collisions */

  struct f_trie *flowspec_trie;		/* Trie for evaluation of flowspec notifications */
};

/* The final union private-public rtable structure */
typedef union rtable {
  struct {
    RTABLE_PUBLIC;
  };
  struct rtable_private priv;
} rtable;

#define RT_IS_LOCKED(tab)	DOMAIN_IS_LOCKED(rtable, (tab)->lock)

#define RT_LOCK(tab)	({ LOCK_DOMAIN(rtable, (tab)->lock); &(tab)->priv; })
#define RT_UNLOCK(tab)	UNLOCK_DOMAIN(rtable, (tab)->lock)
#define RT_PRIV(tab)	({ ASSERT_DIE(RT_IS_LOCKED((tab))); &(tab)->priv; })
#define RT_PUB(tab)	SKIP_BACK(rtable, priv, tab)

#define RT_LOCKED(tpub, tpriv) for (struct rtable_private *tpriv = RT_LOCK(tpub); tpriv; RT_UNLOCK(tpriv), (tpriv = NULL))
#define RT_RETURN(tpriv, ...) do { RT_UNLOCK(tpriv); return __VA_ARGS__; } while (0)

#define RT_PRIV_SAME(tpriv, tpub)	(&(tpub)->priv == (tpriv))

/* Flags for birdloop_flag() */
#define RTF_CLEANUP	1
#define RTF_NHU		2
#define RTF_EXPORT	4
#define RTF_DELETE	8

extern struct rt_cork {
  _Atomic uint active;
  event_list queue;
  event run;
} rt_cork;

static inline void rt_cork_acquire(void)
{
  atomic_fetch_add_explicit(&rt_cork.active, 1, memory_order_acq_rel);
}

static inline void rt_cork_release(void)
{
  if (atomic_fetch_sub_explicit(&rt_cork.active, 1, memory_order_acq_rel) == 1)
  {
    synchronize_rcu();
    ev_send(&global_work_list, &rt_cork.run);
  }
}

static inline int rt_cork_check(event *e)
{
  rcu_read_lock();

  int corked = (atomic_load_explicit(&rt_cork.active, memory_order_acquire) > 0);
  if (corked)
    ev_send(&rt_cork.queue, e);

  rcu_read_unlock();

  return corked;
}


typedef struct network {
  struct rte_storage *routes;		/* Available routes for this network */
  struct rt_pending_export *first, *last;
  struct fib_node n;			/* FIB flags reserved for kernel syncer */
} net;

struct rte_storage {
  struct rte_storage *next;		/* Next in chain */
  struct rte rte;			/* Route data */
};

#define RTE_COPY(r)		((r) ? (r)->rte : (rte) {})
#define RTE_COPY_VALID(r)	(((r) && (rte_is_valid(&(r)->rte))) ? (r)->rte : (rte) {})
#define RTE_OR_NULL(r)		((r) ? &((r)->rte) : NULL)
#define RTE_VALID_OR_NULL(r)	(((r) && (rte_is_valid(&(r)->rte))) ? &((r)->rte) : NULL)

/* Table-channel connections */

struct rt_import_request {
  struct rt_import_hook *hook;		/* The table part of importer */
  char *name;
  u8 trace_routes;

  event_list *list;			/* Where to schedule announce events */

  void (*dump_req)(struct rt_import_request *req);
  void (*log_state_change)(struct rt_import_request *req, u8 state);
  /* Preimport is called when the @new route is just-to-be inserted, replacing @old.
   * Return a route (may be different or modified in-place) to continue or NULL to withdraw. */
  int (*preimport)(struct rt_import_request *req, struct rte *new, struct rte *old);
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

  u64 flush_seq;			/* Table export seq when the channel announced flushing */
  btime last_state_change;		/* Time of last state transition */

  u8 import_state;			/* IS_* */
  u8 stale_set;				/* Set this stale_cycle to imported routes */
  u8 stale_valid;			/* Routes with this stale_cycle and bigger are considered valid */
  u8 stale_pruned;			/* Last prune finished when this value was set at stale_valid */
  u8 stale_pruning;			/* Last prune started when this value was set at stale_valid */

  void (*stopped)(struct rt_import_request *);	/* Stored callback when import is stopped */
  event announce_event;			/* This event announces table updates */
};

struct rt_pending_export {
  struct rt_pending_export * _Atomic next;	/* Next export for the same destination */
  struct rte_storage *new, *new_best, *old, *old_best;
  u64 seq;				/* Sequential ID (table-local) of the pending export */
};

struct rt_export_request {
  struct rt_export_hook *hook;		/* Table part of the export */
  char *name;
  const net_addr *addr;			/* Network prefilter address */
  u8 trace_routes;
  u8 addr_mode;				/* Network prefilter mode (TE_ADDR_*) */

  event_list *list;			/* Where to schedule export events */

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
  struct rt_exporter *table;		/* The connected table */

  pool *pool;

  struct rt_export_request *req;	/* The requestor */

  struct rt_export_stats {
    /* Export - from core to protocol */
    u32 updates_received;		/* Number of route updates received */
    u32 withdraws_received;		/* Number of route withdraws received */
  } stats;

  btime last_state_change;		/* Time of last state transition */

  _Atomic u8 export_state;		/* Route export state (TES_*, see below) */
  struct event event;			/* Event running all the export operations */

  struct bmap seq_map;			/* Keep track which exports were already procesed */

  void (*stopped)(struct rt_export_request *);	/* Stored callback when export is stopped */
};

struct rt_table_export_hook {
  union {
    struct rt_export_hook h;
    struct {				/* Overriding the parent structure beginning */
      node _n;
      struct rt_table_exporter *table;
    };
  };
  
  union {
    struct fib_iterator feed_fit;		/* Routing table iterator used during feeding */
    struct {
      struct f_trie_walk_state *walk_state;	/* Iterator over networks in trie */
      struct f_trie *walk_lock;			/* Locked trie for walking */
      union {					/* Last net visited but not processed */
	net_addr walk_last;
	net_addr_ip4 walk_last_ip4;
	net_addr_ip6 walk_last_ip6;
      };
    };
  };

  struct rt_pending_export *_Atomic last_export;/* Last export processed */
  struct rt_pending_export *rpe_next;	/* Next pending export to process */

  u8 refeed_pending;			/* Refeeding and another refeed is scheduled */
  u8 feed_type;				/* Which feeding method is used (TFT_*, see below) */

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

/* Value of addr_mode */
#define TE_ADDR_NONE	0		/* No address matching */
#define TE_ADDR_EQUAL	1		/* Exact query - show route <addr> */
#define TE_ADDR_FOR	2		/* Longest prefix match - show route for <addr> */
#define TE_ADDR_IN	3		/* Interval query - show route in <addr> */


#define TFT_FIB		1
#define TFT_TRIE	2
#define TFT_HASH	3

void rt_request_import(rtable *tab, struct rt_import_request *req);
void rt_request_export(rtable *tab, struct rt_export_request *req);
void rt_request_export_other(struct rt_exporter *tab, struct rt_export_request *req);

void rt_export_once(struct rt_exporter *tab, struct rt_export_request *req);

void rt_stop_import(struct rt_import_request *, void (*stopped)(struct rt_import_request *));
void rt_stop_export(struct rt_export_request *, void (*stopped)(struct rt_export_request *));

const char *rt_import_state_name(u8 state);
const char *rt_export_state_name(u8 state);

static inline u8 rt_import_get_state(struct rt_import_hook *ih) { return ih ? ih->import_state : TIS_DOWN; }
static inline u8 rt_export_get_state(struct rt_export_hook *eh) { return eh ? eh->export_state : TES_DOWN; }

void rt_set_export_state(struct rt_export_hook *hook, u8 state);

void rte_import(struct rt_import_request *req, const net_addr *net, rte *new, struct rte_src *src);

/*
 * For table export processing
 */

/* Get next rpe. If src is given, it must match. */
struct rt_pending_export *rpe_next(struct rt_pending_export *rpe, struct rte_src *src);

/* Walk all rpe's */
#define RPE_WALK(first, it, src) \
  for (struct rt_pending_export *it = (first); it; it = rpe_next(it, (src)))

/* Mark the pending export processed */
void rpe_mark_seen(struct rt_export_hook *hook, struct rt_pending_export *rpe);

#define rpe_mark_seen_all(hook, first, src) \
  RPE_WALK((first), _rpe, (src)) rpe_mark_seen((hook), _rpe)

/* Get pending export seen status */
int rpe_get_seen(struct rt_export_hook *hook, struct rt_pending_export *rpe);

/*
 * For rt_export_hook and rt_exporter inheritance
 */

void rt_init_export(struct rt_exporter *re, struct rt_export_hook *hook);
struct rt_export_hook *rt_alloc_export(struct rt_exporter *re, uint size);
void rt_stop_export_common(struct rt_export_hook *hook);
void rt_export_stopped(struct rt_export_hook *hook);
void rt_exporter_init(struct rt_exporter *re);

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

/*
 * Next hop update data structures
 */

#define NHU_CLEAN	0
#define NHU_SCHEDULED	1
#define NHU_RUNNING	2
#define NHU_DIRTY	3

struct hostentry {
  node ln;
  ip_addr addr;				/* IP address of host, part of key */
  ip_addr link;				/* (link-local) IP address of host, used as gw
					   if host is directly attached */
  rtable *tab;				/* Dependent table, part of key */
  struct hostentry *next;		/* Next in hash chain */
  unsigned hash_key;			/* Hash key */
  unsigned uc;				/* Use count */
  ea_list *src;				/* Source attributes */
  byte nexthop_linkable;		/* Nexthop list is completely non-device */
  u32 igp_metric;			/* Chosen route IGP metric */
};

struct hostcache {
  slab *slab;				/* Slab holding all hostentries */
  struct hostentry **hash_table;	/* Hash table for hostentries */
  unsigned hash_order, hash_shift;
  unsigned hash_max, hash_min;
  unsigned hash_items;
  linpool *lp;				/* Linpool for trie */
  struct f_trie *trie;			/* Trie of prefixes that might affect hostentries */
  list hostentries;			/* List of all hostentries */
  event update;
  struct rt_export_request req;		/* Notifier */
};

struct rt_flowspec_link {
  rtable *src;
  rtable *dst;
  u32 uc;
  struct rt_export_request req;
};

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
void rt_postconfig(struct config *);
void rt_commit(struct config *new, struct config *old);
void rt_lock_table_priv(struct rtable_private *, const char *file, uint line);
void rt_unlock_table_priv(struct rtable_private *, const char *file, uint line);
static inline void rt_lock_table_pub(rtable *t, const char *file, uint line)
{ RT_LOCKED(t, tt) rt_lock_table_priv(tt, file, line); }
static inline void rt_unlock_table_pub(rtable *t, const char *file, uint line)
{ RT_LOCKED(t, tt) rt_unlock_table_priv(tt, file, line); }

#define rt_lock_table(t)	_Generic((t),  rtable *: rt_lock_table_pub, \
				struct rtable_private *: rt_lock_table_priv)((t), __FILE__, __LINE__)
#define rt_unlock_table(t)	_Generic((t),  rtable *: rt_unlock_table_pub, \
				struct rtable_private *: rt_unlock_table_priv)((t), __FILE__, __LINE__)

struct f_trie * rt_lock_trie(struct rtable_private *tab);
void rt_unlock_trie(struct rtable_private *tab, struct f_trie *trie);
void rt_flowspec_link(rtable *src, rtable *dst);
void rt_flowspec_unlink(rtable *src, rtable *dst);
rtable *rt_setup(pool *, struct rtable_config *);

static inline net *net_find(struct rtable_private *tab, const net_addr *addr) { return (net *) fib_find(&tab->fib, addr); }
static inline net *net_find_valid(struct rtable_private *tab, const net_addr *addr)
{ net *n = net_find(tab, addr); return (n && n->routes && rte_is_valid(&n->routes->rte)) ? n : NULL; }
static inline net *net_get(struct rtable_private *tab, const net_addr *addr) { return (net *) fib_get(&tab->fib, addr); }
net *net_route(struct rtable_private *tab, const net_addr *n);
int rt_examine(rtable *t, net_addr *a, struct channel *c, const struct filter *filter);
rte *rt_export_merged(struct channel *c, rte ** feed, uint count, linpool *pool, int silent);
void rt_refresh_begin(struct rt_import_request *);
void rt_refresh_end(struct rt_import_request *);
void rt_modify_stale(rtable *t, struct rt_import_request *);
void rt_schedule_prune(struct rtable_private *t);
void rte_dump(struct rte_storage *);
void rt_dump(rtable *);
void rt_dump_all(void);
void rt_dump_hooks(rtable *);
void rt_dump_hooks_all(void);
int rt_reload_channel(struct channel *c);
void rt_reload_channel_abort(struct channel *c);
void rt_refeed_channel(struct channel *c);
void rt_prune_sync(rtable *t, int all);
struct rtable_config *rt_new_table(struct symbol *s, uint addr_type);
void rt_new_default_table(struct symbol *s);
struct rtable_config *rt_get_default_table(struct config *cf, uint addr_type);

static inline int rt_is_ip(rtable *tab)
{ return (tab->addr_type == NET_IP4) || (tab->addr_type == NET_IP6); }

static inline int rt_is_vpn(rtable *tab)
{ return (tab->addr_type == NET_VPN4) || (tab->addr_type == NET_VPN6); }

static inline int rt_is_roa(rtable *tab)
{ return (tab->addr_type == NET_ROA4) || (tab->addr_type == NET_ROA6); }

static inline int rt_is_flow(rtable *tab)
{ return (tab->addr_type == NET_FLOW4) || (tab->addr_type == NET_FLOW6); }


/* Default limit for ECMP next hops, defined in sysdep code */
extern const int rt_default_ecmp;

struct rt_show_data_rtable {
  node n;
  const char *name;
  struct rt_exporter *table;
  struct channel *export_channel;
  struct channel *prefilter;
  struct krt_proto *kernel;
};

struct rt_show_data {
  struct cli *cli;			/* Pointer back to the CLI */
  net_addr *addr;
  list tables;
  struct rt_show_data_rtable *tab;	/* Iterator over table list */
  struct rt_show_data_rtable *last_table; /* Last table in output */
  struct rt_export_request req;		/* Export request in use */
  int verbose, tables_defined_by;
  const struct filter *filter;
  struct proto *show_protocol;
  struct proto *export_protocol;
  struct channel *export_channel;
  struct config *running_on_config;
  struct rt_export_hook *kernel_export_hook;
  int export_mode, addr_mode, primary_only, filtered, stats;

  int net_counter, rt_counter, show_counter, table_counter;
  int net_counter_last, rt_counter_last, show_counter_last;
  int show_counter_last_flush;
};

void rt_show(struct rt_show_data *);
struct rt_show_data_rtable * rt_show_add_exporter(struct rt_show_data *d, struct rt_exporter *t, const char *name);
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

/* Host entry: Resolve hook for recursive nexthops */
extern struct ea_class ea_gen_hostentry;
struct hostentry_adata {
  adata ad;
  struct hostentry *he;
  u32 labels[0];
};

void
ea_set_hostentry(ea_list **to, rtable *dep, rtable *tab, ip_addr gw, ip_addr ll, u32 lnum, u32 labels[lnum]);

void ea_show_hostentry(const struct adata *ad, byte *buf, uint size);
void ea_show_nexthop_list(struct cli *c, struct nexthop_adata *nhad);

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
#define DEF_PREF_UNKNOWN	0	/* Routes with no preference set */

/*
 *	Route Origin Authorization
 */

#define ROA_UNKNOWN	0
#define ROA_VALID	1
#define ROA_INVALID	2

int net_roa_check(rtable *tab, const net_addr *n, u32 asn);

#endif
