/*
 *	BIRD Internet Routing Daemon -- Routing Table
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2019--2024 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_ROUTE_H_
#define _BIRD_ROUTE_H_

#include "lib/lists.h"
#include "lib/tlists.h"
#include "lib/lockfree.h"
#include "lib/bitmap.h"
#include "lib/resource.h"
#include "lib/net.h"
#include "lib/netindex.h"
#include "lib/obstacle.h"
#include "lib/type.h"
#include "lib/fib.h"
#include "lib/route.h"
#include "lib/event.h"
#include "lib/rcu.h"
#include "lib/io-loop.h"
#include "lib/settle.h"

#include "filter/data.h"

#include "conf/conf.h"

#include <stdatomic.h>

struct ea_list;
struct adata;
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
  u32 debug;				/* Debugging flags (D_*) */
  byte sorted;				/* Routes of network are sorted according to rte_better() */
  byte trie_used;			/* Rtable has attached trie */
  struct rt_cork_threshold {
    u64 low, high;
  } cork_threshold;			/* Cork threshold values */
  struct settle_config export_settle;	/* Export announcement settler */
  struct settle_config export_rr_settle;/* Export announcement settler config valid when any
					   route refresh is running */
  struct settle_config digest_settle;	/* Settle times for digests */
  struct rtable_config *roa_aux_table;	/* Auxiliary table config for ROA connections */
  struct rt_stream_config {
    struct rtable_config *src;
    void (*setup)(union rtable *);
    void (*stop)(union rtable *);
  } master;				/* Data source (this table is aux) */
  struct thread_group_config *thread_group;	/* Thread group to assign loops to */
};

/*
 *	Route export journal
 *
 *	The journal itself is held in struct rt_exporter.
 *	Workflow:
 *	  (1) Initialize by rt_exporter_init()
 *	  (2) Push data by rt_exporter_push() (the export item is copied)
 *	  (3) Shutdown by rt_exporter_shutdown(), event is called after cleanup
 *
 *	Subscribers:
 *	  (1) Initialize by rt_export_subscribe()
 *	  (2a) Get data by rt_export_get();
 *	  (2b) Release data after processing by rt_export_release()
 *	  (3) Request refeed by rt_export_refeed()
 *	  (4) Unsubscribe by rt_export_unsubscribe()
 */

struct rt_export_request {
  /* Formal name */
  char *name;

  /* Memory */
  pool *pool;

  /* State information */
  enum rt_export_state {
#define RT_EXPORT_STATES \
    DOWN, \
    FEEDING, \
    PARTIAL, \
    READY, \
    STOP, \

#define RT_EXPORT_STATES_ENUM_HELPER(p) TES_##p,
    MACRO_FOREACH(RT_EXPORT_STATES_ENUM_HELPER, RT_EXPORT_STATES)
    TES_MAX
#undef RT_EXPORT_STATES_ENUM_HELPER
  } _Atomic export_state;
  btime last_state_change;

  /* Table feeding contraption */
  struct rt_export_feeder {
    /* Formal name */
    const char *name;

    /* Enlisting */
    struct rt_exporter * _Atomic exporter;
    DOMAIN(rtable) domain;			/* Lock this instead of RCU */

    /* Prefiltering, useful for more scenarios */
    struct rt_prefilter {
      /* Network prefilter mode (TE_ADDR_*) */
      enum {
	TE_ADDR_NONE = 0,	/* No address matching */
	TE_ADDR_EQUAL,		/* Exact query - show route <addr> */
	TE_ADDR_FOR,		/* Longest prefix match - show route for <addr> */
	TE_ADDR_IN,		/* Interval query - show route in <addr> */
	TE_ADDR_TRIE,		/* Query defined by trie */
	TE_ADDR_HOOK,		/* Query processed by supplied custom hook */
      } mode;

      union {
	const struct f_trie *trie;
	const net_addr *addr;
	int (*hook)(const struct rt_prefilter *, const net_addr *);
      };
    } prefilter;

#define TLIST_PREFIX	rt_export_feeder
#define TLIST_TYPE	struct rt_export_feeder
#define TLIST_ITEM	n
#define TLIST_WANT_WALK
#define TLIST_WANT_ADD_TAIL

    /* Feeding itself */
    u32 feed_index;				/* Index of the feed in progress */
    u32 (*next_feed_index)(struct rt_export_feeder *, u32 try_this);
    struct rt_feeding_request {
      struct rt_feeding_request *next;		/* Next in request chain */
      void (*done)(struct rt_feeding_request *);/* Called when this refeed finishes */
      struct rt_prefilter prefilter;		/* Reload only matching nets */
    } *feeding, *feed_pending;
    TLIST_DEFAULT_NODE;
    u8 trace_routes;
  } feeder;

  /* Regular updates */
  struct bmap seq_map;		/* Which lfjour items are already processed */
  struct bmap feed_map;		/* Which nets were already fed (for initial feeding) */
  struct lfjour_recipient r;
  struct rt_export_union *cur;

  /* Statistics */
  struct rt_export_stats {
    u32 updates_received;	/* Number of route updates received */
    u32 withdraws_received;	/* Number of route withdraws received */
  } stats;

  /* Tracing */
  u8 trace_routes;
  void (*dump)(struct rt_export_request *req);
  void (*fed)(struct rt_export_request *req);
};

#include "lib/tlists.h"

struct rt_export_union {
  enum rt_export_kind {
    RT_EXPORT_STOP = 1,
    RT_EXPORT_FEED,
    RT_EXPORT_UPDATE,
  } kind;
  const struct rt_export_item {
    LFJOUR_ITEM_INHERIT(li);		/* Member of lockfree journal */
    char data[0];			/* Memcpy helper */
    const rte *new, *old;		/* Route update */
  } *update;
  const struct rt_export_feed {
    uint count_routes, count_exports;
    struct netindex *ni;
    rte *block;
    u64 *exports;
    char data[0];
  } *feed;
  struct rt_export_request *req;
};

struct rt_exporter {
  struct lfjour journal;			/* Journal for update keeping */
  TLIST_LIST(rt_export_feeder) feeders;		/* List of active feeder structures */
  bool _Atomic feeders_lock;			/* Spinlock for the above list */
  u8 trace_routes;				/* Debugging flags (D_*) */
  u8 net_type;					/* Which net this exporter provides */
  DOMAIN(rtable) domain;			/* Lock this instead of RCU */
  u32 _Atomic max_feed_index;			/* Stop feeding at this index */
  const char *name;				/* Name for logging */
  netindex_hash *netindex;			/* Table for net <-> id conversion */
  void (*stopped)(struct rt_exporter *);	/* Callback when exporter can stop */
  void (*cleanup_done)(struct rt_exporter *, u64 end);	/* Callback when cleanup has been done */
  struct rt_export_feed *(*feed_net)(struct rt_exporter *, struct rcu_unwinder *, u32, struct bmap *, bool (*)(struct rt_export_feeder *, const net_addr *), struct rt_export_feeder *, const struct rt_export_item *first);
  void (*feed_cleanup)(struct rt_exporter *, struct rt_export_feeder *);
};

extern struct rt_export_feed rt_feed_index_out_of_range;

/* Exporter API */
void rt_exporter_init(struct rt_exporter *, struct settle_config *);
struct rt_export_item *rt_exporter_push(struct rt_exporter *, const struct rt_export_item *);
struct rt_export_feed *rt_alloc_feed(uint routes, uint exports);
void rt_exporter_shutdown(struct rt_exporter *, void (*stopped)(struct rt_exporter *));

void rt_exporter_dump(struct dump_request *, struct rt_exporter *);
static inline struct resmem rt_exporter_memsize(struct rt_exporter *e)
{ return lfjour_memsize(&e->journal); }

/* Standalone feeds */
void rt_feeder_subscribe(struct rt_exporter *, struct rt_export_feeder *);
void rt_feeder_unsubscribe(struct rt_export_feeder *);
void rt_export_refeed_feeder(struct rt_export_feeder *, struct rt_feeding_request *);

struct rt_export_feed *rt_export_next_feed(struct rt_export_feeder *, struct bmap *seen);
#define RT_FEED_WALK(_feeder, _f)	\
  for (const struct rt_export_feed *_f; _f = rt_export_next_feed(_feeder, NULL); ) \

static inline bool rt_export_feed_active(struct rt_export_feeder *f)
{ return !!atomic_load_explicit(&f->exporter, memory_order_acquire); }

/* Full blown exports */
void rtex_export_subscribe(struct rt_exporter *, struct rt_export_request *);
void rtex_export_unsubscribe(struct rt_export_request *);

const struct rt_export_union * rt_export_get(struct rt_export_request *);
void rt_export_release(const struct rt_export_union *);
void rt_export_retry_later(const struct rt_export_union *);
void rt_export_processed(struct rt_export_request *, u64);
void rt_export_refeed_request(struct rt_export_request *rer, struct rt_feeding_request *rfr);

static inline enum rt_export_state rt_export_get_state(struct rt_export_request *r)
{ return atomic_load_explicit(&r->export_state, memory_order_acquire); }
const char *rt_export_state_name(enum rt_export_state state);

static inline void rt_export_walk_cleanup(const struct rt_export_union **up)
{
  if (*up)
    rt_export_release(*up);
}

#define RT_EXPORT_WALK(_reader, _u)	\
  for (CLEANUP(rt_export_walk_cleanup) const struct rt_export_union *_u;\
      _u = rt_export_get(_reader);					\
      rt_export_release(_u))						\

/* Convenince common call to request refeed */
#define rt_export_refeed(h, r)	_Generic((h), \
    struct rt_export_feeder *: rt_export_refeed_feeder, \
    struct rt_export_request *: rt_export_refeed_request, \
    void *: bug)(h, r)

/* Subscription to regular table exports needs locking */
#define rt_export_subscribe(_t, _kind, f) do { \
  RT_LOCKED(_t, tp) { \
    rt_lock_table(tp); \
    rtex_export_subscribe(&tp->export_##_kind, f); \
  }} while (0) \

#define rt_export_unsubscribe(_kind, _fx) do { \
  struct rt_export_request *_f = _fx; \
  struct rt_exporter *e = atomic_load_explicit(&_f->feeder.exporter, memory_order_acquire); \
  RT_LOCKED(SKIP_BACK(rtable, export_##_kind, e), _tp) { \
    rtex_export_unsubscribe(_f); \
    rt_unlock_table(_tp); \
  }} while (0) \

static inline int rt_prefilter_net(const struct rt_prefilter *p, const net_addr *n)
{
  switch (p->mode)
  {
    case TE_ADDR_NONE:	return 1;
    case TE_ADDR_IN:	return net_in_netX(n, p->addr);
    case TE_ADDR_EQUAL:	return net_equal(n, p->addr);
    case TE_ADDR_FOR:	return net_in_netX(p->addr, n);
    case TE_ADDR_TRIE:	return trie_match_net(p->trie, n);
    case TE_ADDR_HOOK:	return p->hook(p, n);
  }

  bug("Crazy prefilter application attempt failed wildly.");
}

static inline bool
rt_net_is_feeding_feeder(struct rt_export_feeder *ref, const net_addr *n)
{
  if (!rt_prefilter_net(&ref->prefilter, n))
    return 0;

  if (!ref->feeding)
    return 1;

  for (struct rt_feeding_request *rfr = ref->feeding; rfr; rfr = rfr->next)
    if (rt_prefilter_net(&rfr->prefilter, n))
      return 1;

  return 0;
}

static inline bool
rt_net_is_feeding_request(struct rt_export_request *req, const net_addr *n)
{
  struct netindex *ni = NET_TO_INDEX(n);
  switch (rt_export_get_state(req))
  {
    case TES_PARTIAL:
    case TES_FEEDING:
      break;

    default:
      return 0;
  }

  /* Already fed */
  if (bmap_test(&req->feed_map, ni->index))
    return 0;

  return rt_net_is_feeding_feeder(&req->feeder, n);
}

#define rt_net_is_feeding(h, n)	_Generic((h), \
    struct rt_export_feeder *: rt_net_is_feeding_feeder, \
    struct rt_export_request *: rt_net_is_feeding_request, \
    void *: bug)(h, n)


/*
 *	The original rtable
 *
 *	To be kept as is for now until we refactor the new structures out of BGP Attrs.
 */


struct rt_uncork_callback {
  event ev;
  callback cb;
};

struct rt_export_hook;

extern uint rtable_max_id;

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
    netindex_hash *netindex;		/* Prefix index for this table */			\
    struct network * _Atomic routes;	/* Actual route objects in the table */			\
    _Atomic u32 routes_block_size;	/* Size of the route object pointer block */		\
    struct f_trie * _Atomic trie;	/* Trie of prefixes defined in fib */			\
    event *hcu_event;			/* Hostcache updater */					\
    struct rt_exporter export_all;	/* Route export journal for all routes */		\
    struct rt_exporter export_best;	/* Route export journal for best routes */		\

/* The complete rtable structure */
struct rtable_private {
  /* Once more the public part */
  struct { RTABLE_PUBLIC; };
  struct rtable_private **locked_at;

  /* Here the private items not to be accessed without locking */
  pool *rp;				/* Resource pool to allocate everything from, including itself */
  struct slab *rte_slab;		/* Slab to allocate route objects */
  int use_count;			/* Number of protocols using this table */
  u32 rt_count;				/* Number of routes in the table */
  u32 net_count;			/* Number of nets in the table */
  u32 debug;				/* Debugging flags (D_*) */

  list imports;				/* Registered route importers */

  TLIST_STRUCT_DEF(rt_flowspec_link, struct rt_flowspec_link) flowspec_links;	/* Links serving flowspec reload */

  struct hmap id_map;
  struct hostcache *hostcache;
  config_ref deleted;			/* Table doesn't exist in current configuration,
					 * delete as soon as use_count becomes 0 and remove
					 * obstacle from this routing table.
					 */

  struct deferred_call *reconf_end;	/* Reconfiguration done callback */
  struct rt_export_request best_req;	/* Internal request from best route announcement cleanup */
  struct rt_uncork_callback nhu_uncork;	/* Helper event to schedule NHU on uncork */
  struct rt_uncork_callback hcu_uncork;	/* Helper event to schedule HCU on uncork */
  struct timer *prune_timer;		/* Timer for periodic pruning / GC */
  struct event *prune_event;		/* Event for prune execution */
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
  u32 prune_index;			/* Rtable prune FIB iterator */
  u32 nhu_index;			/* Next Hop Update FIB iterator */
  event *nhu_event;			/* Nexthop updater */
  struct f_trie *trie_new;		/* New prefix trie defined during pruning */
  const struct f_trie *trie_old;	/* Old prefix trie waiting to be freed */
  u32 trie_lock_count;			/* Prefix trie locked by walks */
  u32 trie_old_lock_count;		/* Old prefix trie locked by walks */
  struct tbf rl_pipe;			/* Rate limiting token buffer for pipe collisions */

  struct f_trie *flowspec_trie;		/* Trie for evaluation of flowspec notifications */
  // struct mpls_domain *mpls_domain;	/* Label allocator for MPLS */
  u32 rte_free_deferred;		/* Counter of deferred rte_free calls */

  struct rt_digestor *export_digest;	/* Route export journal for digest tries */
  struct rt_stream *master;		/* Data source (this table is aux) */
};

/* The final union private-public rtable structure */
typedef union rtable {
  struct {
    RTABLE_PUBLIC;
  };
  struct rtable_private priv;
} rtable;

/* Define the lock cleanup function */
LOBJ_UNLOCK_CLEANUP(rtable, rtable);

#define RT_IS_LOCKED(tab)	LOBJ_IS_LOCKED((tab), rtable)
#define RT_LOCKED(tab, tp)	LOBJ_LOCKED((tab), tp, rtable, rtable)
#define RT_LOCK(tab, tp)	LOBJ_LOCK((tab), tp, rtable, rtable)

#define RT_UNLOCKED_TEMPORARILY(tab, tp)	LOBJ_UNLOCKED_TEMPORARILY((tab), tp, rtable, rtable)

#define RT_PUB(tab)	SKIP_BACK(rtable, priv, tab)

#define RT_UNCORKING	(1ULL << 44)

extern struct rt_cork {
  _Atomic u64 active;
  DOMAIN(resource) dom;
  event_list queue;
} rt_cork;

static inline void rt_cork_acquire(void)
{
  atomic_fetch_add_explicit(&rt_cork.active, 1, memory_order_acq_rel);
}

static inline void rt_cork_release(void)
{
  u64 upd = atomic_fetch_add_explicit(&rt_cork.active, RT_UNCORKING, memory_order_acq_rel) + RT_UNCORKING;

  /* Actualy released? */
  if ((upd >> 44) == (upd & (RT_UNCORKING - 1)))
  {
    LOCK_DOMAIN(resource, rt_cork.dom);
    synchronize_rcu();
    ev_run_list(&rt_cork.queue);
    UNLOCK_DOMAIN(resource, rt_cork.dom);
  }

  atomic_fetch_sub_explicit(&rt_cork.active, RT_UNCORKING + 1, memory_order_acq_rel);
}

void rt_cork_send_callback(void *_data);

static inline bool rt_cork_check(struct rt_uncork_callback *rcc)
{
  /* Wait until all uncorks have finished */
  while (1)
  {
    rcu_read_lock();

    /* Not corked */
    u64 corked = atomic_load_explicit(&rt_cork.active, memory_order_acquire);
    if (!corked)
    {
      rcu_read_unlock();
      return 0;
    }

    /* Yes, corked */
    if (corked < RT_UNCORKING)
    {
      if (!rcc->ev.hook)
      {
	rcc->ev.hook = rt_cork_send_callback;
	rcc->ev.data = rcc;
      }

      ev_send(&rt_cork.queue, &rcc->ev);
      rcu_read_unlock();
      return 1;
    }

    /* In progress, retry */
    rcu_read_unlock();
    birdloop_yield();
  }
}

struct rt_pending_export {
  struct rt_export_item it;
  struct rt_pending_export *_Atomic next;	/* Next export for the same net */
  u64 seq_all;					/* Interlink from BEST to ALL */
};

struct rt_net_pending_export {
  struct rt_pending_export * _Atomic first, * _Atomic last;
};

typedef struct network {
  struct rte_storage * _Atomic routes;		/* Available routes for this network */

  /* Uncleaned pending exports */
  struct rt_net_pending_export all;
  struct rt_net_pending_export best;
} net;

struct rte_storage {
  struct rte_storage * _Atomic next;		/* Next in chain */
  union {
    struct {
      RTE_IN_TABLE_WRITABLE;
    };
    const struct rte rte;			/* Route data */
  };
};

#define RTE_COPY(r)		((r) ? (r)->rte : (rte) {})
#define RTE_COPY_VALID(r)	(((r) && (rte_is_valid((r)))) ? *(r) : (rte) {})
#define RTE_OR_NULL(r)		((r) ? &((r)->rte) : NULL)
#define RTE_VALID_OR_NULL(r)	(((r) && (rte_is_valid((r)))) ? (r) : NULL)

#define RTES_WRITE(r)		(((r) != ((struct rte_storage *) 0)) ? ((struct rte *) &(r)->rte) : NULL)

#define RTE_GET_NETINDEX(e) NET_TO_INDEX((e)->net)

/* Table import */

struct rt_import_request {
  struct rt_import_hook *hook;		/* The table part of importer */
  char *name;
  u8 trace_routes;

  struct birdloop *loop;		/* Where to schedule cleanup event */

  void (*dump_req)(struct rt_import_request *req);
  void (*log_state_change)(struct rt_import_request *req, u8 state);
  /* Preimport is called when the @new route is just-to-be inserted, replacing @old.
   * Return a route (may be different or modified in-place) to continue or NULL to withdraw. */
  int (*preimport)(struct rt_import_request *req, struct rte *new, const struct rte *old);
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
  event cleanup_event;			/* Used to finally unhook the import from the table */
};


#define TIS_DOWN	0
#define TIS_UP		1
#define TIS_STOP	2
#define TIS_FLUSHING	3
#define TIS_WAITING	4
#define TIS_CLEARED	5
#define TIS_MAX		6


void rt_request_import(rtable *tab, struct rt_import_request *req);
void rt_stop_import(struct rt_import_request *, void (*stopped)(struct rt_import_request *));
const char *rt_import_state_name(u8 state);
static inline u8 rt_import_get_state(struct rt_import_hook *ih) { return ih ? ih->import_state : TIS_DOWN; }

void rte_import(struct rt_import_request *req, const net_addr *net, rte *new, struct rte_src *src);

/* When rtable is just a view / aggregate, this is the basis for its source */
struct rt_stream {
  struct rt_import_request dst;
  rtable *dst_tab;
};
	

#if 0
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

#define rpe_mark_seen_all(hook, first, last, src) do { \
  RPE_WALK((first), _rpe, (src)) { \
    rpe_mark_seen((hook), _rpe); \
    if (_rpe == last) break; \
  }} while (0)

/* Get pending export seen status */
int rpe_get_seen(struct rt_export_hook *hook, struct rt_pending_export *rpe);

#endif

/*
 * Channel export hooks. To be refactored out.
 */

int channel_preimport(struct rt_import_request *req, rte *new, const rte *old);


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
  rtable *owner;			/* Nexthop owner table */
  struct hostentry *next;		/* Next in hash chain */
  unsigned hash_key;			/* Hash key */
  u32 igp_metric;			/* Chosen route IGP metric */
  _Atomic u32 version;			/* Bumped on update */
  byte nexthop_linkable;		/* Nexthop list is completely non-device */
  ea_list * _Atomic src;		/* Source attributes */
  struct lfuc uc;			/* Use count */
};

struct hostcache {
  slab *slab;				/* Slab holding all hostentries */
  rtable *tab;				/* Parent routing table */
  struct hostentry **hash_table;	/* Hash table for hostentries */
  unsigned hash_order, hash_shift;
  unsigned hash_max, hash_min;
  unsigned hash_items;
  linpool *lp;				/* Linpool for trie */
  struct f_trie *trie;			/* Trie of prefixes that might affect hostentries */
  list hostentries;			/* List of all hostentries */
  struct rt_export_request req;		/* Notifier */
  event source_event;
};

struct rt_digestor {
  struct rt_export_request req;		/* Notifier from the table */
  struct lfjour	digest;			/* Digest journal of struct rt_digest */
  struct settle settle;			/* Settle timer before announcing digests */
  struct f_trie *trie;			/* Trie to be announced */
  rtable *tab;				/* Table this belongs to */
  event event;
};

struct rt_digest {
  LFJOUR_ITEM_INHERIT(li);
  struct f_trie *trie;			/* Trie marking all prefixes where ROA have changed */
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

const struct f_trie * rt_lock_trie(struct rtable_private *tab);
void rt_unlock_trie(struct rtable_private *tab, const struct f_trie *trie);
void rt_flowspec_link(rtable *src, rtable *dst);
void rt_flowspec_unlink(rtable *src, rtable *dst);
rtable *rt_setup(pool *, struct rtable_config *);
void rt_setup_digestor(struct rtable_private *tab);

struct rt_export_feed *rt_net_feed(rtable *t, const net_addr *a, const struct rt_pending_export *first);
rte rt_net_best(rtable *t, const net_addr *a);
int rt_examine(rtable *t, net_addr *a, struct channel *c, const struct filter *filter);
rte *rt_export_merged(struct channel *c, const struct rt_export_feed *feed, linpool *pool, int silent);
void rt_refresh_begin(struct rt_import_request *);
void rt_refresh_end(struct rt_import_request *);
void rt_schedule_prune(struct rtable_private *t);
void rte_dump(struct dump_request *, struct rte_storage *);
void rt_dump(struct dump_request *, rtable *);
void rt_dump_all(struct dump_request *);
void rt_dump_hooks(struct dump_request *, rtable *);
void rt_dump_hooks_all(struct dump_request *);
int rt_reload_channel(struct channel *c);
void rt_reload_channel_abort(struct channel *c);
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
  struct rt_exporter *exporter;
  struct channel *export_channel;
  struct channel *prefilter;
  struct krt_proto *kernel;
  struct rt_export_feeder req;		/* Export feeder in use */
};

struct rt_show_data {
  struct cli *cli;			/* Pointer back to the CLI */
  net_addr *addr;
  list tables;
  struct rt_show_data_rtable *tab;	/* Iterator over table list */
  struct rt_show_data_rtable *last_table; /* Last table in output */
  int verbose, tables_defined_by;
  struct timeformat tf_route;
  const struct filter *filter;
  struct proto *show_protocol;
  struct proto *export_protocol;
  struct channel *export_channel;
  OBSREF(struct config) running_on_config;
//  struct rt_export_hook *kernel_export_hook;
  int export_mode, addr_mode, primary_only, filtered, stats;

  int net_counter, rt_counter, show_counter, table_counter;
  int net_counter_last, rt_counter_last, show_counter_last;
  int show_counter_last_flush;
};

void rt_show(struct rt_show_data *);
struct rt_show_data_rtable * rt_show_add_table(struct rt_show_data *d, rtable *t);
struct rt_show_data_rtable * rt_show_add_exporter(struct rt_show_data *d, struct rt_exporter *e);

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
extern struct ea_class ea_gen_hostentry_version;
struct hostentry_adata {
  adata ad;
  struct hostentry *he;
  u32 labels[0];
};

#define HOSTENTRY_LABEL_COUNT(head)	(head->ad.length + sizeof(struct adata) - sizeof(struct hostentry_adata)) / sizeof(u32)

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
#define DEF_PREF_L3VPN_IMPORT	 80	/* L3VPN import -> lower than BGP */
#define DEF_PREF_L3VPN_EXPORT	120	/* L3VPN export -> higher than BGP */
#define DEF_PREF_INHERITED	10	/* Routes inherited from other routing daemons */
#define DEF_PREF_UNKNOWN	0	/* Routes with no preference set */

/*
 *	Route Origin Authorization
 */

#define ROA_UNKNOWN	0
#define ROA_VALID	1
#define ROA_INVALID	2

enum aspa_result {
  ASPA_UNKNOWN = 0,
  ASPA_VALID,
  ASPA_INVALID,
};

int net_roa_check(rtable *tab, const net_addr *n, u32 asn);
enum aspa_result aspa_check(rtable *tab, const struct adata *path, bool force_upstream);

#endif
