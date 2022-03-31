/*
 *	BIRD Internet Routing Daemon -- Routing Table
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
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

struct ea_list;
struct protocol;
struct proto;
struct rte_src;
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
  struct rtable *table;
  struct proto_config *krt_attached;	/* Kernel syncer attached to this table */
  uint addr_type;			/* Type of address data stored in table (NET_*) */
  int gc_max_ops;			/* Maximum number of operations before GC is run */
  int gc_min_time;			/* Minimum time between two consecutive GC runs */
  byte sorted;				/* Routes of network are sorted according to rte_better() */
  byte internal;			/* Internal table of a protocol */
  byte trie_used;			/* Rtable has attached trie */
  btime min_settle_time;		/* Minimum settle time for notifications */
  btime max_settle_time;		/* Maximum settle time for notifications */
};

typedef struct rtable {
  resource r;
  node n;				/* Node in list of all tables */
  pool *rp;				/* Resource pool to allocate everything from, including itself */
  struct fib fib;
  struct f_trie *trie;			/* Trie of prefixes defined in fib */
  char *name;				/* Name of this table */
  list channels;			/* List of attached channels (struct channel) */
  uint addr_type;			/* Type of address data stored in table (NET_*) */
  int pipe_busy;			/* Pipe loop detection */
  int use_count;			/* Number of protocols using this table */
  u32 rt_count;				/* Number of routes in the table */

  byte internal;			/* Internal table of a protocol */

  struct hmap id_map;
  struct hostcache *hostcache;
  struct rtable_config *config;		/* Configuration of this table */
  struct config *deleted;		/* Table doesn't exist in current configuration,
					 * delete as soon as use_count becomes 0 and remove
					 * obstacle from this routing table.
					 */
  struct event *rt_event;		/* Routing table event */
  btime last_rt_change;			/* Last time when route changed */
  btime base_settle_time;		/* Start time of rtable settling interval */
  btime gc_time;			/* Time of last GC */
  int gc_counter;			/* Number of operations since last GC */
  byte prune_state;			/* Table prune state, 1 -> scheduled, 2-> running */
  byte prune_trie;			/* Prune prefix trie during next table prune */
  byte hcu_scheduled;			/* Hostcache update is scheduled */
  byte nhu_state;			/* Next Hop Update state */
  struct fib_iterator prune_fit;	/* Rtable prune FIB iterator */
  struct fib_iterator nhu_fit;		/* Next Hop Update FIB iterator */
  struct f_trie *trie_new;		/* New prefix trie defined during pruning */
  struct f_trie *trie_old;		/* Old prefix trie waiting to be freed */
  u32 trie_lock_count;			/* Prefix trie locked by walks */
  u32 trie_old_lock_count;		/* Old prefix trie locked by walks */

  list subscribers;			/* Subscribers for notifications */
  struct timer *settle_timer;		/* Settle time for notifications */
  list flowspec_links;			/* List of flowspec links, src for NET_IPx and dst for NET_FLOWx */
  struct f_trie *flowspec_trie;		/* Trie for evaluation of flowspec notifications */
} rtable;

struct rt_subscription {
  node n;
  rtable *tab;
  void (*hook)(struct rt_subscription *b);
  void *data;
};

struct rt_flowspec_link {
  node n;
  rtable *src;
  rtable *dst;
  u32 uc;
};

#define NHU_CLEAN	0
#define NHU_SCHEDULED	1
#define NHU_RUNNING	2
#define NHU_DIRTY	3

typedef struct network {
  struct rte *routes;			/* Available routes for this network */
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

extern list routing_tables;
struct config;

void rt_init(void);
void rt_preconfig(struct config *);
void rt_commit(struct config *new, struct config *old);
void rt_lock_table(rtable *);
void rt_unlock_table(rtable *);
struct f_trie * rt_lock_trie(rtable *tab);
void rt_unlock_trie(rtable *tab, struct f_trie *trie);
void rt_subscribe(rtable *tab, struct rt_subscription *s);
void rt_unsubscribe(struct rt_subscription *s);
void rt_flowspec_link(rtable *src, rtable *dst);
void rt_flowspec_unlink(rtable *src, rtable *dst);
rtable *rt_setup(pool *, struct rtable_config *);
static inline void rt_shutdown(rtable *r) { rfree(r->rp); }

static inline net *net_find(rtable *tab, const net_addr *addr) { return (net *) fib_find(&tab->fib, addr); }
static inline net *net_find_valid(rtable *tab, const net_addr *addr)
{ net *n = net_find(tab, addr); return (n && rte_is_valid(n->routes)) ? n : NULL; }
static inline net *net_get(rtable *tab, const net_addr *addr) { return (net *) fib_get(&tab->fib, addr); }
net *net_get(rtable *tab, const net_addr *addr);
net *net_route(rtable *tab, const net_addr *n);
rte *rte_find(net *net, struct rte_src *src);
rte *rte_get_temp(struct rta *, struct rte_src *src);
void rte_update2(struct channel *c, const net_addr *n, rte *new, struct rte_src *src);
/* rte_update() moved to protocol.h to avoid dependency conflicts */
int rt_examine(rtable *t, net_addr *a, struct proto *p, const struct filter *filter);
rte *rt_export_merged(struct channel *c, net *net, rte **rt_free, linpool *pool, int silent);
void rt_refresh_begin(rtable *t, struct channel *c);
void rt_refresh_end(rtable *t, struct channel *c);
void rt_modify_stale(rtable *t, struct channel *c);
void rt_schedule_prune(rtable *t);
void rte_dump(rte *);
void rte_free(rte *);
rte *rte_do_cow(rte *);
static inline rte * rte_cow(rte *r) { return (r->flags & REF_COW) ? rte_do_cow(r) : r; }
rte *rte_cow_rta(rte *r, linpool *lp);
void rt_dump(rtable *);
void rt_dump_all(void);
int rt_feed_channel(struct channel *c);
void rt_feed_channel_abort(struct channel *c);
int rte_update_in(struct channel *c, const net_addr *n, rte *new, struct rte_src *src);
int rt_reload_channel(struct channel *c);
void rt_reload_channel_abort(struct channel *c);
void rt_prune_sync(rtable *t, int all);
int rte_update_out(struct channel *c, const net_addr *n, rte *new, rte *old, rte **old_exported, int refeed);
struct rtable_config *rt_new_table(struct symbol *s, uint addr_type);

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
  rtable *table;
  struct channel *export_channel;
};

struct rt_show_data {
  net_addr *addr;
  list tables;
  struct rt_show_data_rtable *tab;	/* Iterator over table list */
  struct rt_show_data_rtable *last_table; /* Last table in output */
  struct fib_iterator fit;		/* Iterator over networks in table */
  struct f_trie_walk_state *walk_state;	/* Iterator over networks in trie */
  struct f_trie *walk_lock;		/* Locked trie for walking */
  int verbose, tables_defined_by;
  const struct filter *filter;
  struct proto *show_protocol;
  struct proto *export_protocol;
  struct channel *export_channel;
  struct config *running_on_config;
  struct krt_proto *kernel;
  int export_mode, addr_mode, primary_only, filtered, stats;

  int table_open;			/* Iteration (fit) is open */
  int trie_walk;			/* Current table is iterated using trie */
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

/* Value of addr_mode */
#define RSD_ADDR_EQUAL	1		/* Exact query - show route <addr> */
#define RSD_ADDR_FOR	2		/* Longest prefix match - show route for <addr> */
#define RSD_ADDR_IN	3		/* Interval query - show route in <addr> */

/* Value of export_mode in struct rt_show_data */
#define RSEM_NONE	0		/* Export mode not used */
#define RSEM_PREEXPORT	1		/* Routes ready for export, before filtering */
#define RSEM_EXPORT	2		/* Routes accepted by export filter */
#define RSEM_NOEXPORT	3		/* Routes rejected by export filter */
#define RSEM_EXPORTED	4		/* Routes marked in export map */

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

int rt_flowspec_check(rtable *tab_ip, rtable *tab_flow, const net_addr *n, rta *a, int interior);


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

int net_roa_check(rtable *tab, const net_addr *n, u32 asn);

#endif
