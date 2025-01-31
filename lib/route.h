/*
 *	BIRD Internet Routing Daemon -- Routing data structures
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2022 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LIB_ROUTE_H_
#define _BIRD_LIB_ROUTE_H_

#undef RT_SOURCE_DEBUG
#undef EA_FREE_DEBUG

#include "lib/type.h"
#include "lib/rcu.h"
#include "lib/hash.h"
#include "lib/event.h"
#include "lib/lockfree.h"

struct network;
struct proto;
struct cli;
struct rtable_private;
struct rte_storage;

#define RTE_IN_TABLE_WRITABLE \
  byte pflags;				/* Protocol-specific flags; may change in-table (!) */ \
  byte flags;				/* Table-specific flags */ \
  u8 stale_cycle;			/* Auxiliary value for route refresh; may change in-table (!) */ \

typedef struct rte {
  RTE_IN_TABLE_WRITABLE;
  u8 generation;			/* If this route import is based on other previously exported route,
					   this value should be 1 + MAX(generation of the parent routes).
					   Otherwise the route is independent and this value is zero. */
  u32 id;				/* Table specific route id */
  struct ea_list *attrs;		/* Attributes of this route */
  const net_addr *net;			/* Network this RTE belongs to */
  struct rte_src *src;			/* Route source that created the route */
  struct rt_import_hook *sender;	/* Import hook used to send the route to the routing table */
  btime lastmod;			/* Last modified (set by table) */
} rte;

#define REF_FILTERED	2		/* Route is rejected by import filter */
#define REF_OBSOLETE	16		/* Route is obsolete, pending propagation */
#define REF_PENDING	32		/* Route has not propagated completely yet */

/* Route is valid for propagation (may depend on other flags in the future), accepts NULL */
static inline int rte_is_valid(const rte *r) { return r && !(r->flags & REF_FILTERED); }

/* Route just has REF_FILTERED flag */
static inline int rte_is_filtered(const rte *r) { return !!(r->flags & REF_FILTERED); }

/* Strip the route of the table-specific values */
static inline rte rte_init_from(const rte *r)
{
  return (rte) {
    .attrs = r->attrs,
    .net = r->net,
    .src = r->src,
  };
}

int rte_same(const rte *, const rte *);

struct rte_src {
  struct rte_src *next;			/* Hash chain */
  struct rte_owner *owner;		/* Route source owner */
  u64 private_id;			/* Private ID, assigned by the protocol */
  u32 global_id;			/* Globally unique ID of the source */
  struct lfuc uc;			/* Use count */
};

struct rte_owner_class {
  void (*get_route_info)(const rte *, byte *buf); /* Get route information (for `show route' command) */
  int (*rte_better)(const rte *, const rte *);
  int (*rte_mergable)(const rte *, const rte *);
  u32 (*rte_igp_metric)(const rte *);
};

struct rte_owner {
  struct rte_owner_class *class;
  int (*rte_recalculate)(struct rtable_private *, struct network *, struct rte_storage *new, struct rte_storage *, struct rte_storage *);
  HASH(struct rte_src) hash;
  const char *name;
  u32 hash_key;
  u32 uc;
  u32 debug;
  event_list *list;
  event *prune;
  event *stop;
};

extern DOMAIN(attrs) attrs_domain;

#define RTA_LOCK       LOCK_DOMAIN(attrs, attrs_domain)
#define RTA_UNLOCK     UNLOCK_DOMAIN(attrs, attrs_domain)

#define RTE_SRC_PU_SHIFT      44
#define RTE_SRC_IN_PROGRESS   (1ULL << RTE_SRC_PU_SHIFT)

/* Get a route source. This also locks the source, therefore the caller has to
 * unlock the source after the route has been propagated. */
struct rte_src *rt_get_source_o(struct rte_owner *o, u64 id);
#define rt_get_source(p, id)  rt_get_source_o(&(p)->sources, (id))

struct rte_src *rt_find_source_global(u32 id);

#ifdef RT_SOURCE_DEBUG
#define rt_lock_source _rt_lock_source_internal
#define rt_unlock_source _rt_unlock_source_internal
#endif

static inline void rt_lock_source(struct rte_src *src)
{
  lfuc_lock(&src->uc);
}

static inline void rt_unlock_source(struct rte_src *src)
{
  lfuc_unlock(&src->uc, src->owner->list, src->owner->prune);
}

#ifdef RT_SOURCE_DEBUG
#undef rt_lock_source
#undef rt_unlock_source

#define rt_lock_source(x) ( log(L_INFO "Lock source %uG at %s:%d", (x)->global_id, __FILE__, __LINE__), _rt_lock_source_internal(x) )
#define rt_unlock_source(x) ( log(L_INFO "Unlock source %uG at %s:%d", (x)->global_id, __FILE__, __LINE__), _rt_unlock_source_internal(x) )
#endif

void rt_init_sources(struct rte_owner *, const char *name, event_list *list);
void rt_destroy_sources(struct rte_owner *, event *);

void rt_dump_sources(struct dump_request *, struct rte_owner *);

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
  byte flags;
  byte weight;
  byte labels;				/* Number of all labels */
  u32 label[0];
};

/* For packing one into eattrs */
struct nexthop_adata {
  struct adata ad;
  /* There is either a set of nexthops or a special destination (RTD_*) */
  union {
    struct nexthop nh;
    uint dest;
  };
};

/* For MPLS label stack generation */
struct nexthop_adata_mpls {
  struct nexthop_adata nhad;
  u32 label_space[MPLS_MAX_LABEL_STACK];
};

#define NEXTHOP_DEST_SIZE	(OFFSETOF(struct nexthop_adata, dest) + sizeof(uint) - OFFSETOF(struct adata, data))
#define NEXTHOP_DEST_LITERAL(x)	((struct nexthop_adata) { \
      .ad.length = NEXTHOP_DEST_SIZE, .dest = (x), })

#define RNF_ONLINK		0x1	/* Gateway is onlink regardless of IP ranges */


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
#define RTS_L3VPN 16			/* MPLS L3VPN */
#define RTS_AGGREGATED 17		/* Aggregated route */
#define RTS_MAX 18

#define RTD_NONE 0			/* Undefined next hop */
#define RTD_UNICAST 1			/* A standard next hop */
#define RTD_BLACKHOLE 2			/* Silently drop packets */
#define RTD_UNREACHABLE 3		/* Reject as unreachable */
#define RTD_PROHIBIT 4			/* Administratively prohibited */
#define RTD_MAX 5

extern const char * rta_dest_names[RTD_MAX];

static inline const char *rta_dest_name(uint n)
{ return (n < RTD_MAX) ? rta_dest_names[n] : "???"; }


/*
 *	Extended Route Attributes
 */

typedef struct eattr {
  word id;				/* EA_CODE(PROTOCOL_..., protocol-dependent ID) */
  byte flags;				/* Protocol-dependent flags */
  byte type;				/* Attribute type */
  byte rfu:5;
  byte originated:1;			/* The attribute has originated locally */
  byte fresh:1;				/* An uncached attribute (e.g. modified in export filter) */
  byte undef:1;				/* Explicitly undefined */

  PADDING(unused, 3, 3);

  union bval u;
} eattr;


#define EA_CODE_MASK 0xffff
#define EA_ALLOW_UNDEF 0x10000		/* ea_find: allow EAF_TYPE_UNDEF */
#define EA_BIT(n) ((n) << 24)		/* Used in bitfield accessors */
#define EA_BIT_GET(ea) ((ea) >> 24)

typedef struct ea_list {
  struct ea_list *next;			/* In case we have an override list */
  byte flags;				/* Flags: EALF_... */
  byte stored:5;			/* enum ea_stored */
  byte rfu:3;
  word count;				/* Number of attributes */
  eattr attrs[0];			/* Attribute definitions themselves */
} ea_list;

enum ea_stored {
  EALS_NONE = 0,			/* This is a temporary ea_list */
  EALS_PREIMPORT = 1,			/* State when route entered rte_update() */
  EALS_FILTERED = 2,			/* State after filters */
  EALS_IN_TABLE = 3,			/* State in table */
  EALS_KEY = 4,				/* EA list used as key */
  EALS_CUSTOM = 0x10,			/* OR this with custom values */
  EALS_MAX = 0x20,
};

struct ea_storage {
  struct ea_storage *_Atomic next_hash;	/* Next in hash chain */
  _Atomic u64 uc;			/* Use count */
  u32 hash_key;				/* List hash */
  PADDING(unused, 0, 4);		/* Sorry, we need u64 for the usecount */
  ea_list l[0];				/* The list itself */
};

#define EALF_SORTED 1			/* Attributes are sorted by code */
#define EALF_BISECT 2			/* Use interval bisection for searching */
#define EALF_HUGE   8			/* List is too big to fit into slab */

struct ea_class {
#define EA_CLASS_INSIDE \
  const char *name;			/* Name (both print and filter) */ \
  struct symbol *sym;			/* Symbol to export to configs */ \
  uint id;				/* Autoassigned attribute ID */ \
  uint uc;				/* Reference count */ \
  btype type;				/* Data type ID */ \
  u16 flags;				/* Protocol-dependent flags */ \
  uint readonly:1;			/* This attribute can't be changed by filters */ \
  uint conf:1;				/* Requested by config */ \
  uint hidden:1;			/* Technical attribute, do not show, do not expose to filters */ \
  void (*format)(const eattr *ea, byte *buf, uint size); \
  void (*stored)(const eattr *ea);	/* When stored into global hash */ \
  void (*freed)(const eattr *ea);	/* When released from global hash */ \
  struct f_val (*empty)(const struct ea_class *);	/* Return this instead of T_VOID as default value for filters */ \

  EA_CLASS_INSIDE;
};

struct ea_class_ref {
  resource r;
  struct ea_class *class;
};

void ea_register_init(struct ea_class *);
struct ea_class_ref *ea_register_alloc(pool *, struct ea_class);
struct ea_class_ref *ea_ref_class(pool *, struct ea_class *);	/* Reference for an attribute alias */

#define EA_REGISTER_ALL_HELPER(x)	ea_register_init(x);
#define EA_REGISTER_ALL(...)		MACRO_FOREACH(EA_REGISTER_ALL_HELPER, __VA_ARGS__)

struct ea_class *ea_class_find_by_id(uint id);
struct ea_class *ea_class_find_by_name(const char *name);
static inline struct ea_class *ea_class_self(struct ea_class *self) { return self; }
#define ea_class_find(_arg)	_Generic((_arg), \
  uint: ea_class_find_by_id, \
  word: ea_class_find_by_id, \
  char *: ea_class_find_by_name, \
  const char *: ea_class_find_by_name, \
  struct ea_class *: ea_class_self)(_arg)

struct ea_walk_state {
  ea_list *eattrs;			/* Ccurrent ea_list, initially set by caller */
  eattr *ea;				/* Current eattr, initially NULL */
  u32 visited[4];			/* Bitfield, limiting max to 128 */
};

#define ea_find(_l, _arg)	_Generic((_arg), uint: ea_find_by_id, struct ea_class *: ea_find_by_class, char *: ea_find_by_name)(_l, _arg)
eattr *ea_find_by_id(ea_list *, unsigned ea);
static inline eattr *ea_find_by_class(ea_list *l, const struct ea_class *def)
{ return ea_find_by_id(l, def->id); }
static inline eattr *ea_find_by_name(ea_list *l, const char *name)
{
  const struct ea_class *def = ea_class_find_by_name(name);
  return def ? ea_find_by_class(l, def) : NULL;
}

#define ea_get_int(_l, _ident, _def)  ({ \
    struct ea_class *cls = ea_class_find((_ident)); \
    ASSERT_DIE(cls->type & EAF_EMBEDDED && cls->type != T_PTR); \
    const eattr *ea = ea_find((_l), cls->id); \
    (ea ? ea->u.data : (_def)); \
    })

#define ea_get_ptr(_l, _ident, _def)  ({ \
    struct ea_class *cls = ea_class_find((_ident)); \
    ASSERT_DIE(cls->type == T_PTR); \
    const eattr *ea = ea_find((_l), cls->id); \
    (ea ? ea->u.v_ptr : (_def)); \
    })

#define ea_get_ip(_l, _ident, _def)  ({ \
    struct ea_class *cls = ea_class_find((_ident)); \
    ASSERT_DIE(cls->type == T_IP); \
    const eattr *ea = ea_find((_l), cls->id); \
    (ea ? *((const ip_addr *) ea->u.ptr->data) : (_def)); \
    })

#define ea_get_adata(_l, _ident)	({ \
    struct ea_class *cls = ea_class_find((_ident)); \
    ASSERT_DIE(!(cls->type & EAF_EMBEDDED)); \
    const eattr *ea = ea_find((_l), cls->id); \
    (ea ? ea->u.ptr : &null_adata); \
    })

eattr *ea_walk(struct ea_walk_state *s, uint id, uint max);
int ea_same(ea_list *x, ea_list *y);	/* Test whether two ea_lists are identical */
uint ea_hash(ea_list *e);		/* Calculate attributes hash value */
ea_list *ea_append(ea_list *to, ea_list *what);
void ea_format_bitfield(const struct eattr *a, byte *buf, int bufsize, const char **names, int min, int max);

/* Normalize ea_list; allocates the result from tmp_linpool */
ea_list *ea_normalize(ea_list *e, u32 upto);

uint ea_list_size(ea_list *);
void ea_list_copy(ea_list *dest, ea_list *src, uint size);

#define EA_LOCAL_LIST(N)  struct { ea_list l; eattr a[N]; }

#define EA_LITERAL_EMBEDDED(_class, _flags, _val) ({ \
    btype _type = (_class)->type; \
    ASSERT_DIE(_type & EAF_EMBEDDED && _type != T_PTR); \
    EA_LITERAL_GENERIC((_class)->id, _type, _flags, .u.i = _val); \
    })

#define EA_LITERAL_STORE_PTR(_class, _flags, _ptr) ({ \
    btype _type = (_class)->type; \
    ASSERT_DIE(_type == T_PTR); \
    EA_LITERAL_GENERIC((_class)->id, _type, _flags, .u.v_ptr = _ptr); \
    })

#define EA_LITERAL_STORE_ADATA(_class, _flags, _buf, _len) ({ \
    btype _type = (_class)->type; \
    ASSERT_DIE(!(_type & EAF_EMBEDDED)); \
    EA_LITERAL_GENERIC((_class)->id, _type, _flags, .u.ad = tmp_store_adata((_buf), (_len))); \
    })

#define EA_LITERAL_DIRECT_ADATA(_class, _flags, _adata) ({ \
    btype _type = (_class)->type; \
    ASSERT_DIE(!(_type & EAF_EMBEDDED)); \
    EA_LITERAL_GENERIC((_class)->id, _type, _flags, .u.ad = _adata); \
    })

#define EA_LITERAL_GENERIC(_id, _type, _flags, ...) \
  ((eattr) { .id = _id, .type = _type, .flags = _flags, __VA_ARGS__ })

#define EA_LITERAL_STORE_STRING(_class, _flags, string) ({EA_LITERAL_STORE_ADATA(_class, _flags, string, strlen(string)+1);})

static inline eattr *
ea_set_attr(ea_list **to, eattr a)
{
  if (!a.id)
    bug("You have forgotten to register your EA class");

  EA_LOCAL_LIST(1) *ea = tmp_alloc(sizeof(*ea));
  *ea = (typeof(*ea)) {
    .l.flags = EALF_SORTED,
    .l.count = 1,
    .l.next = *to,
    .a[0] = a,
  };

  *to = &ea->l;
  return &ea->a[0];
}

static inline void
ea_unset_attr(ea_list **to, bool local, const struct ea_class *def)
{
  ea_set_attr(to, EA_LITERAL_GENERIC(def->id, 0, 0,
	.fresh = local, .originated = local, .undef = 1));
}

static inline void
ea_set_attr_u32(ea_list **to, const struct ea_class *def, uint flags, u64 data)
{ ea_set_attr(to, EA_LITERAL_EMBEDDED(def, flags, data)); }

static inline void
ea_set_attr_ptr(ea_list **to, const struct ea_class *def, uint flags, void *data)
{ ea_set_attr(to, EA_LITERAL_STORE_PTR(def, flags, data)); }

static inline void
ea_set_attr_data(ea_list **to, const struct ea_class *def, uint flags, const void *data, uint len)
{ ea_set_attr(to, EA_LITERAL_STORE_ADATA(def, flags, data, len)); }

static inline void
ea_copy_attr(ea_list **to, ea_list *from, const struct ea_class *def)
{
  eattr *e = ea_find_by_class(from, def);
  if (e)
    if (e->type == T_PTR)
      ea_set_attr_ptr(to, def, e->flags, (void *)e->u.v_ptr);
    else if (e->type & EAF_EMBEDDED)
      ea_set_attr_u32(to, def, e->flags, e->u.data);
    else
      ea_set_attr_data(to, def, e->flags, e->u.ptr->data, e->u.ptr->length);
  else
    ea_unset_attr(to, 0, def);
}

/*
 *	Common route attributes
 */

/* Preference: first-order comparison */
extern struct ea_class ea_gen_preference;
static inline u32 rt_get_preference(const rte *rt)
{ return ea_get_int(rt->attrs, &ea_gen_preference, 0); }

/* IGP metric: second-order comparison */
extern struct ea_class ea_gen_igp_metric;
u32 rt_get_igp_metric(const rte *rt);
#define IGP_METRIC_UNKNOWN 0x80000000	/* Default igp_metric used when no other
					   protocol-specific metric is availabe */

/* From: Advertising router */
extern struct ea_class ea_gen_from;


/* MPLS Label, Policy and Class */
extern struct ea_class ea_gen_mpls_label,
       ea_gen_mpls_policy, ea_gen_mpls_class;


/* Source: An old method to devise the route source protocol and kind.
 * To be superseded in a near future by something more informative. */
extern struct ea_class ea_gen_source;
static inline u32 rt_get_source_attr(const rte *rt)
{ return ea_get_int(rt->attrs, &ea_gen_source, 0); }

/* Flowspec validation result */
enum flowspec_valid {
  FLOWSPEC_UNKNOWN	= 0,
  FLOWSPEC_VALID	= 1,
  FLOWSPEC_INVALID	= 2,
  FLOWSPEC__MAX,
};

extern const char * flowspec_valid_names[FLOWSPEC__MAX];
static inline const char *flowspec_valid_name(enum flowspec_valid v)
{ return (v < FLOWSPEC__MAX) ? flowspec_valid_names[v] : "???"; }

extern struct ea_class ea_gen_flowspec_valid;
static inline enum flowspec_valid rt_get_flowspec_valid(const rte *rt)
{ return ea_get_int(rt->attrs, &ea_gen_flowspec_valid, FLOWSPEC_UNKNOWN); }

/* Next hop: For now, stored as adata */
extern struct ea_class ea_gen_nexthop;

static inline void ea_set_dest(struct ea_list **to, uint flags, uint dest)
{
  struct nexthop_adata nhad = NEXTHOP_DEST_LITERAL(dest);
  ea_set_attr_data(to, &ea_gen_nexthop, flags, &nhad.ad.data, nhad.ad.length);
}

/* Next hop structures */

#define NEXTHOP_ALIGNMENT	(_Alignof(struct nexthop))
#define NEXTHOP_MAX_SIZE	(sizeof(struct nexthop) + sizeof(u32)*MPLS_MAX_LABEL_STACK)
#define NEXTHOP_SIZE(_nh)	NEXTHOP_SIZE_CNT(((_nh)->labels))
#define NEXTHOP_SIZE_CNT(cnt)	BIRD_ALIGN((sizeof(struct nexthop) + sizeof(u32) * (cnt)), NEXTHOP_ALIGNMENT)
#define nexthop_size(nh)	NEXTHOP_SIZE((nh))

#define NEXTHOP_NEXT(_nh)	((void *) (_nh) + NEXTHOP_SIZE(_nh))
#define NEXTHOP_END(_nhad)	((_nhad)->ad.data + (_nhad)->ad.length)
#define NEXTHOP_VALID(_nh, _nhad) ((void *) (_nh) < (void *) NEXTHOP_END(_nhad))
#define NEXTHOP_ONE(_nhad)	(NEXTHOP_NEXT(&(_nhad)->nh) == NEXTHOP_END(_nhad))

#define NEXTHOP_WALK(_iter, _nhad) for ( \
    struct nexthop *_iter = &(_nhad)->nh; \
    (void *) _iter < (void *) NEXTHOP_END(_nhad); \
    _iter = NEXTHOP_NEXT(_iter))


static inline int nexthop_same(struct nexthop_adata *x, struct nexthop_adata *y)
{ return adata_same(&x->ad, &y->ad); }
struct nexthop_adata *nexthop_merge(struct nexthop_adata *x, struct nexthop_adata *y, int max, linpool *lp);
struct nexthop_adata *nexthop_sort(struct nexthop_adata *x, linpool *lp);
int nexthop_is_sorted(struct nexthop_adata *x);

#define NEXTHOP_IS_REACHABLE(nhad)	((nhad)->ad.length > NEXTHOP_DEST_SIZE)

static inline struct nexthop_adata *
rte_get_nexthops(rte *r)
{
  eattr *nhea = ea_find(r->attrs, &ea_gen_nexthop);
  return nhea ? SKIP_BACK(struct nexthop_adata, ad, nhea->u.ptr) : NULL;
}

/* Route has regular, reachable nexthop (i.e. not RTD_UNREACHABLE and like) */
static inline int rte_is_reachable(rte *r)
{
  struct nexthop_adata *nhad = rte_get_nexthops(r);
  return nhad && NEXTHOP_IS_REACHABLE(nhad);
}

static inline int nhea_dest(eattr *nhea)
{
  if (!nhea)
    return RTD_NONE;

  struct nexthop_adata *nhad = nhea ? (struct nexthop_adata *) nhea->u.ptr : NULL;
  if (NEXTHOP_IS_REACHABLE(nhad))
    return RTD_UNICAST;
  else
    return nhad->dest;
}

static inline int rte_dest(const rte *r)
{
  return nhea_dest(ea_find(r->attrs, &ea_gen_nexthop));
}

/* ASPA Providers eattr */
extern struct ea_class ea_gen_aspa_providers;


void rta_init(void);

ea_list *ea_lookup_slow(ea_list *r, u32 squash_upto, enum ea_stored oid);

static inline struct ea_storage *ea_get_storage(ea_list *r)
{
  ASSERT_DIE(r->stored);
  return SKIP_BACK(struct ea_storage, l[0], r);
}

static inline ea_list *ea_ref(ea_list *r)
{
  ASSERT_DIE(0 < atomic_fetch_add_explicit(&ea_get_storage(r)->uc, 1, memory_order_acq_rel)); //TODO Is this ok? Are we sure no one will decrease the count?
  return r;
}

static inline ea_list *ea_lookup(ea_list *r, u32 squash_upto, enum ea_stored oid)
{
  ASSERT_DIE(oid);
  if ((r->stored == oid) || BIT32_TEST(&squash_upto, r->stored))
    return ea_ref(r);
  else
    return ea_lookup_slow(r, squash_upto, oid);
}

struct ea_finally_free_deferred_call {
  struct deferred_call dc;
  struct rcu_stored_phase phase;
  struct ea_storage *attrs;
};

struct ea_free_deferred {
  struct deferred_call dc;
  ea_list *attrs;
};

void ea_free_deferred(struct deferred_call *dc);

#ifdef EA_FREE_DEBUG
#define ea_free_later _ea_free_later_internal
#endif

static inline ea_list *ea_free_later(ea_list *r)
{
  if (!r)
    return NULL;

  struct ea_free_deferred efd = {
    .dc.hook = ea_free_deferred,
    .attrs = r,
  };

  defer_call(&efd.dc, sizeof efd);
  return r;
}

#ifdef EA_FREE_DEBUG
#undef ea_free_later
#define ea_free_later(x) ( log(L_INFO "EA free request %p at %s:%d", (x), __FILE__, __LINE__), _ea_free_later_internal(x) )
#endif

#define ea_free ea_free_later

static inline ea_list *ea_lookup_tmp(ea_list *r, u32 squash_upto, enum ea_stored oid)
{
  return ea_free_later(ea_lookup(r, squash_upto, oid));
}

static inline ea_list *ea_ref_tmp(ea_list *r)
{
  ASSERT_DIE(r->stored);
  return ea_free_later(ea_ref(r));
}

static inline ea_list *ea_strip_to(ea_list *r, u32 strip_to)
{
  ASSERT_DIE(strip_to);
  while (r && !BIT32_TEST(&strip_to, r->stored))
    r = r->next;

  return r;
}

void ea_dump(struct dump_request *, ea_list *);
void ea_dump_all(struct dump_request *);
void ea_show_list(struct cli *, ea_list *);

#endif
