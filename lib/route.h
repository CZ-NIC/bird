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

#include "lib/type.h"

struct network;
struct proto;
struct cli;


typedef struct rte {
  struct ea_list *attrs;		/* Attributes of this route */
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
} rte;

#define REF_FILTERED	2		/* Route is rejected by import filter */
#define REF_STALE	4		/* Route is stale in a refresh cycle */
#define REF_DISCARD	8		/* Route is scheduled for discard */
#define REF_MODIFY	16		/* Route is scheduled for modify */

/* Route is valid for propagation (may depend on other flags in the future), accepts NULL */
static inline int rte_is_valid(rte *r) { return r && !(r->flags & REF_FILTERED); }

/* Route just has REF_FILTERED flag */
static inline int rte_is_filtered(rte *r) { return !!(r->flags & REF_FILTERED); }

struct rte_src {
  struct rte_src *next;			/* Hash chain */
  struct proto *proto;			/* Protocol the source is based on */
  u32 private_id;			/* Private ID, assigned by the protocol */
  u32 global_id;			/* Globally unique ID of the source */
  unsigned uc;				/* Use count */
};


struct rte_src *rt_find_source(struct proto *p, u32 id);
struct rte_src *rt_get_source(struct proto *p, u32 id);
static inline void rt_lock_source(struct rte_src *src) { src->uc++; }
static inline void rt_unlock_source(struct rte_src *src) { src->uc--; }
void rt_prune_sources(void);

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
#define RTS_MAX 16

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
  struct ea_list *next_hash;		/* Next in hash chain */
  struct ea_list **pprev_hash;		/* Previous in hash chain */
  u32 uc;				/* Use count */
  u32 hash_key;				/* List hash */
  struct ea_list *next;			/* In case we have an override list */
  byte flags;				/* Flags: EALF_... */
  byte rfu;
  word count;				/* Number of attributes */
  eattr attrs[0];			/* Attribute definitions themselves */
} ea_list;

#define EALF_SORTED 1			/* Attributes are sorted by code */
#define EALF_BISECT 2			/* Use interval bisection for searching */
#define EALF_CACHED 4			/* List is cached */

struct ea_class {
#define EA_CLASS_INSIDE \
  const char *name;			/* Name (both print and filter) */ \
  struct symbol *sym;			/* Symbol to export to configs */ \
  uint id;				/* Autoassigned attribute ID */ \
  uint uc;				/* Reference count */ \
  btype type;				/* Data type ID */ \
  uint readonly:1;			/* This attribute can't be changed by filters */ \
  uint conf:1;				/* Requested by config */ \
  void (*format)(const eattr *ea, byte *buf, uint size); \
  void (*stored)(const eattr *ea);	/* When stored into global hash */ \
  void (*freed)(const eattr *ea);	/* When released from global hash */ \

  EA_CLASS_INSIDE;
};

struct ea_class_ref {
  resource r;
  struct ea_class *class;
};

void ea_register_init(struct ea_class *);
struct ea_class_ref *ea_register_alloc(pool *, struct ea_class);

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
    ASSERT_DIE(cls->type & EAF_EMBEDDED); \
    const eattr *ea = ea_find((_l), cls->id); \
    (ea ? ea->u.data : (_def)); \
    })

#define ea_get_ip(_l, _ident, _def)  ({ \
    struct ea_class *cls = ea_class_find((_ident)); \
    ASSERT_DIE(cls->type == T_IP); \
    const eattr *ea = ea_find((_l), cls->id); \
    (ea ? *((const ip_addr *) ea->u.ptr->data) : (_def)); \
    })

eattr *ea_walk(struct ea_walk_state *s, uint id, uint max);
void ea_dump(ea_list *);
int ea_same(ea_list *x, ea_list *y);	/* Test whether two ea_lists are identical */
uint ea_hash(ea_list *e);	/* Calculate 16-bit hash value */
ea_list *ea_append(ea_list *to, ea_list *what);
void ea_format_bitfield(const struct eattr *a, byte *buf, int bufsize, const char **names, int min, int max);

/* Normalize ea_list; allocates the result from tmp_linpool */
ea_list *ea_normalize(const ea_list *e);

uint ea_list_size(ea_list *);
void ea_list_copy(ea_list *dest, ea_list *src, uint size);

#define EA_LOCAL_LIST(N)  struct { ea_list l; eattr a[N]; }

#define EA_LITERAL_EMBEDDED(_class, _flags, _val) ({ \
    btype _type = (_class)->type; \
    ASSERT_DIE(_type & EAF_EMBEDDED); \
    EA_LITERAL_GENERIC((_class)->id, _type, _flags, .u.i = _val); \
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

static inline eattr *
ea_set_attr(ea_list **to, eattr a)
{
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
ea_unset_attr(ea_list **to, _Bool local, const struct ea_class *def)
{
  ea_set_attr(to, EA_LITERAL_GENERIC(def->id, 0, 0,
	.fresh = local, .originated = local, .undef = 1));
}

static inline void
ea_set_attr_u32(ea_list **to, const struct ea_class *def, uint flags, u64 data)
{ ea_set_attr(to, EA_LITERAL_EMBEDDED(def, flags, data)); }

static inline void
ea_set_attr_data(ea_list **to, const struct ea_class *def, uint flags, const void *data, uint len)
{ ea_set_attr(to, EA_LITERAL_STORE_ADATA(def, flags, data, len)); }

static inline void
ea_copy_attr(ea_list **to, ea_list *from, const struct ea_class *def)
{
  eattr *e = ea_find_by_class(from, def);
  if (e)
    if (e->type & EAF_EMBEDDED)
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
static inline u32 rt_get_preference(rte *rt)
{ return ea_get_int(rt->attrs, &ea_gen_preference, 0); }

/* IGP metric: second-order comparison */
extern struct ea_class ea_gen_igp_metric;
u32 rt_get_igp_metric(const rte *rt);
#define IGP_METRIC_UNKNOWN 0x80000000	/* Default igp_metric used when no other
					   protocol-specific metric is availabe */

/* From: Advertising router */
extern struct ea_class ea_gen_from;

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
static inline enum flowspec_valid rt_get_flowspec_valid(rte *rt)
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

/* Route has regular, reachable nexthop (i.e. not RTD_UNREACHABLE and like) */
static inline int rte_is_reachable(rte *r)
{
  eattr *nhea = ea_find(r->attrs, &ea_gen_nexthop);
  if (!nhea)
    return 0;

  struct nexthop_adata *nhad = (void *) nhea->u.ptr;
  return NEXTHOP_IS_REACHABLE(nhad);
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

void rta_init(void);
ea_list *ea_lookup(ea_list *);		/* Get a cached (and normalized) variant of this attribute list */
static inline int ea_is_cached(ea_list *r) { return r->flags & EALF_CACHED; }
static inline ea_list *ea_clone(ea_list *r) { r->uc++; return r; }
void ea__free(ea_list *r);
static inline void ea_free(ea_list *r) { if (r && !--r->uc) ea__free(r); }

void ea_dump(ea_list *);
void ea_dump_all(void);
void ea_show_list(struct cli *, ea_list *);

#define rta_lookup	ea_lookup
#define rta_is_cached	ea_is_cached
#define rta_clone	ea_clone
#define rta_free	ea_free

#endif
