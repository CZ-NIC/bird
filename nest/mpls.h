/*
 *	BIRD Internet Routing Daemon -- MPLS Structures
 *
 *	(c) 2022 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_MPLS_H_
#define _BIRD_MPLS_H_

#include "nest/bird.h"
#include "lib/bitmap.h"
#include "lib/hash.h"
#include "nest/route.h"
#include "nest/protocol.h"


#define MPLS_POLICY_NONE	0
#define MPLS_POLICY_STATIC	1
#define MPLS_POLICY_PREFIX	2
#define MPLS_POLICY_AGGREGATE	3
#define MPLS_POLICY_VRF		4

#define MPLS_FEC_DOWN		0
#define MPLS_FEC_CLEAN		1
#define MPLS_FEC_DIRTY		2


struct mpls_domain_config {
  node n;				/* Node in config.mpls_domains */
  struct mpls_domain *domain;		/* Our instance */
  const char *name;

  list ranges;				/* List of label ranges (struct mpls_range_config) */
  struct mpls_range_config *static_range;  /* Default static label range */
  struct mpls_range_config *dynamic_range; /* Default dynamic label range */
};

struct mpls_domain {
  node n;				/* Node in global list of MPLS domains (mpls_domains) */
  struct mpls_domain_config *cf;	/* Our config */
  const char *name;
  pool *pool;				/* Pool for the domain and associated objects */

  struct lmap labels;			/* Bitmap of allocated labels */
  uint label_count;			/* Number of allocated labels */
  uint use_count;			/* Reference counter */

  struct config *removed;		/* Deconfigured, waiting for zero use_count,
					   while keeping config obstacle */

  list ranges;				/* List of label ranges (struct mpls_range) */
  list handles;				/* List of label handles (struct mpls_handle) */
};

struct mpls_range_config {
  node n;				/* Node in mpls_domain_config.ranges */
  struct mpls_range *range;		/* Our instance */
  struct mpls_domain_config *domain;	/* Parent MPLS domain */
  const char *name;

  uint start;				/* Label range start, (uint) -1 for undefined */
  uint length;				/* Label range length, (uint) -1 for undefined */
  u8 implicit;				/* Implicitly defined range */
};

struct mpls_range {
  node n;				/* Node in mpls_domain.ranges */
  struct mpls_range_config *cf;		/* Our config */
  const char *name;

  uint lo, hi;				/* Label range interval */
  uint label_count;			/* Number of allocated labels */
  uint use_count;			/* Reference counter */
  u8 removed;				/* Deconfigured, waiting for zero use_count */
};

struct mpls_handle {
  node n;				/* Node in mpls_domain.handles */

  struct mpls_range *range;		/* Associated range, keeping reference */
  uint label_count;			/* Number of allocated labels */
};


void mpls_init(void);
struct mpls_domain_config * mpls_domain_config_new(struct symbol *s);
void mpls_domain_postconfig(struct mpls_domain_config *cf);
struct mpls_range_config * mpls_range_config_new(struct mpls_domain_config *m, struct symbol *s);
void mpls_preconfig(struct config *c);
void mpls_commit(struct config *new, struct config *old);
uint mpls_new_label(struct mpls_domain *m, struct mpls_handle *h, uint n);
void mpls_free_label(struct mpls_domain *m, struct mpls_handle *h, uint n);
void mpls_move_label(struct mpls_domain *m, struct mpls_handle *fh, struct mpls_handle *th, uint n);

static inline struct mpls_domain_config *cf_default_mpls_domain(struct config *cfg)
{ return EMPTY_LIST(cfg->mpls_domains) ? NULL : HEAD(cfg->mpls_domains); }


struct mpls_channel_config {
  struct channel_config c;

  struct mpls_domain_config *domain;
  struct mpls_range_config *range;

  uint label_policy;
};

struct mpls_channel {
  struct channel c;

  struct mpls_domain *domain;
  struct mpls_range *range;

  uint label_policy;
};


void mpls_channel_postconfig(struct channel_config *CF);
extern struct channel_class channel_mpls;


struct mpls_fec {
  u32 label;				/* Label for FEC */
  u32 hash;				/* Hash for primary key (net / rta) */
  u32 uc;				/* Number of LSPs for FEC */
  u8 state;				/* FEC state (MPLS_FEC_*) */
  u8 policy;				/* Label policy (MPLS_POLICY_*) */

  struct mpls_handle *handle;		/* Handle holding the label */

  struct mpls_fec *next_k;		/* Next in mpls_fec.net_hash/rta_hash */
  struct mpls_fec *next_l;		/* Next in mpls_fec.label_hash */

  union {				/* Extension part of key */
    u64 path_id;			/* Source path_id */
    u32 class_id;			/* Aaggregation class */
  };
  union {				/* Primary key */
    struct rta *rta;
    struct iface *iface;
    net_addr net[0];
  };
};

struct mpls_fec_map {
  pool *pool;				/* Pool for FEC map */
  slab *slabs[4];			/* Slabs for FEC allocation */
  HASH(struct mpls_fec) net_hash;	/* Hash table for MPLS_POLICY_PREFIX FECs */
  HASH(struct mpls_fec) rta_hash;	/* Hash table for MPLS_POLICY_AGGREGATE FECs */
  HASH(struct mpls_fec) label_hash;	/* Hash table for FEC lookup by label */
  struct mpls_fec *vrf_fec;		/* Single FEC for MPLS_POLICY_VRF */

  struct channel *channel;		/* MPLS channel for FEC announcement */
  struct mpls_domain *domain;		/* MPLS domain, keeping reference */
  struct mpls_handle *handle;		/* Handle for dynamic allocation of labels */
  struct mpls_handle *static_handle;	/* Handle for static label allocations, optional */
  struct iface *vrf_iface;

  u8 mpls_rts;				/* Source value used for MPLS routes (RTS_*) */
  u8 mpls_scope;			/* Scope  value used for MPLS routes (SCOPE_*) */
};


struct mpls_fec_map *mpls_fec_map_new(pool *p, struct channel *c, uint rts);
void mpls_fec_map_reconfigure(struct mpls_fec_map *m, struct channel *C);
void mpls_fec_map_free(struct mpls_fec_map *m);
struct mpls_fec *mpls_find_fec_by_label(struct mpls_fec_map *x, u32 label);
struct mpls_fec *mpls_get_fec_by_label(struct mpls_fec_map *m, u32 label);
struct mpls_fec *mpls_get_fec_by_net(struct mpls_fec_map *m, const net_addr *net, u64 path_id);
struct mpls_fec *mpls_get_fec_by_rta(struct mpls_fec_map *m, const rta *src, u32 class_id);
void mpls_free_fec(struct mpls_fec_map *x, struct mpls_fec *fec);
int  mpls_handle_rte(struct mpls_fec_map *m, const net_addr *n, rte *r, linpool *lp, struct mpls_fec **locked_fec);
void mpls_handle_rte_cleanup(struct mpls_fec_map *m, struct mpls_fec **locked_fec);
void mpls_rte_insert(net *n UNUSED, rte *r);
void mpls_rte_remove(net *n UNUSED, rte *r);


struct mpls_show_ranges_cmd {
  struct mpls_domain_config *domain;
  struct mpls_range_config *range;

  /* Runtime */
  struct mpls_domain *dom;
};

void mpls_show_ranges(struct mpls_show_ranges_cmd *cmd);

#endif
