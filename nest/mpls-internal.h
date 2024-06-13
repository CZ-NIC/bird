/*
 *	BIRD Internet Routing Daemon -- MPLS Structures
 *
 *	(c) 2022 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_MPLS_INTERNAL_H_
#define _BIRD_MPLS_INTERNAL_H_

#include "nest/bird.h"
#include "lib/bitmap.h"
#include "lib/hash.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/mpls.h"
#include "lib/tlists.h"


#define MPLS_DOMAIN_PUBLIC \
  node n;				/* Node in global list of MPLS domains (mpls_domains) */ \
  const char *name;	\
  DOMAIN(attrs) lock;	\

struct mpls_domain {
  MPLS_DOMAIN_PUBLIC;
  struct mpls_domain **locked_at;
  struct mpls_domain_config *cf;	/* Our config */
  pool *pool;				/* Pool for the domain and associated objects */

  struct lmap labels;			/* Bitmap of allocated labels */
  uint label_count;			/* Number of allocated labels */
  uint use_count;			/* Reference counter */

  config_ref removed;			/* Deconfigured, waiting for zero use_count,
					   while keeping config obstacle */

  struct mpls_range *static_range;	/* Direct static range pointer */
  list ranges;				/* List of label ranges (struct mpls_range) */
  event range_cleanup;			/* Event for asynchronous cleanup of removed ranges */
};

struct mpls_domain_pub {
  union {
    struct { MPLS_DOMAIN_PUBLIC; };
    struct mpls_domain priv;
  };
};

#define mpls_domain_private mpls_domain
#define MPLS_DOMAIN_LOCK(_obj, _pobj)	LOBJ_LOCK(_obj, _pobj, mpls_domain, attrs)
#define MPLS_DOMAIN_LOCKED(_obj, _pobj)	LOBJ_LOCKED(_obj, _pobj, mpls_domain, attrs)
LOBJ_UNLOCK_CLEANUP(mpls_domain, attrs);

#define MPLS_DOMAIN_PRIV(_obj)		LOBJ_PRIV(_obj, attrs)
#define MPLS_DOMAIN_PUB(_pobj)		SKIP_BACK(struct mpls_domain_pub, priv, (_pobj))

#define MPLS_RANGE_PUBLIC \
  node n;				/* Node in mpls_domain.ranges */  \
  DOMAIN(attrs) lock;			/* Shared with the domain */	  \

struct mpls_range {
  MPLS_RANGE_PUBLIC;
  struct mpls_range **locked_at;
  struct mpls_range_config *cf;		/* Our config */
  const char *name;

  struct mpls_domain *domain;
  list handles;				/* List of label handles (struct mpls_handle) */

  uint lo, hi;				/* Label range interval */
  uint label_count;			/* Number of allocated labels */
  uint use_count;			/* Reference counter */
  u8 removed;				/* Deconfigured, waiting for zero use_count */
};

struct mpls_range_pub {
  union {
    struct { MPLS_RANGE_PUBLIC; };
    struct mpls_range priv;
  };
};

#define mpls_range_private mpls_range
#define MPLS_RANGE_LOCK(_obj, _pobj)	LOBJ_LOCK(_obj, _pobj, mpls_range, attrs)
#define MPLS_RANGE_LOCKED(_obj, _pobj)	LOBJ_LOCKED(_obj, _pobj, mpls_range, attrs)
LOBJ_UNLOCK_CLEANUP(mpls_range, attrs);

#define MPLS_RANGE_PRIV(_obj)		LOBJ_PRIV(_obj, attrs)
#define MPLS_RANGE_PUB(_pobj)		SKIP_BACK(struct mpls_range_pub, priv, (_pobj))

#define MPLS_HANDLE_PUBLIC \
  node n;				/* Node in mpls_domain.handles */	\
  const char *name;			/* Shared with the range */		\
  DOMAIN(attrs) lock;			/* Shared with the domain */		\

struct mpls_handle {
  MPLS_HANDLE_PUBLIC;
  struct mpls_handle **locked_at;

  struct mpls_range *range;		/* Associated range, keeping reference */
  uint label_count;			/* Number of allocated labels */
};

struct mpls_handle_pub {
  union {
    struct { MPLS_HANDLE_PUBLIC; };
    struct mpls_handle priv;
  };
};

#define mpls_handle_private mpls_handle
#define MPLS_HANDLE_LOCK(_obj, _pobj)	LOBJ_LOCK(_obj, _pobj, mpls_handle, attrs)
#define MPLS_HANDLE_LOCKED(_obj, _pobj)	LOBJ_LOCKED(_obj, _pobj, mpls_handle, attrs)
LOBJ_UNLOCK_CLEANUP(mpls_handle, attrs);

#define MPLS_HANDLE_PRIV(_obj)		LOBJ_PRIV(_obj, attrs)
#define MPLS_HANDLE_PUB(_pobj)		SKIP_BACK(struct mpls_handle_pub, priv, (_pobj))

uint mpls_new_label(struct mpls_handle *h, uint n);
void mpls_free_label(struct mpls_handle *h, uint n);
void mpls_move_label(struct mpls_handle *fh, struct mpls_handle *th, uint n);

void mpls_lock_domain(struct mpls_domain *m);
void mpls_unlock_domain(struct mpls_domain *m);

void mpls_lock_range(struct mpls_range *m);
void mpls_unlock_range(struct mpls_range *m);

void mpls_revive_fec(struct mpls_fec *);

#endif
