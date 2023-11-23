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

uint mpls_new_label(struct mpls_domain *m, struct mpls_handle *h, uint n);
void mpls_free_label(struct mpls_domain *m, struct mpls_handle *h, uint n);
void mpls_move_label(struct mpls_domain *m, struct mpls_handle *fh, struct mpls_handle *th, uint n);

#endif
