/*
 *	BIRD Internet Routing Daemon -- Filters
 *
 *	(c) 1999 Pavel Machek <pavel@ucw.cz>
 *	(c) 2018--2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_FILT_H_
#define _BIRD_FILT_H_

#include "lib/resource.h"
#include "lib/ip.h"
#include "lib/macro.h"
#include "nest/route.h"
#include "nest/attrs.h"

/* Possible return values of filter execution */
enum filter_return {
  F_NOP = 0,
  F_NONL,
  F_RETURN,
  F_ACCEPT,   /* Need to preserve ordering: accepts < rejects! */
  F_REJECT,
  F_ERROR,
  F_QUITBIRD,
};

struct f_val;

/* The filter encapsulating structure to be pointed-to from outside */
struct f_line;
struct filter {
  char *name;
  struct f_line *root;
};

struct rte;

enum filter_return f_run(const struct filter *filter, struct rte **rte, struct linpool *tmp_pool, int flags);
enum filter_return f_eval_rte(const struct f_line *expr, struct rte **rte, struct linpool *tmp_pool);
uint f_eval_int(const struct f_line *expr);
enum filter_return f_eval_buf(const struct f_line *expr, struct linpool *tmp_pool, buffer *buf);

char *filter_name(struct filter *filter);
int filter_same(struct filter *new, struct filter *old);
int f_same(const struct f_line *f1, const struct f_line *f2);

#define FILTER_ACCEPT NULL
#define FILTER_REJECT ((void *) 1)
#define FILTER_UNDEF  ((void *) 2)	/* Used in BGP */

#define FF_SILENT 2			/* Silent filter execution */

/* Custom route attributes */
struct custom_attribute {
  resource r;
  struct f_dynamic_attr *fda;
  const char *name;
};

struct custom_attribute *ca_lookup(pool *p, const char *name, int ea_type);

#endif
