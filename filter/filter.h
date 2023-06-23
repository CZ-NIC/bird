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
#include "filter/data.h"

/* Possible return values of filter execution */
enum filter_return {
  F_NOP = 0,
  F_NONL,
  F_RETURN,
  F_ACCEPT,   /* Need to preserve ordering: accepts < rejects! */
  F_REJECT,
  F_ERROR,
};

static inline const char *filter_return_str(const enum filter_return fret) {
  switch (fret) {
#define FRS(x) case x: return #x
    FRS(F_NOP);
    FRS(F_NONL);
    FRS(F_RETURN);
    FRS(F_ACCEPT);
    FRS(F_REJECT);
    FRS(F_ERROR);
#undef FRS
    default: bug("This shall not happen");
  }
}

/* The filter encapsulating structure to be pointed-to from outside */
struct f_inst;
struct f_line;
struct filter {
  struct symbol *sym;
  const struct f_line *root;
};

struct rte;

enum filter_return f_run(const struct filter *filter, struct rte **rte, struct linpool *tmp_pool, int flags);
enum filter_return f_run_args(const struct filter *filter, struct rte **rte, struct linpool *tmp_pool, uint argc, const struct f_val *argv, int flags);
enum filter_return f_eval_rte(const struct f_line *expr, struct rte **rte, struct linpool *tmp_pool, uint argc, const struct f_val *argv, struct f_val *pres);
enum filter_return f_eval_buf(const struct f_line *expr, struct linpool *tmp_pool, buffer *buf);

struct f_val cf_eval(const struct f_inst *inst, int type);
static inline uint cf_eval_int(const struct f_inst *inst) { return cf_eval(inst, T_INT).val.i; };

const char *filter_name(const struct filter *filter);
int filter_same(const struct filter *new, const struct filter *old);
int f_same(const struct f_line *f1, const struct f_line *f2);

void filter_commit(struct config *new, struct config *old);

void filters_dump_all(void);

#define FILTER_ACCEPT NULL
#define FILTER_REJECT ((struct filter *) 1)
#define FILTER_UNDEF  ((struct filter *) 2)	/* Used in BGP */

#define FF_SILENT 2			/* Silent filter execution */

/* Custom route attributes */
struct custom_attribute {
  resource r;
  struct f_dynamic_attr *fda;
  const char *name;
};

struct custom_attribute *ca_lookup(pool *p, const char *name, int ea_type);

#endif
