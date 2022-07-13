/*
 *	Filters: utility functions
 *
 *	Copyright 1998 Pavel Machek <pavel@ucw.cz>
 *		  2017 Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/f-inst.h"
#include "lib/idm.h"
#include "nest/protocol.h"
#include "nest/rt.h"

#define P(a,b) ((a<<8) | b)

const char *
filter_name(const struct filter *filter)
{
  if (!filter)
    return "ACCEPT";
  else if (filter == FILTER_REJECT)
    return "REJECT";
  else if (!filter->sym)
    return "(unnamed)";
  else
    return filter->sym->name;
}

struct filter *f_new_where(struct f_inst *where)
{
  struct f_inst *cond = f_new_inst(FI_CONDITION, where,
				   f_new_inst(FI_DIE, F_ACCEPT),
				   f_new_inst(FI_DIE, F_REJECT));

  struct filter *f = cfg_allocz(sizeof(struct filter));
  f->root = f_linearize(cond, 0);
  return f;
}
