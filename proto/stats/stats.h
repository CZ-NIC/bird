/*
 *	BIRD -- Statistics Protocol
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_STATS_H_
#define _BIRD_STATS_H_
#include "lib/timer.h"
#include "filter/data.h"

struct stats_channel;

struct stats_term_config {
  node n;
  const struct f_line *code;
  struct f_val val;
  int type;                     /* type declared in configuration */
  const char *name;
};

struct stats_config {
  struct proto_config c;
  list terms;                    /* list of counter terms */
};

struct stats_proto {
  struct proto p;
  struct stats_channel *c;
  struct tbf rl_gen;
};

struct stats_channel {
  struct channel c;
  pool *pool;                     /* copy of procotol pool */
  u32 _counter;			  /* internal counter */
  u32 counter;			  /* publicly accessible counter */
  struct settle_timer *settle_timer;
};

struct stats_channel_config {
  struct channel_config c;
  btime min_settle_time;              /* wait before notifying filters */
  btime max_settle_time;
};

int stats_get_counter(struct symbol *sym);
struct f_val stats_eval_term(struct stats_term_config *tc);
int stats_get_type(struct stats_term_config *tc);

#if 0
/*
 * get_stats_counter() - extract last notified counter
 *   for specific stats channel if it runs
 *
 */
inline int
stats_get_counter(struct symbol *sym)
{
  if (sym->ch_config->channel)
    return (int) ((struct stats_channel *) sym->ch_config->channel)->counter;
  else
    return 0;
}

/*
 * stats_eval_term() - evaluate stats term
 *
 */
inline struct f_val
stats_eval_term(struct stats_term_config *tc)
{
  enum filter_return fret = f_eval(tc->code, &tc->val);

  if (fret > F_RETURN)
    tc->val.type = T_VOID;

  if (tc->type != tc->val.type)
    tc->val.type = T_VOID;

  return tc->val;
}

int
stats_get_type(struct stats_term_config *tc)
{
  return tc->type;
}

#endif // if 0

#endif
