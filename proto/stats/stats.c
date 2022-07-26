/*
 *	BIRD -- Statistics Protocol
 *
 *      (c) 2022       Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022       CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Stats
 *
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/rt.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "lib/string.h"
#include "lib/timer.h"

#include "stats.h"

static void stats_settle_timer(struct settle_timer *st);

static void
stats_rt_notify(struct proto *P UNUSED, struct channel *src_ch, const net_addr *n UNUSED, rte *new, const rte *old)
{
  struct stats_channel *ch = (void *) src_ch;

  int changed = 0;
  if (new && old)
    /* count of exported routes stays the same */
    log(L_INFO "nothing happen - no change of counter");
  else if (!old)
  {
    log(L_INFO "increasing _counter");
    ch->_counter++;
    changed = 1;
    if (ch->_counter > 100)
      log(L_INFO "underflow?");
  }
  else if (!new)
  {
    log(L_INFO "decreasing _counter");
    ch->_counter--;
    changed = 1;
    if (ch->_counter > 100)
      log(L_INFO "underflow? - ");
  }
  else  /* shouldn't happen */
  {
    log(L_INFO "BUG is here !!!");
    bug("Both pointers *new and *old in rt_notify are NULL");
  }

  log(L_INFO "stats channel %s: preparing to kick the timer %d", src_ch->name,
changed);
  if (changed)
  {
    settle_timer_changed(ch->settle_timer);
    kick_settle_timer(ch->settle_timer);
  }
}

static void
stats_reload_routes(struct channel *C)
{
  // TODO
  struct stats_channel *c = (void *) C;

  c->_counter = c->counter = 0;
  channel_request_feeding(C);
}

static struct proto *
stats_init(struct proto_config *CF)
{
  log(L_INFO "stats_init() ");
  struct proto *P = proto_new(CF);
  struct stats_proto *p = (void *) P;

  P->rt_notify = stats_rt_notify;
  P->reload_routes = stats_reload_routes;

  p->rl_gen = (struct tbf) TBF_DEFAULT_LOG_LIMITS;

  return P;
}

static struct settle_timer_class stats_settle_class = {
  .action = stats_settle_timer,
  .kick = NULL,
};

static void 
stats_configure_channels(struct proto *P, struct proto_config *CF)
{
  log(L_INFO "stats_configure_channels()");
  struct channel_config *cc;
  WALK_LIST(cc, CF->channels)
  {
    struct channel *c = proto_find_channel_by_name(P, cc->name);
    proto_configure_channel(P, &c, cc);
  } 
}

static int
stats_start(struct proto *P)
{
  log(L_INFO "stats_start() ");
  stats_configure_channels(P, P->cf);
  return PS_UP;
}

static int
stats_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct stats_proto *p = (void *) P;
  struct stats_config *new = (void *) CF;

  struct channel *c;
  WALK_LIST(c, p->p.channels)
    c->stale = 1;

  struct channel_config *cc;
  WALK_LIST(cc, new->c.channels)
  {
    c = proto_find_channel_by_name(P, cc->name);
    if (!proto_configure_channel(P, &c, cc))
      return 0;

    if (c)
    {
      struct stats_channel *sc = (void *) c;
      struct stats_channel_config *scc = (void *) cc;

      sc->settle_timer->min_settle_time = &(scc->min_settle_time);
      sc->settle_timer->max_settle_time = &(scc->max_settle_time);

      if (sc->counter != sc->_counter)
      {
	sc->counter = sc->_counter;

	/* notify all hooked filters */
	// TODO here
      }

      c->stale = 0;
    }
  }

  struct channel *c2;
  WALK_LIST_DELSAFE(c, c2, p->p.channels)
    if (c->stale && !proto_configure_channel(P, &c, NULL))
      return 0;
  
  return 1;
}

static void
stats_show_proto_info(struct proto *P)
{
  struct stats_proto *p = (void *) P;

  struct stats_channel *sc;
  WALK_LIST(sc, p->p.channels)
  {
    cli_msg(-1006, "  Channel %s", sc->c.name);
    cli_msg(-1006, "    Exports:  %10u (currently:  %10u)",
	      sc->counter,
	      sc->_counter);
    if (!P->disabled)
    {
      cli_msg(-1006, "    Settle time:  %4u s", (*(sc->settle_timer->min_settle_time)) TO_S);
      cli_msg(-1006, "    Settle time:  %4u s", (*(sc->settle_timer->max_settle_time)) TO_S);
    }
  }
}

void
stats_update_debug(struct proto *P)
{
  struct channel *c;
  WALK_LIST(c, P->channels)
  {
    c->debug = P->debug;
  }
}

static void
stats_settle_timer(struct settle_timer *st)
{
  timer *t = (void *) st;
  struct stats_channel *c = t->data;
  log(L_INFO "stats_settle_timer() _counter: %u, counter: %u",
      c->_counter, c->counter);

  /* update only if real change happen */
  if (c->counter != c->_counter)
  {
    c->counter = c->_counter;
    /* do update here */
    // WALK_LIST(s, subscribers)
    // { ... }
  }
}

static int
stats_channel_start(struct channel *C)
{
  struct stats_channel *c = (void *) C;
  struct stats_channel_config *cc = (void *) C->config;
  struct stats_proto *p = (void *) C->proto;

  c->pool = p->p.pool;

  if (!c->settle_timer)
    c->settle_timer = stm_new_timer(
      c->pool, (void *) c, &stats_settle_class);

  c->settle_timer->min_settle_time = &(cc->min_settle_time);
  c->settle_timer->max_settle_time = &(cc->max_settle_time);

  c->_counter = 0;
  c->counter = 0;

  return 0;
}

static void
stats_channel_shutdown(struct channel *C)
{
  log(L_INFO "stats_channel_shutdown()");
  struct stats_channel *c = (void *) C;

  tm_stop((timer *) c->settle_timer);

  c->settle_timer->min_settle_time = NULL;
  c->settle_timer->max_settle_time = NULL;

  mb_free(c->settle_timer);
  c->settle_timer = NULL;

  c->_counter = 0;
  c->counter = 0;
  c->pool = NULL;
}

struct channel_class channel_stats = {
  .channel_size =	sizeof(struct stats_channel),
  .config_size =	sizeof(struct stats_channel_config),
  .start =		stats_channel_start,
  .shutdown =		stats_channel_shutdown,
};

struct protocol proto_stats = {
  .name =		"Stats",
  .template =		"stat%d",
  .channel_mask =	NB_ANY,
  .proto_size =		sizeof(struct stats_proto),
  .config_size =	sizeof(struct stats_config),
  .init =		stats_init,
  .start =		stats_start,
  .reconfigure =	stats_reconfigure,
  .show_proto_info = 	stats_show_proto_info
};

void
stats_build(void)
{
  proto_build(&proto_stats);
}
