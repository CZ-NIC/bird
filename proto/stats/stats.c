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

#include "stats.h"

#ifdef CONFIG_BGP
#include "proto/bgp/bgp.h"
#endif

static void
stats_rt_notify(struct proto *P, struct channel *src_ch, const net_addr *n, rte *new, const rte *old)
{
  struct stats_channel *ch = src_ch;
  log(L_INFO "stats_rt_notify() %u", ch->max_generation);

  if (old)
  {
    if (old->generation < ch->max_generation)
    {
      ch->counters[old->generation]--;
      log(L_INFO "channel %s counter %u was decreased", src_ch->name, old->generation);
    }
    else
    {
      log(L_WARN "Stats: Maximum generation reached in channel %s, route is dropped.",
	src_ch->name
      );
    }
  }

  if (new)
  {
    if (new->generation < ch->max_generation)
    {
      ch->counters[new->generation]++;
      log(L_INFO "channel %s counter %u was increased", src_ch->name, new->generation);
    }
    else
    {
      log(L_WARN "Stats: Maximum generation reached in channel %s, route is dropped.",
	src_ch->name
      );
    }
  }  
}

static int
stats_preexport(struct channel *c, rte *e)
{
  struct stats_proto *p = (void *) c->proto;
  log(L_INFO "stats_preexport()");

  return 0;
}

static void
stats_reload_routes(struct channel *C)
{
  struct stats_proto *p = (void *) C->proto;

  /* Route reload on one channel is just refeed on the other */
  //channel_request_feeding(p->c);
}

static void 
stats_configure_channels(struct proto *P, struct proto_config *CF)
{
  struct stats_proto *p = (void *) P;
  struct stats_config *cf = (void *) CF;
  log(L_INFO "stats_configure_channels()");

  struct channel_config *cc;
  WALK_LIST(cc, CF->channels)
  {
    struct channel *c = NULL;
    proto_configure_channel(P, &c, cc);

    struct stats_channel *sc = (void *) c;
    struct stats_channel_config *scc = (void *) cc;

    sc->max_generation = scc->max_generation;
  } 
}

static struct proto *
stats_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct stats_proto *p = (void *) P;
  struct stats_config *cf = (void *) CF;
  log(L_INFO "stats_init()");

  P->rt_notify = stats_rt_notify;
  P->preexport = stats_preexport;
  P->reload_routes = stats_reload_routes;

  p->rl_gen = (struct tbf) TBF_DEFAULT_LOG_LIMITS;

  stats_configure_channels(P, CF);

  return P;
}

static struct channel *
stats_find_channel(struct stats_proto *p, const char *name)
{
  struct channel *c;
  WALK_LIST(c, p->p.channels)
    if (strcmp(c->name, name))
      return c;

  return NULL;
}
 
static int
stats_start(struct proto *P) 
{
  struct stats_proto *p = (struct stats_proto *) P;
  log(L_INFO "stats_start()");

  return PS_UP;
}

static int
stats_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct stats_proto *p = (void *) P;
  struct stats_config *new = (void *) CF;
  struct stats_config *old = (void *) P->cf;
  log(L_INFO "stats_reconfigure()");

  struct channel *c;
  WALK_LIST(c, p->p.channels)
    c->stale = 1;

  struct channel_config *cc;
  WALK_LIST(cc, new->c.channels)
  {
    c = (struct channel *) stats_find_channel(p, cc->name);
    if (!proto_configure_channel(P, &c, cc))
      return 0;

    if (c)
    {
      struct stats_channel *sc = (void *) c;
      struct stats_channel_config *scc = (void *) cc;

      sc->counters = mb_realloc(sc->counters, scc->max_generation);

      if (sc->max_generation < scc->max_generation)
	/* zero newly created counters */
	memset(sc->counters + sc->max_generation, 0, scc->max_generation - sc->max_generation);

      sc->max_generation = scc->max_generation;
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
stats_copy_config(struct proto_config *dest UNUSED, struct proto_config *src UNUSED)
{
  /* Just a shallow copy, not many items here */
}

/* NO NEED TO PRINT ANYTHING BEFORE protocol header

static void
stats_get_status(struct proto *P, byte *buf)
{
  struct stats_proto *p = (void *) P;
  
  cli_msg(-1006, " another super informative message "); 
}
*/

static void
stats_show_proto_info(struct proto *P)
{
  struct stats_proto *p = (void *) P;
  log(L_INFO "stats_show_proto_info() ");

  u32 *arr = mb_alloc(p->p.pool, 256 * sizeof(u32));

  struct stats_channel *sc;
  WALK_LIST(sc, p->p.channels)
  {
    for (uint i = 0; i < 256; i++)
    {
      arr[i] = 0;
    }
  
    u8 len = 0;
    for (u8 i = 0; i < sc->max_generation; i++)
      if (sc->counters[i])
      {
	log(L_INFO "found non-zero %u in counter %u", sc->counters[i], i);
	arr[len] = i;
	len++;
      }

    cli_msg(-1006, "  Channel %s", sc->c.name);
    cli_msg(-1006, "    Max generation:  %3u", sc->max_generation);
    cli_msg(-1006, "    Counter     exported");

    for (u8 i = 0; i < len; i++)
      cli_msg(-1006, "      %3u:    %10u ", arr[i], sc->counters[arr[i]]);

    if (!len)
      cli_msg(-1006, "      <all zeroes>");

    cli_msg(-1006, "");
  }

  mb_free(arr);
}

void
stats_update_debug(struct proto *P)
{
  struct stats_proto *p = (void *) P;

  //p->c->debug = p->p.debug;
}

static int
stats_channel_start(struct channel *C)
{
  struct stats_proto *p = (void *) C->proto;
  struct stats_channel *c = (void *) C;
  log(L_INFO "stats_channel_start() %s", C->name);

  c->pool = p->p.pool;

  c->counters = mb_allocz(c->pool, c->max_generation * sizeof(u32));

  return 0;
}

static void
stats_channel_shutdown(struct channel *C)
{
  struct stats_channel *c = (void *) C;
  log(L_INFO "stats_channel_shutdown() %s", C->name);

  mb_free(c->counters);
  
  c->max_generation = 0;
  c->counters = NULL;
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
  .copy_config = 	stats_copy_config,
  //.get_status = 	stats_get_status,
  .show_proto_info = 	stats_show_proto_info
};

void
stats_build(void)
{
  proto_build(&proto_stats);
}
