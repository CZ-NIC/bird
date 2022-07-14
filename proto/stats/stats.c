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
  struct stats_proto *p = (void *) P;
  log(L_INFO "stats_rf_notify()");

  if (new && old)
  {
    new->generation = old->generation + 1;
    p->counters[old->generation]--;
    p->counters[new->generation]++;
    log(L_INFO "counter %u increased", new->generation);
  }
  else if (new && !old)
  {
    new->generation = 0;
    p->counters[0]++;
    log(L_INFO "counter 0 increased");
  }
  else if (!new && old)
  {
    (p->counters[old->generation])--;
    log(L_INFO "counter %u decreased", old->generation);
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
  channel_request_feeding(p->c);
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

  struct channel_config *cc;
  WALK_LIST(cc, CF->channels) 
  {
    struct channel *c = NULL;
    proto_configure_channel(P, &c, cc);
  }

  return P;
}

static int
stats_start(struct proto *P) 
{
  struct stats_proto *p = (struct stats_proto *) P;
  log(L_INFO "stats_start() ");

  p->counters = (u32 *) mb_allocz(p->p.pool, 256 * sizeof(u32));

  return PS_UP;
}

static int
stats_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct stats_proto *p = (void *) P;
  struct stats_config *cf = (void *) CF;

  //return stats_configure_channels(p, cf);
  return 1;
}

static void
stats_copy_config(struct proto_config *dest UNUSED, struct proto_config *src UNUSED)
{
  /* Just a shallow copy, not many items here */
}

static void
stats_get_status(struct proto *P, byte *buf)
{
  struct stats_proto *p = (void *) P;
}

static void
stats_show_proto_info(struct proto *P)
{
  struct stats_proto *p = (void *) P;

  cli_msg(-1006, "  Counters contents  ");
  for (int i = 0; i < 64; i++) 
  {
    cli_msg(-1006, "%3u: %10u | %3u: %10u | %3u: %10u | %3u: %10u",
       i       , *(p->counters + i),
      (i + 64 ), *(p->counters + i + 64),
      (i + 128), *(p->counters + i + 128),
      (i + 192), *(p->counters + i + 192)
    );
  }   
}

void
stats_update_debug(struct proto *P)
{
  struct stats_proto *p = (void *) P;

  p->c->debug = p->p.debug;
}


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
  .get_status = 	stats_get_status,
  .show_proto_info = 	stats_show_proto_info
};

void
stats_build(void)
{
  proto_build(&proto_stats);
}
