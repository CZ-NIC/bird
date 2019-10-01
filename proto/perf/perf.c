/*
 *	BIRD -- Table-to-Table Routing Protocol a.k.a Pipe
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Perf
 *
 * Run this protocol to measure route import and export times.
 * Generates a load of dummy routes and measures time to import.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "lib/string.h"

#include "perf.h"

#include <stdlib.h>
#include <time.h>

#define PLOG(msg, ...) log(L_INFO "Perf %s %s " msg, BIRD_VERSION, p->p.name, ##__VA_ARGS__)

static inline void
random_data(void *p, uint len)
{
  uint ints = (len + sizeof(int) - 1) / sizeof(int);
  int *d = alloca(sizeof(uint) * ints);
  for (uint i=0; i<ints; i++)
    d[i] = random();

  memcpy(p, d, len);
}

static ip_addr
random_gw(net_addr *prefix)
{
  ASSERT(net_is_ip(prefix));
  ip_addr px = net_prefix(prefix);
  ip_addr mask = net_pxmask(prefix);

  ip_addr out;
  random_data(&out, sizeof(ip_addr));

  if (ipa_is_ip4(px))
    out = ipa_and(out, ipa_from_ip4(ip4_mkmask(32)));

  return ipa_or(ipa_and(px, mask), ipa_and(out, ipa_not(mask)));
}

static net_addr_ip4
random_net_ip4(void)
{
  u32 x; random_data(&x, sizeof(u32));
  x &= ((1 << 20) - 1);
  uint pxlen = u32_log2(x) + 5;

  ip4_addr px; random_data(&px, sizeof(ip4_addr));

  net_addr_ip4 out = {
    .type = NET_IP4,
    .pxlen = pxlen,
    .length = sizeof(net_addr_ip4),
    .prefix = ip4_and(ip4_mkmask(pxlen), px),
  };

  if (!net_validate((net_addr *) &out))
    return random_net_ip4();

  int c = net_classify((net_addr *) &out);
  if ((c < 0) || !(c & IADDR_HOST) || ((c & IADDR_SCOPE_MASK) <= SCOPE_LINK))
    return random_net_ip4();

  return out;
}

struct perf_random_routes {
  net_addr net;
  rte *ep;
  struct rta a;
};

static const uint perf_random_routes_size = sizeof(struct perf_random_routes) + (RTA_MAX_SIZE - sizeof(struct rta));

static inline s64 timediff(struct timespec *begin, struct timespec *end)
{ return (end->tv_sec - begin->tv_sec) * (s64) 1000000000 + end->tv_nsec - begin->tv_nsec; }

static void
perf_ifa_notify(struct proto *P, uint flags, struct ifa *ad)
{
  struct perf_proto *p = (struct perf_proto *) P;

  if (ad->flags & IA_SECONDARY)
    return;

  if (p->ifa && p->ifa == ad && (flags & IF_CHANGE_DOWN)) {
    p->ifa = NULL;
    if (ev_active(p->loop))
      ev_postpone(p->loop);

    return;
  }

  if (!p->ifa && (flags & IF_CHANGE_UP)) {
    p->ifa = ad;
    ev_schedule(p->loop);
    PLOG("starting");
    return;
  }
}

static void
perf_loop(void *data)
{
  struct proto *P = data;
  struct perf_proto *p = data;

  const uint N = 1U << p->exp;
  const uint offset = perf_random_routes_size;

  if (!p->run) {
    ASSERT(p->data == NULL);
    p->data = xmalloc(offset * N);
    bzero(p->data, offset * N);
    p->stop = 1;
  }

  ip_addr gw = random_gw(&p->ifa->prefix);

  struct timespec ts_begin, ts_generated, ts_update, ts_withdraw;

  clock_gettime(CLOCK_MONOTONIC, &ts_begin);

  struct rta *a = NULL;

  for (uint i=0; i<N; i++) {
    struct perf_random_routes *prr = p->data + offset * i;
    *((net_addr_ip4 *) &prr->net) = random_net_ip4();

    if (!p->attrs_per_rte || !(i % p->attrs_per_rte)) {
      a = &prr->a;
      bzero(a, RTA_MAX_SIZE);

      a->src = p->p.main_source;
      a->source = RTS_PERF;
      a->scope = SCOPE_UNIVERSE;
      a->dest = RTD_UNICAST;

      a->nh.iface = p->ifa->iface;
      a->nh.gw = gw;
      a->nh.weight = 1;

      if (p->attrs_per_rte)
	a = rta_lookup(a);
    }

    ASSERT(a);

    prr->ep = rte_get_temp(a);
    prr->ep->pflags = 0;
  }

  clock_gettime(CLOCK_MONOTONIC, &ts_generated);

  for (uint i=0; i<N; i++) {
    struct perf_random_routes *prr = p->data + offset * i;
    rte_update(P, &prr->net, prr->ep);
  }

  clock_gettime(CLOCK_MONOTONIC, &ts_update);

  if (!p->keep)
    for (uint i=0; i<N; i++) {
      struct perf_random_routes *prr = p->data + offset * i;
      rte_update(P, &prr->net, NULL);
    }

  clock_gettime(CLOCK_MONOTONIC, &ts_withdraw);

  s64 gentime = timediff(&ts_begin, &ts_generated);
  s64 updatetime = timediff(&ts_generated, &ts_update);
  s64 withdrawtime = timediff(&ts_update, &ts_withdraw);

  if (updatetime NS >= p->threshold_min)
    PLOG("exp=%u times: gen=%ld update=%ld withdraw=%ld",
	p->exp, gentime, updatetime, withdrawtime);

  if (updatetime NS < p->threshold_max)
    p->stop = 0;

  if ((updatetime NS < p->threshold_min) || (++p->run == p->repeat)) {
    xfree(p->data);
    p->data = NULL;

    if (p->stop || (p->exp == p->to)) {
      PLOG("done with exp=%u", p->exp);
      return;
    }

    p->run = 0;
    p->exp++;
  }

  rt_schedule_prune(P->main_channel->table);
  ev_schedule(p->loop);
}

static void
perf_rt_notify(struct proto *P, struct channel *c UNUSED, struct network *net UNUSED, struct rte *new UNUSED, struct rte *old UNUSED)
{
  struct perf_proto *p = (struct perf_proto *) P;
  p->exp++;
  return;
}

static void
perf_feed_begin(struct channel *c, int initial UNUSED)
{
  struct perf_proto *p = (struct perf_proto *) c->proto;

  p->run++;
  p->data = xmalloc(sizeof(struct timespec));
  p->exp = 0;

  clock_gettime(CLOCK_MONOTONIC, p->data);
}

static void
perf_feed_end(struct channel *c)
{
  struct perf_proto *p = (struct perf_proto *) c->proto;
  struct timespec ts_end;
  clock_gettime(CLOCK_MONOTONIC, &ts_end);

  s64 feedtime = timediff(p->data, &ts_end);

  PLOG("feed n=%lu time=%lu", p->exp, feedtime);

  if (p->run < p->repeat)
    channel_request_feeding(c);
  else
    PLOG("feed done");
}

static struct proto *
perf_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);

  P->main_channel = proto_add_channel(P, proto_cf_main_channel(CF));

  struct perf_proto *p = (struct perf_proto *) P;

  p->loop = ev_new_init(P->pool, perf_loop, p);

  struct perf_config *cf = (struct perf_config *) CF;

  p->threshold_min = cf->threshold_min;
  p->threshold_max = cf->threshold_max;
  p->from = cf->from;
  p->to = cf->to;
  p->repeat = cf->repeat;
  p->keep = cf->keep;
  p->mode = cf->mode;
  p->attrs_per_rte = cf->attrs_per_rte;

  switch (p->mode) {
    case PERF_MODE_IMPORT:
      P->ifa_notify = perf_ifa_notify;
      break;
    case PERF_MODE_EXPORT:
      P->rt_notify = perf_rt_notify;
      P->feed_begin = perf_feed_begin;
      P->feed_end = perf_feed_end;
      break;
  }

  return P;
}

static int
perf_start(struct proto *P)
{
  struct perf_proto *p = (struct perf_proto *) P;

  p->ifa = NULL;
  p->run = 0;
  p->exp = p->from;
  ASSERT(p->data == NULL);

  return PS_UP;
}

static int
perf_reconfigure(struct proto *P UNUSED, struct proto_config *CF UNUSED)
{
  return 0;
}

static void
perf_copy_config(struct proto_config *dest UNUSED, struct proto_config *src UNUSED)
{
}

struct protocol proto_perf = {
  .name = 		"Perf",
  .template =		"perf%d",
  .class =		PROTOCOL_PERF,
  .channel_mask = 	NB_IP,
  .proto_size =		sizeof(struct perf_proto),
  .config_size = 	sizeof(struct perf_config),
  .init =		perf_init,
  .start =		perf_start,
  .reconfigure = 	perf_reconfigure,
  .copy_config =	perf_copy_config,
};
