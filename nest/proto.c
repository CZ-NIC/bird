/*
 *	BIRD -- Protocols
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/protocol.h"
#include "lib/resource.h"
#include "lib/lists.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/string.h"
#include "conf/conf.h"
#include "nest/rt.h"
#include "nest/iface.h"
#include "nest/cli.h"
#include "filter/filter.h"
#include "filter/f-inst.h"

pool *proto_pool;
list STATIC_LIST_INIT(proto_list);

static list STATIC_LIST_INIT(protocol_list);

#define CD(c, msg, args...) ({ if (c->debug & D_STATES) log(L_TRACE "%s.%s: " msg, c->proto->name, c->name ?: "?", ## args); })
#define PD(p, msg, args...) ({ if (p->debug & D_STATES) log(L_TRACE "%s: " msg, p->name, ## args); })

static timer *proto_shutdown_timer;
static timer *gr_wait_timer;

#define GRS_NONE	0
#define GRS_INIT	1
#define GRS_ACTIVE	2
#define GRS_DONE	3

static int graceful_restart_state;
static u32 graceful_restart_locks;

static char *p_states[] = { "DOWN", "START", "UP", "STOP" };
static char *c_states[] = { "DOWN", "START", "UP", "STOP", "RESTART" };

extern struct protocol proto_unix_iface;

static void channel_request_reload(struct channel *c);
static void proto_shutdown_loop(timer *);
static void proto_rethink_goal(struct proto *p);
static char *proto_state_name(struct proto *p);
static void channel_init_limit(struct channel *c, struct limit *l, int dir, struct channel_limit *cf);
static void channel_update_limit(struct channel *c, struct limit *l, int dir, struct channel_limit *cf);
static void channel_reset_limit(struct channel *c, struct limit *l, int dir);
static void channel_feed_end(struct channel *c);
static void channel_export_stopped(struct rt_export_request *req);
static void channel_check_stopped(struct channel *c);

static inline int proto_is_done(struct proto *p)
{ return (p->proto_state == PS_DOWN) && proto_is_inactive(p); }

static inline event_list *proto_event_list(struct proto *p)
{ return p->loop == &main_birdloop ? &global_event_list : birdloop_event_list(p->loop); }

static inline event_list *proto_work_list(struct proto *p)
{ return p->loop == &main_birdloop ? &global_work_list : birdloop_event_list(p->loop); }

static inline void proto_send_event(struct proto *p)
{ ev_send(proto_event_list(p), p->event); }

#define PROTO_ENTER_FROM_MAIN(p)    ({ \
    ASSERT_DIE(birdloop_inside(&main_birdloop)); \
    struct birdloop *_loop = (p)->loop; \
    if (_loop != &main_birdloop) birdloop_enter(_loop); \
    _loop; \
    })

#define PROTO_LEAVE_FROM_MAIN(loop) ({ if (loop != &main_birdloop) birdloop_leave(loop); })

#define PROTO_LOCKED_FROM_MAIN(p)	for (struct birdloop *_proto_loop = PROTO_ENTER_FROM_MAIN(p); _proto_loop; PROTO_LEAVE_FROM_MAIN(_proto_loop), (_proto_loop = NULL))


static inline int channel_is_active(struct channel *c)
{ return (c->channel_state != CS_DOWN); }

static inline int channel_reloadable(struct channel *c)
{ return c->proto->reload_routes && c->reloadable; }

static inline void
channel_log_state_change(struct channel *c)
{
  CD(c, "State changed to %s", c_states[c->channel_state]);
}

void
channel_import_log_state_change(struct rt_import_request *req, u8 state)
{
  struct channel *c = SKIP_BACK(struct channel, in_req, req);
  CD(c, "Channel import state changed to %s", rt_import_state_name(state));
}

void
channel_export_log_state_change(struct rt_export_request *req, u8 state)
{
  struct channel *c = SKIP_BACK(struct channel, out_req, req);
  CD(c, "Channel export state changed to %s", rt_export_state_name(state));

  switch (state)
  {
    case TES_FEEDING:
      if (c->proto->feed_begin)
	c->proto->feed_begin(c, !c->refeeding);
      break;
    case TES_READY:
      channel_feed_end(c);
      break;
  }
}

static void
channel_dump_import_req(struct rt_import_request *req)
{
  struct channel *c = SKIP_BACK(struct channel, in_req, req);
  debug("  Channel %s.%s import request %p\n", c->proto->name, c->name, req);
}

static void
channel_dump_export_req(struct rt_export_request *req)
{
  struct channel *c = SKIP_BACK(struct channel, out_req, req);
  debug("  Channel %s.%s export request %p\n", c->proto->name, c->name, req);
}

static void
proto_log_state_change(struct proto *p)
{
  if (p->debug & D_STATES)
  {
    char *name = proto_state_name(p);
    if (name != p->last_state_name_announced)
    {
      p->last_state_name_announced = name;
      PD(p, "State changed to %s", proto_state_name(p));
    }
  }
  else
    p->last_state_name_announced = NULL;
}


struct channel_config *
proto_cf_find_channel(struct proto_config *pc, uint net_type)
{
  struct channel_config *cc;

  WALK_LIST(cc, pc->channels)
    if (cc->net_type == net_type)
      return cc;

  return NULL;
}

/**
 * proto_find_channel_by_table - find channel connected to a routing table
 * @p: protocol instance
 * @t: routing table
 *
 * Returns pointer to channel or NULL
 */
struct channel *
proto_find_channel_by_table(struct proto *p, rtable *t)
{
  struct channel *c;

  WALK_LIST(c, p->channels)
    if (c->table == t)
      return c;

  return NULL;
}

/**
 * proto_find_channel_by_name - find channel by its name
 * @p: protocol instance
 * @n: channel name
 *
 * Returns pointer to channel or NULL
 */
struct channel *
proto_find_channel_by_name(struct proto *p, const char *n)
{
  struct channel *c;

  WALK_LIST(c, p->channels)
    if (!strcmp(c->name, n))
      return c;

  return NULL;
}

int channel_preimport(struct rt_import_request *req, rte *new, rte *old);

void rt_notify_optimal(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *rpe);
void rt_notify_any(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *rpe);
void rt_feed_any(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *rpe, rte **feed, uint count);
void rt_notify_accepted(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *rpe, rte **feed, uint count);
void rt_notify_merged(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *rpe, rte **feed, uint count);


/**
 * proto_add_channel - connect protocol to a routing table
 * @p: protocol instance
 * @cf: channel configuration
 *
 * This function creates a channel between the protocol instance @p and the
 * routing table specified in the configuration @cf, making the protocol hear
 * all changes in the table and allowing the protocol to update routes in the
 * table.
 *
 * The channel is linked in the protocol channel list and when active also in
 * the table channel list. Channels are allocated from the global resource pool
 * (@proto_pool) and they are automatically freed when the protocol is removed.
 */

struct channel *
proto_add_channel(struct proto *p, struct channel_config *cf)
{
  struct channel *c = mb_allocz(proto_pool, cf->channel->channel_size);

  c->name = cf->name;
  c->channel = cf->channel;
  c->proto = p;
  c->table = cf->table->table;
  rt_lock_table(c->table);

  c->in_filter = cf->in_filter;
  c->out_filter = cf->out_filter;
  c->out_subprefix = cf->out_subprefix;

  channel_init_limit(c, &c->rx_limit, PLD_RX, &cf->rx_limit);
  channel_init_limit(c, &c->in_limit, PLD_IN, &cf->in_limit);
  channel_init_limit(c, &c->out_limit, PLD_OUT, &cf->out_limit);

  c->net_type = cf->net_type;
  c->ra_mode = cf->ra_mode;
  c->preference = cf->preference;
  c->debug = cf->debug;
  c->merge_limit = cf->merge_limit;
  c->in_keep = cf->in_keep;
  c->rpki_reload = cf->rpki_reload;

  c->channel_state = CS_DOWN;
  c->last_state_change = current_time();
  c->reloadable = 1;

  init_list(&c->roa_subscriptions);

  CALL(c->channel->init, c, cf);

  add_tail(&p->channels, &c->n);

  CD(c, "Connected to table %s", c->table->name);

  return c;
}

void
proto_remove_channel(struct proto *p UNUSED, struct channel *c)
{
  ASSERT(c->channel_state == CS_DOWN);

  CD(c, "Removed", c->name);

  rt_unlock_table(c->table);
  rem_node(&c->n);
  mb_free(c);
}


static void
proto_start_channels(struct proto *p)
{
  struct channel *c;
  WALK_LIST(c, p->channels)
    if (!c->disabled)
      channel_set_state(c, CS_UP);
}

static void
proto_pause_channels(struct proto *p)
{
  struct channel *c;
  WALK_LIST(c, p->channels)
    if (!c->disabled && channel_is_active(c))
      channel_set_state(c, CS_PAUSE);
}

static void
proto_stop_channels(struct proto *p)
{
  struct channel *c;
  WALK_LIST(c, p->channels)
    if (!c->disabled && channel_is_active(c))
      channel_set_state(c, CS_STOP);
}

static void
proto_remove_channels(struct proto *p)
{
  struct channel *c;
  WALK_LIST_FIRST(c, p->channels)
    proto_remove_channel(p, c);
}

struct roa_subscription {
  node roa_node;
  struct settle settle;
  struct channel *c;
  struct rt_export_request req;
};

static void
channel_roa_in_changed(struct settle *se)
{
  struct roa_subscription *s = SKIP_BACK(struct roa_subscription, settle, se);
  struct channel *c = s->c;
  int active = !!c->reload_req.hook;

  CD(c, "Reload triggered by RPKI change%s", active ? " - already active" : "");

  if (!active)
    channel_request_reload(c);
  else
    c->reload_pending = 1;
}

static void
channel_roa_out_changed(struct settle *se)
{
  struct roa_subscription *s = SKIP_BACK(struct roa_subscription, settle, se);
  struct channel *c = s->c;

  CD(c, "Feeding triggered by RPKI change");

  c->refeed_pending = 1;

  if (c->out_req.hook)
    rt_stop_export(&c->out_req, channel_export_stopped);
}

static void
channel_export_one_roa(struct rt_export_request *req, const net_addr *net UNUSED, struct rt_pending_export *first)
{
  struct roa_subscription *s = SKIP_BACK(struct roa_subscription, req, req);

  /* TODO: use the information about what roa has changed */
  settle_kick(&s->settle, s->c->proto->loop);

  rpe_mark_seen_all(req->hook, first, NULL);
}

static void
channel_dump_roa_req(struct rt_export_request *req)
{
  struct roa_subscription *s = SKIP_BACK(struct roa_subscription, req, req);
  struct channel *c = s->c;
  struct rtable_private *tab = SKIP_BACK(struct rtable_private, exporter.e, req->hook->table);

  debug("  Channel %s.%s ROA %s change notifier from table %s request %p\n",
      c->proto->name, c->name,
      (s->settle.hook == channel_roa_in_changed) ? "import" : "export",
      tab->name, req);
}

static int
channel_roa_is_subscribed(struct channel *c, rtable *tab, int dir)
{
  void (*hook)(struct settle *) =
    dir ? channel_roa_in_changed : channel_roa_out_changed;

  struct roa_subscription *s;
  node *n;

  WALK_LIST2(s, n, c->roa_subscriptions, roa_node)
    if ((tab == SKIP_BACK(rtable, priv.exporter.e, s->req.hook->table))
	  && (s->settle.hook == hook))
      return 1;

  return 0;
}

static void
channel_roa_subscribe(struct channel *c, rtable *tab, int dir)
{
  if (channel_roa_is_subscribed(c, tab, dir))
    return;

  struct roa_subscription *s = mb_allocz(c->proto->pool, sizeof(struct roa_subscription));

  *s = (struct roa_subscription) {
    .settle = SETTLE_INIT(&c->roa_settle, dir ? channel_roa_in_changed : channel_roa_out_changed, NULL),
    .c = c,
    .req = {
      .name = mb_sprintf(c->proto->pool, "%s.%s.roa-%s.%s",
	  c->proto->name, c->name, dir ? "in" : "out", tab->name),
      .list = proto_work_list(c->proto),
      .trace_routes = c->debug | c->proto->debug,
      .dump_req = channel_dump_roa_req,
      .export_one = channel_export_one_roa,
    },
  };

  add_tail(&c->roa_subscriptions, &s->roa_node);
  rt_request_export(tab, &s->req);
}

static void
channel_roa_unsubscribed(struct rt_export_request *req)
{
  struct roa_subscription *s = SKIP_BACK(struct roa_subscription, req, req);
  struct channel *c = s->c;

  rem_node(&s->roa_node);
  mb_free(s);
  
  channel_check_stopped(c);
}

static void
channel_roa_unsubscribe(struct roa_subscription *s)
{
  rt_stop_export(&s->req, channel_roa_unsubscribed);
}

static void
channel_roa_subscribe_filter(struct channel *c, int dir)
{
  const struct filter *f = dir ? c->in_filter : c->out_filter;
  rtable *tab;
  int valid = 1, found = 0;

  if ((f == FILTER_ACCEPT) || (f == FILTER_REJECT))
    return;

  /* No automatic reload for non-reloadable channels */
  if (dir && !channel_reloadable(c))
    valid = 0;

#ifdef CONFIG_BGP
  /* No automatic reload for BGP channels without in_table / out_table */
  if (c->channel == &channel_bgp)
    valid = dir ? ((c->in_keep & RIK_PREFILTER) == RIK_PREFILTER) : !!c->out_table;
#endif

  struct filter_iterator fit;
  FILTER_ITERATE_INIT(&fit, f, c->proto->pool);

  FILTER_ITERATE(&fit, fi)
  {
    switch (fi->fi_code)
    {
    case FI_ROA_CHECK:
      tab = fi->i_FI_ROA_CHECK.rtc->table;
      if (valid) channel_roa_subscribe(c, tab, dir);
      found = 1;
      break;

    default:
      break;
    }
  }
  FILTER_ITERATE_END;

  FILTER_ITERATE_CLEANUP(&fit);

  if (!valid && found)
    log(L_WARN "%s.%s: Automatic RPKI reload not active for %s",
	c->proto->name, c->name ?: "?", dir ? "import" : "export");
}

static void
channel_roa_unsubscribe_all(struct channel *c)
{
  struct roa_subscription *s;
  node *n, *x;

  WALK_LIST2_DELSAFE(s, n, x, c->roa_subscriptions, roa_node)
    channel_roa_unsubscribe(s);
}

static void
channel_start_import(struct channel *c)
{
  if (c->in_req.hook)
  {
    log(L_WARN "%s.%s: Attempted to start channel's already started import", c->proto->name, c->name);
    return;
  }

  c->in_req = (struct rt_import_request) {
    .name = mb_sprintf(c->proto->pool, "%s.%s", c->proto->name, c->name),
    .trace_routes = c->debug | c->proto->debug,
    .list = proto_work_list(c->proto),
    .dump_req = channel_dump_import_req,
    .log_state_change = channel_import_log_state_change,
    .preimport = channel_preimport,
  };

  ASSERT(c->channel_state == CS_UP);

  channel_reset_limit(c, &c->rx_limit, PLD_RX);
  channel_reset_limit(c, &c->in_limit, PLD_IN);

  memset(&c->import_stats, 0, sizeof(struct channel_import_stats));

  DBG("%s.%s: Channel start import req=%p\n", c->proto->name, c->name, &c->in_req);
  rt_request_import(c->table, &c->in_req);
}

static void
channel_start_export(struct channel *c)
{
  if (c->out_req.hook)
  {
    log(L_WARN "%s.%s: Attempted to start channel's already started export", c->proto->name, c->name);
    return;
  }

  ASSERT(c->channel_state == CS_UP);

  c->out_req = (struct rt_export_request) {
    .name = mb_sprintf(c->proto->pool, "%s.%s", c->proto->name, c->name),
    .list = proto_work_list(c->proto),
    .addr = c->out_subprefix,
    .addr_mode = c->out_subprefix ? TE_ADDR_IN : TE_ADDR_NONE,
    .trace_routes = c->debug | c->proto->debug,
    .dump_req = channel_dump_export_req,
    .log_state_change = channel_export_log_state_change,
  };

  bmap_init(&c->export_map, c->proto->pool, 1024);
  bmap_init(&c->export_reject_map, c->proto->pool, 1024);

  channel_reset_limit(c, &c->out_limit, PLD_OUT);

  memset(&c->export_stats, 0, sizeof(struct channel_export_stats));

  switch (c->ra_mode) {
    case RA_OPTIMAL:
      c->out_req.export_one = rt_notify_optimal;
      break;
    case RA_ANY:
      c->out_req.export_one = rt_notify_any;
      c->out_req.export_bulk = rt_feed_any;
      break;
    case RA_ACCEPTED:
      c->out_req.export_bulk = rt_notify_accepted;
      break;
    case RA_MERGED:
      c->out_req.export_bulk = rt_notify_merged;
      break;
    default:
      bug("Unknown route announcement mode");
  }

  DBG("%s.%s: Channel start export req=%p\n", c->proto->name, c->name, &c->out_req);
  rt_request_export(c->table, &c->out_req);
}

static void
channel_check_stopped(struct channel *c)
{
  switch (c->channel_state)
  {
    case CS_STOP:
      if (!EMPTY_LIST(c->roa_subscriptions) || c->out_req.hook || c->in_req.hook)
	return;

      channel_set_state(c, CS_DOWN);
      proto_send_event(c->proto);

      break;
    case CS_PAUSE:
      if (!EMPTY_LIST(c->roa_subscriptions) || c->out_req.hook)
	return;

      channel_set_state(c, CS_START);
      break;
    default:
      bug("Stopped channel in a bad state: %d", c->channel_state);
  }

  DBG("%s.%s: Channel requests/hooks stopped (in state %s)\n", c->proto->name, c->name, c_states[c->channel_state]);
}

void
channel_import_stopped(struct rt_import_request *req)
{
  struct channel *c = SKIP_BACK(struct channel, in_req, req);

  mb_free(c->in_req.name);
  c->in_req.name = NULL;

  channel_check_stopped(c);
}

static void
channel_export_stopped(struct rt_export_request *req)
{
  struct channel *c = SKIP_BACK(struct channel, out_req, req);

  /* The hook has already stopped */
  req->hook = NULL;

  if (c->refeed_pending)
  {
    c->refeeding = 1;
    c->refeed_pending = 0;
    rt_request_export(c->table, req);
    return;
  }

  mb_free(c->out_req.name);
  c->out_req.name = NULL;

  channel_check_stopped(c);
}

static void
channel_feed_end(struct channel *c)
{
  struct rt_export_request *req = &c->out_req;

  /* Reset export limit if the feed ended with acceptable number of exported routes */
  struct limit *l = &c->out_limit;
  if (c->refeeding &&
      (c->limit_active & (1 << PLD_OUT)) &&
      (c->refeed_count <= l->max) &&
      (l->count <= l->max))
  {
    log(L_INFO "Protocol %s resets route export limit (%u)", c->proto->name, l->max);

    c->refeed_pending = 1;
    rt_stop_export(req, channel_export_stopped);
    return;
  }

  if (c->proto->feed_end)
    c->proto->feed_end(c);

  if (c->refeed_pending)
    rt_stop_export(req, channel_export_stopped);
  else
    c->refeeding = 0;
}

/* Called by protocol for reload from in_table */
void
channel_schedule_reload(struct channel *c)
{
  ASSERT(c->in_req.hook);

  rt_request_export(c->table, &c->reload_req);
}

static void
channel_reload_stopped(struct rt_export_request *req)
{
  struct channel *c = SKIP_BACK(struct channel, reload_req, req);

  /* Restart reload */
  if (c->reload_pending)
    channel_request_reload(c);
}

static void
channel_reload_log_state_change(struct rt_export_request *req, u8 state)
{
  if (state == TES_READY)
    rt_stop_export(req, channel_reload_stopped);
}

static void
channel_reload_dump_req(struct rt_export_request *req)
{
  struct channel *c = SKIP_BACK(struct channel, reload_req, req);
  debug("  Channel %s.%s import reload request %p\n", c->proto->name, c->name, req);
}

void channel_reload_export_bulk(struct rt_export_request *req, const net_addr *net, struct rt_pending_export *rpe, rte **feed, uint count);

/* Called by protocol to activate in_table */
void
channel_setup_in_table(struct channel *c)
{
  c->reload_req = (struct rt_export_request) {
    .name = mb_sprintf(c->proto->pool, "%s.%s.import", c->proto->name, c->name),
    .list = proto_work_list(c->proto),
    .trace_routes = c->debug | c->proto->debug,
    .export_bulk = channel_reload_export_bulk,
    .dump_req = channel_reload_dump_req,
    .log_state_change = channel_reload_log_state_change,
  };

  c->in_keep |= RIK_PREFILTER;
}


static void
channel_do_start(struct channel *c)
{
  c->proto->active_channels++;

  CALL(c->channel->start, c);

  channel_start_import(c);
}

static void
channel_do_up(struct channel *c)
{
  /* Register RPKI/ROA subscriptions */
  if (c->rpki_reload)
  {
    channel_roa_subscribe_filter(c, 1);
    channel_roa_subscribe_filter(c, 0);
  }
}

static void
channel_do_pause(struct channel *c)
{
  /* Need to abort feeding */
  if (c->reload_req.hook)
  {
    c->reload_pending = 0;
    rt_stop_export(&c->reload_req, channel_reload_stopped);
  }

  /* Stop export */
  if (c->refeed_pending)
    c->refeed_pending = 0;
  else if (c->out_req.hook)
    rt_stop_export(&c->out_req, channel_export_stopped);

  channel_roa_unsubscribe_all(c);

  bmap_free(&c->export_map);
  bmap_free(&c->export_reject_map);
}

static void
channel_do_stop(struct channel *c)
{
  /* Stop import */
  if (c->in_req.hook)
    rt_stop_import(&c->in_req, channel_import_stopped);

  c->gr_wait = 0;
  if (c->gr_lock)
    channel_graceful_restart_unlock(c);

  CALL(c->channel->shutdown, c);

}

static void
channel_do_down(struct channel *c)
{
  ASSERT(!c->reload_req.hook);

  c->proto->active_channels--;

  // bmap_free(&c->export_map);
  memset(&c->import_stats, 0, sizeof(struct channel_import_stats));
  memset(&c->export_stats, 0, sizeof(struct channel_export_stats));

  c->out_table = NULL;

  /* The in_table and out_table are going to be freed by freeing their resource pools. */

  CALL(c->channel->cleanup, c);

  /* Schedule protocol shutddown */
  if (proto_is_done(c->proto))
    proto_send_event(c->proto);
}

void
channel_set_state(struct channel *c, uint state)
{
  uint cs = c->channel_state;

  DBG("%s reporting channel %s state transition %s -> %s\n", c->proto->name, c->name, c_states[cs], c_states[state]);
  if (state == cs)
    return;

  c->channel_state = state;
  c->last_state_change = current_time();

  switch (state)
  {
  case CS_START:
    ASSERT(cs == CS_DOWN || cs == CS_PAUSE);

    if (cs == CS_DOWN)
      channel_do_start(c);

    break;

  case CS_UP:
    ASSERT(cs == CS_DOWN || cs == CS_START);

    if (cs == CS_DOWN)
      channel_do_start(c);

    if (!c->gr_wait && c->proto->rt_notify)
      channel_start_export(c);

    channel_do_up(c);
    break;

  case CS_PAUSE:
    ASSERT(cs == CS_UP);

    if (cs == CS_UP)
      channel_do_pause(c);
    break;

  case CS_STOP:
    ASSERT(cs == CS_UP || cs == CS_START || cs == CS_PAUSE);

    if (cs == CS_UP)
      channel_do_pause(c);

    channel_do_stop(c);
    break;

  case CS_DOWN:
    ASSERT(cs == CS_STOP);

    channel_do_down(c);
    break;

  default:
    ASSERT(0);
  }

  channel_log_state_change(c);
}

/**
 * channel_request_feeding - request feeding routes to the channel
 * @c: given channel
 *
 * Sometimes it is needed to send again all routes to the channel. This is
 * called feeding and can be requested by this function. This would cause
 * channel export state transition to ES_FEEDING (during feeding) and when
 * completed, it will switch back to ES_READY. This function can be called
 * even when feeding is already running, in that case it is restarted.
 */
void
channel_request_feeding(struct channel *c)
{
  ASSERT(c->out_req.hook);

  if (c->refeed_pending)
    return;

  c->refeed_pending = 1;
  rt_stop_export(&c->out_req, channel_export_stopped);
}

static void
channel_request_reload(struct channel *c)
{
  ASSERT(c->in_req.hook);
  ASSERT(channel_reloadable(c));

  CD(c, "Reload requested");

  c->proto->reload_routes(c);

  /*
   * Should this be done before reload_routes() hook?
   * Perhaps, but routes are updated asynchronously.
   */
  channel_reset_limit(c, &c->rx_limit, PLD_RX);
  channel_reset_limit(c, &c->in_limit, PLD_IN);
}

const struct channel_class channel_basic = {
  .channel_size = sizeof(struct channel),
  .config_size = sizeof(struct channel_config)
};

void *
channel_config_new(const struct channel_class *cc, const char *name, uint net_type, struct proto_config *proto)
{
  struct channel_config *cf = NULL;
  struct rtable_config *tab = NULL;

  if (net_type)
  {
    if (!net_val_match(net_type, proto->protocol->channel_mask))
      cf_error("Unsupported channel type");

    if (proto->net_type && (net_type != proto->net_type))
      cf_error("Different channel type");

    tab = rt_get_default_table(new_config, net_type);
  }

  if (!cc)
    cc = &channel_basic;

  cf = cfg_allocz(cc->config_size);
  cf->name = name;
  cf->channel = cc;
  cf->parent = proto;
  cf->table = tab;
  cf->out_filter = FILTER_REJECT;

  cf->net_type = net_type;
  cf->ra_mode = RA_OPTIMAL;
  cf->preference = proto->protocol->preference;
  cf->debug = new_config->channel_default_debug;
  cf->rpki_reload = 1;

  cf->roa_settle = (struct settle_config) {
    .min = 1 S,
    .max = 20 S,
  };

  add_tail(&proto->channels, &cf->n);

  return cf;
}

void *
channel_config_get(const struct channel_class *cc, const char *name, uint net_type, struct proto_config *proto)
{
  struct channel_config *cf;

  /* We are using name as token, so no strcmp() */
  WALK_LIST(cf, proto->channels)
    if (cf->name == name)
    {
      /* Allow to redefine channel only if inherited from template */
      if (cf->parent == proto)
	cf_error("Multiple %s channels", name);

      cf->parent = proto;
      return cf;
    }

  return channel_config_new(cc, name, net_type, proto);
}

struct channel_config *
channel_copy_config(struct channel_config *src, struct proto_config *proto)
{
  struct channel_config *dst = cfg_alloc(src->channel->config_size);

  memcpy(dst, src, src->channel->config_size);
  memset(&dst->n, 0, sizeof(node));
  add_tail(&proto->channels, &dst->n);
  CALL(src->channel->copy_config, dst, src);

  return dst;
}


static int reconfigure_type;  /* Hack to propagate type info to channel_reconfigure() */

int
channel_reconfigure(struct channel *c, struct channel_config *cf)
{
  /* FIXME: better handle these changes, also handle in_keep_filtered */
  if ((c->table != cf->table->table) ||
      (cf->ra_mode && (c->ra_mode != cf->ra_mode)) ||
      (cf->in_keep != c->in_keep) ||
      cf->out_subprefix && c->out_subprefix &&
	  !net_equal(cf->out_subprefix, c->out_subprefix) ||
      (!cf->out_subprefix != !c->out_subprefix))
    return 0;

  /* Note that filter_same() requires arguments in (new, old) order */
  int import_changed = !filter_same(cf->in_filter, c->in_filter);
  int export_changed = !filter_same(cf->out_filter, c->out_filter);
  int rpki_reload_changed = (cf->rpki_reload != c->rpki_reload);

  if (c->preference != cf->preference)
    import_changed = 1;

  if (c->merge_limit != cf->merge_limit)
    export_changed = 1;

  /* Reconfigure channel fields */
  c->in_filter = cf->in_filter;
  c->out_filter = cf->out_filter;

  channel_update_limit(c, &c->rx_limit, PLD_RX, &cf->rx_limit);
  channel_update_limit(c, &c->in_limit, PLD_IN, &cf->in_limit);
  channel_update_limit(c, &c->out_limit, PLD_OUT, &cf->out_limit);

  // c->ra_mode = cf->ra_mode;
  c->merge_limit = cf->merge_limit;
  c->preference = cf->preference;
  c->out_req.addr = c->out_subprefix = cf->out_subprefix;
  c->debug = cf->debug;
  c->in_req.trace_routes = c->out_req.trace_routes = c->debug | c->proto->debug;
  c->rpki_reload = cf->rpki_reload;

  if (	  (c->roa_settle.min != cf->roa_settle.min)
       || (c->roa_settle.max != cf->roa_settle.max))
  {
    c->roa_settle = cf->roa_settle;

    struct roa_subscription *s;
    node *n;

    WALK_LIST2(s, n, c->roa_subscriptions, roa_node)
    {
      s->settle.cf = cf->roa_settle;
      if (settle_active(&s->settle))
	settle_kick(&s->settle, &main_birdloop);
    }
  }

  /* Execute channel-specific reconfigure hook */
  if (c->channel->reconfigure && !c->channel->reconfigure(c, cf, &import_changed, &export_changed))
    return 0;

  /* If the channel is not open, it has no routes and we cannot reload it anyways */
  if (c->channel_state != CS_UP)
    goto done;

  /* Update RPKI/ROA subscriptions */
  if (import_changed || export_changed || rpki_reload_changed)
  {
    channel_roa_unsubscribe_all(c);

    if (c->rpki_reload)
    {
      channel_roa_subscribe_filter(c, 1);
      channel_roa_subscribe_filter(c, 0);
    }
  }

  if (reconfigure_type == RECONFIG_SOFT)
  {
    if (import_changed)
      log(L_INFO "Channel %s.%s changed import", c->proto->name, c->name);

    if (export_changed)
      log(L_INFO "Channel %s.%s changed export", c->proto->name, c->name);

    goto done;
  }

  /* Route reload may be not supported */
  if (import_changed && !channel_reloadable(c))
    return 0;

  if (import_changed || export_changed)
    log(L_INFO "Reloading channel %s.%s", c->proto->name, c->name);

  if (import_changed)
    channel_request_reload(c);

  if (export_changed)
    channel_request_feeding(c);

done:
  CD(c, "Reconfigured");
  return 1;
}


int
proto_configure_channel(struct proto *p, struct channel **pc, struct channel_config *cf)
{
  struct channel *c = *pc;

  if (!c && cf)
  {
    /* We could add the channel, but currently it would just stay in down state
       until protocol is restarted, so it is better to force restart anyways. */
    if (p->proto_state != PS_DOWN)
    {
      log(L_INFO "Cannot add channel %s.%s", p->name, cf->name);
      return 0;
    }

    *pc = proto_add_channel(p, cf);
  }
  else if (c && !cf)
  {
    if (c->channel_state != CS_DOWN)
    {
      log(L_INFO "Cannot remove channel %s.%s", c->proto->name, c->name);
      return 0;
    }

    proto_remove_channel(p, c);
    *pc = NULL;
  }
  else if (c && cf)
  {
    if (!channel_reconfigure(c, cf))
    {
      log(L_INFO "Cannot reconfigure channel %s.%s", c->proto->name, c->name);
      return 0;
    }
  }

  return 1;
}

static void
proto_cleanup(struct proto *p)
{
  rfree(p->pool);
  p->pool = NULL;

  p->active = 0;
  proto_log_state_change(p);
  proto_rethink_goal(p);
}

static void
proto_loop_stopped(void *ptr)
{
  struct proto *p = ptr;

  birdloop_enter(&main_birdloop);

  p->loop = &main_birdloop;
  proto_cleanup(p);

  birdloop_leave(&main_birdloop);
}

static void
proto_event(void *ptr)
{
  struct proto *p = ptr;

  if (p->do_stop)
  {
    if (p->proto == &proto_unix_iface)
      if_flush_ifaces(p);

    p->do_stop = 0;
  }

  if (proto_is_done(p))
    if (p->loop != &main_birdloop)
      birdloop_stop_self(p->loop, proto_loop_stopped, p);
    else
      proto_cleanup(p);
}


/**
 * proto_new - create a new protocol instance
 * @c: protocol configuration
 *
 * When a new configuration has been read in, the core code starts
 * initializing all the protocol instances configured by calling their
 * init() hooks with the corresponding instance configuration. The initialization
 * code of the protocol is expected to create a new instance according to the
 * configuration by calling this function and then modifying the default settings
 * to values wanted by the protocol.
 */
void *
proto_new(struct proto_config *cf)
{
  struct proto *p = mb_allocz(proto_pool, cf->protocol->proto_size);

  p->cf = cf;
  p->debug = cf->debug;
  p->mrtdump = cf->mrtdump;
  p->name = cf->name;
  p->proto = cf->protocol;
  p->net_type = cf->net_type;
  p->disabled = cf->disabled;
  p->hash_key = random_u32();
  cf->proto = p;

  init_list(&p->channels);

  return p;
}

static struct proto *
proto_init(struct proto_config *c, node *n)
{
  struct protocol *pr = c->protocol;
  struct proto *p = pr->init(c);

  p->loop = &main_birdloop;
  p->proto_state = PS_DOWN;
  p->last_state_change = current_time();
  p->vrf = c->vrf;
  insert_node(&p->n, n);

  p->event = ev_new_init(proto_pool, proto_event, p);

  PD(p, "Initializing%s", p->disabled ? " [disabled]" : "");

  return p;
}

static void
proto_start(struct proto *p)
{
  DBG("Kicking %s up\n", p->name);
  PD(p, "Starting");

  p->pool = rp_newf(proto_pool, "Protocol %s", p->cf->name);

  if (graceful_restart_state == GRS_INIT)
    p->gr_recovery = 1;

  if (p->cf->loop_order != DOMAIN_ORDER(the_bird))
    p->loop = birdloop_new(p->pool, p->cf->loop_order, p->pool->name);

  PROTO_LOCKED_FROM_MAIN(p)
    proto_notify_state(p, (p->proto->start ? p->proto->start(p) : PS_UP));
}


/**
 * proto_config_new - create a new protocol configuration
 * @pr: protocol the configuration will belong to
 * @class: SYM_PROTO or SYM_TEMPLATE
 *
 * Whenever the configuration file says that a new instance
 * of a routing protocol should be created, the parser calls
 * proto_config_new() to create a configuration entry for this
 * instance (a structure staring with the &proto_config header
 * containing all the generic items followed by protocol-specific
 * ones). Also, the configuration entry gets added to the list
 * of protocol instances kept in the configuration.
 *
 * The function is also used to create protocol templates (when class
 * SYM_TEMPLATE is specified), the only difference is that templates
 * are not added to the list of protocol instances and therefore not
 * initialized during protos_commit()).
 */
void *
proto_config_new(struct protocol *pr, int class)
{
  struct proto_config *cf = cfg_allocz(pr->config_size);

  if (class == SYM_PROTO)
    add_tail(&new_config->protos, &cf->n);

  cf->global = new_config;
  cf->protocol = pr;
  cf->name = pr->name;
  cf->class = class;
  cf->debug = new_config->proto_default_debug;
  cf->mrtdump = new_config->proto_default_mrtdump;
  cf->loop_order = DOMAIN_ORDER(the_bird);

  init_list(&cf->channels);

  return cf;
}


/**
 * proto_copy_config - copy a protocol configuration
 * @dest: destination protocol configuration
 * @src: source protocol configuration
 *
 * Whenever a new instance of a routing protocol is created from the
 * template, proto_copy_config() is called to copy a content of
 * the source protocol configuration to the new protocol configuration.
 * Name, class and a node in protos list of @dest are kept intact.
 * copy_config() protocol hook is used to copy protocol-specific data.
 */
void
proto_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct channel_config *cc;
  node old_node;
  int old_class;
  const char *old_name;

  if (dest->protocol != src->protocol)
    cf_error("Can't copy configuration from a different protocol type");

  if (dest->protocol->copy_config == NULL)
    cf_error("Inheriting configuration for %s is not supported", src->protocol->name);

  DBG("Copying configuration from %s to %s\n", src->name, dest->name);

  /*
   * Copy struct proto_config here. Keep original node, class and name.
   * protocol-specific config copy is handled by protocol copy_config() hook
   */

  old_node = dest->n;
  old_class = dest->class;
  old_name = dest->name;

  memcpy(dest, src, src->protocol->config_size);

  dest->n = old_node;
  dest->class = old_class;
  dest->name = old_name;
  init_list(&dest->channels);

  WALK_LIST(cc, src->channels)
    channel_copy_config(cc, dest);

  /* FIXME: allow for undefined copy_config */
  dest->protocol->copy_config(dest, src);
}

void
proto_clone_config(struct symbol *sym, struct proto_config *parent)
{
  struct proto_config *cf = proto_config_new(parent->protocol, SYM_PROTO);
  proto_copy_config(cf, parent);
  cf->name = sym->name;
  cf->proto = NULL;
  cf->parent = parent;

  sym->class = cf->class;
  sym->proto = cf;
}

static void
proto_undef_clone(struct symbol *sym, struct proto_config *cf)
{
  rem_node(&cf->n);

  sym->class = SYM_VOID;
  sym->proto = NULL;
}

/**
 * protos_preconfig - pre-configuration processing
 * @c: new configuration
 *
 * This function calls the preconfig() hooks of all routing
 * protocols available to prepare them for reading of the new
 * configuration.
 */
void
protos_preconfig(struct config *c)
{
  struct protocol *p;

  init_list(&c->protos);
  DBG("Protocol preconfig:");
  WALK_LIST(p, protocol_list)
  {
    DBG(" %s", p->name);
    p->name_counter = 0;
    if (p->preconfig)
      p->preconfig(p, c);
  }
  DBG("\n");
}

static int
proto_reconfigure(struct proto *p, struct proto_config *oc, struct proto_config *nc, int type)
{
  /* If the protocol is DOWN, we just restart it */
  if (p->proto_state == PS_DOWN)
    return 0;

  /* If there is a too big change in core attributes, ... */
  if ((nc->protocol != oc->protocol) ||
      (nc->net_type != oc->net_type) ||
      (nc->disabled != p->disabled) ||
      (nc->vrf != oc->vrf))
    return 0;

  p->name = nc->name;
  p->debug = nc->debug;
  p->mrtdump = nc->mrtdump;
  reconfigure_type = type;

  /* Execute protocol specific reconfigure hook */
  if (!p->proto->reconfigure || !p->proto->reconfigure(p, nc))
    return 0;

  DBG("\t%s: same\n", oc->name);
  PD(p, "Reconfigured");
  p->cf = nc;

  return 1;
}

/**
 * protos_commit - commit new protocol configuration
 * @new: new configuration
 * @old: old configuration or %NULL if it's boot time config
 * @force_reconfig: force restart of all protocols (used for example
 * when the router ID changes)
 * @type: type of reconfiguration (RECONFIG_SOFT or RECONFIG_HARD)
 *
 * Scan differences between @old and @new configuration and adjust all
 * protocol instances to conform to the new configuration.
 *
 * When a protocol exists in the new configuration, but it doesn't in the
 * original one, it's immediately started. When a collision with the other
 * running protocol would arise, the new protocol will be temporarily stopped
 * by the locking mechanism.
 *
 * When a protocol exists in the old configuration, but it doesn't in the
 * new one, it's shut down and deleted after the shutdown completes.
 *
 * When a protocol exists in both configurations, the core decides
 * whether it's possible to reconfigure it dynamically - it checks all
 * the core properties of the protocol (changes in filters are ignored
 * if type is RECONFIG_SOFT) and if they match, it asks the
 * reconfigure() hook of the protocol to see if the protocol is able
 * to switch to the new configuration.  If it isn't possible, the
 * protocol is shut down and a new instance is started with the new
 * configuration after the shutdown is completed.
 */
void
protos_commit(struct config *new, struct config *old, int force_reconfig, int type)
{
  struct proto_config *oc, *nc;
  struct symbol *sym;
  struct proto *p;
  node *n;


  DBG("protos_commit:\n");
  if (old)
  {
    WALK_LIST(oc, old->protos)
    {
      p = oc->proto;
      sym = cf_find_symbol(new, oc->name);

      /* Handle dynamic protocols */
      if (!sym && oc->parent && !new->shutdown)
      {
	struct symbol *parsym = cf_find_symbol(new, oc->parent->name);
	if (parsym && parsym->class == SYM_PROTO)
	{
	  /* This is hack, we would like to share config, but we need to copy it now */
	  new_config = new;
	  cfg_mem = new->mem;
	  conf_this_scope = new->root_scope;
	  sym = cf_get_symbol(oc->name);
	  proto_clone_config(sym, parsym->proto);
	  new_config = NULL;
	  cfg_mem = NULL;
	}
      }

      if (sym && sym->class == SYM_PROTO && !new->shutdown)
      {
	/* Found match, let's check if we can smoothly switch to new configuration */
	/* No need to check description */
	nc = sym->proto;
	nc->proto = p;

	/* We will try to reconfigure protocol p */
	if (! force_reconfig && proto_reconfigure(p, oc, nc, type))
	  continue;

	if (nc->parent)
	{
	  proto_undef_clone(sym, nc);
	  goto remove;
	}

	/* Unsuccessful, we will restart it */
	if (!p->disabled && !nc->disabled)
	  log(L_INFO "Restarting protocol %s", p->name);
	else if (p->disabled && !nc->disabled)
	  log(L_INFO "Enabling protocol %s", p->name);
	else if (!p->disabled && nc->disabled)
	  log(L_INFO "Disabling protocol %s", p->name);

	p->down_code = nc->disabled ? PDC_CF_DISABLE : PDC_CF_RESTART;
	p->cf_new = nc;
      }
      else if (!new->shutdown)
      {
      remove:
	log(L_INFO "Removing protocol %s", p->name);
	p->down_code = PDC_CF_REMOVE;
	p->cf_new = NULL;
      }
      else if (new->gr_down)
      {
	p->down_code = PDC_CMD_GR_DOWN;
	p->cf_new = NULL;
      }
      else /* global shutdown */
      {
	p->down_code = PDC_CMD_SHUTDOWN;
	p->cf_new = NULL;
      }

      p->reconfiguring = 1;
      config_add_obstacle(old);
      proto_rethink_goal(p);
    }
  }

  struct proto *first_dev_proto = NULL;

  n = NODE &(proto_list.head);
  WALK_LIST(nc, new->protos)
    if (!nc->proto)
    {
      /* Not a first-time configuration */
      if (old)
	log(L_INFO "Adding protocol %s", nc->name);

      p = proto_init(nc, n);
      n = NODE p;

      if (p->proto == &proto_unix_iface)
	first_dev_proto = p;
    }
    else
      n = NODE nc->proto;

  DBG("Protocol start\n");

  /* Start device protocol first */
  if (first_dev_proto)
    proto_rethink_goal(first_dev_proto);

  /* Determine router ID for the first time - it has to be here and not in
     global_commit() because it is postponed after start of device protocol */
  if (!config->router_id)
  {
    config->router_id = if_choose_router_id(config->router_id_from, 0);
    if (!config->router_id)
      die("Cannot determine router ID, please configure it manually");
  }

  /* Start all new protocols */
  WALK_LIST_DELSAFE(p, n, proto_list)
    proto_rethink_goal(p);
}

static void
proto_shutdown(struct proto *p)
{
  if (p->proto_state == PS_START || p->proto_state == PS_UP)
  {
    /* Going down */
    DBG("Kicking %s down\n", p->name);
    PD(p, "Shutting down");
    proto_notify_state(p, (p->proto->shutdown ? p->proto->shutdown(p) : PS_DOWN));
  }
}

static void
proto_rethink_goal(struct proto *p)
{
  if (p->reconfiguring && !p->active)
  {
    struct proto_config *nc = p->cf_new;
    node *n = p->n.prev;
    DBG("%s has shut down for reconfiguration\n", p->name);
    p->cf->proto = NULL;
    config_del_obstacle(p->cf->global);
    proto_remove_channels(p);
    rem_node(&p->n);
    rfree(p->event);
    mb_free(p->message);
    mb_free(p);
    if (!nc)
      return;
    p = proto_init(nc, n);
  }

  /* Determine what state we want to reach */
  if (p->disabled || p->reconfiguring)
  {
    PROTO_LOCKED_FROM_MAIN(p)
      proto_shutdown(p);
  }
  else if (!p->active)
    proto_start(p);
}

struct proto *
proto_spawn(struct proto_config *cf, uint disabled)
{
  struct proto *p = proto_init(cf, TAIL(proto_list));
  p->disabled = disabled;
  proto_rethink_goal(p);
  return p;
}


/**
 * DOC: Graceful restart recovery
 *
 * Graceful restart of a router is a process when the routing plane (e.g. BIRD)
 * restarts but both the forwarding plane (e.g kernel routing table) and routing
 * neighbors keep proper routes, and therefore uninterrupted packet forwarding
 * is maintained.
 *
 * BIRD implements graceful restart recovery by deferring export of routes to
 * protocols until routing tables are refilled with the expected content. After
 * start, protocols generate routes as usual, but routes are not propagated to
 * them, until protocols report that they generated all routes. After that,
 * graceful restart recovery is finished and the export (and the initial feed)
 * to protocols is enabled.
 *
 * When graceful restart recovery need is detected during initialization, then
 * enabled protocols are marked with @gr_recovery flag before start. Such
 * protocols then decide how to proceed with graceful restart, participation is
 * voluntary. Protocols could lock the recovery for each channel by function
 * channel_graceful_restart_lock() (state stored in @gr_lock flag), which means
 * that they want to postpone the end of the recovery until they converge and
 * then unlock it. They also could set @gr_wait before advancing to %PS_UP,
 * which means that the core should defer route export to that channel until
 * the end of the recovery. This should be done by protocols that expect their
 * neigbors to keep the proper routes (kernel table, BGP sessions with BGP
 * graceful restart capability).
 *
 * The graceful restart recovery is finished when either all graceful restart
 * locks are unlocked or when graceful restart wait timer fires.
 *
 */

static void graceful_restart_done(timer *t);

/**
 * graceful_restart_recovery - request initial graceful restart recovery
 *
 * Called by the platform initialization code if the need for recovery
 * after graceful restart is detected during boot. Have to be called
 * before protos_commit().
 */
void
graceful_restart_recovery(void)
{
  graceful_restart_state = GRS_INIT;
}

/**
 * graceful_restart_init - initialize graceful restart
 *
 * When graceful restart recovery was requested, the function starts an active
 * phase of the recovery and initializes graceful restart wait timer. The
 * function have to be called after protos_commit().
 */
void
graceful_restart_init(void)
{
  if (!graceful_restart_state)
    return;

  log(L_INFO "Graceful restart started");

  if (!graceful_restart_locks)
  {
    graceful_restart_done(NULL);
    return;
  }

  graceful_restart_state = GRS_ACTIVE;
  gr_wait_timer = tm_new_init(proto_pool, graceful_restart_done, NULL, 0, 0);
  tm_start(gr_wait_timer, config->gr_wait S);
}

/**
 * graceful_restart_done - finalize graceful restart
 * @t: unused
 *
 * When there are no locks on graceful restart, the functions finalizes the
 * graceful restart recovery. Protocols postponing route export until the end of
 * the recovery are awakened and the export to them is enabled. All other
 * related state is cleared. The function is also called when the graceful
 * restart wait timer fires (but there are still some locks).
 */
static void
graceful_restart_done(timer *t UNUSED)
{
  log(L_INFO "Graceful restart done");
  graceful_restart_state = GRS_DONE;

  struct proto *p;
  WALK_LIST(p, proto_list)
  {
    if (!p->gr_recovery)
      continue;

    struct channel *c;
    WALK_LIST(c, p->channels)
    {
      /* Resume postponed export of routes */
      if ((c->channel_state == CS_UP) && c->gr_wait && p->rt_notify)
	channel_start_export(c);

      /* Cleanup */
      c->gr_wait = 0;
      c->gr_lock = 0;
    }

    p->gr_recovery = 0;
  }

  graceful_restart_locks = 0;
}

void
graceful_restart_show_status(void)
{
  if (graceful_restart_state != GRS_ACTIVE)
    return;

  cli_msg(-24, "Graceful restart recovery in progress");
  cli_msg(-24, "  Waiting for %d channels to recover", graceful_restart_locks);
  cli_msg(-24, "  Wait timer is %t/%u", tm_remains(gr_wait_timer), config->gr_wait);
}

/**
 * channel_graceful_restart_lock - lock graceful restart by channel
 * @p: channel instance
 *
 * This function allows a protocol to postpone the end of graceful restart
 * recovery until it converges. The lock is removed when the protocol calls
 * channel_graceful_restart_unlock() or when the channel is closed.
 *
 * The function have to be called during the initial phase of graceful restart
 * recovery and only for protocols that are part of graceful restart (i.e. their
 * @gr_recovery is set), which means it should be called from protocol start
 * hooks.
 */
void
channel_graceful_restart_lock(struct channel *c)
{
  ASSERT(graceful_restart_state == GRS_INIT);
  ASSERT(c->proto->gr_recovery);

  if (c->gr_lock)
    return;

  c->gr_lock = 1;
  graceful_restart_locks++;
}

/**
 * channel_graceful_restart_unlock - unlock graceful restart by channel
 * @p: channel instance
 *
 * This function unlocks a lock from channel_graceful_restart_lock(). It is also
 * automatically called when the lock holding protocol went down.
 */
void
channel_graceful_restart_unlock(struct channel *c)
{
  if (!c->gr_lock)
    return;

  c->gr_lock = 0;
  graceful_restart_locks--;

  if ((graceful_restart_state == GRS_ACTIVE) && !graceful_restart_locks)
    tm_start(gr_wait_timer, 0);
}



/**
 * protos_dump_all - dump status of all protocols
 *
 * This function dumps status of all existing protocol instances to the
 * debug output. It involves printing of general status information
 * such as protocol states, its position on the protocol lists
 * and also calling of a dump() hook of the protocol to print
 * the internals.
 */
void
protos_dump_all(void)
{
  debug("Protocols:\n");

  struct proto *p;
  WALK_LIST(p, proto_list)
  {
#define DPF(x)	(p->x ? " " #x : "")
    debug("  protocol %s (%p) state %s with %d active channels flags: %s%s%s%s%s\n",
	p->name, p, p_states[p->proto_state], p->active_channels,
	DPF(disabled), DPF(active), DPF(do_stop), DPF(reconfiguring));
#undef DPF

    struct channel *c;
    WALK_LIST(c, p->channels)
    {
      debug("\tTABLE %s\n", c->table->name);
      if (c->in_filter)
	debug("\tInput filter: %s\n", filter_name(c->in_filter));
      if (c->out_filter)
	debug("\tOutput filter: %s\n", filter_name(c->out_filter));
      debug("\tChannel state: %s/%s/%s\n", c_states[c->channel_state],
	  c->in_req.hook ? rt_import_state_name(rt_import_get_state(c->in_req.hook)) : "-",
	  c->out_req.hook ? rt_export_state_name(rt_export_get_state(c->out_req.hook)) : "-");
    }

    if (p->proto->dump && (p->proto_state != PS_DOWN))
      p->proto->dump(p);
  }
}

/**
 * proto_build - make a single protocol available
 * @p: the protocol
 *
 * After the platform specific initialization code uses protos_build()
 * to add all the standard protocols, it should call proto_build() for
 * all platform specific protocols to inform the core that they exist.
 */
void
proto_build(struct protocol *p)
{
  add_tail(&protocol_list, &p->n);
}

/* FIXME: convert this call to some protocol hook */
extern void bfd_init_all(void);

void protos_build_gen(void);

/**
 * protos_build - build a protocol list
 *
 * This function is called during BIRD startup to insert
 * all standard protocols to the global protocol list. Insertion
 * of platform specific protocols (such as the kernel syncer)
 * is in the domain of competence of the platform dependent
 * startup code.
 */
void
protos_build(void)
{
  protos_build_gen();

  proto_pool = rp_new(&root_pool, "Protocols");
  proto_shutdown_timer = tm_new(proto_pool);
  proto_shutdown_timer->hook = proto_shutdown_loop;
}


/* Temporary hack to propagate restart to BGP */
int proto_restart;

static void
proto_shutdown_loop(timer *t UNUSED)
{
  struct proto *p, *p_next;

  WALK_LIST_DELSAFE(p, p_next, proto_list)
    if (p->down_sched)
    {
      proto_restart = (p->down_sched == PDS_RESTART);

      p->disabled = 1;
      proto_rethink_goal(p);
      if (proto_restart)
      {
	p->disabled = 0;
	proto_rethink_goal(p);
      }
    }
}

static inline void
proto_schedule_down(struct proto *p, byte restart, byte code)
{
  /* Does not work for other states (even PS_START) */
  ASSERT(p->proto_state == PS_UP);

  /* Scheduled restart may change to shutdown, but not otherwise */
  if (p->down_sched == PDS_DISABLE)
    return;

  p->down_sched = restart ? PDS_RESTART : PDS_DISABLE;
  p->down_code = code;
  tm_start_max(proto_shutdown_timer, restart ? 250 MS : 0);
}

/**
 * proto_set_message - set administrative message to protocol
 * @p: protocol
 * @msg: message
 * @len: message length (-1 for NULL-terminated string)
 *
 * The function sets administrative message (string) related to protocol state
 * change. It is called by the nest code for manual enable/disable/restart
 * commands all routes to the protocol, and by protocol-specific code when the
 * protocol state change is initiated by the protocol. Using NULL message clears
 * the last message. The message string may be either NULL-terminated or with an
 * explicit length.
 */
void
proto_set_message(struct proto *p, char *msg, int len)
{
  mb_free(p->message);
  p->message = NULL;

  if (!msg || !len)
    return;

  if (len < 0)
    len = strlen(msg);

  if (!len)
    return;

  p->message = mb_alloc(proto_pool, len + 1);
  memcpy(p->message, msg, len);
  p->message[len] = 0;
}


static const char * channel_limit_name[] = {
  [PLA_WARN] = "warn",
  [PLA_BLOCK] = "block",
  [PLA_RESTART] = "restart",
  [PLA_DISABLE] = "disable",
};


static void
channel_log_limit(struct channel *c, struct limit *l, int dir)
{
  const char *dir_name[PLD_MAX] = { "receive", "import" , "export" };
  log(L_WARN "Channel %s.%s hits route %s limit (%d), action: %s",
      c->proto->name, c->name, dir_name[dir], l->max, channel_limit_name[c->limit_actions[dir]]);
}

static void
channel_activate_limit(struct channel *c, struct limit *l, int dir)
{
  if (c->limit_active & (1 << dir))
    return;

  c->limit_active |= (1 << dir);
  channel_log_limit(c, l, dir);
}

static int
channel_limit_warn(struct limit *l, void *data)
{
  struct channel_limit_data *cld = data;
  struct channel *c = cld->c;
  int dir = cld->dir;

  channel_log_limit(c, l, dir);

  return 0;
}

static int
channel_limit_block(struct limit *l, void *data)
{
  struct channel_limit_data *cld = data;
  struct channel *c = cld->c;
  int dir = cld->dir;

  channel_activate_limit(c, l, dir);

  return 1;
}

static const byte chl_dir_down[PLD_MAX] = { PDC_RX_LIMIT_HIT, PDC_IN_LIMIT_HIT, PDC_OUT_LIMIT_HIT };

static int
channel_limit_down(struct limit *l, void *data)
{
  struct channel_limit_data *cld = data;
  struct channel *c = cld->c;
  struct proto *p = c->proto;
  int dir = cld->dir;

  channel_activate_limit(c, l, dir);

  if (p->proto_state == PS_UP)
    proto_schedule_down(p, c->limit_actions[dir] == PLA_RESTART, chl_dir_down[dir]);

  return 1;
}

static int (*channel_limit_action[])(struct limit *, void *) = {
  [PLA_NONE] = NULL,
  [PLA_WARN] = channel_limit_warn,
  [PLA_BLOCK] = channel_limit_block,
  [PLA_RESTART] = channel_limit_down,
  [PLA_DISABLE] = channel_limit_down,
};

static void
channel_update_limit(struct channel *c, struct limit *l, int dir, struct channel_limit *cf)
{
  l->action = channel_limit_action[cf->action];
  c->limit_actions[dir] = cf->action;

  struct channel_limit_data cld = { .c = c, .dir = dir };
  limit_update(l, &cld, cf->action ? cf->limit : ~((u32) 0));
}

static void
channel_init_limit(struct channel *c, struct limit *l, int dir, struct channel_limit *cf)
{
  channel_reset_limit(c, l, dir);
  channel_update_limit(c, l, dir, cf);
}

static void
channel_reset_limit(struct channel *c, struct limit *l, int dir)
{
  limit_reset(l);
  c->limit_active &= ~(1 << dir);
}

static struct rte_owner_class default_rte_owner_class;

static inline void
proto_do_start(struct proto *p)
{
  p->active = 1;

  rt_init_sources(&p->sources, p->name, proto_event_list(p));
  if (!p->sources.class)
    p->sources.class = &default_rte_owner_class;

  if (!p->cf->late_if_feed)
    if_feed_baby(p);
}

static void
proto_do_up(struct proto *p)
{
  if (!p->main_source)
    p->main_source = rt_get_source(p, 0);
    // Locked automaticaly

  proto_start_channels(p);

  if (p->cf->late_if_feed)
    if_feed_baby(p);
}

static inline void
proto_do_pause(struct proto *p)
{
  proto_pause_channels(p);
}

static void
proto_do_stop(struct proto *p)
{
  p->down_sched = 0;
  p->gr_recovery = 0;

  if (p->main_source)
  {
    rt_unlock_source(p->main_source);
    p->main_source = NULL;
  }

  proto_stop_channels(p);
  rt_destroy_sources(&p->sources, p->event);

  p->do_stop = 1;
  proto_send_event(p);
}

static void
proto_do_down(struct proto *p)
{
  p->down_code = 0;
  neigh_prune();

  /* Shutdown is finished in the protocol event */
  if (proto_is_done(p))
    proto_send_event(p);
}



/**
 * proto_notify_state - notify core about protocol state change
 * @p: protocol the state of which has changed
 * @ps: the new status
 *
 * Whenever a state of a protocol changes due to some event internal
 * to the protocol (i.e., not inside a start() or shutdown() hook),
 * it should immediately notify the core about the change by calling
 * proto_notify_state() which will write the new state to the &proto
 * structure and take all the actions necessary to adapt to the new
 * state. State change to PS_DOWN immediately frees resources of protocol
 * and might execute start callback of protocol; therefore,
 * it should be used at tail positions of protocol callbacks.
 */
void
proto_notify_state(struct proto *p, uint state)
{
  uint ps = p->proto_state;

  DBG("%s reporting state transition %s -> %s\n", p->name, p_states[ps], p_states[state]);
  if (state == ps)
    return;

  p->proto_state = state;
  p->last_state_change = current_time();

  switch (state)
  {
  case PS_START:
    ASSERT(ps == PS_DOWN || ps == PS_UP);

    if (ps == PS_DOWN)
      proto_do_start(p);
    else
      proto_do_pause(p);
    break;

  case PS_UP:
    ASSERT(ps == PS_DOWN || ps == PS_START);

    if (ps == PS_DOWN)
      proto_do_start(p);

    proto_do_up(p);
    break;

  case PS_STOP:
    ASSERT(ps == PS_START || ps == PS_UP);

    proto_do_stop(p);
    break;

  case PS_DOWN:
    if (ps != PS_STOP)
      proto_do_stop(p);

    proto_do_down(p);
    break;

  default:
    bug("%s: Invalid state %d", p->name, ps);
  }

  proto_log_state_change(p);
}

/*
 *  CLI Commands
 */

static char *
proto_state_name(struct proto *p)
{
  switch (p->proto_state)
  {
  case PS_DOWN:		return p->active ? "flush" : "down";
  case PS_START:	return "start";
  case PS_UP:		return "up";
  case PS_STOP:		return "stop";
  default:		return "???";
  }
}

static void
channel_show_stats(struct channel *c)
{
  struct channel_import_stats *ch_is = &c->import_stats;
  struct channel_export_stats *ch_es = &c->export_stats;
  struct rt_import_stats *rt_is = c->in_req.hook ? &c->in_req.hook->stats : NULL;
  struct rt_export_stats *rt_es = c->out_req.hook ? &c->out_req.hook->stats : NULL;

#define SON(ie, item)	((ie) ? (ie)->item : 0)
#define SCI(item) SON(ch_is, item)
#define SCE(item) SON(ch_es, item)
#define SRI(item) SON(rt_is, item)
#define SRE(item) SON(rt_es, item)

  u32 rx_routes = c->rx_limit.count;
  u32 in_routes = c->in_limit.count;
  u32 out_routes = c->out_limit.count;

  if (c->in_keep)
    cli_msg(-1006, "    Routes:         %u imported, %u filtered, %u exported, %u preferred",
	    in_routes, (rx_routes - in_routes), out_routes, SRI(pref));
  else
    cli_msg(-1006, "    Routes:         %u imported, %u exported, %u preferred",
	    in_routes, out_routes, SRI(pref));

  cli_msg(-1006, "    Route change stats:     received   rejected   filtered    ignored   RX limit   IN limit   accepted");
  cli_msg(-1006, "      Import updates:     %10u %10u %10u %10u %10u %10u %10u",
	  SCI(updates_received), SCI(updates_invalid),
	  SCI(updates_filtered), SRI(updates_ignored),
	  SCI(updates_limited_rx), SCI(updates_limited_in),
	  SRI(updates_accepted));
  cli_msg(-1006, "      Import withdraws:   %10u %10u        --- %10u        --- %10u",
	  SCI(withdraws_received), SCI(withdraws_invalid),
	  SRI(withdraws_ignored), SRI(withdraws_accepted));
  cli_msg(-1006, "      Export updates:     %10u %10u %10u        --- %10u %10u",
	  SRE(updates_received), SCE(updates_rejected),
	  SCE(updates_filtered), SCE(updates_limited), SCE(updates_accepted));
  cli_msg(-1006, "      Export withdraws:   %10u        ---        ---        ---         ---%10u",
	  SRE(withdraws_received), SCE(withdraws_accepted));

#undef SRI
#undef SRE
#undef SCI
#undef SCE
#undef SON
}

void
channel_show_limit(struct limit *l, const char *dsc, int active, int action)
{
  if (!l->action)
    return;

  cli_msg(-1006, "    %-16s%d%s", dsc, l->max, active ? " [HIT]" : "");
  cli_msg(-1006, "      Action:       %s", channel_limit_name[action]);
}

void
channel_show_info(struct channel *c)
{
  cli_msg(-1006, "  Channel %s", c->name);
  cli_msg(-1006, "    State:          %s", c_states[c->channel_state]);
  cli_msg(-1006, "    Import state:   %s", rt_import_state_name(rt_import_get_state(c->in_req.hook)));
  cli_msg(-1006, "    Export state:   %s", rt_export_state_name(rt_export_get_state(c->out_req.hook)));
  cli_msg(-1006, "    Table:          %s", c->table->name);
  cli_msg(-1006, "    Preference:     %d", c->preference);
  cli_msg(-1006, "    Input filter:   %s", filter_name(c->in_filter));
  cli_msg(-1006, "    Output filter:  %s", filter_name(c->out_filter));

  if (graceful_restart_state == GRS_ACTIVE)
    cli_msg(-1006, "    GR recovery:   %s%s",
	    c->gr_lock ? " pending" : "",
	    c->gr_wait ? " waiting" : "");

  channel_show_limit(&c->rx_limit, "Receive limit:", c->limit_active & (1 << PLD_RX), c->limit_actions[PLD_RX]);
  channel_show_limit(&c->in_limit, "Import limit:", c->limit_active & (1 << PLD_IN), c->limit_actions[PLD_IN]);
  channel_show_limit(&c->out_limit, "Export limit:", c->limit_active & (1 << PLD_OUT), c->limit_actions[PLD_OUT]);

  if (c->channel_state != CS_DOWN)
    channel_show_stats(c);
}

void
channel_cmd_debug(struct channel *c, uint mask)
{
  if (cli_access_restricted())
    return;

  c->debug = mask;
  cli_msg(0, "");
}

void
proto_cmd_show(struct proto *p, uintptr_t verbose, int cnt)
{
  byte buf[256], tbuf[TM_DATETIME_BUFFER_SIZE];

  /* First protocol - show header */
  if (!cnt)
    cli_msg(-2002, "%-10s %-10s %-10s %-6s %-12s  %s",
	    "Name", "Proto", "Table", "State", "Since", "Info");

  buf[0] = 0;
  if (p->proto->get_status)
    p->proto->get_status(p, buf);
  tm_format_time(tbuf, &config->tf_proto, p->last_state_change);
  cli_msg(-1002, "%-10s %-10s %-10s %-6s %-12s  %s",
	  p->name,
	  p->proto->name,
	  p->main_channel ? p->main_channel->table->name : "---",
	  proto_state_name(p),
	  tbuf,
	  buf);

  if (verbose)
  {
    if (p->cf->dsc)
      cli_msg(-1006, "  Description:    %s", p->cf->dsc);
    if (p->message)
      cli_msg(-1006, "  Message:        %s", p->message);
    if (p->cf->router_id)
      cli_msg(-1006, "  Router ID:      %R", p->cf->router_id);
    if (p->vrf)
      cli_msg(-1006, "  VRF:            %s", p->vrf->name);

    if (p->proto->show_proto_info)
      p->proto->show_proto_info(p);
    else
    {
      struct channel *c;
      WALK_LIST(c, p->channels)
	channel_show_info(c);
    }

    cli_msg(-1006, "");
  }
}

void
proto_cmd_disable(struct proto *p, uintptr_t arg, int cnt UNUSED)
{
  if (p->disabled)
  {
    cli_msg(-8, "%s: already disabled", p->name);
    return;
  }

  log(L_INFO "Disabling protocol %s", p->name);
  p->disabled = 1;
  p->down_code = PDC_CMD_DISABLE;
  proto_set_message(p, (char *) arg, -1);
  proto_shutdown(p);
  cli_msg(-9, "%s: disabled", p->name);
}

void
proto_cmd_enable(struct proto *p, uintptr_t arg, int cnt UNUSED)
{
  if (!p->disabled)
  {
    cli_msg(-10, "%s: already enabled", p->name);
    return;
  }

  log(L_INFO "Enabling protocol %s", p->name);
  p->disabled = 0;
  proto_set_message(p, (char *) arg, -1);
  proto_rethink_goal(p);
  cli_msg(-11, "%s: enabled", p->name);
}

void
proto_cmd_restart(struct proto *p, uintptr_t arg, int cnt UNUSED)
{
  if (p->disabled)
  {
    cli_msg(-8, "%s: already disabled", p->name);
    return;
  }

  log(L_INFO "Restarting protocol %s", p->name);
  p->disabled = 1;
  p->down_code = PDC_CMD_RESTART;
  proto_set_message(p, (char *) arg, -1);
  proto_shutdown(p);
  p->disabled = 0;
  /* After the protocol shuts down, proto_rethink_goal() is run from proto_event. */
  cli_msg(-12, "%s: restarted", p->name);
}

void
proto_cmd_reload(struct proto *p, uintptr_t dir, int cnt UNUSED)
{
  struct channel *c;

  if (p->disabled)
  {
    cli_msg(-8, "%s: already disabled", p->name);
    return;
  }

  /* If the protocol in not UP, it has no routes */
  if (p->proto_state != PS_UP)
    return;

  /* All channels must support reload */
  if (dir != CMD_RELOAD_OUT)
    WALK_LIST(c, p->channels)
      if ((c->channel_state == CS_UP) && !channel_reloadable(c))
      {
	cli_msg(-8006, "%s: reload failed", p->name);
	return;
      }

  log(L_INFO "Reloading protocol %s", p->name);

  /* re-importing routes */
  if (dir != CMD_RELOAD_OUT)
    WALK_LIST(c, p->channels)
      if (c->channel_state == CS_UP)
	channel_request_reload(c);

  /* re-exporting routes */
  if (dir != CMD_RELOAD_IN)
    WALK_LIST(c, p->channels)
      if (c->channel_state == CS_UP)
	channel_request_feeding(c);

  cli_msg(-15, "%s: reloading", p->name);
}

extern void pipe_update_debug(struct proto *P);

void
proto_cmd_debug(struct proto *p, uintptr_t mask, int cnt UNUSED)
{
  p->debug = mask;

#ifdef CONFIG_PIPE
  if (p->proto == &proto_pipe)
    pipe_update_debug(p);
#endif
}

void
proto_cmd_mrtdump(struct proto *p, uintptr_t mask, int cnt UNUSED)
{
  p->mrtdump = mask;
}

static void
proto_apply_cmd_symbol(const struct symbol *s, void (* cmd)(struct proto *, uintptr_t, int), uintptr_t arg)
{
  if (s->class != SYM_PROTO)
  {
    cli_msg(9002, "%s is not a protocol", s->name);
    return;
  }

  if (s->proto->proto)
  {
    struct proto *p = s->proto->proto;
    PROTO_LOCKED_FROM_MAIN(p)
      cmd(p, arg, 0);
    cli_msg(0, "");
  }
  else
    cli_msg(9002, "%s does not exist", s->name);
}

static void
proto_apply_cmd_patt(const char *patt, void (* cmd)(struct proto *, uintptr_t, int), uintptr_t arg)
{
  struct proto *p;
  int cnt = 0;

  WALK_LIST(p, proto_list)
    if (!patt || patmatch(patt, p->name))
      PROTO_LOCKED_FROM_MAIN(p)
	cmd(p, arg, cnt++);

  if (!cnt)
    cli_msg(8003, "No protocols match");
  else
    cli_msg(0, "");
}

void
proto_apply_cmd(struct proto_spec ps, void (* cmd)(struct proto *, uintptr_t, int),
		int restricted, uintptr_t arg)
{
  if (restricted && cli_access_restricted())
    return;

  if (ps.patt)
    proto_apply_cmd_patt(ps.ptr, cmd, arg);
  else
    proto_apply_cmd_symbol(ps.ptr, cmd, arg);
}

struct proto *
proto_get_named(struct symbol *sym, struct protocol *pr)
{
  struct proto *p, *q;

  if (sym)
  {
    if (sym->class != SYM_PROTO)
      cf_error("%s: Not a protocol", sym->name);

    p = sym->proto->proto;
    if (!p || p->proto != pr)
      cf_error("%s: Not a %s protocol", sym->name, pr->name);
  }
  else
  {
    p = NULL;
    WALK_LIST(q, proto_list)
      if ((q->proto == pr) && (q->proto_state != PS_DOWN))
      {
	if (p)
	  cf_error("There are multiple %s protocols running", pr->name);
	p = q;
      }
    if (!p)
      cf_error("There is no %s protocol running", pr->name);
  }

  return p;
}

struct proto *
proto_iterate_named(struct symbol *sym, struct protocol *proto, struct proto *old)
{
  if (sym)
  {
    /* Just the first pass */
    if (old)
    {
      cli_msg(0, "");
      return NULL;
    }

    if (sym->class != SYM_PROTO)
      cf_error("%s: Not a protocol", sym->name);

    struct proto *p = sym->proto->proto;
    if (!p || (p->proto != proto))
      cf_error("%s: Not a %s protocol", sym->name, proto->name);

    return p;
  }
  else
  {
    for (struct proto *p = !old ? HEAD(proto_list) : NODE_NEXT(old);
	 NODE_VALID(p);
	 p = NODE_NEXT(p))
    {
      if ((p->proto == proto) && (p->proto_state != PS_DOWN))
      {
	cli_separator(this_cli);
	return p;
      }
    }

    /* Not found anything during first pass */
    if (!old)
      cf_error("There is no %s protocol running", proto->name);

    /* No more items */
    cli_msg(0, "");
    return NULL;
  }
}
