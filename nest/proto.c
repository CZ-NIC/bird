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
#include "nest/route.h"
#include "nest/iface.h"
#include "nest/mpls.h"
#include "nest/cli.h"
#include "filter/filter.h"
#include "filter/f-inst.h"

pool *proto_pool;
static TLIST_LIST(proto) global_proto_list;

static list STATIC_LIST_INIT(protocol_list);

#define CD(c, msg, args...) ({ if (c->debug & D_STATES) log(L_TRACE "%s.%s: " msg, c->proto->name, c->name ?: "?", ## args); })
#define PD(p, msg, args...) ({ if (p->debug & D_STATES) log(L_TRACE "%s: " msg, p->name, ## args); })

static timer *gr_wait_timer;

#define GRS_NONE	0
#define GRS_INIT	1
#define GRS_ACTIVE	2
#define GRS_DONE	3

static int graceful_restart_state;
static u32 graceful_restart_locks;

static char *p_states[] = { "DOWN", "START", "UP", "STOP" };
static char *c_states[] = { "DOWN", "START", "UP", "STOP", "RESTART" };

proto_state_table proto_state_table_pub;

extern struct protocol proto_unix_iface;

static void proto_rethink_goal(struct proto *p);
static char *proto_state_name(struct proto *p);
void proto_journal_item_cleanup(struct lfjour * journal UNUSED, struct lfjour_item *i);
static void channel_init_limit(struct channel *c, struct limit *l, int dir, struct channel_limit *cf);
static void channel_update_limit(struct channel *c, struct limit *l, int dir, struct channel_limit *cf);
static void channel_reset_limit(struct channel *c, struct limit *l, int dir);
static void channel_stop_export(struct channel *c);
static void channel_check_stopped(struct channel *c);
static inline void channel_reimport(struct channel *c, struct rt_feeding_request *rfr)
{
  rt_export_refeed(&c->reimporter, rfr);
  ev_send(proto_event_list(c->proto), &c->reimport_event);
}

static inline void channel_refeed(struct channel *c, struct rt_feeding_request *rfr)
{
  rt_export_refeed(&c->out_req, rfr);
}

static inline int proto_is_done(struct proto *p)
{ return (p->proto_state == PS_FLUSH) && proto_is_inactive(p); }

static inline int channel_is_active(struct channel *c)
{ return (c->channel_state != CS_DOWN); }

static inline int channel_reloadable(struct channel *c)
{
  return c->reloadable && c->proto->reload_routes
      || ((c->in_keep & RIK_PREFILTER) == RIK_PREFILTER);
}

static inline void
channel_log_state_change(struct channel *c)
{
  CD(c, "State changed to %s", c_states[c->channel_state]);
}

static void
channel_import_log_state_change(struct rt_import_request *req, u8 state)
{
  SKIP_BACK_DECLARE(struct channel, c, in_req, req);
  CD(c, "Channel import state changed to %s", rt_import_state_name(state));
}

static void
channel_export_fed(struct rt_export_request *req)
{
  SKIP_BACK_DECLARE(struct channel, c, out_req, req);

  struct limit *l = &c->out_limit;
  if ((c->limit_active & (1 << PLD_OUT)) && (l->count <= l->max))
  {
    c->limit_active &= ~(1 << PLD_OUT);
    channel_request_full_refeed(c);
  }
  else
    CALL(c->proto->export_fed, c);
}

void
channel_request_full_refeed(struct channel *c)
{
  rt_export_refeed(&c->out_req, NULL);
}

static void
channel_dump_import_req(struct rt_import_request *req)
{
  SKIP_BACK_DECLARE(struct channel, c, in_req, req);
  debug("  Channel %s.%s import request %p\n", c->proto->name, c->name, req);
}

static void
channel_dump_export_req(struct rt_export_request *req)
{
  SKIP_BACK_DECLARE(struct channel, c, out_req, req);
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
  struct channel *c = mb_allocz(proto_pool, cf->class->channel_size);

  c->name = cf->name;
  c->class = cf->class;
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

  /* Announcing existence of the channel */
  PST_LOCKED(ts)
  {
    /* Allocating channel ID */
    c->id = hmap_first_zero(&ts->channel_id_map);
    hmap_set(&ts->channel_id_map, c->id);

    /* The current channel state table may be too small */
    if (c->id >= ts->length_channels)
    {
      ea_list **l = mb_allocz(ts->pool, sizeof(ea_list*) * ts->length_channels * 2);
      memcpy(l, ts->channels, sizeof(ea_list*) * ts->length_channels);
      mb_free(ts->channels);

      ts->channels = l;
      ts->length_channels = ts->length_channels * 2;
    }

    /* Create the actual channel information */
    struct ea_list *ca = NULL;

    ea_set_attr(&ca, EA_LITERAL_STORE_STRING(&ea_name, 0, c->name));
    ea_set_attr(&ca, EA_LITERAL_EMBEDDED(&ea_proto_id, 0, c->proto->id));
    ea_set_attr(&ca, EA_LITERAL_EMBEDDED(&ea_channel_id, 0, c->id));
    ea_set_attr(&ca, EA_LITERAL_EMBEDDED(&ea_in_keep, 0, c->in_keep));
    ea_set_attr(&ca, EA_LITERAL_STORE_PTR(&ea_rtable, 0, c->table));

    ASSERT_DIE(c->id < ts->length_channels);
    ASSERT_DIE(ts->channels[c->id] == NULL);
    ts->channels[c->id] = ea_lookup_slow(ca, 0, EALS_IN_TABLE);

    /* Update channel list in protocol state */
    ASSERT_DIE(c->proto->id < ts->length_states);

    ea_set_attr(&p->ea_state,
      EA_LITERAL_DIRECT_ADATA(&ea_proto_channel_list, 0, int_set_add(
        tmp_linpool, ea_get_adata(p->ea_state, &ea_proto_channel_list), c->id)));

    ea_lookup(p->ea_state, 0, EALS_CUSTOM);
    proto_announce_state_locked(ts, c->proto, p->ea_state);
  }

  CALL(c->class->init, c, cf);

  add_tail(&p->channels, &c->n);

  CD(c, "Connected to table %s", c->table->name);

  return c;
}

void
proto_remove_channel(struct proto *p UNUSED, struct channel *c)
{
  ASSERT(c->channel_state == CS_DOWN);

  CD(c, "Removed", c->name);

  ea_set_attr(&p->ea_state,
    EA_LITERAL_DIRECT_ADATA(&ea_proto_channel_list, 0, int_set_del(
      tmp_linpool, ea_get_adata(p->ea_state, &ea_proto_channel_list), c->id)));

  ea_lookup(p->ea_state, 0, EALS_CUSTOM);
  proto_announce_state(c->proto, p->ea_state);

  PST_LOCKED(ts)
  {
    ASSERT_DIE(c->id < ts->length_channels);
    ea_free_later(ts->channels[c->id]);
    ts->channels[c->id] = NULL;
    hmap_clear(&ts->channel_id_map, c->id);
  }

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

/**
 * # Automatic ROA reloads
 *
 * Route origin authorizations may (and do) change over time by updates via
 * our RPKI protocols. This then manifests in ROA tables. As the roa_check()
 * is always executed on a specific contents of ROA table in a specific moment
 * of time, its value may switch after updates in the ROA table and therefore
 * must be re-evaluated any time the result may have changed.
 *
 * To enable this mechanism, there are auxiliary tools integrated in BIRD
 * to automatically re-evaluate all filters that may get a different outcome
 * after ROA change.
 *
 * ROA Subscription Data Structure (struct roa_subscription) is the connector
 * between the channel and the ROA table, keeping track about unprocessed
 * changes and initiating the reloads. The modus operandi is as follows:
 *
 * Init 1. Check whether the filter uses ROA at all.
 * Init 2. Request exports from the ROA table
 * Init 3. Allocate a trie
 *
 * Export from ROA: This may affect all routes for prefixes matching the ROA
 * prefix, disregarding its maxlen. Thus we mark these routes in the request's
 * auxiliary trie. Then we ping the settle timer to wait a reasonable amount of
 * time before actually requesting channel reload.
 *
 * Settle timer fires when nothing has pinged it for the 'min' time, or 'max'
 * time has elapsed since the first ping. It then:
 *
 * - requests partial channel import / export reload based on the trie
 * - allocates a new trie
 *
 * As the import/export reload uses the auxiliary trie to prefilter prefixes,
 * the trie must be freed after the reload is done, which is ensured in the
 * .done() hook of the reimport/reexport request.
 *
 * # Channel export refeed
 *
 * The request, either by ROA or from CLI, is enqueued to the channel and an
 * auxiliary export hook is requested from the table. This way, the ordinary
 * updates can flow uninterrupted while refeed gets prefiltered by the given
 * trie (if given). When the auxiliary export hook finishes, the .done() hook
 * is then called for the requestor to do their cleanup.
 *
 * While refeeding, special care must be taken about route changes inside the
 * table. For this, an auxiliary trie is allocated to keep track about already
 * refed net, to avoid unnecessary multiple re-evaluation of filters.
 *
 * # Channel import reload from import table
 *
 * When the import table is on, the channel keeps the original version of the route
 * in the table together with the actual version after filters, in a form of
 * an additional layer of route attributes underneath the actual version. This makes
 * it exceptionally simple to get the original version of the route directly
 * from the table by an ordinary export which strips all the newer layers.
 *
 * Then, by processing all these auxiliary exports, the channel basically re-imports
 * all the routes into the table back again, re-evaluating the filters and ROA checks.
 *
 * # Channel import reload from protocols
 *
 * When the import table is off, the protocol gets the reimport request directly
 * via the .reload_routes() hook and must do its internal route reload instead.
 * The protocol may not support it and in such case, this function returns 0
 * indicating that no partial reload is going to happen. It's then on the
 * developer's or user's discretion to run a full reload instead.
 *
 * # Caveats, FIXME's, TODO's and other kinds of hell
 *
 * The partial reexport uses a trie to track state for single prefixes. This
 * may do crazy things if a partial reload was to be performed on any other
 * table than plain IPv6 or IPv4. Network types like VPNv6 or Flowspec may
 * cause some crashes. This is currently not checked anywhere.
 *
 * Anyway, we decided to split the table FIB structure to carry only a mapping
 * between a prefix and a locally-unique ID, and after this update is done
 * (probably also in v2), the tracking tries may be easily replaced by
 * bitfields, therefore fixing this bug.
 *
 * We also probably didn't do a proper analysis of the implemented algorithm
 * for reexports, so if there is somebody willing to formally prove that we
 * both won't miss any update and won't reexport more than needed, you're welcome
 * to submit such a proof.
 *
 * We wish you a pleasant reading, analyzing and bugfixing experience.
 *
 *					  Kata, Maria and the BIRD Team
 */

struct roa_subscription {
  node roa_node;
  struct channel *c;
  rtable *tab;
  void (*refeed_hook)(struct channel *, struct rt_feeding_request *);
  struct lfjour_recipient digest_recipient;
  event update_event;
};

struct roa_reload_request {
  struct rt_feeding_request req;
  struct roa_subscription *s;
  struct lfjour_item *item;
};

static void
channel_roa_reload_done(struct rt_feeding_request *req)
{
  SKIP_BACK_DECLARE(struct roa_reload_request, rrr, req, req);
  ASSERT_DIE(rrr->s->c->channel_state == CS_UP);

  lfjour_release(&rrr->s->digest_recipient, rrr->item);
  ev_send(proto_work_list(rrr->s->c->proto), &rrr->s->update_event);
  mb_free(rrr);
  /* FIXME: this should reset import/export filters if ACTION BLOCK */
}

static void
channel_roa_changed(void *_s)
{
  struct roa_subscription *s = _s;

  u64 first_seq = 0, last_seq = 0;
  uint count = 0;
  for (struct lfjour_item *it; it = lfjour_get(&s->digest_recipient); )
  {
    SKIP_BACK_DECLARE(struct rt_digest, rd, li, s->digest_recipient.cur);
    struct roa_reload_request *rrr = mb_alloc(s->c->proto->pool, sizeof *rrr);
    *rrr = (struct roa_reload_request) {
      .req = {
	.prefilter = {
	  .mode = TE_ADDR_TRIE,
	  .trie = rd->trie,
	},
	.done = channel_roa_reload_done,
      },
      .s = s,
      .item = it,
    };

    if (!first_seq) first_seq = it->seq;
    last_seq = it->seq;
    count++;
    s->refeed_hook(s->c, &rrr->req);
  }

  if (s->c->debug & D_EVENTS)
    if (count)
      log(L_INFO "%s.%s: Requested %u automatic roa reloads, seq %lu to %lu",
	  s->c->proto->name, s->c->name, count, first_seq, last_seq);
    else
      log(L_INFO "%s.%s: No roa reload requested",
	  s->c->proto->name, s->c->name);
}

static inline void (*channel_roa_reload_hook(int dir))(struct channel *, struct rt_feeding_request *)
{
  return dir ? channel_reimport : channel_refeed;
}

static int
channel_roa_is_subscribed(struct channel *c, rtable *tab, int dir)
{
  struct roa_subscription *s;
  node *n;

  WALK_LIST2(s, n, c->roa_subscriptions, roa_node)
    if ((tab == s->tab) && (s->refeed_hook == channel_roa_reload_hook(dir)))
      return 1;

  return 0;
}

static void
channel_roa_subscribe(struct channel *c, rtable *tab, int dir)
{
  if (channel_roa_is_subscribed(c, tab, dir))
    return;

  rtable *aux = tab->config->roa_aux_table->table;

  struct roa_subscription *s = mb_allocz(c->proto->pool, sizeof(struct roa_subscription));
  *s = (struct roa_subscription) {
    .c = c,
    .tab = aux,
    .refeed_hook = channel_roa_reload_hook(dir),
    .digest_recipient = {
      .target = proto_work_list(c->proto),
      .event = &s->update_event,
    },
    .update_event = {
      .hook = channel_roa_changed,
      .data = s,
    },
  };

  add_tail(&c->roa_subscriptions, &s->roa_node);

  RT_LOCK(aux, t);
  rt_lock_table(t);
  rt_setup_digestor(t);
  lfjour_register(&t->export_digest->digest, &s->digest_recipient);
}

static void
channel_roa_unsubscribe(struct roa_subscription *s)
{
  struct channel *c = s->c;

  RT_LOCKED(s->tab, t)
  {
    lfjour_unregister(&s->digest_recipient);
    rt_unlock_table(t);
  }

  ev_postpone(&s->update_event);

  rem_node(&s->roa_node);
  mb_free(s);

  channel_check_stopped(c);
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

  struct filter_iterator fit;
  FILTER_ITERATE_INIT(&fit, f->root, c->proto->pool);

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
    .loop = c->proto->loop,
    .dump_req = channel_dump_import_req,
    .log_state_change = channel_import_log_state_change,
    .preimport = channel_preimport,
  };

  ASSERT(c->channel_state == CS_UP);

  channel_reset_limit(c, &c->rx_limit, PLD_RX);
  channel_reset_limit(c, &c->in_limit, PLD_IN);

  bmap_init(&c->imported_map, c->proto->pool, 16);

  memset(&c->import_stats, 0, sizeof(struct channel_import_stats));

  DBG("%s.%s: Channel start import req=%p\n", c->proto->name, c->name, &c->in_req);
  rt_request_import(c->table, &c->in_req);
}

void channel_notify_basic(void *);
void channel_notify_accepted(void *);
void channel_notify_merged(void *);

static void
channel_start_export(struct channel *c)
{
  if (rt_export_get_state(&c->out_req) != TES_DOWN)
    bug("%s.%s: Attempted to start channel's already started export", c->proto->name, c->name);

  ASSERT(c->channel_state == CS_UP);

  pool *p = rp_newf(c->proto->pool, c->proto->pool->domain, "Channel %s.%s export", c->proto->name, c->name);

  c->out_req = (struct rt_export_request) {
    .name = mb_sprintf(p, "%s.%s", c->proto->name, c->name),
    .r = {
      .target = proto_work_list(c->proto),
      .event = &c->out_event,
    },
    .pool = p,
    .feeder.prefilter = {
      .mode = c->out_subprefix ? TE_ADDR_IN : TE_ADDR_NONE,
      .addr = c->out_subprefix,
    },
    .trace_routes = c->debug | c->proto->debug,
    .dump = channel_dump_export_req,
    .fed = channel_export_fed,
  };

  c->out_event = (event) {
    .data = c,
  };

  bmap_init(&c->export_accepted_map, p, 16);
  bmap_init(&c->export_rejected_map, p, 16);

  channel_reset_limit(c, &c->out_limit, PLD_OUT);

  memset(&c->export_stats, 0, sizeof(struct channel_export_stats));

  DBG("%s.%s: Channel start export req=%p\n", c->proto->name, c->name, &c->out_req);

  switch (c->ra_mode) {
    case RA_OPTIMAL:
      c->out_event.hook = channel_notify_basic;
      rt_export_subscribe(c->table, best, &c->out_req);
      break;
    case RA_ANY:
      c->out_event.hook = channel_notify_basic;
      rt_export_subscribe(c->table, all, &c->out_req);
      break;
    case RA_ACCEPTED:
      c->out_event.hook = channel_notify_accepted;
      rt_export_subscribe(c->table, all, &c->out_req);
      break;
    case RA_MERGED:
      c->out_event.hook = channel_notify_merged;
      rt_export_subscribe(c->table, all, &c->out_req);
      break;
    default:
      bug("Unknown route announcement mode");
  }
}

static void
channel_check_stopped(struct channel *c)
{
  switch (c->channel_state)
  {
    case CS_STOP:
      if (c->obstacles || !EMPTY_LIST(c->roa_subscriptions) || c->in_req.hook)
	return;

      ASSERT_DIE(rt_export_get_state(&c->out_req) == TES_DOWN);
      ASSERT_DIE(!rt_export_feed_active(&c->reimporter));

      channel_set_state(c, CS_DOWN);
      proto_send_event(c->proto, c->proto->event);

      break;
    case CS_PAUSE:
      if (c->obstacles || !EMPTY_LIST(c->roa_subscriptions))
	return;

      ASSERT_DIE(rt_export_get_state(&c->out_req) == TES_DOWN);
      ASSERT_DIE(!rt_export_feed_active(&c->reimporter));

      channel_set_state(c, CS_START);
      break;
  }

  DBG("%s.%s: Channel requests/hooks stopped (in state %s)\n", c->proto->name, c->name, c_states[c->channel_state]);
}

void
channel_add_obstacle(struct channel *c)
{
  c->obstacles++;
}

void
channel_del_obstacle(struct channel *c)
{
  if (!--c->obstacles)
    channel_check_stopped(c);
}

void
channel_import_stopped(struct rt_import_request *req)
{
  SKIP_BACK_DECLARE(struct channel, c, in_req, req);

  mb_free(c->in_req.name);
  c->in_req.name = NULL;

  bmap_free(&c->imported_map);

  channel_check_stopped(c);
}

static u32
channel_reimport_next_feed_index(struct rt_export_feeder *f, u32 try_this)
{
  SKIP_BACK_DECLARE(struct channel, c, reimporter, f);
  while (!bmap_test(&c->imported_map, try_this))
    if (!(try_this & (try_this - 1))) /* return every power of two to check for maximum */
      return try_this;
    else
      try_this++;

  return try_this;
}

static void
channel_do_reload(void *_c)
{
  struct channel *c = _c;

  RT_FEED_WALK(&c->reimporter, f)
  {
    bool seen = 0;
    for (uint i = 0; i < f->count_routes; i++)
    {
      rte *r = &f->block[i];

      if (r->flags & REF_OBSOLETE)
	break;

      if (r->sender == c->in_req.hook)
      {
	/* Strip the table-specific information */
	rte new = rte_init_from(r);

	/* Strip the later attribute layers */
	new.attrs = ea_strip_to(new.attrs, BIT32_ALL(EALS_PREIMPORT));

	/* And reload the route */
	rte_update(c, r->net, &new, new.src);

	seen = 1;
      }
    }

    if (!seen)
      bmap_clear(&c->imported_map, f->ni->index);

    /* Local data needed no more */
    tmp_flush();

    MAYBE_DEFER_TASK(proto_work_list(c->proto), &c->reimport_event,
	"%s.%s reimport", c->proto->name, c->name);
  }
}

/* Called by protocol to activate in_table */
static void
channel_setup_in_table(struct channel *c)
{
  c->reimporter = (struct rt_export_feeder) {
    .name = mb_sprintf(c->proto->pool, "%s.%s.reimport", c->proto->name, c->name),
    .trace_routes = c->debug,
    .next_feed_index = channel_reimport_next_feed_index,
  };
  c->reimport_event = (event) {
    .hook = channel_do_reload,
    .data = c,
  };
  rt_feeder_subscribe(&c->table->export_all, &c->reimporter);
}


static void
channel_do_start(struct channel *c)
{
  c->proto->active_channels++;

  if ((c->in_keep & RIK_PREFILTER) == RIK_PREFILTER)
    channel_setup_in_table(c);

  CALL(c->class->start, c);

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
  /* Drop ROA subscriptions */
  channel_roa_unsubscribe_all(c);

  /* Stop export */
  channel_stop_export(c);
}

static void
channel_do_stop(struct channel *c)
{
  /* Stop import */
  if (c->in_req.hook)
    rt_stop_import(&c->in_req, channel_import_stopped);

  /* Need to abort reimports as well */
  rt_feeder_unsubscribe(&c->reimporter);
  ev_postpone(&c->reimport_event);

  c->gr_wait = 0;
  if (c->gr_lock)
    channel_graceful_restart_unlock(c);

  CALL(c->class->shutdown, c);

}

static void
channel_do_down(struct channel *c)
{
  ASSERT_DIE(!rt_export_feed_active(&c->reimporter));

  c->proto->active_channels--;

  memset(&c->import_stats, 0, sizeof(struct channel_import_stats));
  memset(&c->export_stats, 0, sizeof(struct channel_export_stats));

  c->out_table = NULL;

  /* The in_table and out_table are going to be freed by freeing their resource pools. */

  CALL(c->class->cleanup, c);

  /* Schedule protocol shutddown */
  if (proto_is_done(c->proto))
    proto_send_event(c->proto, c->proto->event);
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

static void
channel_stop_export(struct channel *c)
{
  switch (rt_export_get_state(&c->out_req))
  {
    case TES_FEEDING:
    case TES_PARTIAL:
    case TES_READY:
      if (c->ra_mode == RA_OPTIMAL)
	rt_export_unsubscribe(best, &c->out_req);
      else
	rt_export_unsubscribe(all, &c->out_req);

      ev_postpone(&c->out_event);

      bmap_free(&c->export_accepted_map);
      bmap_free(&c->export_rejected_map);

      c->out_req.name = NULL;
      rfree(c->out_req.pool);

      channel_check_stopped(c);
      break;

    case TES_DOWN:
      break;

    case TES_STOP:
    case TES_MAX:
      bug("Impossible export state");
  }
}

void
channel_request_reload(struct channel *c, struct rt_feeding_request *cir)
{
  ASSERT(c->in_req.hook);
  ASSERT(channel_reloadable(c));

  if (cir)
    CD(c, "Partial import reload requested");
  else
    CD(c, "Full import reload requested");

  if ((c->in_keep & RIK_PREFILTER) == RIK_PREFILTER)
    channel_reimport(c, cir);
  else if (! c->proto->reload_routes(c, cir))
    cli_msg(-15, "%s.%s: partial reload refused, please run full reload instead", c->proto->name, c->name);
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

    if (proto->net_type && (net_type != proto->net_type) && (net_type != NET_MPLS))
      cf_error("Different channel type");

    tab = rt_get_default_table(new_config, net_type);
  }

  if (!cc)
    cc = &channel_basic;

  cf = cfg_allocz(cc->config_size);
  cf->name = name;
  cf->class = cc;
  cf->parent = proto;
  cf->table = tab;
  cf->out_filter = FILTER_REJECT;

  cf->net_type = net_type;
  cf->ra_mode = RA_OPTIMAL;
  cf->preference = proto->protocol->preference;
  cf->debug = new_config->channel_default_debug;
  cf->rpki_reload = 1;

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
      cf->copy = 1;
      return cf;
    }

  return channel_config_new(cc, name, net_type, proto);
}

struct channel_config *
channel_copy_config(struct channel_config *src, struct proto_config *proto)
{
  struct channel_config *dst = cfg_alloc(src->class->config_size);

  memcpy(dst, src, src->class->config_size);
  memset(&dst->n, 0, sizeof(node));
  add_tail(&proto->channels, &dst->n);
  CALL(src->class->copy_config, dst, src);

  return dst;
}


static int reconfigure_type;  /* Hack to propagate type info to channel_reconfigure() */

int
channel_reconfigure(struct channel *c, struct channel_config *cf)
{
  /* Touched by reconfiguration */
  c->stale = 0;

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
  c->out_req.feeder.prefilter.addr = c->out_subprefix = cf->out_subprefix;
  c->debug = cf->debug;
  c->in_req.trace_routes = c->out_req.trace_routes = c->debug | c->proto->debug;
  c->rpki_reload = cf->rpki_reload;

  /* Execute channel-specific reconfigure hook */
  if (c->class->reconfigure && !c->class->reconfigure(c, cf, &import_changed, &export_changed))
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
    channel_request_reload(c, NULL);

  if (export_changed)
    channel_request_full_refeed(c);

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
    if (p->proto_state != PS_DOWN_XX)
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
proto_loop_stopped(void *ptr)
{
  struct proto *p = ptr;

  ASSERT_DIE(birdloop_inside(&main_birdloop));
  ASSERT_DIE(p->loop != &main_birdloop);

  p->pool = NULL; /* is freed by birdloop_free() */
  birdloop_free(p->loop);
  p->loop = &main_birdloop;

  proto_notify_state(p, PS_DOWN_XX);
  proto_rethink_goal(p);
}

static void
proto_event(void *ptr)
{
  struct proto *p = ptr;

  if (p->do_stop)
  {
    p->do_stop = 0;
  }

  if (proto_is_done(p) && p->pool_inloop)  /* perusing pool_inloop to do this once only */
  {
    /* Interface notification unsubscribe can't be done
     * before the protocol is really done, as it also destroys
     * the neighbors which may be needed (e.g. by BGP->MRT)
     * during the STOP phase as well. */
    iface_unsubscribe(&p->iface_sub);

    rp_free(p->pool_inloop);
    p->pool_inloop = NULL;
    if (p->loop != &main_birdloop)
      birdloop_stop_self(p->loop, proto_loop_stopped, p);
    else
    {
      proto_notify_state(p, PS_DOWN_XX);
      proto_rethink_goal(p);
    }
  }
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

  OBSREF_SET(p->global_config, cf->global);
  p->cf = cf;
  p->debug = cf->debug;
  p->mrtdump = cf->mrtdump;
  p->name = cf->name;
  p->proto = cf->protocol;
  p->net_type = cf->net_type;
  p->disabled = cf->disabled;
  p->hash_key = random_u32();
  cf->proto = p;

  PST_LOCKED(tp)
  {
    p->id = hmap_first_zero(&tp->proto_id_map);
    hmap_set(&tp->proto_id_map, p->id);

    if (p->id >= tp->length_states)
    {
      /* Grow the states array */
      ea_list **new_states = mb_allocz(tp->pool, sizeof *new_states * tp->length_states * 2);
      memcpy(new_states, tp->states, tp->length_states * sizeof *new_states);

      mb_free(tp->states);
      tp->states = new_states;
      tp->length_states *= 2;
    }
  }

  init_list(&p->channels);

  /*
    Making first version of proto eatters.
  */
  struct ea_list *state = NULL;

  ea_set_attr(&state, EA_LITERAL_STORE_STRING(&ea_name, 0, p->name));
  ea_set_attr(&state, EA_LITERAL_STORE_PTR(&ea_protocol_type, 0, &p->proto));
  ea_set_attr(&state, EA_LITERAL_EMBEDDED(&ea_state, 0, p->proto_state));
  ea_set_attr(&state, EA_LITERAL_STORE_ADATA(&ea_last_modified, 0, &p->last_state_change, sizeof(btime)));
  ea_set_attr(&state, EA_LITERAL_EMBEDDED(&ea_proto_id, 0, p->id));
  ea_set_attr(&state, EA_LITERAL_STORE_ADATA(&ea_proto_channel_list, 0, NULL, 0));

  proto_announce_state(p, state);

  return p;
}

static struct proto *
proto_init(struct proto_config *c, struct proto *after)
{
  struct protocol *pr = c->protocol;
  struct proto *p = pr->init(c);

  p->loop = &main_birdloop;
  p->proto_state = PS_DOWN_XX;
  p->last_state_change = current_time();
  p->vrf = c->vrf;
  proto_add_after(&global_proto_list, p, after);

  p->event = ev_new_init(proto_pool, proto_event, p);

  PD(p, "Initializing%s", p->disabled ? " [disabled]" : "");

  return p;
}

static void
proto_start(struct proto *p)
{
  DBG("Kicking %s up\n", p->name);
  PD(p, "Starting");

  if (graceful_restart_state == GRS_INIT)
    p->gr_recovery = 1;

  if (p->cf->loop_order != DOMAIN_ORDER(the_bird))
  {
    p->loop = birdloop_new(proto_pool, p->cf->loop_order, p->cf->loop_max_latency, "Protocol %s", p->cf->name);
    p->pool = birdloop_pool(p->loop);
  }
  else
    p->pool = rp_newf(proto_pool, the_bird_domain.the_bird, "Protocol %s", p->cf->name);

  p->iface_sub.target = proto_event_list(p);
  p->iface_sub.name = p->name;
  p->iface_sub.debug = !!(p->debug & D_IFACES);

  PROTO_LOCKED_FROM_MAIN(p)
  {
    p->pool_inloop = rp_newf(p->pool, birdloop_domain(p->loop), "Protocol %s early cleanup objects", p->cf->name);
    p->pool_up = rp_newf(p->pool, birdloop_domain(p->loop), "Protocol %s stop-free objects", p->cf->name);
    proto_notify_state(p, (p->proto->start ? p->proto->start(p) : PS_UP));
  }
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
  if (p->proto_state == PS_DOWN_XX)
    return 0;

  /* If there is a too big change in core attributes, ... */
  if ((nc->protocol != oc->protocol) ||
      (nc->net_type != oc->net_type) ||
      (nc->disabled != p->disabled) ||
      (nc->vrf != oc->vrf))
    return 0;

  p->sources.name = p->name = nc->name;
  p->sources.debug = p->debug = nc->debug;
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

static struct protos_commit_request {
  struct config *new;
  struct config *old;
  enum protocol_startup phase;
  int type;
} protos_commit_request;

static int proto_rethink_goal_pending = 0;

static void protos_do_commit(struct config *new, struct config *old, int type);

/**
 * protos_commit - commit new protocol configuration
 * @new: new configuration
 * @old: old configuration or %NULL if it's boot time config
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
protos_commit(struct config *new, struct config *old, int type)
{
  protos_commit_request = (struct protos_commit_request) {
    .new = new,
    .old = old,
    .phase = (new->shutdown && !new->gr_down) ? PROTOCOL_STARTUP_REGULAR : PROTOCOL_STARTUP_NECESSARY,
    .type = type,
  };

  protos_do_commit(new, old, type);
}

static void
protos_do_commit(struct config *new, struct config *old, int type)
{
  enum protocol_startup phase = protos_commit_request.phase;
  struct proto_config *oc, *nc;
  struct symbol *sym;
  struct proto *p;

  if ((phase < PROTOCOL_STARTUP_REGULAR) || (phase > PROTOCOL_STARTUP_NECESSARY))
  {
    protos_commit_request = (struct protos_commit_request) {};
    return;
  }

  DBG("protos_commit:\n");
  if (old)
  {
    WALK_LIST(oc, old->protos)
    {
      if (oc->protocol->startup != phase)
	continue;

      p = oc->proto;
      sym = cf_find_symbol(new, oc->name);

      struct birdloop *proto_loop = PROTO_ENTER_FROM_MAIN(p);

      /* Handle dynamic protocols */
      if (!sym && oc->parent && !new->shutdown)
      {
	struct symbol *parsym = cf_find_symbol(new, oc->parent->name);
	if (parsym && parsym->class == SYM_PROTO)
	{
	  /* This is hack, we would like to share config, but we need to copy it now */
	  new_config = new;
	  cfg_mem = new->mem;
	  new->current_scope = new->root_scope;
	  sym = cf_get_symbol(new, oc->name);
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
	if (proto_reconfigure(p, oc, nc, type))
	{
	  OBSREF_CLEAR(p->global_config);
	  OBSREF_SET(p->global_config, new);
	  PROTO_LEAVE_FROM_MAIN(proto_loop);
	  continue;
	}

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
      PROTO_LEAVE_FROM_MAIN(proto_loop);

      proto_rethink_goal(p);
    }
  }

  struct proto *after = NULL;

  WALK_LIST(nc, new->protos)
    if ((nc->protocol->startup == phase) && !nc->proto)
    {
      /* Not a first-time configuration */
      if (old)
	log(L_INFO "Adding protocol %s", nc->name);

      p = proto_init(nc, after);
      after = p;

      proto_rethink_goal(p);
    }
    else
      after = nc->proto;

  DBG("Protocol start\n");

  /* Determine router ID for the first time - it has to be here and not in
     global_commit() because it is postponed after start of device protocol */
  if ((phase == PROTOCOL_STARTUP_NECESSARY) && !old)
  {
    struct global_runtime *gr = atomic_load_explicit(&global_runtime, memory_order_relaxed);
    if (!gr->router_id)
    {
      gr->router_id = if_choose_router_id(new->router_id_from, 0);
      if (!gr->router_id)
	die("Cannot determine router ID, please configure it manually");
    }
  }

  /* Commit next round of protocols */
  if (new->shutdown && !new->gr_down)
    protos_commit_request.phase++;
  else
    protos_commit_request.phase--;

  /* If something is pending, the next round will be called asynchronously from proto_rethink_goal(). */
  if (!proto_rethink_goal_pending)
    protos_do_commit(new, old, type);
}

static void
proto_shutdown(struct proto *p)
{
  if (p->proto_state == PS_START || p->proto_state == PS_UP)
  {
    /* Going down */
    DBG("Kicking %s down\n", p->name);
    PD(p, "Shutting down");
    proto_notify_state(p, (p->proto->shutdown ? p->proto->shutdown(p) : PS_FLUSH));
    if (p->reconfiguring)
    {
      proto_rethink_goal_pending++;
      p->reconfiguring = 2;
    }
  }
}

static void
proto_rethink_goal(struct proto *p)
{
  int goal_pending = (p->reconfiguring == 2);

  if (p->reconfiguring && (p->proto_state == PS_DOWN_XX))
  {
    struct proto_config *nc = p->cf_new;
    struct proto *after = p->n.prev;

    proto_announce_state(p, NULL);

    DBG("%s has shut down for reconfiguration\n", p->name);
    p->cf->proto = NULL;
    OBSREF_CLEAR(p->global_config);
    proto_remove_channels(p);
    proto_rem_node(&global_proto_list, p);
    rfree(p->event);
    mb_free(p->message);
    mb_free(p);
    if (!nc)
      goto done;

    p = proto_init(nc, after);
  }

  /* Determine what state we want to reach */
  if (p->disabled || p->reconfiguring)
  {
    PROTO_LOCKED_FROM_MAIN(p)
      proto_shutdown(p);
  }
  else if (p->proto_state == PS_DOWN_XX)
    proto_start(p);

done:
  if (goal_pending && !--proto_rethink_goal_pending)
    protos_do_commit(
	protos_commit_request.new,
	protos_commit_request.old,
	protos_commit_request.type
	);
}

struct proto *
proto_spawn(struct proto_config *cf, uint disabled)
{
  struct proto *p = proto_init(cf, global_proto_list.last);
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
  u32 gr_wait = atomic_load_explicit(&global_runtime, memory_order_relaxed)->gr_wait;
  tm_start(gr_wait_timer, gr_wait S);
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
graceful_restart_done(timer *t)
{
  log(L_INFO "Graceful restart done");
  graceful_restart_state = GRS_DONE;

  WALK_TLIST(proto, p, &global_proto_list)
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

  rfree(t);
}

void
graceful_restart_show_status(void)
{
  if (graceful_restart_state != GRS_ACTIVE)
    return;

  cli_msg(-24, "Graceful restart recovery in progress");
  cli_msg(-24, "  Waiting for %d channels to recover", graceful_restart_locks);
  cli_msg(-24, "  Wait timer is %t/%u", tm_remains(gr_wait_timer),
      atomic_load_explicit(&global_runtime, memory_order_relaxed)->gr_wait);
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

  WALK_TLIST(proto, p, &global_proto_list) PROTO_LOCKED_FROM_MAIN(p)
  {
#define DPF(x)	(p->x ? " " #x : "")
    debug("  protocol %s (%p) state %s with %d active channels flags: %s%s%s\n",
	p->name, p, p_states[p->proto_state], p->active_channels,
	DPF(disabled), DPF(do_stop), DPF(reconfiguring));
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
	  rt_export_state_name(rt_export_get_state(&c->out_req)));
    }

    debug("\tSOURCES\n");
    rt_dump_sources(&p->sources);

    if (p->proto->dump &&
	(p->proto_state != PS_DOWN_XX) &&
	(p->proto_state != PS_FLUSH))
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
  proto_pool = rp_new(&root_pool, the_bird_domain.the_bird, "Protocols");

  /* Protocol attributes */
  ea_register_init(&ea_name);
  ea_register_init(&ea_protocol_name);
  ea_register_init(&ea_protocol_type);
  ea_register_init(&ea_state);
  ea_register_init(&ea_last_modified);
  ea_register_init(&ea_info);
  ea_register_init(&ea_proto_id);
  ea_register_init(&ea_channel_id);
  ea_register_init(&ea_in_keep);
  ea_register_init(&ea_proto_channel_list);
  ea_register_init(&ea_rtable);

  proto_state_table_pub.lock = DOMAIN_NEW(rtable);

  /* Init proto_state_table */
  pool *p = rp_new(&root_pool, the_bird_domain.the_bird, "Proto state table");

  PST_LOCKED(ts)
  {
    ts->length_channels = 64;
    ts->length_states = 32;

    hmap_init(&ts->proto_id_map, p, ts->length_states); /* for proto ids. Value of proto id is the same as index of that proto in ptoto_state_table->attrs */
    hmap_init(&ts->channel_id_map, p, ts->length_channels);

    ts->pool = p;
    ts->states = mb_allocz(p, sizeof(ea_list *) * ts->length_states);
    ts->channels = mb_allocz(p, sizeof(ea_list *) * ts->length_channels * 2);
  }

  /* Init proto state journal */
  struct settle_config cf = {.min = 0, .max = 0};
  proto_state_table_pub.journal.item_done = proto_journal_item_cleanup;
  proto_state_table_pub.journal.item_size = sizeof(struct proto_pending_update);
  proto_state_table_pub.journal.loop = birdloop_new(&root_pool, DOMAIN_ORDER(service), 1, "proto journal loop");
  proto_state_table_pub.journal.domain = proto_state_table_pub.lock.rtable;

  lfjour_init(&proto_state_table_pub.journal, &cf);

  protos_build_gen();
}


/* Temporary hack to propagate restart to BGP */
int proto_restart;

static void
proto_restart_event_hook(void *_p)
{
  struct proto *p = _p;
  if (!p->down_sched)
    return;

  proto_restart = (p->down_sched == PDS_RESTART);
  p->disabled = 1;
  proto_rethink_goal(p);

  p->restart_event = NULL;
  p->restart_timer = NULL;

  if (proto_restart)
    /* No need to call proto_rethink_goal() here again as the proto_cleanup() routine will
     * call it after the protocol stops ... and both these routines are fixed to main_birdloop.
     */
    p->disabled = 0;
}

static void
proto_send_restart_event(struct proto *p)
{
  if (!p->restart_event)
    p->restart_event = ev_new_init(p->pool, proto_restart_event_hook, p);

  ev_send(&global_event_list, p->restart_event);
}

static void
proto_send_restart_event_from_timer(struct timer *t)
{
  proto_send_restart_event((struct proto *) t->data);
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

  if (!restart)
  {
    if (p->restart_timer && tm_active(p->restart_timer))
      tm_stop(p->restart_timer);

    proto_send_restart_event(p);
  }
  else
  {
    if (!p->restart_timer)
      p->restart_timer = tm_new_init(p->pool, proto_send_restart_event_from_timer, p, 0, 0);

    tm_start_max_in(p->restart_timer, 250 MS, p->loop);
  }
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

static inline void
proto_do_start(struct proto *p)
{
  p->sources.debug = p->debug;
  rt_init_sources(&p->sources, p->name, proto_event_list(p));

  if (!p->cf->late_if_feed)
    iface_subscribe(&p->iface_sub);
}

static void
proto_do_up(struct proto *p)
{
  if (!p->main_source)
    p->main_source = rt_get_source(p, 0);
    // Locked automaticaly

  proto_start_channels(p);

  if (p->cf->late_if_feed)
    iface_subscribe(&p->iface_sub);
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

  rp_free(p->pool_up);
  p->pool_up = NULL;

  proto_stop_channels(p);
  rt_destroy_sources(&p->sources, p->event);

  p->do_stop = 1;
  proto_send_event(p, p->event);
}

static void
proto_do_down(struct proto *p)
{
  p->down_code = 0;

  /* Shutdown is finished in the protocol event */
  if (proto_is_done(p))
    proto_send_event(p, p->event);
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

  ea_set_attr(&p->ea_state, EA_LITERAL_EMBEDDED(&ea_state, 0, p->proto_state));
  ea_lookup(p->ea_state, 0, EALS_CUSTOM);
  proto_announce_state(p, p->ea_state);

  switch (state)
  {
  case PS_START:
    ASSERT(ps == PS_DOWN_XX || ps == PS_UP);

    if (ps == PS_DOWN_XX)
      proto_do_start(p);
    else 
      proto_do_pause(p);
    break;

  case PS_UP:
    ASSERT(ps == PS_DOWN_XX || ps == PS_START);

    if (ps == PS_DOWN_XX)
      proto_do_start(p);

    proto_do_up(p);
    break;

  case PS_STOP:
    ASSERT(ps == PS_START || ps == PS_UP);

    proto_do_stop(p);
    break;

  case PS_FLUSH:
    if (ps != PS_STOP)
      proto_do_stop(p);

    proto_do_down(p);
    break;

  case PS_DOWN_XX:
    ASSERT(ps == PS_FLUSH);

    CALL(p->proto->cleanup, p);

    if (p->pool)
    {
      rp_free(p->pool);
      p->pool = NULL;
    }

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
  case PS_DOWN_XX:		return "down";
  case PS_START:	return "start";
  case PS_UP:		return "up";
  case PS_STOP:		return "stop";
  case PS_FLUSH:	return "flush";
  default:		return "???";
  }
}

static void
channel_show_stats(struct channel *c)
{
  struct channel_import_stats *ch_is = &c->import_stats;
  struct channel_export_stats *ch_es = &c->export_stats;
  struct rt_import_stats *rt_is = c->in_req.hook ? &c->in_req.hook->stats : NULL;
  struct rt_export_stats *rt_es = &c->out_req.stats;

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
  cli_msg(-1006, "    Export state:   %s", rt_export_state_name(rt_export_get_state(&c->out_req)));
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

  rcu_read_lock();
  tm_format_time(tbuf, &atomic_load_explicit(&global_runtime, memory_order_acquire)->tf_proto, p->last_state_change);
  rcu_read_unlock();
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

struct channel_cmd_reload_request {
  struct rt_feeding_request cfr;
  struct proto_reload_request *prr;
};

static void
channel_reload_done(struct rt_feeding_request *cfr)
{
  SKIP_BACK_DECLARE(struct channel_cmd_reload_request, ccrfr, cfr, cfr);
  if (atomic_fetch_sub_explicit(&ccrfr->prr->counter, 1, memory_order_acq_rel) == 1)
    ev_send_loop(&main_birdloop, &ccrfr->prr->ev);
}

static struct rt_feeding_request *
channel_create_reload_request(struct proto_reload_request *prr)
{
  if (!prr->trie)
    return NULL;

  /* Increase the refeed counter */
  atomic_fetch_add_explicit(&prr->counter, 1, memory_order_relaxed);
  ASSERT_DIE(this_cli->parser_pool != prr->trie->lp);

  struct channel_cmd_reload_request *req = lp_alloc(prr->trie->lp, sizeof *req);
  *req = (struct channel_cmd_reload_request) {
    .cfr = {
      .done = channel_reload_done,
      .prefilter = {
	.mode = TE_ADDR_TRIE,
	.trie = prr->trie,
      },
    },
      .prr = prr,
  };

  return &req->cfr;
}

void
proto_cmd_reload(struct proto *p, uintptr_t _prr, int cnt UNUSED)
{
  struct proto_reload_request *prr = (void *) _prr;
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
  if (prr->dir & CMD_RELOAD_IN)
    WALK_LIST(c, p->channels)
      if ((c->channel_state == CS_UP) && !channel_reloadable(c))
      {
	cli_msg(-8006, "%s: reload failed", p->name);
	return;
      }

  log(L_INFO "Reloading protocol %s", p->name);

  /* re-importing routes */
  WALK_LIST(c, p->channels)
    if (c->channel_state == CS_UP)
    {
      if (prr->dir & CMD_RELOAD_IN)
	channel_request_reload(c, channel_create_reload_request(prr));

      if (prr->dir & CMD_RELOAD_OUT)
	if (c->out_req.name)
	  rt_export_refeed(&c->out_req, channel_create_reload_request(prr));
    }

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
  int cnt = 0;

  WALK_TLIST(proto, p, &global_proto_list)
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
  struct proto *p;

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
    WALK_TLIST(proto, q, &global_proto_list)
      if ((q->proto == pr) && (q->proto_state != PS_DOWN_XX))
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
    for (struct proto *p = old ? old->n.next : global_proto_list.first;
	p;
	p = p->n.next)
    {
      if ((p->proto == proto) && (p->proto_state != PS_DOWN_XX))
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

static void
proto_journal_item_cleanup_(ea_list *proto_attr, ea_list *old_attr)
{
  ea_free_later(old_attr);

  if (!proto_attr)
  {
    PST_LOCKED(tp)
    {
      int p_id = ea_get_int(old_attr, &ea_proto_id, 0);
      hmap_clear(&tp->proto_id_map, p_id);
      tp->states[p_id] = NULL;
    }
  }
}

void
proto_journal_item_cleanup(struct lfjour * journal UNUSED, struct lfjour_item *i)
{
  /* Called after a journal update was has been read. */
  struct proto_pending_update *pupdate = SKIP_BACK(struct proto_pending_update, li, i);
  proto_journal_item_cleanup_(pupdate->proto_attr, pupdate->old_proto_attr);
}

void
proto_announce_state_locked(struct proto_state_table_private* ts, struct proto *p, ea_list *attr)
{
  /*
    Should be called each time one (or more) variables tracked in proto eattrs changes.
    Changes proto eattrs and activates journal.
  */
  ea_set_attr(&attr, EA_LITERAL_STORE_ADATA(&ea_last_modified, 0, &p->last_state_change, sizeof(btime)));

  attr = ea_lookup(attr, 0, EALS_CUSTOM);

  ASSERT_DIE(p->id < ts->length_states);
  ea_list *old_attr = ts->states[p->id];

  if (attr == old_attr)
  {
    /* Nothing has changed */
    ea_free_later(attr);
    return;
  }

  ts->states[p->id] = attr;

  if (p->ea_state && p->ea_state->stored)
    ea_free_later(p->ea_state);
  p->ea_state = attr ? ea_ref(attr) : NULL;

  struct proto_pending_update *pupdate = SKIP_BACK(struct proto_pending_update, li, lfjour_push_prepare(&proto_state_table_pub.journal));

  if (!pupdate)
  {
    proto_journal_item_cleanup_(attr, old_attr);
    return;
  }

  *pupdate = (struct proto_pending_update) {
    .li = pupdate->li,	/* Keep the item's internal state */
    .proto_attr = attr,
    .old_proto_attr = old_attr,
    .protocol = p
  };

  lfjour_push_commit(&proto_state_table_pub.journal);
}

void
proto_announce_state(struct proto *p, ea_list *attr)
{
  PST_LOCKED(ts)
    proto_announce_state_locked(ts, p, attr);
}

struct proto_announce_state_deferred {
  struct deferred_call dc;
  struct proto *p;
};

static void proto_announce_state_deferred(struct deferred_call *dc)
{
  SKIP_BACK_DECLARE(struct proto_announce_state_deferred, pasd, dc, dc);
  proto_announce_state(pasd->p, pasd->p->ea_state);
}

void
proto_announce_state_later(struct proto *p, ea_list *attr)
{
  ea_free_later(p->ea_state);
  p->ea_state = ea_lookup(attr, 0, EALS_CUSTOM);

  struct proto_announce_state_deferred pasd = {
    .dc.hook = proto_announce_state_deferred,
    .p = p,
  };

  defer_call(&pasd.dc, sizeof pasd);
}

ea_list *
channel_get_state(int id)
{
  PST_LOCKED(ts)
  {
    ASSERT_DIE((u32) id < ts->length_channels);
    if (ts->channels[id])
      return ea_ref_tmp(ts->channels[id]);
  }
  return NULL;
}

ea_list *
proto_get_state(int id)
{
  ea_list *eal;
  PST_LOCKED(ts)
  {
    ASSERT_DIE((u32)id < ts->length_states);
    eal = ts->states[id];
  }
  if (eal)
    return ea_ref_tmp(eal);
  return NULL;
}

void
proto_states_subscribe(struct lfjour_recipient *r)
{
  PST_LOCKED(ts)
    lfjour_register(&proto_state_table_pub.journal, r);
}

void
proto_states_unsubscribe(struct lfjour_recipient *r)
{
  PST_LOCKED(ts)
    lfjour_unregister(r);
}

/* State attribute declarations */
struct ea_class ea_name = {
  .name = "proto_name",
  .type = T_STRING,
};

struct ea_class ea_protocol_name = {
  .name = "proto_protocol_name",
  .type = T_STRING,
};

struct ea_class ea_protocol_type = {
  .name = "proto_protocol_type",
  .type = T_PTR,
};

struct ea_class ea_main_table_id = {
  .name = "proto_main_table_id",
  .type = T_INT,
};

struct ea_class ea_state = {
  .name = "proto_state",
  .type = T_ENUM_STATE,
};

struct ea_class ea_last_modified = {
  .name = "proto_last_modified",
  .type = T_BTIME,
};

struct ea_class ea_info = {
  .name = "proto_info",
  .type = T_STRING,
};

struct ea_class ea_proto_id = {
  .name = "proto_proto_id",
  .type = T_INT,
};

struct ea_class ea_proto_channel_list = {
  .name = "ea_proto_channel_list",
  .type = T_CLIST,
};

struct ea_class ea_channel_id = {
  .name = "proto_channel_id",
  .type = T_INT,
};

struct ea_class ea_in_keep = {
  .name = "channel_in_keep",
  .type = T_INT,
};


struct ea_class ea_rtable = {
  .name = "rtable",
  .type = T_PTR,
};
