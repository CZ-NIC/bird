/*
 *	BIRD -- Route Export Mechanisms
 *
 *	(c) 2024       Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"

struct rt_export_feed rt_feed_index_out_of_range;

#define rtex_trace(_req, _cat, msg, args...) do { \
  if ((_req)->trace_routes & _cat) \
    log(L_TRACE "%s: " msg, (_req)->name, ##args); \
} while (0)

static inline enum rt_export_state
rt_export_change_state(struct rt_export_request *r, u32 expected_mask, enum rt_export_state state)
{
  r->last_state_change = current_time();
  enum rt_export_state old = atomic_exchange_explicit(&r->export_state, state, memory_order_acq_rel);
  if (!((1 << old) & expected_mask))
    bug("Unexpected export state change from %s to %s, expected mask %02x",
      rt_export_state_name(old),
      rt_export_state_name(state),
      expected_mask
      );

  rtex_trace(r, D_STATES, "Export state changed from %s to %s",
      rt_export_state_name(old), rt_export_state_name(state));

  return old;
}

const struct rt_export_union *
rt_export_get(struct rt_export_request *r)
{
  ASSERT_DIE(!r->cur);

#define EXPORT_FOUND(_kind) do { \
  struct rt_export_union *reu = tmp_alloc(sizeof *reu); \
  *reu = (struct rt_export_union) { \
    .kind = _kind, \
    .req = r, \
    .update = update, \
    .feed = feed, \
  }; \
  return (r->cur = reu); \
} while (0)

#define NOT_THIS_UPDATE	\
  lfjour_release(&r->r); \
  continue;

  while (1)
  {
    enum rt_export_state es = rt_export_get_state(r);
    switch (es)
    {
      case TES_DOWN:
	rtex_trace(r, (D_ROUTES|D_STATES), "Export is down");
	return NULL;

      case TES_STOP:
	rtex_trace(r, (D_ROUTES|D_STATES), "Received stop event");
	struct rt_export_union *reu = tmp_alloc(sizeof *reu);
	*reu = (struct rt_export_union) {
	  .kind = RT_EXPORT_STOP,
	  .req = r,
	};
	return (r->cur = reu);

      case TES_PARTIAL:
      case TES_FEEDING:
      case TES_READY:
	break;

      case TES_MAX:
	bug("invalid export state");
    }

    /* Process sequence number reset event */
    if (lfjour_reset_seqno(&r->r))
      bmap_reset(&r->seq_map, 4);

    /* Get a new update */
    SKIP_BACK_DECLARE(struct rt_export_item, update, li, lfjour_get(&r->r));
    SKIP_BACK_DECLARE(struct rt_exporter, e, journal, lfjour_of_recipient(&r->r));
    struct rt_export_feed *feed = NULL;

    /* No update, try feed */
    if (!update)
    {
      if (es == TES_READY)
      {
	/* Fed up of feeding */
	rtex_trace(r, D_ROUTES, "Export drained");
	return NULL;
      }
      else if (feed = rt_export_next_feed(&r->feeder))
      {
	/* Feeding more */
	bmap_set(&r->feed_map, feed->ni->index);
	rtex_trace(r, D_ROUTES, "Feeding %N", feed->ni->addr);

	EXPORT_FOUND(RT_EXPORT_FEED);
      }
      else if (rt_export_get_state(r) == TES_DOWN)
      {
	/* Torn down inbetween */
	rtex_trace(r, D_STATES, "Export ended itself");
	return NULL;
      }
      else
      {
	/* No more food */
	rt_export_change_state(r, BIT32_ALL(TES_FEEDING, TES_PARTIAL), TES_READY);
	rtex_trace(r, D_STATES, "Fed up");
	CALL(r->fed, r);
	return NULL;
      }
    }

    /* There actually is an update */
    if (bmap_test(&r->seq_map, update->seq))
    {
      /* But this update has been already processed, let's try another one */
      rtex_trace(r, D_ROUTES, "Skipping an already processed update %lu", update->seq);
      NOT_THIS_UPDATE;
    }

    /* Is this update allowed by prefilter? */
    const net_addr *n = (update->new ?: update->old)->net;
    struct netindex *ni = NET_TO_INDEX(n);

    if (!rt_prefilter_net(&r->feeder.prefilter, n))
    {
      rtex_trace(r, D_ROUTES, "Not exporting %N due to prefilter", n);
      NOT_THIS_UPDATE;
    }

    if ((es != TES_READY) && rt_net_is_feeding(r, n))
    {
      /* But this net shall get a feed first! */
      rtex_trace(r, D_ROUTES, "Expediting %N feed due to pending update %lu", n, update->seq);
      if (r->feeder.domain.rtable)
      {
	LOCK_DOMAIN(rtable, r->feeder.domain);
	feed = e->feed_net(e, NULL, ni->index, NULL, NULL, update);
	UNLOCK_DOMAIN(rtable, r->feeder.domain);
      }
      else
      {
	RCU_ANCHOR(u);
	feed = e->feed_net(e, u, ni->index, NULL, NULL, update);
      }

      bmap_set(&r->feed_map, ni->index);
      ASSERT_DIE(feed && (feed != &rt_feed_index_out_of_range));

      EXPORT_FOUND(RT_EXPORT_FEED);
    }

    /* OK, now this actually is an update, thank you for your patience */
    rtex_trace(r, D_ROUTES, "Updating %N, seq %lu", n, update->seq);

    EXPORT_FOUND(RT_EXPORT_UPDATE);
  }

#undef NOT_THIS_UPDATE
#undef EXPORT_FOUND
}

void
rt_export_release(const struct rt_export_union *u)
{
  /* May be already released */
  if (!u->req)
    return;

  struct rt_export_request *r = u->req;

  /* Must be crosslinked */
  ASSERT_DIE(r->cur == u);
  r->cur = NULL;

  switch (u->kind)
  {
    case RT_EXPORT_FEED:
      for (uint i = 0; i < u->feed->count_exports; i++)
	bmap_set(&r->seq_map, u->feed->exports[i]);

      if (!u->update)
	break;

      /* fall through */

    case RT_EXPORT_UPDATE:
      rtex_trace(r, D_ROUTES, "Export %lu released", u->update->seq);
      lfjour_release(&r->r);

      break;

    case RT_EXPORT_STOP:
      /* Checking that we have indeed stopped the exporter */
      ASSERT_DIE(rt_export_get_state(r) == TES_DOWN);
      rtex_trace(r, D_ROUTES, "Export stopped");
      break;

    default:
      bug("strange export kind");
  }
}

void
rt_export_processed(struct rt_export_request *r, u64 seq)
{
  rtex_trace(r, D_ROUTES, "Marking export %lu as processed", seq);

  /* Check sequence number reset event */
  if (lfjour_reset_seqno(&r->r))
    bmap_reset(&r->seq_map, 4);

  ASSERT_DIE(!bmap_test(&r->seq_map, seq));
  bmap_set(&r->seq_map, seq);
}

struct rt_export_feed *
rt_alloc_feed(uint routes, uint exports)
{
  struct rt_export_feed *feed;
  uint size = sizeof *feed
    + routes * sizeof *feed->block + _Alignof(typeof(*feed->block))
    + exports * sizeof *feed->exports + _Alignof(typeof(*feed->exports));

  feed = tmp_alloc(size);

  feed->count_routes = routes;
  feed->count_exports = exports;
  BIRD_SET_ALIGNED_POINTER(feed->block, feed->data);
  BIRD_SET_ALIGNED_POINTER(feed->exports, &feed->block[routes]);

  /* Consistency check */
  ASSERT_DIE(((void *) &feed->exports[exports]) <= ((void *) feed) + size);

  return feed;
}

static struct rt_export_feed *
rt_export_get_next_feed(struct rt_export_feeder *f, struct rcu_unwinder *u)
{
  for (uint retry = 0; retry < (u ? 1024 : ~0U); retry++)
  {
    ASSERT_DIE(u || DOMAIN_IS_LOCKED(rtable, f->domain));

    struct rt_exporter *e = atomic_load_explicit(&f->exporter, memory_order_acquire);
    if (!e)
    {
      rtex_trace(f, (D_ROUTES|D_STATES), "Exporter kicked us away");
      return NULL;
    }

    struct rt_export_feed *feed = e->feed_net(e, u, f->feed_index,
	rt_net_is_feeding_feeder, f, NULL);
    if (feed == &rt_feed_index_out_of_range)
    {
      rtex_trace(f, D_ROUTES, "Nothing more to feed", f->feed_index);
      f->feed_index = ~0;
      return NULL;
    }

#define NOT_THIS_FEED(...) {		\
  rtex_trace(f, D_ROUTES, __VA_ARGS__);	\
  f->feed_index++;			\
  continue;				\
}

    if (!feed)
      NOT_THIS_FEED("Nothing found for index %u", f->feed_index);

    f->feed_index++;
    return feed;
  }

  RCU_RETRY_FAST(u);
}

struct rt_export_feed *
rt_export_next_feed(struct rt_export_feeder *f)
{
  ASSERT_DIE(f);

  struct rt_export_feed *feed = NULL;
  if (f->domain.rtable)
  {
    LOCK_DOMAIN(rtable, f->domain);
    feed = rt_export_get_next_feed(f, NULL);
    UNLOCK_DOMAIN(rtable, f->domain);
  }
  else
  {
    RCU_ANCHOR(u);
    feed = rt_export_get_next_feed(f, u);
  }

  if (feed)
    return feed;

  /* Feeding done */
  while (f->feeding)
  {
    struct rt_feeding_request *rfr = f->feeding;
    f->feeding = rfr->next;
    CALL(rfr->done, rfr);
  }

  f->feed_index = 0;

  if (f->feed_pending)
  {
    rtex_trace(f, D_STATES, "Feeding done, refeed request pending");
    f->feeding = f->feed_pending;
    f->feed_pending = NULL;
    return rt_export_next_feed(f);
  }
  else
  {
    rtex_trace(f, D_STATES, "Feeding done (%u)", f->feed_index);
    return NULL;
  }
}

static void
rt_feeding_request_default_done(struct rt_feeding_request *rfr)
{
  mb_free(rfr);
}

void
rt_export_refeed_feeder(struct rt_export_feeder *f, struct rt_feeding_request *rfr)
{
  if (!rfr)
    return;

  rfr->next = f->feed_pending;
  f->feed_pending = rfr;
}

void rt_export_refeed_request(struct rt_export_request *rer, struct rt_feeding_request *rfr)
{
  if (!rfr)
  {
    rfr = mb_allocz(rer->pool, sizeof *rfr);
    rfr->done = rt_feeding_request_default_done;
  }

  bmap_reset(&rer->feed_map, 4);
  rt_export_refeed_feeder(&rer->feeder, rfr);
  rt_export_change_state(rer, BIT32_ALL(TES_FEEDING, TES_PARTIAL, TES_READY), TES_PARTIAL);
  if (rer->r.event)
    ev_send(rer->r.target, rer->r.event);
}

void
rtex_export_subscribe(struct rt_exporter *e, struct rt_export_request *r)
{
  rt_export_change_state(r, BIT32_ALL(TES_DOWN), TES_FEEDING);

  ASSERT_DIE(r->pool);

  rt_feeder_subscribe(e, &r->feeder);

  lfjour_register(&e->journal, &r->r);

  r->stats = (struct rt_export_stats) {};
  r->last_state_change = current_time();
  bmap_init(&r->seq_map, r->pool, 4);
  bmap_init(&r->feed_map, r->pool, 4);

  rt_export_refeed_request(r, NULL);
}

void
rtex_export_unsubscribe(struct rt_export_request *r)
{
  rt_feeder_unsubscribe(&r->feeder);

  if (r->cur)
    rt_export_release(r->cur);

  switch (rt_export_change_state(r, BIT32_ALL(TES_FEEDING, TES_PARTIAL, TES_READY, TES_STOP), TES_DOWN))
  {
    case TES_FEEDING:
    case TES_PARTIAL:
    case TES_READY:
    case TES_STOP:
      lfjour_unregister(&r->r);
      break;
    default:
      bug("not implemented");
  }

  bmap_free(&r->feed_map);
  bmap_free(&r->seq_map);
}

static void
rt_exporter_cleanup_done(struct lfjour *j, u64 begin_seq UNUSED, u64 end_seq)
{
  SKIP_BACK_DECLARE(struct rt_exporter, e, journal, j);

  /* TODO: log the begin_seq / end_seq values */

  CALL(e->cleanup_done, e, end_seq);
  if (e->stopped && (lfjour_count_recipients(j) == 0))
  {
    settle_cancel(&j->announce_timer);
    ev_postpone(&j->cleanup_event);
    e->stopped(e);
  }
}

void
rt_exporter_init(struct rt_exporter *e, struct settle_config *scf)
{
  rtex_trace(e, D_STATES, "Exporter init");
  e->journal.cleanup_done = rt_exporter_cleanup_done;
  lfjour_init(&e->journal, scf);
  ASSERT_DIE(e->feed_net);
  ASSERT_DIE(e->netindex);
}

struct rt_export_item *
rt_exporter_push(struct rt_exporter *e, const struct rt_export_item *uit)
{
  /* Get the object */
  struct lfjour_item *lit = lfjour_push_prepare(&e->journal);
  if (!lit)
    return NULL;

  SKIP_BACK_DECLARE(struct rt_export_item, it, li, lit);

  /* Copy the data, keeping the header */
  memcpy(&it->data, &uit->data, e->journal.item_size - OFFSETOF(struct rt_export_item, data));

  /* Commit the update */
  rtex_trace(e, D_ROUTES, "Announcing change %lu at %N: %p (%u) -> %p (%u)",
      lit->seq, (uit->new ?: uit->old)->net,
      uit->old, uit->old ? uit->old->id : 0,
      uit->new, uit->new ? uit->new->id : 0);

  lfjour_push_commit(&e->journal);

  /* Return the update pointer */
  return it;
}

#define RTEX_FEEDERS_LOCK(e)  \
  while (atomic_exchange_explicit(&e->feeders_lock, 1, memory_order_acq_rel)) \
    birdloop_yield(); \
  CLEANUP(_rtex_feeders_unlock_) UNUSED struct rt_exporter *_rtex_feeders_locked_ = e;

static inline void _rtex_feeders_unlock_(struct rt_exporter **e)
{
  ASSERT_DIE(atomic_exchange_explicit(&(*e)->feeders_lock, 0, memory_order_acq_rel));
}

void
rt_feeder_subscribe(struct rt_exporter *e, struct rt_export_feeder *f)
{
  f->feed_index = 0;

  atomic_store_explicit(&f->exporter, e, memory_order_relaxed);
  f->domain = e->domain;

  RTEX_FEEDERS_LOCK(e);
  rt_export_feeder_add_tail(&e->feeders, f);

  rtex_trace(f, D_STATES, "Subscribed to exporter %s", e->name);
}

static void
rt_feeder_do_unsubscribe(struct rt_export_feeder *f)
{
  struct rt_exporter *e = atomic_exchange_explicit(&f->exporter, NULL, memory_order_acquire);
  if (e)
  {
    RTEX_FEEDERS_LOCK(e);
    rt_export_feeder_rem_node(&e->feeders, f);

    rtex_trace(f, D_STATES, "Unsubscribed from exporter %s", e->name);
  }
  else
    rtex_trace(f, D_STATES, "Already unsubscribed");
}

void
rt_feeder_unsubscribe(struct rt_export_feeder *f)
{
  if (f->domain.rtable)
  {
    LOCK_DOMAIN(rtable, f->domain);
    rt_feeder_do_unsubscribe(f);
    UNLOCK_DOMAIN(rtable, f->domain);
  }
  else
  {
    RCU_ANCHOR(u);
    rt_feeder_do_unsubscribe(f);
  }
}

void
rt_exporter_shutdown(struct rt_exporter *e, void (*stopped)(struct rt_exporter *))
{
  rtex_trace(e, D_STATES, "Exporter shutdown");

  /* Last lock check before dropping the domain reference */
  if (e->journal.domain)
    ASSERT_DIE(DG_IS_LOCKED(e->journal.domain));

  e->journal.domain = NULL;

  /* We have to tell every receiver to stop */
  _Bool done = 1;
  WALK_TLIST(lfjour_recipient, r, &e->journal.recipients)
  {
    done = 0;
    rt_export_change_state(
	SKIP_BACK(struct rt_export_request, r, r),
	BIT32_ALL(TES_FEEDING, TES_PARTIAL, TES_READY, TES_STOP),
	TES_STOP);
  }

  /* We can drop feeders synchronously */
  {
    RTEX_FEEDERS_LOCK(e);
    WALK_TLIST_DELSAFE(rt_export_feeder, f, &e->feeders)
    {
      ASSERT_DIE(atomic_exchange_explicit(&f->exporter, NULL, memory_order_acq_rel) == e);
      rt_export_feeder_rem_node(&e->feeders, f);
    }
  }

  /* Wait for feeders to finish */
  synchronize_rcu();

  /* The rest is done via the cleanup routine */
  lfjour_do_cleanup_now(&e->journal);

  if (done)
  {
    ev_postpone(&e->journal.cleanup_event);
    settle_cancel(&e->journal.announce_timer);
    CALL(stopped, e);
  }
  else
//  e->stopped = stopped;
    bug("not implemented yet");
}
