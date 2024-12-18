/*
 *	BIRD Internet Routing Daemon -- Route aggregation
 *
 *	(c) 2023--2023 Igor Putovny <igor.putovny@nic.cz>
 *	(c) 2023       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Route aggregation
 *
 * This is an implementation of route aggregation functionality.
 * It enables user to specify a set of route attributes in the configuarion file
 * and then, for a given destination (net), aggregate routes with the same
 * values of these attributes into a single multi-path route.
 *
 * Structure &channel contains pointer to aggregation list which is represented
 * by &aggr_list_linearized. In rt_notify_aggregated(), attributes from this
 * list are evaluated for every route of a given net and results are stored
 * in &rte_val_list which contains pointer to this route and array of &f_val.
 * Array of pointers to &rte_val_list entries is sorted using
 * sort_rte_val_list(). For comparison of &f_val structures, val_compare()
 * is used. Comparator function is written so that sorting is stable. If all
 * attributes have the same values, routes are compared by their global IDs.
 *
 * After sorting, &rte_val_list entries containing equivalent routes will be
 * adjacent to each other. Function process_rte_list() iterates through these
 * entries to identify sequences of equivalent routes. New route will be
 * created for each such sequence, even if only from a single route.
 * Only attributes from the aggreagation list will be set for the new route.
 * New &rta is created and prepare_rta() is used to copy static and dynamic
 * attributes to new &rta from &rta of the original route. New route is created
 * by create_merged_rte() from new &rta and exported to the routing table.
 */

#undef LOCAL_DEBUG

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "nest/bird.h"
#include "nest/iface.h"
#include "filter/filter.h"
#include "aggregator.h"

#include <stdlib.h>

/*
 * Compare list of &f_val entries.
 * @count: number of &f_val entries
 */
static int
same_val_list(const struct f_val *v1, const struct f_val *v2, uint len)
{
  for (uint i = 0; i < len; i++)
    if (!val_same(&v1[i], &v2[i]))
      return 0;

  return 1;
}

/*
 * Create and export new merged route.
 * @old: first route in a sequence of equivalent routes that are to be merged
 * @rte_val: first element in a sequence of equivalent rte_val_list entries
 * @length: number of equivalent routes that are to be merged (at least 1)
 * @ail: aggregation list
 */
static void
aggregator_bucket_update(struct aggregator_proto *p, struct aggregator_bucket *bucket, const net_addr *net)
{
  /* Empty bucket */
  if (!bucket->rte)
  {
    rte_update(p->dst, net, NULL, bucket->last_src);
    rt_unlock_source(bucket->last_src);
    bucket->last_src = NULL;
    return;
  }

  /* Store TMP linpool state */
  struct lp_state *tmp_state = lp_save(tmp_linpool);

  /* Allocate route */
  struct rte new = { .net = net, .src = bucket->rte->rte.src };
  ea_set_attr(&new.attrs, EA_LITERAL_EMBEDDED(&ea_gen_source, 0, RTS_AGGREGATED));

  if (net_type_match(net, NB_DEST))
    ea_set_dest(&new.attrs, 0, RTD_UNREACHABLE);

  /* Seed the attributes from aggregator rule */
  f_eval_rte(p->premerge, &new, p->aggr_on_count, bucket->aggr_data, 0, NULL);

  /*
  log("=============== CREATE MERGED ROUTE ===============");
  log("New route created: id = %d, protocol: %s", new->src->global_id, new->src->proto->name);
  log("===================================================");
  */

  /* merge filter needs one argument called "routes" */
  struct f_val val = {
    .type = T_ROUTES_BLOCK,
    .val.rte_block = {},
  };

  for (struct aggregator_route *rte = bucket->rte; rte; rte = rte->next_rte)
    val.val.rte_block.len++;

  val.val.rte_block.rte = tmp_alloc(sizeof(struct rte *) * val.val.rte_block.len);
  {
    uint i = 0;
    for (struct aggregator_route *rte = bucket->rte; rte; rte = rte->next_rte)
      val.val.rte_block.rte[i++] = &rte->rte;
    ASSERT_DIE(i == val.val.rte_block.len);
  }

  /* Actually run the merge rule */
  enum filter_return fret = f_eval_rte(p->merge_by, &new, 1, &val, 0, NULL);

  /* Finally import the route */
  switch (fret)
  {
    /* Pass the route to the protocol */
    case F_ACCEPT:
      rte_update(p->dst, net, &new, bucket->last_src ?: new.src);
      break;

    /* Something bad happened */
    default:
      ASSERT_DIE(fret == F_ERROR);
      /* fall through */

    /* We actually don't want this route */
    case F_REJECT:
      if (bucket->last_src)
	rte_update(p->dst, net, NULL, bucket->last_src);
      break;
  }

  /* Switch source lock for bucket->last_src */
  if (bucket->last_src != new.src)
  {
    if (new.src)
      rt_lock_source(new.src);
    if (bucket->last_src)
      rt_unlock_source(bucket->last_src);

    bucket->last_src = new.src;
  }

  lp_restore(tmp_linpool, tmp_state);
}

/*
 * Reload all the buckets on reconfiguration if merge filter has changed.
 * TODO: make this splitted
 */
static void
aggregator_reload_buckets(void *data)
{
  struct aggregator_proto *p = data;

  HASH_WALK(p->buckets, next_hash, b)
    if (b->rte)
      aggregator_bucket_update(p, b, b->rte->rte.net);
  HASH_WALK_END;
}

static inline u32 aggr_route_hash(const rte *e)
{
  struct {
    const net_addr *net;  /* the net_addr pointer is stable as long as any route exists for it in the source table */
    struct rte_src *src;
  } obj = {
    .net = e->net,
    .src = e->src,
  };

  return mem_hash(&obj, sizeof obj);
}

#define AGGR_RTE_KEY(n)			(&(n)->rte)
#define AGGR_RTE_NEXT(n)		((n)->next_hash)
#define AGGR_RTE_EQ(a,b)		(((a)->src == (b)->src) && ((a)->net == (b)->net))
#define AGGR_RTE_FN(_n)			aggr_route_hash(_n)
#define AGGR_RTE_ORDER			4 /* Initial */

#define AGGR_RTE_REHASH			aggr_rte_rehash
#define AGGR_RTE_PARAMS			/8, *2, 2, 2, 4, 24

HASH_DEFINE_REHASH_FN(AGGR_RTE, struct aggregator_route);


#define AGGR_BUCK_KEY(n)		(n)
#define AGGR_BUCK_NEXT(n)		((n)->next_hash)
#define AGGR_BUCK_EQ(a,b)		(((a)->hash == (b)->hash) && (same_val_list((a)->aggr_data, (b)->aggr_data, p->aggr_on_count)))
#define AGGR_BUCK_FN(n)			((n)->hash)
#define AGGR_BUCK_ORDER			4 /* Initial */

#define AGGR_BUCK_REHASH		aggr_buck_rehash
#define AGGR_BUCK_PARAMS		/8, *2, 2, 2, 4, 24

HASH_DEFINE_REHASH_FN(AGGR_BUCK, struct aggregator_bucket);


#define AGGR_DATA_MEMSIZE	(sizeof(struct f_val) * p->aggr_on_count)

static void
aggregator_rt_notify(struct proto *P, struct channel *src_ch, const net_addr *net, rte *new, const rte *old)
{
  SKIP_BACK_DECLARE(struct aggregator_proto, p, p, P);
  ASSERT_DIE(src_ch == p->src);
  struct aggregator_bucket *new_bucket = NULL, *old_bucket = NULL;
  struct aggregator_route *old_route = NULL;

  /* Find the objects for the old route */
  if (old)
    old_route = HASH_FIND(p->routes, AGGR_RTE, old);

  if (old_route)
    old_bucket = old_route->bucket;

  /* Find the bucket for the new route */
  if (new)
  {
    /* Routes are identical, do nothing */
    if (old_route && rte_same(&old_route->rte, new))
      return;

    /* Evaluate route attributes. */
    struct aggregator_bucket *tmp_bucket = sl_allocz(p->bucket_slab);
    struct lp_state *tmp_state = lp_save(tmp_linpool);

    struct ea_list *oa = new->attrs;
    enum filter_return fret = f_eval_rte(p->aggr_on, new, 0, NULL, p->aggr_on_count, tmp_bucket->aggr_data);

    if (new->attrs != oa)
      log(L_WARN "Aggregator rule modifies the route");

    /* Check filter return value */
    if (fret > F_RETURN)
    {
      sl_free(tmp_bucket);
      lp_restore(tmp_linpool, tmp_state);

      return;
    }

    /* Compute the hash */
    u64 haux;
    mem_hash_init(&haux);
    for (uint i = 0; i < p->aggr_on_count; i++)
      mem_hash_mix_f_val(&haux, &tmp_bucket->aggr_data[i]);
    tmp_bucket->hash = mem_hash_value(&haux);

    /* Find the existing bucket */
    if (new_bucket = HASH_FIND(p->buckets, AGGR_BUCK, tmp_bucket))
      sl_free(tmp_bucket);
    else
    {
      new_bucket = tmp_bucket;
      HASH_INSERT2(p->buckets, AGGR_BUCK, p->p.pool, new_bucket);
    }

    /* Store the route attributes */
    new->attrs = ea_lookup(new->attrs, 0, EALS_KEY);

    /* Insert the new route into the bucket */
    struct aggregator_route *arte = sl_alloc(p->route_slab);
    *arte = (struct aggregator_route) {
      .bucket = new_bucket,
      .rte = *new,
      .next_rte = new_bucket->rte,
    };
    new_bucket->rte = arte;
    new_bucket->count++;
    HASH_INSERT2(p->routes, AGGR_RTE, p->p.pool, arte);

    lp_restore(tmp_linpool, tmp_state);
  }

  /* Remove the old route from its bucket */
  if (old_bucket)
  {
    for (struct aggregator_route **k = &old_bucket->rte; *k; k = &(*k)->next_rte)
      if (*k == old_route)
      {
	*k = (*k)->next_rte;
	break;
      }

    old_bucket->count--;
    HASH_REMOVE2(p->routes, AGGR_RTE, p->p.pool, old_route);
    ea_free(old_route->rte.attrs);
    sl_free(old_route);
  }

  /* Announce changes */
  if (old_bucket)
    aggregator_bucket_update(p, old_bucket, net);

  if (new_bucket && (new_bucket != old_bucket))
    aggregator_bucket_update(p, new_bucket, net);

  /* Cleanup the old bucket if empty */
  if (old_bucket && (!old_bucket->rte || !old_bucket->count))
  {
    ASSERT_DIE(!old_bucket->rte && !old_bucket->count);
    HASH_REMOVE2(p->buckets, AGGR_BUCK, p->p.pool, old_bucket);
    sl_free(old_bucket);
  }
}

static int
aggregator_preexport(struct channel *C, struct rte *new)
{
  SKIP_BACK_DECLARE(struct aggregator_proto, p, p, C->proto);
  /* Reject our own routes */
  if (new->sender == p->dst->in_req.hook)
    return -1;

  /* Disallow aggregating already aggregated routes */
  if (ea_get_int(new->attrs, &ea_gen_source, 0) == RTS_AGGREGATED)
  {
    log(L_ERR "Multiple aggregations of the same route not supported.");
    return -1;
  }

  return 0;
}

static void
aggregator_postconfig(struct proto_config *CF)
{
  SKIP_BACK_DECLARE(struct aggregator_config, cf, c, CF);

  if (!cf->dst->table)
    cf_error("Source table not specified");

  if (!cf->src->table)
    cf_error("Destination table not specified");

  if (cf->dst->table->addr_type != cf->src->table->addr_type)
    cf_error("Both tables must be of the same type");

  cf->dst->in_filter = cf->src->in_filter;

  cf->src->in_filter = FILTER_REJECT;
  cf->dst->out_filter = FILTER_REJECT;

  cf->dst->debug = cf->src->debug;
}

static struct proto *
aggregator_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  SKIP_BACK_DECLARE(struct aggregator_proto, p, p, P);
  SKIP_BACK_DECLARE(struct aggregator_config, cf, c, CF);

  proto_configure_channel(P, &p->src, cf->src);
  proto_configure_channel(P, &p->dst, cf->dst);

  p->aggr_on_count = cf->aggr_on_count;
  p->aggr_on = cf->aggr_on;
  p->premerge = cf->premerge;
  p->merge_by = cf->merge_by;

  P->rt_notify = aggregator_rt_notify;
  P->preexport = aggregator_preexport;

  return P;
}

static int
aggregator_start(struct proto *P)
{
  SKIP_BACK_DECLARE(struct aggregator_proto, p, p, P);

  p->bucket_slab = sl_new(P->pool, birdloop_event_list(P->loop), sizeof(struct aggregator_bucket) + AGGR_DATA_MEMSIZE);
  HASH_INIT(p->buckets, P->pool, AGGR_BUCK_ORDER);

  p->route_slab = sl_new(P->pool, birdloop_event_list(P->loop), sizeof(struct aggregator_route));
  HASH_INIT(p->routes, P->pool, AGGR_RTE_ORDER);

  p->reload_buckets = (event) {
    .hook = aggregator_reload_buckets,
    .data = p,
  };

  return PS_UP;
}

static int
aggregator_shutdown(struct proto *P)
{
  SKIP_BACK_DECLARE(struct aggregator_proto, p, p, P);

  HASH_WALK_DELSAFE(p->buckets, next_hash, b)
  {
    for (struct aggregator_route *arte; arte = b->rte; )
    {
      b->rte = arte->next_rte;
      b->count--;
      HASH_REMOVE(p->routes, AGGR_RTE, arte);
      ea_free(arte->rte.attrs);
      sl_free(arte);
    }

    if (b->last_src)
      rt_unlock_source(b->last_src);

    ASSERT_DIE(b->count == 0);
    HASH_REMOVE(p->buckets, AGGR_BUCK, b);
    sl_free(b);
  }
  HASH_WALK_END;

  return PS_FLUSH;
}

static int
aggregator_reconfigure(struct proto *P, struct proto_config *CF)
{
  SKIP_BACK_DECLARE(struct aggregator_proto, p, p, P);
  SKIP_BACK_DECLARE(struct aggregator_config, cf, c, CF);

  TRACE(D_EVENTS, "Reconfiguring");

  /* Compare numeric values (shortcut) */
  if (cf->aggr_on_count != p->aggr_on_count)
    return 0;

  /* Compare aggregator rule */
  if (!f_same(cf->aggr_on, p->aggr_on) || !f_same(cf->premerge, p->premerge))
    return 0;

  /* Compare merge filter */
  if (!f_same(cf->merge_by, p->merge_by))
    ev_schedule(&p->reload_buckets);

  p->aggr_on = cf->aggr_on;
  p->premerge = cf->premerge;
  p->merge_by = cf->merge_by;

  return 1;
}

struct protocol proto_aggregator = {
  .name =		"Aggregator",
  .template =		"aggregator%d",
  .preference =		1,
  .channel_mask =	NB_ANY,
  .proto_size =		sizeof(struct aggregator_proto),
  .config_size =	sizeof(struct aggregator_config),
  .startup =		PROTOCOL_STARTUP_CONNECTOR,
  .postconfig =		aggregator_postconfig,
  .init =		aggregator_init,
  .start =		aggregator_start,
  .shutdown =		aggregator_shutdown,
  .reconfigure =	aggregator_reconfigure,
};

void
aggregator_build(void)
{
  proto_build(&proto_aggregator);
}
