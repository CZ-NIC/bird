/*
 *  BIRD Internet Routing Daemon -- Route aggregation
 *
 *  (c) 2023
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
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/resource.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/string.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/data.h"
#include "lib/hash.h"
#include "lib/string.h"
#include "lib/alloca.h"
#include "lib/flowspec.h"
#include <stdlib.h>

/* Context of &f_val comparison. */
struct cmp_ctx {
  const struct channel *c;
  const struct network *net;
  const int val_count;
  u32 failed:1;
};

static linpool *rte_update_pool;

/*
 * Set static attribute in @rta from static attribute in @old according to @sa.
 */
static void
rta_set_static_attr(struct rta *rta, const struct rta *old, struct f_static_attr sa)
{
  switch (sa.sa_code)
  {
    case SA_FROM:
      rta->from = old->from;
      break;

    case SA_GW:
      rta->dest = RTD_UNICAST;
      rta->nh.gw = old->nh.gw;
      rta->nh.iface = old->nh.iface;
      rta->nh.next = NULL;
      rta->hostentry = NULL;
      rta->nh.labels = 0;
      break;

    case SA_SCOPE:
      rta->scope = old->scope;
      break;

    case SA_DEST:
      rta->dest = old->dest;
      rta->nh.gw = IPA_NONE;
      rta->nh.iface = NULL;
      rta->nh.next = NULL;
      rta->hostentry = NULL;
      rta->nh.labels = 0;
      break;

    case SA_IFNAME:
      rta->dest = RTD_UNICAST;
      rta->nh.gw = IPA_NONE;
      rta->nh.iface = old->nh.iface;
      rta->nh.next = NULL;
      rta->hostentry = NULL;
      rta->nh.labels = 0;
      break;

    case SA_GW_MPLS:
      rta->nh.labels = old->nh.labels;
      memcpy(&rta->nh.label, &old->nh.label, sizeof(u32) * old->nh.labels);
      break;

    case SA_WEIGHT:
      rta->nh.weight = old->nh.weight;
      break;

    case SA_PREF:
      rta->pref = old->pref;
      break;

    default:
      bug("Invalid static attribute access (%u/%u)", sa.f_type, sa.sa_code);
  }
}

static int
get_dynamic_attr_count(const struct aggr_item_linearized *ail)
{
  int ea_count = 0;

  for (int i = 0; i < ail->count; i++)
    if (ail->items[i].type == AGGR_ITEM_DYNAMIC_ATTR)
      ea_count++;

  return ea_count;
}

/*
 * Copy static and dynamic attributes from @old to @new according to
 * aggregation list @ail. Because route may not have any extended
 * attributes, return real number of attributes that were copied.
 */
static int
prepare_rta(struct rta *new, const struct rta *old, const struct aggr_item_linearized *ail)
{
  int pos = 0;

  for (int i = 0; i < ail->count; i++)
  {
    if (ail->items[i].type == AGGR_ITEM_DYNAMIC_ATTR)
    {
      u32 ea_code = ail->items[i].da.ea_code;
      const struct eattr *e = ea_find(old->eattrs, ea_code);

      if (e)
        new->eattrs->attrs[pos++] = *e;
    }
    else if (ail->items[i].type == AGGR_ITEM_STATIC_ATTR)
      rta_set_static_attr(new, old, ail->items[i].sa);
  }

  return pos;
}

/*
 * Find route with lowest ID in a sequence of rte_val_list entries
 * within range [start, start + length).
 * @start: first element in a sequence of equivalent routes
 */
static const struct rte *
find_rte_lowest_id(const struct rte_val_list **start, int length)
{
  const struct rte *rte = start[0]->rte;
  u32 id = rte->src->global_id;

  for (int i = 1; i < length; i++)
  {
    u32 current = start[i]->rte->src->global_id;

    if (current < id)
    {
      id = current;
      rte = start[i]->rte;
    }
  }

  log("Lowest ID: %d", id);
  return rte;
}

static int
compare_f_val(const struct f_val *v1, const struct f_val *v2, struct cmp_ctx *ctx)
{
  int result = val_compare(v1, v2);

  if (result != F_CMP_ERROR)
    return result;

  ctx->failed = 1;

  struct buffer buf;
  LOG_BUFFER_INIT(buf);

  buffer_puts(&buf, "v1 = ");
  val_format(v1, &buf);
  buffer_puts(&buf, ", v2 = ");
  val_format(v2, &buf);
  log(L_WARN "%s.%s: Error comparing values while aggregating routes to %N: %s",
      ctx->c->proto->name, ctx->c->name, ctx->net->n.addr, buf.start);

  bug("Sorting routes according to aggregation list: F_CMP_ERROR");
}

/*
 * Compare list of &f_val entries.
 * @count: number of &f_val entries
 */
static int
compare_val_list(const struct f_val *v1, const struct f_val *v2, struct cmp_ctx *ctx)
{
  for (int i = 0; i < ctx->val_count; i++)
  {
    int res = compare_f_val(&v1[i], &v2[i], ctx);
    if (res != 0)
      return res;
  }

  return 0;
}

/*
 * Comparator function for sorting array of pointers to &rte_val_list structures.
 * Compare lists of &f_val associated with routes.
 * If all values are equal, compare route's global IDs.
 * @count: pointer to number of f_val entries
 */
static int
compare_val_list_id(const void *fst, const void *snd, void *context)
{
  struct cmp_ctx *ctx = (struct cmp_ctx *)context;

  for (int i = 0; i < ctx->val_count; i++)
  {
    /*
     * This function receives two void pointers.
     * Since we are sorting array of pointers, we have to cast this void
     * pointer to struct rte_val_list** (pointer to first array element,
     * which is a pointer). Dereference it once to access this element,
     * which is struct rte_val_list*. Finally access f_val at position i
     * and take its address, thus getting struct f_val*.
     */
    const struct f_val *v1 = &(*(struct rte_val_list **)fst)->values[i];
    const struct f_val *v2 = &(*(struct rte_val_list **)snd)->values[i];
    int result = compare_f_val(v1, v2, ctx);

    if (result != 0)
      return result;
  }

  u32 id1 = (*(struct rte_val_list **)fst)->rte->src->global_id;
  u32 id2 = (*(struct rte_val_list **)snd)->rte->src->global_id;
  return id1 < id2 ? -1 : 1;
}

/*
 * Sort array of pointers to &rte_val_list entries.
 * @rte_val: first element in array of pointers to &rte_val_list
 * @rte_count: number of &rte_val_list entries
 * @val_count: number of &f_val entries in each &rte_val_list entry
 */
static void
sort_rte_val_list(const struct rte_val_list **rte_val, int rte_count, struct cmp_ctx *ctx)
{
  log("======== Sorting routes... ========");
  qsort_r(rte_val, rte_count, sizeof(struct rte_val_list *), compare_val_list_id, (void *)ctx);

  for (int i = 0; i < rte_count; i++)
    log("route ID: %d", rte_val[i]->rte->src->global_id);
}

/*
 * Create and export new merged route.
 * @old: first route in a sequence of equivalent routes that are to be merged
 * @rte_val: first element in a sequence of equivalent rte_val_list entries
 * @length: number of equivalent routes that are to be merged (at least 1)
 * @ail: aggregation list
 */
static void
create_merged_rte(struct channel *c, struct network *net, const struct rte_val_list **rte_val,
                  int length, const struct aggr_item_linearized *ail, int refeed)
{
  const struct rte *old = rte_val[0]->rte;
  const struct rta *rta_old = old->attrs;
  struct rta *rta_new = allocz(rta_size(rta_old));

  int ea_count = get_dynamic_attr_count(ail);
  struct ea_list *eal = allocz(sizeof(struct ea_list) + sizeof(struct eattr) * ea_count);

  rta_new->dest = RTD_UNREACHABLE;
  rta_new->eattrs = eal;
  eal->next = NULL;
  eal->count = prepare_rta(rta_new, rta_old, ail);

  const struct rte *rte_lowest = find_rte_lowest_id(rte_val, length);
  struct rte *new = rte_get_temp(rta_new, rte_lowest->src);
  new->net = net;

  do_rt_notify(c, net, new, NULL, refeed);
  log("=============== CREATE MERGED ROUTE ===============");
  log("New route created: id = %d, protocol: %s", new->src->global_id, new->src->proto->name);
  log("===================================================");

  struct rte_block *rb = allocz(sizeof(struct rte_block) + sizeof(struct rte *) * length);
  rb->ad.length = sizeof(struct rte_block) + sizeof(struct rte *) * length - sizeof(struct adata);

  for (int i = 0; i < length; i++)
    rb->routes[i] = (struct rte *)rte_val[i]->rte;

  struct f_val val = {
    .type = T_ROUTES_BLOCK,
    .val.ad = &rb->ad,
  };

  f_run_val(ail->merge_filter, &new, rte_update_pool, &val, 0);
}

/*
 * Iterate through &rte_val_list entries and identify all sequences of
 * equivalent routes.
 * @rte_count: total number of routes being processed
 * @val_count: number of &f_val entries with each route
 * @ail: aggregation list
 */
static void
process_rte_list(struct channel *c, struct network *net, const struct rte_val_list **rte_val,
                 int rte_count, int val_count, const struct aggr_item_linearized *ail, int refeed)
{
  if (rte_count == 1)
  {
    create_merged_rte(c, net, rte_val, 1, ail, refeed);
    return;
  }

  struct cmp_ctx ctx = {
    .c = c,
    .net = net,
    .val_count = val_count,
    .failed = 0,
  };

  /*
   * &start and &current are initially indices to first and second of
   * &rte_val_list entries. If these entries contain equivalent routes,
   * &current is incremented until non-equivalent route is found.
   * [start, current) then define a range of routes that are to be merged.
   * When non-equivalent route is found, &start is updated and the process
   * continues until all entries are processed.
   */
  int start = 0;
  int current = 1;
  log("RTE count: %d", rte_count);
  log("VAL count: %d", val_count);

  while (start < rte_count && current < rte_count)
  {
    int res = compare_val_list(&rte_val[start]->values[0], &rte_val[current]->values[0], &ctx);

    /* At least two equivalent routes were found, try to find more. */
    if (res == 0)
    {
      int merged = 1;

      while (current < rte_count && res == 0)
      {
        log("Routes %d and %d are equal", rte_val[start]->rte->src->global_id, rte_val[current]->rte->src->global_id);
        current++;
        merged++;

        if (current < rte_count)
          res = compare_val_list(&rte_val[start]->values[0], &rte_val[current]->values[0], &ctx);
      }

      log("Creating merged route from %d routes", merged);
      create_merged_rte(c, net, &rte_val[start], merged, ail, refeed);
      start = current;
      current++;
    }
    else
    {
      log("Route %d and %d are NOT equal", rte_val[start]->rte->src->global_id, rte_val[current]->rte->src->global_id);
      log("Creating standalone route from route %d", rte_val[start]->rte->src->global_id);
      create_merged_rte(c, net, &rte_val[start], 1, ail, refeed);
      start = current;
      current++;
    }
  }

  if (start < rte_count)
  {
    log("Creating standalone route from route %d", rte_val[start]->rte->src->global_id);
    create_merged_rte(c, net, &rte_val[start], 1, ail, refeed);
  }
}

static int
get_rte_count(const struct rte *rte)
{
  int count = 0;
  for (; rte; rte = rte->next)
    count++;
  return count;
}

static void
log_attributes(const struct f_val *val, int count)
{
    struct buffer buf;
    LOG_BUFFER_INIT(buf);

    for (int i = 0; i < count; i++)
    {
      val_format(&val[i], &buf);
      log("%s", buf.start);
    }
}

/*
 * Evaluate static attribute of @rt1 according to @sa
 * and store result in @pos.
 */
static void
eval_static_attr(const struct rte *rt1, struct f_static_attr sa, struct f_val *pos)
{
  const struct rta *rta = rt1->attrs;

#define RESULT(_type, value, result)    \
  do {                                  \
    pos->type = _type;                  \
    pos->val.value = result;            \
  } while (0)

  switch (sa.sa_code)
  {
    case SA_FROM:       RESULT(sa.f_type, ip, rta->from); break;
    case SA_GW:	        RESULT(sa.f_type, ip, rta->nh.gw); break;
    case SA_PROTO:	    RESULT(sa.f_type, s, rt1->src->proto->name); break;
    case SA_SOURCE:	    RESULT(sa.f_type, i, rta->source); break;
    case SA_SCOPE:	    RESULT(sa.f_type, i, rta->scope); break;
    case SA_DEST:	    RESULT(sa.f_type, i, rta->dest); break;
    case SA_IFNAME:	    RESULT(sa.f_type, s, rta->nh.iface ? rta->nh.iface->name : ""); break;
    case SA_IFINDEX:	RESULT(sa.f_type, i, rta->nh.iface ? rta->nh.iface->index : 0); break;
    case SA_WEIGHT:	    RESULT(sa.f_type, i, rta->nh.weight + 1); break;
    case SA_PREF:	    RESULT(sa.f_type, i, rta->pref); break;
    case SA_GW_MPLS:    RESULT(sa.f_type, i, rta->nh.labels ? rta->nh.label[0] : MPLS_NULL); break;
    default:
      bug("Invalid static attribute access (%u/%u)", sa.f_type, sa.sa_code);
  }

#undef RESULT
}

/*
 * Evaluate dynamic attribute of @rt1 according to @da
 * and store result in @pos.
 */
static void
eval_dynamic_attr(const struct rte *rt1, struct f_dynamic_attr da, struct f_val *pos)
{
  const struct rta *rta = rt1->attrs;
  const struct eattr *e = ea_find(rta->eattrs, da.ea_code);

#define RESULT(_type, value, result)    \
  do {                                  \
    pos->type = _type;                  \
    pos->val.value = result;            \
  } while (0)

#define RESULT_VOID         \
  do {                      \
    pos->type = T_VOID;     \
  } while (0)

  if (!e)
  {
    /* A special case: undefined as_path looks like empty as_path */
    if (da.type == EAF_TYPE_AS_PATH)
    {
      RESULT(T_PATH, ad, &null_adata);
      return;
    }

    /* The same special case for int_set */
    if (da.type == EAF_TYPE_INT_SET)
    {
      RESULT(T_CLIST, ad, &null_adata);
      return;
    }

    /* The same special case for ec_set */
    if (da.type == EAF_TYPE_EC_SET)
    {
      RESULT(T_ECLIST, ad, &null_adata);
      return;
    }

    /* The same special case for lc_set */
    if (da.type == EAF_TYPE_LC_SET)
    {
      RESULT(T_LCLIST, ad, &null_adata);
      return;
    }

    /* Undefined value */
    RESULT_VOID;
    return;
  }

  switch (e->type & EAF_TYPE_MASK)
  {
    case EAF_TYPE_INT:
      RESULT(da.f_type, i, e->u.data);
      break;
    case EAF_TYPE_ROUTER_ID:
      RESULT(T_QUAD, i, e->u.data);
      break;
    case EAF_TYPE_OPAQUE:
      RESULT(T_ENUM_EMPTY, i, 0);
      break;
    case EAF_TYPE_IP_ADDRESS:
      RESULT(T_IP, ip, *((ip_addr *) e->u.ptr->data));
      break;
    case EAF_TYPE_AS_PATH:
      RESULT(T_PATH, ad, e->u.ptr);
      break;
    case EAF_TYPE_BITFIELD:
      RESULT(T_BOOL, i, !!(e->u.data & (1u << da.bit)));
      break;
    case EAF_TYPE_INT_SET:
      RESULT(T_CLIST, ad, e->u.ptr);
      break;
    case EAF_TYPE_EC_SET:
      RESULT(T_ECLIST, ad, e->u.ptr);
      break;
    case EAF_TYPE_LC_SET:
      RESULT(T_LCLIST, ad, e->u.ptr);
      break;
    default:
      bug("Unknown dynamic attribute type");
  }

#undef RESULT
#undef RESULT_VOID
}

void
rt_notify_aggregated(struct channel *c, struct network *net, struct rte *new_changed, struct rte *old_changed,
		             struct rte *new_best, struct rte *old_best, int refeed)
{
  const struct aggr_item_linearized *ail = c->ai_aggr;
  const int attr_count = ail->count;

  if (net->routes == NULL)
    return;

  struct rte *best0 = net->routes;
  const int rte_count = get_rte_count(best0);

  if (rte_count == 0)
    return;

  log("---- RT NOTIFY AGGREGATED ----");
  log("Routes count: %d", rte_count);
  log("Aggregation list attributes count: %d", attr_count);
  log("aggr_item_linearized: %p", ail);

  struct rte **rte_temp = allocz(sizeof(struct rte *) * rte_count);
  struct rte **rte_free_temp = allocz(sizeof(struct rte *) * rte_count);

  int rte_temp_count = 0;
  int rte_free_count = 0;

  /* Run filter for all routes before aggregation. */
  for (struct rte *rt0 = best0; rt0; rt0 = rt0->next)
  {
    struct rte *rte_free = NULL;
    struct rte *filtered = export_filter(c, rt0, &rte_free, 0);

    if (filtered)
      rte_temp[rte_temp_count++] = filtered;

    if (rte_free)
      rte_free_temp[rte_free_count++] = rte_free;
  }

  const struct rte_val_list **rte_val_list_ptrs = allocz(sizeof(struct rte_val_list *) * rte_count);
  int rte_val_list_pos = 0;

  for (int rte_idx = 0; rte_idx < rte_temp_count; rte_idx++)
  {
    struct rte *rt0 = rte_temp[rte_idx];
    struct rte_val_list *rte_val = allocz(sizeof(struct rte_val_list) + sizeof(struct f_val) * attr_count);

    rte_val->rte = rt0;
    rte_val_list_ptrs[rte_val_list_pos++] = rte_val;

    for (int val_idx = 0; val_idx < attr_count; val_idx++)
    {
      int type = ail->items[val_idx].type;

      /* Evaluate route attributes. */
      switch (type)
      {
        case AGGR_ITEM_TERM: {
          const struct f_line *line = ail->items[val_idx].line;
          struct rte *rt1 = rt0;
          enum filter_return fret = f_aggr_eval_line(line, &rt1, rte_update_pool, &rte_val->values[val_idx]);

          if (rt1 != rt0)
          {
            rte_free(rt1);
            log(L_WARN "rt1 != rt0");
          }

          if (fret > F_RETURN)
            log(L_WARN "%s.%s: Wrong number of items left on stack after evaluation of aggregation list", rt1->src->proto->name, rt1->sender);

          break;
        }

        case AGGR_ITEM_STATIC_ATTR: {
          struct f_val *pos = &rte_val->values[val_idx];
          eval_static_attr(rt0, ail->items[val_idx].sa, pos);
          break;
        }

        case AGGR_ITEM_DYNAMIC_ATTR: {
          struct f_val *pos = &rte_val->values[val_idx];
          eval_dynamic_attr(rt0, ail->items[val_idx].da, pos);
          break;
        }

        default:
          break;
      }
    }

    log_attributes(&rte_val->values[0], attr_count);
  }

  struct cmp_ctx ctx = {
    .c = c,
    .net = net,
    .val_count = attr_count,
    .failed = 0,
  };

  sort_rte_val_list(rte_val_list_ptrs, rte_temp_count, &ctx);

  if (ctx.failed)
    log(L_WARN "%s.%s: Could not aggregate routes to %N due to previous errors", c->proto->name, c->name, net->n.addr);
  else
    process_rte_list(c, net, rte_val_list_ptrs, rte_temp_count, attr_count, ail, refeed);

  for (int i = 0; i < rte_free_count; i++)
    rte_free(rte_free_temp[i]);
}

