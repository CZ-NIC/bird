/*
 *  BIRD Internet Routing Daemon -- Route aggregation
 *
 *  (c) 2023--2025 Igor Putovny <igor.putovny@nic.cz>
 *  (c) 2023--2025 Maria Matejka <mq@ucw.cz>
 *  (c) 2025       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Aggregator protocol
 *
 * The purpose of the aggregator protocol is to aggregate routes based on
 * user-specified set of route attributes. It can be used for aggregating
 * routes for a given destination (net) or for aggregating prefixes.
 *
 * Aggregation of routes for networks means that for each destination, routes
 * with the same values of attributes will be aggregated into a single
 * multi-path route. Aggregation is performed by inserting routes into a hash
 * table based on values of their attributes and generating new routes from
 * the routes in th same bucket. Buckets are represented by @aggregator_bucket,
 * which contains linked list of @aggregator_route.
 *
 * Aggregation of prefixes aggregates a given set of prefixes into another set
 * of prefixes. It offers a reduction in number of prefixes without changing
 * the routing semantics. Aggregator is capable of processing incremental
 * updates.
 */

#undef LOCAL_DEBUG

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "nest/bird.h"
#include "nest/iface.h"
#include "filter/filter.h"
#include "proto/aggregator/aggregator.h"

extern linpool *rte_update_pool;

/*
 * Add @bucket to the list of bucket pointers in @p to position @bucket.id
 */
static void
aggregator_add_bucket(struct aggregator_proto *p, struct aggregator_bucket *bucket)
{
  ASSERT_DIE(p != NULL);
  ASSERT_DIE(p->bucket_list != NULL);
  ASSERT_DIE(bucket != NULL);

  /* Save bucket pointer */
  if (bucket->id < p->bucket_list_size)
  {
    p->bucket_list[bucket->id] = bucket;
    return;
  }

  /* Reallocate if more space is needed */
  const size_t old_size = p->bucket_list_size;

  while (bucket->id >= p->bucket_list_size)
    p->bucket_list_size *= 2;

  ASSERT_DIE(old_size < p->bucket_list_size);

  p->bucket_list = mb_realloc(p->bucket_list, sizeof(p->bucket_list[0]) * p->bucket_list_size);
  memset(&p->bucket_list[old_size], 0, sizeof(p->bucket_list[0]) * (p->bucket_list_size - old_size));

  ASSERT_DIE(bucket->id < p->bucket_list_size);
  ASSERT_DIE(p->bucket_list[bucket->id] == NULL);

  p->bucket_list[bucket->id] = bucket;
}

/*
 * Withdraw all routes that are on the stack
 */
static void
aggregator_withdraw_rte(struct aggregator_proto *p)
{
  if ((p->addr_type == NET_IP4 && p->rte_withdrawal_count > IP4_WITHDRAWAL_MAX_EXPECTED_LIMIT) ||
      (p->addr_type == NET_IP6 && p->rte_withdrawal_count > IP6_WITHDRAWAL_MAX_EXPECTED_LIMIT))
    log(L_WARN "This number of updates was not expected."
               "They will be processed. Please, report this to developers.");

  struct rte_withdrawal_item *node = NULL;

  while (node = p->rte_withdrawal_stack)
  {
    rte_update2(p->dst, &node->addr, NULL, node->bucket->last_src);
    p->rte_withdrawal_stack = node->next;
    p->rte_withdrawal_count--;
  }

  ASSERT_DIE(p->rte_withdrawal_stack == NULL);
  ASSERT_DIE(p->rte_withdrawal_count == 0);

  lp_flush(p->rte_withdrawal_pool);
}

/*
 * Change size of trie node so that @id fits into node's bitmap, allocate
 * new slab configured with this size and initialize root node there.
 */
static void
aggregator_resize_slab(struct aggregator_proto *p, u32 id)
{
  ASSERT_DIE(p->trie_slab != NULL);

  /* Calculate sufficient bitmap size */
  while (id >= (p->bitmap_size * sizeof(p->root->potential_buckets[0]) * 8))
    p->bitmap_size *= 2;

  /* Save bucket with default route */
  struct aggregator_bucket *default_rte_bucket = p->root->original_bucket;

  /* Calculate size of trie node with bigger bitmap */
  const size_t node_size = sizeof(*p->root) + sizeof(p->root->potential_buckets[0]) * p->bitmap_size;

  /* Free old slab and create new */
  rfree(p->trie_slab);
  p->trie_slab = sl_new(p->p.pool, node_size);

  /* Initialize root node in new slab */
  p->root = aggregator_root_init(default_rte_bucket, p->trie_slab);
}

static void
aggregator_aggregate_on_feed_end(struct channel *C)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, C->proto);

  if (C != p->src)
    return;

  ASSERT_DIE(p->aggr_mode == PREFIX_AGGR);
  ASSERT_DIE(p->root != NULL);

  aggregator_aggregate(p);
  p->initial_feed = false;
}

/*
 * Set static attribute in @rta from static attribute in @old according to @sa.
 */
static void
aggregator_rta_set_static_attr(struct rta *rta, const struct rta *old, struct f_static_attr sa)
{
  switch (sa.sa_code)
  {
    case SA_NET:
      break;

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

/*
 * Compare list of &f_val entries.
 * @count: number of &f_val entries
 */
static int
aggregator_same_val_list(const struct f_val *v1, const struct f_val *v2, u32 len)
{
  for (u32 i = 0; i < len; i++)
    if (!val_same(&v1[i], &v2[i]))
      return 0;

  return 1;
}

/*
 * Create and export new merged route
 */
void
aggregator_bucket_update(struct aggregator_proto *p, struct aggregator_bucket *bucket, const struct net_addr *addr)
{
  /* Empty bucket */
  if (!bucket->rte)
  {
    rte_update2(p->dst, addr, NULL, bucket->last_src);
    bucket->last_src = NULL;
    return;
  }

  /* Allocate RTA and EA list */
  struct rta *rta = allocz(rta_size(bucket->rte->attrs));
  rta->dest = RTD_UNREACHABLE;
  rta->source = RTS_AGGREGATED;
  rta->scope = SCOPE_UNIVERSE;

  struct ea_list *eal = allocz(sizeof(*eal) + sizeof(struct eattr) * p->aggr_on_da_count);
  eal->next = NULL;
  eal->count = 0;
  rta->eattrs = eal;

  /* Seed the attributes from aggregator rule */
  for (u32 i = 0; i < p->aggr_on_count; i++)
  {
    if (p->aggr_on[i].type == AGGR_ITEM_DYNAMIC_ATTR)
    {
      u32 ea_code = p->aggr_on[i].da.ea_code;
      const struct eattr *e = ea_find(bucket->rte->attrs->eattrs, ea_code);

      if (e)
        eal->attrs[eal->count++] = *e;
    }
    else if (p->aggr_on[i].type == AGGR_ITEM_STATIC_ATTR)
      aggregator_rta_set_static_attr(rta, bucket->rte->attrs, p->aggr_on[i].sa);
  }

  struct network *net = allocz(sizeof(*net) + sizeof(*addr));
  net_copy(net->n.addr, addr);

  /*
   * Here we need _some_ net to run the filters properly
   * TODO: use a temporary local net instead of a real one to avoid confusion
   */
  struct rte *new_rte = rte_get_temp(rta, p->p.main_source);
  new_rte->net = net;

  if (p->logging)
  {
    log("=============== CREATE MERGED ROUTE ===============");
    log("New route created: id = %d, protocol: %s", new_rte->src->global_id, new_rte->src->proto->name);
    log("===================================================");
  }

  /* merge filter needs one argument called "routes" */
  struct f_val val = {
    .type = T_ROUTES_BLOCK,
    .val.rte = bucket->rte,
  };

  /* Actually run the filter */
  enum filter_return fret = f_eval_rte(p->merge_by, &new_rte, rte_update_pool, 1, &val, 0);

  /* Src must be stored now, rte_update2() may return new */
  struct rte_src *new_src = new_rte ? new_rte->src : NULL;

  /* Finally import the route */
  switch (fret)
  {
    /* Pass the route to the protocol */
    case F_ACCEPT:
      rte_update2(p->dst, net->n.addr, new_rte, bucket->last_src ?: new_rte->src);
      break;

    /* Something bad happened */
    default:
      ASSERT_DIE(fret == F_ERROR);
      /* fall through */

    /* We actually don't want this route */
    case F_REJECT:
      if (bucket->last_src)
        rte_update2(p->dst, net->n.addr, NULL, bucket->last_src);
      break;
  }

  /* Switch source lock for bucket->last_src */
  if (bucket->last_src != new_src)
  {
    if (new_src)
      rt_lock_source(new_src);

    if (bucket->last_src)
      rt_unlock_source(bucket->last_src);

    bucket->last_src = new_src;
  }
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
    {
      aggregator_bucket_update(p, b, b->rte->net->n.addr);
      lp_flush(rte_update_pool);
    }
  HASH_WALK_END;
}


/*
 * Evaluate static attribute of @rt1 according to @sa
 * and store result in @pos.
 */
static void
aggregator_eval_static_attr(const struct rte *rt1, struct f_static_attr sa, struct f_val *pos)
{
  const struct rta *rta = rt1->attrs;

#define RESULT(_type, value, result)    \
  do {                                  \
    pos->type = _type;                  \
    pos->val.value = result;            \
  } while (0)

  switch (sa.sa_code)
  {
    case SA_NET:        RESULT(sa.f_type, net, rt1->net->n.addr);                               break;
    case SA_FROM:       RESULT(sa.f_type, ip, rta->from);                                       break;
    case SA_GW:         RESULT(sa.f_type, ip, rta->nh.gw);                                      break;
    case SA_PROTO:      RESULT(sa.f_type, s, rt1->src->proto->name);                            break;
    case SA_SOURCE:     RESULT(sa.f_type, i, rta->source);                                      break;
    case SA_SCOPE:      RESULT(sa.f_type, i, rta->scope);                                       break;
    case SA_DEST:       RESULT(sa.f_type, i, rta->dest);                                        break;
    case SA_IFNAME:     RESULT(sa.f_type, s, rta->nh.iface ? rta->nh.iface->name : "");         break;
    case SA_IFINDEX:    RESULT(sa.f_type, i, rta->nh.iface ? rta->nh.iface->index : 0);         break;
    case SA_WEIGHT:     RESULT(sa.f_type, i, rta->nh.weight + 1);                               break;
    case SA_PREF:       RESULT(sa.f_type, i, rta->pref);                                        break;
    case SA_GW_MPLS:    RESULT(sa.f_type, i, rta->nh.labels ? rta->nh.label[0] : MPLS_NULL);    break;
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
aggregator_eval_dynamic_attr(const struct rte *rt1, struct f_dynamic_attr da, struct f_val *pos)
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

static inline u32
aggregator_route_hash(const rte *e)
{
  struct {
    net *net;
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
#define AGGR_RTE_FN(_n)			aggregator_route_hash(_n)
#define AGGR_RTE_ORDER			4 /* Initial */

#define AGGR_RTE_REHASH			aggr_rte_rehash
#define AGGR_RTE_PARAMS			/8, *2, 2, 2, 4, 24

HASH_DEFINE_REHASH_FN(AGGR_RTE, struct aggregator_route);


#define AGGR_BUCK_KEY(n)		(n)
#define AGGR_BUCK_NEXT(n)		((n)->next_hash)
#define AGGR_BUCK_EQ(a,b)		(((a)->hash == (b)->hash) && (aggregator_same_val_list((a)->aggr_data, (b)->aggr_data, p->aggr_on_count)))
#define AGGR_BUCK_FN(n)			((n)->hash)
#define AGGR_BUCK_ORDER			4 /* Initial */

#define AGGR_BUCK_REHASH		aggr_buck_rehash
#define AGGR_BUCK_PARAMS		/8, *2, 2, 2, 4, 24

HASH_DEFINE_REHASH_FN(AGGR_BUCK, struct aggregator_bucket);


#define AGGR_DATA_MEMSIZE	(sizeof(struct f_val) * p->aggr_on_count)

static void
aggregator_rt_notify(struct proto *P, struct channel *src_ch, net *net, rte *new, rte *old)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, P);
  ASSERT_DIE(src_ch == p->src);

  struct aggregator_bucket *new_bucket = NULL, *old_bucket = NULL;
  struct aggregator_route  *new_route  = NULL, *old_route  = NULL;

  /* Ignore all updates if protocol is not up */
  if (p->p.proto_state != PS_UP)
    return;

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
    struct aggregator_bucket *tmp_bucket = allocz(sizeof(*tmp_bucket) + sizeof(tmp_bucket->aggr_data[0]) * p->aggr_on_count);
    ASSERT_DIE(tmp_bucket->id == 0);

    for (u32 val_idx = 0; val_idx < p->aggr_on_count; val_idx++)
    {
      int type = p->aggr_on[val_idx].type;
      struct f_val *pos = &tmp_bucket->aggr_data[val_idx];

      switch (type)
      {
        case AGGR_ITEM_TERM: {
          const struct f_line *line = p->aggr_on[val_idx].line;
          struct rte *rt1 = new;
          enum filter_return fret = f_eval_rte(line, &new, rte_update_pool, 0, NULL, pos);

          if (rt1 != new)
          {
            rte_free(rt1);
            log(L_WARN "Aggregator rule modifies the route, reverting");
          }

          if (fret > F_RETURN)
            log(L_WARN "%s.%s: Wrong number of items left on stack after evaluation of aggregation list", rt1->src->proto->name, rt1->sender->name);

	      switch (pos->type)
          {
	        case T_VOID:
	        case T_INT:
	        case T_BOOL:
	        case T_PAIR:
	        case T_QUAD:
	        case T_ENUM:
	        case T_IP:
	        case T_EC:
	        case T_LC:
	        case T_RD:
	          /* Fits, OK */
	          break;

	        default:
	          log(L_WARN "%s.%s: Expression evaluated to type %s unsupported by aggregator. Store this value as a custom attribute instead", new->src->proto->name, new->sender->name, f_type_name(pos->type));
	          *pos = (struct f_val) { .type = T_INT, .val.i = 0 };
	      }

          break;
        }

        case AGGR_ITEM_STATIC_ATTR:
          aggregator_eval_static_attr(new, p->aggr_on[val_idx].sa, pos);
          break;

        case AGGR_ITEM_DYNAMIC_ATTR:
          aggregator_eval_dynamic_attr(new, p->aggr_on[val_idx].da, pos);
          break;

        default:
          break;
      }
    }

    /* Compute the hash */
    u64 haux;
    mem_hash_init(&haux);

    for (u32 i = 0; i < p->aggr_on_count; i++)
    {
      mem_hash_mix_num(&haux, tmp_bucket->aggr_data[i].type);

#define MX(k) mem_hash_mix(&haux, &IT(k), sizeof IT(k));
#define IT(k) tmp_bucket->aggr_data[i].val.k

      switch (tmp_bucket->aggr_data[i].type)
      {
        case T_VOID:
          break;
        case T_INT:
        case T_BOOL:
        case T_PAIR:
        case T_QUAD:
        case T_ENUM:
          MX(i);
          break;
        case T_EC:
        case T_RD:
          MX(ec);
          break;
        case T_LC:
          MX(lc);
          break;
        case T_IP:
          MX(ip);
          break;
        case T_NET:
          mem_hash_mix_num(&haux, net_hash(IT(net)));
          break;
        case T_STRING:
          mem_hash_mix_str(&haux, IT(s));
          break;
        case T_PATH_MASK:
          mem_hash_mix(&haux, IT(path_mask), sizeof(*IT(path_mask)) + IT(path_mask)->len * sizeof (IT(path_mask)->item));
          break;
        case T_PATH:
        case T_CLIST:
        case T_ECLIST:
        case T_LCLIST:
        case T_BYTESTRING:
          mem_hash_mix(&haux, IT(ad)->data, IT(ad)->length);
          break;
        case T_NONE:
        case T_PATH_MASK_ITEM:
        case T_ROUTE:
        case T_ROUTES_BLOCK:
          bug("Invalid type %s in hashing", f_type_name(tmp_bucket->aggr_data[i].type));
        case T_SET:
          MX(t);
          break;
        case T_PREFIX_SET:
          MX(ti);
          break;
      }
    }

    tmp_bucket->hash = mem_hash_value(&haux);

    /* Find the existing bucket */
    if (new_bucket = HASH_FIND(p->buckets, AGGR_BUCK, tmp_bucket))
      ;
    else
    {
      const size_t bucket_size = sizeof(*new_bucket) + sizeof(new_bucket->aggr_data[0]) * p->aggr_on_count;
      new_bucket = lp_allocz(p->bucket_pool, bucket_size);
      memcpy(new_bucket, tmp_bucket, bucket_size);

      /* Insert bucket into hash chain */
      HASH_INSERT2(p->buckets, AGGR_BUCK, p->p.pool, new_bucket);

      /* Assign ID */
      new_bucket->id = hmap_first_zero(&p->bucket_id_map);
      hmap_set(&p->bucket_id_map, new_bucket->id);

      /* Save bucket pointer */
      aggregator_add_bucket(p, new_bucket);
      p->buckets_count++;

      if (p->aggr_mode == PREFIX_AGGR)
      {
        /*
         * If ID of new bucket doesn't fit into bitmap in trie nodes, we have to
         * create new slab and build whole trie all over again.
         */
        if (new_bucket->id >= (p->bitmap_size * sizeof(p->root->potential_buckets[0]) * 8))
        {
          aggregator_resize_slab(p, new_bucket->id);

          /* Trie already exists after initial feed, build it again in the new slab */
          if (!p->initial_feed)
            aggregator_aggregate(p);
        }
      }
    }

    /* Store the route attributes */
    if (rta_is_cached(new->attrs))
      rta_clone(new->attrs);
    else
      new->attrs = rta_lookup(new->attrs);

    if (p->logging)
      log("New rte: %p, net: %p, src: %p, hash: %x", new, new->net, new->src, aggregator_route_hash(new));

    /* Insert the new route into the bucket */
    struct aggregator_route *arte = lp_allocz(p->route_pool, sizeof(*arte));

    *arte = (struct aggregator_route) {
      .bucket = new_bucket,
      .rte = *new,
    };

    arte->rte.next = new_bucket->rte,
    new_bucket->rte = &arte->rte;
    new_bucket->count++;
    HASH_INSERT2(p->routes, AGGR_RTE, p->p.pool, arte);

    /* New route */
    new_route = arte;
    ASSERT_DIE(new_route != NULL);

    if (p->logging)
      log("Inserting rte: %p, arte: %p, net: %p, src: %p, hash: %x",
          &arte->rte, arte, arte->rte.net, arte->rte.src, aggregator_route_hash(&arte->rte));
  }

  /* Remove the old route from its bucket */
  if (old_bucket)
  {
    for (struct rte **k = &old_bucket->rte; *k; k = &(*k)->next)
    {
      if (*k == &old_route->rte)
      {
        *k = (*k)->next;
        break;
      }
    }

    old_bucket->count--;
    HASH_REMOVE2(p->routes, AGGR_RTE, p->p.pool, old_route);
    rta_free(old_route->rte.attrs);
  }

  /* Aggregation within nets allows incremental updates */
  if (p->aggr_mode == NET_AGGR)
  {
    /* Announce changes */
    if (old_bucket)
      aggregator_bucket_update(p, old_bucket, net->n.addr);

    if (new_bucket && (new_bucket != old_bucket))
      aggregator_bucket_update(p, new_bucket, net->n.addr);
  }
  else if (p->aggr_mode == PREFIX_AGGR)
  {
    /* When receiving initial feed, whole trie is aggregated at once */
    if (!p->initial_feed)
    {
      /* After initial feed, recompute after receiving incremental update */
      aggregator_recompute(p, old_route, new_route);

      /* Process route withdrawals triggered by recomputation */
      aggregator_withdraw_rte(p);
    }
  }

  /* Cleanup the old bucket if empty */
  if (old_bucket && (!old_bucket->rte || !old_bucket->count))
  {
    ASSERT_DIE(!old_bucket->rte && !old_bucket->count);
    HASH_REMOVE2(p->buckets, AGGR_BUCK, p->p.pool, old_bucket);

    /* Free bucket ID */
    hmap_clear(&p->bucket_id_map, old_bucket->id);

    ASSERT_DIE(p->bucket_list[old_bucket->id] == old_bucket);
    p->bucket_list[old_bucket->id] = NULL;
    p->buckets_count--;
  }
}

static int
aggregator_preexport(struct channel *C, struct rte *new)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, C->proto);

  /* Reject our own routes */
  if (new->sender == p->dst)
    return -1;

  /* Disallow aggregating already aggregated routes */
  if (new->attrs->source == RTS_AGGREGATED)
  {
    log(L_ERR "Multiple aggregations of the same route not supported in BIRD 2.");
    return -1;
  }

  return 0;
}

static void
aggregator_postconfig(struct proto_config *CF)
{
  struct aggregator_config *cf = SKIP_BACK(struct aggregator_config, c, CF);

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

// TODO: set pools to NULL?
static struct proto *
aggregator_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, P);
  struct aggregator_config *cf = SKIP_BACK(struct aggregator_config, c, CF);

  proto_configure_channel(P, &p->src, cf->src);
  proto_configure_channel(P, &p->dst, cf->dst);

  p->aggr_mode          = cf->aggr_mode;
  p->aggr_on_count      = cf->aggr_on_count;
  p->aggr_on_da_count   = cf->aggr_on_da_count;
  p->aggr_on            = cf->aggr_on;
  p->merge_by           = cf->merge_by;
  p->logging            = cf->logging;
  p->bucket_list        = NULL;
  p->bucket_list_size   = 0;
  p->buckets_count      = 0;

  P->rt_notify = aggregator_rt_notify;
  P->preexport = aggregator_preexport;
  P->feed_end = aggregator_aggregate_on_feed_end;

  return P;
}

/*
 * Initialize hash table and create default route
 *
 * TODO: tohle asi máme zavolat při startu protokolu
 * a uklidit při vypnutí, ne?
 */
static void
aggregator_trie_init(struct aggregator_proto *p)
{
  /* Zero prefix for default route */
  ip_addr prefix = (p->addr_type == NET_IP4) ? ipa_from_ip4(IP4_NONE) : ipa_from_ip6(IP6_NONE);

  struct net_addr addr = { 0 };
  net_fill_ipa(&addr, prefix, 0);

  /* Create net for zero prefix */
  struct network *default_net = mb_allocz(p->p.pool, sizeof(*default_net) + sizeof(addr));
  net_copy(default_net->n.addr, &addr);

  /* Create route attributes with zero nexthop */
  struct rta rta = { 0 };

  /* Allocate bucket for root node */
  struct aggregator_bucket *new_bucket = lp_allocz(p->bucket_pool, sizeof(*new_bucket));

  u64 haux = 0;
  mem_hash_init(&haux);
  new_bucket->hash = mem_hash_value(&haux);

  /* Assign ID to the root node bucket */
  new_bucket->id = hmap_first_zero(&p->bucket_id_map);
  hmap_set(&p->bucket_id_map, new_bucket->id);

  /* Add bucket pointer to the list of pointers */
  aggregator_add_bucket(p, new_bucket);
  p->buckets_count++;

  struct aggregator_route *arte = lp_allocz(p->route_pool, sizeof(*arte));

  *arte = (struct aggregator_route) {
    .bucket = new_bucket,
    .rte = { .attrs = rta_lookup(&rta) },
  };

  /* Put route into bucket */
  arte->rte.next = new_bucket->rte;
  new_bucket->rte = &arte->rte;
  new_bucket->count++;

  arte->rte.net = default_net;
  default_net->routes = &arte->rte;

  /* Insert bucket and route into their hash chains */
  HASH_INSERT2(p->routes, AGGR_RTE, p->p.pool, arte);
  HASH_INSERT2(p->buckets, AGGR_BUCK, p->p.pool, new_bucket);

  /* Allocate and initialize root node */
  p->root = aggregator_root_init(new_bucket, p->trie_slab);
}

static int
aggregator_start(struct proto *P)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, P);

  ASSERT_DIE(p->bucket_pool == NULL);
  ASSERT_DIE(p->route_pool == NULL);
  ASSERT_DIE(p->trie_slab == NULL);
  ASSERT_DIE(p->root == NULL);

  p->addr_type = p->src->table->addr_type;

  p->bucket_pool = lp_new(P->pool);
  HASH_INIT(p->buckets, P->pool, AGGR_BUCK_ORDER);

  p->route_pool = lp_new(P->pool);
  HASH_INIT(p->routes, P->pool, AGGR_RTE_ORDER);

  p->reload_buckets = (event) {
    .hook = aggregator_reload_buckets,
    .data = p,
  };

  hmap_init(&p->bucket_id_map, P->pool, 1024);
  hmap_set(&p->bucket_id_map, 0);       /* 0 is default value, do not use it as ID */

  p->initial_feed = true;

  if (p->aggr_mode == PREFIX_AGGR)
  {
    ASSERT_DIE(p->trie_slab == NULL);
    ASSERT_DIE(p->bucket_list == NULL);
    ASSERT_DIE(p->bucket_list_size == 0);
    ASSERT_DIE(p->buckets_count == 0);

    p->bitmap_size = POTENTIAL_BUCKETS_BITMAP_INIT_SIZE;

    const size_t node_size = sizeof(*p->root) + sizeof(p->root->potential_buckets[0]) * p->bitmap_size;
    p->trie_slab = sl_new(P->pool, node_size);

    p->bucket_list_size = BUCKET_LIST_INIT_SIZE;
    p->bucket_list = mb_allocz(P->pool, sizeof(p->bucket_list[0]) * p->bucket_list_size);

    p->rte_withdrawal_pool = lp_new(P->pool);
    p->rte_withdrawal_count = 0;

    aggregator_trie_init(p);
  }

  return PS_UP;
}

static int
aggregator_shutdown(struct proto *P UNUSED)
{
  return PS_DOWN;
}

static void
aggregator_cleanup(struct proto *P)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, P);

  /*
   * Linpools will be freed along with other protocol resources but pointers
   * have to be set to NULL because protocol may be started again.
   */
  p->bucket_pool = NULL;
  p->route_pool = NULL;
  p->trie_slab = NULL;
  p->rte_withdrawal_pool = NULL;

  p->root = NULL;

  p->bucket_list = NULL;
  p->bucket_list_size = 0;
  p->buckets_count = 0;

  p->rte_withdrawal_stack = NULL;
  p->rte_withdrawal_count = 0;

  p->bucket_id_map = (struct hmap) { 0 };

  p->initial_feed = true;

  p->bitmap_size = 0;
}

static int
aggregator_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, P);
  struct aggregator_config *cf = SKIP_BACK(struct aggregator_config, c, CF);

  TRACE(D_EVENTS, "Reconfiguring");

  /* Compare numeric values (shortcut) */
  if (cf->aggr_on_count != p->aggr_on_count)
    return 0;

  if (cf->aggr_on_da_count != p->aggr_on_da_count)
    return 0;

  /* Compare aggregator rule */
  for (u32 i = 0; i < p->aggr_on_count; i++)
  {
    switch (cf->aggr_on[i].type)
    {
      case AGGR_ITEM_TERM:
        if (!f_same(cf->aggr_on[i].line, p->aggr_on[i].line))
          return 0;
        break;
      case AGGR_ITEM_STATIC_ATTR:
        if (memcmp(&cf->aggr_on[i].sa, &p->aggr_on[i].sa, sizeof(struct f_static_attr)) != 0)
          return 0;
        break;
      case AGGR_ITEM_DYNAMIC_ATTR:
        if (memcmp(&cf->aggr_on[i].da, &p->aggr_on[i].da, sizeof(struct f_dynamic_attr)) != 0)
          return 0;
        break;
      default:
        bug("Broken aggregator rule");
    }
  }

  /* Compare merge filter */
  if (!f_same(cf->merge_by, p->merge_by))
    ev_schedule(&p->reload_buckets);

  p->aggr_on = cf->aggr_on;
  p->merge_by = cf->merge_by;

  return 1;
}

static void
aggregator_get_status(struct proto *P, byte *buf)
{
  struct aggregator_proto *p = SKIP_BACK(struct aggregator_proto, p, P);

  if (p->p.proto_state == PS_DOWN)
    buf[0] = 0;
  else
  {
    if (p->aggr_mode == PREFIX_AGGR)
      strcpy(buf, "prefix aggregation");
    else
      strcpy(buf, "net aggregation");
  }
}

struct protocol proto_aggregator = {
  .name             = "Aggregator",
  .template         = "aggregator%d",
  .class            = PROTOCOL_AGGREGATOR,
  .preference       = 1,
  .channel_mask     = NB_ANY,
  .proto_size       = sizeof(struct aggregator_proto),
  .config_size      = sizeof(struct aggregator_config),
  .postconfig       = aggregator_postconfig,
  .init             = aggregator_init,
  .start            = aggregator_start,
  .shutdown         = aggregator_shutdown,
  .cleanup          = aggregator_cleanup,
  .reconfigure      = aggregator_reconfigure,
  .get_status       = aggregator_get_status,
};

void
aggregator_build(void)
{
  proto_build(&proto_aggregator);
}
