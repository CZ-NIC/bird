/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	Using RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: RPKI to Router Protocol
 *
 * The Resource Public Key Infrastructure (RPKI) to router protocol implementation
 * is based on the RTRlib (http://rpki.realmv6.org/). The BIRD takes over
 * |packets.c|, |rtr.c|, |transport.c|, |tcp_transport.c| and |ssh_transport.c| files
 * from RTRlib.
 *
 * A SSH transport requires LibSSH library. LibSSH is loading dynamically using dlopen
 * function.
 */

#undef LOCAL_DEBUG

#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include "rpki.h"

static const char *mgr_str_status[] = {
    [RTR_MGR_CLOSED] = "RTR_MGR_CLOSED",
    [RTR_MGR_CONNECTING] = "RTR_MGR_CONNECTING",
    [RTR_MGR_ESTABLISHED] = "RTR_MGR_ESTABLISHED",
    [RTR_MGR_ERROR] = "RTR_MGR_ERROR",
};

const char *
get_group_status(struct rpki_cache_group *group)
{
  return mgr_str_status[group->status];
}

static struct proto *
rpki_init(struct proto_config *C)
{
  struct proto *P = proto_new(C, sizeof(struct rpki_proto));
  struct rpki_proto *p = (void *) P;
  p->cf = (void *) C;

  init_list(&p->group_list);

  return P;
}

const char *
get_cache_ident(struct rpki_cache *cache)
{
  return tr_ident(cache->rtr_socket->tr_socket);
}

void
debug_print_groups(struct rpki_proto *p)
{
  struct rpki_cache_group *g;
  WALK_LIST(g, p->group_list)
  {
    DBG("Group(%u) %s \n", g->preference, get_group_status(g));

    struct rpki_cache *c;
    WALK_LIST(c, g->cache_list)
    {
      DBG("  Cache(%s) %s \n", get_cache_ident(c), rtr_state_to_str(c->rtr_socket->state));
    }
  }
}

static struct rpki_cache_group *
rpki_cache_group_alloc(struct rpki_proto *p, u8 preference)
{
  struct rpki_cache_group *new = mb_allocz(p->p.pool, sizeof(struct rpki_cache_group));
  init_list(&new->cache_list);
  new->preference = preference;
  return new;
}

static struct rpki_cache_group *
rpki_new_cache_group_before(struct rpki_proto *p, struct rpki_cache_group *before, list *group_list, u8 preference)
{
  struct rpki_cache_group *new = rpki_cache_group_alloc(p, preference);

  if (&before->n == group_list->head)
    add_head(group_list, &new->n);
  else
    insert_node(&new->n, before->n.prev);

  return new;
}

static void
rpki_insert_cache_into_group(struct rpki_cache *cache)
{
  struct rpki_proto *p = cache->p;
  struct rpki_cache_group *group_iter;
  WALK_LIST(group_iter, p->group_list)
  {
    if (group_iter->preference == cache->cfg->preference)
    {
      add_tail(&group_iter->cache_list, &cache->n);
      cache->group = group_iter;
      return;
    }

    if (group_iter->preference > cache->cfg->preference)
    {
      struct rpki_cache_group *new_group = rpki_new_cache_group_before(p, group_iter, &p->group_list, cache->cfg->preference);
      add_tail(&new_group->cache_list, &cache->n);
      cache->group = new_group;
      return;
    }
  }

  struct rpki_cache_group *new_group = rpki_cache_group_alloc(p, cache->cfg->preference);
  add_tail(&p->group_list, &new_group->n);
  add_tail(&new_group->cache_list, &cache->n);
  cache->group = new_group;
}

struct rpki_cache_cfg *
rpki_new_cache_cfg(void)
{
  struct rpki_cache_cfg *cache = cfg_allocz(sizeof(struct rpki_cache_cfg));
  cache->preference = RPKI_DEFAULT_CACHE_PREFERENCE;
  cache->ip = IPA_NONE;

  cache->retry_interval   = RPKI_DEFAULT_RETRY_INTERVAL;
  cache->refresh_interval = RPKI_DEFAULT_REFRESH_INTERVAL;
  cache->expire_interval  = RPKI_DEFAULT_EXPIRE_INTERVAL;

  /* The port number will be set afterwards */
  return cache;
}

/*
 * We need be able to identify routes that origin from the cache server
 * for case that the cache server send bad serial number and we have to
 * remove from table all ROA learned from this cache server.
 *
 * This function return first not used ROA_SRC_* number in protocol
 */
static u8
get_unused_roa_src(struct rpki_proto *p)
{
  u8 bitmap[256];

  /* The first 3 are reserved for:
   * 	ROA_SRC_ANY 0,
   * 	ROA_SRC_CONFIG 1,
   * 	ROA_SRC_DYNAMIC 2,
   */
  const u8 number_of_reserved = 3;
  memset(bitmap, 1, number_of_reserved);
  bzero(bitmap+number_of_reserved, sizeof(bitmap)-number_of_reserved);

  struct rpki_cache_group *group;
  WALK_LIST(group, p->group_list)
  {
    struct rpki_cache *cache;
    WALK_LIST(cache, group->cache_list)
    {
      if (bitmap[cache->roa_src] != 0)
        RPKI_WARN(p, "ROA_SRC %u is used more than once!", cache->roa_src);
      bitmap[cache->roa_src] += 1;
    }
  }

  uint i;
  for (i = number_of_reserved; i < sizeof(bitmap); i++)
    if (bitmap[i] == 0)
      return i;

  RPKI_WARN(p, "All ROA_SRC are used?!");
  return ROA_SRC_RPKI;
}

struct rpki_cache *
rpki_new_cache(struct rpki_proto *p, struct rpki_cache_cfg *cache_cfg)
{
  struct rpki_cache *cache = mb_allocz(p->p.pool, sizeof(struct rpki_cache));
  struct rtr_socket *rtr_socket = mb_allocz(p->p.pool, sizeof(struct rtr_socket));
  struct tr_socket *tr_socket = mb_allocz(p->p.pool, sizeof(struct tr_socket));

  cache->p = p;
  cache->cfg = cache_cfg;
  cache->roa_src = get_unused_roa_src(p);
  cache->retry_timer = tm_new_set(p->p.pool, &rpki_retry_hook, cache, 0, 0);
  cache->refresh_timer = tm_new_set(p->p.pool, &rpki_refresh_hook, cache, 0, 0);
  cache->expire_timer = tm_new_set(p->p.pool, &rpki_expire_hook, cache, 0, 0);
  cache->rtr_socket = rtr_socket;
  cache->rtr_socket->tr_socket = tr_socket;
  cache->rtr_socket->cache = cache;

  if (cache_cfg->ssh)
    tr_ssh_init(cache);
  else
    tr_tcp_init(cache);

  rtr_init(rtr_socket, cache_cfg->refresh_interval, cache_cfg->expire_interval, cache_cfg->retry_interval);

  return cache;
}

/*
 * Close connection without change a status
 */
void
rpki_close_connection(struct rpki_cache *cache)
{
  sock *sk = cache->sk;

  if (sk)
  {
    CACHE_TRACE(D_EVENTS, cache, "Close the connection");
    tr_close(cache->rtr_socket->tr_socket);
    rfree(sk);
    cache->sk = NULL;
  }
}

int
rpki_open_connection(struct rpki_cache *cache)
{
  struct rpki_proto *p = cache->p;
  struct tr_socket *tr_socket = cache->rtr_socket->tr_socket;
  CACHE_TRACE(D_EVENTS, cache, "Open a connection");

  ASSERT(cache->sk == NULL);

  cache->sk = sk_new(p->p.pool);
  sock *sk = cache->sk;

  sk->tx_hook = rpki_connected_hook;
  sk->err_hook = rpki_err_hook;
  sk->data = cache;
  sk->daddr = cache->cfg->ip;
  sk->dport = cache->cfg->port;
  sk->host = cache->cfg->hostname;
  sk->rbsize = RPKI_RX_BUFFER_SIZE;
  sk->tbsize = RPKI_TX_BUFFER_SIZE;
  sk->tos = IP_PREC_INTERNET_CONTROL;

  sk->type = -1; /* must be set in the specific transport layer in tr_open() */

  if (tr_open(tr_socket) == TR_ERROR)
  {
    sk_log_error(sk, p->p.name);
    rtr_change_socket_state(cache->rtr_socket, RTR_ERROR_TRANSPORT);
    return TR_ERROR;
  }

  return TR_SUCCESS;
}

/*
 * Open connections to all caches in group
 */
static void
rpki_open_group(struct rpki_cache_group *group)
{
  struct rpki_cache *cache;
  WALK_LIST(cache, group->cache_list)
  {
    if (cache->rtr_socket->state == RTR_SHUTDOWN)
      rpki_open_connection(cache);
  }
}

static void
rpki_close_group(struct rpki_cache_group *group)
{
  struct rpki_cache *cache;
  WALK_LIST(cache, group->cache_list)
  {
    if (cache->rtr_socket->state != RTR_SHUTDOWN)
      rtr_change_socket_state(cache->rtr_socket, RTR_SHUTDOWN);
  }
}

static void
rpki_remove_cache_from_group(struct rpki_cache *cache)
{
  rem2_node(&cache->n);
}

static void
rpki_free_cache(struct rpki_cache *cache)
{
  rpki_remove_cache_from_group(cache);
  rpki_close_connection(cache);
  pfx_table_src_remove(cache);

  tr_free(cache->rtr_socket->tr_socket);
  mb_free(cache->rtr_socket->tr_socket);
  mb_free(cache->rtr_socket);

  /* Timers */
  tm_stop(cache->retry_timer);
  tm_stop(cache->refresh_timer);
  tm_stop(cache->expire_timer);
  rfree(cache->retry_timer);

  rfree(cache->refresh_timer);
  rfree(cache->expire_timer);

  mb_free(cache);
}

static void
rpki_stop_and_free_caches(struct rpki_proto *p)
{
  struct rpki_cache_group *group;
  WALK_LIST_FIRST(group, p->group_list)
  {
    struct rpki_cache *cache;
    WALK_LIST_FIRST(cache, group->cache_list)
    {
      rem_node(NODE cache);
      rpki_free_cache(cache);
    }
    rem_node(NODE group);
    mb_free(group);
  }

  proto_notify_state(&p->p, PS_DOWN);
}

static int
rpki_shutdown(struct proto *P)
{
  struct rpki_proto *p = (struct rpki_proto *) P;

  rpki_stop_and_free_caches(p);

  return PS_DOWN;
}

static int
are_port_and_host_same(struct rpki_cache_cfg *a, struct rpki_cache_cfg *b)
{
  return (
      (a->port == b->port) &&
      (
	  (a->hostname && b->hostname && strcmp(a->hostname, b->hostname) == 0) ||
	  (ipa_nonzero(a->ip) && (ipa_compare(a->ip, b->ip) == 0))
      )
  );
}

static struct rpki_cache_cfg *
find_cache_cfg_by_host_and_port(list *cache_list, struct rpki_cache_cfg *needle)
{
  struct rpki_cache_cfg *cache_cfg;
  WALK_LIST(cache_cfg, *cache_list)
  {
    if (are_port_and_host_same(needle, cache_cfg))
      return cache_cfg;
  }
  return NULL;
}

static struct rpki_cache *
find_cache_in_proto_by_host_and_port(struct rpki_proto *p, struct rpki_cache_cfg *needle)
{
  struct rpki_cache_group *group;
  WALK_LIST(group, p->group_list)
  {
    struct rpki_cache *cache;
    WALK_LIST(cache, group->cache_list)
    {
      if (are_port_and_host_same(needle, cache->cfg))
        return cache;
    }
  }
  return NULL;
}

static void
remove_empty_cache_groups(struct rpki_proto *p)
{
  struct rpki_cache_group *group, *group_nxt;
  WALK_LIST_DELSAFE(group, group_nxt, p->group_list)
  {
    if (EMPTY_LIST(group->cache_list))
      rem_node(&group->n);
  }
}

/*
 * Move cache into `cache->cfg->preference` preference
 */
static void
move_cache_into_group(struct rpki_cache *cache)
{
  rpki_remove_cache_from_group(cache);
  rpki_insert_cache_into_group(cache);
  remove_empty_cache_groups(cache->p);
}

/*
 * Go through the group list ordered by priority.
 * Open the first CLOSED group or stop opening groups if the processed group state is CONNECTING or ESTABLISHED
 * Then close all groups with the more unimportant priority
 */
void
rpki_relax_groups(struct rpki_proto *p)
{
  RPKI_TRACE(D_EVENTS, p, "rpki_relax_groups START");
  debug_print_groups(p);

  if (EMPTY_LIST(p->group_list))
  {
    RPKI_WARN(p, "No cache in configuration found");
    return;
  }

  bool close_all_next_groups = false;

  struct rpki_cache_group *group;
  WALK_LIST(group, p->group_list)
  {
    if (!close_all_next_groups)
    {
      switch (group->status)
      {
        case RTR_MGR_CLOSED:
          RPKI_TRACE(D_EVENTS, p, "rpki_relax_groups open group(%u)", group->preference);
          rpki_open_group(group);
	  /* Fall through */
        case RTR_MGR_CONNECTING:
        case RTR_MGR_ESTABLISHED:
          close_all_next_groups = 1;
          break;

        case RTR_MGR_ERROR:
          break;
      }
    }
    else
      rpki_close_group(group);
  }

  debug_print_groups(p);
  RPKI_TRACE(D_EVENTS, p, "rpki_relax_groups END");
  return;
}

static int
rpki_reconfigure_proto(struct rpki_proto *p, struct rpki_config *new_cf, struct rpki_config *old_cf)
{
  if (old_cf->roa_table_cf && old_cf->roa_table_cf->table != new_cf->roa_table_cf->table)
  {
    RPKI_TRACE(D_EVENTS, p, "ROA table changed");
    return 0; /* Need to restart the protocol */
  }

  struct rpki_cache_cfg *old;
  WALK_LIST(old, old_cf->cache_cfg_list)
  {
    struct rpki_cache *cache = find_cache_in_proto_by_host_and_port(p, old);
    if (!cache)
      bug("Weird...");

    struct rpki_cache_cfg *new = find_cache_cfg_by_host_and_port(&new_cf->cache_cfg_list, old);
    if (!new)
    {
      /* The cache was in new configuration deleted */
      rpki_free_cache(cache);
      continue;
    }

    cache->cfg = new;

    if (old->preference != new->preference)
    {
      /* The preference of cache was changed */
      move_cache_into_group(cache);
    }

    if (!!old->ssh != !!new->ssh)
    {
      /* toggled SSH enable/disable */
      return 0; /* Need to restart the protocol */
    }

    if (old->ssh && new->ssh)
    {
      /* TODO: RTR_FAST_RECONNECT will be probably enough */

      if (strcmp(old->ssh->bird_private_key, new->ssh->bird_private_key) != 0)
	return 0; /* Need to restart the protocol */

      if (strcmp(old->ssh->cache_public_key, new->ssh->cache_public_key) != 0)
	return 0; /* Need to restart the protocol */

      if (strcmp(old->ssh->username, new->ssh->username) != 0)
	return 0; /* Need to restart the protocol */
    }
  }

  struct rpki_cache_cfg *new;
  WALK_LIST(new, new_cf->cache_cfg_list)
  {
    struct rpki_cache *cache = find_cache_in_proto_by_host_and_port(p, new);
    if (cache)
      cache->cfg = new;

    struct rpki_cache_cfg *old = find_cache_cfg_by_host_and_port(&old_cf->cache_cfg_list, new);
    if (!old)
    {
      /* Some cache was added to new configuration */
      struct rpki_cache *new_cache = rpki_new_cache(p, new);
      rpki_insert_cache_into_group(new_cache);
    }
  }

  debug_print_groups(p);

  return 1;
}

/*
 * Return 0 if need to restart rtrlib manager
 * Return 1 if not need to restart rtrlib manager
 */
static int
rpki_reconfigure(struct proto *P, struct proto_config *c)
{
  struct rpki_proto *p = (struct rpki_proto *) P;
  struct rpki_config *old_cf = p->cf;
  struct rpki_config *new_cf = (struct rpki_config *) c;

  int continue_without_restart = rpki_reconfigure_proto(p, new_cf, old_cf);

  p->cf = new_cf;

  if (continue_without_restart)
    rpki_relax_groups(p);

  return continue_without_restart;
}

static void
rpki_get_status(struct proto *P, byte *buf)
{
  struct rpki_proto *p = (struct rpki_proto *) P;
  unsigned int i, j;

  uint established_connections = 0;
  uint cache_servers = 0;
  uint connecting = 0;

  struct rpki_cache_group *group;
  WALK_LIST(group, p->group_list)
  {
    struct rpki_cache *cache;
    WALK_LIST(cache, group->cache_list)
    {
      cache_servers++;

      switch (cache->rtr_socket->state)
      {
	case RTR_ESTABLISHED:
	case RTR_SYNC:
	  established_connections++;
	  break;

	case RTR_SHUTDOWN:
	  break;

	default:
	  connecting++;
      }
    }
  }

  if (established_connections > 0)
    bsprintf(buf, "Keep synchronized with %u cache server%s", established_connections, (established_connections > 1) ? "s" : "");
  else if (connecting > 0)
    bsprintf(buf, "Connecting to %u cache server%s", connecting, (connecting > 1) ? "s" : "");
  else if (cache_servers == 0)
    bsprintf(buf, "No cache server is configured");
  else if (cache_servers == 1)
    bsprintf(buf, "Cannot connect to a cache server");
  else
    bsprintf(buf, "Cannot connect to any cache servers");
}

static int
rpki_start(struct proto *P)
{
  struct rpki_proto *p = (struct rpki_proto *) P;
  struct rpki_config *cf = (struct rpki_config *) (P->cf);

  struct rpki_config empty_configuration = {
      .roa_table_cf = cf->roa_table_cf
  };
  init_list(&empty_configuration.cache_cfg_list);
  rpki_reconfigure_proto(p, cf, &empty_configuration);

  rpki_relax_groups(p);

  return PS_UP;
}

struct protocol proto_rpki = {
  .name = 		"RPKI",
  .template = 		"rpki%d",
  .config_size =	sizeof(struct rpki_config),
  .init = 		rpki_init,
  .start = 		rpki_start,
//  .show_proto_info =	rpki_show_proto_info,	// TODO: be nice to be implemented
  .shutdown = 		rpki_shutdown,
  .reconfigure = 	rpki_reconfigure,
  .get_status = 	rpki_get_status,
};
