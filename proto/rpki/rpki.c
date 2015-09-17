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
 * The Resource Public Key Infrastructure (RPKI) to Router Protocol (RFC 6810)
 * is protocol for communication between router (BIRD) and RPKI cache server
 * (RPKI validator). Validator sends   implementation
 * is based on the RTRlib (http://rpki.realmv6.org/). The BIRD takes over
 * |packets.c|, |rtr.c| (inside |rpki.c|), |transport.c|, |tcp_transport.c| and |ssh_transport.c| files
 * from RTRlib.
 *
 * A SSH transport requires LibSSH library. LibSSH is loading dynamically using dlopen
 * function.
 */

/*
 * TODO list
 *  - Receive Router Key PDU with End-Entity certificate
 *  	https://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-rfc6810-bis-07#section-5.10
 *    	It's implemented in RTRlib.
 *  - Saving EE Certificate
 */

#include <stdlib.h>
#include <netdb.h>

#undef LOCAL_DEBUG

#include "rpki.h"
#include "lib/string.h"
#include "nest/cli.h"

static const char *str_cache_states[] = {
    [RPKI_CS_CONNECTING] = "CONNECTING",
    [RPKI_CS_ESTABLISHED] = "ESTABLISHED",
    [RPKI_CS_RESET] = "RESET",
    [RPKI_CS_SYNC] = "SYNC",
    [RPKI_CS_FAST_RECONNECT] = "FAST_RECONNECT",
    [RPKI_CS_ERROR_NO_DATA_AVAIL] = "ERROR_NO_DATA_AVAIL",
    [RPKI_CS_ERROR_NO_INCR_UPDATE_AVAIL] = "ERROR_NO_INCR_UPDATE_AVAIL",
    [RPKI_CS_ERROR_FATAL] = "ERROR_FATAL",
    [RPKI_CS_ERROR_TRANSPORT] = "ERROR_TRANSPORT",
    [RPKI_CS_SHUTDOWN] = "SHUTDOWN"
};

const char *
rpki_cache_state_to_str(enum rpki_cache_state state)
{
  return str_cache_states[state];
}

/* Return 0 if non-valid transition,
 * return 1 if valid transition */
static int
rpki_is_allowed_transition_cache_state(const enum rpki_cache_state old, const enum rpki_cache_state new)
{
  switch (new)
  {
  case RPKI_CS_CONNECTING: 			return old == RPKI_CS_SHUTDOWN || old == RPKI_CS_ERROR_TRANSPORT || old == RPKI_CS_FAST_RECONNECT;
  case RPKI_CS_ESTABLISHED: 			return old == RPKI_CS_SYNC;
  case RPKI_CS_RESET:				return old == RPKI_CS_ERROR_NO_DATA_AVAIL || old == RPKI_CS_ERROR_NO_INCR_UPDATE_AVAIL;
  case RPKI_CS_SYNC:				return old == RPKI_CS_RESET || old == RPKI_CS_CONNECTING || old == RPKI_CS_ESTABLISHED;
  case RPKI_CS_FAST_RECONNECT:			return old == RPKI_CS_ESTABLISHED || old == RPKI_CS_SYNC;
  case RPKI_CS_ERROR_NO_DATA_AVAIL:		return old == RPKI_CS_SYNC;
  case RPKI_CS_ERROR_NO_INCR_UPDATE_AVAIL:	return old == RPKI_CS_SYNC;
  case RPKI_CS_ERROR_FATAL:			return 1;
  case RPKI_CS_ERROR_TRANSPORT:			return 1;
  case RPKI_CS_SHUTDOWN:			return 1;
  }
  return 0;
}

static struct proto *
rpki_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);

  return P;
}

const char *
rpki_get_cache_ident(struct rpki_cache *cache)
{
  return rpki_tr_ident(cache->tr_sock);
}

/*
 * Timers
 */

void
rpki_schedule_next_refresh(struct rpki_cache *cache)
{
  if (cache->state == RPKI_CS_SHUTDOWN)
  {
    CACHE_DBG(cache, "Stop refreshing");
    return;
  }

  unsigned time_to_wait = cache->refresh_interval;

  CACHE_DBG(cache, "Scheduling next refresh after %u seconds", time_to_wait);
  tm_start(cache->refresh_timer, time_to_wait);
}

void
rpki_schedule_next_retry(struct rpki_cache *cache)
{
  uint time_to_wait = cache->retry_interval;

  switch (cache->state)
  {
  case RPKI_CS_ESTABLISHED:
  case RPKI_CS_SYNC:
  case RPKI_CS_RESET:
    CACHE_DBG(cache, "Stop retrying connection");
    break;

  default:
    CACHE_DBG(cache, "Scheduling next retry after %u seconds", time_to_wait);
    tm_start(cache->retry_timer, time_to_wait);
  }
}

void
rpki_schedule_next_expire_check(struct rpki_cache *cache)
{
  /* minimum time to wait is 1 second */
  unsigned time_to_wait = MAX(((int)cache->expire_interval - (int)(now - cache->last_update)), 1);

  CACHE_DBG(cache, "Scheduling next expiration check after %u seconds", time_to_wait);
  tm_start(cache->expire_timer, time_to_wait);
}

static void
rpki_refresh_hook(struct timer *tm)
{
  struct rpki_cache *cache = tm->data;

  CACHE_DBG(cache, "%s", rpki_cache_state_to_str(cache->state));

  switch (cache->state)
  {
  case RPKI_CS_ESTABLISHED:
    rpki_cache_change_state(cache, RPKI_CS_SYNC);
    break;

  case RPKI_CS_SYNC:
    rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
    break;

  default:
    break;
  }

  rpki_schedule_next_refresh(cache);
}

static void
rpki_retry_hook(struct timer *tm)
{
  struct rpki_cache *cache = tm->data;

  CACHE_DBG(cache, "%s", rpki_cache_state_to_str(cache->state));

  switch (cache->state)
  {
  case RPKI_CS_ESTABLISHED:
  case RPKI_CS_CONNECTING:
  case RPKI_CS_SYNC:
  case RPKI_CS_SHUTDOWN:
    break;

  default:
    rpki_cache_change_state(cache, RPKI_CS_CONNECTING);
    break;
  }

  rpki_schedule_next_retry(cache);
}

static void
rpki_purge_records_if_outdated(struct rpki_cache *cache)
{
  if (cache->last_update == 0)
    return;

  if ((cache->last_update + cache->expire_interval) < now)
  {
    CACHE_TRACE(D_EVENTS, cache, "All routes expired");
    rpki_table_remove_all(cache);
    cache->request_session_id = 1;
    cache->serial_number = 0;
    cache->last_update = 0;
  }
  else
  {
    CACHE_DBG(cache, "No outdated records, remains %d seconds to become obsolete", (int)cache->expire_interval - (int)(now - cache->last_update));
  }
}

static void
rpki_expire_hook(struct timer *tm)
{
  struct rpki_cache *cache = tm->data;

  if (cache->last_update == 0)
    return;

  CACHE_DBG(cache, ""); /* Show name of function */

  rpki_purge_records_if_outdated(cache);
  rpki_schedule_next_expire_check(cache);
}

static int
rpki_open_connection(struct rpki_cache *cache)
{
  CACHE_TRACE(D_EVENTS, cache, "Opening a connection");

  if (rpki_tr_open(cache->tr_sock) == TR_ERROR)
  {
    rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
    return TR_ERROR;
  }

  return TR_SUCCESS;
}

static void
rpki_close_connection(struct rpki_cache *cache)
{
  CACHE_TRACE(D_EVENTS, cache, "Closing a connection");
  rpki_tr_close(cache->tr_sock);
}

/**
 * rpki_cache_change_state - check and change cache state
 * @cache: RPKI cache instance
 * @new_state: suggested new state
 *
 * Validates and makes transition. Does appropriate actions after change
 */
void
rpki_cache_change_state(struct rpki_cache *cache, const enum rpki_cache_state new_state)
{
  const enum rpki_cache_state old_state = cache->state;

  if (old_state == new_state)
    return;

  if (!rpki_is_allowed_transition_cache_state(old_state, new_state))
  {
    CACHE_TRACE(D_EVENTS, cache, "Change state %s -> %s is not allowed", rpki_cache_state_to_str(old_state), rpki_cache_state_to_str(new_state));
    ASSERT(0);
    return;
  }

  CACHE_TRACE(D_EVENTS, cache, "Change state %s -> %s", rpki_cache_state_to_str(old_state), rpki_cache_state_to_str(new_state));
  cache->state = new_state;

  switch (new_state)
  {
  case RPKI_CS_CONNECTING:
  {
    sock *sk = cache->tr_sock->sk;

    if (sk == NULL || sk->fd < 0)
      rpki_open_connection(cache);
    else
      rpki_cache_change_state(cache, RPKI_CS_SYNC);

    break;
  }

  case RPKI_CS_ESTABLISHED:
    break;

  case RPKI_CS_RESET:
    /* Resetting RTR connection. */
    cache->request_session_id = 1;
    cache->serial_number = 0;
    rpki_cache_change_state(cache, RPKI_CS_SYNC);
    break;

  case RPKI_CS_SYNC:
    /* Requesting for receive validation records from the RTR server. */
    if (cache->request_session_id)
    {
      /* Change to state RESET, if socket dont has a session_id */
      if (rpki_send_reset_query(cache) != RPKI_SUCCESS)
	rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    }
    else
    {
      /* if we already have a session_id, send a serial query and start to sync */
      if (rpki_send_serial_query(cache) != RPKI_SUCCESS)
	rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    }
    break;

  case RPKI_CS_ERROR_NO_INCR_UPDATE_AVAIL:
    /* Server was unable to answer the last serial or reset query. */
    rpki_purge_records_if_outdated(cache);
    rpki_cache_change_state(cache, RPKI_CS_RESET);
    break;

  case RPKI_CS_ERROR_NO_DATA_AVAIL:
    /* No validation records are available on the RTR server. */
    rpki_cache_change_state(cache, RPKI_CS_RESET);
    break;

  case RPKI_CS_ERROR_FATAL:
    /* Fatal protocol error occurred. */
    cache->request_session_id = 1;
    cache->serial_number = 0;
    cache->last_update = 0;
    rpki_table_remove_all(cache);
    /* Fall through */

  case RPKI_CS_ERROR_TRANSPORT:
    /* Error on the transport socket occurred. */
    rpki_close_connection(cache);
    rpki_schedule_next_retry(cache);
    break;

  case RPKI_CS_FAST_RECONNECT:
    /* Reconnect without any waiting period */
    rpki_close_connection(cache);
    rpki_cache_change_state(cache, RPKI_CS_CONNECTING);
    break;

  case RPKI_CS_SHUTDOWN:
    /* RTR Socket is stopped. */
    rpki_close_connection(cache);
    cache->request_session_id = 1;
    cache->serial_number = 0;
    cache->last_update = 0;
    rpki_table_remove_all(cache);
    break;
  };
}

/**
 * rpki_check_refresh_interval - check validity of refresh interval value
 * @seconds: suggested value
 *
 * Validate value and return NULL if check passed or error message if check failed.
 */
const char *
rpki_check_refresh_interval(uint seconds)
{
  if (seconds < 1)
    return "Minimum allowed refresh interval is 1 second";
  if (seconds > 86400)
    return "Maximum allowed refresh interval is 86400 seconds";
  return NULL;
}

/**
 * rpki_check_retry_interval - check validity of retry interval value
 * @seconds: suggested value
 *
 * Validate value and return NULL if check passed or error message if check failed.
 */
const char *
rpki_check_retry_interval(uint seconds)
{
  if (seconds < 1)
    return "Minimum allowed retry interval is 1 second";
  if (seconds > 7200)
    return "Maximum allowed retry interval is 7200 seconds";
  return NULL;
}

/**
 * rpki_check_expire_interval - check validity of expire interval value
 * @seconds: suggested value
 *
 * Validate value and return NULL if check passed or error message if check failed.
 */
const char *
rpki_check_expire_interval(uint seconds)
{
  if (seconds < 600)
    return "Minimum allowed expire interval is 600 seconds";
  if (seconds > 172800)
    return "Maximum allowed expire interval is 172800 seconds";
  return NULL;
}

static struct rpki_cache *
rpki_init_cache(struct rpki_proto *p, struct rpki_config *cf)
{
  pool *pool = rp_new(p->p.pool, cf->hostname);

  struct rpki_cache *cache = mb_allocz(pool, sizeof(struct rpki_cache));

  cache->pool = pool;
  cache->p = p;

  proto_configure_channel(&p->p, &cache->roa4_channel, proto_cf_find_channel(p->p.cf, NET_ROA4));
  proto_configure_channel(&p->p, &cache->roa6_channel, proto_cf_find_channel(p->p.cf, NET_ROA6));

  cache->state = RPKI_CS_SHUTDOWN;
  cache->request_session_id = 1;
  cache->serial_number = 0;
  cache->last_update = 0;
  cache->version = RPKI_MAX_VERSION;

  cache->refresh_interval = cf->refresh_interval;
  cache->retry_interval = cf->retry_interval;
  cache->expire_interval = cf->expire_interval;
  cache->retry_timer = tm_new_set(pool, &rpki_retry_hook, cache, 0, 0);
  cache->refresh_timer = tm_new_set(pool, &rpki_refresh_hook, cache, 0, 0);
  cache->expire_timer = tm_new_set(pool, &rpki_expire_hook, cache, 0, 0);

  cache->tr_sock = mb_allocz(pool, sizeof(struct rpki_tr_sock));
  cache->tr_sock->cache = cache;

  if (cf->ssh)
    rpki_tr_ssh_init(cache->tr_sock);
  else
    rpki_tr_tcp_init(cache->tr_sock);

  CACHE_TRACE(D_EVENTS, cache, "Created");

  return cache;
}

static void
rpki_free_cache(struct rpki_cache *cache)
{
  struct rpki_proto *p = cache->p;

  rpki_table_remove_all(cache);

  CACHE_TRACE(D_EVENTS, p->cache, "Destroyed");
  rfree(cache->pool);
  p->cache = NULL;
}

static int
rpki_shutdown(struct proto *P)
{
  struct rpki_proto *p = (void *) P;
  p->cache = NULL;

  /* protocol memory pool will be automatically freed */
  return PS_DOWN;
}

static void
rpki_start_cache(struct rpki_cache *cache)
{
  rpki_cache_change_state(cache, RPKI_CS_CONNECTING);
}

static void
rpki_replace_cache(struct rpki_cache *cache, struct rpki_config *new, struct rpki_config *old)
{
  struct rpki_proto *p = cache->p;

  rpki_free_cache(cache);

  p->cache = rpki_init_cache(p, new);
  rpki_start_cache(p->cache);
}

static void
rpki_fast_reconnect_cache(struct rpki_cache *cache, struct rpki_config *new, struct rpki_config *old)
{
  if (cache->state == RPKI_CS_ESTABLISHED)
    rpki_cache_change_state(cache, RPKI_CS_FAST_RECONNECT);
  else
    rpki_replace_cache(cache, old, new);
}

/*
 * Return 0 if need to restart
 * Return 1 if reconfiguration finished successful
 */
static int
rpki_reconfigure_cache(struct rpki_proto *p, struct rpki_cache *cache, struct rpki_config *new, struct rpki_config *old)
{
  u8 try_fast_reconnect = 0;

  if (!proto_configure_channel(&p->p, &cache->roa4_channel, proto_cf_find_channel(p->p.cf, NET_ROA4)) ||
      !proto_configure_channel(&p->p, &cache->roa6_channel, proto_cf_find_channel(p->p.cf, NET_ROA6)))
  {
    CACHE_TRACE(D_EVENTS, cache, "Channels changed");
    return 0;
  }

  if (strcmp(old->hostname, new->hostname) != 0)
  {
    CACHE_TRACE(D_EVENTS, cache, "Remote cache server address changed to %s", new->hostname);
    goto hard_cache_replace;
  }

  if (old->port != new->port)
  {
    CACHE_TRACE(D_EVENTS, cache, "Remote cache server port changed to %u", new->port);
    goto hard_cache_replace;
  }

  if (!!old->ssh != !!new->ssh)
  {
    CACHE_TRACE(D_EVENTS, cache, "SSH encryption toggled");
    goto hard_cache_replace;
  }
  else if (old->ssh && new->ssh)
  {
    if ((strcmp(old->ssh->bird_private_key, new->ssh->bird_private_key) != 0) ||
	(strcmp(old->ssh->cache_public_key, new->ssh->cache_public_key) != 0) ||
	(strcmp(old->ssh->user, new->ssh->user) != 0))
    {
      CACHE_TRACE(D_EVENTS, cache, "Settings of SSH transport encryption changed");
      try_fast_reconnect = 1;
    }
  }

  if (cache->expire_interval != new->expire_interval)
  {
    cache->expire_interval = new->expire_interval;
    CACHE_TRACE(D_EVENTS, cache, "Expire interval changed to %u seconds", cache->expire_interval);
    try_fast_reconnect = 1;
  }

  if (cache->refresh_interval != new->refresh_interval)
  {
    cache->refresh_interval = new->refresh_interval;
    CACHE_TRACE(D_EVENTS, cache, "Refresh interval changed to %u seconds", cache->refresh_interval);
    try_fast_reconnect = 1;
  }

  if (cache->retry_interval != new->retry_interval)
  {
    cache->retry_interval = new->retry_interval;
    CACHE_TRACE(D_EVENTS, cache, "Retry interval changed to %u seconds", cache->retry_interval);
    try_fast_reconnect = 1;
  }

  if (try_fast_reconnect)
    rpki_fast_reconnect_cache(cache, new, old);

  return 1;

 hard_cache_replace:
  rpki_replace_cache(cache, new, old);
  return 1;
}

/*
 * Return 0 if need to restart
 * Return 1 if reconfiguration finished successful
 */
static int
rpki_reconfigure_proto(struct rpki_proto *p, struct rpki_config *new_cf, struct rpki_config *old_cf)
{
  u8 new = new_cf && new_cf->hostname;
  u8 old = old_cf && old_cf->hostname;
  struct rpki_cache *cache = p->cache;

  if (new && !old)
  {
    p->cache = rpki_init_cache(p, new_cf);
    rpki_start_cache(p->cache);
  }
  else if (!new && old && cache)
    rpki_free_cache(cache);
  else if (new && old && cache)
    return rpki_reconfigure_cache(p, cache, new_cf, old_cf);

  return 1;
}

/*
 * Return 0 if need to restart
 * Return 1 if reconfiguration finished successful
 */
static int
rpki_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct rpki_proto *p = (void *) P;
  struct rpki_config *new = (void *) CF;
  struct rpki_config *old = (void *) p->p.cf;

  P->cf = CF;
  if (rpki_reconfigure_proto(p, new, old))
    return 1;

  P->cf = (void *) old;
  return 0;
}

static void
rpki_get_status(struct proto *P, byte *buf)
{
  struct rpki_proto *p = (struct rpki_proto *) P;

  if (P->proto_state == PS_DOWN)
  {
    *buf = 0;
    return;
  }

  if (p->cache)
    bsprintf(buf, "%s", rpki_cache_state_to_str(p->cache->state));
  else
    bsprintf(buf, "No cache server configured");
}

static void
rpki_show_proto_info_timer(const char *name, uint num, timer *t)
{
  if (t->expires)
    cli_msg(-1006, "  %-17s %us (remains %us)", name, num, tm_remains(t));
  else
    cli_msg(-1006, "  %-17s %us", name, num);
}

static void
rpki_show_proto_info(struct proto *P)
{
  struct rpki_proto *p = (struct rpki_proto *) P;
  struct rpki_config *cf = (void *) p->p.cf;
  struct rpki_cache *cache = p->cache;

  if (cache)
  {
    cli_msg(-1006, "  Remote server:    %s", rpki_get_cache_ident(cache));
    cli_msg(-1006, "  Status:           %s", rpki_cache_state_to_str(cache->state));
    cli_msg(-1006, "  Transport:        %s", cf->ssh ? "SSHv2" : "Unprotected over TCP");
    cli_msg(-1006, "  Protocol version: %u", cache->version);

    if (cache->last_update)
      cli_msg(-1006, "  Last update:      before %us", now - cache->last_update);
    else
      cli_msg(-1006, "  Last update:      ---");

    rpki_show_proto_info_timer("Retry interval:", cache->retry_interval, cache->retry_timer);
    rpki_show_proto_info_timer("Refresh interval:", cache->refresh_interval, cache->refresh_timer);
    rpki_show_proto_info_timer("Expire interval:", cache->expire_interval, cache->expire_timer);

    if (cache->roa4_channel)
      channel_show_info(cache->roa4_channel);
    else
      cli_msg(-1006, "  No roa4 channel");

    if (cache->roa6_channel)
      channel_show_info(cache->roa6_channel);
    else
      cli_msg(-1006, "  No roa6 channel");
  }
}

static int
rpki_start(struct proto *P)
{
  struct rpki_proto *p = (void *) P;
  struct rpki_config *cf = (void *) P->cf;

  rpki_reconfigure_proto(p, cf, NULL);

  return PS_UP;
}

static void
rpki_postconfig(struct proto_config *CF)
{
  /* Define default channel */
  if (EMPTY_LIST(CF->channels))
    channel_config_new(NULL, CF->net_type, CF);
}

static void
rpki_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct rpki_config *d = (void *) dest;
  struct rpki_config *s = (void *) src;

  /*
   * Make a deep copy.
   * The SSH configuration block can be reopened and extended.
   */
  if (s->ssh)
  {
    d->ssh = cfg_alloc(sizeof(struct rpki_config_ssh));
    memcpy(d->ssh, s->ssh, sizeof(struct rpki_config_ssh));
  }
}

void
rpki_check_config(struct rpki_config *cf)
{
  /* Do not check templates at all */
  if (cf->c.class == SYM_TEMPLATE)
    return;

  if (cf->hostname == NULL)
    cf_error("Address or hostname of remote cache server must be set");

  if (cf->port == 0)
  {
    if (cf->ssh != NULL)
      cf->port = RPKI_SSH_PORT;
    else
      cf->port = RPKI_PORT;
  }
}

struct protocol proto_rpki = {
    .name = 		"RPKI",
    .template = 	"rpki%d",
    .preference = 	DEF_PREF_RPKI,
    .proto_size = 	sizeof(struct rpki_proto),
    .config_size =	sizeof(struct rpki_config),
    .init = 		rpki_init,
    .start = 		rpki_start,
    .postconfig = 	rpki_postconfig,
    .channel_mask =	(NB_ROA4 | NB_ROA6),
    .show_proto_info =	rpki_show_proto_info,
    .shutdown = 	rpki_shutdown,
    .copy_config = 	rpki_copy_config,
    .reconfigure = 	rpki_reconfigure,
    .get_status = 	rpki_get_status,
};
