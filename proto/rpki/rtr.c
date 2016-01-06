/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file was part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "rpki.h"

#include "packets.h"
#include "rtr.h"
#include "lib/timer.h"

static const char *rtr_socket_str_states[] = {
    [RTR_CONNECTING] = "RTR_CONNECTING",
    [RTR_ESTABLISHED] = "RTR_ESTABLISHED",
    [RTR_RESET] = "RTR_RESET",
    [RTR_SYNC] = "RTR_SYNC",
    [RTR_FAST_RECONNECT] = "RTR_FAST_RECONNECT",
    [RTR_ERROR_NO_DATA_AVAIL] = "RTR_ERROR_NO_DATA_AVAIL",
    [RTR_ERROR_NO_INCR_UPDATE_AVAIL] = "RTR_ERROR_NO_INCR_UPDATE_AVAIL",
    [RTR_ERROR_FATAL] = "RTR_ERROR_FATAL",
    [RTR_ERROR_TRANSPORT] = "RTR_ERROR_TRANSPORT",
    [RTR_SHUTDOWN] = "RTR_SHUTDOWN"
};

void
rtr_init(struct rtr_socket *rtr_socket, const unsigned int refresh_interval, const unsigned int expire_interval, const unsigned int retry_interval)
{
  if(refresh_interval == 0)
    rtr_socket->refresh_interval = 300;
  else if (refresh_interval > 3600)
  {
    CACHE_TRACE(D_EVENTS, rtr_socket->cache, "The refresh interval %u is too big, setting it to 3600 seconds", refresh_interval);
    rtr_socket->refresh_interval = 3600;
  }
  else
    rtr_socket->refresh_interval = (refresh_interval > (3600 - RPKI_RECV_TIMEOUT) ? (3600 - RPKI_RECV_TIMEOUT) : refresh_interval);

  rtr_socket->expire_interval = (expire_interval == 0 ? (rtr_socket->refresh_interval * 2) : expire_interval);
  rtr_socket->retry_interval = (retry_interval == 0) ? 600 : retry_interval;

  rtr_socket->state = RTR_SHUTDOWN;
  rtr_socket->request_session_id = true;
  rtr_socket->serial_number = 0;
  rtr_socket->last_update = 0;
  rtr_socket->version = RTR_PROTOCOL_MAX_SUPPORTED_VERSION;
}

void
rtr_purge_records_if_outdated(struct rpki_cache *cache)
{
  struct rtr_socket *rtr_socket = cache->rtr_socket;

  if (rtr_socket->last_update == 0)
    return;

  if ((rtr_socket->last_update + rtr_socket->expire_interval) < now)
  {
    pfx_table_src_remove(cache);
    CACHE_TRACE(D_EVENTS, cache, "All ROA records from %s expired", get_cache_ident(cache));
    rtr_socket->request_session_id = true;
    rtr_socket->serial_number = 0;
    rtr_socket->last_update = 0;
  }
  else
  {
    CACHE_DBG(cache, "There are no outdated roa records, it remains %u seconds to become obsolete", (now - (rtr_socket->last_update + rtr_socket->expire_interval)));
  }
}

void
rtr_stop(struct rtr_socket *rtr_socket)
{
  rtr_change_socket_state(rtr_socket, RTR_SHUTDOWN);
  CACHE_TRACE(D_EVENTS, rtr_socket->cache, "Socket shut down");
}

const char *
rtr_state_to_str(enum rtr_socket_state state)
{
  return rtr_socket_str_states[state];
}

/*
 * Set group status to @mgr_status if all sockets of caches in the @group are @socket_state
 */
static void
set_group_status_to_if_all_sockets_are(struct rpki_cache_group *group, const enum rtr_mgr_status mgr_status, const enum rtr_socket_state socket_state)
{
  bool do_all_sockets_pass = true;

  struct rpki_cache *cache;
  WALK_LIST(cache, group->cache_list)
  {
    if (cache->rtr_socket->state != socket_state)
      do_all_sockets_pass = false;
  }
  if (do_all_sockets_pass)
    group->status = mgr_status;
}

void
rtr_change_socket_state(struct rtr_socket *rtr_socket, const enum rtr_socket_state new_state)
{
  const enum rtr_socket_state old_state = rtr_socket->state;

  if (old_state == new_state)
    return;

  rtr_socket->state = new_state;

  struct rpki_cache *cache = rtr_socket->cache;
  CACHE_TRACE(D_EVENTS, cache, "Change state %s -> %s", rtr_state_to_str(old_state), rtr_state_to_str(new_state));

  switch (new_state)
  {
    case RTR_CONNECTING:
      if (old_state == RTR_SHUTDOWN)
	cache->group->status = RTR_MGR_CONNECTING;

      if (cache->sk == NULL || cache->sk->fd < 0)
      {
	if (rpki_open_connection(cache) == TR_SUCCESS)
	  cache->rtr_socket->state = RTR_SYNC; /* Need call a setup the bird socket in io.c loop */
      }
      else
	rtr_change_socket_state(rtr_socket, RTR_SYNC);
      break;

    case RTR_ESTABLISHED:
      /* set status of group to RTR_MGR_ESTABLISHED if all caches in the common group are RTR_ESTABLISHED */
      set_group_status_to_if_all_sockets_are(cache->group, RTR_MGR_ESTABLISHED, RTR_ESTABLISHED);
      rpki_relax_groups(cache->p);
      break;

    case RTR_RESET:
      /* Resetting RTR connection. */
      rtr_socket->request_session_id = true;
      rtr_socket->serial_number = 0;
      rtr_change_socket_state(rtr_socket, RTR_SYNC);
      break;

    case RTR_SYNC:
      /* Requesting for receive validation records from the RTR server.  */
      if (rtr_socket->request_session_id)
      {
	//change to state RESET, if socket dont has a session_id
	if (rtr_send_reset_query(cache) != RTR_SUCCESS)
	  rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
      }
      else
      {
	//if we already have a session_id, send a serial query and start to sync
	if (rtr_send_serial_query(cache) != RTR_SUCCESS)
	  rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
      }
      break;

    case RTR_ERROR_NO_INCR_UPDATE_AVAIL:
      /* Server was unable to answer the last serial or reset query. */
      rtr_purge_records_if_outdated(cache);
      /* Fall through */

    case RTR_ERROR_NO_DATA_AVAIL:
      /* No validation records are available on the RTR server. */
      rtr_change_socket_state(rtr_socket, RTR_RESET);
      break;

    case RTR_ERROR_FATAL:
      /* Fatal protocol error occurred. */
      rtr_socket->request_session_id = true;
      rtr_socket->serial_number = 0;
      rtr_socket->last_update = 0;
      pfx_table_src_remove(cache);
      /* Fall through */

    case RTR_ERROR_TRANSPORT:
      /* Error on the transport socket occurred. */
      rpki_close_connection(cache);
      rtr_schedule_next_retry(cache);
      cache->group->status = RTR_MGR_ERROR;
      rpki_relax_groups(cache->p);
      break;

    case RTR_FAST_RECONNECT:
      /* Reconnect without any waiting period */
      rpki_close_connection(cache);
      rtr_change_socket_state(rtr_socket, RTR_CONNECTING);
      break;

    case RTR_SHUTDOWN:
      /* RTR Socket is stopped. */
      rpki_close_connection(cache);
      rtr_socket->request_session_id = true;
      rtr_socket->serial_number = 0;
      rtr_socket->last_update = 0;
      pfx_table_src_remove(cache);

      /* set status of group to RTR_MGR_CLOSED if all caches in the common group are RTR_SHUTDOWN */
      set_group_status_to_if_all_sockets_are(cache->group, RTR_MGR_CLOSED, RTR_SHUTDOWN);
      rpki_relax_groups(cache->p);
      break;
  };
}

/*
 * Timers
 */

void
rtr_schedule_next_refresh(struct rpki_cache *cache)
{
  struct rtr_socket *rtr_socket = cache->rtr_socket;
  struct rpki_proto *p = cache->p;

  if (cache->rtr_socket->state == RTR_SHUTDOWN)
  {
    CACHE_DBG(cache, "Stop refreshing");
    return;
  }

  unsigned time_to_wait = MAX(((int)rtr_socket->refresh_interval - (int)(now - rtr_socket->last_update)), 1);

  CACHE_DBG(cache, "Next refresh of cache(%s) will be after %u seconds", tr_ident(rtr_socket->tr_socket), time_to_wait);
  tm_start(cache->refresh_timer, time_to_wait);
}

void
rtr_schedule_next_retry(struct rpki_cache *cache)
{
  struct rtr_socket *rtr_socket = cache->rtr_socket;
  struct rpki_proto *p = cache->p;

  switch (cache->rtr_socket->state)
  {
    case RTR_ESTABLISHED:
    case RTR_SYNC:
    case RTR_RESET:
      CACHE_DBG(cache, "Stop retrying connection");
      break;

    default:
      CACHE_TRACE(D_EVENTS, cache, "Connection will retry after %u seconds again", cache->rtr_socket->retry_interval);
      tm_start(cache->retry_timer, cache->rtr_socket->retry_interval);
  }
}

void
rtr_schedule_next_expire_check(struct rpki_cache *cache)
{
  struct rtr_socket *rtr_socket = cache->rtr_socket;
  struct rpki_proto *p = cache->p;

  unsigned time_to_wait = MAX(((int)rtr_socket->expire_interval - (int)(now - rtr_socket->last_update)), 1);

  CACHE_DBG(cache, "Next ROA expiration check will be after %u seconds again", time_to_wait);
  tm_stop(cache->expire_timer);
  tm_start(cache->expire_timer, time_to_wait);
}

void
rpki_refresh_hook(struct timer *tm)
{
  struct rpki_cache *cache = tm->data;
  struct rtr_socket *rtr_socket = cache->rtr_socket;

  switch (rtr_socket->state)
  {
    case RTR_ESTABLISHED:
      CACHE_DBG(cache, "Refreshing");
      rtr_change_socket_state(rtr_socket, RTR_SYNC);
      rtr_schedule_next_refresh(cache);
      break;

    case RTR_CONNECTING:
    case RTR_SYNC:
      /* Wait a small amount of time to the end of transitive state */
      tm_start(tm, 1);
      break;

    default:
      CACHE_DBG(cache, "Stop Refreshing (%s)", rtr_socket_str_states[rtr_socket->state]);
      break;
  }
}

void
rpki_retry_hook(struct timer *tm)
{
  struct rpki_cache *cache = tm->data;
  struct rtr_socket *rtr_socket = cache->rtr_socket;
  struct rpki_proto *p = cache->p;

  switch (rtr_socket->state)
  {
    case RTR_ESTABLISHED:
    case RTR_CONNECTING:
    case RTR_SYNC:
    case RTR_SHUTDOWN:
      CACHE_DBG(cache, "Stop Retry Connecting (%s)", rtr_socket_str_states[rtr_socket->state]);
      break;

    default:
      CACHE_DBG(cache, "Retry Connecting (%s)", rtr_socket_str_states[rtr_socket->state]);
      rtr_change_socket_state(rtr_socket, RTR_CONNECTING);
      debug_print_groups(p);
      break;
  }
}

void
rpki_expire_hook(struct timer *tm)
{
  struct rpki_cache *cache = tm->data;
  struct rtr_socket *rtr_socket = cache->rtr_socket;

  if (rtr_socket->last_update == 0)
    return;

  CACHE_DBG(cache, "Expire Hook");

  rtr_purge_records_if_outdated(cache);
  rtr_schedule_next_expire_check(cache);
}
