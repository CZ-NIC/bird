/*
 *	BIRD -- YANG-CBOR / CORECONF api
 *
 *	(c) 2026       Maria Matejka <mq@jmq.cz>
 *	(c) 2026       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/tlists.h"
#include "conf/conf.h"
#include "yang/yang.h"

static TLIST_LIST(yang_api) global_api_list;
static pool *yang_pool;

bool
yang_socket_same(const struct yang_socket_params *a, const struct yang_socket_params *b)
{
  if (a->kind != b->kind)
    return false;

  if (a->port != b->port)
    return false;

  if (!ipa_equal(a->local_ip, b->local_ip))
    return false;

  return true;
}

static bool
yang_api_same(const struct yang_api_params *a, const struct yang_api_params *b)
{
  if (a->restricted != b->restricted)
    return false;

  return true;
}

static bool
yang_session_step(struct yang_session *se)
{
  struct yang_socket *s = se->socket;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  enum coap_parse_state state = se->coap.parser.state;

  log(L_TRACE "state is %d", state);
  switch (state) {
    case COAP_PS_MORE:
      return false;

    case COAP_PS_ERROR:
      log(L_INFO "%s: CoAP error %u", api->name, state);
      sk_close(se->sock);
      mb_free(se);
      return false;

    case COAP_PS_HEADER:
      log(L_INFO "Header parsed");
      return true;

    case COAP_PS_OPTION_COMPLETE:
      log(L_INFO "Options parsed");
      return true;

    case COAP_PS_PAYLOAD_COMPLETE:
      log(L_INFO "Payload parsed");
      return true;

    default:
      log(L_INFO "Status %u", state);
      return false;
  }
}

static int
yang_session_rx(sock *sk, uint size)
{
  struct yang_session *se = sk->data;

  /* Check the received data in */
  coap_tcp_rx(&se->coap, sk->rbuf, size);

  /* Parse and process the data */
  do coap_tcp_parse(&se->coap);
  while (coap_process(&se->coap) || yang_session_step(se));

  return 1;
}

static void
yang_session_err(sock *sk, int err)
{
  struct yang_session *se = sk->data;
  struct yang_socket *s = se->socket;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  if (err)
    log(L_INFO "%s: Connection lost (%M)", api->name, err);
  else
    log(L_INFO "%s: Connection closed", api->name);

  sk_close(sk);
  mb_free(se);
}

static int
yang_socket_accept(sock *sk, uint size UNUSED)
{
  struct yang_socket *s = sk->data;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  struct yang_session *se = mb_allocz(api->pool, sizeof *se);
  se->sock = sk;
  se->socket = s;

  sk->rx_hook = yang_session_rx;
  sk->err_hook = yang_session_err;
  sk->data = se;

  return 0;
}

static void
yang_listen_error(sock *sk, int err)
{
  struct yang_socket *s = sk->data;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  if (err == ECONNABORTED)
    log(L_WARN "%s: Incoming connection aborted", api->name);
  else
    log(L_ERR "%s: Error on listening socket: %M", err);
}

static void
yang_socket_olocked(void *_s)
{
  struct yang_socket *s = _s;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  s->sock = sock_new(api->pool);

  switch (s->params.kind)
  {
    case YANG_SOCKET_COAP_TCP:
      s->sock->pool = api->pool;
      s->sock->type = SK_TCP_PASSIVE;
      break;

    default:
      bug("Not implemented yet");
  }

  s->sock->saddr = s->params.local_ip;
  s->sock->sport = s->params.port;

  s->sock->rbsize = 16384;
  s->sock->tbsize = 16384;

  s->sock->rx_hook = yang_socket_accept;
  s->sock->err_hook = yang_listen_error;

  s->sock->data = s;

  sk_open(s->sock, &main_birdloop);
}

static void
yang_socket_new(struct yang_api *api, struct yang_socket_config *sc)
{
  struct yang_socket *s = mb_allocz(api->pool, sizeof *s);

  s->config = sc;
  sc->socket = s;
  yang_socket_add_tail(&api->listen, s);

  s->params = sc->params;

  s->olock = olock_new(api->pool);
  s->olock->addr = sc->params.local_ip;
  s->olock->port = sc->params.port;
  s->olock->event.hook = yang_socket_olocked;
  s->olock->event.data = s;
  s->olock->target = &global_event_list;
  
  switch (sc->params.kind)
  {
    case YANG_SOCKET_COAP_TCP:
      s->olock->type = OBJLOCK_TCP;
      break;

    case YANG_SOCKET_COAP_UDP:
      s->olock->type = OBJLOCK_UDP;
      break;

    default:
      bug("Strange API endpoint kind: %d", sc->params.kind);
  }

  olock_acquire(s->olock);
}

static void
yang_socket_delete(struct yang_socket *s)
{
  rfree(s->olock);
  rfree(s->sock);

#if 0
      switch (api->params.kind)
      {
	case YANG_SOCKET_COAP_TCP:
	  yang_socket_coap_tcp_delete(api);
	  break;

	case YANG_SOCKET_COAP_UDP:
	  yang_socket_coap_udp_delete(api);
	  break;

	default:
	  bug("Strange API endpoint kind: %d", api->params.kind);
      }
#endif
}

static void
yang_api_new(struct yang_api_config *ac)
{
  pool *p = rp_newf(yang_pool, yang_pool->domain, "YANG API %s", ac->name);
  struct yang_api *api = mb_allocz(p, sizeof *api);

  api->name = ac->name;
  api->pool = p;
  api->config = ac;
  api->params = ac->params;

  WALK_TLIST(yang_socket_config, sc, &ac->listen)
    yang_socket_new(api, sc);
}

static void
yang_api_delete(struct yang_api *api)
{
  WALK_TLIST_DELSAFE(yang_socket, s, &api->listen)
    yang_socket_delete(s);

  ASSERT_DIE(EMPTY_TLIST(yang_socket, &api->listen));

  api->config->api = NULL;

  rp_free(api->pool);
}

static void
yang_api_reconfigure(struct yang_api *api)
{
  /* Match sockets to new config */
  WALK_TLIST(yang_socket_config, sc, &api->config->listen)
  {
    /* Looking for the same socket */
    WALK_TLIST(yang_socket, s, &api->listen)
      if (yang_socket_same(&s->params, &sc->params))
	/* Found same */
      {
	ASSERT_DIE(yang_socket_config_enlisted(s->config) != &api->config->listen);
	/* Drop the old config pointer */
	s->config->socket = NULL;

	/* Set the new pointers */
	s->config = sc;
	sc->socket = s;

	break;
      }

    /* Not found */
    if (!sc->socket)
      yang_socket_new(api, sc);
  }

  /* Delete sockets not defined in new config */
  WALK_TLIST_DELSAFE(yang_socket, s, &api->listen)
    if (yang_socket_config_enlisted(s->config) != &api->config->listen)
      yang_socket_delete(s);

}

void
yang_commit(struct config *new, struct config *old)
{
  /* Match running APIs to new config */
  WALK_TLIST(yang_api_config, ac, &new->yang)
  {

    /* Is there an API with the same name?
     * Note: We expect the users to not have lots of API endpoints configured,
     * and therefore this is ok being O(N^2). */
    WALK_TLIST(yang_api, api, &global_api_list)
      if (!strcmp(api->name, ac->name))
      {
	ASSERT_DIE(api->config->global == old);
	ASSERT_DIE(api->config->api == api);

	if (yang_api_same(&api->params, &ac->params))
	  /* Found same, keep */
	{
	  /* Drop the old config pointer */
	  api->config->api = NULL;

	  /* Set the new pointers */
	  api->config = ac;
	  ac->api = api;

	  /* The name is shared with the symbol */
	  api->name = ac->name;

	  /* Reconfigure sockets */
	  yang_api_reconfigure(api);
	}

	/* Otherwise, we just pretend nothing was found */
	break;
      }

    /* Found same, done */
    if (ac->api)
      continue;

    /* Make new API endpoint */
    yang_api_new(ac);
  }

  /* Find unmatched endpoints and delete them */
  WALK_TLIST_DELSAFE(yang_api, api, &global_api_list)
    if (api->config->global != new)
    {
      api->config->api = NULL;
      yang_api_delete(api);
    }

  /* Consistency check of the old config */
  WALK_TLIST(yang_api_config, ac, &new->yang)
    ASSERT_DIE(!ac->api);
}

/**
 * yang_init - initialize needed YANG data structures on startup
 */
void
yang_init(void)
{
  yang_pool = rp_new(&root_pool, root_pool.domain, "YANG API toplevel");
}
