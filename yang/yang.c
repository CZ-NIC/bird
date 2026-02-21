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

static bool yang_default_endpoint(struct yang_session *se);

static bool
yang_model_cli_endpoint_wellknown_core(struct yang_session *se)
{
  struct yang_socket *s = se->socket;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  switch (se->coap.parser.state) {
    case COAP_PS_MORE:
    case COAP_PS_HEADER:
      log(L_ERR "%s: Unexpected state in endpoint (TODO bad)", api->name);
      return false;

    case COAP_PS_ERROR:
      log(L_ERR "%s: CoAP error in endpoint (TODO bad)", api->name);
      return false;

    case COAP_PS_OPTION_PARTIAL:
    case COAP_PS_OPTION_COMPLETE:
      switch (se->coap.parser.option_type) {
	case COAP_OPT_URI_QUERY:
	  log(L_INFO "URI Query (%u-%u/%u): %.*s",
	      se->coap.parser.option_chunk_offset,
	      se->coap.parser.option_chunk_offset + se->coap.parser.option_chunk_len,
	      se->coap.parser.option_len,
	      se->coap.parser.option_chunk_len, se->coap.parser.option_value);
	  break;
	default:
	  if (se->coap.parser.option_type & COAP_OPT_F_CRITICAL)
	  {
	    /* TODO: make this a macro or func */
	    log(L_INFO "Unhandled option %u, fail / TODO copy token", se->coap.parser.option_type);
	    if (!se->error_sent)
	    {
	      struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
		  0, "Unhandled option %u", se->coap.parser.option_type);
	      coap_tx_send(&se->coap, COAP_TX_FRAME(COAP_CERR_BAD_OPTION, payload));
	      se->error_sent = true;
	    }
	  }
      }
      return true;

    case COAP_PS_PAYLOAD_COMPLETE:
      /* TODO: make this a macro or func? */
      se->endpoint = yang_default_endpoint;

      /* fall through */

    case COAP_PS_PAYLOAD_PARTIAL:
      log(L_INFO "Payload (%u-%u/%u)", se->coap.parser.payload_chunk_offset,
	  se->coap.parser.payload_chunk_offset + se->coap.parser.payload_chunk_len,
	  se->coap.parser.payload_total_len);

      return true;

    default:
      bug("what the hell");

  }
}

static const struct yang_url_node
yang_model_cli_wellknown_core = {
  .endpoint = yang_model_cli_endpoint_wellknown_core,
  .stem = "core",
  .children = {
    NULL
  },
},
yang_model_cli_wellknown = {
  .stem = ".well-known",
  .children = {
    &yang_model_cli_wellknown_core,
    NULL
  },
},
yang_model_cli_root = {
  NULL, NULL, {
    &yang_model_cli_wellknown,
    NULL
  },
};

const struct yang_url_node *yang_url_tree[YANG_MODEL__MAX] = {
  NULL, &yang_model_cli_root,
};

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

static void
yang_session_rx_option(struct yang_session *se)
{
  if (se->coap.parser.option_type > COAP_OPT_URI_PATH)
  {
    /* This should have been already resolved by COAP_OPT_URI_PATH
     * and ending up here means wrong path */
    log(L_INFO "Error 4.04: Not Found (TODO)");
    return;
  }

  switch (se->coap.parser.option_type) {
    case COAP_OPT_URI_HOST:
      log(L_INFO "URI Host (%u-%u/%u): %.*s",
	  se->coap.parser.option_chunk_offset,
	  se->coap.parser.option_chunk_offset + se->coap.parser.option_chunk_len,
	  se->coap.parser.option_len,
	  se->coap.parser.option_chunk_len, se->coap.parser.option_value);
      return;

    case COAP_OPT_URI_PORT:
      log(L_INFO "URI Port");
      return;

    case COAP_OPT_URI_PATH:
      log(L_INFO "URI Path (%u-%u/%u): %.*s",
	  se->coap.parser.option_chunk_offset,
	  se->coap.parser.option_chunk_offset + se->coap.parser.option_chunk_len,
	  se->coap.parser.option_len,
	  se->coap.parser.option_chunk_len, se->coap.parser.option_value);

      ASSERT_DIE(se->url_pos == se->coap.parser.option_chunk_offset);

      while (*se->url)
	if (!strncmp(&(*se->url)->stem[se->url_pos], se->coap.parser.option_value, se->coap.parser.option_chunk_len))
	{
	  if (se->coap.parser.option_chunk_offset + se->coap.parser.option_chunk_len == se->coap.parser.option_len)
	  {
	    se->endpoint = ((*se->url)->endpoint) ?: yang_default_endpoint;
	    se->url = (*se->url)->children;
	    return;
	  }
	  break;
	}
	else
	  se->url++;

      if (!*se->url)
	log(L_INFO "Error 4.04: Not Found (TODO)");

      return;

    default:
      if (se->coap.parser.option_type & COAP_OPT_F_CRITICAL)
      {
	log(L_INFO "Unhandled option %u, fail", se->coap.parser.option_type);
	if (!se->error_sent)
	{
	  struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
	      0, "Unhandled option %u", se->coap.parser.option_type);
	  coap_tx_send(&se->coap, COAP_TX_FRAME(COAP_CERR_BAD_OPTION, payload));
	  se->error_sent = true;
	}
      }
      return;
  }
}

static bool
yang_default_endpoint(struct yang_session *se)
{
  enum coap_parse_state state = se->coap.parser.state;
  struct yang_socket *s = se->socket;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  log(L_TRACE "state is %d", state);
  switch (state) {
    case COAP_PS_MORE:
      return false;

    case COAP_PS_ERROR:
      log(L_ERR "%s: CoAP error, closing", api->name);
      se->sock->rx_hook = NULL;
      return false;

    case COAP_PS_HEADER:
      /* Reset all required data structures so that we can process the options */
      se->error_sent = false;
      se->url = &yang_url_tree[api->params.model]->children[0];
      se->url_pos = 0;
      return true;

    case COAP_PS_OPTION_PARTIAL:
    case COAP_PS_OPTION_COMPLETE:
      yang_session_rx_option(se);
      return true;

    case COAP_PS_PAYLOAD_PARTIAL:
    case COAP_PS_PAYLOAD_COMPLETE:
      /* If found, the endpoint function should not be this one */
      log(L_INFO "Error 4.04: Not Found (TODO)");
      return true;

    default:
      log(L_INFO "Dummy: Status %u", state);
      return false;
  }
}

static int
yang_session_rx(sock *sk, uint size)
{
  struct yang_session *se = sk->data;
  struct yang_socket *s = se->socket;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  log(L_TRACE "%s: RX data", api->name);

  /* Check the received data in */
  coap_tcp_rx(&se->coap, sk->rbuf, size);

  while (true)
  {
    /* Aggresively send data if possible */
    coap_tx_flush(&se->coap, sk);

    /* Next parser step */
    if (!coap_tcp_parse(&se->coap))
      return 1;

    /* It may be CoAP internal */
    if (coap_process(&se->coap))
      continue;

    /* Or the current endpoint will take care */
    if (se->endpoint(se))
      continue;

    /* Send remaining data if possible */
    coap_tx_flush(&se->coap, sk);
    return 1;
  }
}

static void
yang_session_tx(sock *sk)
{
  struct yang_session *se = sk->data;

  coap_tx_written(&se->coap, sk);
  coap_tx_flush(&se->coap, sk);
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
  se->endpoint = yang_default_endpoint;

  coap_session_init(&se->coap);

  sk->rx_hook = yang_session_rx;
  sk->tx_hook = yang_session_tx;
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
