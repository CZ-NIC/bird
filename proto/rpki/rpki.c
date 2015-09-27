/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: The Resource Public Key Infrastructure (RPKI) to Router Protocol
 */

#define LOCAL_DEBUG

#include <stdlib.h>
#include <unistd.h>

#include "proto/rpki/rpki.h"
#include "lib/socket.h"

struct proto *ugly_hack_to_get_proto;

static void status_cb(const struct rtr_mgr_group *group, enum rtr_mgr_status status, const struct rtr_socket *socket, void *data)
{
  struct rpki_proto *rpki = data;
  if(status == RTR_MGR_ERROR)
  {
    RPKI_TRACE(rpki, "Error -> Should we here stop the protocol?"); /* FIXME */
  }

  RPKI_TRACE(rpki, "Status: %s\t%s", rtr_mgr_status_to_str(status), rtr_state_to_str(socket->state));
}

static void update_cb(struct pfx_table *p, const struct pfx_record rec, const bool added)
{
  /* FIXME: update_cb() should have void *data attribute, same like status_cb() */
  struct proto *P = ugly_hack_to_get_proto;
  struct rpki_proto *rpki = (struct rpki_proto *) P;

  ip4_addr ip4 = {};
  ip6_addr ip6 = {};
  char ip[INET6_ADDRSTRLEN];
  if (rec.prefix.ver == RTRLIB_IPV4)
  {
    ip4 = ipa_from_u32(rec.prefix.u.addr4.addr);
    ip4_ntop(ip4, ip);
  }
  else
  {
    ip6 = ip6_build(rec.prefix.u.addr6.addr[0], rec.prefix.u.addr6.addr[1], rec.prefix.u.addr6.addr[2], rec.prefix.u.addr6.addr[3]);
    ip6_ntop(ip6, ip);
  }

  if(added)
  {
    RPKI_TRACE(rpki, "+++ %45s/%u-%-3u \tASN: %10u", ip, rec.min_len, rec.max_len, rec.asn);
//  P->rte_insert();
  }
  else
  {
    RPKI_TRACE(rpki, "--- %45s/%u-%-3u \tASN: %10u", ip, rec.min_len, rec.max_len, rec.asn);
//  P->rte_remove();
  }
}

static struct proto *
rpki_init(struct proto_config *C)
{
  struct proto *P = proto_new(C, sizeof(struct rpki_proto));
  struct rpki_proto *rpki = (struct rpki_proto *) P;
  struct rpki_config *cf = (struct rpki_config *) C;

  RPKI_TRACE(rpki, "------------- rpki_init -------------");

  ugly_hack_to_get_proto = P;

  /* TODO: Add defaults */
  return P;
}

struct rpki_cache *
rpki_new_cache(void)
{
  struct rpki_cache *cache = (struct rpki_cache *)cfg_allocz(sizeof(struct rpki_cache));
  strcpy(cache->port, RPKI_PORT);
  return cache;
}

static void
normalize_fulfillment_of_cache(struct rpki_cache *cache)
{
  if (cache->full_domain_name == NULL)
  {
    bsnprintf(cache->ip_buf, INET6_ADDRSTRLEN, "%I", cache->ip);
    cache->full_domain_name = cache->ip_buf;
  }

  bzero(&cache->rtr_tcp, sizeof(struct rtr_socket));
  bzero(&cache->tcp_config, sizeof(struct tr_tcp_config));
  bzero(&cache->tr_tcp, sizeof(struct tr_socket));
}

static int
rpki_start(struct proto *P)
{
  struct rpki_proto *rpki = (struct rpki_proto *) P;
  struct rpki_config *cf = (struct rpki_config *) (P->cf);

  RPKI_TRACE(rpki, "------------- rpki_start -------------");

  rpki->rtr_groups_len = get_list_length(&cf->cache_list);
  rpki->rtr_groups = mb_allocz(P->pool, rpki->rtr_groups_len * sizeof(struct rtr_mgr_group));
  struct rtr_mgr_group *groups = rpki->rtr_groups;

  uint idx = 0;
  struct rpki_cache *cache;
  WALK_LIST(cache, cf->cache_list)
  {
    struct tr_tcp_config *tcp_config = &cache->tcp_config;
    struct rtr_socket *rtr_tcp = &cache->rtr_tcp;
    struct tr_socket *tr_tcp = &cache->tr_tcp;

    normalize_fulfillment_of_cache(cache);

    tcp_config->host = cache->full_domain_name;
    tcp_config->port = cache->port;
    tr_tcp_init(tcp_config, tr_tcp);

    // create an rtr_socket and associate it with the transport socket
    rtr_tcp->tr_socket = tr_tcp;

    groups[idx].sockets = mb_allocz(P->pool, 1 * sizeof(struct rtr_socket *));
    groups[idx].sockets_len = 1;
    groups[idx].sockets[0] = rtr_tcp;
    groups[idx].preference = cache->preference;

    idx++;
  }

  rpki->rtr_conf = rtr_mgr_init(groups, rpki->rtr_groups_len, 30, 520, &update_cb, NULL, &status_cb, rpki);
  rtr_mgr_start(rpki->rtr_conf);

  return PS_UP;
}

static int
rpki_shutdown(struct proto *P)
{
  struct rpki_proto *rpki = (struct rpki_proto *) P;
  struct rpki_config *cf = (struct rpki_config *) (P->cf);

  RPKI_TRACE(rpki, "------------- rpki_shutdown -------------");

  rtr_mgr_stop(rpki->rtr_conf);
  rtr_mgr_free(rpki->rtr_conf);

  /* TODO: fix memory leaks created by start->disable->enable rpki protocol */

  return PS_DOWN;
}

static int
rpki_reconfigure(struct proto *p, struct proto_config *c)
{
  struct rpki_proto *rpki = (struct rpki_proto *) p;
  struct rpki_config *new = (struct rpki_config *) c;

  log(L_DEBUG "------------- rpki_reconfigure -------------");

  return 1;
}

static void
rpki_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct rpki_config *d = (struct rpki_config *) dest;
  struct rpki_config *s = (struct rpki_config *) src;

  log(L_DEBUG "------------- rpki_copy_config -------------");
}

static void
rpki_get_status(struct proto *p, byte *buf)
{
  struct proto_rpki *rpki = (struct proto_rpki *) p;

  log(L_DEBUG "------------- rpki_get_status -------------");
}

struct protocol proto_rpki = {
  .name = 		"RPKI",
  .template = 		"rpki%d",
//  .attr_class = 	EAP_BGP,
//  .preference = 	DEF_PREF_BGP,
  .config_size =	sizeof(struct rpki_config),
  .init = 		rpki_init,
  .start = 		rpki_start,
  .shutdown = 		rpki_shutdown,
//  .cleanup = 		rpki_cleanup,
  .reconfigure = 	rpki_reconfigure,
  .copy_config = 	rpki_copy_config,
  .get_status = 	rpki_get_status,
//  .get_attr = 		rpki_get_attr,
//  .get_route_info = 	rpki_get_route_info,
//  .show_proto_info = 	rpki_show_proto_info
};
