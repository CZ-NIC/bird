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
#include <pthread.h>
#include <dlfcn.h>

#include "proto/rpki/rpki.h"
#include "lib/socket.h"
#include "lib/ip.h"
#include "nest/route.h"

struct rpki_entry {
  node n;
  u32 asn;
  ip_addr ip;
  u8 pxlen;
  u8 maxlen;
  u8 added;
  struct rpki_proto *rpki;
};

void pipe_drain(int fd); 	/* implementation in io.c */
void pipe_kick(int fd); 	/* implementation in io.c */

static list rpki_proto_list;

static void *rtrlib;
static struct rtr_mgr_config * (*rtr_mgr_init_fp)(
    struct rtr_mgr_group groups[], const unsigned int groups_len,
    const unsigned int refresh_interval, const unsigned int expire_interval,
    const void *update_fp,
    const void *spki_update_fp,
    const void *status_fp,
    void *status_fp_data);
static int (*rtr_mgr_start_fp)(struct rtr_mgr_config *config);
static const char * (*rtr_state_to_str_fp)(enum rtr_socket_state state);
static const char * (*rtr_mgr_status_to_str_fp)(enum rtr_mgr_status status);
static int (*tr_tcp_init_fp)(const struct tr_tcp_config *config, struct tr_socket *socket);
static void (*rtr_mgr_stop_fp)(struct rtr_mgr_config *config);
static void (*rtr_mgr_free_fp)(struct rtr_mgr_config *config);

static int
was_dlsym_ok(struct rpki_proto *p)
{
  char *err_buffer = dlerror();

  if (err_buffer != NULL)
  {
    RPKI_ERROR(p, "%s. Try the latest version of RTRLib.", err_buffer);
    return 0; /* FAIL */
  }
  return 1; /* OK */
}

static int
load_rtrlib(struct rpki_proto *p)
{
  rtrlib = dlopen(p->cf->rtrlib_path, RTLD_LAZY);
  if (!rtrlib)
  {
    RPKI_ERROR(p, "dlopen(): %s. Try specify path to the shared RTRLib (http://rpki.realmv6.org/) with 'rtrlib' option"
		  "inside of the rpki protocol configuration", dlerror());
    return 0; /* FAIL */
  }
  else
  {
    RPKI_TRACE(p, "Loaded RTRLib from %s", p->cf->rtrlib_path);
  }

  dlerror();    /* Clear any existing error */

  rtr_mgr_init_fp = (struct rtr_mgr_config * (*)(
      struct rtr_mgr_group groups[], const unsigned int groups_len,
      const unsigned int refresh_interval, const unsigned int expire_interval,
      const void *update_fp,
      const void *spki_update_fp,
      const void *status_fp,
      void *status_fp_data)) dlsym(rtrlib, "rtr_mgr_init");
  if (!was_dlsym_ok(p))
    return 0; /* FAIL */

  rtr_mgr_start_fp = (int (*)(struct rtr_mgr_config *)) dlsym(rtrlib, "rtr_mgr_start");
  if (!was_dlsym_ok(p))
    return 0; /* FAIL */

  rtr_state_to_str_fp = (const char * (*)(enum rtr_socket_state state)) dlsym(rtrlib, "rtr_state_to_str");
  if (!was_dlsym_ok(p))
    return 0; /* FAIL */

  rtr_mgr_status_to_str_fp = (const char * (*)(enum rtr_mgr_status status)) dlsym(rtrlib, "rtr_mgr_status_to_str");
  if (!was_dlsym_ok(p))
    return 0; /* FAIL */

  tr_tcp_init_fp = (int (*)(const struct tr_tcp_config *config, struct tr_socket *socket)) dlsym(rtrlib, "tr_tcp_init");
  if (!was_dlsym_ok(p))
    return 0; /* FAIL */

  rtr_mgr_stop_fp = (void (*)(struct rtr_mgr_config *config)) dlsym(rtrlib, "rtr_mgr_stop");
  if (!was_dlsym_ok(p))
    return 0; /* FAIL */

  rtr_mgr_free_fp = (void (*)(struct rtr_mgr_config *config)) dlsym(rtrlib, "rtr_mgr_free");
  if (!was_dlsym_ok(p))
    return 0; /* FAIL */

  return 1; /* OK */
}

void
rpki_init_all(void)
{
  init_list(&rpki_proto_list);
  rtrlib = NULL;
}

static void
status_cb(const struct rtr_mgr_group *group, enum rtr_mgr_status status, const struct rtr_socket *socket, void *data)
{
  struct rpki_proto *p = data;

  if (status == RTR_MGR_ERROR)
  {
    RPKI_ERROR(p, "Error -> Should we here stop the protocol?"); /* FIXME */
  }
  else
  {
    RPKI_TRACE(p, "status: %s\t%s", (*rtr_mgr_status_to_str_fp)(status), (*rtr_state_to_str_fp)(socket->state));
  }
}

static void
send_data_to_main_thread(struct rpki_proto *p, struct rpki_entry *e)
{
  rpki_lock_sessions(p);
  add_tail(&p->notify_list, &e->n);
  rpki_unlock_sessions(p);

  pipe_kick(p->notify_write_sk->fd);
}

static void
log_skip_entry(struct rpki_proto *p, const struct pfx_record *rec, const bool added)
{
  char ip_buf[INET6_ADDRSTRLEN];
  ip4_addr ip4;
  ip6_addr ip6;

  if (rec->prefix.ver == RTRLIB_IPV4)
  {
    ip4 = ipa_from_u32(rec->prefix.u.addr4.addr);
    ip4_ntop(ip4, ip_buf);
  }
  else
  {
    ip6 = ip6_build(rec->prefix.u.addr6.addr[0], rec->prefix.u.addr6.addr[1], rec->prefix.u.addr6.addr[2], rec->prefix.u.addr6.addr[3]);
    ip6_ntop(ip6, ip_buf);
  }

#define RPKI_LOG_ADD "add"
#define RPKI_LOG_DEL "del"
#define RPKI_LOG_ENTRY_FMT(ip_fmt) " roa %-25" ip_fmt "/%u-%-3u ASN: %u"
#define RPKI_LOG_FMT(operation_name)              operation_name RPKI_LOG_ENTRY_FMT("I")
#define RPKI_LOG_SKIP_FMT(operation_name) "skip " operation_name RPKI_LOG_ENTRY_FMT("s") " (unsupported IP version)"

  if (added)
  {
    RPKI_TRACE(p, RPKI_LOG_SKIP_FMT(RPKI_LOG_ADD), ip_buf, rec->min_len, rec->max_len, rec->asn);
  }
  else
  {
    RPKI_TRACE(p, RPKI_LOG_SKIP_FMT(RPKI_LOG_DEL), ip_buf, rec->min_len, rec->max_len, rec->asn);
  }
}

static struct rpki_proto *
find_rpki_proto_by_rtr_socket(const struct rtr_socket *socket)
{
  struct rpki_proto *p_not_skipped_back;
  unsigned int i, j;

  WALK_LIST(p_not_skipped_back, rpki_proto_list)
  {
    struct rpki_proto *p = SKIP_BACK(struct rpki_proto, rpki_node, p_not_skipped_back);

    for(i = 0; i < p->rtr_conf->len; i++)
    {
      for(j = 0; j < p->rtr_conf->groups[i].sockets_len; j++)
      {
	if (socket == p->rtr_conf->groups[i].sockets[j])
	  return p;
      }
    }
  }

  return NULL;
}

static void
rtr_thread_update_hook(struct pfx_table *pfx_table, const struct pfx_record rec, const bool added)
{
  struct rpki_proto *p = find_rpki_proto_by_rtr_socket(rec.socket);

  /* process only records that are the same with BIRD IP version */
#ifdef IPV6
  if (rec.prefix.ver != RTRLIB_IPV6)
  {
    log_skip_entry(p, &rec);
    return;
  }
#else
  if (rec.prefix.ver != RTRLIB_IPV4)
  {
    log_skip_entry(p, &rec, added);
    return;
  }
#endif

#ifdef IPV6
  ip_addr ip = ip6_build(rec.prefix.u.addr6.addr[0], rec.prefix.u.addr6.addr[1], rec.prefix.u.addr6.addr[2], rec.prefix.u.addr6.addr[3]);
#else
  ip_addr ip = ipa_from_u32(rec.prefix.u.addr4.addr);
#endif

  struct rpki_entry *e = mb_allocz(p->p.pool, sizeof(struct rpki_entry));
  e->added = added;
  e->asn = rec.asn;
  e->ip = ip;
  e->pxlen = rec.min_len;
  e->maxlen = rec.max_len;
  e->rpki = p;

  if (e->added)
  {
    RPKI_TRACE(p, RPKI_LOG_FMT(RPKI_LOG_ADD), e->ip, e->pxlen, e->maxlen, e->asn);
  }
  else
  {
    RPKI_TRACE(p, RPKI_LOG_FMT(RPKI_LOG_DEL), e->ip, e->pxlen, e->maxlen, e->asn);
  }

  send_data_to_main_thread(p, e);
}

static struct proto *
rpki_init(struct proto_config *C)
{
  struct proto *P = proto_new(C, sizeof(struct rpki_proto));
  struct rpki_proto *p = (struct rpki_proto *) P;
  p->cf = (struct rpki_config *) C;

  RPKI_TRACE(p, "------------- rpki_init -------------");

  return P;
}

struct rpki_cache *
rpki_new_cache(void)
{
  struct rpki_cache *cache = (struct rpki_cache *)cfg_allocz(sizeof(struct rpki_cache));
  strcpy(cache->port, RPKI_PORT);
  cache->preference = ~0;
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
rpki_notify_hook(struct birdsock *sk, int size)
{
  struct rpki_proto *p = sk->data;
  struct rpki_entry *entry;

  pipe_drain(sk->fd);

  rpki_lock_sessions(p);
  /* TODO: optimize like in the BFD proto */
  WALK_LIST_FIRST(entry, p->notify_list)
  {
    rem2_node(&entry->n);
    if (entry->added)
      roa_add_item(p->cf->roa_table_cf->table, entry->ip, entry->pxlen, entry->maxlen, entry->asn, ROA_SRC_RPKI);
    else
      roa_delete_item(p->cf->roa_table_cf->table, entry->ip, entry->pxlen, entry->maxlen, entry->asn, ROA_SRC_RPKI);
  }
  rpki_unlock_sessions(p);
}

static void
rpki_noterr_hook(struct birdsock *sk, int err)
{
  struct rpki_proto *p = sk->data;
  RPKI_ERROR(p, "Notify socket error: %m", err);
}

static void
create_read_socket(struct rpki_proto *p, int fd)
{
  sock *sk = sk_new(p->p.pool);
  sk->type = SK_MAGIC;
  sk->fd = fd;
  sk->rx_hook = rpki_notify_hook;
  sk->err_hook = rpki_noterr_hook;
  sk->data = p;
  if (sk_open(sk) < 0)
    RPKI_DIE(p, "read socket sk_open() failed");
  p->notify_read_sk = sk;
}

static void
create_write_socket(struct rpki_proto *p, int fd)
{
  sock *sk = sk_new(p->p.pool);
  sk->type = SK_MAGIC;
  sk->fd = fd;
  sk->flags = SKF_THREAD;
  sk->data = p;
  if (sk_open(sk) < 0)
    RPKI_DIE(p, "write socket sk_open() failed");
  p->notify_write_sk = sk;
}

static void
create_rw_sockets(struct rpki_proto *p)
{
  int pipe_fildes[2];

  int rv = pipe(pipe_fildes);
  if (rv < 0)
    RPKI_DIE(p, "pipe: %m");

  create_read_socket (p, pipe_fildes[0]);
  create_write_socket(p, pipe_fildes[1]);
}

static int
rpki_start(struct proto *P)
{
  struct rpki_proto *p = (struct rpki_proto *) P;
  struct rpki_config *cf = (struct rpki_config *) (P->cf);

  RPKI_TRACE(p, "------------- rpki_start -------------");

  if (!rtrlib && !load_rtrlib(p))
    return PS_DOWN;

  create_rw_sockets(p);
  init_list(&p->notify_list);
  pthread_spin_init(&p->notify_lock, PTHREAD_PROCESS_PRIVATE);

  add_tail(&rpki_proto_list, &p->rpki_node);

  p->rtr_sockets_len = get_list_length(&cf->cache_list);
  p->rtr_groups = mb_allocz(P->pool, 1 * sizeof(struct rtr_mgr_group));
  struct rtr_mgr_group *groups = p->rtr_groups;

  p->rtr_sockets = mb_allocz(P->pool, p->rtr_sockets_len * sizeof(struct rtr_socket *));
  groups[0].sockets = p->rtr_sockets;
  groups[0].sockets_len = p->rtr_sockets_len;
  groups[0].preference = 1;

  uint idx = 0;
  struct rpki_cache *cache;
  WALK_LIST(cache, cf->cache_list)
  {
    /* TODO: Make them dynamic. Reconfigure reallocate structures */
    struct tr_tcp_config *tcp_config = &cache->tcp_config;
    struct rtr_socket *rtr_tcp = &cache->rtr_tcp;
    struct tr_socket *tr_tcp = &cache->tr_tcp;

    normalize_fulfillment_of_cache(cache);

    tcp_config->host = cache->full_domain_name;
    tcp_config->port = cache->port;
    (*tr_tcp_init_fp)(tcp_config, tr_tcp);

    // create an rtr_socket and associate it with the transport socket
    rtr_tcp->tr_socket = tr_tcp;

    groups[0].sockets[idx] = rtr_tcp;

    idx++;
  }

  p->rtr_conf = (*rtr_mgr_init_fp)(groups, 1, 30, 520, &rtr_thread_update_hook, NULL, &status_cb, p);
  (*rtr_mgr_start_fp)(p->rtr_conf);

  return PS_UP;
}

static int
rpki_shutdown(struct proto *P)
{
  struct rpki_proto *p = (struct rpki_proto *) P;

  (*rtr_mgr_stop_fp)(p->rtr_conf);
  (*rtr_mgr_free_fp)(p->rtr_conf);
  mb_free(p->rtr_groups);
  mb_free(p->rtr_sockets);

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
