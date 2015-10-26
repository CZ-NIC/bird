/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	Using RTRLib: http://rpki.realmv6.org/
 *
 *	(c) 2015 CZ.NIC
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: The Resource Public Key Infrastructure (RPKI) to Router Protocol
 */

/*
 * TODO
 *  - Make correct log depending on protocol option 'debug all|off|{ states, routes, filters, interfaces, events, packets }'
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

#define RPKI_LOG_ADD "add"
#define RPKI_LOG_DEL "del"
#define RPKI_LOG_ENTRY_FMT(ip_fmt) " roa " ip_fmt "/%u max %u as %u"
#define RPKI_LOG_FMT(operation_name) operation_name RPKI_LOG_ENTRY_FMT("%I")
#define RPKI_LOG_SKIP_FMT(operation_name) operation_name RPKI_LOG_ENTRY_FMT("%s") " skipped incompatible IP version"

static inline const char *
get_rtr_socket_ident(const struct rtr_socket *socket)
{
  return socket->tr_socket->ident_fp(socket->tr_socket->socket);
}
#define RPKI_CACHE_TRACE(p, rtr_socket, msg, args...) RPKI_TRACE(p, "%s " msg, get_rtr_socket_ident(rtr_socket), ## args);
#define RPKI_CACHE_ERROR(p, rtr_socket, msg, args...) RPKI_ERROR(p, "%s " msg, get_rtr_socket_ident(rtr_socket), ## args);

struct rpki_entry {
  node n;
  u32 asn;
  ip_addr ip;
  u8 pxlen;
  u8 maxlen;
  u8 added;
};

void pipe_drain(int fd); 	/* implementation in io.c */
void pipe_kick(int fd); 	/* implementation in io.c */

static list rpki_proto_list;
static pthread_mutex_t rpki_proto_list_lock;

/* RTRLib and function pointers */
static void *rtrlib;
static struct rtr_mgr_config * (*rtr_mgr_init_x)(
    struct rtr_mgr_group groups[], const unsigned int groups_len,
    const unsigned int refresh_interval, const unsigned int expire_interval,
    const void *update_fp,
    const void *spki_update_fp,
    const void *status_fp,
    void *status_fp_data);
static int (*rtr_mgr_start_x)(struct rtr_mgr_config *config);
static const char * (*rtr_state_to_str_x)(enum rtr_socket_state state);
static const char * (*rtr_mgr_status_to_str_x)(enum rtr_mgr_status status);
static int (*tr_tcp_init_x)(const struct tr_tcp_config *config, struct tr_socket *socket);
static int (*tr_ssh_init_x)(const struct tr_ssh_config *config, struct tr_socket *socket);
static void (*tr_free_x)(struct tr_socket *tr_sock);
static void (*rtr_mgr_stop_x)(struct rtr_mgr_config *config);
static void (*rtr_mgr_free_x)(struct rtr_mgr_config *config);

static inline void
lock_rpki_proto_list(void)
{
  pthread_mutex_lock(&rpki_proto_list_lock);
}

static inline void
unlock_rpki_proto_list(void)
{
  pthread_mutex_unlock(&rpki_proto_list_lock);
}

/*
 * Try load system shared library RTRLib
 * Return NULL pointer if successful
 * Otherwise return a pointer to a description of the error
 */
char *
rpki_load_rtrlib(void)
{
  char *err_buf = NULL;

  if (rtrlib != NULL)
    return NULL; /* RTRLib is loaded already */

  const char *rtrlib_name = RPKI_LIBRTR_DEFAULT;

#ifdef LIBRTR
  rtrlib_name = LIBRTR; /* Use a compile variable */
#endif

  rtrlib = dlopen(rtrlib_name, RTLD_LAZY);
  if (!rtrlib)
  {
    /* This would be probably often repeated problem */
    char *help_msg = "Try recompile BIRD with CFLAGS='-DLIBRTR=\\\"/path/to/librtr.so\\\"' "
	"or see BIRD User's Guide for more information.";
    err_buf = mb_alloc(&root_pool, 512);
    bsnprintf(err_buf, 512, "%s. %s", dlerror(), help_msg);
    return err_buf;
  }

  dlerror(); /* Clear any existing error */

  rtr_mgr_init_x = (struct rtr_mgr_config * (*)(
      struct rtr_mgr_group groups[], const unsigned int groups_len,
      const unsigned int refresh_interval, const unsigned int expire_interval,
      const void *update_fp,
      const void *spki_update_fp,
      const void *status_fp,
      void *status_fp_data)) dlsym(rtrlib, "rtr_mgr_init");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  rtr_mgr_start_x = (int (*)(struct rtr_mgr_config *)) dlsym(rtrlib, "rtr_mgr_start");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  rtr_state_to_str_x = (const char * (*)(enum rtr_socket_state state)) dlsym(rtrlib, "rtr_state_to_str");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  rtr_mgr_status_to_str_x = (const char * (*)(enum rtr_mgr_status status)) dlsym(rtrlib, "rtr_mgr_status_to_str");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  tr_tcp_init_x = (int (*)(const struct tr_tcp_config *config, struct tr_socket *socket)) dlsym(rtrlib, "tr_tcp_init");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  tr_ssh_init_x = (int (*)(const struct tr_ssh_config *config, struct tr_socket *socket)) dlsym(rtrlib, "tr_ssh_init");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  tr_free_x = (void (*)(struct tr_socket *)) dlsym(rtrlib, "tr_free");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  rtr_mgr_stop_x = (void (*)(struct rtr_mgr_config *config)) dlsym(rtrlib, "rtr_mgr_stop");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  rtr_mgr_free_x = (void (*)(struct rtr_mgr_config *config)) dlsym(rtrlib, "rtr_mgr_free");
  if ((err_buf = dlerror()) != NULL)
    return err_buf;

  return NULL; /* OK */
}

void
rpki_init_all(void)
{
  init_list(&rpki_proto_list);
  pthread_mutex_init(&rpki_proto_list_lock, NULL);
  rtrlib = NULL;
}

static const char *rtr_socket_states[] = {
    [RTR_CONNECTING]  = "Socket is establishing the transport connection",
    [RTR_ESTABLISHED] = "Connection is established, socket is waiting for a Serial Notify or expiration of the refresh_interval timer",
    [RTR_RESET] = "Resetting RTR connection",
    [RTR_SYNC] = "Receiving validation records from the RTR server",
    [RTR_FAST_RECONNECT] = "Reconnect without any waiting period",
    [RTR_ERROR_NO_DATA_AVAIL] = "No validation records are available on the RTR server",
    [RTR_ERROR_NO_INCR_UPDATE_AVAIL] = "Server was unable to answer the last serial or reset query",
    [RTR_ERROR_FATAL] = "Fatal protocol error occurred",
    [RTR_ERROR_TRANSPORT] = "Error on the transport socket occurred",
    [RTR_SHUTDOWN] = "RTR Socket is stopped",
};

static void
rtr_mgr_thread_status_hook(const struct rtr_mgr_group *group, enum rtr_mgr_status status, const struct rtr_socket *socket, void *data)
{
  struct rpki_proto *p = data;

  switch (status)
  {
    case RTR_MGR_ERROR:
      RPKI_CACHE_ERROR(p, socket, "%s", rtr_socket_states[socket->state]);
      break;
    default:
      RPKI_CACHE_TRACE(p, socket, "[%s] %s", rtr_state_to_str_x(socket->state), rtr_socket_states[socket->state]);
  }

  switch (status)
  {
    case RTR_MGR_CONNECTING:
      proto_notify_state(&p->p, PS_START);	// TODO: must be in main BIRD thread
      break;
    case RTR_MGR_ESTABLISHED:			// BIRD is synchronized with all cache servers within the same preference cache group
      proto_notify_state(&p->p, PS_UP);		// TODO: must be in main BIRD thread
      break;
  }
}

/* This seems useless, TODO: Remove it */
static void
rtr_thread_status_hook(const struct rtr_socket *socket, const enum rtr_socket_state status, void *data)
{
  struct rpki_proto *p = data;

  RPKI_CACHE_TRACE(p, socket, "[%s == %s] %s == %s", rtr_state_to_str_x(socket->state), rtr_state_to_str_x(status), rtr_socket_states[socket->state], rtr_socket_states[status]);

  switch (status)
  {
    case RTR_SHUTDOWN:
      break;

    case RTR_ERROR_FATAL:
    case RTR_ERROR_TRANSPORT:
    case RTR_ERROR_NO_DATA_AVAIL: /** No validation records are available on the RTR server. */
    case RTR_ERROR_NO_INCR_UPDATE_AVAIL: /** Server was unable to answer the last serial or reset query. */
      RPKI_CACHE_ERROR(p, socket, "%s", rtr_socket_states[socket->state]);
      break;

    case RTR_FAST_RECONNECT:
    case RTR_SYNC:
    case RTR_RESET:
    case RTR_CONNECTING:
      proto_notify_state(&p->p, PS_START);
      break;

    case RTR_ESTABLISHED:
      proto_notify_state(&p->p, PS_UP);
      break;
  }
}

static void
log_skipped_entry(struct rpki_proto *p, const struct pfx_record *rec, const bool added)
{
  char ip_buf[INET6_ADDRSTRLEN];
  ip4_addr ip4;
  ip6_addr ip6;

  if (rec->prefix.ver == RTRLIB_IPV4)
  {
    ip4 = ip4_from_u32(rec->prefix.u.addr4.addr);
    ip4_ntop(ip4, ip_buf);
  }
  else
  {
    ip6 = ip6_build(rec->prefix.u.addr6.addr[0], rec->prefix.u.addr6.addr[1], rec->prefix.u.addr6.addr[2], rec->prefix.u.addr6.addr[3]);
    ip6_ntop(ip6, ip_buf);
  }

  if (added)
  {
    RPKI_CACHE_TRACE(p, rec->socket, RPKI_LOG_SKIP_FMT(RPKI_LOG_ADD), ip_buf, rec->min_len, rec->max_len, rec->asn);
  }
  else
  {
    RPKI_CACHE_TRACE(p, rec->socket, RPKI_LOG_SKIP_FMT(RPKI_LOG_DEL), ip_buf, rec->min_len, rec->max_len, rec->asn);
  }
}

/*
 * Return (struct rpki_proto *) or NULL
 */
static struct rpki_proto *
get_rpki_proto_by_rtr_socket(const struct rtr_socket *socket)
{
  struct rpki_proto *p_not_skipped_back;
  unsigned int i, j;

  lock_rpki_proto_list();
  WALK_LIST(p_not_skipped_back, rpki_proto_list)
  {
    struct rpki_proto *p = SKIP_BACK(struct rpki_proto, rpki_node, p_not_skipped_back);

    for (i = 0; i < p->rtr_conf->len; i++)
    {
      for (j = 0; j < p->rtr_conf->groups[i].sockets_len; j++)
      {
	if (socket == p->rtr_conf->groups[i].sockets[j])
	{
	  unlock_rpki_proto_list();
	  return p;
	}
      }
    }
  }
  unlock_rpki_proto_list();
  return NULL; /* FAIL */
}

static void
send_data_to_main_thread(struct rpki_proto *p, struct rpki_entry *e)
{
  rpki_lock_notify(p);
  add_tail(&p->roa_update_list, &e->n);
  rpki_unlock_notify(p);
  pipe_kick(p->roa_update.write->fd);
}

static void
rtr_thread_update_hook(void *pfx_table, const struct pfx_record rec, const bool added)
{
  struct rpki_proto *p = get_rpki_proto_by_rtr_socket(rec.socket);
  if (!p)
  {
    bug("rtr_thread_update_hook: Cannot find matching protocol for %s\n", get_rtr_socket_ident(rec.socket));
    return;
  }
  /* process only records that are the same with BIRD IP version */
#ifdef IPV6
  if (rec.prefix.ver != RTRLIB_IPV6)
  {
    log_skipped_entry(p, &rec, added);
    return;
  }

  ip_addr ip = ip6_build(rec.prefix.u.addr6.addr[0], rec.prefix.u.addr6.addr[1], rec.prefix.u.addr6.addr[2], rec.prefix.u.addr6.addr[3]);
#else
  if (rec.prefix.ver != RTRLIB_IPV4)
  {
    log_skipped_entry(p, &rec, added);
    return;
  }

  ip_addr ip = ip4_from_u32(rec.prefix.u.addr4.addr);
#endif

  /* TODO: Make more effective solution with thread-safe recycle-able pool/queue of rpki_entry structures
   *       without endless allocations and frees */
  struct rpki_entry *e = mb_allocz(p->p.pool, sizeof(struct rpki_entry));
  e->added = added;
  e->asn = rec.asn;
  e->ip = ip;
  e->pxlen = rec.min_len;
  e->maxlen = rec.max_len;

  if (e->added)
  {
    RPKI_CACHE_TRACE(p, rec.socket, RPKI_LOG_FMT(RPKI_LOG_ADD), e->ip, e->pxlen, e->maxlen, e->asn);
  }
  else
  {
    RPKI_CACHE_TRACE(p, rec.socket, RPKI_LOG_FMT(RPKI_LOG_DEL), e->ip, e->pxlen, e->maxlen, e->asn);
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
  cache->preference = RPKI_DEFAULT_CACHE_PREFERENCE;
  /* cache port will be set afterwards */
  return cache;
}

static int
recv_data_in_main_thread(struct birdsock *sk, int size)
{
  struct rpki_proto *p = sk->data;
  struct rpki_entry *e;
  list tmp_list;

  pipe_drain(sk->fd);

  rpki_lock_notify(p);
  init_list(&tmp_list);
  add_tail_list(&tmp_list, &p->roa_update_list);
  init_list(&p->roa_update_list);
  rpki_unlock_notify(p);

  WALK_LIST_FIRST(e, tmp_list)
  {
    rpki_lock_notify(p);
    rem2_node(&e->n);
    rpki_unlock_notify(p);

    if (e->added)
      roa_add_item(p->cf->roa_table_cf->table, e->ip, e->pxlen, e->maxlen, e->asn, ROA_SRC_RPKI);
    else
      roa_delete_item(p->cf->roa_table_cf->table, e->ip, e->pxlen, e->maxlen, e->asn, ROA_SRC_RPKI);
    mb_free(e);
  }

  return 0;
}

static void
recv_err_in_main_thread(struct birdsock *sk, int err)
{
  struct rpki_proto *p = sk->data;
  RPKI_ERROR(p, "Notify socket error: %m", err);
}

static sock *
create_pipe(struct rpki_proto *p, int fd)
{
  sock *sk = sk_new(p->p.pool);
  sk->type = SK_MAGIC;
  sk->fd = fd;
  sk->data = p;
  return sk;
}

static sock *
create_read_pipe(struct rpki_proto *p, int fd)
{
  sock *sk = create_pipe(p, fd);
  sk->rx_hook = recv_data_in_main_thread;
  sk->err_hook = recv_err_in_main_thread;
  if (sk_open(sk) < 0)
    return NULL;
  return sk;
}

static sock *
create_write_pipe(struct rpki_proto *p, int fd)
{
  sock *sk = create_pipe(p, fd);
  sk->flags = SKF_THREAD;
  if (sk_open(sk) < 0)
    return NULL;
  return sk;
}

static void
create_pipe_pair(struct rpki_proto *p, struct rpki_rw_sk_pair *sk_pair)
{
  int pipe_fildes[2];

  if ((pipe(pipe_fildes) < 0)
      || ((sk_pair->read = create_read_pipe(p, pipe_fildes[0])) == NULL)
      || ((sk_pair->write = create_write_pipe(p, pipe_fildes[1])) == NULL)
  )
    RPKI_DIE(p, "pipe: %m");
}

static uint
count_number_of_various_preferences(list *cache_list)
{
  uint i;
  u8 preference[256];
  bzero(preference, sizeof(preference));

  struct rpki_cache *cache;
  WALK_LIST(cache, *cache_list)
  {
    preference[cache->preference]++;
  }

  uint count = 0;
  for (i = 0; i < 256; i++)
  {
    if (preference[i])
      count++;
  }
  return count;
}

static uint
count_number_of_caches_with_specific_preference(list *cache_list, uint preference)
{
  uint count = 0;

  struct rpki_cache *cache;
  WALK_LIST(cache, *cache_list)
  {
    if (cache->preference == preference)
      count++;
  }

  return count;
}

static struct rtr_socket *
create_rtrlib_tcp_socket(struct rpki_cache *cache, pool *pool)
{
  struct rtr_socket *rtrlib_tcp = mb_allocz(pool, sizeof(struct rtr_socket));
  rtrlib_tcp->tr_socket = mb_allocz(pool, sizeof(struct tr_socket));

  struct tr_tcp_config tcp_config = {
      .host = cache->host,
      .port = cache->port
  };

  tr_tcp_init_x(&tcp_config, rtrlib_tcp->tr_socket);

  return rtrlib_tcp;
}

static struct rtr_socket *
create_rtrlib_ssh_socket(struct rpki_cache *cache, pool *pool)
{
  struct rtr_socket *rtrlib_ssh = mb_allocz(pool, sizeof(struct rtr_socket));
  rtrlib_ssh->tr_socket = mb_allocz(pool, sizeof(struct tr_socket));
  struct tr_ssh_config ssh_config = {
      .host = cache->host,
      .port = atoi(cache->port), /* TCP transport needs port in (char *) */
      .username = cache->ssh->user,
      .client_privkey_path = cache->ssh->bird_private_key,
      .server_hostkey_path = cache->ssh->cache_public_key,
  };

  tr_ssh_init_x(&ssh_config, rtrlib_ssh->tr_socket);

  return rtrlib_ssh;
}

static struct rtr_socket *
create_rtrlib_socket(struct rpki_proto *p, struct rpki_cache *cache, pool *pool)
{
  struct rtr_socket *s;
  if (cache->ssh)
    s = create_rtrlib_ssh_socket(cache, pool);
  else
    s = create_rtrlib_tcp_socket(cache, pool);

  s->connection_state_fp = &rtr_thread_status_hook;
  s->connection_state_fp_param = p;
  return s;
}

struct rtr_mgr_group_crate {
  struct rtr_mgr_group *groups;
  uint groups_len;
};

static struct rtr_mgr_group_crate
group_cache_list_by_preferences(struct rpki_proto *p, list *cache_list, pool *pool)
{
  /* TODO: Improve algorithm for grouping cache servers by preferences.
   * 	   At the beginning sort a list of caches by preferences... */

  u8 completed_preference[256];
  bzero(completed_preference, sizeof(completed_preference));

  uint groups_len = count_number_of_various_preferences(cache_list);
  struct rtr_mgr_group *groups = mb_allocz(pool, groups_len * sizeof(struct rtr_mgr_group));

  DBG("group_cache_list_by_preferences(): groups_len %u \n", groups_len);

  uint group_idx = 0;
  struct rpki_cache *first_cache_in_group;
  WALK_LIST(first_cache_in_group, *cache_list)
  {
    if (completed_preference[first_cache_in_group->preference])
      continue;
    completed_preference[first_cache_in_group->preference] = 1;

    struct rtr_mgr_group *group = &groups[group_idx];

    group->preference = first_cache_in_group->preference;
    group->sockets_len = count_number_of_caches_with_specific_preference(cache_list, first_cache_in_group->preference);
    group->sockets = mb_allocz(pool, group->sockets_len * sizeof(struct rtr_socket *));

    uint socket_idx = 0;
    struct rpki_cache *cache;
    WALK_LIST(cache, *cache_list)
    {
      if (cache->preference == groups[group_idx].preference)
      {
	group->sockets[socket_idx] = cache->rtrlib_sock = create_rtrlib_socket(p, cache, pool);
	DBG("group_cache_list_by_preferences(): add cache %s:%s to group %u, socket %u \n", cache->host, cache->port, group_idx, socket_idx);
	socket_idx++;
      }
    }
    group_idx++;
  }

  return (struct rtr_mgr_group_crate) {groups, groups_len};
}

/*
 * Return RTR_SUCCESS or RTR_ERROR
 */
static int
rpki_start_rtrlib_mgr(struct rpki_proto *p, struct rpki_config *cf)
{
  struct rtr_mgr_group_crate grouped_list = group_cache_list_by_preferences(p, &cf->cache_list, p->p.pool);

  p->rtr_conf = rtr_mgr_init_x(grouped_list.groups, grouped_list.groups_len, 10, 20, &rtr_thread_update_hook, NULL, &rtr_mgr_thread_status_hook, p);

  return rtr_mgr_start_x(p->rtr_conf);
}

static int
rpki_start(struct proto *P)
{
  struct rpki_proto *p = (struct rpki_proto *) P;
  struct rpki_config *cf = (struct rpki_config *) (P->cf);

  create_pipe_pair(p, &p->roa_update);
  init_list(&p->roa_update_list);
  pthread_mutex_init(&p->roa_update_lock, NULL);

  lock_rpki_proto_list();
  add_tail(&rpki_proto_list, &p->rpki_node);
  unlock_rpki_proto_list();

  if (rpki_start_rtrlib_mgr(p, cf) != RTR_SUCCESS)
  {
    RPKI_ERROR(p, "Cannot start RTRLib Manager");
    return PS_DOWN;
  }

  return PS_START;
}

static void
rpki_stop_and_free_rtrlib_mgr(struct rpki_proto *p)
{
  RPKI_TRACE(p, "Stopping RTRLib Manager");

  rtr_mgr_stop_x(p->rtr_conf);	/* this takes long time */
  rtr_mgr_free_x(p->rtr_conf);

  struct rpki_cache *cache;
  WALK_LIST(cache, p->cf->cache_list)
  {
    if (cache->rtrlib_sock)
    {
      tr_free_x(cache->rtrlib_sock->tr_socket);

      mb_free(cache->rtrlib_sock->tr_socket);
      mb_free(cache->rtrlib_sock);
    }
  }
}

static int
rpki_shutdown(struct proto *P)
{
  struct rpki_proto *p = (struct rpki_proto *) P;

  log(L_DEBUG "------------- rpki_shutdown -------------");

  rpki_stop_and_free_rtrlib_mgr(p);

  lock_rpki_proto_list();
  rem2_node(&p->rpki_node);
  unlock_rpki_proto_list();

  pthread_mutex_destroy(&p->roa_update_lock);

  return PS_DOWN;
}

static struct rpki_cache *
get_cache_by_host_and_port(list *cache_list, struct rpki_cache *needle)
{
  struct rpki_cache *cache;
  WALK_LIST(cache, *cache_list)
  {
    if ((strcmp(needle->host, cache->host) == 0) && (strcmp(needle->port, cache->port) == 0))
    {
      return cache;
    }
  }
  return NULL;
}

/*
 * Return 1 if need to restart rtrlib manager
 * Return 0 if not need to restart rtrlib manager
 */
static int
is_required_restart_rtrlib_mgr(struct rpki_proto *p, struct rpki_config *new_cf)
{
  struct rpki_config *old_cf = p->cf;

  struct rpki_cache *cache;
  WALK_LIST(cache, old_cf->cache_list)
  {
    struct rpki_cache *match = get_cache_by_host_and_port(&new_cf->cache_list, cache);
    if (!match)
    {
      /* some cache was deleted from old configuration */
      RPKI_WARN(p, "reconfiguration has no match for cache %s:%s", cache->host, cache->port);
      return 1; /* TODO: maybe can be called only rtr_stop(); without manager restart */
    }

    if (cache->preference != match->preference || (!!cache->ssh != !!match->ssh))
      return 1;

    if (cache->ssh && match->ssh)
    {
      if (strcmp(cache->ssh->bird_private_key, match->ssh->bird_private_key) != 0)
	return 1;

      if (strcmp(cache->ssh->cache_public_key, match->ssh->cache_public_key) != 0)
	return 1;

      if (strcmp(cache->ssh->user, match->ssh->user) != 0)
	return 1;
    }
  }

  WALK_LIST(cache, new_cf->cache_list)
  {
    struct rpki_cache *match = get_cache_by_host_and_port(&new_cf->cache_list, cache);
    if (!match)
    {
      /* some cache was added to new configuration */
      return 1;
    }
  }

  return 0; /* no restart required */
}

static int
rpki_reconfigure(struct proto *P, struct proto_config *c)
{
  struct rpki_proto *p = (struct rpki_proto *) P;
  struct rpki_config *new_cf = (struct rpki_config *) c;

  RPKI_TRACE(p, "------------- rpki_reconfigure -------------");

  if (is_required_restart_rtrlib_mgr(p, new_cf))
  {
    RPKI_TRACE(p, "Reconfiguration: Something changed, RTRLib Manager must be restarted");
    if (P->proto_state != PS_DOWN)
      rpki_stop_and_free_rtrlib_mgr(p);

    if (rpki_start_rtrlib_mgr(p, new_cf) != RTR_SUCCESS)
    {
      RPKI_ERROR(p, "Reconfiguration failed: Cannot start RTRLib Manager");
      p->cf = new_cf;
      return 0; /* FAIL */
    }
  }
  p->cf = new_cf;
  return 1; /* OK */
}

static void
rpki_get_status(struct proto *P, byte *buf)
{
  struct rpki_proto *p = (struct rpki_proto *) P;
  unsigned int i, j;

  uint established_connections = 0;
  uint cache_servers = 0;

  for (i = 0; i < p->rtr_conf->len; i++)
  {
    for (j = 0; j < p->rtr_conf->groups[i].sockets_len; j++)
    {
      cache_servers++;
      switch (p->rtr_conf->groups[i].sockets[j]->state)
      {
	case RTR_ESTABLISHED:
	case RTR_RESET:
	case RTR_SYNC:
	  established_connections++;
	  break;
      }
    }
  }

  if (established_connections == 1)
    bsprintf(buf, "Keep synchronized with 1 cache server");
  else if (established_connections > 1)
    bsprintf(buf, "Keep synchronized with %u cache servers", established_connections);
  else if (cache_servers == 0)
    bsprintf(buf, "No cache server is configured");
  else if (cache_servers == 1)
    bsprintf(buf, "Cannot connect to cache server");
  else
    bsprintf(buf, "Cannot connect to any cache servers");
}

struct protocol proto_rpki = {
  .name = 		"RPKI",
  .template = 		"rpki%d",
  .config_size =	sizeof(struct rpki_config),
  .init = 		rpki_init,
  .start = 		rpki_start,
  .shutdown = 		rpki_shutdown,
  .reconfigure = 	rpki_reconfigure,
  .get_status = 	rpki_get_status,
};
