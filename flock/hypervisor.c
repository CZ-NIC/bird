#include "lib/birdlib.h"

#include "lib/resource.h"
#include "lib/io-loop.h"
#include "lib/socket.h"

#include "flock/flock.h"

#include <sys/socket.h>

/**
 * Main control socket
 **/

static struct birdloop *hcs_loop;
static pool *hcs_pool;

OBSREF(struct shutdown_placeholder) hcs_shutdown_placeholder;

static int
hcs_rx(sock *s, uint size)
{
  s64 sz = hcs_parse(s->data, s->rbuf, size);
  if (sz < 0)
  {
    log(L_INFO "CLI parser error at position %ld: %s", -sz-1, hcs_error(s->data));
    sk_close(s);
    return 0; /* Must return 0 when closed */
  }

  if (!hcs_complete(s->data))
  {
    ASSERT_DIE(sz == size);
    return 1;
  }

  log(L_INFO "Parsed command.");

  /* TODO do something more */

  hcs_parser_cleanup(s->data);
  s->data = hcs_parser_init(s->pool);

  if (sz == size)
    return 1;

  memmove(s->rbuf, s->rbuf + sz, size - sz);
  return hcs_rx(s, size - sz);
}

static void
hcs_err(sock *s, int err)
{
  log(L_INFO "CLI dropped: %s", strerror(err));
  hcs_parser_cleanup(s->data);
  sk_close(s);
}

static int
hcs_connect(sock *s, uint size UNUSED)
{
  log(L_INFO "CLI connected: %p", s);

  s->rx_hook = hcs_rx;
  s->err_hook = hcs_err;
  s->data = hcs_parser_init(s->pool);
  return 1;
}

static void
hcs_connect_err(sock *s UNUSED, int err)
{
  ASSERT_DIE(err);
  log(L_INFO "Failed to accept CLI connection: %s", strerror(err));
}

static void
hcs_stopped(void *data)
{
  ASSERT_DIE(data == hcs_loop);
  hcs_pool = NULL;
  hcs_loop = NULL;
  OBSREF_CLEAR(hcs_shutdown_placeholder);

  unlink(flock_config.control_socket_path);
}

static void
hcs_shutdown(void *_data UNUSED)
{
  birdloop_stop(hcs_loop, hcs_stopped, hcs_loop);
}

void
hypervisor_control_socket(void)
{
  struct birdloop *loop = hcs_loop = birdloop_new(&root_pool, DOMAIN_ORDER(control), 0, "Control socket");
  birdloop_enter(loop);

  pool *p = hcs_pool = rp_new(birdloop_pool(loop), birdloop_domain(loop), "Control socket pool");
  sock *s = sk_new(p);
  s->type = SK_UNIX_PASSIVE;
  s->rx_hook = hcs_connect;
  s->err_hook = hcs_connect_err;
  s->rbsize = 1024;

  unlink(flock_config.control_socket_path);
  if (sk_open_unix(s, loop, flock_config.control_socket_path) < 0)
    die("Can't create control socket %s: %m", flock_config.control_socket_path);

  ev_send(&shutdown_event_list, ev_new_init(p, hcs_shutdown, NULL));

  birdloop_leave(loop);

  OBSREF_SET(hcs_shutdown_placeholder, &shutdown_placeholder);
}



/**
 * Exposed process' communication structure
 **/
static struct hypervisor_exposed {
  pool *p;
  sock *s;
  struct birdloop *loop;
} he;

/**
 * Exposed process' parent side (requestor)
 **/
static int
hypervisor_exposed_parent_rx(sock *sk, uint size UNUSED)
{
  log(L_INFO "HV EP RX");
  recvmsg(sk->fd, NULL, 0);
  return 0;
}

static void
hypervisor_exposed_parent_err(sock *sk UNUSED, int e UNUSED)
{
}

/**
 * Exposed process' child side (executor)
 **/
static int
hypervisor_exposed_child_rx(sock *sk, uint size UNUSED)
{
  log(L_INFO "HV EC RX");
  recvmsg(sk->fd, NULL, 0);
  return 0;
}

static void
hypervisor_exposed_child_err(sock *sk UNUSED, int e UNUSED)
{
}

/**
 * Common init code
 */
void
hypervisor_exposed_fork(void)
{
  int fds[2], e;

  /* create socketpair before forking to do communication */
  e = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
  if (e < 0)
    die("Failed to create internal socketpair: %m");

  e = fork();
  if (e < 0)
    die("Failed to fork exposed: %m");

  /* Create the communication channel (both sides at once) */
  he.loop = birdloop_new(&root_pool, DOMAIN_ORDER(proto), 0, "Exposed interlink");

  birdloop_enter(he.loop);
  he.p = rp_new(birdloop_pool(he.loop), birdloop_domain(he.loop), "Exposed interlink pool");
  he.s = sk_new(he.p);
  he.s->type = SK_MAGIC;
  he.s->rx_hook = e ? hypervisor_exposed_parent_rx : hypervisor_exposed_child_rx;
  he.s->err_hook = e ? hypervisor_exposed_parent_err : hypervisor_exposed_child_err;
  he.s->fd = fds[!!e];
  close(fds[!e]);

  if (sk_open(he.s, he.loop) < 0)
    bug("Exposed parent: sk_open failed");

  birdloop_leave(he.loop);

  /* Now there is a loop both in child and parent, prepared to read the socket.
   * There is only one difference. Whereas the parent has to continue its run
   * to do other duties, the child is stuck here forever. */
  if (e)
    return;

  /* Child-only */
  while (1)
    pause();
}
