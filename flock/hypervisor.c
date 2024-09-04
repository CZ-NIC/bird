#include "lib/birdlib.h"

#include "lib/resource.h"
#include "lib/io-loop.h"
#include "lib/socket.h"

#include "flock/flock.h"

#include <sys/socket.h>

/**
 * Main control socket
 **/

pool *hypervisor_control_socket_pool;

static int
hcs_connect(sock *s, uint size UNUSED)
{
  log(L_INFO "CLI connected: %p", s);
  sk_close(s);
  return 1;
}

static void
hcs_connect_err(sock *s UNUSED, int err)
{
  ASSERT_DIE(err);
  log(L_INFO "Failed to accept CLI connection: %s", strerror(err));
}

void
hypervisor_control_socket(void)
{
  struct birdloop *loop = birdloop_new(&root_pool, DOMAIN_ORDER(control), 0, "Control socket");
  birdloop_enter(loop);

  pool *p = hypervisor_control_socket_pool = rp_new(birdloop_pool(loop), birdloop_domain(loop), "Control socket pool");
  sock *s = sk_new(p);
  s->type = SK_UNIX_PASSIVE;
  s->rx_hook = hcs_connect;
  s->err_hook = hcs_connect_err;
  s->rbsize = 1024;

  unlink(flock_config.control_socket_path);
  if (sk_open_unix(s, loop, flock_config.control_socket_path) < 0)
    die("Can't create control socket %s: %m", flock_config.control_socket_path);

  birdloop_leave(loop);
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
