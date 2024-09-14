#include "lib/birdlib.h"

#include "lib/cbor.h"
#include "lib/hash.h"
#include "lib/io-loop.h"
#include "lib/resource.h"
#include "lib/socket.h"

#include "flock/flock.h"

#include <stdlib.h>
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
  s->data = hcs_parser_init(s);

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
  s->data = hcs_parser_init(s);
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
  s->tbsize = 1024;

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

static void hexp_received_telnet(void *);
struct hexp_received_telnet {
  event e;
  struct hexp_telnet_port *p;
  int fd;
  u16 port;
};

static int
hypervisor_telnet_connected(sock *sk, uint size UNUSED)
{
  int fd = accept(sk->fd, NULL, 0);
  if (fd < 0)
  {
    if (errno == EAGAIN)
      return 1;

    log(L_ERR "failed to accept telnet connection: %m");
    return 0;
  }

  int e = fork();
  if (e < 0)
  {
    log(L_ERR "failed to fork: %m");
    return 0;
  }

  if (e)
  {
    log(L_INFO "telnet connected");
    close(fd);
    return 1;
  }

  close(0);
  close(1);
  close(2);
  dup2(fd, 0);
  dup2(fd, 1);

  e = execl("/usr/sbin/telnetd", "telnetd", "-E", "/bin/bash", NULL);
  log(L_ERR "failed to execl: %m");
  exit(42);
}

static int
hypervisor_exposed_parent_rx(sock *sk, uint size UNUSED)
{
  int sfd = -1;
  byte buf[128], cbuf[CMSG_SPACE(sizeof sfd)];
  struct iovec v = {
    .iov_base = buf,
    .iov_len = sizeof buf,
  };
  struct msghdr m = {
    .msg_iov = &v,
    .msg_iovlen = 1,
    .msg_control = &cbuf,
    .msg_controllen = sizeof cbuf,
  };

  int e = recvmsg(sk->fd, &m, 0);

  struct cmsghdr *c = CMSG_FIRSTHDR(&m);
  memcpy(&sfd, CMSG_DATA(c), sizeof sfd);

  ASSERT_DIE(buf[0] == 0xa1);
  ASSERT_DIE(buf[1] == 0x21);
  ASSERT_DIE(buf[2] == 0x19);

  u16 port = ntohs(*((u16 *) &buf[3]));
  log(L_INFO "RX %d bytes, fd %d, port %u", e, sfd, port);

  sock *skl = sk_new(sk->pool);
  skl->type = SK_MAGIC;
  skl->rx_hook = hypervisor_telnet_connected;
  skl->fd = sfd;
  if (sk_open(skl, sk->loop) < 0)
    bug("Telnet listener: sk_open failed");

  struct hexp_received_telnet *hrt = mb_allocz(he.p, sizeof *hrt);
  *hrt = (struct hexp_received_telnet) {
    .e = {
      .hook = hexp_received_telnet,
      .data = hrt,
    },
    .p = sk->data,
    .port = port,
    .fd = sfd,
  };
  ev_send_loop(hcs_loop, &hrt->e);

  return 0;
}

static void
hypervisor_exposed_parent_err(sock *sk, int e UNUSED)
{
  sk_close(sk);
}

/**
 * Exposed process' child side (executor)
 **/
static int
hypervisor_exposed_child_rx(sock *sk, uint size UNUSED)
{
  byte buf[128];
  struct iovec v = {
    .iov_base = buf,
    .iov_len = sizeof buf,
  };
  struct msghdr m = {
    .msg_iov = &v,
    .msg_iovlen = 1,
  };
  int e = recvmsg(sk->fd, &m, 0);
  if (e != 3)
  {
    log(L_ERR "Got something strange: %d, %m", e);
    return 0;
  }

  /* Only one thing is actually supported for now: opening a listening socket */
  int sfd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sfd < 0)
  {
    log(L_ERR "Failed to socket(): %m");
    return 0;
  }

  while (1)
  {
    u32 r = (random_u32() % (32768-1024) + 1024);
    union {
      struct sockaddr_in6 sin;
      struct sockaddr a;
    } sin = {
      .sin = {
	.sin6_family = AF_INET6,
	.sin6_port = htons(r),
	.sin6_addr.s6_addr[15] = 1,
      },
    };

    int e = bind(sfd, &sin.a, sizeof sin);
    if (e < 0)
      if (errno == EADDRINUSE)
      {
	log(L_INFO "Tried to bind to %u but already in use", r);
	continue;
      } else {
	log(L_ERR "Failed to bind to %u: %m", r);
	close(sfd);
	return 0;
      }

    e = listen(sfd, 10);
    if (e < 0)
    {
      log(L_ERR "Failed to listen(): %m", e);
      close(sfd);
      return 0;
    }

    log(L_INFO "SUCCESS");

    byte outbuf[128];
    linpool *lp = lp_new(sk->pool);
    struct cbor_writer *cw = cbor_init(outbuf, sizeof outbuf, lp);
    cbor_open_block_with_length(cw, 1);
    cbor_add_int(cw, -2);
    cbor_add_int(cw, r);
    struct iovec v = {
      .iov_base = outbuf,
      .iov_len = cw->pt,
    };
    byte cbuf[CMSG_SPACE(sizeof sfd)];
    struct msghdr m = {
      .msg_iov = &v,
      .msg_iovlen = 1,
      .msg_control = &cbuf,
      .msg_controllen = sizeof cbuf,
    };
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof sfd);
    memcpy(CMSG_DATA(c), &sfd, sizeof sfd);

    e = sendmsg(sk->fd, &m, 0);
    if (e < 0)
      log(L_ERR "Failed to send socket: %m");

    close(sfd);

    return 0;
  }
}

static void
hypervisor_exposed_child_err(sock *sk, int e)
{
  if (e == 0)
    log(L_INFO "Exposed child exiting OK");
  else
    log(L_ERR "Exposed child control socket failure: %s", strerror(e));

  sk_close(sk);
  exit(!!e);
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

  /* Create the communication channel (this runs twice!) */
  he.loop = birdloop_new(&root_pool, DOMAIN_ORDER(proto), 0, "Exposed interlink");

  birdloop_enter(he.loop);
  he.p = rp_new(birdloop_pool(he.loop), birdloop_domain(he.loop), "Exposed interlink pool");
  he.s = sk_new(he.p);
  he.s->type = SK_MAGIC;
  /* Set the hooks and fds according to the side we are at */
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

  /**
   * Child only
   **/

  /* Run worker threads */
  struct thread_config tc = {};
  bird_thread_commit(&tc);

  /* Wait for Godot */
  birdloop_minimalist_main();
}


/**
 * Hypervisor's mapping between external ports and names
 */

#define HEXP_TELNET_KEY(tp)	tp->name, tp->hash
#define HEXP_TELNET_NEXT(tp)	tp->next
#define HEXP_TELNET_EQ(a,h,b,i)	((h) == (i)) && (!(a) && !(b) || !strcmp(a,b))
#define HEXP_TELNET_FN(a,h)	h

#define TLIST_PREFIX hexp_telnet_requestor
#define TLIST_TYPE struct hexp_telnet_requestor
#define TLIST_ITEM n
struct hexp_telnet_requestor {
  TLIST_DEFAULT_NODE;
  sock *s;
  struct cbor_parser_context *ctx;
};

#define TLIST_WANT_ADD_TAIL
#include "lib/tlists.h"

static void
hexp_sock_err(sock *s, int err)
{
  struct hexp_telnet_requestor *req = s->data;
  s->data = req->ctx;

  hexp_telnet_requestor_rem_node(hexp_telnet_requestor_enlisted(req), req);
  mb_free(req);
  hcs_err(s, err);
}

struct hexp_telnet_port {
  struct hexp_telnet_port *next;
  const char *name;
  uint hash;
  uint port;

  TLIST_LIST(hexp_telnet_requestor) requestors;
  int fd;
};

static struct hexp_telnet {
  pool *pool;
  HASH(struct hexp_telnet_port) port_hash;
} hexp_telnet;

static void
hexp_init_telnet(void)
{
  pool *p = rp_new(hcs_pool, hcs_pool->domain, "Hypervisor exposed telnets");
  hexp_telnet.pool = p;
  HASH_INIT(hexp_telnet.port_hash, p, 6);
}

static void
hexp_have_telnet(sock *s, struct hexp_telnet_port *p)
{
  struct linpool *lp = lp_new(s->pool);
  struct cbor_writer *cw = cbor_init(s->tbuf, s->tbsize, lp);
  cbor_open_block_with_length(cw, 1);
  cbor_add_int(cw, -2);
  cbor_add_int(cw, p->port);
  sk_send(s, cw->pt);
  rfree(lp);
}

void
hexp_get_telnet(sock *s, const char *name)
{
  if (!hexp_telnet.pool)
    hexp_init_telnet();

  uint h = name ? mem_hash(name, strlen(name)) : 0;
  struct hexp_telnet_port *p = HASH_FIND(hexp_telnet.port_hash, HEXP_TELNET, name, h);
  if (p && p->port)
    return hexp_have_telnet(s, p);
  else if (!p)
  {
    he.s->data = p = mb_alloc(hcs_pool, sizeof *p);
    *p = (struct hexp_telnet_port) {
      .name = name,
      .hash = h,
      .fd = -1,
    };
    HASH_INSERT(hexp_telnet.port_hash, HEXP_TELNET, p);

    uint8_t buf[64];
    linpool *lp = lp_new(s->pool);
    struct cbor_writer *cw = cbor_init(buf, sizeof buf, lp);
    cbor_open_block_with_length(cw, 1);
    cbor_add_int(cw, 1);
    cw->cbor[cw->pt++] = 0xf6;

    struct iovec v = {
      .iov_base = buf,
      .iov_len = cw->pt,
    };
    struct msghdr m = {
      .msg_iov = &v,
      .msg_iovlen = 1,
    };

    int e = sendmsg(he.s->fd, &m, 0);
    if (e != cw->pt)
      bug("sendmsg error handling not implemented, got %d (%m)", e);

    rfree(lp);
  }

  s->rx_hook = NULL;
  s->err_hook = hexp_sock_err;

  struct hexp_telnet_requestor *req = mb_allocz(hcs_pool, sizeof *req);
  req->s = s;
  req->ctx = s->data;
  s->data = req;
  hexp_telnet_requestor_add_tail(&p->requestors, req);
}

static void hexp_received_telnet(void *_data)
{
  struct hexp_received_telnet *hrt = _data;

  ASSERT_DIE(!hrt->p->port);
  hrt->p->port = hrt->port;
  hrt->p->fd = hrt->fd;

  byte outbuf[128];
  linpool *lp = lp_new(hcs_pool);
  struct cbor_writer *cw = cbor_init(outbuf, sizeof outbuf, lp);
  cbor_open_block_with_length(cw, 1);
  cbor_add_int(cw, -2);
  cbor_add_int(cw, hrt->port);

  WALK_TLIST_DELSAFE(hexp_telnet_requestor, r, &hrt->p->requestors)
  {
    r->s->rx_hook = hcs_rx;
    r->s->err_hook = hcs_err;
    memcpy(r->s->tbuf, outbuf, cw->pt);
    sk_send(r->s, cw->pt);
    hexp_telnet_requestor_rem_node(&hrt->p->requestors, r);
  }

  birdloop_enter(he.loop);
  mb_free(hrt);
  birdloop_leave(he.loop);
}
