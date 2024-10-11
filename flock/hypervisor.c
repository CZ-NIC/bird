#include "lib/birdlib.h"

#include "lib/cbor.h"
#include "lib/hash.h"
#include "lib/io-loop.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/string.h"

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
hcs_connect(sock *s, uint size UNUSED)
{
  log(L_INFO "CLI connected: %p", s);

  hcs_parser_init(s);
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
  struct hcs_parser_channel *hpc;
} he;

/**
 * Exposed process' parent side (requestor)
 **/

static void hexp_received_telnet(void *);
struct hexp_received_telnet {
  event e;
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
    sk_close(sk);
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
hypervisor_exposed_parent_rx(sock *sk, uint size)
{
  if ((size != 5) || (sk->rxfd < 0))
  {
    log(L_ERR "Exposed parent RX %d bytes, fd %d, what the hell", size, sk->rxfd);
    sk_close(sk);
    ev_send_loop(&main_birdloop, &poweroff_event);
    return 0;
  }

  ASSERT_DIE(sk->rbuf[0] == 0xa1);
  ASSERT_DIE(sk->rbuf[1] == 0x21);
  ASSERT_DIE(sk->rbuf[2] == 0x19);

  u16 port = ntohs(*((u16 *) &sk->rbuf[3]));
  log(L_INFO "RX %d bytes, fd %d, port %u", size, sk->rxfd, port);

  struct hexp_received_telnet *hrt = mb_allocz(he.p, sizeof *hrt);
  *hrt = (struct hexp_received_telnet) {
    .e = {
      .hook = hexp_received_telnet,
      .data = hrt,
    },
    .port = port,
    .fd = sk->rxfd,
  };
  ev_send_loop(hcs_loop, &hrt->e);

  sk->rxfd = -1;

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
hypervisor_exposed_child_rx(sock *sk, uint size)
{
  if (size != 3)
  {
    log(L_ERR "Got something strange: %d, %m", size);
    abort();
    sk_close(sk);
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

    sk->txfd = sfd;

    struct {
      struct cbor_writer cw;
      struct cbor_writer_stack_item si[2];
    } cw;

    cbor_writer_init(&cw.cw, 2, sk->tbuf, sk->tbsize);
    CBOR_PUT_MAP(&cw.cw)
    {
      cbor_put_int(&cw.cw, -2);
      cbor_put_int(&cw.cw, r);
    }

    e = sk_send(sk, cw.cw.data.pos - cw.cw.data.start);
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
  e = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds);
  if (e < 0)
    die("Failed to create internal socketpair: %m");

  e = fork();
  if (e < 0)
    die("Failed to fork exposed: %m");

  if (!e) this_thread_id |= 0xe000;

  /* Create the communication channel (this runs twice!) */
  he.loop = birdloop_new(&root_pool, DOMAIN_ORDER(proto), 0, "Exposed interlink");

  birdloop_enter(he.loop);
  he.p = rp_new(birdloop_pool(he.loop), birdloop_domain(he.loop), "Exposed interlink pool");
  he.s = sk_new(he.p);
  he.s->type = SK_MAGIC; /* because we already have the fd */

  /* Set the hooks and fds according to the side we are at */
  he.s->rx_hook = e ? hypervisor_exposed_parent_rx : hypervisor_exposed_child_rx;
  he.s->err_hook = e ? hypervisor_exposed_parent_err : hypervisor_exposed_child_err;
  he.s->fd = fds[!!e];
  he.s->flags = e ? SKF_FD_RX : SKF_FD_TX;
  close(fds[!e]);

  if (sk_open(he.s, he.loop) < 0)
    bug("Exposed parent: sk_open failed");

  sk_set_rbsize(he.s, 128);
  sk_set_tbsize(he.s, 128);

  he.s->type = SK_UNIX_MSG; /* now we can reveal who we are */

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

void
hexp_cleanup_after_fork(void)
{
  birdloop_enter(he.loop);
  rp_free(he.p);
  rem_node((node *) he.loop); /* FIXME: this is terrible but i'm lazy now */
  birdloop_leave(he.loop);
  birdloop_free(he.loop);
}

/**
 * Hypervisor's mapping between external ports and names
 */

struct hcs_parser_channel {
  CBOR_CHANNEL_EMBED(cch, 4);
  struct hcs_parser_stream *htx;

  enum {
    HCS_CMD_SHUTDOWN = 1,
    HCS_CMD_TELNET,
    HCS_CMD_MACHINE_START,
    HCS_CMD_MACHINE_STOP,
    HCS_CMD__MAX,
  } cmd;

  union flock_machine_config cfg;
};

static void
hexp_sock_err(sock *s, int err UNUSED)
{
  he.hpc = NULL;
}

void
hexp_get_telnet(struct hcs_parser_channel *hpc)
{
  if (he.hpc)
    log(L_ERR "Multiple telnet requests not supported yet");

  log(L_INFO "Get telnet: %p name %s", hpc, hpc->cfg.cf.name);
  he.hpc = hpc;

  /* TODO: use channels here as well */
  uint8_t buf[] = { 0xa1, 0x01, 0xf6 };
  int e = write(he.s->fd, buf, sizeof buf);
  if (e != sizeof buf)
    bug("write error handling not implemented, got %d (%m)", e);
}

static void hexp_received_telnet(void *_hrt)
{
  struct hexp_received_telnet *hrt = _hrt;

  if (he.hpc->cfg.cf.name)
  {
    /* Transferring the received listening socket to the container */
    struct cbor_channel *ccc = container_get_channel(he.hpc->cfg.cf.name);

    BIRDLOOP_INSIDE(ccc->stream->loop)
      CBOR_REPLY(ccc, cw)
	CBOR_PUT_MAP(cw) {
	  cbor_put_int(cw, -2);
	  cbor_put_null(cw);
	  ccc->stream->s->txfd = hrt->fd;
	}

    close(hrt->fd);
  }
  else
  {
    /* Opening listener here */

    sock *skl = sk_new(hcs_pool);
    skl->type = SK_MAGIC;
    skl->rx_hook = hypervisor_telnet_connected;
    skl->data = skl;
    skl->fd = hrt->fd;
    if (sk_open(skl, hcs_loop) < 0)
      bug("Telnet listener: sk_open failed");
  }

  if (he.hpc)
  {
    CBOR_REPLY(&he.hpc->cch, cw)
      CBOR_PUT_MAP(cw)
      {
	cbor_put_int(cw, -2);
	cbor_put_int(cw, hrt->port);
      }

    cbor_channel_done(&he.hpc->cch);
  }

  birdloop_enter(he.loop);
  mb_free(hrt);
  birdloop_leave(he.loop);
}

/*
 * Hand-written parser for a very simple CBOR protocol:
 *
 * - on toplevel always array of three elements:
 *   - the ID (u64)
 *   - the command saying what to expect in the third element
 *     - 0 with NULL (7-22) = shutdown the hypervisor
 *     - 1 with NULL = open a telnet listener
 *     - 2 with one string = create a machine of this name
 *     - 3 with array of strings = run the given command inside the hypervisor
 */

struct hcs_parser_stream {
  struct cbor_parser_context *ctx;
  struct hcs_parser_channel *channel;
  sock *sock;

  u64 bytes_consumed;
  u64 major_state;

  CBOR_STREAM_EMBED(stream, 4);
};

static void
hcs_request_poweroff(struct hcs_parser_channel *hpc)
{
  log(L_INFO "Requested shutdown via CLI");
  ev_send_loop(&main_birdloop, &poweroff_event);

  CBOR_REPLY(&hpc->cch, cw)
    CBOR_PUT_MAP(cw)
    {
      cbor_put_int(cw, -1);
      cbor_put_string(cw, "OK");
    }

  cbor_channel_done(&hpc->cch);
}

struct hcs_parser_stream *
hcs_parser_init(sock *s)
{
  struct hcs_parser_stream *htx = mb_allocz(s->pool, sizeof *htx);

  CBOR_STREAM_INIT(htx, stream, cch, s->pool, struct hcs_parser_channel);
  cbor_stream_attach(&htx->stream, s);
  htx->stream.parse = hcs_parse;
  htx->stream.cancel = hcs_parser_cleanup;

  return htx;
}

#define CBOR_PARSER_ERROR(...)	do {			\
  log(L_ERR "Hypervisor ctl parse: " __VA_ARGS__);	\
  return CPR_ERROR;					\
} while (0)

enum cbor_parse_result
hcs_parse(struct cbor_channel *cch, enum cbor_parse_result res)
{
  SKIP_BACK_DECLARE(struct hcs_parser_channel, hpc, cch, cch);
  SKIP_BACK_DECLARE(struct hcs_parser_stream, htx, stream, cch->stream);
  struct cbor_parser_context *ctx = &htx->stream.parser;

  switch (res)
  {
      case CPR_MAJOR:
	/* Check type acceptance */
	switch (htx->major_state)
	{
	  case 0: /* Command */
	    CBOR_PARSE_ONLY(ctx, POSINT, hpc->cmd);
	    if (hpc->cmd > HCS_CMD__MAX)
	      CBOR_PARSER_ERROR("Command key too high, got %lu", hpc->cmd);

	    htx->major_state = hpc->cmd + 10;
	    return CPR_MORE;

	  case HCS_CMD_SHUTDOWN + 10: /* shutdown command: expected null */
	    if ((ctx->type != 7) || (ctx->value != 22))
	      CBOR_PARSER_ERROR("Expected null, got %u-%u", ctx->type, ctx->value);

	    hcs_request_poweroff(hpc);
	    htx->major_state = 3;
	    return CPR_MORE;

	  case HCS_CMD_TELNET + 10: /* telnet listener open */
	    if ((ctx->type == 7) && (ctx->value == 22))
	    {
	      hexp_get_telnet(hpc);
	      htx->major_state = 3;
	      return CPR_MORE;
	    }

	    else CBOR_PARSE_IF(ctx, TEXT, hpc->cfg.cf.name)
	      ;
	    else
	      CBOR_PARSER_ERROR("Expected null or string, got %s", cbor_type_str(ctx->type));
	    return CPR_MORE;

	  case HCS_CMD_MACHINE_START + 10: /* machine creation request */
	    if (ctx->type != 5)
	      CBOR_PARSER_ERROR("Expected mapping, got %u", ctx->type);

	    htx->major_state = 501;
	    return CPR_MORE;

	  case HCS_CMD_MACHINE_STOP + 1: /* machine shutdown request */
	    if (ctx->type != 5)
	      CBOR_PARSER_ERROR("Expecting mapping, got %u", ctx->type);

	    htx->major_state = 601;
	    return CPR_MORE;

	  case 7: /* process spawner */
	    bug("process spawner not implemented");

	  case 501: /* machine creation argument */
	    CBOR_PARSE_ONLY(ctx, POSINT, htx->major_state);

	    if (ctx->value >= 5)
	      CBOR_PARSER_ERROR("Command key too high, got %lu", ctx->value);

	    htx->major_state += 502;
	    return CPR_MORE;

	  case 502: /* machine creation argument 0: name */
	    CBOR_PARSE_ONLY(ctx, TEXT, hpc->cfg.cf.name);
	    return CPR_MORE;

	  case 503: /* machine creation argument 1: type */
	    CBOR_PARSE_ONLY(ctx, POSINT, hpc->cfg.cf.type);

	    if ((ctx->value < 1) && (ctx->value > 1) )
	      CBOR_PARSER_ERROR("Unexpected type, got %lu", ctx->value);

	    htx->major_state = 501;
	    return CPR_MORE;

	  case 504: /* machine creation argument 2: basedir */
	    CBOR_PARSE_ONLY(ctx, BYTES, hpc->cfg.container.basedir);
	    return CPR_MORE;

	  case 505: /* machine creation argument 3: workdir */
	    CBOR_PARSE_ONLY(ctx, BYTES, hpc->cfg.container.workdir);
	    return CPR_MORE;

	  case 601: /* machine shutdown argument */
	    CBOR_PARSE_ONLY(ctx, POSINT, htx->major_state);

	    if (ctx->value >= 5)
	      CBOR_PARSER_ERROR("Command key too high, got %lu", ctx->value);

	    htx->major_state += 602;
	    return CPR_MORE;

	  case 602: /* machine creation argument 0: name */
	    CBOR_PARSE_ONLY(ctx, TEXT, hpc->cfg.cf.name);
	    return CPR_MORE;

	  default:
	    bug("invalid parser state");
	}
	break;

      case CPR_STR_END:
	/* Bytes read completely! */
	switch (htx->major_state)
	{
	  case HCS_CMD_TELNET + 10:
	    hexp_get_telnet(hpc);
	    htx->major_state = 3;
	    return CPR_MORE;

	  case 502:
	  case 504:
	  case 505:
	    htx->major_state = 501;
	    return CPR_MORE;

	  case 602:
	    htx->major_state = 601;
	    return CPR_MORE;

	  default:
	    bug("Unexpected state to end a (byte)string in");
	  /* Code to run at the end of a (byte)string */
	}
	break;

    case CPR_BLOCK_END:
      switch (htx->major_state)
      {
	/* Code to run at the end of the mapping */
	case 0: /* toplevel item ended */
	  htx->major_state = ~0ULL;
	  return CPR_BLOCK_END;

	case 3:
	  htx->major_state = 0;
	  return CPR_MORE;

	case 501:
	  switch (hpc->cfg.cf.type)
	  {
	    case 1:
	      hypervisor_container_start(&hpc->cch, &hpc->cfg.container);
	      break;
	    default:
	      CBOR_PARSER_ERROR("Unknown machine type: %d", hpc->cfg.cf.type);
	  }
	  htx->major_state = 3;
	  return CPR_MORE;

	case 601:
	  hypervisor_container_shutdown(&hpc->cch, &hpc->cfg.container);
	  htx->major_state = 3;
	  return CPR_MORE;

	default:
	  bug("Unexpected state to end a mapping in");
      }
      break;

    case CPR_ERROR:
    case CPR_MORE:
      CBOR_PARSER_ERROR("Invalid input");

  }

  return CPR_MORE;
}

bool
hcs_complete(struct hcs_parser_stream *htx)
{
  return htx->major_state == ~0ULL;
}

const char *
hcs_error(struct hcs_parser_stream *htx)
{
  return htx->ctx->error;
}

void
hcs_parser_cleanup(struct hcs_parser_stream *htx)
{
  log(L_INFO "hcs parser cleanup");
  cbor_parser_free(htx->ctx);
}
