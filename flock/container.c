#include "lib/birdlib.h"
#include "lib/cbor.h"
#include "lib/io-loop.h"

#include "flock/flock.h"

#include <stdlib.h>

static struct container_config {
  const char *hostname;
  const char *workdir;
  const char *basedir;
} ccf;

static int container_forker_fd = -1;

static void
container_mainloop(int fd)
{
  log(L_INFO "container mainloop with fd %d", fd);
  /* TODO cleanup the loops from the forked process */
  while (1)
  {
    pause();
    log(L_INFO "woken up!");
  }
}

static uint container_counter = 0;

static void
container_start(void)
{
  log(L_INFO "Requested to start a container, name %s, base %s, work %s",
      ccf.hostname, ccf.basedir, ccf.workdir);

  /* create socketpair before forking to do communication */
  int fds[2];
  int e = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
  if (e < 0)
    die("Failed to create internal socketpair: %m");

  pid_t pid = fork();
  if (pid < 0)
    die("Failed to fork container: %m");

  if (!pid)
  {
    close(fds[0]);
    ASSERT_DIE(container_counter < 0x6000);
    this_thread_id -= (container_counter << 1) + 0x3000 ;
    container_mainloop(fds[1]); /* this never returns */
    bug("container_mainloop has returned");
  }

  container_counter -= 2;

  close(fds[1]);

  byte outbuf[128];
  linpool *lp = lp_new(&root_pool);
  struct cbor_writer *cw = cbor_init(outbuf, sizeof outbuf, lp);
  cbor_open_block_with_length(cw, 1);
  cbor_add_int(cw, -2);
  cbor_add_int(cw, pid);
  struct iovec v = {
    .iov_base = outbuf,
    .iov_len = cw->pt,
  };
  byte cbuf[CMSG_SPACE(sizeof fds[0])];
  struct msghdr m = {
    .msg_iov = &v,
    .msg_iovlen = 1,
    .msg_control = &cbuf,
    .msg_controllen = sizeof cbuf,
  };
  struct cmsghdr *c = CMSG_FIRSTHDR(&m);
  c->cmsg_level = SOL_SOCKET;
  c->cmsg_type = SCM_RIGHTS;
  c->cmsg_len = CMSG_LEN(sizeof fds[0]);
  memcpy(CMSG_DATA(c), &fds[0], sizeof fds[0]);

  e = sendmsg(container_forker_fd, &m, 0);
  if (e < 0)
    log(L_ERR "Failed to send socket: %m");

  close(fds[0]);
  rfree(lp);
}

/* The Parent */

static int
hypervisor_container_rx(sock *sk, uint sz)
{
  log(L_INFO "received %u data from %p (container_rx)", sz, sk);
  return 1;
}

static int
hypervisor_container_forker_rx(sock *sk, uint _sz UNUSED)
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
  if (e < 3)
  {
    log(L_ERR "Container forker RX hangup, what the hell");
    sk_close(sk);
    ev_send_loop(&main_birdloop, &poweroff_event);
    return 0;
  }

  struct cmsghdr *c = CMSG_FIRSTHDR(&m);
  memcpy(&sfd, CMSG_DATA(c), sizeof sfd);

  ASSERT_DIE(buf[0] == 0xa1);
  ASSERT_DIE(buf[1] == 0x21);
  pid_t pid;
  if (buf[2] < 0x18)
    pid = buf[2];
  else if (buf[2] == 24)
    pid = buf[3];
  else if (buf[2] == 25)
    pid = buf[3] << 8 + buf[4];
  else if (buf[3] == 26)
    pid = buf[3] << 32 + buf[4] << 24 + buf[5] << 16 + buf[6];
  else
    bug("not implemented");

  log(L_INFO "Machine started with PID %d", pid);

  sock *skl = sk_new(sk->pool);
  skl->type = SK_MAGIC;
  skl->rx_hook = hypervisor_container_rx;
  skl->fd = sfd;
  if (sk_open(skl, sk->loop) < 0)
    bug("Machine control socket: sk_open failed");

  /* TODO: create the machine struct
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
  */

  return 0;
}

static void
hypervisor_container_forker_err(sock *sk, int e UNUSED)
{
  sk_close(sk);
}

/* The child */

static struct hypervisor_container_forker {
  sock *s;
  pool *p;
  struct birdloop *loop;
} hcf;

void
hypervisor_container_request(const char *name, const char *basedir, const char *workdir)
{
  birdloop_enter(hcf.loop);
  linpool *lp = lp_new(hcf.p);
  struct cbor_writer *cw = cbor_init(hcf.s->tbuf, hcf.s->tbsize, lp);
  cbor_open_block_with_length(cw, 3);
  cbor_add_int(cw, 0);
  cbor_add_string(cw, name);
  cbor_add_int(cw, 1);
  cbor_add_string(cw, basedir);
  cbor_add_int(cw, 2);
  cbor_add_string(cw, workdir);
  sk_send(hcf.s, cw->pt);
  birdloop_leave(hcf.loop);
}

struct cbor_parser_context {
  linpool *lp;

  PACKED enum {
    CPE_TYPE = 0,
    CPE_READ_INT,
    CPE_COMPLETE_INT,
    CPE_READ_BYTE,
  } partial_state, partial_next;

  byte type;
  u64 value;
  u64 partial_countdown;

  u64 bytes_consumed;

  byte *target_buf;
  uint target_len;

  u64 major_state;

  const char *error;

#define LOCAL_STACK_MAX_DEPTH 3
  u64 stack_countdown[LOCAL_STACK_MAX_DEPTH];
  uint stack_pos;
};

#define CBOR_PARSER_ERROR bug

#define CBOR_PARSER_READ_INT(next)  do {		\
  ctx->partial_state = CPE_READ_INT;			\
  ctx->partial_countdown = (1 << (ctx->value - 24));	\
  ctx->value = 0;					\
  ctx->partial_next = next;				\
} while (0)

static struct cbor_parser_context ctx_, *ctx = &ctx_;

static void
hcf_parse(byte *buf, int size)
{
  ASSERT_DIE(size > 0);

  for (int pos = 0; pos < size; pos++)
  {
    const byte bp = buf[pos];
    bool value_is_special = 0;
    bool exit_stack = false;

    switch (ctx->partial_state)
    {
      case CPE_TYPE:
	/* Split the byte to type and value */
	ctx->type = bp >> 5;
	ctx->value = bp & 0x1f;

	if (ctx->type == 7)
	{
	  if (ctx->value < 20)
	    CBOR_PARSER_ERROR("Unknown simple value %u", ctx->value);
	  else if (ctx->value < 24)
	    ; /* false, true, null, undefined */
	  else if (ctx->value < 28)
	  {
	    /* Need more data */
	    CBOR_PARSER_READ_INT(CPE_COMPLETE_INT);
	    break;
	  }
	  else if (ctx->value == 31)
	    ; /* break-stop */
	  else
	    CBOR_PARSER_ERROR("Unknown simple value %u", ctx->value);
	}
	else
	{
	  if (ctx->value < 24)
	    ; /* Immediate value, fall through */
	  else if (ctx->value < 28)
	  {
	    /* Need more data */
	    CBOR_PARSER_READ_INT(CPE_COMPLETE_INT);
	    break;
	  }
	  else if ((ctx->value == 31) && (ctx->type >= 2) && (ctx->type <= 5))
	    /* Indefinite length, fall through */
	    value_is_special = 1;
	  else
	    CBOR_PARSER_ERROR("Garbled additional value %u for type %u", ctx->value, ctx->type);
	}
	/* fall through */

      case CPE_READ_INT:
	if (ctx->partial_state == CPE_READ_INT)
	{
	  /* Reading a network order integer */
	  ctx->value <<= 8;
	  ctx->value |= bp;
	  if (--ctx->partial_countdown)
	    break;
	}
	/* fall through */

      case CPE_COMPLETE_INT:
	/* TODO: exception for 7-31 end of long thing */

	/* Check type acceptance */
	switch (ctx->major_state)
	{
	  case 0: /* toplevel */
	    if (ctx->type != 5)
	      CBOR_PARSER_ERROR("Expected mapping, got %u", ctx->type);

	    ccf = (struct container_config) {};

	    ctx->major_state = 1;
	    break;

	  case 1: /* inside toplevel mapping */
	    if (ctx->type != 0)
	      CBOR_PARSER_ERROR("Expected integer, got %u", ctx->type);

	    if (ctx->value >= 3)
	      CBOR_PARSER_ERROR("Mapping key too high, got %lu", ctx->value);

	    ctx->major_state = ctx->value + 2;
	    break;

	  case 2: /* machine hostname */
	    if (ctx->type != 3)
	      CBOR_PARSER_ERROR("Expected string, got %u", ctx->type);

	    if (value_is_special)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (ccf.hostname)
	      CBOR_PARSER_ERROR("Duplicate argument 0 / hostname");

	    ASSERT_DIE(!ctx->target_buf);
	    ccf.hostname = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
	    break;

	  case 3: /* workdir */
	    if (ctx->type != 3)
	      CBOR_PARSER_ERROR("Expected string, got %u", ctx->type);

	    if (value_is_special)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (ccf.workdir)
	      CBOR_PARSER_ERROR("Duplicate argument 1 / workdir");

	    ASSERT_DIE(!ctx->target_buf);
	    ccf.workdir = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
	    break;

	  case 4: /* basedir */
	    if (ctx->type != 3)
	      CBOR_PARSER_ERROR("Expected string, got %u", ctx->type);

	    if (value_is_special)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (ccf.basedir)
	      CBOR_PARSER_ERROR("Duplicate argument 1 / basedir");

	    ASSERT_DIE(!ctx->target_buf);
	    ccf.basedir = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
	    break;

	  default:
	    bug("invalid parser state");
	}

	/* Some types are completely parsed, some not yet */
	switch (ctx->type)
	{
	  case 0:
	  case 1:
	  case 7:
	    exit_stack = !--ctx->stack_countdown[ctx->stack_pos];
	    ctx->partial_state = CPE_TYPE;
	    break;

	  case 2:
	  case 3:
	    ctx->partial_state = CPE_READ_BYTE;
	    ctx->partial_countdown = ctx->value;
	    ctx->target_buf = ctx->target_buf ?: lp_allocu(
		ctx->lp, ctx->target_len = (ctx->target_len ?: ctx->value));
	    break;

	  case 4:
	  case 5:
	    if (++ctx->stack_pos >= LOCAL_STACK_MAX_DEPTH)
	      CBOR_PARSER_ERROR("Stack too deep");

	    /* set array/map size;
	     * once for arrays, twice for maps;
	     * ~0 for indefinite */
	    ctx->stack_countdown[ctx->stack_pos] = value_is_special ? ~0ULL :
	      (ctx->value * (ctx->type - 3));
	    ctx->partial_state = CPE_TYPE;
	    break;
	}

	break;

      case CPE_READ_BYTE:
	*ctx->target_buf = bp;
	ctx->target_buf++;
	if (--ctx->target_len)
	  break;

	/* Read completely! */
	switch (ctx->major_state)
	{
	  case 2:
	  case 3:
	  case 4:
	    ctx->major_state = 1;
	    break;

	  default:
	    bug("Unexpected state to end a (byte)string in");
	  /* Code to run at the end of a (byte)string */
	}

	ctx->target_buf = NULL;
	ctx->partial_state = CPE_TYPE;

	exit_stack = !--ctx->stack_countdown[ctx->stack_pos];
    }

    /* End of array or map */
    while (exit_stack)
    {
      switch (ctx->major_state)
      {
	/* Code to run at the end of the mapping */
	case 0: /* toplevel item ended */
	  ctx->major_state = ~0ULL;
	  ctx->bytes_consumed = 0;
	  if (size > pos + 1)
	    hcf_parse(buf + pos + 1, size - pos - 1);
	  return;

	case 1: /* the mapping ended */
	  if (!ccf.hostname)
	    CBOR_PARSER_ERROR("Missing hostname");

	  if (!ccf.workdir)
	    CBOR_PARSER_ERROR("Missing workdir");

	  if (!ccf.basedir)
	    CBOR_PARSER_ERROR("Missing basedir");

	  container_start();

	  ctx->major_state = 0;
	  break;

	default:
	  bug("Unexpected state to end a mapping in");
      }

      /* Check exit from the next item */
      ASSERT_DIE(ctx->stack_pos);
      exit_stack = !--ctx->stack_countdown[--ctx->stack_pos];
    }
  }

  ctx->bytes_consumed += size;
}

void
hypervisor_container_fork(void)
{
  int fds[2], e;

  /* create socketpair before forking to do communication */
  e = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
  if (e < 0)
    die("Failed to create internal socketpair: %m");

  e = fork();
  if (e < 0)
    die("Failed to fork container forker: %m");

  if (e)
  {
    /* parent side */
    hcf.loop = birdloop_new(&root_pool, DOMAIN_ORDER(proto), 0, "Container forker");

    birdloop_enter(hcf.loop);
    hcf.p = rp_new(birdloop_pool(hcf.loop), birdloop_domain(hcf.loop), "Container forker pool");
    hcf.s = sk_new(hcf.p);
    hcf.s->type = SK_MAGIC;
    /* Set the hooks and fds according to the side we are at */
    hcf.s->rx_hook = hypervisor_container_forker_rx;
    hcf.s->err_hook = hypervisor_container_forker_err;
    sk_set_tbsize(hcf.s, 16384);
    hcf.s->fd = fds[0];
    close(fds[1]);

    if (sk_open(hcf.s, hcf.loop) < 0)
      bug("Container forker parent: sk_open failed");

    birdloop_leave(hcf.loop);
    return;
  }

  /* noreturn child side */
  close(fds[0]);
  container_forker_fd = fds[1];

  this_thread_id |= 0xf000;

  /* initialize the forker */
  ctx->lp = lp_new(&root_pool);
  ctx->type = 0xff;
  ctx->stack_countdown[0] = 1;

  while (true)
  {
    byte buf[4096];

    ssize_t rx = read(fds[1], buf, sizeof buf);

    times_update();

    if (rx == 0)
    {
      log(L_INFO "Container forker socket closed, exiting");
      exit(0);
    }

    if (rx < 0)
      bug("Container forker child: failed to read: %m");

    hcf_parse(buf, rx);
  }
}

