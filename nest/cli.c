/*
 *	BIRD Internet Routing Daemon -- Command-Line Interface
 *
 *	(c) 1999--2017 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Command line interface
 *
 * This module takes care of the BIRD's command-line interface (CLI).
 * The CLI exists to provide a way to control BIRD remotely and to inspect
 * its status. It uses a very simple textual protocol over a stream
 * connection provided by the platform dependent code (on UNIX systems,
 * it's a UNIX domain socket).
 *
 * Each session of the CLI consists of a sequence of request and replies,
 * slightly resembling the FTP and SMTP protocols.
 * Requests are commands encoded as a single line of text, replies are
 * sequences of lines starting with a four-digit code followed by either
 * a space (if it's the last line of the reply) or a minus sign (when the
 * reply is going to continue with the next line), the rest of the line
 * contains a textual message semantics of which depends on the numeric
 * code. If a reply line has the same code as the previous one and it's
 * a continuation line, the whole prefix can be replaced by a single
 * white space character.
 *
 * Reply codes starting with 0 stand for `action successfully completed' messages,
 * 1 means `table entry', 8 `runtime error' and 9 `syntax error'.
 *
 * Each CLI session is internally represented by a &cli structure and a
 * resource pool containing all resources associated with the connection,
 * so that it can be easily freed whenever the connection gets closed, not depending
 * on the current state of command processing. A socket is associated with
 * the session, over which requests and replies are sent.
 *
 * The CLI commands are declared as a part of the configuration grammar
 * by using the |CF_CLI| macro. When a command is received, it is processed
 * by the same lexical analyzer and parser as used for the configuration, but
 * it's switched to a special mode by prepending a fake token to the text,
 * so that it uses only the CLI command rules. Then the parser invokes
 * an execution routine corresponding to the command, which constructs the
 * reply.
 *
 * Replies are buffered in memory and then sent asynchronously. Commands
 * which produce long outputs must split them to pieces and yield to other
 * operations between pieces. To simplify this (and possibly also complex
 * parsing of input), the CLI session runs in a coroutine with its own
 * execution context. At any time, cli_yield() can be called to interrupt
 * the current coroutine and have the buffered output sent.
 *
 * Alternatively, a long sequence of replies can be split to parts
 * using the @cont hook, which translates to yielding internally.
 *
 * The @this_cli variable points to a &cli structure of the session being
 * currently parsed, but it's available only before the first yield.
 *
 * A note on transmit buffer management: cli.tx_buf is a head of a list
 * of TX buffers (struct cli_out). A buffer pointed to by cli.tx_write
 * is the one currently written to using cli_printf() and cli_alloc_out(),
 * its wpos field points to the position of the write head in that buffer.
 * On the other side, cli.tx_pos is the buffer being set to the socket
 * and its outpos field is the position of the read head.
 */

#define LOCAL_DEBUG 1

#include "nest/bird.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "lib/coroutine.h"
#include "lib/string.h"

pool *cli_pool;

/* Hack for scheduled undo notification */
extern cli *cmd_reconfig_stored_cli;

/*
 *	Output buffering
 */

static byte *
cli_alloc_out(cli *c, int size)
{
  struct cli_out *o;

  if (!(o = c->tx_write) || o->wpos + size > o->end)
    {
      if (!o && c->tx_buf)
	o = c->tx_buf;
      else
	{
	  o = mb_alloc(c->pool, sizeof(struct cli_out) + CLI_TX_BUF_SIZE);
	  if (c->tx_write)
	    c->tx_write->next = o;
	  else
	    c->tx_buf = o;
	  o->wpos = o->outpos = o->buf;
	  o->end = o->buf + CLI_TX_BUF_SIZE;
	}
      c->tx_write = o;
      if (!c->tx_pos)
	c->tx_pos = o;
      o->next = NULL;
    }
  o->wpos += size;
  return o->wpos - size;
}

static void
cli_vprintf(cli *c, int code, const char *msg, va_list args)
{
  byte buf[CLI_LINE_SIZE];
  int cd = code;
  int errcode;
  int size, cnt;

  if (cd < 0)
    {
      cd = -cd;
      if (cd == c->last_reply)
	size = bsprintf(buf, " ");
      else
	size = bsprintf(buf, "%04d-", cd);
      errcode = -8000;
    }
  else if (cd == CLI_ASYNC_CODE)
    {
      size = 1; buf[0] = '+';
      errcode = cd;
    }
  else
    {
      size = bsprintf(buf, "%04d ", cd);
      errcode = 8000;
    }

  c->last_reply = cd;
  cnt = bvsnprintf(buf+size, sizeof(buf)-size-1, msg, args);
  if (cnt < 0)
    {
      cli_printf(c, errcode, "<line overflow>");
      return;
    }
  size += cnt;
  buf[size++] = '\n';
  memcpy(cli_alloc_out(c, size), buf, size);
}

/**
 * cli_printf - send reply to a CLI connection
 * @c: CLI connection
 * @code: numeric code of the reply, negative for continuation lines
 * @msg: a printf()-like formatting string.
 *
 * This function send a single line of reply to a given CLI connection.
 * In works in all aspects like bsprintf() except that it automatically
 * prepends the reply line prefix.
 *
 * Please note that if the connection can be already busy sending some
 * data in which case cli_printf() stores the output to a temporary buffer,
 * so please avoid sending a large batch of replies without waiting
 * for the buffers to be flushed.
 *
 * If you want to write to the current CLI output, you can use the cli_msg()
 * macro instead.
 *
 * If you want to pass a va_list, use cli_vprintf().
 */
void
cli_printf(cli *c, int code, char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  cli_vprintf(c, code, msg, args);
  va_end(args);
}

static void
cli_copy_message(cli *c)
{
  byte *p, *q;
  uint cnt = 2;

  if (c->ring_overflow)
    {
      byte buf[64];
      int n = bsprintf(buf, "<%d messages lost>\n", c->ring_overflow);
      c->ring_overflow = 0;
      memcpy(cli_alloc_out(c, n), buf, n);
    }
  p = c->ring_read;
  while (*p)
    {
      cnt++;
      p++;
      if (p == c->ring_end)
	p = c->ring_buf;
      ASSERT(p != c->ring_write);
    }
  c->async_msg_size += cnt;
  q = cli_alloc_out(c, cnt);
  *q++ = '+';
  p = c->ring_read;
  do
    {
      *q = *p++;
      if (p == c->ring_end)
	p = c->ring_buf;
    }
  while (*q++);
  c->ring_read = p;
  q[-1] = '\n';
}

static void
cli_hello(cli *c)
{
  cli_printf(c, 1, "BIRD " BIRD_VERSION " ready.");
  c->cont = NULL;
}

static void
cli_free_out(cli *c)
{
  struct cli_out *o, *p;

  if (o = c->tx_buf)
    {
      o->wpos = o->outpos = o->buf;
      while (p = o->next)
	{
	  o->next = p->next;
	  mb_free(p);
	}
    }
  c->tx_write = c->tx_pos = NULL;
  c->async_msg_size = 0;
}

static void
cli_write(cli *c)
{
  sock *s = c->socket;

  while (c->tx_pos)
    {
      struct cli_out *o = c->tx_pos;

      int len = o->wpos - o->outpos;
      s->tbuf = o->outpos;
      o->outpos = o->wpos;

      coro_sk_write(s, len);

      c->tx_pos = o->next;
    }

  /* Everything is written */
  s->tbuf = NULL;
  cli_free_out(c);
  ev_schedule(c->event);
}

void
cli_write_trigger(cli *c)
{
  if (c->tx_pos && c->socket->tbuf == NULL)
    cli_write(c);
}

static void
cli_err_hook(sock *s, int err)
{
  if (config->cli_debug)
    {
      if (err)
	log(L_INFO "CLI connection dropped: %s", strerror(err));
      else
	log(L_INFO "CLI connection closed");
    }
  cli_free(s->data);
}

/*
 *	Echoing of asynchronous messages
 */

static list cli_log_hooks;
static int cli_log_inited;

void
cli_set_log_echo(cli *c, uint mask, uint size)
{
  if (c->ring_buf)
    {
      mb_free(c->ring_buf);
      c->ring_buf = c->ring_end = c->ring_read = c->ring_write = NULL;
      rem_node(&c->n);
    }
  c->log_mask = mask;
  if (mask && size)
    {
      c->ring_buf = mb_alloc(c->pool, size);
      c->ring_end = c->ring_buf + size;
      c->ring_read = c->ring_write = c->ring_buf;
      add_tail(&cli_log_hooks, &c->n);
      c->log_threshold = size / 8;
    }
  c->ring_overflow = 0;
}

void
cli_echo(uint class, byte *msg)
{
  unsigned len, free, i, l;
  cli *c;
  byte *m;

  if (!cli_log_inited || EMPTY_LIST(cli_log_hooks))
    return;
  len = strlen(msg) + 1;
  WALK_LIST(c, cli_log_hooks)
    {
      if (!(c->log_mask & (1 << class)))
	continue;
      if (c->ring_read <= c->ring_write)
	free = (c->ring_end - c->ring_buf) - (c->ring_write - c->ring_read + 1);
      else
	free = c->ring_read - c->ring_write - 1;
      if ((len > free) ||
	  (free < c->log_threshold && class < (unsigned) L_INFO[0]))
	{
	  c->ring_overflow++;
	  continue;
	}
      if (c->ring_read == c->ring_write)
	ev_schedule(c->event);
      m = msg;
      l = len;
      while (l)
	{
	  if (c->ring_read <= c->ring_write)
	    i = c->ring_end - c->ring_write;
	  else
	    i = c->ring_read - c->ring_write;
	  if (i > l)
	    i = l;
	  memcpy(c->ring_write, m, i);
	  m += i;
	  l -= i;
	  c->ring_write += i;
	  if (c->ring_write == c->ring_end)
	    c->ring_write = c->ring_buf;
	}
    }
}

/*
 *	Reading of input
 */

static int
cli_getchar(cli *c)
{
  sock *s = c->socket;

  if (c->rx_aux == s->rpos)
    {
      DBG("CLI: Waiting on read\n");
      c->rx_aux = s->rpos = s->rbuf;
      c->state = CLI_STATE_WAIT_RX;
      int n = coro_sk_read(s);
      c->state = CLI_STATE_RUN;
      DBG("CLI: Read returned %d bytes\n", n);
      ASSERT(n);
    }
  return *c->rx_aux++;
}

static int
cli_read_line(cli *c)
{
  byte *d = c->rx_buf;
  byte *dend = c->rx_buf + CLI_RX_BUF_SIZE - 2;
  for (;;)
    {
      int ch = cli_getchar(c);
      if (ch == '\r')
	;
      else if (ch == '\n')
	break;
      else if (d < dend)
	*d++ = ch;
    }

  if (d >= dend)
    return 0;

  *d = 0;
  return 1;
}

/*
 *	Execution of commands
 */

struct cli *this_cli;

struct cli_conf_order {
  struct conf_order co;
  struct cli *cli;
};

static void
cli_cmd_error(struct conf_order *co, const char *msg, va_list args)
{
  struct cli_conf_order *cco = (struct cli_conf_order *) co;
  cli_vprintf(cco->cli, 9001, msg, args);
}

static void
cli_command(struct cli *c)
{
  struct conf_state state = {
    .name = "",
    .lino = 1
  };

  struct cli_conf_order o = {
    .co = {
      .ctx = NULL,
      .state = &state,
      .buf = c->rx_buf,
      .len = strlen(c->rx_buf),
      .cf_include = NULL,
      .cf_outclude = NULL,
      .cf_error = cli_cmd_error,
      .lp = c->parser_pool,
      .pool = c->pool,
    },
    .cli = c,
  };

  if (config->cli_debug > 1)
    log(L_TRACE "CLI: %s", c->rx_buf);
  
  lp_flush(c->parser_pool);
  this_cli = c;
  cli_parse(&(o.co));
}

/*
 *	Session control
 */

static void
cli_event(void *data)
{
  cli *c = data;
  DBG("CLI: Event in state %u\n", (int) c->state);

  while (c->ring_read != c->ring_write &&
      c->async_msg_size < CLI_MAX_ASYNC_QUEUE)
    cli_copy_message(c);

  cli_write_trigger(c);

  if (c->state == CLI_STATE_YIELD ||
      c->state == CLI_STATE_WAIT_TX && !c->tx_pos)
    coro_resume(c->coro);
}

void
cli_yield(cli *c)
{
  c->state = CLI_STATE_YIELD;
  DBG("CLI: Yielding\n");
  ev_schedule(c->event);
  coro_suspend();
  c->state = CLI_STATE_RUN;
  DBG("CLI: Yield resumed\n");
}

static void
cli_coroutine(void *_c)
{
  cli *c = _c;
  sock *s = c->socket;

  DBG("CLI: Coroutine started\n");
  c->rx_aux = s->rbuf;

  for (;;)
    {
      while (c->tx_pos)
	{
	  DBG("CLI: Sleeping on write\n");
	  c->state = CLI_STATE_WAIT_TX;
	  coro_suspend();
	  c->state = CLI_STATE_RUN;
	  DBG("CLI: Woke up on write\n");
	}

      if (c->cont)
	{
	  c->cont(c);
	  cli_write_trigger(c);
	  cli_yield(c);
	  continue;
	}

      if (!cli_read_line(c))
	cli_printf(c, 9000, "Command too long");
      else
	cli_command(c);
      cli_write_trigger(c);
    }
}

cli *
cli_new(sock *s)
{
  pool *p = rp_new(cli_pool, "CLI session");
  cli *c = mb_alloc(p, sizeof(cli));
  DBG("CLI: Created new session\n");

  bzero(c, sizeof(cli));
  c->pool = p;
  c->socket = s;
  c->event = ev_new(p);
  c->event->hook = cli_event;
  c->event->data = c;
  c->cont = cli_hello;
  c->parser_pool = lp_new_default(c->pool);
  c->show_pool = lp_new_default(c->pool);
  c->rx_buf = mb_alloc(c->pool, CLI_RX_BUF_SIZE);

  s->pool = c->pool;		/* We need to have all the socket buffers allocated in the cli pool */
  rmove(s, c->pool);
  s->err_hook = cli_err_hook;
  s->data = c;

  return c;
}

void
cli_run(cli *c)
{
  DBG("CLI: Running\n");
  c->state = CLI_STATE_RUN;
  c->rx_pos = c->rx_buf;
  c->rx_aux = NULL;
  c->coro = coro_new(c->pool, cli_coroutine, c);
  coro_resume(c->coro);
}

void
cli_free(cli *c)
{
  DBG("CLI: Destroying session\n");
  cli_set_log_echo(c, 0, 0);
  if (c->cleanup)
    c->cleanup(c);
  if (c == cmd_reconfig_stored_cli)
    cmd_reconfig_stored_cli = NULL;
  rfree(c->pool);
}

/**
 * cli_init - initialize the CLI module
 *
 * This function is called during BIRD startup to initialize
 * the internal data structures of the CLI module.
 */
void
cli_init(void)
{
  cli_pool = rp_new(&root_pool, "CLI");
  init_list(&cli_log_hooks);
  cli_log_inited = 1;
}
