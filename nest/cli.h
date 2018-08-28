/*
 *	BIRD Internet Routing Daemon -- Command-Line Interface
 *
 *	(c) 1999--2017 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_CLI_H_
#define _BIRD_CLI_H_

#include "lib/resource.h"
#include "lib/coroutine.h"
#include "lib/event.h"
#include "lib/socket.h"

#define CLI_RX_BUF_SIZE 4096
#define CLI_TX_BUF_SIZE 4096
#define CLI_MAX_ASYNC_QUEUE 4096

#define CLI_MSG_SIZE 500
#define CLI_LINE_SIZE 512

struct cli_out {
  struct cli_out *next;
  byte *wpos, *outpos, *end;
  byte buf[0];
};

enum cli_state {
  CLI_STATE_INIT,
  CLI_STATE_RUN,
  CLI_STATE_WAIT_RX,
  CLI_STATE_WAIT_TX,
  CLI_STATE_YIELD,
};

typedef struct cli {
  node n;				/* Node in list of all log hooks */
  pool *pool;
  coroutine *coro;
  enum cli_state state;
  int restricted;			/* CLI is restricted to read-only commands */

  /* I/O */
  sock *socket;
  byte *rx_buf, *rx_pos, *rx_aux;
  struct cli_out *tx_buf, *tx_pos, *tx_write;
  event *event;

  /* Continuation mechanism */
  void (*cont)(struct cli *c);
  void (*cleanup)(struct cli *c);
  void *rover;				/* Private to continuation routine */
  int last_reply;

  /* Pools */
  struct linpool *parser_pool;		/* Pool used during parsing */
  struct linpool *show_pool;		/* Pool used during route show */

  /* Asynchronous messages */
  byte *ring_buf;			/* Ring buffer for asynchronous messages */
  byte *ring_end, *ring_read, *ring_write;	/* Pointers to the ring buffer */
  uint ring_overflow;			/* Counter of ring overflows */
  uint log_mask;			/* Mask of allowed message levels */
  uint log_threshold;			/* When free < log_threshold, store only important messages */
  uint async_msg_size;			/* Total size of async messages queued in tx_buf */
} cli;

extern pool *cli_pool;
extern struct cli *this_cli;		/* Used during parsing */

#define CLI_ASYNC_CODE 10000

/* Functions to be called by command handlers */

void cli_printf(cli *, int, char *, ...);
#define cli_msg(x...) cli_printf(this_cli, x)
void cli_write_trigger(cli *c);
void cli_set_log_echo(cli *, uint mask, uint size);
void cli_yield(cli *c);

/* Functions provided to sysdep layer */

void cli_init(void);
cli *cli_new(sock *s);
void cli_run(cli *);
void cli_free(cli *);
void cli_echo(uint class, byte *msg);

static inline int cli_access_restricted(void)
{
  if (this_cli && this_cli->restricted)
    return (cli_printf(this_cli, 8007, "Access denied"), 1);
  else
    return 0;
}

#endif
