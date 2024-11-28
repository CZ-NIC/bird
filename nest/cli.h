/*
 *	BIRD Internet Routing Daemon -- Command-Line Interface
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_CLI_H_
#define _BIRD_CLI_H_

#include "lib/resource.h"
#include "lib/lists.h"
#include "lib/event.h"
#include "lib/tlists.h"
#include "conf/conf.h"

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

typedef struct cli {
  node n;				/* Node in list of all log hooks */
  pool *pool;
  struct birdsock *sock;		/* Underlying socket */
  byte *rx_buf, *rx_pos;		/* sysdep */
  struct cli_out *tx_buf, *tx_pos, *tx_write;
  event *event;
  void (*cont)(struct cli *c);
  void (*cleanup)(struct cli *c);	/* The CLI has closed prematurely */
  void *rover;				/* Private to continuation routine */
  struct config *main_config;		/* Main config currently in use */
  int last_reply;
  int restricted;			/* CLI is restricted to read-only commands */
  struct linpool *parser_pool;		/* Pool used during parsing */
  uint log_mask;			/* Mask of allowed message levels */
  uint log_threshold;			/* When free < log_threshold, store only important messages */
  uint async_msg_size;			/* Total size of async messages queued in tx_buf */
} cli;

struct cli_config {
#define TLIST_PREFIX cli_config
#define TLIST_TYPE struct cli_config
#define TLIST_ITEM n
#define TLIST_DEFINED_BEFORE
#define TLIST_WANT_ADD_TAIL
#define TLIST_WANT_WALK
  TLIST_DEFAULT_NODE;
  const char *name;
  struct config *config;
  uint uid, gid, mode;
  _Bool restricted;
};
#include "lib/tlists.h"

void cli_config_listen(struct cli_config *, const char *);

extern pool *cli_pool;
extern struct cli *this_cli;		/* Used during parsing */

#define CLI_ASYNC_CODE 10000

/* Functions to be called by command handlers */

void cli_printf(cli *, int, char *, ...);
#define cli_msg(x...) cli_printf(this_cli, x)

static inline void cli_separator(cli *c)
{ if (c->last_reply) cli_printf(c, -c->last_reply, ""); };

/* Functions provided to sysdep layer */

cli *cli_new(struct birdsock *, struct cli_config *);
void cli_init(void);
void cli_free(cli *);
void cli_kick(cli *);
void cli_written(cli *);

static inline int cli_access_restricted(void)
{
  if (this_cli && this_cli->restricted)
    return (cli_printf(this_cli, 8007, "Access denied"), 1);
  else
    return 0;
}

/* Functions provided by sysdep layer */

void cli_write_trigger(cli *);
int cli_get_command(cli *);

#endif
