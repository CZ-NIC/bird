/*
 *	BIRD Internet Routing Daemon -- Unix Config Reader
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2018 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nest/bird.h"
#include "conf/conf.h"
#include "conf/parser.h"

#ifdef PATH_IPROUTE_DIR

static inline void
add_num_const(struct cf_context *ctx, char *name, int val)
{
  struct symbol *s = cf_get_symbol(ctx, name);
  s->class = SYM_CONSTANT | T_INT;
  s->def = cfg_allocz(sizeof(struct f_val));
  SYM_TYPE(s) = T_INT;
  SYM_VAL(s).i = val;
}

/* the code of read_iproute_table() is based on
   rtnl_tab_initialize() from iproute2 package */
static void
read_iproute_table(struct cf_context *ctx, char *file, char *prefix, int max)
{
  char buf[512], namebuf[512];
  char *name;
  int val;
  FILE *fp;

  strcpy(namebuf, prefix);
  name = namebuf + strlen(prefix);

  fp = fopen(file, "r");
  if (!fp)
    return;

  while (fgets(buf, sizeof(buf), fp))
  {
    char *p = buf;

    while (*p == ' ' || *p == '\t')
      p++;

    if (*p == '#' || *p == '\n' || *p == 0)
      continue;

    if (sscanf(p, "0x%x %s\n", &val, name) != 2 &&
	sscanf(p, "0x%x %s #", &val, name) != 2 &&
	sscanf(p, "%d %s\n", &val, name) != 2 &&
	sscanf(p, "%d %s #", &val, name) != 2)
      continue;

    if (val < 0 || val > max)
      continue;

    for(p = name; *p; p++)
      if ((*p < 'a' || *p > 'z') && (*p < '0' || *p > '9') && (*p != '_'))
	*p = '_';

    add_num_const(ctx, namebuf, val);
  }

  fclose(fp);
}

#endif // PATH_IPROUTE_DIR


char *config_name = PATH_CONFIG_FILE;

void
sysdep_preconfig(struct cf_context *ctx)
{
  init_list(&ctx->new_config->logfiles);

  ctx->new_config->latency_limit = UNIX_DEFAULT_LATENCY_LIMIT;
  ctx->new_config->watchdog_warning = UNIX_DEFAULT_WATCHDOG_WARNING;

#ifdef PATH_IPROUTE_DIR
  read_iproute_table(ctx, PATH_IPROUTE_DIR "/rt_protos", "ipp_", 256);
  read_iproute_table(ctx, PATH_IPROUTE_DIR "/rt_realms", "ipr_", 256);
  read_iproute_table(ctx, PATH_IPROUTE_DIR "/rt_scopes", "ips_", 256);
  read_iproute_table(ctx, PATH_IPROUTE_DIR "/rt_tables", "ipt_", 256);
#endif
}

int
sysdep_commit(struct config *new, struct config *old UNUSED)
{
  log_switch(debug_flag, &new->logfiles, new->syslog_name);
  return 0;
}

#define MAX_INCLUDE_DEPTH 8
#define UCO struct unix_conf_order *uco = (struct unix_conf_order *) co

struct unix_conf_order {
  struct conf_order co;		/* First field of struct conf_order is resource r; */
  struct unix_ifs *ifs;		/* Input file stack; initially NULL, is inited inside config_parse() */
  struct linpool *ifs_lp;	/* Where to allocate IFS from */
  struct cli *cli;		/* CLI if called from CLI */
  event *ev;			/* Start event if called from CLI */
  int type;			/* Type of reconfig */
  uint timeout;			/* Config timeout */
};

static void
unix_conf_order_free(resource *r)
{
  struct unix_conf_order *uco = (struct unix_conf_order *) r;
  rfree(uco->ifs_lp);
}

static struct resclass unix_conf_order_class = {
  "Unix Conf Order",
  sizeof(struct unix_conf_order),
  unix_conf_order_free,
  NULL,
  NULL,
  NULL,
};

struct unix_ifs {
  struct unix_ifs *up;			/* Who included this file */
  struct unix_ifs *next;		/* Next file to include */

  struct conf_state *state;		/* Appropriate conf_state */
  int fd;				/* File descriptor */
  byte depth;				/* Include depth remaining, 0 = cannot include */
};

static int
unix_cf_read(struct conf_order *co, byte *dest, uint len)
{
  UCO;

  ASSERT(uco->ifs->state == co->state);

  if (uco->ifs->fd == -1)
    uco->ifs->fd = open(co->state->name, O_RDONLY);

  if (uco->ifs->fd < 0)
    if (uco->ifs->up)
      {
	const char *fn = co->state->name;
	co->state = uco->ifs->up->state; /* We want to raise this error in the parent file */
	cf_error(co->ctx, "Unable to open included file %s: %m", fn);
      }
    else
      cf_error(co->ctx, "Unable to open configuration file %s: %m", co->state->name);

  int l = read(uco->ifs->fd, dest, len);
  if (l < 0)
    cf_error(co->ctx, "Read error: %m");
  return l;
}

static void
unix_cf_include(struct conf_order *co, const char *name, uint len)
{
  UCO;

  byte new_depth = uco->ifs ? (uco->ifs->depth - 1) : MAX_INCLUDE_DEPTH;

  /* Includes are relative to the current file unless the path is absolute.
   * Joining the current file dirname with the include relative path. */
  const char *patt;
  if (co->state && *name != '/')
    {
      /* dlen is upper bound of current file dirname length */
      int dlen = strlen(co->state->name);
      char *dir = alloca(dlen + 1);
      char *npatt = alloca(dlen + len + 2);

      /* dirname() may overwrite its argument */
      memcpy(dir, co->state->name, dlen + 1);
      sprintf(npatt, "%s/%s", dirname(dir), name);
      patt = npatt;
    }
  else
    patt = name;

  /* Skip globbing if there are no wildcards, mainly to get proper
     response when the included config file is missing */
  if (!strpbrk(name, "?*["))
    {
      struct unix_ifs *uifs = lp_alloc(uco->ifs_lp, sizeof(struct unix_ifs));

      *uifs = (struct unix_ifs) {
	.next = uco->ifs,
	.up = uco->ifs,
	.state = cf_new_state(co->ctx, patt),
	.fd = -1,
	.depth = new_depth,
      };

      co->state = uifs->state;
      uco->ifs = uifs;

      return;
    }

  /* Expand the pattern */
  /* FIXME: glob() is not completely thread-safe, see the manpage */
  glob_t g = {};
  int rv = glob(patt, GLOB_ERR | GLOB_NOESCAPE, NULL, &g);
  if (rv == GLOB_ABORTED)
    cf_error(co->ctx, "Unable to match pattern %s: %m", patt);
  if ((rv != 0) || (g.gl_pathc <= 0))
    return;

  /*
   * Now we put all found files to ifs stack in reverse order, they
   * will be activated and processed in order as ifs stack is popped
   * by pop_ifs() and enter_ifs() in check_eof().
   */
  struct unix_ifs *last_uifs = uco->ifs;
  for (int i = g.gl_pathc - 1; i >= 0; i--)
    {
      char *fname = g.gl_pathv[i];
      struct stat fs;

      if (stat(fname, &fs) < 0)
	{
	  globfree(&g);
	  cf_error(co->ctx, "Unable to stat included file %s: %m", fname);
	}

      if (fs.st_mode & S_IFDIR)
        continue;

      /* Prepare new stack item */
      struct unix_ifs *uifs = lp_alloc(uco->ifs_lp, sizeof(struct unix_ifs));

      *uifs = (struct unix_ifs) {
	.next = last_uifs,
	.up = uco->ifs,
	.state = cf_new_state(co->ctx, fname),
	.fd = -1,
	.depth = new_depth,
      };

      last_uifs = uifs;
    }

  globfree(&g);
  
  co->state = last_uifs->state;
  uco->ifs = last_uifs;

  return;
}

static int
unix_cf_outclude(struct conf_order *co)
{
  UCO;

  close(uco->ifs->fd);
  cf_free_state(co->ctx, uco->ifs->state);

  /* No more files to read */
  if (!uco->ifs->next)
    return 1;

  uco->ifs = uco->ifs->next;
  co->state = uco->ifs->state;
  return 0;
}

typedef void (*cf_error_type)(struct conf_order *co, const char *msg, va_list args);
typedef void (*cf_done_type)(struct conf_order *co);

static struct unix_conf_order *
unix_new_conf_order(pool *p)
{
  struct unix_conf_order *uco = ralloc(p, &unix_conf_order_class);
  
  uco->co.flags = CO_FILENAME;
  uco->co.cf_read_hook = unix_cf_read;
  uco->co.cf_include = unix_cf_include;
  uco->co.cf_outclude = unix_cf_outclude;

  uco->ifs_lp = lp_new_default(p);

  return uco;
}

static void
unix_cf_error_die(struct conf_order *co, const char *msg, va_list args)
{
  die("%s, line %u: %V", co->state->name, co->state->lino, msg, &args);
}

struct config *
read_config(void)
{
  struct unix_conf_order *uco = unix_new_conf_order(&root_pool);

  uco->co.buf = config_name;
  uco->co.len = strlen(config_name);
  uco->co.flags |= CO_SYNC;
  uco->co.cf_error = unix_cf_error_die;

  config_parse(&(uco->co));

  struct config *c = uco->co.new_config;
  rfree(uco);

  return c;
}

static void
unix_cf_error_log(struct conf_order *co, const char *msg, va_list args)
{
  log(L_ERR "%s, line %u: %V", co->state->name, co->state->lino, msg, &args);
}

static void
unix_cf_done_async(struct conf_order *co)
{
  UCO;
  struct config *c = co->new_config;
  if (c)
    config_commit(c, RECONFIG_HARD, 0);
  
  rfree(uco);
}

void
async_config(void)
{
  struct unix_conf_order *uco = unix_new_conf_order(&root_pool);

  uco->co.buf = config_name;
  uco->co.len = strlen(config_name);
  uco->co.cf_error = unix_cf_error_log;
  uco->co.cf_done = unix_cf_done_async;

  log(L_INFO "Reconfiguration requested by SIGHUP");
  config_parse(&(uco->co));
}

static void
unix_cf_error_cli(struct conf_order *co, const char *msg, va_list args)
{
  cli_msg(8002, "%s, line %d: %s", co->state->name, co->state->lino, msg, &args);
}

static void cmd_reconfig_msg(cli *c, int r);

/* Hack for scheduled undo notification */
cli *cmd_reconfig_stored_cli;

static void
unix_cf_done_cli(struct conf_order *co)
{
  UCO;
  ev_schedule(uco->cli->event);
}

static void
cmd_done_config(struct unix_conf_order *uco)
{
  log(L_INFO "config done handler");
  if (uco->type == RECONFIG_CHECK)
    {
      if (!uco->co.new_config)
	goto cleanup;
      
      cli_printf(uco->cli, 20, "Configuration OK");
      config_free(uco->co.new_config);
    }
  else
    {
      struct config *c = uco->co.new_config;
      if (!c)
	goto cleanup;

      int r = config_commit(c, uco->type, uco->timeout);

      if ((r >= 0) && (uco->timeout > 0))
	{
	  cmd_reconfig_stored_cli = uco->cli;
	  cli_printf(uco->cli, -22, "Undo scheduled in %d s", uco->timeout);
	}

      cmd_reconfig_msg(uco->cli, r);
    }

cleanup:
  rfree(uco);
}

static void
cmd_read_config_ev(void *data)
{
  struct unix_conf_order *uco = data;
  log(L_INFO "Reading configuration from %s on CLI request: begin", uco->co.buf);
  return config_parse(&(uco->co));
}

static void
cmd_read_config(struct unix_conf_order *uco)
{
  uco->co.buf = uco->co.buf ?: config_name;
  uco->co.len = strlen(uco->co.buf);
  uco->co.cf_error = unix_cf_error_cli;
  uco->co.cf_done = unix_cf_done_cli;

  uco->cli = this_cli;

  cli_msg(-2, "Reading configuration from %s", uco->co.buf);
  this_cli->running_config = &(uco->co);

  uco->ev = ev_new(uco->co.pool);
  uco->ev->hook = cmd_read_config_ev;
  uco->ev->data = uco;

  ev_schedule(uco->ev);

  cli_yield(this_cli);

  cmd_done_config(uco);
}

static inline int
cmd_check_running_config(void)
{
  if (!this_cli->running_config)
    return 0;

  /* TODO: Queue this config. */
  cli_msg(25, "Reconfiguration rejected, another config not parsed yet");
  return 1;
}

void
cmd_check_config(char *name)
{
  if (cmd_check_running_config())
    return;

  struct unix_conf_order *uco = unix_new_conf_order(&root_pool);

  uco->co.buf = name;
  uco->type = RECONFIG_CHECK;

  cmd_read_config(uco);
}

static void
cmd_reconfig_msg(cli *c, int r)
{
  
  switch (r)
    {
    case CONF_DONE:	cli_printf(c,  3, "Reconfigured"); break;
    case CONF_PROGRESS: cli_printf(c,  4, "Reconfiguration in progress"); break;
    case CONF_QUEUED:	cli_printf(c,  5, "Reconfiguration already in progress, queueing new config"); break;
    case CONF_UNQUEUED:	cli_printf(c, 17, "Reconfiguration already in progress, removing queued config"); break;
    case CONF_CONFIRM:	cli_printf(c, 18, "Reconfiguration confirmed"); break;
    case CONF_SHUTDOWN:	cli_printf(c,  6, "Reconfiguration ignored, shutting down"); break;
    case CONF_NOTHING:	cli_printf(c, 19, "Nothing to do"); break;
    default:		break;
    }
}

void
cmd_reconfig_undo_notify(void)
{
  if (cmd_reconfig_stored_cli)
    {
      cli *c = cmd_reconfig_stored_cli;
      cli_printf(c, CLI_ASYNC_CODE, "Config timeout expired, starting undo");
      cli_write_trigger(c);
    }
}

void
cmd_reconfig(char *name, int type, uint timeout)
{
  if (cli_access_restricted())
    return;

  if (cmd_check_running_config())
    return;

  struct unix_conf_order *uco = unix_new_conf_order(&root_pool);

  uco->co.buf = name;
  uco->type = type;
  uco->timeout = timeout;

  return cmd_read_config(uco);
}

void
cmd_reconfig_confirm(void)
{
  if (cli_access_restricted())
    return;

  int r = config_confirm();
  cmd_reconfig_msg(this_cli, r);
}

void
cmd_reconfig_undo(void)
{
  if (cli_access_restricted())
    return;

  cli_msg(-21, "Undo requested");

  int r = config_undo();
  cmd_reconfig_msg(this_cli, r);
}

