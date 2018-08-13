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

struct unix_conf_order {
  struct conf_order co;
  struct unix_ifs *ifs;
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
  struct unix_conf_order *uco = (struct unix_conf_order *) co;

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
unix_cf_include(struct conf_order *co, char *name, uint len)
{
  struct unix_conf_order *uco = (struct unix_conf_order *) co;

  if (!uco->ifs)
    cf_error(co->ctx, "Max include depth reached");

  byte new_depth = uco->ifs->depth - 1;

  /* Includes are relative to the current file unless the path is absolute.
   * Joining the current file dirname with the include relative path. */
  char *patt;
  if (*name != '/')
    {
      /* dlen is upper bound of current file dirname length */
      int dlen = strlen(co->state->name);
      char *dir = alloca(dlen + 1);
      patt = alloca(dlen + len + 2);

      /* dirname() may overwrite its argument */
      memcpy(dir, co->state->name, dlen + 1);
      sprintf(patt, "%s/%s", dirname(dir), name);
    }
  else
    patt = name;

  /* Skip globbing if there are no wildcards, mainly to get proper
     response when the included config file is missing */
  if (!strpbrk(name, "?*["))
    {
      struct unix_ifs *uifs = cf_alloc(co->ctx, sizeof(struct unix_ifs));

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
      struct unix_ifs *uifs = cf_alloc(co->ctx, sizeof(struct unix_ifs));

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
  struct unix_conf_order *uco = (struct unix_conf_order *) co;

  close(uco->ifs->fd);
  cf_free_state(co->ctx, uco->ifs->state);

  /* No more files to read */
  if (!uco->ifs->next)
    return 1;

  uco->ifs = uco->ifs->next;
  co->state = uco->ifs->state;
  return 0;
}

#define MAX_INCLUDE_DEPTH 8

typedef void (*cf_error_type)(struct conf_order *order, const char *msg, va_list args);

static struct config *
unix_read_config(char *name, cf_error_type arg_cf_error)
{
  struct conf_state state = { .name = name };

  struct unix_ifs uifs = {
    .state = &state,
    .depth = MAX_INCLUDE_DEPTH,
    .fd = -1,
  };

  struct unix_conf_order uco = {
    .co = {
      .cf_read_hook = unix_cf_read,
      .cf_include = unix_cf_include,
      .cf_outclude = unix_cf_outclude,
      .cf_error = arg_cf_error,
      .state = &state,
    },
    .ifs = &uifs,
  };

  return config_parse(&uco.co);
}

static void
unix_cf_error_die(struct conf_order *order, const char *msg, va_list args)
{
  die("%s, line %u: %V", order->state->name, order->state->lino, msg, &args);
}

struct config *
read_config(void)
{
  return unix_read_config(config_name, unix_cf_error_die);
}

static void
unix_cf_error_log(struct conf_order *order, const char *msg, va_list args)
{
  log(L_ERR "%s, line %u: %V", order->state->name, order->state->lino, msg, &args);
}

void
async_config(void)
{
  log(L_INFO "Reconfiguration requested by SIGHUP");
  struct config *conf = unix_read_config(config_name, unix_cf_error_log);

  if (conf)
    config_commit(conf, RECONFIG_HARD, 0);
}

static void
unix_cf_error_cli(struct conf_order *order, const char *msg, va_list args)
{
  cli_msg(8002, "%s, line %d: %s", order->state->name, order->state->lino, msg, &args);
}

static struct config *
cmd_read_config(char *name)
{
  if (!name)
    name = config_name;

  cli_msg(-2, "Reading configuration from %s", name);
  return unix_read_config(name, unix_cf_error_cli);
}

void
cmd_check_config(char *name)
{
  struct config *conf = cmd_read_config(name);
  if (!conf)
    return;

  cli_msg(20, "Configuration OK");
  config_free(conf);
}

static void
cmd_reconfig_msg(int r)
{
  switch (r)
    {
    case CONF_DONE:	cli_msg( 3, "Reconfigured"); break;
    case CONF_PROGRESS: cli_msg( 4, "Reconfiguration in progress"); break;
    case CONF_QUEUED:	cli_msg( 5, "Reconfiguration already in progress, queueing new config"); break;
    case CONF_UNQUEUED:	cli_msg(17, "Reconfiguration already in progress, removing queued config"); break;
    case CONF_CONFIRM:	cli_msg(18, "Reconfiguration confirmed"); break;
    case CONF_SHUTDOWN:	cli_msg( 6, "Reconfiguration ignored, shutting down"); break;
    case CONF_NOTHING:	cli_msg(19, "Nothing to do"); break;
    default:		break;
    }
}

/* Hack for scheduled undo notification */
cli *cmd_reconfig_stored_cli;

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

  struct config *conf = cmd_read_config(name);
  if (!conf)
    return;

  int r = config_commit(conf, type, timeout);

  if ((r >= 0) && (timeout > 0))
    {
      cmd_reconfig_stored_cli = this_cli;
      cli_msg(-22, "Undo scheduled in %d s", timeout);
    }

  cmd_reconfig_msg(r);
}

void
cmd_reconfig_confirm(void)
{
  if (cli_access_restricted())
    return;

  int r = config_confirm();
  cmd_reconfig_msg(r);
}

void
cmd_reconfig_undo(void)
{
  if (cli_access_restricted())
    return;

  cli_msg(-21, "Undo requested");

  int r = config_undo();
  cmd_reconfig_msg(r);
}

