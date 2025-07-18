/*
 *	BIRD Internet Routing Daemon -- Unix Entry Point
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <libgen.h>

#include "nest/bird.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/tlists.h"
#include "lib/string.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/mpls.h"
#include "nest/cli.h"
#include "nest/locks.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/data.h"

#include "unix.h"
#include "krt.h"

/*
 *	Debugging
 */

static void
async_dump_report(struct dump_request *dr UNUSED, int state, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vlog(((state > 1000) ? L_ERR : L_INFO)[0], fmt, args);
  va_end(args);
}

static void
async_dump_run(struct dump_request *dreq)
{
  RDUMP("ASYNC STATE DUMP\n");

  rdump(dreq, &root_pool);
  sk_dump_all(dreq);
  // XXXX tm_dump_all();
  if_dump_all(dreq);
  neigh_dump_all(dreq);
  rta_dump_all(dreq);
  rt_dump_all(dreq);
  protos_dump_all(dreq);

  debug("\n");
}

void
async_dump(void)
{
  struct dump_request *dr = dump_to_file_init(0);
  dr->report = async_dump_report;
  dump_to_file_run(dr, "bird.dump", "async dump", async_dump_run);
}

/*
 *	Dropping privileges
 */

#ifdef CONFIG_RESTRICTED_PRIVILEGES
#include CONFIG_INCLUDE_SYSPRIV_H
#else

static inline void
drop_uid(uid_t uid UNUSED)
{
  die("Cannot change user on this platform");
}

#endif

static inline void
drop_gid(gid_t gid)
{
  if (setgid(gid) < 0)
    die("setgid: %m");

  if (setgroups(0, NULL) < 0)
    die("setgroups: %m");
}

/*
 *	Hostname
 */

char *
get_hostname(linpool *lp)
{
  struct utsname uts = {};

  if (uname(&uts) < 0)
      return NULL;

  return lp_strdup(lp, uts.nodename);
}

/*
 *	Reading the Configuration
 */

#ifdef PATH_IPROUTE_DIR

static inline void
add_num_const(struct config *conf, char *name, int val, const char *file, const uint line)
{
  struct f_val *v = cfg_alloc(sizeof(struct f_val));
  *v = (struct f_val) { .type = T_INT, .val.i = val };
  struct symbol *sym = cf_get_symbol(conf, name);
  if (sym->class && cf_symbol_is_local(conf, sym))
    cf_error("Error reading value for %s from %s:%d: already defined", name, file, line);

  cf_define_symbol(conf, sym, SYM_CONSTANT | T_INT, val, v);
}

/* the code of read_iproute_table() is based on
   rtnl_tab_initialize() from iproute2 package */
static void
read_iproute_table(struct config *conf, char *file, char *prefix, uint max)
{
  char buf[512], namebuf[512];
  char *name;
  uint val;
  FILE *fp;

  strcpy(namebuf, prefix);
  name = namebuf + strlen(prefix);

  fp = fopen(file, "r");
  if (!fp)
    return;

  for (uint line = 1; fgets(buf, sizeof(buf), fp); line++)
  {
    char *p = buf;

    while (*p == ' ' || *p == '\t')
      p++;

    if (*p == '#' || *p == '\n' || *p == 0)
      continue;

    if (sscanf(p, "0x%x %s\n", &val, name) != 2 &&
	sscanf(p, "0x%x %s #", &val, name) != 2 &&
	sscanf(p, "%u %s\n", &val, name) != 2 &&
	sscanf(p, "%u %s #", &val, name) != 2)
      continue;

    if (val > max)
      continue;

    for(p = name; *p; p++)
      if ((*p < 'a' || *p > 'z') && (*p < 'A' || *p > 'Z') && (*p < '0' || *p > '9') && (*p != '_'))
	*p = '_';

    add_num_const(conf, namebuf, val, file, line);
  }

  fclose(fp);
}

#endif // PATH_IPROUTE_DIR


static char *config_name = PATH_CONFIG_FILE;

static int
cf_read(byte *dest, uint len, int fd)
{
  int l = read(fd, dest, len);
  if (l < 0)
    cf_error("Read error");
  return l;
}

static void cli_preconfig(struct config *c);

void
sysdep_preconfig(struct config *c)
{
  init_list(&c->logfiles);

  c->latency_limit = UNIX_DEFAULT_LATENCY_LIMIT;
  c->watchdog_warning = UNIX_DEFAULT_WATCHDOG_WARNING;

#ifdef PATH_IPROUTE_DIR
  read_iproute_table(c, PATH_IPROUTE_DIR "/rt_protos", "ipp_", 255);
  read_iproute_table(c, PATH_IPROUTE_DIR "/rt_realms", "ipr_", 0xffffffff);
  read_iproute_table(c, PATH_IPROUTE_DIR "/rt_scopes", "ips_", 255);
  read_iproute_table(c, PATH_IPROUTE_DIR "/rt_tables", "ipt_", 0xffffffff);
#endif

  cli_preconfig(c);
}

static void cli_commit(struct config *new, struct config *old);

int
sysdep_commit(struct config *new, struct config *old)
{
  log_switch(0, &new->logfiles, new->syslog_name);
  cli_commit(new, old);
  return 0;
}

static int
unix_read_config(struct config **cp, const char *name)
{
  struct config *conf = config_alloc(name);
  int ret;

  *cp = conf;
  conf->file_fd = open(name, O_RDONLY);
  if (conf->file_fd < 0)
    return 0;
  cf_read_hook = cf_read;
  ret = config_parse(conf);
  close(conf->file_fd);
  return ret;
}

static struct config *
read_config(void)
{
  struct config *conf;

  if (!unix_read_config(&conf, config_name))
    {
      if (conf->err_msg)
	die("%s:%d:%d %s", conf->err_file_name, conf->err_lino, conf->err_chno, conf->err_msg);
      else
	die("Unable to open configuration file %s: %m", config_name);
    }

  return conf;
}

void
async_config(void)
{
  struct config *conf;

  config_free_old();

  log(L_INFO "Reconfiguration requested by SIGHUP");
  if (!unix_read_config(&conf, config_name))
    {
      if (conf->err_msg)
	log(L_ERR "%s:%d:%d %s", conf->err_file_name, conf->err_lino, conf->err_chno, conf->err_msg);
      else
	log(L_ERR "Unable to open configuration file %s: %m", config_name);
      config_free(conf);
    }
  else
    config_commit(conf, RECONFIG_HARD, 0);
}

static struct config *
cmd_read_config(const char *name)
{
  struct config *conf;

  if (!name)
    name = config_name;

  cli_msg(-2, "Reading configuration from %s", name);
  if (!unix_read_config(&conf, name))
    {
      if (conf->err_msg)
	cli_msg(8002, "%s:%d:%d %s", conf->err_file_name, conf->err_lino, conf->err_chno, conf->err_msg);
      else
	cli_msg(8002, "%s: %m", name);
      config_free(conf);
      conf = NULL;
    }

  return conf;
}

void
cmd_check_config(const char *name)
{
  if (cli_access_restricted())
    return;

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
cmd_reconfig(const char *name, int type, uint timeout)
{
  if (cli_access_restricted())
    return;

  config_free_old();

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

void
cmd_reconfig_status(void)
{
  int s = config_status();
  btime t = config_timer_status();

  switch (s)
  {
  case CONF_DONE:	cli_msg(-3, "Daemon is up and running"); break;
  case CONF_PROGRESS:	cli_msg(-4, "Reconfiguration in progress"); break;
  case CONF_QUEUED:	cli_msg(-5, "Reconfiguration in progress, next one enqueued"); break;
  case CONF_SHUTDOWN:	cli_msg(-6, "Shutdown in progress"); break;
  default:		break;
  }

  if (t >= 0)
    cli_msg(-22, "Configuration unconfirmed, undo in %t s", t);

  cli_msg(0, "");
}


/*
 *	Command-Line Interface
 */

static struct cli_config initial_control_socket_config = {
  .name = PATH_CONTROL_SOCKET,
  .mode = 0660,
};
#define path_control_socket initial_control_socket_config.name

static struct cli_config *main_control_socket_config = NULL;

#define TLIST_PREFIX cli_listener
#define TLIST_TYPE struct cli_listener
#define TLIST_ITEM n
#define TLIST_WANT_ADD_TAIL
#define TLIST_WANT_WALK
static struct cli_listener {
  TLIST_DEFAULT_NODE;
  sock *s;
  struct cli_config *config;
} *main_control_socket = NULL;

#include "lib/tlists.h"

static TLIST_LIST(cli_listener) cli_listeners;

static void
cli_write(cli *c)
{
  sock *s = c->priv;

  while (c->tx_pos)
    {
      struct cli_out *o = c->tx_pos;

      int len = o->wpos - o->outpos;
      s->tbuf = o->outpos;
      o->outpos = o->wpos;

      if (sk_send(s, len) <= 0)
	return;

      c->tx_pos = o->next;
    }

  /* Everything is written */
  s->tbuf = NULL;
  cli_written(c);
}

void
cli_write_trigger(cli *c)
{
  sock *s = c->priv;

  if (s->tbuf == NULL)
    cli_write(c);
}

static void
cli_tx(sock *s)
{
  cli_write(s->data);
}

int
cli_get_command(cli *c)
{
  sock *s = c->priv;
  byte *t = s->rbuf;
  byte *tend = s->rpos;
  byte *d = c->rx_pos;
  byte *dend = c->rx_buf + CLI_RX_BUF_SIZE - 2;

  while (t < tend)
    {
      if (*t == '\r')
	t++;
      else if (*t == '\n')
	{
	  *d = 0;
	  t++;

	  /* Move remaining data and reset pointers */
	  uint rest = (t < tend) ? (tend - t) : 0;
	  memmove(s->rbuf, t, rest);
	  s->rpos = s->rbuf + rest;
	  c->rx_pos = c->rx_buf;

	  return (d < dend) ? 1 : -1;
	}
      else if (d < dend)
	*d++ = *t++;
    }

  s->rpos = s->rbuf;
  c->rx_pos = d;
  return 0;
}

static int
cli_rx(sock *s, uint size UNUSED)
{
  cli_kick(s->data);
  return 0;
}

static void
cli_err(sock *s, int err)
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

static void
cli_connect_err(sock *s UNUSED, int err)
{
  ASSERT_DIE(err);
  if (config->cli_debug)
    log(L_INFO "Failed to accept CLI connection: %s", strerror(err));
}

static int
cli_connect(sock *s, uint size UNUSED)
{
  cli *c;

  if (config->cli_debug)
    log(L_INFO "CLI connect");
  s->rx_hook = cli_rx;
  s->tx_hook = cli_tx;
  s->err_hook = cli_err;
  s->data = c = cli_new(s, ((struct cli_listener *) s->data)->config);
  s->pool = c->pool;		/* We need to have all the socket buffers allocated in the cli pool */
  s->fast_rx = 1;
  c->rx_pos = c->rx_buf;
  rmove(s, c->pool);
  return 1;
}

static struct cli_listener *
cli_listen(struct cli_config *cf)
{
  struct cli_listener *l = mb_allocz(cli_pool, sizeof *l);
  l->config = cf;
  sock *s = l->s = sk_new(cli_pool);
  s->type = SK_UNIX_PASSIVE;
  s->rx_hook = cli_connect;
  s->err_hook = cli_connect_err;
  s->data = l;
  s->rbsize = 1024;
  s->fast_rx = 1;

  /* Return value intentionally ignored */
  unlink(cf->name);

  if (sk_open_unix(s, cf->name) < 0)
  {
    log(L_ERR "Cannot create control socket %s: %m", cf->name);
    goto err;
  }

  if (cf->uid || cf->gid)
    if (chown(cf->name, cf->uid, cf->gid) < 0)
    {
      log(L_ERR "Cannot chown control socket %s: %m", cf->name);
      goto err;
    }

  if (chmod(cf->name, cf->mode) < 0)
  {
    log(L_ERR "Cannot chmod control socket %s: %m", cf->name);
    goto err;
  }

  cli_listener_add_tail(&cli_listeners, l);

  return l;

err:
  rfree(s);
  mb_free(l);
  return NULL;
}

static void
cli_deafen(struct cli_listener *l)
{
  rfree(l->s);
  unlink(l->config->name);
  cli_listener_rem_node(&cli_listeners, l);
  mb_free(l);
}

static void
cli_init_unix(uid_t use_uid, gid_t use_gid)
{
  ASSERT_DIE(main_control_socket_config == NULL);

  main_control_socket_config = &initial_control_socket_config;
  main_control_socket_config->uid = use_uid;
  main_control_socket_config->gid = use_gid;

  ASSERT_DIE(main_control_socket == NULL);
  main_control_socket = cli_listen(main_control_socket_config);
  if (!main_control_socket)
    die("Won't run without control socket");
}

static void
cli_preconfig(struct config *c)
{
  if (!main_control_socket_config)
    return;

  struct cli_config *ccf = mb_alloc(cli_pool, sizeof *ccf);
  memcpy(ccf, main_control_socket_config, sizeof *ccf);
  ccf->n = (struct cli_config_node) {};
  ccf->config = c;
  cli_config_add_tail(&c->cli, ccf);
}

static void
cli_commit(struct config *new, struct config *old)
{
  if (new->shutdown)
  {
    /* Keep the main CLI throughout the shutdown */
    initial_control_socket_config.config = new;
    main_control_socket->config = &initial_control_socket_config;
  }

  WALK_TLIST(cli_config, c, &new->cli)
  {
    _Bool seen = 0;
    WALK_TLIST(cli_listener, l, &cli_listeners)
      if (l->config->config != new)
	if (!strcmp(l->config->name, c->name))
	{
	  ASSERT_DIE(l->config->config == old);
	  l->config = c;
	  seen = 1;
	  break;
	}

    if (!seen)
      cli_listen(c);
  }

  WALK_TLIST_DELSAFE(cli_listener, l, &cli_listeners)
    if (l->config->config != new)
      cli_deafen(l);
}


/*
 *	PID file
 */

static char *pid_file;
static int pid_fd;

static inline void
open_pid_file(void)
{
  if (!pid_file)
    return;

  pid_fd = open(pid_file, O_WRONLY|O_CREAT, 0664);
  if (pid_fd < 0)
    die("Cannot create PID file %s: %m", pid_file);
}

static inline void
write_pid_file(void)
{
  int pl, rv;
  char ps[24];

  if (!pid_file)
    return;

  /* We don't use PID file for uniqueness, so no need for locking */

  pl = bsnprintf(ps, sizeof(ps), "%ld\n", (s64) getpid());
  if (pl < 0)
    bug("PID buffer too small");

  rv = ftruncate(pid_fd, 0);
  if (rv < 0)
    die("fruncate: %m");

  rv = write(pid_fd, ps, pl);
  if(rv < 0)
    die("write: %m");

  close(pid_fd);
}

static inline void
unlink_pid_file(void)
{
  if (pid_file)
    unlink(pid_file);
}


/*
 *	Shutdown
 */

void
cmd_shutdown(void)
{
  if (cli_access_restricted())
    return;

  cli_msg(7, "Shutdown requested");
  order_shutdown(0);
}

void
async_shutdown(void)
{
  DBG("Shutting down...\n");
  order_shutdown(0);
}

void
sysdep_shutdown_done(void)
{
  unlink_pid_file();
  cli_deafen(main_control_socket);
  log_msg(L_FATAL "Shutdown completed");
  exit(0);
}

void
cmd_graceful_restart(void)
{
  if (cli_access_restricted())
    return;

  cli_msg(25, "Graceful restart requested");
  order_shutdown(1);
}


/*
 *	Signals
 */

volatile sig_atomic_t async_config_flag;
volatile sig_atomic_t async_dump_flag;
volatile sig_atomic_t async_shutdown_flag;

static void
handle_sighup(int sig UNUSED)
{
  DBG("Caught SIGHUP...\n");
  async_config_flag = 1;
}

static void
handle_sigusr(int sig UNUSED)
{
  DBG("Caught SIGUSR...\n");
  async_dump_flag = 1;
}

static void
handle_sigterm(int sig UNUSED)
{
  DBG("Caught SIGTERM...\n");
  async_shutdown_flag = 1;
}

void watchdog_sigalrm(int sig UNUSED);

static void
signal_init(void)
{
  struct sigaction sa;

  bzero(&sa, sizeof(sa));
  sa.sa_handler = handle_sigusr;
  sa.sa_flags = SA_RESTART;
  sigaction(SIGUSR1, &sa, NULL);
  sa.sa_handler = handle_sighup;
  sa.sa_flags = SA_RESTART;
  sigaction(SIGHUP, &sa, NULL);
  sa.sa_handler = handle_sigterm;
  sa.sa_flags = SA_RESTART;
  sigaction(SIGTERM, &sa, NULL);
  sa.sa_handler = watchdog_sigalrm;
  sa.sa_flags = 0;
  sigaction(SIGALRM, &sa, NULL);
  signal(SIGPIPE, SIG_IGN);
}

/*
 *	Parsing of command-line arguments
 */

static char *opt_list = "bc:dD:ps:P:u:g:flRh";
int parse_and_exit;
char *bird_name;
static char *use_user;
static char *use_group;
static int run_in_foreground = 0;

static void
display_usage(void)
{
  fprintf(stderr, "Usage: %s [--version] [--help] [-c <config-file>] [OPTIONS]\n", bird_name);
}

static void
display_help(void)
{
  display_usage();

  fprintf(stderr,
    "\n"
    "Options: \n"
    "  -c <config-file>     Use given configuration file instead of\n"
    "                       "  PATH_CONFIG_FILE "\n"
    "  -d                   Enable debug messages and run bird in foreground\n"
    "  -D <debug-file>      Log debug messages to given file instead of stderr\n"
    "  -f                   Run bird in foreground\n"
    "  -g <group>           Use given group ID\n"
    "  -h, --help           Display this information\n"
    "  -l                   Look for a configuration file and a control socket\n"
    "                       in the current working directory\n"
    "  -p                   Test configuration file and exit without start\n"
    "  -P <pid-file>        Create a PID file with given filename\n"
    "  -R                   Apply graceful restart recovery after start\n"
    "  -s <control-socket>  Use given filename for a control socket\n"
    "  -u <user>            Drop privileges and use given user ID\n"
    "  --version            Display version of BIRD\n");

  exit(0);
}

static void
display_version(void)
{
  fprintf(stderr, "BIRD version " BIRD_VERSION "\n");
  exit(0);
}

static inline char *
get_bird_name(char *s, char *def)
{
  char *t;
  if (!s)
    return def;
  t = strrchr(s, '/');
  if (!t)
    return s;
  if (!t[1])
    return def;
  return t+1;
}

static inline uid_t
get_uid(const char *s)
{
  struct passwd *pw;
  char *endptr;
  long int rv;

  if (!s)
    return 0;

  errno = 0;
  rv = strtol(s, &endptr, 10);

  if (!errno && !*endptr)
    return rv;

  pw = getpwnam(s);
  if (!pw)
    die("Cannot find user '%s'", s);

  return pw->pw_uid;
}

static inline gid_t
get_gid(const char *s)
{
  struct group *gr;
  char *endptr;
  long int rv;

  if (!s)
    return 0;

  errno = 0;
  rv = strtol(s, &endptr, 10);

  if (!errno && !*endptr)
    return rv;

  gr = getgrnam(s);
  if (!gr)
    die("Cannot find group '%s'", s);

  return gr->gr_gid;
}

static void
parse_args(int argc, char **argv)
{
  int config_changed = 0;
  int socket_changed = 0;
  int c;

  bird_name = get_bird_name(argv[0], "bird");
  if (argc == 2)
    {
      if (!strcmp(argv[1], "--version"))
	display_version();
      if (!strcmp(argv[1], "--help"))
	display_help();
    }
  while ((c = getopt(argc, argv, opt_list)) >= 0)
    switch (c)
      {
      case 'c':
	config_name = optarg;
	config_changed = 1;
	break;
      case 'd':
	log_init_debug("");
	run_in_foreground = 1;
	break;
      case 'D':
	log_init_debug(optarg);
	break;
      case 'p':
	parse_and_exit = 1;
	break;
      case 's':
	path_control_socket = optarg;
	socket_changed = 1;
	break;
      case 'P':
	pid_file = optarg;
	break;
      case 'u':
	use_user = optarg;
	break;
      case 'g':
	use_group = optarg;
	break;
      case 'f':
	run_in_foreground = 1;
	break;
      case 'l':
	if (!config_changed)
	  config_name = xbasename(config_name);
	if (!socket_changed)
	  path_control_socket = xbasename(path_control_socket);
	break;
      case 'R':
	graceful_restart_recovery();
	break;
      case 'h':
	display_help();
	break;
      default:
	fputc('\n', stderr);
	display_usage();
	exit(1);
      }
  if (optind < argc)
   {
     display_usage();
     exit(1);
   }
}

/*
 *	Hic Est main()
 */

int
main(int argc, char **argv)
{
#ifdef HAVE_LIBDMALLOC
  if (!getenv("DMALLOC_OPTIONS"))
    dmalloc_debug(0x2f03d00);
#endif

  parse_args(argc, argv);
  log_switch(1, NULL, NULL);

  random_init();
  resource_init();
  timer_init();
  olock_init();
  io_init();
  rt_init();
  if_init();
  mpls_init();
//  roa_init();
  config_init();

  uid_t use_uid = get_uid(use_user);
  gid_t use_gid = get_gid(use_group);

  cli_init();

  if (!parse_and_exit)
  {
    test_old_bird(path_control_socket);
    cli_init_unix(use_uid, use_gid);
  }

  if (use_gid)
    drop_gid(use_gid);

  if (use_uid)
    drop_uid(use_uid);

  if (!parse_and_exit)
    open_pid_file();

  protos_build();

  struct config *conf = read_config();

  if (parse_and_exit)
    exit(0);

  if (!run_in_foreground)
    {
      pid_t pid = fork();
      if (pid < 0)
	die("fork: %m");
      if (pid)
	return 0;
      setsid();
      close(0);
      if (open("/dev/null", O_RDWR) < 0)
	die("Cannot open /dev/null: %m");
      dup2(0, 1);
      dup2(0, 2);
    }

  main_thread_init();

  write_pid_file();

  signal_init();

  config_commit(conf, RECONFIG_HARD, 0);

  graceful_restart_init();

#ifdef LOCAL_DEBUG
  async_dump_flag = 1;
#endif

  log(L_INFO "Started");
  DBG("Entering I/O loop.\n");

  io_loop();
  bug("I/O loop died");
}
