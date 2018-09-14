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
#include <libgen.h>

#include "nest/bird.h"
#include "lib/coroutine.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/string.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/cli.h"
#include "nest/locks.h"
#include "conf/conf.h"
#include "filter/filter.h"

#include "unix.h"
#include "krt.h"

/*
 *	Debugging
 */

#ifdef DEBUGGING
int debug_flag = 1;
#else
int debug_flag = 0;
#endif

void
async_dump(void)
{
  debug("INTERNAL STATE DUMP\n\n");

  rdump(&root_pool);
  sk_dump_all();
  // XXXX tm_dump_all();
  if_dump_all();
  neigh_dump_all();
  rta_dump_all();
  rt_dump_all();
  protos_dump_all();

  debug("\n");
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
}


/*
 *	Command-Line Interface
 */

static sock *cli_sk;
static char *path_control_socket = PATH_CONTROL_SOCKET;

static int
cli_connect(sock *s, uint size UNUSED)
{
  cli *c;

  if (config->cli_debug)
    log(L_INFO "CLI connect");
  c = cli_new(s);
  s->fast_rx = 1;
  cli_run(c);
  return 1;
}

static void
cli_init_unix(uid_t use_uid, gid_t use_gid)
{
  sock *s;

  cli_init();
  s = cli_sk = sk_new(cli_pool);
  s->type = SK_UNIX_PASSIVE;
  s->rx_hook = cli_connect;
  s->rbsize = 1024;
  s->fast_rx = 1;

  /* Return value intentionally ignored */
  unlink(path_control_socket);

  if (sk_open_unix(s, path_control_socket) < 0)
    die("Cannot create control socket %s: %m", path_control_socket);

  if (use_uid || use_gid)
    if (chown(path_control_socket, use_uid, use_gid) < 0)
      die("chown: %m");

  if (chmod(path_control_socket, 0660) < 0)
    die("chmod: %m");
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

  pl = bsnprintf(ps, sizeof(ps), "%ld\n", (long) getpid());
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
  order_shutdown();
}

void
async_shutdown(void)
{
  DBG("Shutting down...\n");
  order_shutdown();
}

void
sysdep_shutdown_done(void)
{
  unlink_pid_file();
  unlink(path_control_socket);
  log_msg(L_FATAL "Shutdown completed");
  exit(0);
}

/*
 *	Signals
 */

volatile int async_config_flag;
volatile int async_dump_flag;
volatile int async_shutdown_flag;

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
static int parse_and_exit;
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
    "  -b                   Run bird in background\n"
    "  -c <config-file>     Use given configuration file instead\n"
    "                       of prefix/etc/bird.conf\n"
    "  -d                   Enable debug messages and run bird in foreground\n"
    "  -D <debug-file>      Log debug messages to given file instead of stderr\n"
    "  -f                   Run bird in foreground\n"
    "  -g <group>           Use given group ID\n"
    "  -h, --help           Display this information\n"
    "  -l                   Look for a configuration file and a communication socket\n"
    "                       file in the current working directory\n"
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
      case 'b':
	run_in_foreground = 0;
	break;
      case 'c':
	config_name = optarg;
	config_changed = 1;
	break;
      case 'd':
	debug_flag |= 1;
	run_in_foreground = 1;
	break;
      case 'D':
	log_init_debug(optarg);
	debug_flag |= 2;
	run_in_foreground = 1;
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
  if (debug_flag == 1)
    log_init_debug("");
  log_switch(debug_flag, NULL, NULL);

  net_init();
  resource_init();
  timer_init();
  olock_init();
  io_init();
  rt_init();
  if_init();
//  roa_init();
  config_init();

  uid_t use_uid = get_uid(use_user);
  gid_t use_gid = get_gid(use_group);

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
  proto_build(&proto_unix_kernel);
  proto_build(&proto_unix_iface);

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
