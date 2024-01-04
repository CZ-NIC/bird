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
#include "tools.h"

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
 *	Signals
 */

extern volatile sig_atomic_t async_config_flag;
extern volatile sig_atomic_t async_dump_flag;
extern volatile sig_atomic_t async_shutdown_flag;

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
    /*yi_init_file();
    if (path_control_socket_yi)
    {
      yi_init_unix(use_uid, use_gid);
    }
    else { //todo delete
      path_control_socket_yi = "bird.ctl";
      log(L_INFO "before function");
      yi_init_unix(use_uid, use_gid);
    }*/
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
  log("before main thread init");
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
