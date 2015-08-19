/*
 *	BIRD Internet Routing Daemon -- Unix Entry Point
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

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
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/event.h"
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

#include "lib/main_helper.h"


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

  resource_init();
  olock_init();
  io_init();
  rt_init();
  if_init();
  roa_init();
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

  if (!(debug_flag||run_in_foreground))
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
