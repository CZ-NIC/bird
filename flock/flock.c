#include "flock/flock.h"

#include "lib/obstacle.h"
#include "lib/runtime.h"
#include "lib/string.h"
#include "lib/timer.h"
#include "sysdep/unix/unix.h"
#include "sysdep/unix/io-loop.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Overall configuration */
struct flock_config flock_config;

/**
 * Shutdown routines
 */
event_list shutdown_event_list;
struct shutdown_placeholder shutdown_placeholder;

static void
reboot_event_hook(void *data UNUSED)
{
  log(L_ERR "Reboot requested but not implemented");
}

static void
poweroff_event_hook(void *data UNUSED)
{
  log(L_INFO "Shutdown requested.");
  ev_run_list(&shutdown_event_list);
}

static void
child_event_hook(void *data UNUSED)
{
  log(L_INFO "Zombie elimination routine invoked.");
  while (1) {
    int status;
    pid_t p = waitpid(-1, &status, WNOHANG);

    if (p < 0)
    {
      log(L_ERR "Zombie elimination failed: %m");
      return;
    }

    if (p == 0)
      return;

    const char *coreinfo = WCOREDUMP(status) ? " (core dumped)" : "";

    if (WIFEXITED(status))
      log(L_INFO "Process %d ended with status %d%s", p, WEXITSTATUS(status), coreinfo);
    else if (WIFSIGNALED(status))
      log(L_INFO "Process %d exited by signal %d (%s)%s", p, WTERMSIG(status), strsignal(WTERMSIG(status)), coreinfo);
    else
      log(L_ERR "Process %d exited with a strange status %d", p, status);
  }
}

event reboot_event = { .hook = reboot_event_hook },
      poweroff_event = { .hook = poweroff_event_hook },
      child_event = { .hook = child_event_hook };

callback shutdown_done_callback;

static void
shutdown_done(callback *c UNUSED)
{
  log(L_INFO "Shutdown finished.");
  exit(0);
}

/**
 * Signal handling
 *
 * We wanna behave as the init process inside the newly create PID namespace
 * which means that the signals have different meanings than for other processes,
 * For more information, see pid_namespaces(7).
 */

static void
hypervisor_reboot_sighandler(int signo UNUSED)
{
  ev_send_loop(&main_birdloop, &reboot_event);
}

static void
hypervisor_poweroff_sighandler(int signo UNUSED)
{
  ev_send_loop(&main_birdloop, &poweroff_event);
}

static void
hypervisor_fail_sighandler(int signo UNUSED)
{
  int e = fork();
  if (e == 0)
  {
    signal(SIGABRT, SIG_DFL);
    abort();
  }

  if (e > 0)
    waitpid(e, NULL, 0);

  _exit(1);
}

static void
hypervisor_child_sighandler(int signo UNUSED)
{
  ev_send_loop(&main_birdloop, &child_event);
}

/*
 * The Main.
 *
 * Bootstrapping and all the fiddling around before anything can actually
 * be really executed.
 */

#define SYSCALL(x, ...)	({ int e = x(__VA_ARGS__); if (e < 0) die("Failed to run %s at %s:%d: %m", #x, __FILE__, __LINE__); e; })

#define KILLABLE_SIGNALS  SIGINT, SIGTERM, SIGHUP, SIGQUIT

static inline void
usage(FILE *f)
{
  fprintf(f,
      "Usage: %s [options] name\n\n"
      "Runs Flock hypervisor with the given name.\n"
      "\n"
      "Options:\n"
      "\t-s <path>\topen control socket at this path\n"
      "\t-l       \tshortcut for -s ./<name>.ctl\n"
      "\n",
      flock_config.exec_name);
}

int
main(int argc, char **argv, char **argh UNUSED)
{
  /* Prepare necessary infrastructure */
  the_bird_lock();
  times_update();
  resource_init();
  random_init();

  birdloop_init();

  struct global_runtime gr = *atomic_load_explicit(&global_runtime, memory_order_relaxed);
//  gr.latency_debug = ~0;
  switch_runtime(&gr);

  ev_init_list(&global_event_list, &main_birdloop, "Global event list");
  ev_init_list(&global_work_list, &main_birdloop, "Global work list");
  ev_init_list(&main_birdloop.event_list, &main_birdloop, "Global fast event list");

  /* Shutdown hooks */
  ev_init_list(&shutdown_event_list, &main_birdloop, "Shutdown event list");
  callback_init(&shutdown_done_callback, shutdown_done, &main_birdloop);
  obstacle_target_init(
      &shutdown_placeholder.obstacles,
      &shutdown_done_callback, &root_pool, "Shutdown");

  boot_time = current_time();

  log_switch(1, NULL, NULL);

  /* Find the original UID/GIDs */
  uid_t euid = geteuid(), egid = getegid();

  /* Parse args */
  flock_config.exec_name = argv[0] ?: "flock-sim";
  int opt;
  bool csp_local = 0;
  while ((opt = getopt(argc, argv, "ls:")) != -1)
  {
    switch (opt)
    {
      case 'l':
	csp_local = 1;
	break;

      case 's':
	csp_local = 0;
	flock_config.control_socket_path = mb_strdup(&root_pool, optarg);
	break;

      default:
	usage(stderr);
	return 2;
    }
  }

  /* Get hypervisor name */
  if (optind != argc - 1)
  {
    usage(stderr);
    return 2;
  }

  flock_config.hypervisor_name = argv[optind];

  /* Fix the control socket path if -l was given */
  if (csp_local)
    flock_config.control_socket_path = mb_sprintf(&root_pool, "./%s.ctl", flock_config.hypervisor_name);
  else if (!flock_config.control_socket_path)
  {
    fprintf(stderr, "No control socket path given, use -s or -l.");
    usage(stderr);
    return 2;
  }

  /* Mask signals for forking and other fragile stuff */
  sigset_t oldmask;
  sigset_t newmask;
  sigemptyset(&newmask);
#define FROB(x) sigaddset(&newmask, x);
  MACRO_FOREACH(FROB, KILLABLE_SIGNALS);
#undef FROB
  sigprocmask(SIG_BLOCK, &newmask, &oldmask);

  /* First we need to create the PID + mount + user namespace to acquire capabilities,
   * and also time namespace for good measure */
  SYSCALL(unshare, CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWTIME);

  /* Then we have to fork() to become PID 1 of the new PID namespace */
  pid_t init_pid = fork();
  if (init_pid < 0)
    die("Failed to become init: %m");

  /* The parent process may end now
   * TODO: allow wait() and/or writing PIDfile
   * instead of just ending */
  if (init_pid > 0)
    return 0;

  /* We also need to fix some UID/GID mappings to become local root.
   * TODO: this will need an upgrade for full-scale containers. */
#define WRITE_ONCE(file, data, len) do {	\
  int fd = SYSCALL(open, file, O_WRONLY);	\
  int e = write(fd, data, len);			\
  if (e != len) die("Failed to write %s to %s", data, file);  \
  close(fd);					\
} while (0)

  {
    char fixer[256];
    int len = bsnprintf(fixer, sizeof fixer, "0 %d 1", euid);
    WRITE_ONCE("/proc/self/uid_map", fixer, len);

    WRITE_ONCE("/proc/self/setgroups", "deny", sizeof "deny");

    len = bsnprintf(fixer, sizeof fixer, "0 %d 1", egid);
    WRITE_ONCE("/proc/self/gid_map", fixer, len);
  }
#undef WRITE_ONCE

  /* Remounting proc to reflect the new PID namespace */
  SYSCALL(mount, "none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
  SYSCALL(mount, "proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);

  /* Now we are init but in the original network namespace,
   * let's spawn a child to do external communication before unsharing */
  hypervisor_exposed_fork();

  /* We also need to prepare all the hypervisor-init stuff */
  hypervisor_control_socket();

  /* And now finally we can go for unsharing the networks */
  SYSCALL(unshare, CLONE_NEWNET);

  /* Before resuming, we also need to fork the container forker */
  hypervisor_container_fork();

  /* Set signal handlers as this process is init in its PID namespace */
  signal(SIGTERM, hypervisor_poweroff_sighandler);
  signal(SIGINT, hypervisor_poweroff_sighandler);
  signal(SIGHUP, hypervisor_reboot_sighandler);
  signal(SIGQUIT, hypervisor_fail_sighandler);
  signal(SIGCHLD, hypervisor_child_sighandler);

  /* Unblock signals */
  sigprocmask(SIG_SETMASK, &oldmask, NULL);

  /* Check limits */
  struct rlimit corelimit;
  getrlimit(RLIMIT_CORE, &corelimit);
  log(L_INFO "Core limit %u %u", corelimit.rlim_cur, corelimit.rlim_max);

  /* Run worker threads */
  struct thread_config tc = {};
  bird_thread_commit(&tc);

  /* Wait for Godot */
  log(L_INFO "Hypervisor running");
  birdloop_minimalist_main();
}
