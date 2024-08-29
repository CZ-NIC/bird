#include "flock/flock.h"

#include "lib/string.h"

#include "lib/timer.h"
#include "sysdep/unix/unix.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
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
 * Signal handling
 *
 * We wanna behave as the init process inside the newly create PID namespace
 * which means that the signals have different meanings than for other processes,
 * For more information, see pid_namespaces(7).
 */

static sig_atomic_t signal_received;
#define SIGREQ_REBOOT	1
#define SIGREQ_POWEROFF	2
#define SIGREQ_FAIL	4

static void
hypervisor_reboot_sighandler(int signo UNUSED)
{
  signal_received |= SIGREQ_REBOOT;
}

static void
hypervisor_poweroff_sighandler(int signo UNUSED)
{
  signal_received |= SIGREQ_POWEROFF;
}

static void
hypervisor_fail_sighandler(int signo UNUSED)
{
  signal_received |= SIGREQ_FAIL;

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
      "Usage: %s name\n\n"
      "Runs hypervisor with the given name.\n",
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
  boot_time = current_time();

  log_switch(1, NULL, NULL);

  /* Parse args */
  flock_config.exec_name = argv[0] ?: "flock-sim";
  int opt;
  while ((opt = getopt(argc, argv, "")) != -1)
  {
    /* TODO: add some options */
    usage(stderr);
    return 2;
  }

  /* Get hypervisor name */
  if (optind != argc - 1)
  {
    usage(stderr);
    return 2;
  }

  flock_config.hypervisor_name = argv[optind];

  /* Mask signals for forking and other fragile stuff */
  sigset_t oldmask;
  sigset_t newmask;
  sigemptyset(&newmask);
#define FROB(x) sigaddset(&newmask, x);
  MACRO_FOREACH(FROB, KILLABLE_SIGNALS);
#undef FROB
  sigprocmask(SIG_BLOCK, &newmask, &oldmask);

  /* Keep the original UID/GIDs */
  uid_t euid = geteuid(), egid = getegid();

  /* First we need to create the PID + mount + user namespace to acquire capabilities */
  SYSCALL(unshare, CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER);

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

  /* And now finally we can go for unsharing the rest -- networks and time */
  SYSCALL(unshare, CLONE_NEWTIME | CLONE_NEWNET);

  /* Set signal handlers as this process is init in its PID namespace */
  signal(SIGTERM, hypervisor_poweroff_sighandler);
  signal(SIGINT, hypervisor_poweroff_sighandler);
  signal(SIGHUP, hypervisor_reboot_sighandler);
  signal(SIGQUIT, hypervisor_fail_sighandler);

  /* Unblock signals */
  sigprocmask(SIG_SETMASK, &oldmask, NULL);

  /* Check limits */
  struct rlimit corelimit;
  getrlimit(RLIMIT_CORE, &corelimit);
  log(L_INFO "Core limit %u %u", corelimit.rlim_cur, corelimit.rlim_max);

  /* Wait for Godot */
  log(L_INFO "Hypervisor running");
  while (1)
  {
    pause();

    uint s = signal_received;
    signal_received &= ~s;

    if (s & SIGREQ_FAIL)
      bug("Fail flag should never propagate from signal");
    else if (s & SIGREQ_POWEROFF)
      return 0;
    else if (s & SIGREQ_REBOOT)
      log(L_ERR "Reboot requested but not implemented");
  }
}
