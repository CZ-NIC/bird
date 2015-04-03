/*
 *	BIRD -- Unit Test Framework (BIRD Test)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <execinfo.h>

#include <sys/resource.h>
#include <sys/wait.h>

#include "test/birdtest.h"


static const char *request;
static int list_tests;
static int do_core;
static int no_fork;
static int no_timeout;

int bt_verbose;
const char *bt_filename;
const char *bt_test_id;

void
bt_init(int argc, char *argv[])
{
  int c;

  srandom(BT_RANDOM_SEED);

  bt_verbose = 0;
  bt_filename = argv[0];

  while ((c = getopt(argc, argv, "lcftv")) >= 0)
    switch (c)
    {
      case 'l':
	printf("\n"
	       "          List of test cases  \n"
	       "------------------------------\n");
	list_tests = 1;
	return;

      case 'c':
	do_core = 1;
	break;

      case 'f':
	no_fork = 1;
	break;

      case 't':
	no_timeout = 1;
	break;

      case 'v':
	bt_verbose++;
	break;

      default:
	goto usage;
    }

  /* Optional requested test_id */
  if ((optind + 1) == argc)
    request = argv[optind++];

  if (optind != argc)
    goto usage;


  if (do_core)
  {
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    int rv = setrlimit(RLIMIT_CORE, &rl);
    bt_syscall(rv < 0, "setrlimit RLIMIT_CORE");
  }

  return;

  usage:
  printf("Usage: %s [-l] [-c] [-f] [-t] [-vv] [<test_id>]\n", argv[0]);
  exit(3);
}

static void
dump_stack(void)
{
  static void *backbuf[50];
  int levels;

  levels = backtrace(backbuf, 50);
  backtrace_symbols_fd(backbuf, levels, STDERR_FILENO);
}

void
bt_test_case5(int (*test_fn)(void), const char *test_id, const char *dsc, int forked, int timeout)
{
  if (list_tests)
  {
    printf("%28s : %s\n", test_id, dsc);
    return;
  }

  if (no_fork)
    forked = 0;

  if (no_timeout)
    timeout = 0;

  if (request && strcmp(test_id, request))
    return;

  int result = 0;

  bt_test_id = test_id;

  bt_note("Starting %s: %s", test_id, dsc);

  if (!forked)
  {
    alarm(timeout);
    result = test_fn();
  }
  else
  {
    pid_t pid = fork();
    bt_syscall(pid < 0, "fork");

    if (pid == 0)
    {
      alarm(timeout);
      result = test_fn();
      _exit(result);
    }

    int s;
    int rv = waitpid(pid, &s, 0);
    bt_syscall(rv < 0, "waitpid");

    result = 2;
    if (WIFEXITED(s))
      result = WEXITSTATUS(s);
    else if (WIFSIGNALED(s))
    {
      int sn = WTERMSIG(s);
      if (sn == SIGALRM)
	bt_log("Timeout expired");
      else if (sn == SIGSEGV)
      {
	bt_log("Segmentation fault:");
	dump_stack();
      }
      else if (sn != SIGABRT)
	bt_log("Signal %d received", sn);
    }

    if (WCOREDUMP(s))
      bt_log("Core dumped");
  }

  if (result != BT_SUCCESS)
  {
    bt_log("Test case failed");
    exit(result);
  }

  bt_note("OK");
}

int
bt_rand_num(void)
{
  return random();
}
