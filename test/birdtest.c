/*
 *	BIRD -- Unit Test Framework (BIRD Test)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#ifdef HAVE_EXECINFO
#include <execinfo.h>
#endif

#include <sys/ioctl.h>
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

int bt_success;
int bt_test_suite_success;

int
bt_rand_num(void)
{
  /* Seeded in bt_init() */
  return random();
}

void
bt_init(int argc, char *argv[])
{
  int c;

  bt_success = 1;
  srandom(BT_RANDOM_SEED);

  bt_verbose = 0;
  bt_filename = argv[0];
  bt_test_id = NULL;

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
  printf("Usage: %s [-l] [-c] [-f] [-t] [-vvv] [<test_id>]\n", argv[0]);
  exit(3);
}

static void
dump_stack(void)
{
#ifdef HAVE_EXECINFO
  static void *backbuf[50];
  int levels;

  levels = backtrace(backbuf, 50);
  backtrace_symbols_fd(backbuf, levels, STDERR_FILENO);
#endif
}

void
bt_test_suite5(int (*test_fn)(void), const char *test_id, const char *dsc, int forked, int timeout)
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
  bt_test_suite_success = 1;

  bt_test_id = test_id;

  if (bt_verbose >= BT_VERBOSE_DEBUG)
    bt_log("Starting");

  if (!forked)
  {
    alarm(timeout);
    result = test_fn();
    result &= bt_test_suite_success;
  }
  else
  {
    pid_t pid = fork();
    bt_syscall(pid < 0, "fork");

    if (pid == 0)
    {
      alarm(timeout);
      result = test_fn();
      result &= bt_test_suite_success;
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

  bt_success &= (result == BT_SUCCESS ? 1 : 0);
  bt_result((result == BT_SUCCESS ? BT_PROMPT_OK : BT_PROMPT_FAIL), "%s", bt_test_id);
  bt_test_id = NULL;
}

static uint
get_num_terminal_cols(void)
{
  struct winsize w;
  ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
  return w.ws_col;
}

void
bt_result(const char *to_right_align_msg, const char *to_left_align_msg, ...)
{
  if (bt_verbose >= BT_VERBOSE_TEST_SUITE)
  {
    char msg_buf[BT_BUFFER_SIZE];

    snprintf(msg_buf, sizeof(char)*BT_BUFFER_SIZE, "%s: ", bt_filename);

    va_list argptr;
    va_start(argptr, to_left_align_msg);
    vsnprintf(msg_buf + strlen(msg_buf), sizeof(msg_buf), to_left_align_msg, argptr);

    char fmt_buf[BT_BUFFER_SIZE];
    uint line_len = strlen(msg_buf) + BT_PROMPT_OK_FAIL_LEN;
    uint left_offset = (line_len / get_num_terminal_cols() + 1) * get_num_terminal_cols() - BT_PROMPT_OK_FAIL_LEN;
    snprintf(fmt_buf, sizeof(fmt_buf), "%%-%us%%s\n", left_offset);

    fprintf(stderr, fmt_buf, msg_buf, to_right_align_msg);
  }
}

int
bt_end(void)
{
  return !bt_success;
}

void
bt_strncat_(char *buf, size_t buf_size, const char *str, ...)
{
  if (str != NULL)
  {
    va_list argptr;
    va_start(argptr, str);
    vsnprintf(buf + strlen(buf), buf_size, str, argptr);
  }
}
