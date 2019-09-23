/*
 *	BIRD -- Unit Test Framework (BIRD Test)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "test/birdtest.h"
#include "lib/string.h"

#ifdef HAVE_EXECINFO_H
#include <execinfo.h>
#endif

#define BACKTRACE_MAX_LINES 100

#define sprintf_concat(s, format, ...) \
    snprintf(s + strlen(s), sizeof(s) - strlen(s), format, ##__VA_ARGS__)

static const char *request;
static int list_tests;
static int do_core;
static int do_die;
static int no_fork;
static int no_timeout;
static int is_terminal;		/* Whether stdout is a live terminal or pipe redirect */

volatile sig_atomic_t async_config_flag;		/* Asynchronous reconfiguration/dump scheduled */
volatile sig_atomic_t async_dump_flag;
volatile sig_atomic_t async_shutdown_flag;


uint bt_verbose;
const char *bt_filename;
const char *bt_test_id;

int bt_result;			/* Overall program run result */
int bt_suite_result;		/* One suit result */
char bt_out_fmt_buf[1024];	/* Temporary memory buffer for output of testing function */

struct timespec bt_begin, bt_suite_begin, bt_suite_case_begin;

u64 bt_random_state[] = {
  0x80241f302bd4d95d, 0xd10ba2e910f772b, 0xea188c9046f507c5, 0x4c4c581f04e6da05,
  0x53d9772877c1b647, 0xab8ce3eb466de6c5, 0xad02844c8a8e865f, 0xe8cc78080295065d
};

void
bt_init(int argc, char *argv[])
{
  int c;

  initstate(BT_RANDOM_SEED, (char *) bt_random_state, sizeof(bt_random_state));

  bt_verbose = 0;
  bt_filename = argv[0];
  bt_result = 1;
  bt_test_id = NULL;
  is_terminal = isatty(fileno(stdout));

  while ((c = getopt(argc, argv, "lcdftv")) >= 0)
    switch (c)
    {
      case 'l':
	list_tests = 1;
	break;

      case 'c':
	do_core = 1;
	break;

      case 'd':
	do_die = 1;
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

  clock_gettime(CLOCK_MONOTONIC, &bt_begin);

  return;

 usage:
  printf("Usage: %s [-l] [-c] [-d] [-f] [-t] [-vvv] [<test_suit_name>]\n", argv[0]);
  printf("Options: \n");
  printf("  -l   List all test suite names and descriptions \n");
  printf("  -c   Force unlimit core dumps (needs root privileges) \n");
  printf("  -d	 Die on first failed test case \n");
  printf("  -f   No forking \n");
  printf("  -t   No timeout limit \n");
  printf("  -v   More verbosity, maximum is 3 -vvv \n");
  exit(3);
}

static void
bt_dump_backtrace(void)
{
#ifdef HAVE_EXECINFO_H
  void *buf[BACKTRACE_MAX_LINES];
  char **pp_backtrace;
  int lines, j;

  if (!bt_verbose)
    return;

  lines = backtrace(buf, BACKTRACE_MAX_LINES);
  bt_log("backtrace() returned %d addresses", lines);

  pp_backtrace = backtrace_symbols(buf, lines);
  if (pp_backtrace == NULL)
  {
    perror("backtrace_symbols");
    exit(EXIT_FAILURE);
  }

  for (j = 0; j < lines; j++)
    bt_log("%s", pp_backtrace[j]);

  free(pp_backtrace);
#endif /* HAVE_EXECINFO_H */
}

static
int bt_run_test_fn(int (*fn)(const void *), const void *fn_arg, int timeout)
{
  int result;
  alarm(timeout);

  result = fn(fn_arg);

  if (!bt_suite_result)
    result = 0;

  return result;
}

static uint
get_num_terminal_cols(void)
{
  struct winsize w = {};
  ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
  uint cols = w.ws_col;
  return (cols > 0 ? cols : 80);
}

/**
 * bt_log_result - pretty print of test result
 * @result: 1 or 0
 * @fmt: a description message (could be long, over more lines)
 * @argptr: variable argument list
 *
 * This function is used for pretty printing of test results on all verbose
 * levels.
 */
static void
bt_log_result(int result, u64 time, const char *fmt, va_list argptr)
{
  static char msg_buf[BT_BUFFER_SIZE];
  char *pos;

  snprintf(msg_buf, sizeof(msg_buf), "%s%s%s%s %" PRIu64 ".%09" PRIu64 "s",
	   bt_filename,
	   bt_test_id ? ": " : "",
	   bt_test_id ? bt_test_id : "",
	   (fmt && strlen(fmt) > 0) ? ": " : "",
	   time / 1000000000,
	   time % 1000000000
	   );
  pos = msg_buf + strlen(msg_buf);

  if (fmt)
    vsnprintf(pos, sizeof(msg_buf) - (pos - msg_buf), fmt, argptr);

  int chrs = 0;
  for (uint i = 0; i < strlen(msg_buf); i += get_num_terminal_cols())
  {
    if (i)
      printf("\n");
    char *stop = msg_buf + i + get_num_terminal_cols();
    char backup = *stop;
    *stop = 0;
    chrs = printf("%s", msg_buf + i);
    *stop = backup;
  }

  int offset = get_num_terminal_cols() - chrs - BT_PROMPT_OK_FAIL_STRLEN;
  if (offset < 0)
  {
    printf("\n");
    offset = get_num_terminal_cols() - BT_PROMPT_OK_FAIL_STRLEN;
  }

  for (int i = 0; i < offset; i++)
    putchar(' ');

  const char *result_str = is_terminal ? BT_PROMPT_OK : BT_PROMPT_OK_NO_COLOR;
  if (!result)
    result_str = is_terminal ? BT_PROMPT_FAIL : BT_PROMPT_FAIL_NO_COLOR;

  printf("%s\n", result_str);

  if (do_die && !result)
    abort();
}

static u64
get_time_diff(struct timespec *begin)
{
  struct timespec end;
  clock_gettime(CLOCK_MONOTONIC, &end);
  return (end.tv_sec - begin->tv_sec) * 1000000000ULL
    + end.tv_nsec - begin->tv_nsec;
}

/**
 * bt_log_overall_result - pretty print of suite case result
 * @result: 1 or 0
 * @fmt: a description message (could be long, over more lines)
 * ...: variable argument list
 *
 * This function is used for pretty printing of test suite case result.
 */
static void
bt_log_overall_result(int result, const char *fmt, ...)
{
  va_list argptr;
  va_start(argptr, fmt);
  bt_log_result(result, get_time_diff(&bt_begin), fmt, argptr);
  va_end(argptr);
}

/**
 * bt_log_suite_result - pretty print of suite case result
 * @result: 1 or 0
 * @fmt: a description message (could be long, over more lines)
 * ...: variable argument list
 *
 * This function is used for pretty printing of test suite case result.
 */
void
bt_log_suite_result(int result, const char *fmt, ...)
{
  if (bt_verbose >= BT_VERBOSE_SUITE || !result)
  {
    va_list argptr;
    va_start(argptr, fmt);
    bt_log_result(result, get_time_diff(&bt_suite_begin), fmt, argptr);
    va_end(argptr);
  }
}

/**
 * bt_log_suite_case_result - pretty print of suite result
 * @result: 1 or 0
 * @fmt: a description message (could be long, over more lines)
 * ...: variable argument list
 *
 * This function is used for pretty printing of test suite result.
 */
void
bt_log_suite_case_result(int result, const char *fmt, ...)
{
  if(bt_verbose >= BT_VERBOSE_SUITE_CASE)
  {
    va_list argptr;
    va_start(argptr, fmt);
    bt_log_result(result, get_time_diff(&bt_suite_case_begin), fmt, argptr);
    va_end(argptr);
  }
}

int
bt_test_suite_base(int (*fn)(const void *), const char *id, const void *fn_arg, int forked, int timeout, const char *dsc, ...)
{
  if (list_tests)
  {
    printf("%28s - ", id);
    va_list args;
    va_start(args, dsc);
    vprintf(dsc, args);
    va_end(args);
    printf("\n");
    return 1;
  }

  if (no_fork)
    forked = 0;

  if (no_timeout)
    timeout = 0;

  if (request && strcmp(id, request))
    return 1;

  bt_suite_result = 1;
  bt_test_id = id;

  if (bt_verbose >= BT_VERBOSE_ABSOLUTELY_ALL)
    bt_log("Starting");

  clock_gettime(CLOCK_MONOTONIC, &bt_suite_begin);

  if (!forked)
  {
    bt_suite_result = bt_run_test_fn(fn, fn_arg, timeout);
  }
  else
  {
    pid_t pid = fork();
    bt_syscall(pid < 0, "fork");

    if (pid == 0)
    {
      /* child of fork */
      _exit(bt_run_test_fn(fn, fn_arg, timeout));
    }

    int s;
    int rv = waitpid(pid, &s, 0);
    bt_syscall(rv < 0, "waitpid");

    if (WIFEXITED(s))
    {
      /* Normal exit */
      bt_suite_result = WEXITSTATUS(s);
    }
    else if (WIFSIGNALED(s))
    {
      /* Stopped by signal */
      bt_suite_result = 0;

      int sn = WTERMSIG(s);
      if (sn == SIGALRM)
      {
	bt_log("Timeout expired");
      }
      else if (sn == SIGSEGV)
      {
	bt_log("Segmentation fault");
	bt_dump_backtrace();
      }
      else if (sn != SIGABRT)
	bt_log("Signal %d received", sn);
    }

    if (WCOREDUMP(s) && bt_verbose)
      bt_log("Core dumped");
  }

  if (!bt_suite_result)
    bt_result = 0;

  bt_log_suite_result(bt_suite_result, NULL);
  bt_test_id = NULL;

  return bt_suite_result;
}

int
bt_exit_value(void)
{
  if (!list_tests || (list_tests && !bt_result))
    bt_log_overall_result(bt_result, "");
  return bt_result ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * bt_assert_batch__ - test a batch of inputs/outputs tests
 * @opts: includes all necessary data
 *
 * Should be called using macro bt_assert_batch().
 * Returns 1 or 0.
 */
int
bt_assert_batch__(struct bt_batch *opts)
{
  int i;
  for (i = 0; i < opts->ndata; i++)
  {
    if (bt_verbose >= BT_VERBOSE_SUITE)
      clock_gettime(CLOCK_MONOTONIC, &bt_suite_case_begin);

    int bt_suit_case_result = opts->test_fn(opts->out_buf, opts->data[i].in, opts->data[i].out);

    if (bt_suit_case_result == 0)
      bt_suite_result = 0;

    char b[BT_BUFFER_SIZE];
    snprintf(b, sizeof(b), "%s(", opts->test_fn_name);

    opts->in_fmt(b+strlen(b), sizeof(b)-strlen(b), opts->data[i].in);
    sprintf_concat(b, ") gives ");
    opts->out_fmt(b+strlen(b), sizeof(b)-strlen(b), opts->out_buf);

    if (bt_suit_case_result == 0)
    {
      sprintf_concat(b, ", but expecting is ");
      opts->out_fmt(b+strlen(b), sizeof(b)-strlen(b), opts->data[i].out);
    }

    bt_log_suite_case_result(bt_suit_case_result, "%s", b);
  }

  return bt_suite_result;
}

/**
 * bt_fmt_str - formating string into output buffer
 * @buf: buffer for write
 * @size: empty size in @buf
 * @data: null-byte terminated string
 *
 * This function can be used with bt_assert_batch() function.
 * Input @data should be const char * string.
 */
void
bt_fmt_str(char *buf, size_t size, const void *data)
{
  const byte *s = data;

  snprintf(buf, size, "\"");
  while (*s)
  {
    snprintf(buf+strlen(buf), size-strlen(buf), bt_is_char(*s) ? "%c" : "\\%03u", *s);
    s++;
  }
  snprintf(buf+strlen(buf), size-strlen(buf), "\"");
}

/**
 * bt_fmt_unsigned - formating unsigned int into output buffer
 * @buf: buffer for write
 * @size: empty size in @buf
 * @data: unsigned number
 *
 * This function can be used with bt_assert_batch() function.
 */
void
bt_fmt_unsigned(char *buf, size_t size, const void *data)
{
  const uint *n = data;
  snprintf(buf, size, "0x%x (%u)", *n, *n);
}

/**
 * bt_fmt_ipa - formating ip_addr into output buffer
 * @buf: buffer for write
 * @size: empty size in @buf
 * @data: should be struct ip_addr *
 *
 * This function can be used with bt_assert_batch() function.
 */
void
bt_fmt_ipa(char *buf, size_t size, const void *data)
{
  const ip_addr *ip = data;
  bsnprintf(buf, size, "%I", *ip);
}

int
bt_is_char(byte c)
{
  return (c >= (byte) 32 && c <= (byte) 126);
}

/*
 * Mock-ups of all necessary public functions in main.c
 */

char *bird_name;
void async_config(void) {}
void async_dump(void) {}
void async_shutdown(void) {}
void cmd_check_config(char *name UNUSED) {}
void cmd_reconfig(char *name UNUSED, int type UNUSED, int timeout UNUSED) {}
void cmd_reconfig_confirm(void) {}
void cmd_reconfig_undo(void) {}
void cmd_reconfig_status(void) {}
void cmd_graceful_restart(void) {}
void cmd_shutdown(void) {}
void cmd_reconfig_undo_notify(void) {}

#include "nest/bird.h"
#include "lib/net.h"
#include "conf/conf.h"
void sysdep_preconfig(struct config *c UNUSED) {}
int sysdep_commit(struct config *new UNUSED, struct config *old UNUSED) { return 0; }
void sysdep_shutdown_done(void) {}

#include "nest/cli.h"
int cli_get_command(cli *c UNUSED) { return 0; }
void cli_write_trigger(cli *c UNUSED) {}
cli *cmd_reconfig_stored_cli;
