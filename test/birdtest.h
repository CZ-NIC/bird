/*
 *	BIRD -- Unit Test Framework (BIRD Test)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRDTEST_H_
#define _BIRDTEST_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#include "nest/bird.h"


extern int bt_result;
extern int bt_suite_result;
extern char bt_out_fmt_buf[1024];

extern uint bt_verbose;
#define BT_VERBOSE_NO			0
#define BT_VERBOSE_SUITE		1
#define BT_VERBOSE_SUITE_CASE		2
#define BT_VERBOSE_ABSOLUTELY_ALL	3

extern const char *bt_filename;
extern const char *bt_test_id;

void bt_init(int argc, char *argv[]);
int  bt_exit_value(void);
int bt_test_suite_base(int (*test_fn)(const void *), const char *test_id, const void *test_fn_argument, int forked, int timeout, const char *dsc, ...);
static inline u64 bt_random(void)
{ return ((u64) random() & 0xffffffff) | ((u64) random() << 32); }

void bt_log_suite_result(int result, const char *fmt, ...);
void bt_log_suite_case_result(int result, const char *fmt, ...);

#define BT_TIMEOUT 			5	/* Default timeout in seconds */
#define BT_FORKING 			1	/* Forking is enabled in default */

#define BT_RANDOM_SEED 			0x5097d2bb

#define BT_BUFFER_SIZE 			10000

#define BT_PROMPT_GREEN 		"\e[1;32m"
#define BT_PROMPT_RED 			"\e[1;31m"
#define BT_PROMPT_NORMAL		"\e[0m"
#define BT_PROMPT_OK			" [" BT_PROMPT_GREEN " OK " BT_PROMPT_NORMAL "] "
#define BT_PROMPT_OK_NO_COLOR		" ["                 " OK "                  "] "
#define BT_PROMPT_FAIL			" [" BT_PROMPT_RED   "FAIL" BT_PROMPT_NORMAL "] "
#define BT_PROMPT_FAIL_NO_COLOR		" ["                 "FAIL"                  "] "
#define BT_PROMPT_OK_FAIL_STRLEN	8	/* strlen ' [FAIL] ' */

static inline int bt_test_fn_noarg(const void *cp) { return ((int (*)(void)) cp)(); }

#define bt_test_suite(fn, dsc, ...) \
  bt_test_suite_extra(fn, BT_FORKING, BT_TIMEOUT, dsc, ##__VA_ARGS__)

#define bt_test_suite_extra(fn, f, t, dsc, ...) \
  bt_test_suite_base(bt_test_fn_noarg, #fn, fn, f, t, dsc, ##__VA_ARGS__)

#define bt_test_suite_arg(fn, arg, dsc, ...) \
  bt_test_suite_arg_extra(fn, arg, BT_FORKING, BT_TIMEOUT, dsc, ##__VA_ARGS__)

#define bt_test_suite_arg_extra(fn, arg, f, t, dsc, ...) \
  bt_test_suite_base(fn, #fn, arg, f, t, dsc, ##__VA_ARGS__)

#define bt_abort() \
  bt_abort_msg("Aborted at %s:%d", __FILE__, __LINE__)

#define bt_abort_msg(format, ...) 					\
  do 									\
  { 									\
    bt_log(format, ##__VA_ARGS__); 					\
    abort(); 								\
  } while (0)

#define bt_log(format, ...) 						\
  do 									\
  {	 								\
    if (bt_test_id) 							\
      printf("%s: %s: " format "\n", bt_filename, bt_test_id, ##__VA_ARGS__); \
    else 								\
      printf("%s: " format "\n", bt_filename, ##__VA_ARGS__);		\
  } while(0)

#define bt_debug(format, ...) 						\
  do 									\
  { 									\
    if (bt_verbose >= BT_VERBOSE_ABSOLUTELY_ALL)			\
      printf(format, ##__VA_ARGS__); 					\
  } while (0)

#define bt_assert(test) \
  bt_assert_msg(test, "Assertion (%s) at %s:%d", #test, __FILE__, __LINE__)

#define bt_assert_msg(test, format, ...)				\
  do									\
  {									\
    int bt_suit_case_result = 1;				\
    if ((test) == 0) 							\
    {									\
      bt_result = 0;						\
      bt_suite_result = 0;					\
      bt_suit_case_result = 0;					\
    }									\
    bt_log_suite_case_result(bt_suit_case_result, format, ##__VA_ARGS__); \
  } while (0)

#define bt_syscall(test, format, ...) 					\
  do 									\
  { 									\
    if (test) 								\
    {									\
      bt_log(format ": %s", ##__VA_ARGS__, strerror(errno)); 		\
      exit(3);								\
    }									\
  } while (0)

#define bt_sprintf_concat(s, format, ...) \
    snprintf(s + strlen(s), sizeof(s) - strlen(s), format, ##__VA_ARGS__)

struct bt_pair {
  const void *in;
  const void *out;
};

/* Data structure used by bt_assert_batch() function */
struct bt_batch {
  /* in_fmt / out_fmt - formating data
   * @buf: buffer for write stringified @data
   * @size: empty size in @buf
   * @data: data for stringify
   *
   * There are some build-in functions, see bt_fmt_* functions */
  void (*in_fmt)(char *buf, size_t size, const void *data);
  void (*out_fmt)(char *buf, size_t size, const void *data);

  /* Temporary output buffer */
  void *out_buf;

  /* test_fn - testing function
   * @out: output data from tested function
   * @in: data for input
   * @expected_out: expected data from tested function
   *
   * Input arguments should not be stringified using in_fmt() or out_fmt()
   * function already. This function should return only 0 or 1 */
  int (*test_fn)(void *out, const void *in, const void *expected_out);

  /* Name of testing function @test_fn */
  const char *test_fn_name;

  /* Number of items in data */
  int ndata;

  /* Array of input and expected output pairs */
  struct bt_pair *data;
};

void bt_fmt_str(char *buf, size_t size, const void *data);
void bt_fmt_unsigned(char *buf, size_t size, const void *data);
void bt_fmt_ipa(char *buf, size_t size, const void *data);
int bt_assert_batch__(struct bt_batch *opts);
int bt_is_char(byte c);

#define bt_assert_batch(data__, fn__, in_fmt__, out_fmt__)		\
  bt_assert_batch__(& (struct bt_batch) {				\
    .data = data__,							\
    .ndata = ARRAY_SIZE(data__),					\
    .test_fn = fn__,							\
    .test_fn_name = #fn__,						\
    .in_fmt = in_fmt__,							\
    .out_fmt = out_fmt__,						\
    .out_buf = bt_out_fmt_buf,	/* Global memory for this usage */	\
  })

#endif /* _BIRDTEST_H_ */
