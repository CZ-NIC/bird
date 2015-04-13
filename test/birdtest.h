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

extern int bt_success;
extern int bt_test_case_success;

extern int bt_verbose;
#define BT_VERBOSE_NOTHING		0
#define BT_VERBOSE_TEST_CASE		1
#define BT_VERBOSE_DEBUG		2

extern const char *bt_filename;
extern const char *bt_test_id;

void bt_init(int argc, char *argv[]);
int  bt_end(void);
void bt_test_suite5(int (*fn)(void), const char *id, const char *dsc, int forked, int timeout);
int  bt_rand_num(void);
void bt_result(const char *result, const char *msg, ...);

#define BT_SUCCESS 			1
#define BT_FAILURE 			0

#define BT_DEFAULT_TIMEOUT 		5
#define BT_DEFAULT_FORKING 		1

#define BT_RANDOM_SEED 			982451653

#define BT_BUFFER_SIZE 			1000

#define BT_PROMPT_GREEN 		"\e[1;32m"
#define BT_PROMPT_RED 			"\e[1;31m"
#define BT_PROMPT_NORMAL		"\e[0m"
#define BT_PROMPT_OK			" [" BT_PROMPT_GREEN " OK " BT_PROMPT_NORMAL "] "
#define BT_PROMPT_FAIL			" [" BT_PROMPT_RED   "FAIL" BT_PROMPT_NORMAL "] "
#define BT_PROMPT_OK_FAIL_LEN		8
#define BT_PROMPT_FN_GIVES(in_fmt)	"%s(" in_fmt ") gives "
#define BT_PROMPT_EXPECTING		", but expecting is "

#define bt_test_suite(fn,dsc) \
    bt_test_suite4(fn, dsc, BT_DEFAULT_FORKING, BT_DEFAULT_TIMEOUT)

#define bt_test_suite4(fn,dsc,f,t) \
    bt_test_suite5(fn, #fn, dsc, f, t)

#define bt_log(format, ...) \
  do { \
    if (bt_test_id == NULL) \
      fprintf(stderr, "%s: " format "\n", bt_filename, ##__VA_ARGS__); \
    else \
      fprintf(stderr, "%s: %s: " format "\n", bt_filename, bt_test_id, ##__VA_ARGS__); \
  } while(0)

#define bt_log_test_case(format, ...) \
    do { if (bt_verbose >= BT_VERBOSE_TEST_CASE) bt_log(format, ##__VA_ARGS__); } while (0)

#define bt_debug(format, ...) \
    do { if (bt_verbose >= BT_VERBOSE_DEBUG) printf(format, ##__VA_ARGS__); } while (0)

#define bt_result_(result, format, ...)	bt_result(result, "%s: " format, bt_test_id, ##__VA_ARGS__)
#define bt_result_ok(format, ...) 	bt_result_(BT_PROMPT_OK,   format, ##__VA_ARGS__)
#define bt_result_fail(format, ...) 	bt_result_(BT_PROMPT_FAIL, format, ##__VA_ARGS__)

#define bt_result_check(result, format, ...) \
    do { if (bt_verbose >= BT_VERBOSE_TEST_CASE) bt_result_(result, format, ##__VA_ARGS__); } while (0)

#define bt_result_check_ok(format, ...) \
  do { if (bt_verbose >= BT_VERBOSE_TEST_CASE) bt_result_ok(format, ##__VA_ARGS__); } while (0)

#define bt_result_check_fail(format, ...) \
  do { if (bt_verbose >= BT_VERBOSE_TEST_CASE) bt_result_fail(format, ##__VA_ARGS__); } while (0)

#define bt_abort() \
    bt_abort_msg("Aborted at %s:%d", __FILE__, __LINE__)

#define bt_abort_msg(format, ...) \
    do { bt_log(format, ##__VA_ARGS__); abort(); } while (0)

#define bt_assert(test) \
    bt_assert_msg(test, "Assertion (%s) failed at %s:%d", #test, __FILE__, __LINE__)

#define bt_assert_msg(test, format, ...) \
    do { if (!(test)) { \
      if (bt_verbose) bt_log(format, ##__VA_ARGS__); \
      bt_success = bt_test_case_success = 0; \
    } } while (0)

#define bt_syscall(test,format, ...) \
    do { if (test) { bt_log(format ": %s", ##__VA_ARGS__, strerror(errno)); exit(3); } } while (0)

#define bt_assert_fn_in(fn, in_out, in_fmt, out_fmt)					\
    do											\
    {											\
      unsigned int i;									\
      for (i = 0; i < (sizeof(in_out)/sizeof(in_out[0])); i++)				\
      {											\
	int single_test_case_success = fn(in_out[i].in) == in_out[i].out;		\
	bt_test_case_success &= single_test_case_success;				\
	if (single_test_case_success)							\
	  bt_result_check_ok(BT_PROMPT_FN_GIVES(in_fmt) out_fmt, #fn, in_out[i].in, fn(in_out[i].in)); \
	else										\
	  bt_result_check_fail(BT_PROMPT_FN_GIVES(in_fmt) out_fmt BT_PROMPT_EXPECTING out_fmt, #fn, in_out[i].in, fn(in_out[i].in), in_out[i].out); \
      }											\
    } while (0)

#define bt_assert_fn_in_out(fn, in_out, in_fmt, out_fmt)				\
    do											\
    {											\
      unsigned int i;									\
      for (i = 0; i < (sizeof(in_out)/sizeof(in_out[0])); i++)				\
      {											\
	fn(in_out[i].in, &in_out[i].fn_out);						\
	int single_test_case_success = !memcmp(&in_out[i].fn_out, &in_out[i].out, sizeof(in_out[i].out)); \
	bt_test_case_success &= single_test_case_success;				\
	if (single_test_case_success)							\
	  bt_result_check_ok  (BT_PROMPT_FN_GIVES(in_fmt) out_fmt, #fn, in_out[i].in, in_out[i].fn_out); \
	else 										\
	  bt_result_check_fail(BT_PROMPT_FN_GIVES(in_fmt) out_fmt BT_PROMPT_EXPECTING out_fmt, #fn, in_out[i].in, in_out[i].fn_out, in_out[i].out); \
      }											\
    } while (0)

#define bt_strcat(buf, str, ...) snprintf(buf + strlen(buf), sizeof(buf), str, ##__VA_ARGS__)

#define bt_dump_struct(buf, data)							\
    do											\
    {											\
      unsigned int bt_j;								\
      u32 *bt_pc = (u32*) data;								\
      bt_strcat(buf, "{");								\
      for (bt_j = 0; bt_j < (sizeof(*data) / sizeof(typeof(*bt_pc))); bt_j++)		\
	bt_strcat(buf, "%s0x%08X", (bt_j ? ", " : ""), bt_pc[bt_j]);			\
      bt_strcat(buf, "}");								\
    } while (0)

#define bt_assert_fn_in_out_struct(fn, in_out, in_fmt)					\
    do											\
    {											\
      char bt_buf[BT_BUFFER_SIZE];							\
      unsigned int i;									\
      for (i = 0; i < (sizeof(in_out)/sizeof(in_out[0])); i++)				\
      {											\
	strcpy(bt_buf, "");								\
	fn(in_out[i].in, &in_out[i].fn_out);						\
	int single_test_case_success = !memcmp(&in_out[i].fn_out, in_out[i].out, sizeof(in_out[i].out)); \
	bt_test_case_success &= single_test_case_success;				\
	bt_strcat(bt_buf, BT_PROMPT_FN_GIVES(in_fmt), #fn, in_out[i].in);		\
	bt_dump_struct(bt_buf, &in_out[i].fn_out); 					\
	if (!single_test_case_success) 							\
	{										\
	  bt_strcat(bt_buf, BT_PROMPT_EXPECTING); 					\
	  bt_dump_struct(bt_buf, &in_out[i].out); 					\
	} 										\
	bt_result_check((single_test_case_success ? BT_PROMPT_OK : BT_PROMPT_FAIL), "%s", bt_buf); \
      }											\
    } while (0)

#endif /* _BIRDTEST_H_ */
