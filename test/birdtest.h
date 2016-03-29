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

extern uint bt_success;
extern uint bt_test_suite_success;

extern uint bt_verbose;
#define BT_VERBOSE_NOTHING		0
#define BT_VERBOSE_TEST_SUITE		1
#define BT_VERBOSE_TEST_CASE		2
#define BT_VERBOSE_DEBUG		3

extern const char *bt_filename;
extern const char *bt_test_id;

void bt_init(int argc, char *argv[]);
int  bt_end(void);
void bt_test_suite_base(int (*test_fn)(const void *), const char *test_id, const void *test_fn_argument, int forked, int timeout, const char *dsc, ...);
long int bt_random(void);
void bt_result(const char *result, const char *msg, ...);

#define BT_SUCCESS 			0
#define BT_FAILURE 			1

#define BT_DEFAULT_TIMEOUT 		5
#define BT_DEFAULT_FORKING 		1

#define BT_RANDOM_SEED 			982451653

#define BT_BUFFER_SIZE 			10000

#define BT_PROMPT_GREEN 		"\e[1;32m"
#define BT_PROMPT_RED 			"\e[1;31m"
#define BT_PROMPT_NORMAL		"\e[0m"
#define BT_PROMPT_OK			" [" BT_PROMPT_GREEN " OK " BT_PROMPT_NORMAL "] "
#define BT_PROMPT_FAIL			" [" BT_PROMPT_RED   "FAIL" BT_PROMPT_NORMAL "] "
#define BT_PROMPT_OK_FAIL_LEN		8
#define BT_PROMPT_FN_GIVES(in_fmt)	"%s(" in_fmt ") gives "
#define BT_PROMPT_EXPECTING		", but expecting is "

#define bt_test_suite(fn, dsc, ...) \
    bt_test_suite_extra(fn, BT_DEFAULT_FORKING, BT_DEFAULT_TIMEOUT, dsc, ##__VA_ARGS__)

#define bt_test_suite_extra(fn, f, t, dsc, ...) \
    bt_test_suite_base((int (*)(const void *))fn, #fn, NULL, f, t, dsc, ##__VA_ARGS__)

#define bt_test_suite_arg(fn, arg, dsc, ...) \
    bt_test_suite_arg_extra(fn, arg, BT_DEFAULT_FORKING, BT_DEFAULT_TIMEOUT, dsc, ##__VA_ARGS__)

#define bt_test_suite_arg_extra(fn, arg, f, t, dsc, ...) \
    bt_test_suite_base(fn, #fn, arg, f, t, dsc, ##__VA_ARGS__)

#define bt_log(format, ...) \
    do { \
      if (bt_test_id == NULL) \
      fprintf(stderr, "%s: " format "\n", bt_filename, ##__VA_ARGS__); \
      else \
      fprintf(stderr, "%s: %s: " format "\n", bt_filename, bt_test_id, ##__VA_ARGS__); \
    } while(0)

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

#define bt_equal(a, b) \
    bt_assert_msg((a) == (b), "Assertion (%s == %s) failed at %s:%d.", #a, #b, __FILE__, __LINE__)

#define bt_assert_msg(test, format, ...) 						\
    do 											\
    {											\
      if (!(test))									\
      { 										\
	if (bt_verbose)									\
	{										\
	  bt_log(format, ##__VA_ARGS__); 						\
	}										\
	bt_test_suite_success = BT_FAILURE; 						\
      }											\
    } while (0)

#define bt_syscall(test,format, ...) \
    do { if (test) { bt_log(format ": %s", ##__VA_ARGS__, strerror(errno)); exit(3); } } while (0)


#define bt_strncat(buf, str, ...) \
    snprintf(buf + strlen(buf), sizeof(buf), str, ##__VA_ARGS__)

void bt_strncat_(char *buf, size_t buf_size, const char *str, ...);

#define bt_dump_struct(buf, data)							\
    do											\
    {											\
      uint k;										\
      u32 *pc = (u32*) data;								\
      bt_strncat(buf, "{");								\
      for (k = 0; k < (sizeof(*data) / sizeof(typeof(*pc))); k++)			\
      {											\
	bt_strncat(buf, "%s0x%08X", (k ? ", " : ""), pc[k]);				\
      }											\
      bt_strncat(buf, "}");								\
    } while (0)

#define bt_dump(buf, data, fmt)								\
    do											\
    {											\
      if (fmt == NULL)									\
      {											\
	bt_dump_struct(buf, &data);							\
      }											\
      else										\
      {											\
	bt_strncat_(buf, sizeof(buf), fmt, data);					\
      }											\
    } while (0)

#define bt_print_result_line(fn, in, out, fn_out, in_fmt, out_fmt, result)		\
    do											\
    {											\
      char buf[BT_BUFFER_SIZE];								\
      snprintf(buf, sizeof(buf), "%s(", #fn);						\
      bt_dump(buf, in, in_fmt);								\
      bt_strncat(buf, ") gives ");							\
      bt_dump(buf, fn_out, out_fmt);							\
      if (!result) 									\
      {											\
	bt_strncat(buf, BT_PROMPT_EXPECTING); 						\
	bt_dump(buf, out, out_fmt);							\
      } 										\
      bt_result_check((single_test_case_success ? BT_PROMPT_OK : BT_PROMPT_FAIL), "%s", buf); \
    } while (0)

/**
 * Usage:
 * 	u32 my_function(const char *input_data) { ... }
 *
 *	struct in_out {
 *     		char *in;
 *   		u32  out;
 * 	} in_out[] = { ... };
 *
 * 	bt_assert_out_fn_in(my_function, in_out, "%s", "%u");
 */
#define bt_assert_out_fn_in(fn, in_out, in_fmt, out_fmt)				\
    do											\
    {											\
      uint i;										\
      for (i = 0; i < (sizeof(in_out)/sizeof(in_out[0])); i++)				\
      {											\
	typeof(in_out[i].out) fn_out = fn(in_out[i].in);				\
	int single_test_case_success = (fn(in_out[i].in) == in_out[i].out);		\
	if (!single_test_case_success)							\
	{										\
	  bt_test_suite_success = BT_FAILURE;						\
	}										\
	bt_print_result_line(fn, in_out[i].in, in_out[i].out, fn_out, in_fmt, out_fmt, single_test_case_success); \
      }											\
    } while (0)

/**
 * Usage:
 * 	void my_function(const char *input_data, u32 *output_data) { ... }
 *
 *	struct in_out {
 *     		char *in;
 *   		u32  out;
 * 	} in_out[] = { ... };
 *
 * 	bt_assert_fn_in_out(my_function, in_out, "%s", "%u");
 */
#define bt_assert_fn_in_out(fn, in_out, in_fmt, out_fmt)				\
    do											\
    {											\
      uint i;										\
      for (i = 0; i < (sizeof(in_out)/sizeof(in_out[0])); i++)				\
      {											\
	typeof(in_out[i].out) fn_out;							\
	bzero(&fn_out, sizeof(fn_out));							\
	fn(in_out[i].in, &fn_out);							\
	int single_test_case_success = !memcmp(&fn_out, &in_out[i].out, sizeof(in_out[i].out)); \
	if (!single_test_case_success)							\
	{										\
	  bt_test_suite_success = BT_FAILURE;						\
	}										\
	bt_print_result_line(fn, in_out[i].in, in_out[i].out, fn_out, in_fmt, out_fmt, single_test_case_success); \
      }											\
    } while (0)

#endif /* _BIRDTEST_H_ */
