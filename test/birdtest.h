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

extern int bt_verbose;
extern const char *bt_filename;
extern const char *bt_test_id;

void bt_init(int argc, char *argv[]);
void bt_test_case5(int (*fn)(void), const char *id, const char *dsc, int forked, int timeout);
int  bt_rand_num(void);

#define BT_SUCCESS 0
#define BT_FAILURE 1

#define BT_DEFAULT_TIMEOUT 5
#define BT_DEFAULT_FORKING 1

#define BT_RANDOM_SEED 982451653

#define bt_test_case(fn,dsc) \
    bt_test_case4(fn, dsc, BT_DEFAULT_FORKING, BT_DEFAULT_TIMEOUT)

#define bt_test_case4(fn,dsc,f,t) \
    bt_test_case5(fn, #fn, dsc, f, t)

#define bt_log(format, ...) \
    fprintf(stderr, "%s: " format "\n", bt_filename, ##__VA_ARGS__)

#define bt_note(format, ...) \
    do { if (bt_verbose) bt_log(format, ##__VA_ARGS__); } while (0)

#define bt_debug(format, ...) \
    do { if (bt_verbose > 1) printf(format, ##__VA_ARGS__); } while (0)

#define bt_abort() \
    bt_abort_msg("Aborted at %s:%d", __FILE__, __LINE__)

#define bt_abort_msg(format, ...) \
    do { bt_log(format, ##__VA_ARGS__); abort(); } while (0)

#define bt_assert(test) \
    bt_assert_msg(test, "Assertion (%s) failed at %s:%d", #test, __FILE__, __LINE__)

#define bt_assert_msg(test,format, ...) \
    do { if (!(test)) bt_abort_msg(format, ##__VA_ARGS__); } while (0)

#define bt_syscall(test,format, ...)			\
    do { if (test) { bt_log(format ": %s", ##__VA_ARGS__, strerror(errno)); exit(3); } } while (0)

#define bt_check(fn, in_out, in_fmt, out_fmt)				\
  do									\
  {									\
    unsigned int bt_i;							\
    for (bt_i = 0; bt_i < (sizeof(in_out)/sizeof(in_out[0])); bt_i++)	\
    {									\
      if (fn(in_out[bt_i].in) == in_out[bt_i].out)			\
	bt_debug    ("[ OK ] %s(" in_fmt ") got " out_fmt " \n", #fn, in_out[bt_i].in, fn(in_out[bt_i].in)); \
      else 								\
	bt_abort_msg("[FAIL] %s(" in_fmt ") got " out_fmt ", but was expected " out_fmt " \n", #fn, in_out[bt_i].in, fn(in_out[bt_i].in), in_out[bt_i].out); \
    }									\
  } while(0)

#endif /* _BIRDTEST_H_ */
