/*
 *	Filters: Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "filter/filter.h"
#include "conf/conf.h"

#define BT_CONFIG_FILE "filter/test.conf"


static struct config *
parse_config_file(const void *filename_void)
{
  bt_bird_init();

  size_t fn_size = strlen((const char *) filename_void) + 1;
  char *filename = alloca(fn_size);
  strncpy(filename, filename_void, fn_size);

  struct config *c = bt_config_file_parse(filename);
  bt_bird_cleanup();

  return c;
}

static int
run_function(const void *parsed_fn_def)
{
  /* XXX: const -> non-const */
  struct f_inst *f = (struct f_inst *) parsed_fn_def;

  linpool *tmp = lp_new_default(&root_pool);
  struct f_val res;
  enum filter_return fret = f_eval(f, tmp, &res);
  rfree(tmp);

  return (fret < F_REJECT);
}

static void
bt_assert_filter(int result, struct f_inst *assert)
{
  int bt_suit_case_result = 1;
  if (!result)
  {
    bt_result = 0;
    bt_suite_result = 0;
    bt_suit_case_result = 0;
  }

  bt_log_suite_case_result(bt_suit_case_result, "Assertion at line %d (%s)", assert->lineno, (char *) assert->a[1].p);
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  struct config *c = parse_config_file(BT_CONFIG_FILE);

  if (c)
  {
    bt_assert_hook = bt_assert_filter;

    struct f_bt_test_suite *t;
    WALK_LIST(t, c->tests)
      bt_test_suite_base(run_function, t->fn_name, t->fn, BT_FORKING, BT_TIMEOUT, "%s", t->dsc);
  }

  return bt_exit_value();
}
