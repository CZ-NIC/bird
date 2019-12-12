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
#include "filter/data.h"
#include "filter/f-inst.h"
#include "conf/conf.h"

#define BT_CONFIG_FILE "filter/test.conf"


struct parse_config_file_arg {
  struct config **cp;
  const char *filename;
};

static int
parse_config_file(const void *argv)
{
  const struct parse_config_file_arg *arg = argv;
  size_t fn_size = strlen(arg->filename) + 1;
  char *filename = alloca(fn_size);
  memcpy(filename, arg->filename, fn_size);
  
  *(arg->cp) = bt_config_file_parse(filename);
  return !!*(arg->cp);
}

static int
run_function(const void *arg)
{
  const struct f_bt_test_suite *t = arg;

  if (t->cmp)
    return t->result == f_same(t->fn, t->cmp);

  linpool *tmp = lp_new_default(&root_pool);
  enum filter_return fret = f_eval(t->fn, tmp, NULL);
  rfree(tmp);

  return (fret < F_REJECT);
}

static void
bt_assert_filter(int result, const struct f_line_item *assert)
{
  int bt_suit_case_result = 1;
  if (!result)
  {
    bt_result = 0;
    bt_suite_result = 0;
    bt_suit_case_result = 0;
  }

  bt_log_suite_case_result(bt_suit_case_result, "Assertion at line %d (%s)",
      assert->lineno, assert->i_FI_ASSERT.s);
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_bird_init();
  
  bt_assert_hook = bt_assert_filter;

  struct config *c = NULL;
  struct parse_config_file_arg pcfa = { .cp = &c, .filename = BT_CONFIG_FILE };

  bt_test_suite_base(parse_config_file, "conf", (const void *) &pcfa, 0, 0, "parse config file");
  bt_assert(c);

  bt_test_suite_base(parse_config_file, "reconf", (const void *) &pcfa, 0, 0, "reconfigure with the same file");
  bt_assert(c);

  struct symbol *s;
  WALK_LIST(s, c->symbols)
    if ((s->class == SYM_FUNCTION) || (s->class == SYM_FILTER))
      bt_assert_msg((s->flags & SYM_FLAG_SAME), "Symbol %s same check", s->name);

  struct f_bt_test_suite *t;
  WALK_LIST(t, c->tests)
    bt_test_suite_base(run_function, t->fn_name, t, BT_FORKING, BT_TIMEOUT, "%s", t->dsc);

  bt_bird_cleanup();
  return bt_exit_value();
}
