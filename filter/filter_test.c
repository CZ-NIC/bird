/*
 *	Filters: Utility Functions Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <string.h>
#include <stdlib.h>

#include "test/birdtest.h"
#include "test/utils.h"

#include "filter/filter.h"
#include "lib/main_helper.h"

static int
t_filter(void)
{
#define TESTING_FILTER_NAME "testing_filter"

  bt_bird_init();

  bt_config_parse(
      BT_CONFIG_PARSE_ROUTER_ID
      BT_CONFIG_PARSE_KERNEL_DEVICE
      "\n"
      "filter " TESTING_FILTER_NAME "\n"
      "{\n"
      "   if net ~ 10.0.0.0/20 then\n"
      "     accept;\n"
      "   else\n"
      "     reject;\n"
      "}\n"
  );

  struct symbol *sym = NULL;
  sym = cf_find_symbol(TESTING_FILTER_NAME);

  /* TODO: check the testing filter */

  return BT_SUCCESS;
}

static char *
load_file(const char *filename)
{
  FILE *f = fopen(filename, "rb");
  bt_assert_msg(f, "Cannot open file %s", filename);
  fseek(f, 0, SEEK_END);
  long pos = ftell(f);
  fseek(f, 0, SEEK_SET);

  char *file_body = mb_allocz(&root_pool, pos+1);
  bt_assert_msg(file_body, "Memory allocation failed for file %s", filename);
  bt_assert_msg(fread(file_body, pos, 1, f) == 1, "Failed reading from file %s", filename);

  fclose(f);
  return file_body;
}

static int
t_example_config_files(void *filename_void)
{
  bt_bird_init();

  const char *filename = filename_void;
  char *cfg_str = load_file(filename);
  bt_config_parse(cfg_str);
  mb_free(cfg_str);

  bt_debug("Parsing configuration from %s\n", filename);
  config_name = filename;
  read_config();
  struct config *conf = read_config();
  config_commit(conf, RECONFIG_HARD, 0);

  return bt_test_suite_success;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_filter, "Test all example config files");

  const char *files[] = {
    "filter/test.conf",
    "filter/test.conf2",
    "filter/test6.conf",
  };
  size_t files_arr_size = sizeof(files)/sizeof(files[0]);
  for (size_t i = 0; i < files_arr_size; i++)
    bt_test_suite_arg_extra(t_example_config_files, files[i], BT_DEFAULT_FORKING, 30, "Test a example config file %s", files[i]);

  return bt_end();
}
