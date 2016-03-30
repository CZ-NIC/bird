/*
 *	Filters: Utility Functions Tests
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
#include "lib/main_helper.h"
#include "conf/conf.h"

static int
t_simple(void)
{
#define TESTING_FILTER_NAME "testing_filter"

  bt_bird_init();

  /*
  struct config *cfg = bt_config_parse(
      BT_CONFIG_SIMPLE
      "\n"
      "filter " TESTING_FILTER_NAME "\n"
      "{\n"
      "   if net ~ 10.0.0.0/20 then\n"
      "     accept;\n"
      "   else\n"
      "     reject;\n"
      "}\n"
      "\n"
      "filter " TESTING_FILTER_NAME "2\n"
      "{\n"
      "   if net ~ 10.0.0.0/20 then\n"
      "     accept;\n"
      "   else {\n"
      "     reject; } \n"
      "}\n"
      "\n"
  );
*/

  struct symbol *sym = NULL;
  sym = cf_get_symbol(TESTING_FILTER_NAME);

  struct symbol *sym2 = NULL;
  sym2 = cf_get_symbol(TESTING_FILTER_NAME "2");


  struct filter *f = sym->def;
  struct filter *f2 = sym2->def;
  bt_assert(strcmp(filter_name(f), TESTING_FILTER_NAME) == 0);


  bt_assert(filter_same(f,f2));

//  bt_debug("f_eval_asn: %u \n", f_eval_asn(f->root));
//  bt_debug("f_eval_int: %u \n", f_eval_int(f->root));
//  struct f_val v = f_eval(f->root, cfg->mem);
//  bt_debug("v type: %d \n", v.type);


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
t_example_config_files(const void *filename_void)
{
  bt_bird_init();

  char *filename = (char *)filename_void;
  bt_debug("Testing BIRD configuration from %s\n", filename);

  char *cfg_str = load_file(filename);
  bt_config_parse(cfg_str);
  mb_free(cfg_str);

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

  bt_test_suite(t_simple, "Simple filter testing");

  const char *files[] = {
//    "filter/test.conf",
    "filter/test.conf2",
//    "filter/test_bgp_filtering.conf",
#ifdef IPV6
    "filter/test6.conf",
#endif
  };
  size_t files_arr_size = sizeof(files)/sizeof(files[0]);
  size_t i;
  for (i = 0; i < files_arr_size; i++)
    bt_test_suite_arg_extra(t_example_config_files, files[i], BT_DEFAULT_FORKING, 30, "Test a example config file %s", files[i]);

  return bt_end();
}
