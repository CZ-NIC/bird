/*
 *	BIRD Test -- Utils for testing parsing configuration file
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>

#include "test/birdtest.h"
#include "test/bt-utils.h"
#include "filter/filter.h"
#include "nest/iface.h"
#include "nest/locks.h"
#include "lib/unix.h"
#include "lib/krt.h"

#define BETWEEN(a, b, c)  (((a) >= (b)) && ((a) <= (c)))

static const byte *bt_config_parse_pos;
static uint bt_config_parse_remain_len;

int static
cf_txt_read(byte *dest_buf, uint max_len, UNUSED int fd) {
  if (max_len > bt_config_parse_remain_len)
    max_len = bt_config_parse_remain_len;
  memcpy(dest_buf, bt_config_parse_pos, max_len);
  bt_config_parse_pos += max_len;
  bt_config_parse_remain_len -= max_len;

  return max_len;
}

void
bt_bird_init(void) {
  if(bt_verbose)
    log_init_debug("");
  log_switch(bt_verbose != 0, NULL, NULL);

  resource_init();
  olock_init();
  io_init();
  rt_init();
  if_init();
  roa_init();
  config_init();

  protos_build();
  proto_build(&proto_unix_kernel);
  proto_build(&proto_unix_iface);
}

static void
bt_debug_with_line_nums(const char *str)
{
  const char *c = str;
  uint lino = 0;
  while (*c)
  {
    lino++;
    bt_debug("%3u   ", lino);
    do
    {
      bt_debug("%c", *c);
    } while (*c && *(c++) != '\n');
  }
  bt_debug("\n");
}

static void
bt_show_cfg_error(const char *str, const struct config *cfg)
{
  const char *c = str;
  int lino = 0;
  int lino_delta = 5;
  int lino_err = cfg->err_lino;

  while (*c)
  {
    lino++;
    if (BETWEEN(lino, lino_err - lino_delta, lino_err + lino_delta))
      bt_debug("%3u%s", lino, (lino_err == lino ? " > " : "   "));
    do
    {
      if (BETWEEN(lino, lino_err - lino_delta, lino_err + lino_delta))
	bt_debug("%c", *c);
    } while (*c && *(c++) != '\n');
  }
  bt_debug("\n");
}

struct config *
bt_config_parse(const char *str_cfg)
{
//  bt_debug("Parsing new configuration:\n");
//  bt_debug_with_line_nums(str_cfg);
  struct config *cfg = config_alloc("");
  bt_config_parse_pos = str_cfg;
  bt_config_parse_remain_len = strlen(str_cfg);
  cf_read_hook = cf_txt_read;

  if (config_parse(cfg))
  {
    config_commit(cfg, RECONFIG_HARD, 0);
    new_config = cfg;

    return cfg;
  }

  bt_assert_msg(0, "At line %d is error: %s", new_config->err_lino, new_config->err_msg);
  bt_show_cfg_error(str_cfg, new_config);

  return NULL;
}

void
bt_bird_init_with_simple_configuration(void)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);
}

uint
naive_pow(uint base, uint power)
{
  uint result = 1;
  uint i;
  for (i = 0; i < power; i++)
    result *= base;
  return result;
}
