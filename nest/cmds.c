/*
 *	BIRD Internet Routing Daemon -- CLI Commands Which Don't Fit Anywhere Else
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "nest/cmds.h"
#include "lib/string.h"
#include "lib/resource.h"
#include "filter/filter.h"

extern int shutting_down;
extern int configuring;

void
cmd_show_status(void)
{
  byte tim[TM_DATETIME_BUFFER_SIZE];

  cli_msg(-1000, "BIRD " BIRD_VERSION);
  tm_format_time(tim, &config->tf_base, current_time());
  cli_msg(-1011, "Router ID is %R", config->router_id);
  cli_msg(-1011, "Hostname is %s", config->hostname);
  cli_msg(-1011, "Current server time is %s", tim);
  tm_format_time(tim, &config->tf_base, boot_time);
  cli_msg(-1011, "Last reboot on %s", tim);
  tm_format_time(tim, &config->tf_base, config->load_time);
  cli_msg(-1011, "Last reconfiguration on %s", tim);

  graceful_restart_show_status();

  if (shutting_down)
    cli_msg(13, "Shutdown in progress");
  else if (configuring)
    cli_msg(13, "Reconfiguration in progress");
  else
    cli_msg(13, "Daemon is up and running");
}

void
cmd_show_symbols(struct sym_show_data *sd)
{
  if (sd->sym)
    cli_msg(1010, "%-8s\t%s", sd->sym->name, cf_symbol_class_name(sd->sym));
  else
  {
    HASH_WALK(config->sym_hash, next, sym)
    {
      if (!sym->scope->active)
	continue;

      if (sd->type && (sym->class != sd->type))
	continue;

      cli_msg(-1010, "%-8s\t%s", sym->name, cf_symbol_class_name(sym));
    }
    HASH_WALK_END;

    cli_msg(0, "");
  }
}

static void
print_size(char *dsc, size_t val)
{
  char *px = " kMG";
  int i = 0;
  while ((val >= 10000) && (i < 3))
    {
      val = (val + 512) / 1024;
      i++;
    }

  cli_msg(-1018, "%-17s %4u %cB", dsc, (unsigned) val, px[i]);
}

extern pool *rt_table_pool;
extern pool *rta_pool;

void
cmd_show_memory(void)
{
  cli_msg(-1018, "BIRD memory usage");
  print_size("Routing tables:", rmemsize(rt_table_pool));
  print_size("Route attributes:", rmemsize(rta_pool));
  print_size("Protocols:", rmemsize(proto_pool));
  print_size("Total:", rmemsize(&root_pool));
  cli_msg(0, "");
}

void
cmd_eval(const struct f_line *expr)
{
  buffer buf;
  LOG_BUFFER_INIT(buf);

  if (f_eval_buf(expr, this_cli->parser_pool, &buf) > F_RETURN)
    {
      cli_msg(8008, "runtime error");
      return;
    }

  cli_msg(23, "%s", buf.start);
}
