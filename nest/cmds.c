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
#include "client/reply_codes.h"
#include "nest/iface.h"

extern int shutting_down;
extern int configuring;

void
cmd_show_status(void)
{
  byte tim[TM_DATETIME_BUFFER_SIZE];

  cli_msg(-1000, "BIRD " BIRD_VERSION);
  tm_format_datetime(tim, &config->tf_base, now);
  cli_msg(-1011, "Router ID is %R", config->router_id);
  cli_msg(-1011, "Current server time is %s", tim);
  tm_format_datetime(tim, &config->tf_base, boot_time);
  cli_msg(-1011, "Last reboot on %s", tim);
  tm_format_datetime(tim, &config->tf_base, config->load_time);
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
  int pos = 0;
  struct symbol *sym = sd->sym;

  if (sym)
    cli_msg(1010, "%-8s\t%s", sym->name, cf_symbol_class_name(sym));
  else
    {
      while (sym = cf_walk_symbols(config, sym, &pos))
	{
	  if (sd->type && (sym->class != sd->type))
	    continue;

	  cli_msg(-1010, "%-8s\t%s", sym->name, cf_symbol_class_name(sym));
	}
      cli_msg(0, "");
    }
}

static int
get_cli_code_for_sym(struct symbol *sym)
{
  if (cf_symbol_is_constant(sym))
    return RC_CONSTANT_NAME;

  if (cf_symbol_is_variable(sym))
    return RC_VARIABLE_NAME;

  switch (sym->class & 0xff)
  {
  case SYM_PROTO:	return RC_PROTOCOL_NAME;
  case SYM_TEMPLATE:	return RC_TEMPLATE_NAME;
  case SYM_FUNCTION:	return RC_FUNCTION_NAME;
  case SYM_FILTER:	return RC_FILTER_NAME;
  case SYM_TABLE:	return RC_TABLE_NAME;
  default:
    log(L_ERR "Undefined class %d of %s", sym->class, sym->name);
  }
  return 0;
}

/**
 * cmd_send_symbols - send all symbols for auto-completion interactive CLI
 *
 * This function sends all known symbols for auto-completion interactive BIRD's
 * CLI. The first symbol is version of BIRD.
 */
void
cmd_send_symbols(void)
{
  int code, pos = 0;
  struct symbol *sym = NULL;

  cli_msg(RC_BIRD_VERSION_NUM, "%s", BIRD_VERSION);

  while (sym = cf_walk_symbols(config, sym, &pos))
  {
    code = get_cli_code_for_sym(sym);
    cli_msg(code, "%s", sym->name);
  }

  struct iface *i;
  WALK_LIST(i, iface_list)
    if (!(i->flags & IF_SHUTDOWN))
      cli_msg(RC_INTERFACE_NAME, "\"%s\"", i->name);

  cli_msg(0, "");
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
extern pool *proto_pool;

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
cmd_eval(struct f_inst *expr)
{
  struct f_val v = f_eval(expr, this_cli->parser_pool);

  if (v.type == T_RETURN)
    {
      cli_msg(8008, "runtime error");
      return;
    }

  buffer buf;
  LOG_BUFFER_INIT(buf);
  val_format(v, &buf);
  cli_msg(23, "%s", buf.start);
}
