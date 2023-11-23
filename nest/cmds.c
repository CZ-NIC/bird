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
#include "nest/cbor_shortcuts.c"

extern int shutting_down;
extern int configuring;

void
cmd_show_status(void)
{
  byte tim[TM_DATETIME_BUFFER_SIZE];

  cli_msg(-1000, "BIRD " BIRD_VERSION);
  tm_format_time(tim, &config->tf_base, current_time());
  cli_msg(-1011, "Router ID is %R  %i    %x", config->router_id, config->router_id, config->router_id);
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


  byte time[TM_DATETIME_BUFFER_SIZE];
  tm_format_time(time, &config->tf_base, current_time());
  struct cbor_writer *w = cbor_init(lp_new(proto_pool), 1000);
  cbor_open_block_with_length(w, 3);
  cbor_string_string(w, "BIRD", BIRD_VERSION);
  cbor_add_string(w, "body");
  cbor_open_block(w);
  cbor_add_string(w, "router_id");
  cbor_add_int(w, config->router_id);
  cbor_string_string(w, "hostname", config->hostname);
  cbor_string_string(w, "server_time", time);
  tm_format_time(time, &config->tf_base, boot_time);
  cbor_string_string(w, "last_reboot", time);
  tm_format_time(time, &config->tf_base, config->load_time);
  cbor_string_string(w, "last_reconfiguration", time);
  
  // TODO graceful restart
  cbor_close_block_or_list(w);
  cbor_add_string(w, "state");
  if (shutting_down)
    cbor_add_string(w, "Shutdown in progress");
  else if (configuring)
    cbor_add_string(w, "Reconfiguration in progress");
  else
    cbor_add_string(w, "Daemon is up and running");
  cbor_write_to_file(w, "test.cbor");
}

void
cmd_show_symbols(struct sym_show_data *sd)
{
  if (sd->sym)
    cli_msg(1010, "%-8s\t%s", sd->sym->name, cf_symbol_class_name(sd->sym));
  else
  {
    for (const struct sym_scope *scope = config->root_scope; scope; scope = scope->next)
      HASH_WALK(scope->hash, next, sym)
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

#define SIZE_SUFFIX	" kMGT"
#define SIZE_FORMAT	"% 4u.%1u % 1cB"
#define SIZE_ARGS(a)	(a).val, (a).decimal, SIZE_SUFFIX[(a).magnitude]

struct size_args {
  u64 val:48;
  u64 decimal:8;
  u64 magnitude:8;
};

static struct size_args
get_size_args(u64 val)
{
#define VALDEC	10 /* One decimal place */
  val *= VALDEC;

  uint i = 0;
  while ((val >= 10000 * VALDEC) && (i < 4))
    {
      val = (val + 512) / 1024;
      i++;
    }

  return (struct size_args) {
    .val = (val / VALDEC),
    .decimal = (val % VALDEC),
    .magnitude = i,
  };
}

static void
print_size(char *dsc, struct resmem vals)
{
  struct size_args effective = get_size_args(vals.effective);
  struct size_args overhead = get_size_args(vals.overhead);

  cli_msg(-1018, "%-17s " SIZE_FORMAT "   " SIZE_FORMAT, dsc, SIZE_ARGS(effective), SIZE_ARGS(overhead));
}

extern pool *rt_table_pool;
extern pool *rta_pool;
extern uint *pages_kept;

void
cmd_show_memory(void)
{
  cli_msg(-1018, "BIRD memory usage");
  cli_msg(-1018, "%-17s Effective    Overhead", "");
  print_size("Routing tables:", rmemsize(rt_table_pool));
  print_size("Route attributes:", rmemsize(rta_pool));
  print_size("Protocols:", rmemsize(proto_pool));
  print_size("Current config:", rmemsize(config_pool));
  struct resmem total = rmemsize(&root_pool);
#ifdef HAVE_MMAP
  print_size("Standby memory:", (struct resmem) { .overhead = page_size * *pages_kept });
  total.overhead += page_size * *pages_kept;
#endif
  print_size("Total:", total);
  cli_msg(0, "");
  
  
  struct cbor_writer *w = cbor_init(lp_new(proto_pool), 1000);
  cbor_open_block_with_length(w, 1);
  
  cbor_add_string(w, "show_memory:message");
  cbor_open_block_with_length(w, 2);

  cbor_string_string(w, "header", "BIRD memory usage");

  cbor_add_string(w, "body");
  cbor_open_block(w);

  struct resmem memory = rmemsize(rt_table_pool);
  cbor_named_block_two_ints(w, "routing_tables", "effective", memory.effective, "overhead", memory.overhead);

  memory = rmemsize(rta_pool);
  cbor_named_block_two_ints(w, "route_attributes", "effective", memory.effective, "overhead", memory.overhead);

  memory = rmemsize(proto_pool);
  cbor_named_block_two_ints(w, "protocols", "effective", memory.effective, "overhead", memory.overhead);

  memory = rmemsize(config_pool);
  cbor_named_block_two_ints(w, "current_config", "effective", memory.effective, "overhead", memory.overhead);

  memory = rmemsize(&root_pool);
#ifdef HAVE_MMAP
  cbor_named_block_two_ints(w, "standby_memory", "effective", 0, "overhead", page_size * *pages_kept);
#endif
  memory.overhead += page_size * *pages_kept;
  cbor_named_block_two_ints(w, "total", "effective", memory.effective, "overhead", memory.overhead);

  cbor_close_block_or_list(w); // we do not know for sure, that standby memory will be printed, so we do not know number of block items. If we know that, we open the block for 6 (or 5) items and we do not close anything

  cbor_write_to_file(w, "/home/kkubecova/Dokumenty/bird/yang/show_memory.cbor");

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
