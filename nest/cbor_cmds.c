#include "nest/cbor_shortcuts.c"
#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "lib/string.h"
#include "filter/filter.h"


struct cbor_show_data {
  int type;	/* Symbols type to show */
  int name_length;
  char *name;
};

uint compare_str(byte *str1, uint length, char *str2) {
  if (length != strlen(str2)) {
    return 0;
  }
  for (size_t i = 0; i < length; i++) {
    if (str1[i]!=str2[i]) {
      return 0;
    }
  }
  return 1;
}


extern pool *rt_table_pool;
extern pool *rta_pool;
extern uint *pages_kept;

uint
cmd_show_memory_cbor(byte *tbuf, uint capacity)
{
  log("in cmd_show_memory_cbor");
  struct cbor_writer *w = cbor_init(tbuf, capacity, lp_new(proto_pool));
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

  cbor_write_to_file(w, "show_memory.cbor");
  return w->pt;
}

extern int shutting_down;
extern int configuring;

uint
cmd_show_status_cbor(byte *tbuf, uint capacity)
{
  struct cbor_writer *w = cbor_init(tbuf, capacity, lp_new(proto_pool));
  cbor_open_block_with_length(w, 1);
  cbor_add_string(w, "show_status:message");

  cbor_open_block_with_length(w, 3);
  cbor_string_string(w, "version", BIRD_VERSION);
  cbor_add_string(w, "body");
  cbor_open_block(w);
  cbor_string_int(w, "router_id", config->router_id);
  cbor_string_string(w, "hostname", config->hostname);
  cbor_string_int(w, "server_time", current_time());
  cbor_string_int(w, "last_reboot", boot_time);
  cbor_string_int(w, "last_reconfiguration", config->load_time);
  if (is_gr_active())
  {
    cbor_add_string(w, "gr_restart");
    cbor_open_block_with_length(w, 2);
    cbor_string_int(w, "waiting_for_n_channels_to_recover", get_graceful_restart_locks_num());
    cbor_add_string(w, "wait_timer");
    cbor_open_block_with_length(w, 2);
    cbor_string_int(w, "remains", get_tm_remains_gr_wait_timer());
    cbor_string_int(w, "count_time", get_config_gr_wait());
  }
  cbor_close_block_or_list(w);
  cbor_add_string(w, "state");
  if (shutting_down)
    cbor_add_string(w, "Shutdown in progress");
  else if (configuring)
    cbor_add_string(w, "Reconfiguration in progress");
  else
    cbor_add_string(w, "Daemon is up and running");
  cbor_write_to_file(w, "test.cbor");
  return w->pt;
}

int
cmd_show_symbols_cbor(byte *tbuf, uint capacity, struct cbor_show_data show)
{
  struct cbor_writer *w = cbor_init(tbuf, capacity, lp_new(proto_pool));
  cbor_open_block_with_length(w, 1);
  cbor_add_string(w, "show_symbols:message");
  cbor_open_block_with_length(w, 1);

  if (show.type == -1)
  {
    cbor_add_string(w, "table");
    cbor_open_list_with_length(w, 1);
    cbor_open_block_with_length(w, 2);

    for (const struct sym_scope *scope = config->root_scope; scope; scope = scope->next)
    {
      HASH_WALK(scope->hash, next, sym)
      {
	if (compare_str(show.name, show.name_length, sym->name))
	{
	  cbor_string_string(w, "name", show.name);
	  cbor_string_string(w, "type", cf_symbol_class_name(sym));
	  return w->pt;
        }
      }
      HASH_WALK_END;
    }
    cbor_string_string(w, "name", show.name);
    cbor_string_string(w, "type", "symbol not known");
    return w->pt;
  }

  else
  {
    cbor_add_string(w, "table");
    cbor_open_list(w);
    for (const struct sym_scope *scope = config->root_scope; scope; scope = scope->next)
      HASH_WALK(scope->hash, next, sym)
      {
        if (!sym->scope->active)
          continue;

        if (show.type != SYM_VOID && (sym->class != show.type))
          continue;

        cbor_open_block_with_length(w, 2);
	cbor_string_string(w, "name", sym->name);
        cbor_string_string(w, "type", cf_symbol_class_name(sym));
      }
      HASH_WALK_END;

    cbor_close_block_or_list(w);
    return w->pt;
  }
}




