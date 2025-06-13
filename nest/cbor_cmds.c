#include "nest/cbor_shortcuts.c"
#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "lib/string.h"
#include "lib/resource.h"
#include "filter/filter.h"


extern pool *rt_table_pool;
extern pool *rta_pool;
extern uint *pages_kept;

uint
cmd_show_memory_cbor(byte *tbuf, uint capacity) {
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
