
UYTC_MODULE(show_memory) {
  UYTC_GROUPING(memory, resmem) {
    UYTC_LEAF(effective, resmem.effective);
    UYTC_LEAF(overhead, resmem.overhead);
  }

  UYTC_CONTAINER(message, msg) {
    UYTC_LEAF(header, "BIRD memory usage");
    UYTC_CONTAINER(body) {
      UYTC_USE(memory, routing_tables, rmemsize(rt_table_pool));
      UYTC_USE(memory, route_attributes, rmemsize(rta_pool));
      UYTC_USE(memory, protocols, rmemsize(proto_pool));
      UYTC_USE(memory, current_config, rmemsize(config_pool));
#ifdef HAVE_MMAP
      UYTC_USE(memory, standby_memory, (struct resmem) { .overhead = page_size * *pages_kept });
#endif
      UYTC_LEAF(total, (struct resmem) { .overhead = &root_pool.overhead + page_size * *pages_kept, .effective = &root_pool.effective });
    }
  }
}
