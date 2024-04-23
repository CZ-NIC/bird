
UYTC_MODULE(show_memory) {
  UYTC_GROUPING(memory, resmem) {
    UYTC_LEAF(effective, resmem.effective);
    UYTC_LEAF(overhead, resmem.overhead);
  }

  UYTC_CONTAINER(message, msg) {
    UYTC_LEAF(header, "BIRD memory usage");
    UYTC_CONTAINER(body, body) {
      UYTC_LEAF(routing_tables, rmemsize(rt_table_pool));
      UYTC_LEAF(route_attributes, rmemsize(rta_pool));
      ...;
#ifdef HAVE_MMAP
      UYTC_LEAF(standby_memory, (struct resmem) { .overhead = page_size * *pages_kept });
#endif
      UYTC_LEAF(total, rmemsize(&root_pool));
    }
  }
}
