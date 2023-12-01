

struct argument {
  char *arg;
  uint len;
};

struct arg_list {
  struct argument *args;
  int capacity;
  int pt;
  struct linpool *lp;
};

uint cmd_show_memory_cbor(byte *tbuf, uint capacity, struct linpool *lp);
uint cmd_show_status_cbor(byte *tbuf, uint capacity, struct linpool *lp);
uint cmd_show_symbols_cbor(byte *tbuf, uint capacity, struct arg_list *args, struct linpool *lp);

