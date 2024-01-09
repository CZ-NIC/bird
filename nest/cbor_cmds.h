#ifndef CBOR_CMDS_H
#define CBVOR_CMDS_H

enum functions {
  SHOW_STATUS = 0,
  SHOW_MEMORY = 1,
  SHOW_SYMBOLS = 2,
  SHOW_OSPF = 3,
  SHOW_PROTOCOLS = 4,
};

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

// TODO include resource header to use typedefed linpool
uint cmd_show_memory_cbor(byte *tbuf, uint capacity, struct linpool *lp);
uint cmd_show_status_cbor(byte *tbuf, uint capacity, struct linpool *lp);
uint cmd_show_symbols_cbor(byte *tbuf, uint capacity, struct arg_list *args, struct linpool *lp);
uint cmd_show_ospf_cbor(byte *tbuf, uint capacity, struct arg_list *args, struct linpool *lp);
uint cmd_show_protocols_cbor(byte *tbuf, uint capacity, struct arg_list *args, struct linpool *lp);


#endif
