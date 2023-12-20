#ifndef _BIRD_CBOR_PARSE_
#define _BIRD_CBOR_PARSE_

#include "nest/bird.h"

struct buff_reader {
  byte *buff;
  uint pt;
  uint size;
};

// TODO incude linpool declaration
uint parse_cbor(uint size, byte *rbuf, byte *tbuf, uint tbsize, struct linpool *lp);

enum functions {
  SHOW_STATUS = 0,
  SHOW_MEMORY = 1,
  SHOW_SYMBOLS = 2,
  SHOW_OSPF = 3,
};

enum cbor_majors {
  UINT = 0,
  NEG_INT = 1,
  BYTE_STR = 2,
  TEXT = 3,
  ARRAY = 4,
  BLOCK = 5,
  TAG = 6,
  FLOAT = 7,
};

struct value {
  int major;
  int64_t val;
};

struct value get_value(struct buff_reader *reader);
uint compare_buff_str(struct buff_reader *buf_read, uint length, char *string);

#endif
