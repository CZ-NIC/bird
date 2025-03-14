#include "sysdep/config.h"
#include "lib/birdlib.h"

enum functions {
  SHOW_STATUS = 0,
  SHOW_MEMORY = 1,
  SHOW_SYMBOLS = 2,
  SHOW_OSPF = 3,
  SHOW_PROTOCOLS = 4,
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

struct buff_reader {
  byte *buff;
  uint pt;
  uint size;
};


uint compare_buff_str(struct buff_reader *buf_read, uint length, char *string);

struct value
get_value(struct buff_reader *reader);


int val_is_break(struct value val);
