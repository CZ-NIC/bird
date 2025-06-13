#include "nest/cbor_cmds.c"

enum functions {
  SHOW_STATUS=0,
  SHOW_MEMORY=1,
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
 int val;
};

struct buff_reader {
  byte *buff;
  uint pt;
  uint size;
};


struct value
get_value(struct buff_reader *reader) {
  struct value val;
  byte *buff = reader->buff;
  val.major = buff[reader->pt]>>5;
  log("in get value");
  int first_byte_val = buff[reader->pt] - (val.major<<5);
  if (first_byte_val <=23) {
    val.val = first_byte_val;
    reader->pt++;
  } else if (first_byte_val == 0x18) {
    val.val = buff[reader->pt+1];
    reader->pt+=2;
  } else if (first_byte_val == 0x19) {
    val.val = buff[reader->pt+1]>>8 + buff[reader->pt+2];
    reader->pt+=3;
  } else if (first_byte_val == 0x1a) {
    val.val = buff[reader->pt+1]>>24 + buff[reader->pt+2]>>16 + buff[reader->pt+3]>>8 + buff[reader->pt+4];
    reader->pt+=5;
  } else if (first_byte_val == 0xff) {
    val.val = -1;
    reader->pt++;
  }
  return val;
}

uint compare_str(struct buff_reader *buf_read, uint length, char *string) {
  if (length != strlen(string)) {
    return 0;
  }
  for (size_t i = 0; i < strlen(string); i++) {
    if (buf_read->buff[i+buf_read->pt]!=string[i]) {
      return 0;
    }
  }
  return 1;
}

int val_is_break(struct value val) {
  return val.major == FLOAT && val.val == -1; // break code is 0xff, so the major is same for float and break
}

uint
do_command(struct buff_reader *rbuf_read, struct buff_reader *tbuf_read, int items_in_block) {
  struct value val= get_value(rbuf_read);
  ASSERT(val.major == UINT);
  switch (val.val)
  {
    case SHOW_MEMORY:
      if (items_in_block != 0) {
        val = get_value(rbuf_read);
        if (val.major == TEXT) {  //Since the list args is optional, we need to know if it is here and check if it is empty.
          ASSERT(compare_str(rbuf_read, val.val, "args"));
          rbuf_read->pt+=val.val;
          val = get_value(rbuf_read);
          ASSERT(val.major == ARRAY);
          ASSERT(val.val <=0);
          if (val.val ==-1) { // list open with unspecified size, but we know there should be none for show memory (but, of course, we know it because of the show memory function, not because of yang) 
            val = get_value(rbuf_read);
            ASSERT(val_is_break(val)); 
          }
        } else {
          ASSERT(items_in_block == -1); // assert the  block was not open to exactly two items (we do not have args list and there is no chance to have another item in the block)
          rbuf_read->pt--; // we read one byte from future, we need to shift pointer back
        }
      }
      return cmd_show_memory_cbor(tbuf_read->buff, tbuf_read->size);
    case SHOW_STATUS:
      return 0;
    default:
      return 0;
  }
}


uint
parse_cbor(uint size, byte *rbuf, byte *tbuf, uint tbsize) {
  log("cbor parse");
  struct buff_reader rbuf_read;
  struct buff_reader tbuf_read;
  rbuf_read.buff = rbuf;
  tbuf_read.buff = tbuf;
  rbuf_read.size = size;
  tbuf_read.size = tbsize;
  rbuf_read.pt = 0;
  tbuf_read.pt = 0;

  if (size == 0) {
    return 0;
  }
  struct value val = get_value(&rbuf_read);
  ASSERT(val.major == BLOCK);
  ASSERT(val.val <=1);
  int wait_for_end_main_block = val.val == -1;
  if (val.val != 0) {
    val = get_value(&rbuf_read);
    if ( !( wait_for_end_main_block == -1 && val_is_break(val) )) {
      ASSERT(val.major == TEXT);
      ASSERT(compare_str(&rbuf_read, val.val, "command:do"));
      rbuf_read.pt+=val.val;

      val = get_value(&rbuf_read);
      ASSERT(val.major == BLOCK);
      ASSERT(val.val == 1 || val.val == 2 || val.val == -1);
      int items_in_block = val.val;

      val = get_value(&rbuf_read);
      ASSERT(val.major == TEXT);
      items_in_block--;
      ASSERT(compare_str(&rbuf_read, val.val, "command"));
      rbuf_read.pt+=val.val;

      tbuf_read.pt = do_command(&rbuf_read, &tbuf_read, items_in_block);
      if (items_in_block == -1) {
        val = get_value(&rbuf_read);
        ASSERT(val.major == FLOAT && val.val == -1);
      }
    }
  }
  return tbuf_read.pt;
}


