#include <string.h>
#include "lib/cbor_parse_tools.h"

uint compare_buff_str(struct buff_reader *buf_read, uint length, char *string) {
  if (length != strlen(string)) {
    return 0;
  }
  for (size_t i = 0; i < strlen(string); i++) {
    if (buf_read->buff[i+buf_read->pt]!=string[i]) {
      return 0;
    }
  }
  return 1;
};

struct value
get_value(struct buff_reader *reader)
{
  struct value val;
  byte *buff = reader->buff;
  val.major = buff[reader->pt]>>5;
  int first_byte_val = buff[reader->pt] - (val.major<<5);
  if (first_byte_val <=23) {
    val.val = first_byte_val;
    reader->pt++;
  } else if (first_byte_val == 0x18)
  {
    val.val = buff[reader->pt+1];
    reader->pt+=2;
  } else if (first_byte_val == 0x19)
  {
    val.val = buff[reader->pt+1];
    val.val = val.val << 8;
    val.val += buff[reader->pt+2];
    reader->pt += 3;
  } else if (first_byte_val == 0x1a)
  {
    val.val = 0;
    for (int i = 1; i < 4; i++)
    {
      val.val += buff[reader->pt+i];
      val.val = val.val << 8;
    }
    val.val += buff[reader->pt+4];
    reader->pt+=5;
  } else if (first_byte_val == 0x1b)
  {
    val.val = 0;
    for (int i = 1; i < 8; i++) {
      val.val += buff[reader->pt+i];
      val.val = val.val << 8;
    }
    val.val += buff[reader->pt+8];
    reader->pt += 9;
  } else if (first_byte_val == 0x1f)
  {
    val.val = -1;
    reader->pt++;
  }
  if (val.major == NEG_INT)
    val.val = -1 - val.val;
  return val;
}


int val_is_break(struct value val)
{
  return val.major == FLOAT && val.val == -1; // break code is 0xff, so the major is same for float and break
}
