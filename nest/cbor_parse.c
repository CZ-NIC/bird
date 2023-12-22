#include "nest/cbor_cmds.c"

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

struct buff_reader {
  byte *buff;
  uint pt;
  uint size;
};


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
    for(int i = 1; i < 8; i++) {
      val.val += buff[reader->pt+i];
      val.val = val.val << 8;
    }
    val.val += buff[reader->pt+8];
    reader->pt+=9;
  } else if (first_byte_val == 0x1f)
  {
    val.val = -1;
    reader->pt++;
  }
  return val;
}


int val_is_break(struct value val)
{
  return val.major == FLOAT && val.val == -1; // break code is 0xff, so the major is same for float and break
}

void skip_optional_args(struct buff_reader *rbuf_read, int items_in_block)
{
  // We are skipping sequence <"args":{}> or empty sequence <>. It can might empty in block length 1 (items_in_block == 0), or undefined length block. "args" might be empty the same way.
  if (items_in_block == 0)
  {
    return;
  }
  struct value val = get_value(rbuf_read);
  if (val.major == TEXT)
  {  //Since the list args is optional, we need to know if it is here and check if it is empty.
    ASSERT(compare_buff_str(rbuf_read, val.val, "args"));
    rbuf_read->pt+=val.val;
    val = get_value(rbuf_read);
    ASSERT(val.major == ARRAY);
    ASSERT(val.val <=0);
    if (val.val ==-1)
    { // list open with unspecified size, but we know there should be none for show memory (but, of course, we know it because of the show memory function, not because of yang)
      val = get_value(rbuf_read);
      ASSERT(val_is_break(val));
    }
  } else
  {
    log("items in block %i", items_in_block);
    ASSERT(items_in_block == -1); // assert the  block was not open to exact num of items, because it cant be just for command (we would returned) and we did not find more items.
    ASSERT(val_is_break(val));
    rbuf_read->pt--; // we read one byte from future, we need to shift pointer back. The val should be break, but we are not going to close the block, because it was not opened here.
  }
}

struct arg_list *parse_arguments(struct buff_reader *rbuf_read, int items_in_block, struct linpool *lp)
{
  // We are in opened block, which could be empty or contain arguments <"args":[{"arg":"string"}]>
  struct arg_list *arguments = (struct arg_list*)lp_alloc(lp, sizeof(struct arg_list));
  arguments->capacity = 0;
  arguments->pt = 0;
  if (items_in_block == 0)
  { // there should not be arg array
    return arguments;
  }
  struct value val = get_value(rbuf_read);
  if (val.major == TEXT)
  {
    log("text");
    ASSERT(compare_buff_str(rbuf_read, val.val, "args"));
    log("args");
    rbuf_read->pt+=val.val;
    val = get_value(rbuf_read);
    ASSERT(val.major == ARRAY);
    int num_array_items = val.val;
    log("num arr items %i", num_array_items);
    if (num_array_items > 0)
    {
      arguments->args = (struct argument*)lp_alloc(lp, sizeof(struct argument) * num_array_items);
      arguments->capacity = num_array_items;
    }
    else if (num_array_items == -1)
    {
      arguments->args = (struct argument*)lp_alloc(lp, sizeof(struct argument) * 4);
      arguments->capacity = 4;
    }
    for (int i = 0; i < num_array_items || num_array_items == -1; i++)
    {
      // There will be only one argument in struct cbor_show_data arg after parsing the array of args. Current bird cli is behaving this way too.
      val = get_value(rbuf_read);
      if (val_is_break(val))
      {
        rbuf_read->pt--;
        return arguments;
      }
      else if (val.major == BLOCK)
      {
        int wait_close = val.val == -1;
        if (!wait_close)
        {
          ASSERT(val.val==1);
        }
        val = get_value(rbuf_read);
        ASSERT(compare_buff_str(rbuf_read, val.val, "arg"));
        rbuf_read->pt+=val.val;

        val = get_value(rbuf_read);
        ASSERT(val.major == TEXT); // Now we have an argument in val
        if (num_array_items == -1 && arguments->capacity == arguments->pt)
        {
          struct argument *a = arguments->args;
          arguments->args = (struct argument*)lp_alloc(lp, sizeof(struct argument) * 2 * arguments->capacity);
          arguments->capacity = 2 * arguments->capacity;
          memcpy(arguments->args, a, sizeof(struct argument) * arguments->pt);
        }
        arguments->args[arguments->pt].arg = rbuf_read->buff + rbuf_read->pt;  // pointer to actual position in rbuf_read buffer
        arguments->args[arguments->pt].len = val.val;
        arguments->pt++;

        rbuf_read->pt+=val.val;
        if (wait_close)
        {
          val = get_value(rbuf_read);
          ASSERT(val_is_break(val));
        }
      }
      else
      {
        ASSERT(0);
      }
    }
  } else
  {
    ASSERT(items_in_block == -1); // assert the  block was not open to exact num of items, because it cant be just for command (we would returned) and we did not found more items.
    rbuf_read->pt--; // we read one byte from future, we need to shift pointer back
  }
  return arguments;
}

uint
do_command(struct buff_reader *rbuf_read, struct buff_reader *tbuf_read, int items_in_block, struct linpool *lp)
{
  log("val from %i", rbuf_read->buff[rbuf_read->pt]);
  struct value val = get_value(rbuf_read);
  ASSERT(val.major == UINT);
  struct arg_list * args;
  log("command %li, major %i", val.val, val.major);
  switch (val.val)
  {
    case SHOW_MEMORY:
      skip_optional_args(rbuf_read, items_in_block);
      return cmd_show_memory_cbor(tbuf_read->buff, tbuf_read->size, lp);
    case SHOW_STATUS:
      log("show status");
      skip_optional_args(rbuf_read, items_in_block);
      return cmd_show_status_cbor(tbuf_read->buff, tbuf_read->size, lp);
    case SHOW_SYMBOLS:
      args = parse_arguments(rbuf_read, items_in_block, lp);
      return cmd_show_symbols_cbor(tbuf_read->buff, tbuf_read->size, args, lp);
    case SHOW_OSPF:
      args = parse_arguments(rbuf_read, items_in_block, lp);
      log("args %i, pt %i", args, args->pt);
      return cmd_show_ospf_cbor(tbuf_read->buff, tbuf_read->size, args, lp);
    default:
      bug("command %li not found", val.val);
      return 0;
  }
}

uint
detect_down(uint size, byte *rbuf)
{
  struct buff_reader rbuf_read;
  rbuf_read.buff = rbuf;
  rbuf_read.size = size;
  rbuf_read.pt = 0;
  struct value val = get_value(&rbuf_read);
  ASSERT(val.major == BLOCK);
  val = get_value(&rbuf_read);
  ASSERT(compare_buff_str(&rbuf_read, val.val, "command:do"));
  rbuf_read.pt+=val.val;
  val = get_value(&rbuf_read);
  return (val.major = TEXT && compare_buff_str(&rbuf_read, val.val, "down"));
}


uint
parse_cbor(uint size, byte *rbuf, byte *tbuf, uint tbsize, struct linpool* lp)
{
  struct buff_reader rbuf_read;
  struct buff_reader tbuf_read;
  rbuf_read.buff = rbuf;
  tbuf_read.buff = tbuf;
  rbuf_read.size = size;
  tbuf_read.size = tbsize;
  rbuf_read.pt = 0;
  tbuf_read.pt = 0;

  if (size == 0)
  {
    return 0;
  }
  struct value val = get_value(&rbuf_read);
  ASSERT(val.major == BLOCK);
  ASSERT(val.val <=1); 
  int wait_for_end_main_block = val.val == -1;
  if (val.val != 0)
  {
    val = get_value(&rbuf_read);
    if ( !( wait_for_end_main_block == -1 && val_is_break(val) ))
    {
      ASSERT(val.major == TEXT);
      ASSERT(compare_buff_str(&rbuf_read, val.val, "command:do")); // this should be mandatory in yang, but when i marked it mandatory, it destroyed all other yangs (required command in all other modules)
      rbuf_read.pt+=val.val;

      val = get_value(&rbuf_read);
      ASSERT(val.major == BLOCK);
      ASSERT(val.val == 1 || val.val == 2 || val.val == -1);
      int items_in_block = val.val;

      val = get_value(&rbuf_read);
      ASSERT(val.major == TEXT);
      if (items_in_block!=-1)
        items_in_block--;
      ASSERT(compare_buff_str(&rbuf_read, val.val, "command"));
      rbuf_read.pt+=val.val;

      tbuf_read.pt = do_command(&rbuf_read, &tbuf_read, items_in_block, lp);
      if (items_in_block == -1)
      {
        val = get_value(&rbuf_read);
        log("val before fall %i %li", val.major, val.val);
        ASSERT(val.major == FLOAT && val.val == -1);
      }
    }
  }
  lp_flush(lp);
  log("parsed");
  return tbuf_read.pt;
}


