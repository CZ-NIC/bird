
#include "nest/cbor_parse.c"

void print_with_size(byte *string, int len)
{
  for (int i = 0; i < len; i++)
  {
    if (string[i] != '_')
      putc(string[i], stdout);
    else
      putc(' ', stdout);
  }
}

void print_show_memory(struct buff_reader *buf_read)
{
  printf("BIRD memory usage\n");
  printf("                  Effective   Overhead\n");
  struct value val = get_value(buf_read);
  ASSERT(val.major == BLOCK);
  val = get_value(buf_read); // header, may be it should be deleted
  ASSERT(val.major == TEXT);
  buf_read->pt+=val.val;
  val = get_value(buf_read);
  ASSERT(val.major == TEXT);
  buf_read->pt+=val.val;
  val = get_value(buf_read); // body
  ASSERT(val.major == TEXT);
  buf_read->pt+=val.val;
  val = get_value(buf_read);
  ASSERT(val.major == BLOCK);

  val = get_value(buf_read);
  while (val.major == TEXT && buf_read->pt < buf_read->size)
  {
    print_with_size(&buf_read->buff[buf_read->pt], val.val);
    for (unsigned long i = 0; i < strlen("                  ") - val.val; i++)
    {
      putc(' ', stdout);
    }
    buf_read->pt+=val.val;
    val = get_value(buf_read); // block open
    val = get_value(buf_read);
    ASSERT(val.major == TEXT);
    buf_read->pt+=val.val;
    val = get_value(buf_read);
    ASSERT(val.major == UINT);
    printf("%7li B  ", val.val);
    val = get_value(buf_read);
    ASSERT(val.major == TEXT);
    buf_read->pt+=val.val;
    val = get_value(buf_read);
    ASSERT(val.major == UINT);
    printf("%7li B\n", val.val);
    val = get_value(buf_read);
  }
}


void print_cbor_response(byte *cbor, int len)
{
  struct buff_reader buf_read;
  buf_read.buff = cbor;
  buf_read.size = len;
  buf_read.pt = 0;
  struct value val = get_value(&buf_read);
  printf("%i %li\n", val.major, val.val);
  ASSERT(val.major == BLOCK);
  ASSERT(val.val <=1);
  val = get_value(&buf_read);
  ASSERT(val.major == TEXT);

  if (compare_buff_str(&buf_read, val.val, "show_memory:message"))
  {
    buf_read.pt += val.val;
    print_show_memory(&buf_read);
  }
}
