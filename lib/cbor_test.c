
#include "test/birdtest.h"
#include "lib/cbor.h"
#if 0
#include "lib/cbor_parse_tools.h"
#endif

#define BUFF_LEN 100

char working_buffer[4096];
char result_buf[32];
struct cbor_writer *writer;
struct cbor_parser_context *parser;

static void
reset_writer(struct cbor_writer *writer)
{
  writer->data = (buffer) {
    .start = working_buffer,
    .pos = working_buffer,
    .end = working_buffer + ARRAY_SIZE(working_buffer),
  };
}

static buffer
reset_parser(struct cbor_parser_context *parser, const struct cbor_writer *writer)
{
  cbor_parser_reset(parser);
  parser->target_buf = result_buf;
  parser->target_len = ARRAY_SIZE(result_buf);
  return (buffer) {
    .start = writer->data.start,
    .pos = writer->data.start,
    .end = writer->data.pos,
  };
}

void print_to_file_for_control_from_outside(void)
{
  FILE *fd;

  fd = fopen("a.cbor", "wb");

  buffer *b = &writer->data;
  fwrite(b->start, b->pos - b->start, 1, fd);
  fclose(fd);
}

static enum cbor_parse_result
full_read(struct cbor_parser_context *parser, buffer *b)
{
  enum cbor_parse_result cr;
  while (1)
  {
    if (b->pos >= b->end)
      return CPR_ERROR; /* 0 */

    cr = cbor_parse_byte(parser, b->pos[0]);
    /* simplification: The target buffer will always have enough space */
    ASSERT(cr != CPR_STR_BUF_END);
    if (cr == CPR_MAJOR || cr == CPR_STR_END)
    {
      b->pos++;
      return cr;
    }

    if (cr == CPR_ERROR)
      return CPR_ERROR; /* 0 */

    /* CPR_MORE -- need more bytes */
    b->pos++;
  }
}

static int UNUSED test_int(void)
{
  /* do not reset neither writer nor parser, they should work fine,
   * they were init'd in the main */
  // reset_writer(writer);

  int num_items = 13;
  int64_t test_int[] = {-123456789012345678, -1234567890, -12345, -123, -25, -13, 0, 13, 25, 123, 12345, 1234567890, 123456789012345678};
  byte bin_int[] = {0x8d, 0x3b, 0x1, 0xb6, 0x9b, 0x4b, 0xa6, 0x30, 0xf3, 0x4d, 0x3a, 0x49, 0x96, 0x2, 0xd1, 0x39, 0x30, 0x38, 0x38, 0x7a, 0x38, 0x18, 0x2c, 0x0, 0xd, 0x18, 0x19, 0x18, 0x7b, 0x19, 0x30, 0x39, 0x1a, 0x49, 0x96, 0x2, 0xd2, 0x1b, 0x1, 0xb6, 0x9b, 0x4b, 0xa6, 0x30, 0xf3, 0x4e};

  cbor_open_array(writer);

  for (int i = 0; i < num_items; i++)
  {
    cbor_put_int(writer, test_int[i]);
  }

  for (long unsigned int i = 0; i < sizeof(bin_int); i++)
  {
    bt_assert((writer->data.start[i] & 0xff) == (bin_int[i] & 0xff));
  }

  buffer b; // = reset_parser(parser, writer);
  b.end = working_buffer + ARRAY_SIZE(working_buffer);
  bt_assert(full_read(parser, &b));
  bt_assert(parser->type == CBOR_ARRAY);
  for (int i = 0; i < num_items; i++)
  {
    bt_assert(full_read(parser, &b));
    bt_assert(parser->type == CBOR_NEGINT || parser->type == CBOR_POSINT);
    bt_assert(((int64_t) parser->value) == test_int[i]);
  }
  bt_assert(cbor_parse_block_end(parser));

  return 1; /* ok */
}

static UNUSED int non_aligned_int(void)
{
#if 0
  w->pt = reader.pt = 0;
  int num_items = 4;
  cbor_open_list_with_length(w, num_items);

  cbor_add_int(w, 30);
  w->cbor[w->pt - 1] = 1;

  cbor_add_int(w, 300);
  w->cbor[w->pt - 2] = 0;
  w->cbor[w->pt - 1] = 1;

  cbor_add_int(w, 300000000);
  for (int i = 4; i > 1; i--)
  {
    w->cbor[w->pt - i] = 0;
  }
  w->cbor[w->pt - 1] = 1;

  cbor_add_int(w, 30000000000000000);
  for (int i = 8; i > 1; i--)
  {
    w->cbor[w->pt - i] = 0;
  }
  w->cbor[w->pt - 1] = 1;

  struct value val = get_value(&reader);
  bt_assert(val.major = ARRAY);
  bt_assert(val.val = num_items);

  for (int i = 0; i < num_items; i++)
  {
    val = get_value(&reader);
    bt_assert(val.major == UINT);
    bt_assert(val.val == 1);
  }
#endif
  return 1;
}

static int test_majors(void)
{
  reset_writer(writer);
  cbor_open_array(writer);
  cbor_open_array(writer);
  cbor_put_posint(writer, 1);
  cbor_close_array(writer);
  cbor_close_array(writer);

  buffer b;
  b = reset_parser(parser, writer);

  bt_assert(full_read(parser, &b) == CPR_MAJOR);
  bt_assert(parser->type == CBOR_ARRAY);
  parser->type = CBOR_MAP; // hopefuly, this do not cause any issues
  bt_assert(full_read(parser, &b) == CPR_MAJOR);
  bt_assert(parser->type == CBOR_ARRAY);
  bt_assert(full_read(parser, &b) == CPR_MAJOR);
  bt_assert(parser->type == CBOR_POSINT);
  //bt_assert(cbor_parse_block_end(parser)); // pos int?
  bt_assert(cbor_parse_block_end(parser)); // inner array
  bt_assert(cbor_parse_block_end(parser)); // outer array
  bt_assert(parser->partial_state == CPE_EXIT);

  reset_writer(writer);

  cbor_open_array(writer);
  cbor_put_string(writer, "b");
  cbor_put_posint(writer, 1);
  cbor_put_negint(writer, -1);

  {
    /* this representation of IPv4 is not correct
     * it is close enough for now */
    //ip_addr a = ip4_build(18, 4, 0, 0);
    byte ip_a[] = { 18, 4, 0, 0 };
    cbor_put_bytes(writer, ip_a, ARRAY_SIZE(ip_a));
  }

  cbor_close_array(writer);

  //buffer b;
  b = reset_parser(parser, writer);

  bt_assert(full_read(parser, &b) == CPR_MAJOR);
  bt_assert(parser->type == CBOR_ARRAY);
  bt_assert(full_read(parser, &b) == CPR_MAJOR);
  bt_assert(parser->type == CBOR_TEXT);
  bt_assert(full_read(parser, &b) == CPR_STR_END);
  bt_assert(false == cbor_parse_block_end(parser)); /* we still have a items in the CBOR array */
  parser->target_buf = result_buf; parser->target_len = ARRAY_SIZE(result_buf);

  bt_assert(full_read(parser, &b) == CPR_MAJOR);
  bt_assert(parser->type == CBOR_POSINT);
  bt_assert(false == cbor_parse_block_end(parser));

  bt_assert(full_read(parser, &b) == CPR_MAJOR);
  bt_assert(parser->type == CBOR_NEGINT);
  bt_assert(false == cbor_parse_block_end(parser));

  // TODO CBOR Tag
  bt_assert(full_read(parser, &b) == CPR_MAJOR);
  bt_assert(parser->type == CBOR_BYTES);
  bt_assert(full_read(parser, &b) == CPR_STR_END);
  bt_assert(cbor_parse_block_end(parser)); // bytes
  bt_assert(cbor_parse_block_end(parser)); // array
  bt_assert(parser->partial_state == CPE_EXIT);


  reset_writer(writer);
  cbor_open_map(writer);
  {
    /* key */   cbor_put_posint(writer, 1);
    /* value */ cbor_put_negint(writer, -1);
  }
  {
    byte data[] = { 1, 2, 3 };
    /* key */   cbor_put_string(writer, "hello world");
    /* value */ cbor_put_bytes(writer, data, ARRAY_SIZE(data));
  }
  cbor_close_map(writer);

  reset_writer(writer);
  bt_assert(full_read(parser, &b));
  bt_assert(parser->type == CBOR_MAP);
  bt_assert(false == cbor_parse_block_end(parser));
  bt_assert(full_read(parser, &b));
  bt_assert(parser->type == CBOR_POSINT);
  bt_assert(false == cbor_parse_block_end(parser));
  bt_assert(full_read(parser, &b));
  bt_assert(parser->type == CBOR_NEGINT);
  bt_assert(false == cbor_parse_block_end(parser));
  bt_assert(full_read(parser, &b));
  bt_assert(parser->type == CBOR_TEXT);
  bt_assert(full_read(parser, &b) == CPR_STR_END);
  bt_assert(cbor_parse_block_end(parser));
  bt_assert(full_read(parser, &b));
  bt_assert(parser->type == CBOR_BYTES);
  bt_assert(cbor_parse_block_end(parser)); // bytes
  bt_assert(cbor_parse_block_end(parser)); // map

  reset_writer(writer);
  cbor_open_map(writer);
  /* intentionally empty map */
  cbor_close_map(writer);

  b = reset_parser(parser, writer);

  bt_assert(full_read(parser, &b));
  bt_assert(parser->type == CBOR_MAP);
  bt_assert(cbor_parse_block_end(parser));

  return 1; /* ok */
}

int main(int argc, char *argv[])
{
  bt_init(argc, argv);

  writer = cbor_writer_new(&root_pool, 64, working_buffer, ARRAY_SIZE(working_buffer));
  parser = cbor_parser_new(&root_pool, 64);

  //bt_test_suite(test_int, "Adding and reading integer from cbor.");
  //bt_test_suite(non_aligned_int, "Reading non-alligned int from cbor.");
  bt_test_suite(test_majors, "Test cbor datatypes.");

  return bt_exit_value();
}
