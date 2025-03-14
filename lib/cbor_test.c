
#include "test/birdtest.h"
#include "lib/cbor.h"
#include "lib/cbor_parse_tools.h"

#define BUFF_LEN 100

struct cbor_writer *w;
struct buff_reader reader;

void print_to_file_for_control_from_outside(void)
{
  FILE *write_ptr;

  write_ptr = fopen("a.cbor", "wb");

  fwrite(w->cbor, w->pt, 1, write_ptr);
  fclose(write_ptr);

}

static int test_int(void)
{
  reader.pt = w->pt = 0;
  int num_items = 13;
  int64_t test_int[] = {-123456789012345678, -1234567890, -12345, -123, -25, -13, 0, 13, 25, 123, 12345, 1234567890, 123456789012345678};
  byte bin_int[] = {0x8d, 0x3b, 0x1, 0xb6, 0x9b, 0x4b, 0xa6, 0x30, 0xf3, 0x4d, 0x3a, 0x49, 0x96, 0x2, 0xd1, 0x39, 0x30, 0x38, 0x38, 0x7a, 0x38, 0x18, 0x2c, 0x0, 0xd, 0x18, 0x19, 0x18, 0x7b, 0x19, 0x30, 0x39, 0x1a, 0x49, 0x96, 0x2, 0xd2, 0x1b, 0x1, 0xb6, 0x9b, 0x4b, 0xa6, 0x30, 0xf3, 0x4e};
  cbor_open_list_with_length(w, num_items);
  for (int i = 0; i < num_items; i++)
  {
    cbor_add_int(w, test_int[i]);
  }

  for (long unsigned int i = 0; i < sizeof(bin_int); i++)
  {
    bt_assert((w->cbor[i] & 0xff) == (bin_int[i] & 0xff));
  }

  struct value val = get_value(&reader);
  bt_assert(val.major = ARRAY);
  bt_assert(val.val = num_items);
  for (int i = 0; i < num_items; i++)
  {
    val = get_value(&reader);
    bt_assert(val.major == NEG_INT || val.major == UINT);
    bt_assert(val.val == test_int[i]);
  }
  return 1;
}

static int non_aligned_int(void)
{
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
  return 1;
}

static int test_majors(void)
{
  w->pt = reader.pt = 0;
  cbor_open_block(w);
  cbor_open_list_with_length(w, 4);
  cbor_add_string(w, "b");
  cbor_add_int(w, 1);
  cbor_add_int(w, -1);
  cbor_add_ipv4(w, ip4_build(18, 4, 0, 0));
  cbor_close_block_or_list(w);

  struct value val = get_value(&reader);
  bt_assert(val.major == BLOCK);
  val = get_value(&reader);
  bt_assert(val.major == ARRAY);
  val = get_value(&reader);
  bt_assert(val.major == TEXT);
  reader.pt += val.val;
  val = get_value(&reader);
  bt_assert(val.major == UINT);
  val = get_value(&reader);
  bt_assert(val.major == NEG_INT);
  val = get_value(&reader);
  bt_assert(val.major == TAG);
  val = get_value(&reader);
  bt_assert(val.major == BYTE_STR);
  reader.pt += val.val;
  val = get_value(&reader);
  bt_assert(val_is_break(val));
  return 1;
}

int main(int argc, char *argv[])
{
  bt_init(argc, argv);
  byte buff[BUFF_LEN];
  w = cbor_init(buff, BUFF_LEN, tmp_linpool);
  reader.buff = buff;
  reader.size = BUFF_LEN;
  reader.pt = 0;

  bt_test_suite(test_int, "Adding and reading integer from cbor.");
  bt_test_suite(non_aligned_int, "Reading non-alligned int from cbor.");
  bt_test_suite(test_majors, "Test cbor datatypes.");

  return bt_exit_value();
}
