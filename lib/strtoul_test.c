/*
 *	BIRD Library -- Parsing Numbers Functions Tests
 *
 *	(c) 2026 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/string.h"

struct bstrtoul_data_out {
  u64 result;
  uint offset;		      /* Offset of @end pointer from the beginning of the string */
  int errno_val;
};

static void
bt_fmt_u64(char *buf, size_t size, const void *data_)
{
  const struct bstrtoul_data_out *data = data_;
  snprintf(buf, size, "0x%lx (%lu)", data->result, data->result);
}

static int
test_bstrtoul10(void *out_, const void *in_, const void *expected_out_)
{
  const char *in = in_;
  const struct bstrtoul_data_out *expected_out = expected_out_;
  struct bstrtoul_data_out *out = out_;

  errno = 0;

  char *end = (char *) 1;
  out->result = bstrtoul10(in, &end);

  bt_assert(out->result == expected_out->result);
  bt_assert(end == in + expected_out->offset);
  bt_assert(errno == expected_out->errno_val);

  return 1;
}

static int
t_bstrtoul10(void)
{
  struct bt_pair test_vectors[] = {
    {
      .in  = "1234567890",
      .out = &(struct bstrtoul_data_out) {
        .result = 1234567890,
	.offset = 10,
      },
    },
    {
      .in  = "987654321",
      .out = &(struct bstrtoul_data_out) {
	.result = 987654321,
	.offset = 9,
      },
    },
    {
      .in  = "18446744073709551615",
      .out = &(struct bstrtoul_data_out) {
	.result = UINT64_MAX,
	.offset = 20,
      },
    },
    {
      .in  = "0",
      .out = &(struct bstrtoul_data_out) {
	.result = 0,
	.offset = 1,
      },
    },
    {
      .in  = "0001234",
      .out = &(struct bstrtoul_data_out) {
	.result = 1234,
	.offset = 7,
      },
    },
    {
      .in  = "999999999999999999999999",
      .out = &(struct bstrtoul_data_out) {
	.result = UINT64_MAX,
	.offset = 19,
	.errno_val = ERANGE,
      },
    },
  };

  return bt_assert_batch(test_vectors, test_bstrtoul10, bt_fmt_str, bt_fmt_u64);
}

static int
test_bstrtoul16(void *out_, const void *in_, const void *expected_out_)
{
  const char *in = in_;
  const struct bstrtoul_data_out *expected_out = expected_out_;
  struct bstrtoul_data_out *out = out_;

  errno = 0;

  char *end = (char *) 1;
  out->result = bstrtoul16(in, &end);

  bt_assert(out->result == expected_out->result);
  bt_assert(end == in + expected_out->offset);
  bt_assert(errno == expected_out->errno_val);

  return 1;
}

static int
t_bstrtoul16(void)
{
  struct bt_pair test_vectors[] = {
    {
      .in  = "123456789",
      .out = &(struct bstrtoul_data_out) {
	.result = 0x123456789,
	.offset = 9,
      },
    },
    {
      .in  = "abcdef",
      .out = &(struct bstrtoul_data_out) {
	.result = 0xabcdef,
	.offset = 6,
      },
    },
    {
      .in  = "ABCDEF",
      .out = &(struct bstrtoul_data_out) {
	.result = 0xABCDEF,
	.offset = 6,
      },
    },
    {
      .in  = "123456789abcDEF",
      .out = &(struct bstrtoul_data_out) {
	.result = 0x123456789abcDEF,
	.offset = 15,
      },
    },
    {
      .in  = "ffffffffffffffff",
      .out = &(struct bstrtoul_data_out) {
	.result = UINT64_MAX,
	.offset = 16,
      },
    },
    {
      .in  = "0",
      .out = &(struct bstrtoul_data_out) {
	.result = 0,
	.offset = 1,
      },
    },
    {
      .in  = "ffffffffffffffff0000",
      .out = &(struct bstrtoul_data_out) {
	.result = UINT64_MAX,
	.offset = 16,
	.errno_val = ERANGE,
      },
    },
    {
      .in  = "0xad",
      .out = &(struct bstrtoul_data_out) {
	.result = 0,
	.offset = 1,
      },
    },
    {
      .in  = "1234xyz",
      .out = &(struct bstrtoul_data_out) {
	.result = 0x1234,
	.offset = 4,
      },
    },
  };

  return bt_assert_batch(test_vectors, test_bstrtoul16, bt_fmt_str, bt_fmt_u64);
}

struct bytestr {
  int len;
  byte buf[32];
};

static void
bt_fmt_bytestr(char *buf, size_t size, const void *data_)
{
  const struct bytestr *data = data_;

  if (data->len <= 0)
  {
    snprintf(buf, size, "...");
    return;
  }

  char *tmp = allocz(data->len + 1);
  char *t = tmp;

  for (int i = 0; i < data->len; i++)
    t += bsprintf(t, "%hx", data->buf[i]);

  snprintf(buf, size, "0x%s", tmp);
}

static int
test_bstrhextobin(void *out_, const void *in_, const void *expected_out_) 
{
  const char *in = in_;
  const struct bytestr *expected_out = expected_out_;
  struct bytestr *out = out_;

  out->len = bstrhextobin(in, out->buf);

  bt_assert(out->len == expected_out->len);

  if (out->len > 0)
    bt_assert(memcmp(out->buf, expected_out->buf, expected_out->len) == 0);

  return 1;
}

static int
t_bstrhextobin(void)
{
  struct bt_pair test_vectors[] = {
    {
      .in  = "1234567890",
      .out = &(struct bytestr) {
	.buf = { 0x12, 0x34, 0x56, 0x78, 0x90 },
	.len = 5,
      },
    },
    {
      .in  = "1234567890abcdef",
      .out = &(struct bytestr) {
	.buf = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef },
	.len = 8,
      },
    },
    {
      .in  = "abcdef",
      .out = &(struct bytestr) {
	.buf = { 0xab, 0xcd, 0xef },
	.len = 3,
      },
    },
    {
      .in  = "ABCDEF",
      .out = &(struct bytestr) {
	.buf = { 0xAB, 0xCD, 0xEF },
	.len = 3,
      },
    },
    {
      .in  = "ffffffffffffffff",
      .out = &(struct bytestr) {
	.buf = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
	.len = 8,
      },
    },
    {
      .in  = "00",
      .out = &(struct bytestr) {
	.buf = { 0x0 },
	.len = 1,
      },
    },
    {
      .in  = "::1234",
      .out = &(struct bytestr) {
	.buf = { 0x12, 0x34 },
	.len = 2,
      },
    },
    {
      .in  = "-ab cd.ef",
      .out = &(struct bytestr) {
	.buf = { 0xab, 0xcd, 0xef },
	.len = 3,
      },
    },
    {
      .in  = "xyz",
      .out = &(struct bytestr) {
	.len = -1,
      },
    },
  };

  return bt_assert_batch(test_vectors, test_bstrhextobin, bt_fmt_str, bt_fmt_bytestr);
}

static int
test_bstrbintohex(void *out_, const void *in_, const void *expected_out_)
{
  const struct bytestr *in = in_;
  const char *expected_out = expected_out_;
  char *out = out_;

  bt_assert(bstrbintohex(in->buf, in->len, out, sizeof(bt_out_fmt_buf) / 4, ':') == 0);

  size_t len_expected_out = strlen(expected_out);
  size_t len_out = strlen(out);

  if (len_out != len_expected_out)
    return 0;

  return memcmp(out, expected_out, len_expected_out) == 0;
}

static int
t_bstrbintohex(void)
{
  struct bt_pair test_vectors[] = {
    {
      .in  = &(struct bytestr) {
	.buf = { 0x12, 0x34, 0x56, 0x78, 0x90 },
	.len = 5,
      },
      .out = "12:34:56:78:90",
    },
    {
      .in  = &(struct bytestr) {
	.buf = { 0xab, 0xcd, 0xef },
	.len = 3,
      },
      .out = "ab:cd:ef",
    },
    {
      .in  = &(struct bytestr) {
	.buf = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef },
	.len = 8,
      },
      .out = "12:34:56:78:90:ab:cd:ef",
    },
    {
      .in  = &(struct bytestr) {
	.buf = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
	.len = 8,
      },
      .out = "ff:ff:ff:ff:ff:ff:ff:ff",
    },
    {
      .in  = &(struct bytestr) {
	.buf = { 0x0 },
	.len = 1,
      },
      .out = "00",
    },
    {
      .in  = &(struct bytestr) {
	.buf = { 0x0, 0x0, 0x0, 0x0 },
	.len = 4,
      },
      .out = "00:00:00:00",
    },
  };

  return bt_assert_batch(test_vectors, test_bstrbintohex, bt_fmt_bytestr, bt_fmt_str);
}

int
main(int argc, char **argv)
{
  bt_init(argc, argv);

  bt_test_suite(t_bstrtoul10,   "Converting decimal string into number");
  bt_test_suite(t_bstrtoul16,   "Converting hexadecimal string into number");
  bt_test_suite(t_bstrhextobin, "Converting hexadecimal string into bytestring");
  bt_test_suite(t_bstrbintohex, "Converting bytestring into hexadecimal string");

  return bt_exit_value();
}

