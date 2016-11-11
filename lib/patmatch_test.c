/*
 *	BIRD Library -- Pattern Matching Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"

#include "nest/bird.h"
#include "lib/string.h"

#define MATCH		(int) { 1 }
#define NOMATCH		(int) { 0 }

struct match_pair {
  byte *pattern;
  byte *data;
};

static int
test_matching(void *out_, const void *in_, const void *expected_out_)
{
  int *out = out_;
  const struct match_pair *in = in_;
  const int *expected_out = expected_out_;

  *out = patmatch(in->pattern, in->data);

  return *out == *expected_out;
}

static void
fmt_match_pair(char *buf, size_t size, const void *data)
{
  const struct match_pair *mp = data;
  snprintf(buf, size, "pattern: '%s', subject: '%s'", mp->pattern, mp->data);
}

static void
fmt_match_result(char *buf, size_t size, const void *data)
{
  const int *result = data;
  snprintf(buf, size, *result ? "match" : "no-match");
}

static int
t_matching(void)
{
  struct bt_pair test_vectors[] = {
    {
      .in  = & (struct match_pair) {
	.pattern = "",
	.data    = "",
      },
      .out = & MATCH,
    },
    {
      .in  = & (struct match_pair) {
	.pattern = "*",
	.data    = "",
      },
      .out = & MATCH,
    },
    {
      .in  = & (struct match_pair) {
	.pattern = "\\*",
	.data    = "*",
      },
      .out = & MATCH,
    },
    {
      .in  = & (struct match_pair) {
	.pattern = "\\*",
	.data    = "a",
      },
      .out = & NOMATCH,
    },
    {
      .in  = & (struct match_pair) {
	.pattern = "?",
	.data    = "",
      },
      .out = & NOMATCH,
    },
    {
      .in  = & (struct match_pair) {
	.pattern = "abcdefghijklmnopqrstuvwxyz",
	.data    = "abcdefghijklmnopqrstuvwxyz",
      },
      .out = & MATCH,
    },
    {
      .in  = & (struct match_pair) {
	.pattern = "??????????????????????????",
	.data    = "abcdefghijklmnopqrstuvwxyz",
      },
      .out = & MATCH,
    },
    {
      .in  = & (struct match_pair) {
	.pattern = "*abcdefghijklmnopqrstuvwxyz*",
	.data    =  "abcdefghijklmnopqrstuvwxyz",
      },
      .out = & MATCH,
    },
    {
      .in  = & (struct match_pair) {
	.pattern = "ab?defg*jklmnop*stu*wxy*z",
	.data    = "abcdefghijklmnopqrstuvwxyz",
      },
      .out = & MATCH,
    },
    {
      .in  = & (struct match_pair) {
	.pattern = "abcdefghijklmnopqrstuvwxyz",
	.data    = "abcdefghijklmnopqrtuvwxyz",
      },
      .out = & NOMATCH,
    },
    {
      .in  = & (struct match_pair) {
	.pattern = "abcdefghijklmnopqr?uvwxyz",
	.data    = "abcdefghijklmnopqrstuvwxyz",
      },
      .out = & NOMATCH,
    },
    {
      .in  = & (struct match_pair) {
	.pattern = "aa*aaaaa?aaaaaaaaaaaaaaaaaaa",
	.data    = "aaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
      .out = & NOMATCH,
    },
  };

  return bt_assert_batch(test_vectors, test_matching, fmt_match_pair, fmt_match_result);
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_matching, "Pattern matching");

  return bt_exit_value();
}
