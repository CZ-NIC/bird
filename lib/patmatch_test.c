/*
 *	BIRD Library -- Pattern Matching Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/string.h"

#define MATCH		1
#define NOMATCH		0

struct in {
  byte *pattern;
  byte *data;
};

struct in_out {
  struct in in;
  byte out;
};

static void
match(struct in in, byte *out)
{
  *out = patmatch(in.pattern, in.data) ? MATCH : NOMATCH;
}

static int
t_matching(void)
{
  struct in_out in_out[] = {
      {
	  .in  = {
	      .pattern = "",
	      .data    = "",
	  },
	  .out = MATCH,
      },
      {
	  .in  = {
	      .pattern = "*",
	      .data    = "",
	  },
	  .out = MATCH,
      },
      {
	  .in  = {
	      .pattern = "\\*",
	      .data    = "*",
	  },
	  .out = MATCH,
      },
      {
	  .in  = {
	      .pattern = "\\*",
	      .data    = "a",
	  },
	  .out = NOMATCH,
      },      {
	  .in  = {
	      .pattern = "?",
	      .data    = "",
	  },
	  .out = NOMATCH,
      },
      {
	  .in  = {
	      .pattern = "abcdefghijklmnopqrstuvwxyz",
	      .data    = "abcdefghijklmnopqrstuvwxyz",
	  },
	  .out = MATCH,
      },
      {
	  .in  = {
	      .pattern = "??????????????????????????",
	      .data    = "abcdefghijklmnopqrstuvwxyz",
	  },
	  .out = MATCH,
      },
      {
	  .in  = {
	      .pattern = "*abcdefghijklmnopqrstuvwxyz*",
	      .data    =  "abcdefghijklmnopqrstuvwxyz",
	  },
	  .out = MATCH,
      },      {
	  .in  = {
	      .pattern = "ab?defg*jklmnop*stu*wxy*z",
	      .data    = "abcdefghijklmnopqrstuvwxyz",
	  },
	  .out = MATCH,
      },
      {
	  .in  = {
	      .pattern = "abcdefghijklmnopqrstuvwxyz",
	      .data    = "abcdefghijklmnopqrtuvwxyz",
	  },
	  .out = NOMATCH,
      },
      {
	  .in  = {
	      .pattern = "abcdefghijklmnopqr?uvwxyz",
	      .data    = "abcdefghijklmnopqrstuvwxyz",
	  },
	  .out = NOMATCH,
      },
      {
	  .in  = {
	      .pattern = "aa*aaaaa?aaaaaaaaaaaaaaaaaaa",
	      .data    = "aaaaaaaaaaaaaaaaaaaaaaaaaa",
	  },
	  .out = NOMATCH,
      },
  };

  bt_assert_fn_in_out(match, in_out, "'%s' ~ '%s'", "%d");

  return BT_SUCCESS;
}
int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_matching, "Pattern matching");

  return bt_end();
}
