/*
 *	BIRD Library -- Generic Bit Operations Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "lib/string.h"

#define BSPRINTF(nw, res, buf, fmt, ...) \
  do { \
    int n = bsprintf(buf, fmt, ##__VA_ARGS__); \
    bt_assert_msg(n == nw, "fmt=\"%s\" returns n=%d, want %d", fmt, n, nw); \
    bt_assert_msg(buf[n] == 0, "fmt=\"%s\" doesn't make buf[%d]=\'\\0\', found 0x%02x instead", fmt, n, buf[n]); \
    bt_assert_msg(memcmp(buf, res, nw) == 0, "fmt=\"%s\" writes \"%*s\", want \"%*s\"", fmt, (n < nw ? n : nw), buf, nw, res); \
  } while (0)

static int
t_simple(void)
{
  bt_test_suite_success = BT_SUCCESS;

  char buf[256];
  memset(buf, 0xa5, 256);

  BSPRINTF(0, "", buf, "", NULL);
  BSPRINTF(1, "%", buf, "%%", NULL);
  BSPRINTF(2, "%%", buf, "%%%%", NULL);

  BSPRINTF(1, "\x00", buf, "%c", 0);
  BSPRINTF(1, "@", buf, "@", 64);
  BSPRINTF(1, "\xff", buf, "%c", 0xff);

  BSPRINTF(7, "Success", buf, "%m");
  errno = 5;
  BSPRINTF(18, "Input/output error", buf, "%m");
  errno = 0;

  BSPRINTF(18, "Input/output error", buf, "%M", 5);

  BSPRINTF(11, "TeSt%StRiNg", buf, "%s", "TeSt%StRiNg");

  BSPRINTF(16, "00000fee1a15600d", buf, "%p", (void *) 0xfee1a15600d);

  long ln = 0;
  BSPRINTF(10, "TeStStRiNg", buf, "TeStS%lntRiNg", &ln);
  bt_assert_msg(ln == 5, "fmt=\"TeStS%%lntRiNg\", &ln makes ln=%ld, want 5", ln);

  BSPRINTF(2, "%d", buf, "%%d", 1);
  BSPRINTF(1, "1", buf, "%d", 1);
  BSPRINTF(2, "+1", buf, "%+d", 1);
  BSPRINTF(2, " 1", buf, "% d", 1);
  BSPRINTF(2, "-1", buf, "%d", -1);
  BSPRINTF(11, "-2147483648", buf, "%d", -2147483648);

  return bt_test_suite_success;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_simple, "printf without varargs");

  return bt_end();
}
